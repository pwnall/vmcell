//! Per-VM **writable scratch** for copy-on-attach extra disks (design §11.5, The HTTP REST API and
//! its OpenAPI document; §17, Open gaps and future capabilities — "a writable-scratch extra disk
//! copied-on-attach from a store artifact").
//!
//! The artifact store is create-only and immutable, so a client that wants a *writable* extra disk
//! gets a **private copy** of the named artifact, made when the VM is created and thrown away with
//! it. This module owns where that copy lives and who deletes it.
//!
//! # Why the copies live inside the artifacts directory
//!
//! Under a reserved `.`-prefixed subdirectory of `--artifacts-dir` ([`SCRATCH_DIR_NAME`]), for two
//! reasons that pull the same way:
//!
//! * **Reflink is a filesystem-local property.** A copy-on-write clone can only share blocks with
//!   its source on the *same* filesystem; a scratch base under `$XDG_RUNTIME_DIR` (tmpfs) or
//!   `/tmp` would force a full byte copy of every disk image on every create, and would put that
//!   copy in RAM. Beside the store, `OverlayStore::clone_file` can actually reflink — which is what
//!   makes "writable disk per cell" cheap on XFS/Btrfs rather than a per-VM image copy.
//! * **It is unnameable from the network.** [`crate::name::validate_artifact_name`] rejects a
//!   leading `.`, so no client-supplied artifact name can ever resolve into this directory, on any
//!   verb. It is the daemon's own bookkeeping, like the `.sha256` digest sidecars beside it.
//!
//! The trade-off, stated rather than discovered: these copies consume space on the store's
//! filesystem while their VMs live, and they are deliberately **excluded from the store's usage and
//! quota accounting** ([`crate::artifact_store::ArtifactStore::usage`]). Counting them would make
//! an upload's 413 depend on which VMs happen to be running, and would report per-VM scratch as
//! snapshot prefixes — a number an operator cannot act on by deleting artifacts.
//!
//! The consequence, named rather than left to be discovered on a full disk: `--max-store-bytes`
//! bounds what a client can *upload*, and **nothing bounds the copies**. One quota-sized artifact
//! attached writable to N cells costs N times its size on this filesystem, so the space an operator
//! must provision is the quota plus (concurrent cells × their writable disks), not the quota. A
//! per-VM or per-daemon ceiling on writable-disk bytes is the obvious next knob; it is not shipped,
//! and a copy that does not fit fails its create loud (naming the disk) rather than booting a cell
//! with a truncated image.
//!
//! # Who deletes them
//!
//! [`VmScratch`] is an RAII guard, held by the live VM's handle and dropped **after** the VMM
//! process is gone — the same ownership discipline `vmcell::vmm::VmTempDir` has for the per-VM
//! socket/serial-log directory (§13, Cross-cutting invariants). A hard-killed daemon (SIGKILL,
//! power loss) runs no `Drop`, exactly as it leaks netns/cgroup/scratch; [`reclaim_orphan_scratch`]
//! is this directory's counterpart to the start-up orphan sweep, and runs from the same start-up
//! window.

use crate::error::{DaemonError, DaemonResult};
use std::path::{Path, PathBuf};

/// The reserved subdirectory of `--artifacts-dir` that per-VM writable-disk copies live in.
///
/// The leading `.` is load-bearing, not cosmetic: [`crate::name::validate_artifact_name`] rejects a
/// leading `.`, so this name is unreachable from any client-supplied artifact name on any verb.
pub const SCRATCH_DIR_NAME: &str = ".vmcell-scratch";

/// The writable-scratch base inside `artifacts_dir` — the **one** composition of that layout.
///
/// Both writers (the launcher, which mints per-VM directories under it) and the one reader that has
/// to know it is not an artifact (the store's usage accounting) go through this function and
/// [`SCRATCH_DIR_NAME`], so the two can never disagree about which directory is scratch.
#[must_use]
pub fn scratch_base(artifacts_dir: &Path) -> PathBuf {
    artifacts_dir.join(SCRATCH_DIR_NAME)
}

/// The name of one VM's scratch directory under [`scratch_base`], for daemon process `pid` and
/// per-process sequence number `seq`.
///
/// Pure and **injective in `(pid, seq)`** — the `-` delimiters keep `(1, 23)` and `(12, 3)` apart —
/// so two concurrent creates, in this daemon or in a sibling daemon sharing the artifacts
/// directory, never mint the same directory. `pid` is what [`reclaim_orphan_scratch`] reads back.
#[must_use]
fn vm_scratch_dir_name(pid: u32, seq: u64) -> String {
    format!("disks-{pid}-{seq}")
}

/// One VM's writable-disk scratch directory: an RAII guard that removes the directory, and every
/// disk copy in it, on [`Drop`].
///
/// Created before the VM boots (the copies have to exist for the VMM to open them) and dropped
/// **after** the VMM process is gone, so removal never races a hypervisor still holding one of the
/// images open. A `start()` that fails partway drops the guard on the way out, which is why a
/// failed create leaves no copy behind.
#[derive(Debug)]
pub struct VmScratch {
    path: PathBuf,
}

impl VmScratch {
    /// Creates a fresh per-VM scratch directory under `base` for this process and `seq`.
    ///
    /// # Errors
    /// [`DaemonError::Internal`] if the directory cannot be created.
    pub fn create(base: &Path, seq: u64) -> DaemonResult<Self> {
        let path = base.join(vm_scratch_dir_name(std::process::id(), seq));
        std::fs::create_dir_all(&path).map_err(|e| {
            DaemonError::Internal(format!(
                "cannot create the per-VM writable-disk scratch dir {}: {e}",
                path.display()
            ))
        })?;
        Ok(Self { path })
    }

    /// The owned directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for VmScratch {
    fn drop(&mut self) {
        // Best-effort by design: `Drop` has no `Result` to surface and must not panic, and the
        // directory may already be gone. A genuine failure is LOGGED rather than swallowed — it is
        // a disk-image-sized leak beside the artifact store, which is exactly the class an operator
        // needs to see.
        if let Err(e) = std::fs::remove_dir_all(&self.path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                dir = %self.path.display(),
                error = %e,
                "failed to remove a VM's writable-disk scratch dir; its disk copies are leaked"
            );
        }
    }
}

/// What a start-up scratch reclamation removed, and what it deliberately left alone.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ScratchReclaim {
    /// Directory names removed (their owning daemon is gone).
    pub removed: Vec<String>,
    /// Directory names left in place, with the reason — a live owner, or a name this daemon does
    /// not recognize and therefore refuses to delete.
    pub retained: Vec<(String, &'static str)>,
}

impl ScratchReclaim {
    /// Whether anything at all was found, so a caller can stay silent on the normal empty case.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.removed.is_empty() && self.retained.is_empty()
    }
}

/// Reclaims writable-disk scratch a **hard-killed** daemon left under `base`.
///
/// The counterpart to the start-up orphan sweep (`vmcell::orchestrator::sweep_orphans`), for the one
/// resource that sweep cannot see: these directories are keyed on the *daemon's* pid rather than on
/// a vmid, because they are minted before the VM that will use them has one.
///
/// **Retain on doubt, never reap on doubt.** A directory is removed only when its name parses as
/// one of ours *and* its owning pid is not this process's and is not alive. A recycled pid that now
/// belongs to something else leaves the directory in place — a bounded leak — rather than deleting a
/// live daemon's disk copies out from under a running guest. This process's own pid counts as dead
/// because the one caller runs at start-up, before this daemon owns any VM, so anything already
/// wearing our pid is residue from a previous process that happened to hold it.
///
/// A missing `base` is the normal first-boot case and reclaims nothing. Errors are logged and
/// skipped per entry rather than aborting the pass: one unreadable directory must not stop the rest
/// from being reclaimed.
#[must_use]
pub fn reclaim_orphan_scratch(base: &Path) -> ScratchReclaim {
    let mut report = ScratchReclaim::default();
    let entries = match std::fs::read_dir(base) {
        Ok(rd) => rd,
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    dir = %base.display(),
                    error = %e,
                    "cannot read the writable-disk scratch base; leaving whatever is in it"
                );
            }
            return report;
        }
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(pid) = owning_pid(&name) else {
            report
                .retained
                .push((name, "not a vmcelld scratch directory name"));
            continue;
        };
        if pid != std::process::id() && pid_is_alive(pid) {
            report.retained.push((name, "its daemon is still running"));
            continue;
        }
        match std::fs::remove_dir_all(entry.path()) {
            Ok(()) => report.removed.push(name),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(
                    dir = %entry.path().display(),
                    error = %e,
                    "cannot reclaim an orphaned writable-disk scratch dir"
                );
                report.retained.push((name, "removal failed"));
            }
        }
    }
    report
}

/// The pid that owns a scratch directory called `name`, or `None` when the name is not one this
/// daemon minted.
///
/// The inverse of [`vm_scratch_dir_name`], and it proves itself against the forward composer rather
/// than trusting its own parse: a candidate `(pid, seq)` is accepted only if re-composing the name
/// reproduces it byte-for-byte. That is what keeps the two from drifting — and what makes an
/// unrelated directory (a stray file, a name from a future layout) *unparseable* and therefore
/// retained rather than deleted.
fn owning_pid(name: &str) -> Option<u32> {
    let mut tail = name.rsplitn(3, '-');
    let seq: u64 = tail.next()?.parse().ok()?;
    let pid: u32 = tail.next()?.parse().ok()?;
    (vm_scratch_dir_name(pid, seq) == name).then_some(pid)
}

/// Whether `pid` names a live process on this host.
///
/// `/proc/<pid>` rather than `kill(pid, 0)`: the daemon may be running with capabilities but the
/// question is only "does this pid exist", and a `procfs` lookup answers it without a signal.
fn pid_is_alive(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The guard OWNS the directory: it exists while held, and it — with every disk copy in it — is
    // gone after the drop. The residue shape AGENTS.md asks for: assert it existed FIRST, so a
    // guard that never created anything cannot pass vacuously.
    //
    // RED on the inverse: delete the `impl Drop for VmScratch` body.
    #[test]
    fn the_scratch_guard_removes_the_directory_and_its_copies() {
        let root = tempfile::tempdir().expect("tempdir");
        let base = scratch_base(root.path());
        let scratch = VmScratch::create(&base, 7).expect("create scratch");
        let path = scratch.path().to_path_buf();
        std::fs::write(path.join("0-data.img"), vec![0xAAu8; 1024]).expect("a disk copy");
        assert!(
            path.is_dir(),
            "the scratch dir exists while the VM holds it"
        );
        assert!(path.join("0-data.img").is_file(), "and holds the copy");

        drop(scratch);
        assert!(
            !path.exists(),
            "the scratch dir and its disk copies must be gone once the VM's handle is dropped"
        );
    }

    // Two VMs never share a scratch directory, whatever order their creates interleave in.
    #[test]
    fn per_vm_scratch_dirs_are_distinct() {
        let root = tempfile::tempdir().expect("tempdir");
        let base = scratch_base(root.path());
        let a = VmScratch::create(&base, 0).expect("a");
        let b = VmScratch::create(&base, 1).expect("b");
        assert_ne!(a.path(), b.path(), "two VMs get two directories");
        // Injectivity of the composer itself, on the axis a single sequence cannot show.
        assert_ne!(
            vm_scratch_dir_name(1, 23),
            vm_scratch_dir_name(12, 3),
            "the (pid, seq) name must be injective"
        );
    }

    // The reserved base is unnameable from the network: no client-supplied artifact name can
    // resolve into it, because the name predicate rejects a leading `.`. That is the whole security
    // argument for putting per-VM scratch inside the artifacts directory, so it is asserted against
    // the real predicate rather than assumed.
    //
    // RED on the inverse: rename `SCRATCH_DIR_NAME` to something without the leading dot.
    #[test]
    fn the_scratch_base_is_unnameable_from_the_network() {
        assert!(
            crate::name::validate_artifact_name(SCRATCH_DIR_NAME).is_err(),
            "a client must never be able to name the scratch base as an artifact"
        );
        assert!(
            SCRATCH_DIR_NAME.starts_with('.'),
            "the leading dot is what the name predicate rejects"
        );
        assert_eq!(
            scratch_base(Path::new("/srv/artifacts")),
            Path::new("/srv/artifacts").join(SCRATCH_DIR_NAME),
            "one layout composition, shared by the launcher and the store's accounting"
        );
    }

    // START-UP RECLAMATION: a directory whose owning daemon is gone is removed; one whose owner is
    // alive is RETAINED — reaping it would delete a running sibling's disk copies out from under a
    // live guest. A pid above the kernel's `pid_max` ceiling can never be live, so the dead leg is
    // deterministic rather than racy.
    //
    // RED on the inverse: drop the `pid_is_alive` check and the live daemon's directory is reaped
    // (the second assertion), or invert it and the dead one survives (the first).
    #[test]
    fn reclaim_removes_dead_owners_and_retains_live_ones() {
        let root = tempfile::tempdir().expect("tempdir");
        let base = scratch_base(root.path());
        let dead = base.join(vm_scratch_dir_name(u32::MAX, 0)); // above pid_max: never alive
        let live = base.join(vm_scratch_dir_name(live_sibling_pid(), 0));
        let foreign = base.join("someone-elses-directory");
        for d in [&dead, &live, &foreign] {
            std::fs::create_dir_all(d).expect("seed");
            std::fs::write(d.join("0-data.img"), b"copy").expect("seed a copy");
        }

        let report = reclaim_orphan_scratch(&base);
        assert!(!dead.exists(), "a dead daemon's scratch is reclaimed");
        assert!(live.is_dir(), "a LIVE daemon's scratch must be retained");
        assert!(
            foreign.is_dir(),
            "an unrecognized name is retained, never deleted on a guess"
        );
        assert_eq!(
            report.removed,
            vec![vm_scratch_dir_name(u32::MAX, 0)],
            "the report names exactly what it removed: {report:?}"
        );
        assert_eq!(report.retained.len(), 2, "and what it left: {report:?}");
    }

    /// A pid that is certainly alive and is not this process: our own parent, falling back to pid 1
    /// (always live). Not `std::process::id()` — the reclaimer treats its OWN pid as residue.
    fn live_sibling_pid() -> u32 {
        let ppid = std::os::unix::process::parent_id();
        if ppid > 1 && pid_is_alive(ppid) {
            ppid
        } else {
            1
        }
    }

    // The name inverse proves itself against the forward composer, so a name that merely LOOKS
    // parseable is not accepted. Without that check, `disks-007-1` (a zero-padded pid that
    // re-composes as `disks-7-1`) would parse, and the reclaimer would remove a directory it does
    // not own.
    #[test]
    fn only_names_the_composer_could_have_produced_are_ours() {
        assert_eq!(owning_pid(&vm_scratch_dir_name(4242, 9)), Some(4242));
        for foreign in [
            "disks-007-1",     // zero-padded: re-composes differently
            "disks-4242",      // too few components
            "vmcell-vm-100-3", // the library's per-VM scratch layout
            "disks-abc-1",     // non-numeric pid
            "disks-4242-x",    // non-numeric seq
            SCRATCH_DIR_NAME,  // the base itself
        ] {
            assert_eq!(
                owning_pid(foreign),
                None,
                "{foreign:?} is not a name this daemon mints; it must be retained"
            );
        }
    }

    // An absent base is the normal first-boot case: nothing to reclaim, no error, no directory
    // created as a side effect of asking.
    #[test]
    fn reclaiming_an_absent_base_is_a_no_op() {
        let root = tempfile::tempdir().expect("tempdir");
        let base = scratch_base(root.path());
        assert!(reclaim_orphan_scratch(&base).is_empty());
        assert!(!base.exists(), "asking must not create it");
    }
}
