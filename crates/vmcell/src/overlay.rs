//! The `OverlayStore` seam: how a suspend/snapshot directory is copy-on-write
//! cloned into a clone's own private copy (§8.4, The zygote fan-out and the OverlayStore seam).
//!
//! The zygote fan-out (§8.4, The zygote fan-out and the OverlayStore seam) and fork/branch lineage (§8.5, Lineage: fork and branch) mint clones by
//! copy-on-write-copying a suspend directory and restoring each private copy.
//! That copy is the one clone-materialization step, and this module makes it an
//! **injectable seam** — a trait with a production implementation and a recording
//! test double — exactly like [`CgroupFs`](crate::metrics::CgroupFs), `Netlink`,
//! and the daemon's `VmEngine`. Before this seam the
//! copy was a bare free function the orchestrator called directly, so the CoW path
//! could only be exercised by actually reflinking on a real filesystem and there
//! was no injection point for an alternative store.
//!
//! **Scope: the suspend directory, not a rootfs disk.** A snapshot-eligible VM has
//! a shared erofs read-only rootfs base (no per-VM copy) plus a fresh in-guest
//! tmpfs overlay (§4.1, The erofs read-only base + tmpfs overlay); the only per-clone writable host state is the suspend
//! directory (the guest-RAM memory file + the backend's `config.json`/sidecar). So
//! this seam is scoped precisely to CoW-cloning **that** directory. It deliberately
//! does not reach into per-backend block-device attachment.
//!
//! **Two doors, one seam.** [`OverlayStore::clone_tree`] takes a directory;
//! [`OverlayStore::clone_file`] takes a single regular file. The second exists because
//! the other thing a caller copy-on-write-copies is *one artifact file*: the daemon's
//! writable-scratch extra disk, copied on attach out of the create-only store (§11.5,
//! The HTTP REST API and its OpenAPI document). That artifact sits in the store
//! directory beside every other artifact, so there is no directory to hand
//! `clone_tree` — and cloning the store directory to materialize one disk would copy
//! the whole store. Both doors are on **this** trait rather than beside it, because
//! S4 (§13, Cross-cutting invariants) says every copy-on-write clone materializes
//! through `env.overlay`; a file-level copy reached around the seam would be the
//! second injection path S4 exists to forbid.

use crate::error::{Error, Result};
use crate::reflink::{CowSupport, clone_file_cow_blocking, clone_tree_cow_blocking, probe_reflink};
use std::path::Path;

/// How a snapshot/suspend directory is copy-on-write cloned into a clone's own
/// private, independent copy.
///
/// The one seam every copy-on-write restore path materializes a clone through
/// (§13, Cross-cutting invariants). Implementors clone a directory tree such that the copy is a faithful,
/// **independent** copy — writing the copy never touches the source (the master),
/// which is the §13 (Cross-cutting invariants) immutability contract — and report whether the copy was a
/// cheap block-level reflink or a full byte copy ([`CowSupport`]).
///
/// The methods are **synchronous** so the trait is object-safe as
/// `Arc<dyn OverlayStore>`; a potentially large [`clone_tree`](OverlayStore::clone_tree)
/// is run on a blocking thread by the orchestrator (`spawn_blocking`) so it never
/// stalls the async runtime — the same discipline the bare function used, now at
/// the seam boundary.
pub trait OverlayStore: Send + Sync + std::fmt::Debug {
    /// Copy-on-write-clones the directory tree at `src` into a fresh private copy
    /// at `dst`.
    ///
    /// `dst` must not already exist; it (and any needed parents) are created. The
    /// clone is a faithful, independent copy: mutating it never touches `src`.
    ///
    /// # Errors
    /// Fails if `src` is not a readable directory, `dst` already exists or cannot
    /// be created, or any entry copy fails.
    fn clone_tree(&self, src: &Path, dst: &Path) -> Result<CowSupport>;

    /// Copy-on-write-clones the single regular **file** at `src` into a fresh private
    /// copy at `dst` — the file-level door beside [`clone_tree`](OverlayStore::clone_tree).
    ///
    /// `dst` must not already exist; its parent directory is created if needed. The
    /// copy is a faithful, independent copy: mutating it never touches `src`. That is
    /// the whole contract a *writable-scratch extra disk* rests on — `src` is an
    /// immutable, create-only store artifact that other cells may be reading, and the
    /// guest writes `dst` (§11.5, The HTTP REST API and its OpenAPI document).
    ///
    /// The returned [`CowSupport`] is honest about which it was: a host filesystem
    /// without reflink still gets a correct writable copy, it just paid a byte copy for
    /// it, and the caller is told rather than left to assume.
    ///
    /// # Errors
    /// Fails if `src` is not a readable regular file, `dst` already exists or cannot be
    /// created, or the copy fails. The **default** implementation refuses with
    /// [`Error::CapabilityUnavailable`]: an injected store that materializes clones some
    /// other way and has not been taught this door has no file-level copy to offer, and
    /// §7.2 (The fail-loud capability contract and `HostCapabilities`) asks an absent
    /// facility to say so in a typed refusal rather than to improvise one — improvising
    /// here means reaching around the store to the host filesystem, which is exactly the
    /// second materialization path S4 forbids.
    fn clone_file(&self, src: &Path, dst: &Path) -> Result<CowSupport> {
        Err(Error::CapabilityUnavailable {
            op: format!(
                "OverlayStore::clone_file: copy-on-write clone of {} into {}",
                src.display(),
                dst.display()
            ),
            needed: format!(
                "an OverlayStore that implements clone_file; {self:?} provides the directory-level \
                 clone_tree only"
            ),
        })
    }

    /// Best-effort probe of whether `dir`'s filesystem gives cheap block-level
    /// copy-on-write, for an up-front cost signal before minting a pool.
    ///
    /// `dir` itself is never written to; any uncertainty is reported as
    /// [`CowSupport::FullCopy`].
    ///
    /// **This is the one entry point for that cost signal** (§8.4, The zygote fan-out
    /// and the `OverlayStore` seam: "a caller wanting an up-front CoW cost signal
    /// probes directly: `env.overlay.probe(zygote.master_dir())`"). The answer is a
    /// property of the *store*, not only of the host filesystem — a store that
    /// materializes clones some other way answers for what **it** would do — so
    /// asking the filesystem behind an injected store's back is a lie by
    /// construction (docs/78 `overlay-probe-not-side-effect-free`, seam half).
    /// [`Zygote::probe_cow_support_in`](crate::Zygote::probe_cow_support_in) is the
    /// packaged call.
    fn probe(&self, dir: &Path) -> CowSupport;
}

/// The production [`OverlayStore`]: reflink (block-level copy-on-write) where the
/// host filesystem supports it (XFS / Btrfs / bcachefs → `FICLONE`), full byte
/// copy otherwise (ext4 / tmpfs / cross-filesystem).
///
/// Wraps the crate's internal `reflink` primitive, which owns the single
/// `FICLONE` ioctl inside the vetted, permissively-licensed `reflink-copy` crate,
/// so no `unsafe` enters the tree.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReflinkOverlayStore;

impl OverlayStore for ReflinkOverlayStore {
    fn clone_tree(&self, src: &Path, dst: &Path) -> Result<CowSupport> {
        clone_tree_cow_blocking(src, dst)
    }

    fn clone_file(&self, src: &Path, dst: &Path) -> Result<CowSupport> {
        clone_file_cow_blocking(src, dst)
    }

    fn probe(&self, dir: &Path) -> CowSupport {
        probe_reflink(dir)
    }
}

/// A recording [`OverlayStore`] test double: records every `(src, dst)` it is asked
/// to clone and returns a configurable [`CowSupport`], so a test can prove a
/// restore path materializes each clone through the seam into a **private** `dst`
/// (never the master) with no reflink filesystem and no VMM (§13, Cross-cutting invariants).
///
/// Not part of the public API (crate-visible under `cfg(test)` only), matching the
/// recording-double convention used for the other seams.
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct RecordingOverlayStore {
    /// Every `(src, dst)` pair passed to [`OverlayStore::clone_tree`], in order.
    clones: std::sync::Arc<std::sync::Mutex<Vec<(std::path::PathBuf, std::path::PathBuf)>>>,
    /// Every `(src, dst)` pair passed to [`OverlayStore::clone_file`], in order — kept
    /// **separate** from `clones` so a test can tell which door a caller went through.
    /// The two doors copy different shapes for different reasons (a suspend directory vs
    /// one store artifact), so a single merged log could not distinguish "materialized
    /// one writable disk" from "cloned the whole store directory".
    file_clones: std::sync::Arc<std::sync::Mutex<Vec<(std::path::PathBuf, std::path::PathBuf)>>>,
    /// Every `dir` passed to [`OverlayStore::probe`], in order. Recorded for the same
    /// reason `clones` is: an equality assertion on the returned [`CowSupport`] alone
    /// cannot tell "the seam answered" from "the host filesystem happens to agree",
    /// and the routing is exactly what docs/78 `overlay-probe-not-side-effect-free`
    /// (seam half) left unproven.
    probes: std::sync::Arc<std::sync::Mutex<Vec<std::path::PathBuf>>>,
    /// The [`CowSupport`] to report from both methods.
    report: CowSupport,
}

#[cfg(test)]
impl RecordingOverlayStore {
    /// A recording store that reports [`CowSupport::Reflink`].
    pub(crate) fn new() -> Self {
        Self::with_report(CowSupport::Reflink)
    }

    /// A recording store that reports the given [`CowSupport`].
    pub(crate) fn with_report(report: CowSupport) -> Self {
        Self {
            clones: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            file_clones: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            probes: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            report,
        }
    }

    /// The recorded `(src, dst)` clone requests, in order.
    pub(crate) fn calls(&self) -> Vec<(std::path::PathBuf, std::path::PathBuf)> {
        self.clones
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The recorded [`OverlayStore::clone_file`] `(src, dst)` requests, in order.
    pub(crate) fn file_calls(&self) -> Vec<(std::path::PathBuf, std::path::PathBuf)> {
        self.file_clones
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The recorded [`OverlayStore::probe`] requests, in order.
    pub(crate) fn probe_calls(&self) -> Vec<std::path::PathBuf> {
        self.probes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[cfg(test)]
impl OverlayStore for RecordingOverlayStore {
    fn clone_tree(&self, src: &Path, dst: &Path) -> Result<CowSupport> {
        // Materialize an empty `dst` so downstream code that expects the clone
        // directory to exist is satisfied, without doing a real copy (the point of
        // the double is to prove the SEAM is called, not to copy bytes).
        std::fs::create_dir_all(dst).map_err(crate::error::Error::Io)?;
        self.clones
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((src.to_path_buf(), dst.to_path_buf()));
        Ok(self.report)
    }

    fn clone_file(&self, src: &Path, dst: &Path) -> Result<CowSupport> {
        // Materialize an EMPTY `dst` file (and its parent) for the same reason `clone_tree`
        // materializes an empty directory: downstream code that expects the copy to exist is
        // satisfied without copying bytes, because the point of the double is to prove the SEAM was
        // called. A test that cares about the bytes uses `ReflinkOverlayStore` — it needs no KVM.
        if let Some(parent) = dst.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(crate::error::Error::Io)?;
        }
        std::fs::write(dst, b"").map_err(crate::error::Error::Io)?;
        self.file_clones
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((src.to_path_buf(), dst.to_path_buf()));
        Ok(self.report)
    }

    fn probe(&self, dir: &Path) -> CowSupport {
        self.probes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(dir.to_path_buf());
        self.report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The production store makes a FAITHFUL, INDEPENDENT copy: writing the clone
    // must not mutate the master (the §13 (Cross-cutting invariants) immutability contract routed through
    // the seam). The inverse — a store that hardlinks/shares the inode — reddens
    // because mutating the clone changes the master's bytes.
    #[test]
    fn reflink_store_clone_tree_is_faithful_and_independent() {
        let root = tempfile::tempdir().expect("tempdir");
        let master = root.path().join("master");
        std::fs::create_dir_all(&master).expect("mk master");
        std::fs::write(master.join("config.json"), b"{\"vsock\":1}").expect("cfg");
        std::fs::write(master.join("mem_file"), vec![0xABu8; 4096]).expect("mem");

        let store = ReflinkOverlayStore;
        let clone = root.path().join("clone");
        let support = store.clone_tree(&master, &clone).expect("clone_tree");
        assert!(matches!(
            support,
            CowSupport::Reflink | CowSupport::FullCopy
        ));
        assert_eq!(
            std::fs::read(clone.join("config.json")).expect("read clone cfg"),
            b"{\"vsock\":1}"
        );

        // Mutate the clone; the master must be untouched (independence).
        std::fs::write(clone.join("config.json"), b"{\"vsock\":2}").expect("rewrite clone");
        assert_eq!(
            std::fs::read(master.join("config.json")).expect("read master cfg"),
            b"{\"vsock\":1}",
            "writing the clone must not mutate the master (§13, Cross-cutting invariants), even through the seam"
        );
    }

    // The store's `probe` must AGREE with what its `clone_tree` actually does on the
    // same filesystem (delegates to the same reflink logic). A store whose probe
    // disagrees with its clone would misreport a pool's cost.
    #[test]
    fn reflink_store_probe_agrees_with_clone() {
        let root = tempfile::tempdir().expect("tempdir");
        let master = root.path().join("m");
        std::fs::create_dir_all(&master).expect("mk master");
        std::fs::write(master.join("f"), vec![0x5Au8; 4096]).expect("f");
        let store = ReflinkOverlayStore;
        let clone_support = store
            .clone_tree(&master, &root.path().join("c"))
            .expect("clone");
        let probe_support = store.probe(root.path());
        assert_eq!(
            clone_support, probe_support,
            "the store's probe must report the same CoW support its clone gets on this fs"
        );
    }

    // The recording double records each (src, dst) and honors its configured
    // report, so a test can assert on the seam without a real copy.
    #[test]
    fn recording_store_records_src_dst_and_reports() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = RecordingOverlayStore::with_report(CowSupport::FullCopy);
        let src = root.path().join("src");
        std::fs::create_dir_all(&src).expect("mk src");
        let dst = root.path().join("dst");
        let got = store.clone_tree(&src, &dst).expect("clone_tree");
        assert_eq!(
            got,
            CowSupport::FullCopy,
            "must honor the configured report"
        );
        assert!(dst.is_dir(), "the double materializes an empty dst dir");
        let calls = store.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], (src, dst), "must record the exact (src, dst)");
    }

    // The double records the exact `dir` each `probe` asked about — the observation a
    // routing gate needs (docs/78 `overlay-probe-not-side-effect-free`, seam half): the
    // returned `CowSupport` alone cannot distinguish "the seam answered" from "the host
    // filesystem happened to agree". A double whose `probe` returns its report without
    // recording (the pre-fix `fn probe(&self, _dir: &Path)`) reddens here.
    #[test]
    fn recording_store_records_probe_dirs() {
        let store = RecordingOverlayStore::with_report(CowSupport::Reflink);
        assert!(
            store.probe_calls().is_empty(),
            "a fresh double has probed nothing"
        );
        let dir = Path::new("/nonexistent/zygote-master");
        assert_eq!(
            store.probe(dir),
            CowSupport::Reflink,
            "probe must honor the configured report"
        );
        assert_eq!(
            store.probe_calls(),
            vec![dir.to_path_buf()],
            "must record the exact probed dir, once"
        );
    }

    // THE FILE-LEVEL DOOR through the seam (§11.5, the daemon's copy-on-attach writable scratch
    // disk): the production store's `clone_file` produces a faithful, INDEPENDENT copy, so a guest
    // writing its private copy cannot reach the create-only store artifact behind it. RED on the
    // inverse — a `clone_file` that hardlinks, or one that hands the source path straight back
    // instead of copying — because the artifact's bytes move under it.
    #[test]
    fn reflink_store_clone_file_is_faithful_and_independent() {
        let root = tempfile::tempdir().expect("tempdir");
        let artifact = root.path().join("data.img");
        std::fs::write(&artifact, b"store-artifact-bytes").expect("seed artifact");

        let store = ReflinkOverlayStore;
        let copy = root.path().join("vm-scratch").join("0-data.img");
        let support = store.clone_file(&artifact, &copy).expect("clone_file");
        assert!(matches!(
            support,
            CowSupport::Reflink | CowSupport::FullCopy
        ));
        assert_eq!(
            std::fs::read(&copy).expect("read copy"),
            b"store-artifact-bytes"
        );

        std::fs::write(&copy, b"the guest wrote here").expect("write copy");
        assert_eq!(
            std::fs::read(&artifact).expect("read artifact"),
            b"store-artifact-bytes",
            "writing the copy must not mutate the store artifact (§11.5), even through the seam"
        );
    }

    // The two doors answer about the SAME filesystem, so they must agree — a store whose file door
    // reported `Reflink` while its tree door paid full copies would misprice a pool of writable
    // scratch disks. This is the seam-level half of `reflink.rs`'s own agreement gate: exactly one
    // of the two hardcoding inverses (`Ok(Reflink)` / `Ok(FullCopy)`) goes red on any given host.
    #[test]
    fn reflink_store_both_doors_report_the_same_support() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = root.path().join("d");
        std::fs::create_dir_all(&dir).expect("mk dir");
        std::fs::write(dir.join("f"), vec![0x5Au8; 4096]).expect("f");
        let store = ReflinkOverlayStore;
        assert_eq!(
            store
                .clone_file(&dir.join("f"), &root.path().join("f-copy"))
                .expect("clone_file"),
            store
                .clone_tree(&dir, &root.path().join("d-copy"))
                .expect("clone_tree"),
            "one filesystem, one answer: the file and directory doors must not disagree"
        );
        assert_eq!(
            store.probe(root.path()),
            store
                .clone_file(&dir.join("f"), &root.path().join("f-copy-2"))
                .expect("clone_file"),
            "and the up-front cost signal must match what the file door then does"
        );
    }

    // A DIRECTORY handed to the file door is a typed refusal, not a silent empty copy — the mirror
    // of `clone_tree`'s not-a-directory arm. RED on the inverse (drop `clone_file_cow_blocking`'s
    // `is_file` guard and let the copy primitive answer): the refusal stops naming the contract it
    // broke.
    #[test]
    fn reflink_store_clone_file_rejects_a_directory() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = root.path().join("a-dir");
        std::fs::create_dir_all(&dir).expect("mk dir");
        let err = ReflinkOverlayStore
            .clone_file(&dir, &root.path().join("out.img"))
            .expect_err("a directory is not a file");
        assert!(
            err.to_string().contains("not a regular file"),
            "the refusal must name what was wrong: {err}"
        );
    }

    // THE DEFAULT ARM (§7.2, The fail-loud capability contract and HostCapabilities): a store that
    // implements only the directory door refuses the file door with a TYPED capability error naming
    // the store and the copy it was asked for — it never improvises by reaching around itself to
    // the host filesystem, which is the second materialization path S4 forbids.
    //
    // RED on the inverse: give the default body `clone_file_cow_blocking(src, dst)` — an injected
    // store's clone would then silently become a real host reflink, and this assertion (which
    // demands a refusal, and that no file appeared at `dst`) fails on both halves.
    #[test]
    fn the_default_file_door_is_a_typed_capability_refusal() {
        /// A store with the pre-`clone_file` shape: the directory door only.
        #[derive(Debug)]
        struct TreeOnlyStore;
        impl OverlayStore for TreeOnlyStore {
            fn clone_tree(&self, src: &Path, dst: &Path) -> Result<CowSupport> {
                clone_tree_cow_blocking(src, dst)
            }
            fn probe(&self, _dir: &Path) -> CowSupport {
                CowSupport::FullCopy
            }
        }

        let root = tempfile::tempdir().expect("tempdir");
        let src = root.path().join("data.img");
        std::fs::write(&src, b"bytes").expect("src");
        let dst = root.path().join("copy.img");
        let err = TreeOnlyStore
            .clone_file(&src, &dst)
            .expect_err("a tree-only store has no file door");
        assert!(
            matches!(err, crate::error::Error::CapabilityUnavailable { .. }),
            "an absent facility is a typed capability refusal, not an Io error: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("TreeOnlyStore") && msg.contains("clone_file"),
            "the refusal must name the store and the door: {msg}"
        );
        assert!(
            !dst.exists(),
            "a refusing store must not have materialized anything"
        );
    }

    // The double records each file-clone `(src, dst)` in its OWN log, so a test can tell which door
    // a caller took. A double that logged both doors into `clones` would let a caller that cloned
    // the whole store directory pass an assertion written for one writable disk.
    #[test]
    fn recording_store_records_file_clones_separately() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = RecordingOverlayStore::with_report(CowSupport::FullCopy);
        let src = root.path().join("data.img");
        std::fs::write(&src, b"bytes").expect("src");
        let dst = root.path().join("scratch").join("0-data.img");
        assert_eq!(
            store.clone_file(&src, &dst).expect("clone_file"),
            CowSupport::FullCopy,
            "must honor the configured report"
        );
        assert!(dst.is_file(), "the double materializes an empty dst file");
        assert_eq!(
            store.file_calls(),
            vec![(src, dst)],
            "must record the exact (src, dst) on the file log"
        );
        assert!(
            store.calls().is_empty(),
            "and must not have logged it as a directory clone"
        );
    }
}
