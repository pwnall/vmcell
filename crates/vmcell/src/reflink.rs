//! Copy-on-write cloning of zygote suspend images (§8.4, The zygote fan-out and the OverlayStore seam).
//!
//! The zygote fan-out (§8.4, The zygote fan-out and the OverlayStore seam) mints many identical VMs from one suspended
//! **zygote** image by copy-on-write-copying its suspend/resume data per clone
//! and restoring each private copy. On a reflink-capable host filesystem (XFS,
//! Btrfs, bcachefs) the copy is a near-instant block-level `FICLONE` that shares
//! physical storage with the master until a clone writes; on any other
//! filesystem (ext4, tmpfs) it degrades to a full byte copy — correct, just not
//! free. Reflinking is what makes an N-VM warm pool cost ≈N×dirtied pages
//! instead of N×guest-RAM on disk (§8.3, Density levers).
//!
//! Making each clone restore from its **own** copy is also what un-breaks the
//! single-use snapshot: the CH backend rewrites `config.json` in place per
//! restore and FC reads a per-dir sidecar, so two restores from one shared dir
//! race and corrupt it (§8.1, The warm-snapshot path and the eligibility law). A per-clone copy removes the race *and* keeps the
//! zygote master immutable (§13, Cross-cutting invariants) — the copy diverges, the master never does.

// The one unsafe operation this needs — the `FICLONE` ioctl — lives inside the
// vetted, permissively-licensed `reflink-copy` crate, which also owns the
// full-copy fallback. So this module stays safe by construction, like `net/`.
#![forbid(unsafe_code)]

use crate::error::{Error, Result};
use std::io;
use std::path::Path;

/// Whether a zygote clone copy used block-level reflink (copy-on-write) or a
/// full byte copy.
///
/// Reported for observability: a `FullCopy` pool over a large guest-RAM image is
/// materially more expensive (both time and disk) than a `Reflink` one, so a
/// caller building a big warm pool on a non-reflink filesystem can warn or pick
/// a different scratch location (§8.4, The zygote fan-out and the OverlayStore seam).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CowSupport {
    /// The host filesystem supports reflink; each copy shares storage with the
    /// master until written (XFS / Btrfs / bcachefs).
    Reflink,
    /// The host filesystem does not support reflink; each clone paid a full byte
    /// copy of the suspend image (ext4 / tmpfs / cross-filesystem).
    FullCopy,
}

impl CowSupport {
    /// Returns `true` when the copy was a zero-on-disk block-level reflink.
    #[must_use]
    pub fn is_reflink(self) -> bool {
        matches!(self, CowSupport::Reflink)
    }

    /// Folds another file's outcome into this one: a directory is `Reflink` only
    /// if **every** file in it reflinked; a single full copy makes the aggregate
    /// `FullCopy`.
    #[must_use]
    fn merge(self, other: CowSupport) -> CowSupport {
        match (self, other) {
            (CowSupport::Reflink, CowSupport::Reflink) => CowSupport::Reflink,
            _ => CowSupport::FullCopy,
        }
    }
}

/// Copy-on-write-clones the directory tree at `src` into `dst`.
///
/// `dst` must not already exist; it (and any needed parents) are created. Every
/// regular file is reflinked where the filesystem supports it and full-copied
/// otherwise (via [`reflink_copy::reflink_or_copy`]), so the clone is always a
/// faithful, independent copy — writing to it never touches the master, which is
/// the zygote-immutability contract (§13, Cross-cutting invariants). Subdirectories are recreated and
/// symlinks are recreated as symlinks; the flat CH/FC snapshot dirs contain
/// neither, but the walk is robust to both. Special files (sockets/fifos) are
/// skipped — a snapshot dir never contains one.
///
/// Returns the aggregate [`CowSupport`]: `Reflink` only if every regular file in
/// the tree reflinked.
///
/// This is the low-level primitive behind [`ReflinkOverlayStore`](crate::overlay::ReflinkOverlayStore).
/// It runs synchronously and may do a large byte copy, so callers invoke it on a
/// blocking thread — the [`OverlayStore`](crate::overlay::OverlayStore) seam call
/// is wrapped in `spawn_blocking` by the orchestrator. Kept unit-testable without
/// a tokio runtime.
///
/// # Errors
/// [`Error::Io`] if `src` is not a readable directory, `dst` already exists or
/// cannot be created, or any entry copy fails. A `src`/`dst` split across two
/// filesystems still succeeds via the full-copy fallback (`FICLONE` `EXDEV` is
/// not surfaced as an error); only a genuine I/O failure fails.
pub(crate) fn clone_tree_cow_blocking(src: &Path, dst: &Path) -> Result<CowSupport> {
    if dst.exists() {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("zygote clone target already exists: {}", dst.display()),
        )));
    }
    let meta = std::fs::metadata(src).map_err(Error::Io)?;
    if !meta.is_dir() {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("zygote master is not a directory: {}", src.display()),
        )));
    }
    std::fs::create_dir_all(dst).map_err(Error::Io)?;

    // Empty-tree identity is `Reflink` (vacuously); a real snapshot dir always
    // has files, so a `FullCopy` result means a file genuinely fell back.
    let mut support = CowSupport::Reflink;
    for entry in walkdir::WalkDir::new(src).min_depth(1).follow_links(false) {
        let entry = entry.map_err(|e| {
            Error::Io(
                e.into_io_error()
                    .unwrap_or_else(|| io::Error::other("walkdir error traversing zygote master")),
            )
        })?;
        let rel = entry.path().strip_prefix(src).map_err(|e| {
            Error::Io(io::Error::other(format!(
                "strip_prefix under zygote master: {e}"
            )))
        })?;
        let target = dst.join(rel);
        let ft = entry.file_type();
        if ft.is_dir() {
            std::fs::create_dir_all(&target).map_err(Error::Io)?;
        } else if ft.is_symlink() {
            let link = std::fs::read_link(entry.path()).map_err(Error::Io)?;
            std::os::unix::fs::symlink(&link, &target).map_err(Error::Io)?;
        } else if ft.is_file() {
            // `reflink_or_copy` returns `None` for a block-level reflink and
            // `Some(bytes)` when it fell back to a full copy. Both are success;
            // only a real I/O error fails the clone.
            match reflink_copy::reflink_or_copy(entry.path(), &target).map_err(Error::Io)? {
                None => {}
                Some(_bytes) => support = support.merge(CowSupport::FullCopy),
            }
        }
        // else: sockets/fifos/etc. — not present in snapshot dirs; skip.
    }
    Ok(support)
}

/// Probes whether `dir`'s filesystem supports reflink, by reflinking a tiny
/// sentinel file inside a private **sibling scratch directory** (never inside
/// `dir` itself) and observing the outcome.
///
/// Best-effort: the scratch dir and both sentinels are removed before return, and
/// any I/O error is treated as "reflink unconfirmed" ⇒ [`CowSupport::FullCopy`].
/// Useful for an up-front signal ("this pool will be cheap / expensive") without
/// having to mint a clone first. The scratch name embeds the pid and a per-process
/// counter so concurrent probes — from sibling processes or from sibling threads —
/// do not collide.
///
/// **The probed directory is never written to** (docs/78
/// `overlay-probe-not-side-effect-free`). Its one production caller probes a
/// zygote *master*, which §13 (Cross-cutting invariants) declares immutable: the
/// pre-fix probe wrote its sentinels straight into that master, so it reported
/// `FullCopy` on a read-only master (the write failed, and "uncertain" is
/// `FullCopy`), and its create/unlink pair raced a concurrent fan-out's
/// [`clone_tree_cow_blocking`] tree walk. The scratch lives one level up because
/// the reflink answer is a property of the **filesystem**, not the directory —
/// and [`same_filesystem`] proves the sibling really is on it, so the answer that
/// comes back is still `dir`'s.
#[must_use]
pub(crate) fn probe_reflink(dir: &Path) -> CowSupport {
    probe_reflink_inner(dir).unwrap_or(CowSupport::FullCopy)
}

/// The fallible body of [`probe_reflink`], separated so every failure mode funnels
/// through one "reflink unconfirmed ⇒ `FullCopy`" collapse in the caller instead of
/// being swallowed arm by arm.
fn probe_reflink_inner(dir: &Path) -> io::Result<CowSupport> {
    // No usable sibling location (`dir` is a filesystem root, or a bare relative name whose
    // parent is `""`) ⇒ unconfirmed. Falling back to probing INSIDE `dir` is exactly the
    // behavior being removed, so there is no fallback: an unconfirmed probe is `FullCopy`.
    let parent = dir
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| {
            io::Error::other(format!(
                "no sibling scratch location beside {} for the reflink probe",
                dir.display()
            ))
        })?;
    // A sibling on a DIFFERENT filesystem answers a different question (`dir` is a mount
    // point). Report unconfirmed rather than a confidently wrong `Reflink`.
    if !same_filesystem(dir, parent)? {
        return Err(io::Error::other(format!(
            "{} is a mount point; its parent is a different filesystem",
            dir.display()
        )));
    }

    // pid disambiguates sibling processes; the counter disambiguates sibling threads in this
    // one (the seam is `Sync`, and a warm-pool builder may probe from several).
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0); // allow-global-state: fn-local monotonic name disambiguator for the probe scratch dir; holds no borrowed state and is never read back, so there is nothing for a seam to inject (rubric B6's "justify" arm)
    let scratch = parent.join(format!(
        ".vmcell-cow-probe-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    // A leftover scratch from a crashed prior probe (same pid after a wrap) would make the
    // `reflink` below fail spuriously; clear it first. Only `NotFound` is "nothing to clear".
    match std::fs::remove_dir_all(&scratch) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    std::fs::create_dir(&scratch)?;

    let outcome = (|| -> io::Result<CowSupport> {
        let src = scratch.join("src");
        let dst = scratch.join("dst");
        std::fs::write(&src, b"vmcell-cow-probe")?;
        Ok(match reflink_copy::reflink(&src, &dst) {
            Ok(()) => CowSupport::Reflink,
            Err(_) => CowSupport::FullCopy,
        })
    })();
    // The scratch dir is this probe's alone, so a whole-tree removal is exact, not scope creep.
    // A failed cleanup does not invalidate the answer — but it does leave residue beside a
    // zygote master, so it is logged rather than discarded (no bare `let _ =` on a Result).
    if let Err(e) = std::fs::remove_dir_all(&scratch) {
        tracing::warn!(
            scratch = %scratch.display(),
            error = %e,
            "failed to remove the reflink-probe scratch dir"
        );
    }
    outcome
}

/// Whether `a` and `b` live on the same filesystem (same `st_dev`).
///
/// The correctness anchor for probing a sibling: reflink support is a filesystem property, so a
/// scratch dir that is *not* on the probed directory's filesystem would answer about the wrong one.
fn same_filesystem(a: &Path, b: &Path) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    Ok(std::fs::metadata(a)?.dev() == std::fs::metadata(b)?.dev())
}

#[cfg(test)]
mod tests {
    use super::*;

    // A clone must be a FAITHFUL, INDEPENDENT copy: same tree, same bytes, and a
    // later write to the clone must NOT touch the master (the zygote-immutability
    // contract, §13, Cross-cutting invariants). The inverse — a clone that hardlinks/shares the inode —
    // goes red here because mutating the clone changes the master's bytes.
    #[tokio::test]
    async fn clone_tree_is_faithful_and_independent() {
        let root = tempfile::tempdir().expect("tempdir");
        let master = root.path().join("zygote");
        std::fs::create_dir_all(master.join("sub")).expect("mk master");
        std::fs::write(master.join("config.json"), b"{\"vsock\":1}").expect("cfg");
        // Stand in for the memory file with some non-trivial bytes.
        std::fs::write(master.join("mem_file"), vec![0xABu8; 4096]).expect("mem");
        std::fs::write(master.join("sub/state"), b"frozen").expect("state");

        let clone = root.path().join("clone");
        let support = clone_tree_cow_blocking(&master, &clone).expect("clone");
        // Depending on the test filesystem this is Reflink or FullCopy — both are
        // valid; we only require a faithful copy, asserted next.
        assert!(matches!(
            support,
            CowSupport::Reflink | CowSupport::FullCopy
        ));

        assert_eq!(
            std::fs::read(clone.join("config.json")).expect("read cfg"),
            b"{\"vsock\":1}"
        );
        assert_eq!(
            std::fs::read(clone.join("mem_file"))
                .expect("read mem")
                .len(),
            4096
        );
        assert_eq!(
            std::fs::read(clone.join("sub/state")).expect("read state"),
            b"frozen"
        );

        // Mutate the clone; the master must be untouched (independence).
        std::fs::write(clone.join("config.json"), b"{\"vsock\":2}").expect("rewrite clone");
        assert_eq!(
            std::fs::read(master.join("config.json")).expect("read master cfg"),
            b"{\"vsock\":1}",
            "writing the clone must not mutate the zygote master (immutability, §13, Cross-cutting invariants)"
        );
    }

    // A missing master is a hard error, never a silently-empty clone.
    #[tokio::test]
    async fn clone_tree_rejects_missing_master() {
        let root = tempfile::tempdir().expect("tempdir");
        let res = clone_tree_cow_blocking(&root.path().join("nope"), &root.path().join("out"));
        assert!(
            matches!(res, Err(Error::Io(_))),
            "missing master must Io-error"
        );
    }

    // A pre-existing target is a hard error — clones never overwrite/merge into a
    // dir that may belong to a live sibling.
    #[tokio::test]
    async fn clone_tree_rejects_existing_target() {
        let root = tempfile::tempdir().expect("tempdir");
        let master = root.path().join("z");
        std::fs::create_dir_all(&master).expect("mk");
        std::fs::write(master.join("f"), b"x").expect("f");
        let target = root.path().join("t");
        std::fs::create_dir_all(&target).expect("pre-existing target");
        let res = clone_tree_cow_blocking(&master, &target);
        assert!(
            matches!(res, Err(Error::Io(ref e)) if e.kind() == io::ErrorKind::AlreadyExists),
            "existing target must be rejected, got {res:?}"
        );
    }

    // `merge` is the aggregate law: any single full copy taints the whole tree to
    // `FullCopy`; all-reflink stays `Reflink`. Its inverse (returning Reflink when
    // a file fell back) would misreport a pool's cost.
    #[test]
    fn cow_support_merge_law() {
        assert_eq!(
            CowSupport::Reflink.merge(CowSupport::Reflink),
            CowSupport::Reflink
        );
        assert_eq!(
            CowSupport::Reflink.merge(CowSupport::FullCopy),
            CowSupport::FullCopy
        );
        assert_eq!(
            CowSupport::FullCopy.merge(CowSupport::Reflink),
            CowSupport::FullCopy
        );
        assert!(CowSupport::Reflink.is_reflink());
        assert!(!CowSupport::FullCopy.is_reflink());
    }

    /// Every `(name, bytes)` pair directly under `dir`, sorted — a byte-exact fingerprint of a
    /// directory's contents for the probe's "touches nothing" assertions below.
    fn dir_fingerprint(dir: &Path) -> Vec<(std::ffi::OsString, Vec<u8>)> {
        let mut out: Vec<_> = std::fs::read_dir(dir)
            .expect("read_dir")
            .map(|e| {
                let e = e.expect("dir entry");
                let bytes = std::fs::read(e.path()).unwrap_or_default();
                (e.file_name(), bytes)
            })
            .collect();
        out.sort();
        out
    }

    // The probe is side-effect-free in BOTH directories it can reach: the probed dir (never
    // written) and the sibling parent that holds the scratch (written, then fully removed).
    // RED on an inverse that leaks the scratch dir (drop the second `remove_dir_all`).
    #[test]
    fn probe_leaves_no_residue() {
        let root = tempfile::tempdir().expect("tempdir");
        let probed = root.path().join("probed");
        std::fs::create_dir_all(&probed).expect("mk probed");
        let before_probed = dir_fingerprint(&probed);
        let before_parent = dir_fingerprint(root.path());
        let _ = probe_reflink(&probed);
        assert_eq!(
            before_probed,
            dir_fingerprint(&probed),
            "probe must leave no residue in the probed dir"
        );
        assert_eq!(
            before_parent,
            dir_fingerprint(root.path()),
            "probe must leave no residue in the sibling parent that holds its scratch"
        );
    }

    // docs/78 GATE (`overlay-probe-not-side-effect-free`): the probed directory is the IMMUTABLE
    // zygote master (§13, Cross-cutting invariants) — the probe may not create, overwrite, or
    // unlink ANY name in it. A post-hoc listing alone cannot see the pre-fix behavior (it removed
    // its own sentinels), so the master is pre-seeded with files carrying exactly the sentinel
    // names the pre-fix probe used, making both halves of its write/unlink pair observable:
    // unprivileged it fails the write (EACCES on a 0o444 file) and then UNLINKS the seeds (unlink
    // needs write on the DIR, which it has); as root it overwrites their bytes and then unlinks
    // them. Either way the byte-exact fingerprint below changes ⇒ RED on the inverse
    // (`probe_reflink` writing `dir.join(...)`), on any uid and any filesystem.
    #[test]
    fn probe_never_touches_the_probed_dir() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().expect("tempdir");
        let master = root.path().join("zygote");
        std::fs::create_dir_all(&master).expect("mk master");
        std::fs::write(master.join("config.json"), b"{\"vsock\":1}").expect("cfg");
        std::fs::write(master.join("mem_file"), vec![0xABu8; 4096]).expect("mem");

        let stem = format!(".vmcell-cow-probe-{}", std::process::id());
        for suffix in ["src", "dst"] {
            let seed = master.join(format!("{stem}.{suffix}"));
            std::fs::write(&seed, format!("seed-{suffix}").as_bytes()).expect("seed");
            std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o444)).expect("chmod");
        }

        let before = dir_fingerprint(&master);
        let _ = probe_reflink(&master);
        assert_eq!(
            before,
            dir_fingerprint(&master),
            "the probe must not create, overwrite, or unlink any name in the probed \
             (immutable-master) dir"
        );
    }

    // A directory with no usable sibling location (a filesystem root has no parent) is
    // "reflink unconfirmed" ⇒ `FullCopy`, never a silent fall-back to writing inside it.
    // RED on the inverse (`unwrap_or(dir)` instead of the `ok_or_else`): probing `/` would then
    // attempt `/.vmcell-cow-probe-*` — and on a host where that succeeds, report `Reflink`.
    #[test]
    fn probe_without_a_sibling_location_is_unconfirmed() {
        let err = probe_reflink_inner(Path::new("/")).expect_err("a root dir has no sibling");
        assert!(
            err.to_string().contains("no sibling scratch location"),
            "the unconfirmed reason must name the missing sibling location, got: {err}"
        );
        assert_eq!(
            probe_reflink(Path::new("/")),
            CowSupport::FullCopy,
            "an unconfirmed probe collapses to FullCopy"
        );
    }

    // The probe must AGREE with what an actual clone does on the same filesystem —
    // a `FullCopy`-unconditionally or `Reflink`-unconditionally probe (the two
    // inverses) disagrees with the authoritative `clone_tree_cow` outcome on any
    // host: on a reflink fs the clone is `Reflink` (catches an unconditional
    // `FullCopy`), on ext4/tmpfs it is `FullCopy` (catches an unconditional
    // `Reflink`). So exactly one inverse goes red on whatever fs the test runs on.
    //
    // It also pins the correctness half of the sibling-scratch move (docs/78
    // `overlay-probe-not-side-effect-free`): the probe answers about `master`'s FILESYSTEM even
    // though it never writes into `master`, so a scratch location that drifted off that
    // filesystem would disagree here.
    #[tokio::test]
    async fn probe_agrees_with_actual_clone_outcome() {
        let root = tempfile::tempdir().expect("tempdir");
        let master = root.path().join("m");
        std::fs::create_dir_all(&master).expect("mk master");
        std::fs::write(master.join("f"), vec![0x5Au8; 4096]).expect("f");
        let clone = root.path().join("c");
        let clone_support = clone_tree_cow_blocking(&master, &clone).expect("clone");
        let probe_support = probe_reflink(&master);
        assert_eq!(
            clone_support, probe_support,
            "probe_reflink must report the same CoW support an actual clone gets on this fs"
        );
    }

    // Symlinks are recreated as symlinks (not dereferenced into a byte copy) — the
    // documented contract. The inverse (follow_links / dereference) turns the link
    // into a regular file and goes red on the symlink_metadata + read_link asserts.
    #[tokio::test]
    async fn clone_tree_preserves_symlinks() {
        let root = tempfile::tempdir().expect("tempdir");
        let master = root.path().join("z");
        std::fs::create_dir_all(&master).expect("mk");
        std::fs::write(master.join("config.json"), b"{}").expect("cfg");
        std::os::unix::fs::symlink("config.json", master.join("link")).expect("symlink");

        let clone = root.path().join("c");
        clone_tree_cow_blocking(&master, &clone).expect("clone");

        let meta = std::fs::symlink_metadata(clone.join("link")).expect("lstat clone link");
        assert!(
            meta.file_type().is_symlink(),
            "a symlink in the master must be cloned as a symlink, not dereferenced"
        );
        assert_eq!(
            std::fs::read_link(clone.join("link")).expect("readlink"),
            std::path::PathBuf::from("config.json"),
            "the symlink target must be preserved verbatim"
        );
    }

    // A src that exists but is NOT a directory is a hard error (distinct from the
    // missing-src case, which fails earlier at metadata()). The inverse — dropping
    // the not-a-dir guard — lets a file src produce an empty `Ok(Reflink)` clone.
    #[tokio::test]
    async fn clone_tree_rejects_non_directory_src() {
        let root = tempfile::tempdir().expect("tempdir");
        let file_src = root.path().join("a-file");
        std::fs::write(&file_src, b"not a dir").expect("write file src");
        let res = clone_tree_cow_blocking(&file_src, &root.path().join("out"));
        assert!(
            matches!(res, Err(Error::Io(ref e)) if e.kind() == io::ErrorKind::InvalidInput),
            "a non-directory src must be rejected with InvalidInput, got {res:?}"
        );
    }
}
