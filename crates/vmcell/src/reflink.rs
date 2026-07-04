//! Copy-on-write cloning of zygote suspend images (§9.4).
//!
//! The zygote fan-out (§9.4) mints many identical VMs from one suspended
//! **zygote** image by copy-on-write-copying its suspend/resume data per clone
//! and restoring each private copy. On a reflink-capable host filesystem (XFS,
//! Btrfs, bcachefs) the copy is a near-instant block-level `FICLONE` that shares
//! physical storage with the master until a clone writes; on any other
//! filesystem (ext4, tmpfs) it degrades to a full byte copy — correct, just not
//! free. Reflinking is what makes an N-VM warm pool cost ≈N×dirtied pages
//! instead of N×guest-RAM on disk (§9.3).
//!
//! Making each clone restore from its **own** copy is also what un-breaks the
//! single-use snapshot: the CH backend rewrites `config.json` in place per
//! restore and FC reads a per-dir sidecar, so two restores from one shared dir
//! race and corrupt it (§9.1). A per-clone copy removes the race *and* keeps the
//! zygote master immutable (§12.12) — the copy diverges, the master never does.

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
/// a different scratch location (§9.4).
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
/// the zygote-immutability contract (§12.12). Subdirectories are recreated and
/// symlinks are recreated as symlinks; the flat CH/FC snapshot dirs contain
/// neither, but the walk is robust to both. Special files (sockets/fifos) are
/// skipped — a snapshot dir never contains one.
///
/// Returns the aggregate [`CowSupport`]: `Reflink` only if every regular file in
/// the tree reflinked. The (potentially large) copy runs on a blocking thread so
/// it never stalls the async runtime.
///
/// # Errors
/// [`Error::Io`] if `src` is not a readable directory, `dst` already exists or
/// cannot be created, or any entry copy fails. A `src`/`dst` split across two
/// filesystems still succeeds via the full-copy fallback (`FICLONE` `EXDEV` is
/// not surfaced as an error); only a genuine I/O failure fails.
pub(crate) async fn clone_tree_cow(src: &Path, dst: &Path) -> Result<CowSupport> {
    let src = src.to_path_buf();
    let dst = dst.to_path_buf();
    tokio::task::spawn_blocking(move || clone_tree_cow_blocking(&src, &dst))
        .await
        .map_err(|e| {
            Error::Io(io::Error::other(format!(
                "zygote cow-clone task panicked: {e}"
            )))
        })?
}

/// Synchronous worker for [`clone_tree_cow`]; separated so the reflink logic is
/// unit-testable without a tokio runtime and runs on a blocking thread.
fn clone_tree_cow_blocking(src: &Path, dst: &Path) -> Result<CowSupport> {
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
/// sentinel file into `dir` and observing the outcome.
///
/// Best-effort and side-effect-free: both sentinels are removed before return,
/// and any I/O error is treated as "reflink unconfirmed" ⇒ [`CowSupport::FullCopy`].
/// Useful for an up-front signal ("this pool will be cheap / expensive") without
/// having to mint a clone first. The sentinel name embeds the pid so concurrent
/// probes from sibling processes do not collide.
#[must_use]
pub(crate) fn probe_reflink(dir: &Path) -> CowSupport {
    let stem = format!(".vmcell-cow-probe-{}", std::process::id());
    let src = dir.join(format!("{stem}.src"));
    let dst = dir.join(format!("{stem}.dst"));
    let outcome = (|| -> io::Result<CowSupport> {
        std::fs::write(&src, b"vmcell-cow-probe")?;
        // A leftover dst from a crashed prior probe would make `reflink` fail
        // spuriously; clear it first.
        let _ = std::fs::remove_file(&dst);
        Ok(match reflink_copy::reflink(&src, &dst) {
            Ok(()) => CowSupport::Reflink,
            Err(_) => CowSupport::FullCopy,
        })
    })();
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
    outcome.unwrap_or(CowSupport::FullCopy)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A clone must be a FAITHFUL, INDEPENDENT copy: same tree, same bytes, and a
    // later write to the clone must NOT touch the master (the zygote-immutability
    // contract, §12.12). The inverse — a clone that hardlinks/shares the inode —
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
        let support = clone_tree_cow(&master, &clone).await.expect("clone");
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
            "writing the clone must not mutate the zygote master (immutability, §12.12)"
        );
    }

    // A missing master is a hard error, never a silently-empty clone.
    #[tokio::test]
    async fn clone_tree_rejects_missing_master() {
        let root = tempfile::tempdir().expect("tempdir");
        let res = clone_tree_cow(&root.path().join("nope"), &root.path().join("out")).await;
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
        let res = clone_tree_cow(&master, &target).await;
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

    // The probe is side-effect-free: it leaves no sentinel files behind.
    #[test]
    fn probe_leaves_no_residue() {
        let root = tempfile::tempdir().expect("tempdir");
        let before: Vec<_> = std::fs::read_dir(root.path())
            .expect("read")
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .collect();
        let _ = probe_reflink(root.path());
        let after: Vec<_> = std::fs::read_dir(root.path())
            .expect("read")
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .collect();
        assert_eq!(before.len(), after.len(), "probe must leave no residue");
    }

    // The probe must AGREE with what an actual clone does on the same filesystem —
    // a `FullCopy`-unconditionally or `Reflink`-unconditionally probe (the two
    // inverses) disagrees with the authoritative `clone_tree_cow` outcome on any
    // host: on a reflink fs the clone is `Reflink` (catches an unconditional
    // `FullCopy`), on ext4/tmpfs it is `FullCopy` (catches an unconditional
    // `Reflink`). So exactly one inverse goes red on whatever fs the test runs on.
    #[tokio::test]
    async fn probe_agrees_with_actual_clone_outcome() {
        let root = tempfile::tempdir().expect("tempdir");
        let master = root.path().join("m");
        std::fs::create_dir_all(&master).expect("mk master");
        std::fs::write(master.join("f"), vec![0x5Au8; 4096]).expect("f");
        let clone = root.path().join("c");
        let clone_support = clone_tree_cow(&master, &clone).await.expect("clone");
        let probe_support = probe_reflink(root.path());
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
        clone_tree_cow(&master, &clone).await.expect("clone");

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
        let res = clone_tree_cow(&file_src, &root.path().join("out")).await;
        assert!(
            matches!(res, Err(Error::Io(ref e)) if e.kind() == io::ErrorKind::InvalidInput),
            "a non-directory src must be rejected with InvalidInput, got {res:?}"
        );
    }
}
