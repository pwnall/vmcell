//! The daemon's flat artifact store: **create / list / delete; no update** (design §18.3).
//!
//! Not the `vmcell` artifact *pipeline* (which builds kernels/rootfs) — a content store the VM APIs
//! draw their `kernel`/`rootfs` inputs from. Every name goes through [`resolve_artifact_path`]
//! (invariant §12.13); no method constructs `dir.join(name)` itself. Create is atomic (temp file +
//! no-clobber rename) so a truncated upload never leaves a half-written artifact a later boot reads;
//! create over an existing name is rejected (the "no update" guard), never a silent overwrite.

use crate::dto::ArtifactInfo;
use crate::error::DaemonError;
use crate::name::resolve_artifact_path;
use sha2::{Digest, Sha256};
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// A content-addressed-by-name store rooted at one directory.
#[derive(Debug, Clone)]
pub struct ArtifactStore {
    dir: PathBuf,
    max_bytes: u64,
}

impl ArtifactStore {
    /// Opens (creating if needed) a store at `dir` with a per-upload size cap of `max_bytes`.
    ///
    /// # Errors
    /// Returns [`DaemonError::Internal`] if the directory cannot be created.
    pub fn open(dir: impl Into<PathBuf>, max_bytes: u64) -> Result<Self, DaemonError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir).map_err(|e| {
            DaemonError::Internal(format!("cannot create artifacts dir {dir:?}: {e}"))
        })?;
        Ok(Self { dir, max_bytes })
    }

    /// The store's root directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Resolves a name to its on-disk path (the single validated join, invariant §12.13).
    ///
    /// # Errors
    /// Returns [`DaemonError::InvalidName`] if the name is not a safe single component.
    pub fn path_for(&self, name: &str) -> Result<PathBuf, DaemonError> {
        Ok(resolve_artifact_path(&self.dir, name)?)
    }

    /// Whether an artifact with this (valid) name exists.
    #[must_use]
    pub fn exists(&self, name: &str) -> bool {
        self.path_for(name).map(|p| p.is_file()).unwrap_or(false)
    }

    /// Creates an artifact from in-memory bytes. **No update**: a create over an existing name is
    /// rejected atomically (no-clobber rename), never an overwrite.
    ///
    /// # Errors
    /// - [`DaemonError::InvalidName`] — bad name.
    /// - [`DaemonError::PayloadTooLarge`] — over the per-upload size cap.
    /// - [`DaemonError::AlreadyExists`] — an artifact of that name already exists.
    /// - [`DaemonError::Internal`] — an I/O failure while writing or renaming.
    pub fn create(&self, name: &str, bytes: &[u8]) -> Result<ArtifactInfo, DaemonError> {
        let path = self.path_for(name)?;
        // The `.sha256` suffix is reserved for digest sidecars (delta 10); an artifact with that
        // name would shadow a real artifact's sidecar and vanish from `list`. Reject before disk
        // (a 400, not a name-syntax error — the name is well-formed, just reserved).
        if name.ends_with(SHA256_SIDECAR_SUFFIX) {
            return Err(DaemonError::BadRequest(format!(
                "artifact name {name:?} must not end in `{SHA256_SIDECAR_SUFFIX}` (reserved for digest sidecars)"
            )));
        }
        if bytes.len() as u64 > self.max_bytes {
            return Err(DaemonError::PayloadTooLarge(format!(
                "artifact {name:?} is {} bytes; the per-upload cap is {} bytes",
                bytes.len(),
                self.max_bytes
            )));
        }
        // A `Booting`-race aside, this early check gives a clean 409 without touching disk; the
        // no-clobber rename below is the authoritative guard.
        if path.exists() {
            return Err(DaemonError::AlreadyExists(format!(
                "artifact {name:?} already exists (the store has no update; delete then create)"
            )));
        }
        // Write to a temp file IN THE SAME DIR (so the rename is atomic, not cross-device), flush,
        // then no-clobber rename into place. A crash mid-write leaves only the temp file.
        let mut tmp = tempfile::NamedTempFile::new_in(&self.dir).map_err(|e| {
            DaemonError::Internal(format!("cannot create temp file in {:?}: {e}", self.dir))
        })?;
        tmp.write_all(bytes)
            .map_err(|e| DaemonError::Internal(format!("cannot write artifact {name:?}: {e}")))?;
        tmp.flush()
            .map_err(|e| DaemonError::Internal(format!("cannot flush artifact {name:?}: {e}")))?;
        // `persist_noclobber` fails if the destination now exists — the atomic "no update" guard,
        // closing the check-then-write race above.
        tmp.persist_noclobber(&path).map_err(|e| {
            if e.error.kind() == std::io::ErrorKind::AlreadyExists {
                DaemonError::AlreadyExists(format!("artifact {name:?} already exists"))
            } else {
                DaemonError::Internal(format!("cannot persist artifact {name:?}: {}", e.error))
            }
        })?;
        // Compute the digest ONCE, at upload, and persist it in a `<name>.sha256` sidecar so
        // `list`/`info` read it back in O(1) instead of re-hashing the whole body (delta 10,
        // §11.3). The sidecar path is derived from the already-validated `path`, never from client
        // input, so it stays anchored inside the artifacts dir.
        let digest = hex_sha256(bytes);
        write_sidecar(&path, &digest)?;
        Ok(ArtifactInfo {
            name: name.to_string(),
            size_bytes: bytes.len() as u64,
            sha256: digest,
        })
    }

    /// Reads one artifact's metadata.
    ///
    /// # Errors
    /// [`DaemonError::InvalidName`] / [`DaemonError::NotFound`] / [`DaemonError::Internal`].
    pub fn info(&self, name: &str) -> Result<ArtifactInfo, DaemonError> {
        let path = self.path_for(name)?;
        if !path.is_file() {
            return Err(DaemonError::NotFound(format!("no artifact {name:?}")));
        }
        artifact_info(name, &path)
    }

    /// Lists every valid direct-child artifact. A stray subdir or a name that fails validation
    /// (written out-of-band) is **skipped** — never surfaced as a usable artifact.
    ///
    /// # Errors
    /// [`DaemonError::Internal`] if the directory cannot be read.
    pub fn list(&self) -> Result<Vec<ArtifactInfo>, DaemonError> {
        let mut out = Vec::new();
        let rd = std::fs::read_dir(&self.dir).map_err(|e| {
            DaemonError::Internal(format!("cannot read artifacts dir {:?}: {e}", self.dir))
        })?;
        for entry in rd.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            // Digest sidecars (delta 10) are internal bookkeeping, never bootable artifacts —
            // exclude them from `list` output (create() forbids a client artifact of that name).
            if name.ends_with(SHA256_SIDECAR_SUFFIX) {
                continue;
            }
            // Only names that would pass the predicate (so a NamedTempFile leftover `.tmp…` or an
            // out-of-band bad name is not offered as a bootable artifact).
            if self.path_for(&name).is_err() {
                continue;
            }
            if let Ok(info) = artifact_info(&name, &path) {
                out.push(info);
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Deletes an artifact. (The "is it pinned by a live VM?" check is the caller's — the handler
    /// consults the registry before calling this, design §18.3.2.)
    ///
    /// # Errors
    /// [`DaemonError::InvalidName`] / [`DaemonError::NotFound`] / [`DaemonError::Internal`].
    pub fn delete(&self, name: &str) -> Result<(), DaemonError> {
        let path = self.path_for(name)?;
        if !path.is_file() {
            return Err(DaemonError::NotFound(format!("no artifact {name:?}")));
        }
        std::fs::remove_file(&path)
            .map_err(|e| DaemonError::Internal(format!("cannot delete artifact {name:?}: {e}")))?;
        // Best-effort: drop the digest sidecar too, so a later re-create writes a fresh one and
        // `list` never surfaces an orphaned sidecar (delta 10).
        let _ = std::fs::remove_file(sidecar_path(&path));
        Ok(())
    }
}

/// The reserved suffix for digest sidecars (delta 10, §11.3). `<artifact>.sha256` holds the hex
/// SHA-256 computed once at upload so `list`/`info` read it back in O(1) instead of re-hashing the
/// whole body on every call. A client cannot create an artifact whose name ends in this suffix (it
/// would shadow a real artifact's sidecar and vanish from `list`).
const SHA256_SIDECAR_SUFFIX: &str = ".sha256";

/// The sidecar path for an artifact, derived by **appending** the suffix to the already-validated,
/// dir-anchored artifact path. `with_extension` would REPLACE (`rootfs.erofs` -> `rootfs.sha256`)
/// and collide across artifacts, so append. Anchored on trusted data (the resolved path), never on
/// client input (invariant §12.13).
fn sidecar_path(artifact_path: &Path) -> PathBuf {
    let mut s = artifact_path.as_os_str().to_owned();
    s.push(SHA256_SIDECAR_SUFFIX);
    PathBuf::from(s)
}

/// Writes the digest sidecar atomically (temp + rename in the same dir), overwriting any stale
/// one. A truncated sidecar never survives a crash; a missing sidecar is tolerated by readers.
fn write_sidecar(artifact_path: &Path, digest: &str) -> Result<(), DaemonError> {
    let sidecar = sidecar_path(artifact_path);
    let dir = artifact_path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(|e| {
        DaemonError::Internal(format!("cannot create sidecar temp in {dir:?}: {e}"))
    })?;
    tmp.write_all(digest.as_bytes())
        .map_err(|e| DaemonError::Internal(format!("cannot write sidecar {sidecar:?}: {e}")))?;
    tmp.flush()
        .map_err(|e| DaemonError::Internal(format!("cannot flush sidecar {sidecar:?}: {e}")))?;
    tmp.persist(&sidecar).map_err(|e| {
        DaemonError::Internal(format!("cannot persist sidecar {sidecar:?}: {}", e.error))
    })?;
    Ok(())
}

/// Reads an artifact's digest sidecar. `None` if absent or corrupt (not exactly 64 lowercase hex
/// chars) — the reader then falls back to a one-time body re-hash.
fn read_sidecar(artifact_path: &Path) -> Option<String> {
    let s = std::fs::read_to_string(sidecar_path(artifact_path)).ok()?;
    let s = s.trim();
    (s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())).then(|| s.to_string())
}

fn artifact_info(name: &str, path: &Path) -> Result<ArtifactInfo, DaemonError> {
    // Size from metadata (no body read); digest from the sidecar written at upload (delta 10) —
    // re-hashing the body only for a legacy/out-of-band artifact that has no sidecar. This is what
    // makes `list` O(entries) instead of O(store bytes).
    let meta = std::fs::metadata(path)
        .map_err(|e| DaemonError::Internal(format!("cannot stat artifact {name:?}: {e}")))?;
    let sha256 = match read_sidecar(path) {
        Some(d) => d,
        None => {
            let bytes = std::fs::read(path).map_err(|e| {
                DaemonError::Internal(format!("cannot read artifact {name:?}: {e}"))
            })?;
            hex_sha256(&bytes)
        }
    };
    Ok(ArtifactInfo {
        name: name.to_string(),
        size_bytes: meta.len(),
        sha256,
    })
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, ArtifactStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ArtifactStore::open(dir.path(), 1024).expect("open");
        (dir, store)
    }

    // The "no update" guard: a second create of the same name is AlreadyExists, and the original
    // bytes are untouched. RED on the inverse (a store that silently overwrites).
    #[test]
    fn create_twice_is_already_exists_and_does_not_overwrite() {
        let (_d, store) = store();
        let first = store.create("k1", b"original").expect("first create");
        assert_eq!(first.size_bytes, 8);
        let err = store
            .create("k1", b"REPLACED")
            .expect_err("second create must fail");
        assert!(matches!(err, DaemonError::AlreadyExists(_)), "got {err:?}");
        // Original content is intact.
        let info = store.info("k1").expect("info");
        assert_eq!(
            info.sha256, first.sha256,
            "bytes must not have been overwritten"
        );
    }

    // Residue check (AGENTS.md): the artifact existed before delete, then is gone.
    #[test]
    fn delete_removes_the_file() {
        let (_d, store) = store();
        store.create("r", b"rootfs").expect("create");
        assert!(store.exists("r"), "artifact exists before delete");
        store.delete("r").expect("delete");
        assert!(!store.exists("r"), "artifact gone after delete");
        assert!(matches!(store.delete("r"), Err(DaemonError::NotFound(_))));
    }

    #[test]
    fn create_over_size_cap_is_payload_too_large() {
        let (_d, store) = store();
        let big = vec![0u8; 2048]; // cap is 1024
        let err = store.create("big", &big).expect_err("must reject");
        assert!(
            matches!(err, DaemonError::PayloadTooLarge(_)),
            "got {err:?}"
        );
        assert!(!store.exists("big"), "an over-cap upload leaves no residue");
    }

    #[test]
    fn create_rejects_invalid_name_before_touching_disk() {
        let (_d, store) = store();
        assert!(matches!(
            store.create("../escape", b"x"),
            Err(DaemonError::InvalidName(_))
        ));
    }

    #[test]
    fn list_is_sorted_and_skips_non_artifacts() {
        let (_d, store) = store();
        store.create("b", b"1").expect("b");
        store.create("a", b"22").expect("a");
        // A subdirectory and a name a client could never create are ignored by list.
        std::fs::create_dir(store.dir().join("subdir")).expect("mkdir");
        let list = store.list().expect("list");
        let names: Vec<&str> = list.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b"], "sorted, files only");
        assert_eq!(list[0].size_bytes, 2);
    }

    // A NamedTempFile leftover (a crashed upload) is not offered as an artifact, and does not
    // collide with a real name.
    #[test]
    fn no_tmp_residue_after_successful_create() {
        let (_d, store) = store();
        store.create("k", b"kernel").expect("create");
        let stray: Vec<_> = std::fs::read_dir(store.dir())
            .expect("readdir")
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp"))
            .collect();
        assert!(
            stray.is_empty(),
            "no temp residue after a successful create"
        );
    }

    // Delta 10 gate: a `<name>.sha256` sidecar is written at upload and matches a fresh (streamed)
    // hash of the bytes. RED on the inverse (a store that never writes the sidecar).
    #[test]
    fn create_writes_matching_sha256_sidecar() {
        let (_d, store) = store();
        let info = store.create("k", b"kernel-bytes").expect("create");
        let sidecar = store.dir().join("k.sha256");
        let on_disk = std::fs::read_to_string(&sidecar).expect("sidecar written at upload");
        assert_eq!(
            on_disk.trim(),
            info.sha256,
            "sidecar must hold the digest returned by create"
        );
        assert_eq!(
            info.sha256,
            hex_sha256(b"kernel-bytes"),
            "and that digest is a real SHA-256 of the bytes"
        );
    }

    // Delta 10 gate: `info` (and `list`) read the digest FROM the sidecar, never by re-hashing the
    // body. RED on the inverse (a store that re-hashes the body on every read): corrupting only the
    // sidecar to a different well-formed digest would be ignored and the body hash returned instead.
    #[test]
    fn info_reads_digest_from_sidecar_not_the_body() {
        let (_d, store) = store();
        store.create("k", b"body").expect("create");
        let bogus = "a".repeat(64); // well-formed but wrong
        std::fs::write(store.dir().join("k.sha256"), &bogus).expect("overwrite sidecar");
        let info = store.info("k").expect("info");
        assert_eq!(
            info.sha256, bogus,
            "info must serve the sidecar digest, not re-hash the body"
        );
    }

    // Delta 10: `.sha256` sidecars never appear as artifacts, and a client cannot create a
    // `.sha256`-suffixed name (it would shadow a real artifact's sidecar).
    #[test]
    fn list_excludes_sidecars_and_rejects_reserved_suffix() {
        let (_d, store) = store();
        store.create("a", b"1").expect("a");
        store.create("b", b"22").expect("b");
        let names: Vec<String> = store
            .list()
            .expect("list")
            .into_iter()
            .map(|i| i.name)
            .collect();
        assert_eq!(
            names,
            vec!["a".to_string(), "b".to_string()],
            "sidecars excluded"
        );
        assert!(matches!(
            store.create("evil.sha256", b"x"),
            Err(DaemonError::BadRequest(_))
        ));
    }

    // Delta 10 residue: delete removes the sidecar too — no orphaned digest survives.
    #[test]
    fn delete_removes_the_sidecar() {
        let (_d, store) = store();
        store.create("r", b"rootfs").expect("create");
        assert!(
            store.dir().join("r.sha256").is_file(),
            "sidecar exists before delete"
        );
        store.delete("r").expect("delete");
        assert!(
            !store.dir().join("r.sha256").exists(),
            "sidecar gone after delete"
        );
    }
}
