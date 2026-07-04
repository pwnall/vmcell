//! The daemon's flat artifact store: **create / list / delete; no update** (design v21 §D3).
//!
//! Not the `vmcell` artifact *pipeline* (which builds kernels/rootfs) — a content store the VM APIs
//! draw their `kernel`/`rootfs` inputs from. Every name goes through [`resolve_artifact_path`]
//! (invariant §D9.1); no method constructs `dir.join(name)` itself. Create is atomic (temp file +
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

    /// Resolves a name to its on-disk path (the single validated join, invariant §D9.1).
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
        Ok(ArtifactInfo {
            name: name.to_string(),
            size_bytes: bytes.len() as u64,
            sha256: hex_sha256(bytes),
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
    /// consults the registry before calling this, design v21 §D3.2.)
    ///
    /// # Errors
    /// [`DaemonError::InvalidName`] / [`DaemonError::NotFound`] / [`DaemonError::Internal`].
    pub fn delete(&self, name: &str) -> Result<(), DaemonError> {
        let path = self.path_for(name)?;
        if !path.is_file() {
            return Err(DaemonError::NotFound(format!("no artifact {name:?}")));
        }
        std::fs::remove_file(&path)
            .map_err(|e| DaemonError::Internal(format!("cannot delete artifact {name:?}: {e}")))
    }
}

fn artifact_info(name: &str, path: &Path) -> Result<ArtifactInfo, DaemonError> {
    let bytes = std::fs::read(path)
        .map_err(|e| DaemonError::Internal(format!("cannot read artifact {name:?}: {e}")))?;
    Ok(ArtifactInfo {
        name: name.to_string(),
        size_bytes: bytes.len() as u64,
        sha256: hex_sha256(&bytes),
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
}
