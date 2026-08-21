//! The daemon's flat artifact store: **create / list / delete; no update** (design §11.3, The artifact store).
//!
//! Not the `vmcell` artifact *pipeline* (which builds kernels/rootfs) — a content store the VM APIs
//! draw their `kernel`/`rootfs` inputs from. Every name goes through [`resolve_artifact_path`]
//! (invariant §13, Cross-cutting invariants); no method constructs `dir.join(name)` itself. Create is atomic (temp file +
//! no-clobber rename) so a truncated upload never leaves a half-written artifact a later boot reads;
//! create over an existing name is rejected (the "no update" guard), never a silent overwrite.
//!
//! Uploads **stream**: [`ArtifactStore::create_streaming`] hands back an [`ArtifactWriter`] the
//! caller feeds chunk by chunk, hashing and capping as the bytes flow, so a multi-gigabyte rootfs
//! never sits in the daemon's memory (design §11.7, The client library and CLI; §17, Open gaps and
//! future capabilities). [`ArtifactStore::create`] is that same path with one chunk — the
//! create-only/atomic/digest/cap laws exist once.

use crate::dto::ArtifactInfo;
use crate::error::DaemonError;
use crate::name::{SHA256_SIDECAR_SUFFIX, is_reserved_sidecar_name, resolve_artifact_path};
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

    /// Resolves a name to its on-disk path (the single validated join, invariant §13, Cross-cutting invariants).
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
    /// A thin wrapper over the streaming path — [`ArtifactStore::create_streaming`] plus one
    /// [`ArtifactWriter::write_chunk`] — so the create-only, atomic, digest-sidecar'd and size-capped
    /// laws are stated **once** and cannot drift between a buffered and a streamed upload (design
    /// §11.3, The artifact store).
    ///
    /// # Errors
    /// - [`DaemonError::InvalidName`] — bad name.
    /// - [`DaemonError::PayloadTooLarge`] — over the per-upload size cap.
    /// - [`DaemonError::AlreadyExists`] — an artifact of that name already exists.
    /// - [`DaemonError::Internal`] — an I/O failure while writing or renaming.
    pub fn create(&self, name: &str, bytes: &[u8]) -> Result<ArtifactInfo, DaemonError> {
        let mut writer = self.create_streaming(name)?;
        writer.write_chunk(bytes)?;
        writer.finish()
    }

    /// Opens a **streaming** create: the caller feeds chunks as they arrive off the network, and the
    /// store hashes, caps and writes each one as it flows (design §11.7, The client library and CLI;
    /// §17, Open gaps and future capabilities — "Streaming upload (v1 reads the file into memory)").
    ///
    /// Every property of the buffered path survives, and each survives *because* it is enforced
    /// incrementally rather than against a body the daemon first has to hold in RAM:
    ///
    /// * **create-only** — a reserved or already-taken name is refused here, before one byte is read;
    ///   the authoritative guard is still the no-clobber rename in [`ArtifactWriter::finish`].
    /// * **atomic** — every chunk lands in a temp file in the same directory, and the artifact appears
    ///   under its real name only on the closing rename, so a torn upload publishes nothing and a
    ///   concurrent reader never sees a prefix of one.
    /// * **digest-sidecar'd at upload** — the SHA-256 is accumulated as the bytes flow, never by a
    ///   second pass over the stored file.
    /// * **capped** — the per-upload ceiling is checked *before* each chunk is written, so at most
    ///   `max_bytes` ever reach the disk however long the client keeps sending.
    ///
    /// # Errors
    /// [`DaemonError::BadRequest`] for the reserved `.sha256` suffix, [`DaemonError::InvalidName`] for
    /// a name that fails the predicate, [`DaemonError::AlreadyExists`] if the name is taken, or
    /// [`DaemonError::Internal`] if the temp file cannot be created.
    pub fn create_streaming(&self, name: &str) -> Result<ArtifactWriter<'_>, DaemonError> {
        // The `.sha256` suffix is reserved for digest sidecars (delta 10); an artifact with that
        // name would shadow a real artifact's sidecar and vanish from `list`. Reject before disk
        // (a 400, not a name-syntax error — the name is well-formed, just reserved). Checked
        // BEFORE `path_for` only to keep this verb's *reaction* (a `BadRequest` naming the
        // reservation); the law itself is in `validate_artifact_name`, which `path_for` also
        // enforces, so a verb that forgets this line still refuses the name.
        if is_reserved_sidecar_name(name) {
            return Err(DaemonError::BadRequest(format!(
                "artifact name {name:?} must not end in `{SHA256_SIDECAR_SUFFIX}` (reserved for digest sidecars)"
            )));
        }
        let path = self.path_for(name)?;
        // A `Booting`-race aside, this early check gives a clean 409 without touching disk — and,
        // on the streaming path, without draining a multi-gigabyte body first; the no-clobber
        // rename in `finish` is the authoritative guard.
        if path.exists() {
            return Err(DaemonError::AlreadyExists(format!(
                "artifact {name:?} already exists (the store has no update; delete then create)"
            )));
        }
        // The temp file lives IN THE SAME DIR, so the closing rename is atomic rather than
        // cross-device. It is a `NamedTempFile`, so every abandoned upload — a torn stream, an
        // over-cap chunk, a dropped connection, a panic — removes it on `Drop` without the ingest
        // loop needing an error path of its own.
        let tmp = tempfile::NamedTempFile::new_in(&self.dir).map_err(|e| {
            DaemonError::Internal(format!("cannot create temp file in {:?}: {e}", self.dir))
        })?;
        Ok(ArtifactWriter {
            store: self,
            name: name.to_string(),
            path,
            tmp,
            hasher: Sha256::new(),
            written: 0,
        })
    }

    /// Reads one artifact's metadata. A digest sidecar is **not** an artifact: a reserved
    /// `<name>.sha256` reads back as [`DaemonError::NotFound`], exactly like an absent name.
    ///
    /// # Errors
    /// [`DaemonError::InvalidName`] / [`DaemonError::NotFound`] / [`DaemonError::Internal`].
    pub fn info(&self, name: &str) -> Result<ArtifactInfo, DaemonError> {
        // The reserved-suffix guard used to live in `create` only, so a client could GET (and, in
        // `delete` below, remove) a live artifact's internal digest record — store bookkeeping is
        // not a client-visible surface (finding `sidecar-suffix-guard-is-create-only`). 404, not
        // the create path's 400: to a client the name simply does not name an artifact. This picks
        // the reaction; `validate_artifact_name` (via `path_for`) is what makes the law
        // unbypassable.
        if is_reserved_sidecar_name(name) {
            return Err(DaemonError::NotFound(format!("no artifact {name:?}")));
        }
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
            if is_reserved_sidecar_name(&name) {
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

    /// Deletes an artifact **or a snapshot prefix directory**. (The "is it pinned by a live VM?"
    /// check is the caller's — the handler consults the registry before calling this, design
    /// §11.3, The artifact store.)
    ///
    /// A name resolves to either a file (an uploaded artifact) or a directory (`<prefix>/`, written
    /// by [`crate::registry::Registry::snapshot`], §11.4). Both are deletable: since `snapshot` now
    /// refuses to reuse a populated prefix (finding `snapshot-prefix-silent-reuse`), a prefix that
    /// could never be freed would burn its name for the daemon's lifetime.
    ///
    /// # Errors
    /// [`DaemonError::InvalidName`] / [`DaemonError::NotFound`] / [`DaemonError::Internal`].
    pub fn delete(&self, name: &str) -> Result<(), DaemonError> {
        // Same reserved-suffix law as `info` (finding `sidecar-suffix-guard-is-create-only`): a
        // client that could DELETE `<artifact>.sha256` would strip a live artifact's digest record
        // while the artifact itself stayed bootable.
        if is_reserved_sidecar_name(name) {
            return Err(DaemonError::NotFound(format!("no artifact {name:?}")));
        }
        let path = self.path_for(name)?;
        // `symlink_metadata`, not `is_file`/`is_dir`: those follow symlinks, and the recursive
        // directory delete below must never walk out of the store through one planted out-of-band.
        let Ok(meta) = path.symlink_metadata() else {
            return Err(DaemonError::NotFound(format!("no artifact {name:?}")));
        };
        if meta.is_dir() {
            // A snapshot prefix. `path` came from `resolve_artifact_path`, so it is a validated
            // single component — the recursive delete is confined to one direct child of the store
            // dir (invariant §13, Cross-cutting invariants). Snapshot dirs carry no sidecar.
            return std::fs::remove_dir_all(&path).map_err(|e| {
                DaemonError::Internal(format!("cannot delete snapshot prefix {name:?}: {e}"))
            });
        }
        if !meta.is_file() {
            return Err(DaemonError::NotFound(format!("no artifact {name:?}")));
        }
        std::fs::remove_file(&path)
            .map_err(|e| DaemonError::Internal(format!("cannot delete artifact {name:?}: {e}")))?;
        // Drop the digest sidecar too, so a later re-create writes a fresh one and `list` never
        // surfaces an orphaned sidecar (delta 10). Best-effort — a legacy artifact has none — but
        // LOGGED, never a bare `let _` on a Result (AGENTS.md, fail loud).
        if let Err(e) = std::fs::remove_file(sidecar_path(&path)) {
            tracing::debug!(artifact = name, error = %e, "no digest sidecar removed with the artifact");
        }
        Ok(())
    }
}

/// One streaming artifact upload in progress: the create-only, atomic, digest-sidecar'd, size-capped
/// write of [`ArtifactStore::create_streaming`], driven one chunk at a time.
///
/// **Abandoning it publishes nothing.** The bytes go to a [`tempfile::NamedTempFile`] whose `Drop`
/// removes it, and the artifact's real name is claimed only by [`ArtifactWriter::finish`]. A torn
/// upload — a client that disconnects, a chunk over the cap, a panic in the ingest loop — therefore
/// leaves neither an artifact nor a temp file, which is what lets the HTTP handler simply drop the
/// writer on its error path instead of carrying a cleanup path that could itself be wrong.
///
/// The borrow of the store is what keeps `max_bytes` and the store directory one fact rather than a
/// copy carried alongside the write.
pub struct ArtifactWriter<'a> {
    store: &'a ArtifactStore,
    name: String,
    /// The final, already-validated, dir-anchored path — resolved once at open, never re-derived
    /// from the client's name at publish time (invariant §13, Cross-cutting invariants).
    path: PathBuf,
    tmp: tempfile::NamedTempFile,
    hasher: Sha256,
    written: u64,
}

impl ArtifactWriter<'_> {
    /// Accepts the next chunk of the upload: caps it, writes it, and folds it into the digest.
    ///
    /// The cap is checked **before** the write and against the running total, so an over-cap upload
    /// is refused at the chunk that crosses the line — not after the whole body has been read into
    /// memory (which is the property that makes this path streaming at all) and never after more
    /// than `max_bytes` have reached the disk.
    ///
    /// # Errors
    /// [`DaemonError::PayloadTooLarge`] when this chunk would cross the per-upload cap;
    /// [`DaemonError::Internal`] on a write failure.
    pub fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), DaemonError> {
        let total = self.written.saturating_add(chunk.len() as u64);
        if total > self.store.max_bytes {
            return Err(DaemonError::PayloadTooLarge(format!(
                "artifact {:?} is at least {total} bytes; the per-upload cap is {} bytes",
                self.name, self.store.max_bytes
            )));
        }
        self.tmp.write_all(chunk).map_err(|e| {
            DaemonError::Internal(format!("cannot write artifact {:?}: {e}", self.name))
        })?;
        self.hasher.update(chunk);
        self.written = total;
        Ok(())
    }

    /// How many bytes of this upload have been accepted so far. What a mid-stream failure reports,
    /// so a torn upload is diagnosable ("failed after N bytes") instead of opaque.
    #[must_use]
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Publishes the upload: flushes, claims the name with a **no-clobber** rename, and writes the
    /// digest sidecar — rolling the artifact back if that sidecar write fails.
    ///
    /// # Errors
    /// [`DaemonError::AlreadyExists`] if the name was taken while the body streamed (the
    /// authoritative create-only guard, closing the check-then-write race with the early check in
    /// [`ArtifactStore::create_streaming`]); [`DaemonError::Internal`] on an I/O failure.
    pub fn finish(self) -> Result<ArtifactInfo, DaemonError> {
        let Self {
            name,
            path,
            mut tmp,
            hasher,
            written,
            ..
        } = self;
        tmp.flush()
            .map_err(|e| DaemonError::Internal(format!("cannot flush artifact {name:?}: {e}")))?;
        // `persist_noclobber` fails if the destination now exists — the atomic "no update" guard,
        // closing the check-then-write race against the early existence check at open.
        tmp.persist_noclobber(&path).map_err(|e| {
            if e.error.kind() == std::io::ErrorKind::AlreadyExists {
                DaemonError::AlreadyExists(format!("artifact {name:?} already exists"))
            } else {
                DaemonError::Internal(format!("cannot persist artifact {name:?}: {}", e.error))
            }
        })?;
        // The digest was computed ONCE, as the bytes flowed, and is persisted in a `<name>.sha256`
        // sidecar so `list`/`info` read it back in O(1) instead of re-hashing the whole body
        // (delta 10, §11.3, The artifact store). The sidecar path is derived from the
        // already-validated `path`, never from client input, so it stays anchored inside the
        // artifacts dir.
        let digest = hex_digest(hasher);
        if let Err(e) = write_sidecar(&path, &digest) {
            // A create is ALL-OR-NOTHING: a bare `?` here returned a 500 while leaving the artifact
            // on disk — a name burned in a create-only store (the client cannot re-create it and
            // never asked to delete it), holding bytes the client believes were rejected, and
            // bootable by a later `create` (finding `failed-sidecar-write-leaves-the-artifact`).
            // Roll back to the state the caller's error reply describes.
            if let Err(rm) = std::fs::remove_file(&path) {
                tracing::warn!(
                    artifact = name,
                    error = %rm,
                    "cannot roll back an artifact whose sidecar write failed; the name stays taken"
                );
            }
            return Err(e);
        }
        Ok(ArtifactInfo {
            name,
            size_bytes: written,
            sha256: digest,
        })
    }
}

/// The sidecar path for an artifact, derived by **appending** the suffix to the already-validated,
/// dir-anchored artifact path. `with_extension` would REPLACE (`rootfs.erofs` -> `rootfs.sha256`)
/// and collide across artifacts, so append. Anchored on trusted data (the resolved path), never on
/// client input (invariant §13, Cross-cutting invariants).
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

/// The lowercase-hex SHA-256 of `bytes` in one shot. `pub(crate)` so the server's upload gates can
/// state their expected digest through the store's own hasher rather than a second implementation.
pub(crate) fn hex_sha256(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex_digest(h)
}

/// The one hex rendering of a finished SHA-256, shared by the one-shot [`hex_sha256`] and by the
/// streaming [`ArtifactWriter::finish`] (which finalizes a hasher it fed chunk by chunk). One law,
/// one predicate: a second rendering could disagree about case or padding and silently invalidate a
/// sidecar a client compares against.
fn hex_digest(hasher: Sha256) -> String {
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        // `fmt::Write` on a `String` is infallible — `String`'s impl returns `Ok` unconditionally.
        // The `Result` exists only because the trait is shared with fallible sinks, and the
        // capacity is reserved above, so there is nothing here that can fail or be reported.
        #[expect(
            clippy::let_underscore_must_use,
            reason = "fmt::Write on a String cannot fail: the impl returns Ok unconditionally and the capacity is pre-reserved"
        )]
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

    // The reserved-suffix law holds on EVERY op, not just `create` (finding
    // `sidecar-suffix-guard-is-create-only`): a client can neither read nor delete an artifact's
    // internal digest record, and the sidecar survives the refused delete. The same test carries
    // the POSITIVE CONTROL (AGENTS.md) — the real artifact name still reaches `info` and `delete`,
    // so the guard rejects the reserved name rather than breaking the ops. RED on the inverse (the
    // pre-fix `info`/`delete`, which happily served and removed `k.sha256`).
    #[test]
    fn sidecar_names_are_neither_readable_nor_deletable_but_real_names_are() {
        let (_d, store) = store();
        let info = store.create("k", b"kernel").expect("create");
        let sidecar = store.dir().join("k.sha256");
        assert!(sidecar.is_file(), "the sidecar exists on disk");

        assert!(
            matches!(store.info("k.sha256"), Err(DaemonError::NotFound(_))),
            "a sidecar must not be readable through the artifact API"
        );
        assert!(
            matches!(store.delete("k.sha256"), Err(DaemonError::NotFound(_))),
            "a sidecar must not be deletable through the artifact API"
        );
        assert!(sidecar.is_file(), "the refused delete left the sidecar");

        // Positive control: the artifact's own name still reaches both ops.
        assert_eq!(store.info("k").expect("info").sha256, info.sha256);
        store.delete("k").expect("delete");
        assert!(!store.exists("k"), "the real artifact deleted");
    }

    // A snapshot prefix directory (`Registry::snapshot` writes `<prefix>/`) is deletable, so a
    // prefix the create-only snapshot guard now refuses to reuse can be freed (finding
    // `snapshot-prefix-silent-reuse`). Residue check: the dir existed before, then is gone. RED on
    // the inverse (the pre-fix `is_file()`-only delete, which 404s the prefix forever).
    #[test]
    fn delete_frees_a_snapshot_prefix_directory() {
        let (_d, store) = store();
        let prefix = store.dir().join("snap1");
        std::fs::create_dir(&prefix).expect("mkdir");
        std::fs::write(prefix.join("state.json"), b"{}").expect("snapshot file");
        assert!(prefix.is_dir(), "prefix exists before delete");

        store.delete("snap1").expect("delete frees the prefix");
        assert!(
            !prefix.exists(),
            "prefix (and its contents) gone after delete"
        );
        assert!(
            matches!(store.delete("snap1"), Err(DaemonError::NotFound(_))),
            "a freed prefix is then absent"
        );
    }

    // The store-side leg of the name-length law (finding `sidecar-suffix-overruns-name-max`): a name
    // whose `<name>.sha256` sidecar would overrun NAME_MAX is refused AT THE BOUNDARY — the same
    // place the reserved suffix is refused — instead of persisting and then 500ing on the sidecar
    // write. Deterministic, no injection needed: 249..=255 bytes is exactly the overrunning range.
    //
    // RED on the inverse (`MAX_ARTIFACT_NAME_LEN = NAME_MAX`): the create returns
    // `Internal("cannot persist sidecar … File name too long")`, and — without `create`'s rollback —
    // `exists()` is true, so the name is burned in a create-only store.
    #[test]
    fn create_rejects_a_name_whose_sidecar_would_not_fit() {
        let (_d, store) = store();
        for len in [
            crate::name::MAX_ARTIFACT_NAME_LEN + 1, // 249: the first name whose sidecar overruns
            255,                                    // NAME_MAX itself
        ] {
            let name = "a".repeat(len);
            let err = store
                .create(&name, b"x")
                .expect_err("a name whose sidecar cannot exist must be refused");
            assert!(matches!(err, DaemonError::InvalidName(_)), "got {err:?}");
            assert_eq!(err.kind().status_code(), 400, "a client error, not a 500");
            assert!(
                !store.dir().join(&name).exists(),
                "the refused upload must leave no artifact behind"
            );
        }
        // Positive control: the longest name that DOES leave room boots the whole path — artifact and
        // sidecar both on disk, both under NAME_MAX.
        let longest = "a".repeat(crate::name::MAX_ARTIFACT_NAME_LEN);
        let info = store.create(&longest, b"x").expect("the ceiling is usable");
        assert!(store.dir().join(&longest).is_file());
        let sidecar = format!("{longest}{}", SHA256_SIDECAR_SUFFIX);
        assert_eq!(sidecar.len(), 255, "the sidecar name is exactly NAME_MAX");
        assert_eq!(
            std::fs::read_to_string(store.dir().join(&sidecar))
                .expect("the sidecar fits")
                .trim(),
            info.sha256
        );
    }

    // `create` is all-or-nothing across BOTH files it writes (finding
    // `failed-sidecar-write-leaves-the-artifact`): a sidecar write that fails must not leave the
    // artifact persisted while the caller is told the create failed — in a create-only store that
    // burns the name for the daemon's lifetime.
    //
    // The failure is injected out-of-band, the way a real one arrives (ENOSPC, a permission change):
    // a DIRECTORY at the sidecar path, so `rename` onto it fails with EISDIR. RED on the inverse
    // (`write_sidecar(&path, &digest)?`): the error is the same, but `k` stays on disk and every
    // later `create("k")` is a 409 the client cannot clear.
    #[test]
    fn a_failed_sidecar_write_rolls_the_artifact_back() {
        let (_d, store) = store();
        std::fs::create_dir(store.dir().join("k.sha256")).expect("block the sidecar path");
        let err = store
            .create("k", b"kernel")
            .expect_err("a sidecar that cannot be written must fail the create");
        assert!(matches!(err, DaemonError::Internal(_)), "got {err:?}");
        assert!(
            !store.exists("k"),
            "the artifact must be rolled back, not left behind under a burned name"
        );
        // …and the name is genuinely free again: the same create succeeds once the path is clear.
        std::fs::remove_dir(store.dir().join("k.sha256")).expect("unblock");
        store
            .create("k", b"kernel")
            .expect("the name is free again");
        assert!(store.exists("k"));
    }

    // ---- the streaming upload (design §11.7, The client library and CLI; §17, Open gaps and future
    // capabilities — "Streaming upload (v1 reads the file into memory)") ----

    /// The temp files a `NamedTempFile` upload leaves in the store dir, by count. Residue and
    /// mid-flight presence are both read through this one helper.
    fn temp_files(store: &ArtifactStore) -> usize {
        std::fs::read_dir(store.dir())
            .expect("readdir")
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp"))
            .count()
    }

    /// A store with a cap big enough for the multi-chunk uploads below.
    fn big_store() -> (tempfile::TempDir, ArtifactStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ArtifactStore::open(dir.path(), 8 << 20).expect("open");
        (dir, store)
    }

    // A body far larger than any single chunk arrives in pieces and is stored byte-exact, with the
    // digest computed AS IT FLOWED matching a one-shot hash of the whole thing — the end-to-end
    // property a streaming upload has to keep. RED on the inverse (a `write_chunk` that hashes but
    // does not write, or writes but does not hash, or that resets the hasher per chunk): the digest
    // or the on-disk bytes disagree with the reference.
    #[test]
    fn a_multi_chunk_stream_is_stored_byte_exact_and_digested_as_it_flows() {
        let (_d, store) = big_store();
        // 48 chunks of 64 KiB: 3 MiB, past any single buffer the daemon holds.
        let chunk: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
        let mut expected = Vec::new();
        let mut writer = store.create_streaming("rootfs").expect("open the upload");
        for _ in 0..48 {
            writer.write_chunk(&chunk).expect("chunk");
            expected.extend_from_slice(&chunk);
        }
        assert_eq!(
            writer.written(),
            expected.len() as u64,
            "the writer counts what it accepted"
        );
        let info = writer.finish().expect("publish");

        assert_eq!(info.size_bytes, expected.len() as u64);
        assert_eq!(
            info.sha256,
            hex_sha256(&expected),
            "the streamed digest must equal a one-shot hash of the same bytes"
        );
        assert_eq!(
            std::fs::read(store.dir().join("rootfs")).expect("read back"),
            expected,
            "and the stored bytes must be the ones that were sent"
        );
        assert_eq!(
            std::fs::read_to_string(store.dir().join("rootfs.sha256"))
                .expect("sidecar")
                .trim(),
            info.sha256,
            "the sidecar is written at upload, from the streamed digest"
        );
        assert_eq!(temp_files(&store), 0, "no temp residue after a publish");
    }

    // The torn upload, with the residue check in the order AGENTS.md prescribes: the temp file
    // EXISTS mid-flight, and after the abandoned writer is dropped it is gone — and the artifact was
    // never published, because the name is claimed only by the rename inside `finish`.
    //
    // RED on the inverse (a writer that opens the destination file directly, or one that persists
    // per chunk): the artifact appears under its real name mid-flight and survives the tear, leaving
    // a truncated image a later boot would read as whole.
    #[test]
    fn a_torn_upload_publishes_nothing_and_leaves_no_temp_behind() {
        let (_d, store) = big_store();
        let chunk = vec![0xABu8; 64 * 1024];
        {
            let mut writer = store.create_streaming("half").expect("open the upload");
            writer.write_chunk(&chunk).expect("first chunk");
            writer.write_chunk(&chunk).expect("second chunk");
            // Mid-flight: the bytes are on disk, under a temp name, and the artifact does not exist.
            assert_eq!(
                temp_files(&store),
                1,
                "the in-flight upload has a temp file"
            );
            assert!(
                !store.exists("half"),
                "an in-flight upload must not be readable under its real name"
            );
            // …and the client goes away: the writer is dropped without `finish`.
        }
        assert_eq!(temp_files(&store), 0, "the temp file goes with the writer");
        assert!(!store.exists("half"), "nothing was published");
        assert!(
            matches!(store.info("half"), Err(DaemonError::NotFound(_))),
            "and the name reads as absent, not as a truncated artifact"
        );
        // Positive control: the torn upload burned nothing — the same name uploads cleanly after.
        store.create("half", b"whole").expect("the name is free");
        assert_eq!(store.info("half").expect("info").size_bytes, 5);
    }

    // The per-upload cap binds the DISK, not just the reply: it is checked before each chunk is
    // written, so the chunk that would cross it is refused and never lands. RED on the inverse (a
    // cap checked in `finish`, or after the write): the temp file grows past the ceiling — the whole
    // point of capping a stream is that an unbounded client cannot fill the artifacts filesystem.
    #[test]
    fn the_cap_trips_on_the_chunk_that_crosses_it_and_nothing_past_it_reaches_the_disk() {
        let (_d, store) = store(); // cap: 1024 bytes
        let chunk = vec![7u8; 512];
        let mut writer = store.create_streaming("over").expect("open");
        writer.write_chunk(&chunk).expect("512");
        writer.write_chunk(&chunk).expect("1024 — exactly the cap");
        let err = writer
            .write_chunk(&chunk)
            .expect_err("the chunk that crosses the cap must be refused");
        assert!(
            matches!(err, DaemonError::PayloadTooLarge(_)),
            "got {err:?}"
        );
        assert_eq!(err.kind().status_code(), 413);
        assert_eq!(writer.written(), 1024, "the refused chunk was not counted");
        let on_disk: u64 = std::fs::read_dir(store.dir())
            .expect("readdir")
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp"))
            .map(|e| e.metadata().expect("stat").len())
            .sum();
        assert_eq!(on_disk, 1024, "at most `max_bytes` ever reach the disk");
        drop(writer);
        assert!(
            !store.exists("over"),
            "an over-cap upload publishes nothing"
        );
        assert_eq!(temp_files(&store), 0, "and leaves no residue");
    }

    // The create-only and reserved-name laws hold on the streaming path too, and hold BEFORE any
    // byte is read — a client must not be able to make the daemon drain a multi-gigabyte body for a
    // request that was always going to be refused. RED on the inverse (checks moved into `finish`):
    // a temp file appears for each refusal.
    #[test]
    fn the_name_laws_refuse_a_streaming_upload_before_it_opens_a_temp_file() {
        let (_d, store) = big_store();
        store.create("taken", b"first").expect("seed");
        for (name, want) in [
            ("evil.sha256", 400u16), // reserved sidecar suffix
            ("../escape", 400),      // fails the name predicate
            ("taken", 409),          // create-only
        ] {
            let err = store
                .create_streaming(name)
                .err()
                .unwrap_or_else(|| panic!("{name} must be refused"));
            assert_eq!(err.kind().status_code(), want, "{name}: {err:?}");
            assert_eq!(
                temp_files(&store),
                0,
                "{name} was refused before a temp file was opened"
            );
        }
        // Positive control: a fresh, well-formed name opens.
        let w = store.create_streaming("fresh").expect("a good name opens");
        assert_eq!(temp_files(&store), 1);
        drop(w);
    }

    // The buffered verb IS the streaming verb with one chunk (one law, one predicate): the same
    // bytes through either door produce the same digest, the same size and the same sidecar. RED on
    // the inverse (a `create` that re-grows its own copy of the write/hash/persist sequence): the
    // two paths can then disagree, which is exactly how the sidecar and the ceiling drifted before.
    #[test]
    fn the_buffered_create_and_the_streaming_one_agree() {
        let (_d, store) = big_store();
        let bytes: Vec<u8> = (0..300_000).map(|i| (i % 256) as u8).collect();
        let buffered = store.create("one-shot", &bytes).expect("buffered");
        let mut w = store.create_streaming("streamed").expect("open");
        for part in bytes.chunks(9_973) {
            w.write_chunk(part).expect("chunk");
        }
        let streamed = w.finish().expect("publish");
        assert_eq!(buffered.sha256, streamed.sha256);
        assert_eq!(buffered.size_bytes, streamed.size_bytes);
        assert_eq!(
            std::fs::read_to_string(store.dir().join("one-shot.sha256")).expect("sidecar"),
            std::fs::read_to_string(store.dir().join("streamed.sha256")).expect("sidecar"),
        );
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
