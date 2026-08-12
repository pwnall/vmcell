//! Reproducible fetch-and-verify manifest for the vmcell-owned artifacts (v15 §10, The artifact build pipeline).
//!
//! Scope (deliberately narrow): a digest-pinned manifest of the artifacts vmcell *controls*
//! — the guest kernel, the erofs rootfs, the proxy CA, and the resolved pins lock
//! (`<artifacts_dir>/resolved_pins.json`, the `pins` entry) — so a consumer can re-hash them on use
//! and reject a tampered or swapped file. The manifested pins are the RESOLVED document, not the
//! committed `pins.json`: since §18 delta 1 the baseline is embedded in the binary and an overlay
//! may have overridden it, so the repo file is not what the artifacts were built from. The VMM binaries
//! (Cloud Hypervisor / Firecracker / QEMU) are **not** vendored or manifested here: QEMU is
//! GPL (redistribution is a legal question the "external binary" carve-out does not cover),
//! CH/FC are 100+ MB per release, and they already arrive digest-verified by their own pins —
//! fetch-and-verify-by-digest delivers the reproducibility without vendoring (v15 changelog).
//!
//! The digest is the same blake3 content hash the artifact cache uses
//! ([`crate::artifact::hash_file`]) — a single hashing path, never a second one.

use crate::artifact::hash_file;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One manifested artifact: its logical name, the path it was hashed from, and its blake3
/// content digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Logical artifact name (e.g. `"kernel"`, `"rootfs"`, `"ca"`, `"pins"`).
    pub artifact: String,
    /// The artifact's path. As serialized by [`ArtifactManifest::write_to`] this is stored
    /// RELATIVE to the manifest's own directory (L-ART-9), so the manifest travels: it
    /// verifies on any host after the manifest and its artifacts are moved together. A
    /// legacy absolute path is honored as-is by [`ArtifactManifest::verify_in`].
    pub path: PathBuf,
    /// blake3 hex digest of the artifact's bytes.
    pub blake3: String,
}

/// A digest-pinned manifest of the vmcell-owned artifacts, for reproducible
/// fetch-and-verify (v15 §10, The artifact build pipeline).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ArtifactManifest {
    /// The manifested artifacts.
    pub entries: Vec<ManifestEntry>,
}

impl ArtifactManifest {
    /// Builds a manifest by hashing each `(name, path)` via the shared content hasher.
    ///
    /// # Errors
    /// Returns [`Error::Io`] if any artifact cannot be read (a missing artifact is a hard
    /// error, never a silently-omitted entry).
    pub fn build(artifacts: &[(&str, &Path)]) -> Result<Self> {
        let mut entries = Vec::with_capacity(artifacts.len());
        for (name, path) in artifacts {
            entries.push(ManifestEntry {
                artifact: (*name).to_string(),
                path: path.to_path_buf(),
                blake3: hash_file(path)?,
            });
        }
        Ok(Self { entries })
    }

    /// Writes the manifest as pretty JSON to `out`, storing each entry's path RELATIVE to
    /// `out`'s directory (L-ART-9) so the manifest travels. A path that is not under the
    /// manifest directory is written unchanged (it cannot be made portable).
    ///
    /// # Errors
    /// Returns [`Error::Artifact`] on a serialization failure or [`Error::Io`] on a write
    /// failure.
    pub fn write_to(&self, out: &Path) -> Result<()> {
        let base = out.parent().unwrap_or_else(|| Path::new("."));
        let portable = ArtifactManifest {
            entries: self
                .entries
                .iter()
                .map(|e| ManifestEntry {
                    artifact: e.artifact.clone(),
                    path: e
                        .path
                        .strip_prefix(base)
                        .map(Path::to_path_buf)
                        .unwrap_or_else(|_| e.path.clone()),
                    blake3: e.blake3.clone(),
                })
                .collect(),
        };
        let json = serde_json::to_string_pretty(&portable)
            .map_err(|e| Error::Artifact(format!("manifest serialization failed: {e}")))?;
        std::fs::write(out, json).map_err(Error::Io)
    }

    /// Re-hashes every entry (resolving relative paths against `base`) and FAILS HARD on the
    /// first digest mismatch — a tampered artifact (or one swapped under an otherwise-intact
    /// manifest) is rejected, never trusted on the strength of the manifest's recorded digest
    /// alone (§10.2, The stage model and the five cache-key rules / verify what you ingest). An absolute entry path is used as-is (legacy).
    ///
    /// # Errors
    /// Returns [`Error::Artifact`] on any digest mismatch, or [`Error::Io`] if an entry's
    /// file cannot be read.
    pub fn verify_in(&self, base: &Path) -> Result<()> {
        for entry in &self.entries {
            let resolved = if entry.path.is_absolute() {
                entry.path.clone()
            } else {
                base.join(&entry.path)
            };
            let actual = hash_file(&resolved)?;
            if actual != entry.blake3 {
                return Err(Error::Artifact(format!(
                    "artifact `{}` digest mismatch at {}: manifest {}, actual {}",
                    entry.artifact,
                    resolved.display(),
                    entry.blake3,
                    actual
                )));
            }
        }
        Ok(())
    }

    /// Re-hashes every entry, resolving a relative path against the current directory. Prefer
    /// [`ArtifactManifest::verify_file`], which resolves against the manifest's own directory.
    ///
    /// # Errors
    /// Returns [`Error::Artifact`] on any digest mismatch, or [`Error::Io`] if an entry's
    /// file cannot be read.
    pub fn verify(&self) -> Result<()> {
        self.verify_in(Path::new("."))
    }

    /// Loads a manifest from a JSON file and verifies it, resolving each relative entry path
    /// against the MANIFEST's own directory (L-ART-9) so a moved bundle still verifies.
    ///
    /// # Errors
    /// Returns [`Error::Io`] / [`Error::Artifact`] on a read or parse failure, or on a digest
    /// mismatch.
    pub fn verify_file(manifest_path: &Path) -> Result<()> {
        let json = std::fs::read_to_string(manifest_path).map_err(Error::Io)?;
        let manifest: Self = serde_json::from_str(&json)
            .map_err(|e| Error::Artifact(format!("malformed manifest JSON: {e}")))?;
        let base = manifest_path.parent().unwrap_or_else(|| Path::new("."));
        manifest.verify_in(base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // §10 (The artifact build pipeline) / verify-what-you-ingest: an intact manifest verifies, but a TAMPERED artifact
    // (bytes changed under the same path, manifest digest unchanged) must be rejected. The
    // inverse — trusting the manifest's recorded digest without re-hashing the file — would
    // accept the tampered bytes and goes red here.
    #[test]
    fn test_manifest_rejects_tampered_artifact() {
        let dir = tempfile::tempdir().expect("tempdir");
        let k = dir.path().join("vmlinux");
        std::fs::write(&k, b"kernel-bytes-v1").expect("write");
        let manifest = ArtifactManifest::build(&[("kernel", k.as_path())]).expect("build");

        // Intact: verifies OK.
        manifest.verify().expect("an intact manifest must verify");

        // Tamper the artifact in place; the manifest's recorded digest is now stale.
        std::fs::write(&k, b"kernel-bytes-TAMPERED").expect("rewrite");
        let err = manifest
            .verify()
            .expect_err("a tampered artifact must be rejected");
        assert!(
            matches!(err, Error::Artifact(_)),
            "expected a digest-mismatch Artifact error, got {err:?}"
        );
    }

    // The JSON round-trip (build -> write_to -> verify_file) must verify an untouched bundle.
    #[test]
    fn test_manifest_file_roundtrip_verifies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = dir.path().join("rootfs.erofs");
        let b = dir.path().join("ca.pem");
        std::fs::write(&a, b"erofs").expect("write");
        std::fs::write(&b, b"-----CA-----").expect("write");
        let manifest = ArtifactManifest::build(&[("rootfs", a.as_path()), ("ca", b.as_path())])
            .expect("build");
        let mp = dir.path().join("manifest.json");
        manifest.write_to(&mp).expect("write manifest");
        ArtifactManifest::verify_file(&mp).expect("a written, untouched manifest must verify");
    }

    // L-ART-9: a manifest must travel. Build it referencing an artifact under dir A, then move
    // the manifest + artifact to dir B (a different host) and verify. With machine-local
    // absolute paths stored (the bug), verify_file resolves the vanished A path and fails ->
    // red; storing paths relative to the manifest dir resolves B and passes.
    #[test]
    fn test_manifest_travels_across_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = dir.path().join("A");
        let b = dir.path().join("B");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();

        std::fs::write(a.join("artifact"), b"bytes").unwrap();
        let manifest =
            ArtifactManifest::build(&[("art", a.join("artifact").as_path())]).expect("build");
        let ma = a.join("manifest.json");
        manifest.write_to(&ma).expect("write");

        // Move the manifest AND the artifact to B, then drop A entirely (host A is gone).
        std::fs::write(b.join("artifact"), b"bytes").unwrap();
        let mb = b.join("manifest.json");
        std::fs::rename(&ma, &mb).unwrap();
        std::fs::remove_dir_all(&a).unwrap();

        ArtifactManifest::verify_file(&mb)
            .expect("a moved manifest + artifact must still verify (paths travel)");
    }
}
