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

/// Refuses to bundle an artifacts dir whose **resolved pins** name an F7 dev path-override
/// (§10.5's "…and is **refused by `bundle`**"; §18 delta 6c).
///
/// # Why the resolved pins, and not a `--pins` overlay
///
/// A bundle is a claim about a directory that *already exists*. `vmcell bundle` therefore takes no
/// overlay and resolves no registry: judging a previously-built dir against **today's** overlay
/// would answer a different question than the one asked, and would pass or fail on a file the
/// build never read. `resolved_pins.json` is the document the pipeline published *into that dir*,
/// is already a manifest entry, and is the only honest answer to "what was this built from" that a
/// bare artifacts dir can give.
///
/// An **absent** `resolved_pins.json` is not a refusal: a dir with no pipeline output has nothing
/// to be unpinned about, and `bundle` already reports the absence in its skipped-artifact notice.
///
/// # Errors
/// [`Error::Artifact`] naming every unpinned pin key (each of which names its label) when one is
/// present, or when the document exists but cannot be read or parsed — a resolved-pins document
/// that cannot be read is a dir whose provenance cannot be checked, which is not the same as one
/// that has none.
pub fn reject_unpinned_registrations(resolved_pins: &Path) -> Result<()> {
    if !resolved_pins.exists() {
        return Ok(());
    }
    let json = std::fs::read_to_string(resolved_pins).map_err(|e| {
        Error::Artifact(format!(
            "failed to read {} to check for unpinned registrations: {e}",
            resolved_pins.display()
        ))
    })?;
    let doc: serde_json::Value = serde_json::from_str(&json).map_err(|e| {
        Error::Artifact(format!(
            "malformed resolved pins at {}: {e}",
            resolved_pins.display()
        ))
    })?;
    let unpinned = crate::artifact::unpinned_registration_pins(&doc);
    if unpinned.is_empty() {
        return Ok(());
    }
    Err(Error::Artifact(format!(
        "refusing to bundle: {} artifact registration(s) in {} resolve through the `{}` dev \
         override ({}). A bundle is a DURABLE PROVENANCE CLAIM — every entry is a digest a \
         consumer re-verifies later — and an unpinned registration means \"whatever was at that \
         path that day\", which no later verify can reproduce (§10.5, F7). Re-register the \
         label(s) with an `image` + `digest` (rootfs) or a `digest` + `source.url` (handler), \
         rebuild, and bundle that.",
        unpinned.len(),
        resolved_pins.display(),
        crate::artifact::registry::UNPINNED_PATH_KEY,
        unpinned.join(", ")
    )))
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

    /// Writes a resolved-pins document into `dir` and returns its path.
    fn write_resolved_pins(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("resolved_pins.json");
        std::fs::write(&path, body).expect("write resolved pins");
        path
    }

    // §10.5's F7, last clause: an unpinned registration is **refused by `bundle`**. A bundle is a
    // durable provenance claim — every entry is a digest a consumer re-verifies later — and an
    // unpinned registration means "whatever was at that path that day", which no later verify can
    // reproduce.
    //
    // Both kinds, because the two registries share one law and a refusal that covered only the
    // rootfs would let a consumer's own handler slip a dev binary into a bundle.
    //
    // RED on the inverse, two ways: (a) a refusal that only checks the `rootfs` namespace — the
    // handler leg passes; (b) a refusal keyed on the pin key's SUFFIX alone — the negative control
    // below (a `kernel_fragments` fragment named `unpinned_path`) is falsely refused.
    #[test]
    fn a_resolved_pins_document_naming_an_unpinned_registration_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        for (kind, body, named) in [
            (
                "rootfs",
                r#"{"rootfs": {"acme": {"unpinned_path": "/tmp/dev.erofs"}}}"#,
                "rootfs_acme_unpinned_path",
            ),
            (
                "handler",
                r#"{"handlers": {"acme": {"unpinned_path": "/tmp/dev-handler"}}}"#,
                "handler_acme_unpinned_path",
            ),
            (
                "the default label",
                r#"{"rootfs": {"default": {"unpinned_path": "/tmp/dev.erofs"}}}"#,
                "rootfs_unpinned_path",
            ),
        ] {
            let path = write_resolved_pins(dir.path(), body);
            let msg = match reject_unpinned_registrations(&path) {
                Err(e) => e.to_string(),
                Ok(()) => panic!("an unpinned {kind} registration must be refused"),
            };
            assert!(
                msg.contains(named),
                "the refusal must name the unpinned entry `{named}`: {msg}"
            );
            assert!(
                msg.contains("bundle"),
                "the refusal must say what it refused to do: {msg}"
            );
        }

        // POSITIVE CONTROL, the one AGENTS.md demands for every negative result: the same document
        // with the unpinned entry replaced by a digest registration passes. Without it this test
        // would also pass against a `bundle` that refused everything.
        let pinned = write_resolved_pins(
            dir.path(),
            &format!(
                r#"{{"rootfs": {{"acme": {{"image": "i", "digest": "sha256:{}"}}}},
                    "handlers": {{"acme": {{"digest": "sha256:{}",
                                            "source": {{"url": "https://example.invalid/h"}}}}}}}}"#,
                "a".repeat(64),
                "b".repeat(64)
            ),
        );
        reject_unpinned_registrations(&pinned).expect("a fully digest-pinned document must bundle");

        // …and a fragment that merely ENDS in the key is not an unpinned registration: refusing it
        // would be a false accusation with a real cost (an un-bundleable artifacts dir).
        let lookalike = write_resolved_pins(
            dir.path(),
            r#"{"kernel_fragments": {"unpinned_path": "CONFIG_X=y"}}"#,
        );
        reject_unpinned_registrations(&lookalike)
            .expect("a kernel fragment is not a registration shape");

        // An ABSENT document is not a refusal: a dir with no pipeline output has nothing to be
        // unpinned about, and `bundle` already reports the absence in its skip notice.
        reject_unpinned_registrations(&dir.path().join("nope.json"))
            .expect("an absent resolved-pins document is not an unpinned one");

        // A document that exists but cannot be parsed IS a hard stop: a dir whose provenance cannot
        // be read is not the same as one that has none.
        let broken = write_resolved_pins(dir.path(), "{not json");
        assert!(
            reject_unpinned_registrations(&broken).is_err(),
            "an unreadable resolved-pins document must not be silently treated as pinned"
        );
    }
}
