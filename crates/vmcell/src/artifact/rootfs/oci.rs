use crate::artifact::StageOutputs;
use crate::error::Result;
use async_trait::async_trait;
use oci_client::manifest::{OciImageManifest, OciManifest};
use oci_client::{Client, Reference};
use std::path::Path;

/// A single OCI layer's decode-relevant identity: its media type (selects the gzip/zstd
/// decoder and gates decodability) and its `sha256:` content digest (names the cache file
/// and is re-verified on every use).
#[derive(Debug, Clone)]
pub(crate) struct OciLayerDesc {
    /// The layer's media type.
    pub media_type: String,
    /// The layer's `sha256:...` content digest.
    pub digest: String,
}

/// Injectable OCI pull seam (ART-3).
///
/// The network pull sits behind a trait so the whole pull→cache→re-verify→decode chain in
/// [`build_rootfs_with`] can be driven by a recording/replaying fake that serves canned
/// manifest layers + blobs — no registry, no network — so the cache-hit re-verify,
/// tag-rejection, and gzip/zstd decode-selection each fail on their inverse in the default
/// suite (contrast the old inline `Client::default()`, which left the chain untested).
#[async_trait]
pub(crate) trait OciPuller: Send + Sync {
    /// Resolve `reference` to its ordered layer descriptors, verifying manifest provenance.
    ///
    /// # Errors
    /// Returns [`crate::error::Error::Artifact`] if the manifest cannot be fetched or its
    /// bytes do not match the pinned digest.
    async fn resolve_layers(&self, reference: &Reference) -> Result<Vec<OciLayerDesc>>;

    /// Pull the blob named by `digest` into `out`.
    ///
    /// # Errors
    /// Returns [`crate::error::Error::Artifact`] if the blob cannot be fetched.
    async fn pull_blob(&self, reference: &Reference, digest: &str, out: &mut Vec<u8>)
    -> Result<()>;
}

/// The real, network-backed puller over `oci_client::Client`.
struct RealOciPuller {
    client: Client,
    auth: oci_client::secrets::RegistryAuth,
}

impl RealOciPuller {
    fn new() -> Self {
        Self {
            client: Client::default(),
            auth: oci_client::secrets::RegistryAuth::Anonymous,
        }
    }
}

#[async_trait]
impl OciPuller for RealOciPuller {
    async fn resolve_layers(&self, reference: &Reference) -> Result<Vec<OciLayerDesc>> {
        // Re-hash the RAW manifest bytes against the pinned digest IN-CODE (ART-5 / A8
        // "verify everything you ingest"). `pull_manifest_raw` already validates the body
        // against the reference digest internally (oci-client 0.17 `validate_digest`), so
        // this is defense-in-depth: we hash exactly the bytes we received and compare to the
        // `sha256:` pin ourselves rather than trusting the transport/library alone.
        let accepted = [
            oci_client::manifest::OCI_IMAGE_MEDIA_TYPE,
            oci_client::manifest::IMAGE_MANIFEST_MEDIA_TYPE,
            oci_client::manifest::OCI_IMAGE_INDEX_MEDIA_TYPE,
            oci_client::manifest::IMAGE_MANIFEST_LIST_MEDIA_TYPE,
        ];
        let (raw, _digest) = self
            .client
            .pull_manifest_raw(reference, &self.auth, &accepted)
            .await
            .map_err(|e| crate::error::Error::Artifact(e.to_string()))?;
        if let Some(pinned) = reference.digest() {
            verify_blob_digest(&raw, pinned)?;
        }
        // Read the ordered layers straight out of the VERIFIED raw bytes (M-ART-3): the
        // layer list we consume must descend from exactly the bytes we hashed against the
        // pin, never a second, independently-fetched manifest whose verification we delegate
        // to the library (a registry answering the two fetches differently would defeat the
        // pin). The old code re-fetched via `pull_image_manifest` and discarded `raw`.
        match parse_oci_manifest(&raw)? {
            OciManifest::Image(m) => Ok(map_layers(m)),
            OciManifest::ImageIndex(idx) => {
                // Multi-arch index: select the platform sub-manifest, then fetch + VERIFY it
                // against the digest carried in the (already-verified) index, so the layer
                // list still descends from the pin. Host-platform selection matches the
                // prior default-client behavior (unchanged for a single-platform pin).
                let sub_digest = oci_client::client::current_platform_resolver(&idx.manifests)
                    .ok_or_else(|| {
                        crate::error::Error::Artifact(
                            "OCI image index has no entry matching the host platform".into(),
                        )
                    })?;
                let sub_ref = reference.clone_with_digest(sub_digest.clone());
                let (sub_raw, _d) = self
                    .client
                    .pull_manifest_raw(&sub_ref, &self.auth, &accepted)
                    .await
                    .map_err(|e| crate::error::Error::Artifact(e.to_string()))?;
                verify_blob_digest(&sub_raw, &sub_digest)?;
                match parse_oci_manifest(&sub_raw)? {
                    OciManifest::Image(m) => Ok(map_layers(m)),
                    OciManifest::ImageIndex(_) => Err(crate::error::Error::Artifact(
                        "OCI image index pointed at a nested index (unsupported)".into(),
                    )),
                }
            }
        }
    }

    async fn pull_blob(
        &self,
        reference: &Reference,
        digest: &str,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        self.client
            .pull_blob(reference, digest, out)
            .await
            .map_err(|e| crate::error::Error::Artifact(e.to_string()))
    }
}

/// Builds a root filesystem by pulling from an OCI registry (the real network puller).
///
/// `options` carries everything the shared inject+pack tail is told beyond the layers themselves —
/// the downstream `extra` files (§4.2, FR-V4), the optional static-musl steward, and the handler
/// applet roster (§10.5); `PackOptions::default()` is a rootfs that carries no consumer content and
/// the default handler's roster.
///
/// # Errors
/// Returns an error if the registry pull or unpacking fails.
pub async fn build_rootfs(
    image: &str,
    digest: &str,
    inputs: &crate::artifact::StageInputs,
    out: &Path,
    options: &super::PackOptions,
) -> Result<StageOutputs> {
    build_rootfs_with(&RealOciPuller::new(), image, digest, inputs, out, options).await
}

/// The digest-pinned base image's layers, decoded into tar streams **in layer order** — the
/// pull→cache→re-verify→decode half of [`build_rootfs`], stopping short of the pack.
///
/// Public because §4.2's external repacking is "compose more layers over a *registered* base": a
/// caller that wants the pinned base plus its own tar layer has to be able to name the base's
/// layers without re-implementing the digest verification that makes them trustworthy. It is the
/// **same** implementation [`build_rootfs`] runs — one pull→verify→decode law, two callers — so a
/// composed pack can never resolve the base differently from a plain one. The one in-tree consumer
/// today is the §15.4 xattr battery, whose `Preserve` input is a synthetic PAX layer merged over
/// this base (the pinned Debian rootfs carries no `SCHILY.xattr` record of its own).
///
/// The returned streams are lazy decoders over the on-disk blob cache: nothing is read until the
/// packer reads it.
///
/// # Errors
/// Returns [`crate::error::Error::Artifact`] if `digest` is not `sha256:`-pinned, if the manifest
/// or a blob cannot be fetched or fails its digest re-verification, or if a layer's media type is
/// one this builder cannot decode.
pub async fn base_layer_tar_streams(
    image: &str,
    digest: &str,
) -> Result<Vec<Box<dyn std::io::Read + Send>>> {
    layer_tar_streams_with(&RealOciPuller::new(), image, digest).await
}

/// The pull→cache→re-verify→decode→pack core, parameterized over an injectable
/// [`OciPuller`] so the whole chain is testable without a registry (ART-3).
async fn build_rootfs_with(
    puller: &dyn OciPuller,
    image: &str,
    digest: &str,
    inputs: &crate::artifact::StageInputs,
    out: &Path,
    options: &super::PackOptions,
) -> Result<StageOutputs> {
    let streams = layer_tar_streams_with(puller, image, digest).await?;
    // The GENERAL tail, never `pack_erofs_with_injection`: that door refuses by name anything but
    // `RootfsFormat::Erofs` (§4.7), so a `rootfs` registry entry declaring `format: ext4` pulled its
    // layers and then died on the door — the format was an accepted input no registry-driven build
    // could honor, and delta 8's producer was reachable only through the `unpinned_path` dev
    // registration, which `bundle` refuses by design. `options.format` chooses the emitter here.
    super::pack_rootfs_with_injection(streams, inputs, out, options).await
}

/// The pull→cache→re-verify→decode half, parameterized over the same injectable [`OciPuller`]
/// so the fake-driven chain tests keep covering it.
async fn layer_tar_streams_with(
    puller: &dyn OciPuller,
    image: &str,
    digest: &str,
) -> Result<Vec<Box<dyn std::io::Read + Send>>> {
    // Digest-pinned pulls only: a tag (or any non-`sha256:` reference) is the §10.2 (The
    // stage model and the five cache-key rules) provenance hard stop and is rejected BEFORE
    // any network I/O — never a tag fallback.
    if !digest.starts_with("sha256:") {
        return Err(crate::error::Error::Artifact(format!(
            "OCI pull requires a digest starting with 'sha256:', got {digest}"
        )));
    }
    let reference_str = format!("{image}@{digest}");
    let reference = Reference::try_from(reference_str.as_str())
        .map_err(|e| crate::error::Error::Artifact(e.to_string()))?;

    let layers = puller.resolve_layers(&reference).await?;

    // The blob cache is sited on the ARTIFACTS dir, never on `out`'s parent: both in-VM builders
    // pass an `out` inside a per-run `TempDir`, so an output-relative cache died with the run and
    // re-pulled this digest-pinned base every time. One composer, `oci_cache_dir` (which also
    // states why sharing it across outputs is safe).
    let cache_dir = crate::artifact::oci_cache_dir();
    tokio::fs::create_dir_all(&cache_dir)
        .await
        .map_err(|e| crate::error::Error::Artifact(e.to_string()))?;

    let mut streams: Vec<Box<dyn std::io::Read + Send>> = Vec::new();

    for layer in layers {
        // A layer whose media type we cannot decode must NOT be silently skipped:
        // dropping a real layer yields an incomplete rootfs that boots as if complete
        // (silent corruption). Fail loud instead (B2 / A8).
        check_layer_media_type(&layer.media_type)?;

        let cache_path = cache_dir.join(layer.digest.replace(':', "-"));

        if !cache_path.exists() {
            let mut blob_data = Vec::new();
            puller
                .pull_blob(&reference, &layer.digest, &mut blob_data)
                .await?;

            // Verify before caching so corrupt network data is never persisted.
            verify_blob_digest(&blob_data, &layer.digest)?;
            tokio::fs::write(&cache_path, &blob_data)
                .await
                .map_err(|e| crate::error::Error::Artifact(e.to_string()))?;
        }

        // Re-verify the (possibly cached) blob on EVERY use: a tampered cache file with an
        // intact digest-derived name must be rejected. Validity is content-addressed, not
        // existence-based.
        read_and_verify_cached_blob(&cache_path, &layer.digest)?;

        let file = std::fs::File::open(&cache_path)
            .map_err(|e| crate::error::Error::Artifact(e.to_string()))?;

        if is_zstd_layer(&layer.media_type) {
            let decoder = zstd::stream::read::Decoder::new(file)
                .map_err(|e| crate::error::Error::Artifact(e.to_string()))?;
            streams.push(Box::new(decoder));
        } else {
            let decoder = flate2::read::GzDecoder::new(file);
            streams.push(Box::new(decoder));
        }
    }

    Ok(streams)
}

/// The OCI/Docker layer media types this builder can decode (gzip and zstd
/// tar layers). A layer outside this set cannot be unpacked.
const DECODABLE_LAYER_MEDIA_TYPES: [&str; 3] = [
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
];

/// Returns whether `media_type` ends with `zstd` (vs gzip) for decoder selection.
fn is_zstd_layer(media_type: &str) -> bool {
    media_type.ends_with("zstd")
}

/// Fails loud if `media_type` is not a layer type this builder can decode.
///
/// Silently skipping an unrecognized layer would drop its files from the rootfs,
/// producing an incomplete image that boots as if complete. Erroring surfaces the
/// missing-decoder case at build time instead of as a mysterious runtime gap.
///
/// # Errors
/// Returns [`crate::error::Error::Artifact`] if `media_type` is not in
/// [`DECODABLE_LAYER_MEDIA_TYPES`].
fn check_layer_media_type(media_type: &str) -> Result<()> {
    if DECODABLE_LAYER_MEDIA_TYPES.contains(&media_type) {
        Ok(())
    } else {
        Err(crate::error::Error::Artifact(format!(
            "unsupported OCI layer media type {media_type:?}: cannot decode, \
             rootfs would be incomplete (supported: {DECODABLE_LAYER_MEDIA_TYPES:?})"
        )))
    }
}

/// Verifies `blob` against a `sha256:...` digest string.
fn verify_blob_digest(blob: &[u8], expected_digest: &str) -> Result<()> {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(blob);
    // sha2 0.11 `finalize()` returns a `hybrid_array::Array` (no `LowerHex`); format the
    // 32 bytes as lowercase hex explicitly (byte-identical to the old `{:x}`).
    let out: [u8; 32] = hasher.finalize().into();
    let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
    let hash = format!("sha256:{hex}");
    if hash != expected_digest {
        return Err(crate::error::Error::Artifact(format!(
            "blob digest mismatch: expected {expected_digest}, got {hash}"
        )));
    }
    Ok(())
}

/// Reads a cached blob from disk and verifies its sha256 digest, rejecting tampered bytes.
fn read_and_verify_cached_blob(cache_path: &Path, expected_digest: &str) -> Result<()> {
    let blob_data =
        std::fs::read(cache_path).map_err(|e| crate::error::Error::Artifact(e.to_string()))?;
    verify_blob_digest(&blob_data, expected_digest)
}

/// Parses the ALREADY-VERIFIED raw manifest bytes into an [`OciManifest`] (M-ART-3), so the
/// layers we consume come from exactly the bytes we hashed against the pin. The untagged
/// enum distinguishes a single-platform image manifest (has `config` + `layers`) from a
/// multi-arch index (has `manifests`); the caller descends an index by its verified digests.
///
/// # Errors
/// Returns [`crate::error::Error::Artifact`] if the bytes are not a valid OCI manifest.
fn parse_oci_manifest(raw: &[u8]) -> Result<OciManifest> {
    serde_json::from_slice(raw).map_err(|e| {
        crate::error::Error::Artifact(format!("failed to parse verified OCI manifest bytes: {e}"))
    })
}

/// Maps an [`OciImageManifest`]'s ordered layers to the decode-relevant [`OciLayerDesc`]s.
fn map_layers(manifest: OciImageManifest) -> Vec<OciLayerDesc> {
    manifest
        .layers
        .into_iter()
        .map(|l| OciLayerDesc {
            media_type: l.media_type,
            digest: l.digest,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Guards ARTIFACT-PIPELINE-7: the digest was verified only inside `if !cache_path.exists()`,
    // so a cache hit reused the blob unverified. Re-verifying on every use must reject a
    // tampered cache file (intact digest-derived name, altered bytes).
    #[test]
    fn test_cached_blob_tamper_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("blob");
        let good = b"hello oci layer";
        std::fs::write(&path, good).expect("write");

        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(good);
        let out: [u8; 32] = h.finalize().into();
        let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
        let digest = format!("sha256:{hex}");

        // Correct cached content verifies.
        assert!(read_and_verify_cached_blob(&path, &digest).is_ok());

        // A tampered cache file must be rejected on use.
        std::fs::write(&path, b"tampered bytes").expect("write");
        assert!(
            read_and_verify_cached_blob(&path, &digest).is_err(),
            "tampered cached blob must be rejected on every use"
        );
    }

    // Guards the LOW media-type finding: a layer we cannot decode must be a hard
    // error, never silently skipped (which would drop its files and yield an
    // incomplete rootfs). The buggy `continue` made this branch silent → red here.
    #[test]
    fn test_unsupported_layer_media_type_errors() {
        // Decodable types pass.
        for mt in DECODABLE_LAYER_MEDIA_TYPES {
            assert!(
                check_layer_media_type(mt).is_ok(),
                "{mt} should be decodable"
            );
        }
        // An uncompressed or foreign layer type is rejected, not skipped.
        assert!(check_layer_media_type("application/vnd.oci.image.layer.v1.tar").is_err());
        assert!(
            check_layer_media_type("application/vnd.docker.image.rootfs.foreign.diff.tar.gzip")
                .is_err()
        );
        // Decoder selection: zstd vs gzip.
        assert!(is_zstd_layer("application/vnd.oci.image.layer.v1.tar+zstd"));
        assert!(!is_zstd_layer(
            "application/vnd.oci.image.layer.v1.tar+gzip"
        ));
    }

    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A recording/replaying OCI pull seam (ART-3): serves canned layer descriptors + blobs
    /// from memory, counting resolve/blob calls, so the pull→cache→re-verify→decode chain
    /// runs with no registry and no network.
    struct FakeOciPuller {
        layers: Vec<OciLayerDesc>,
        blobs: HashMap<String, Vec<u8>>,
        resolve_calls: AtomicUsize,
        blob_calls: AtomicUsize,
    }

    #[async_trait]
    impl OciPuller for FakeOciPuller {
        async fn resolve_layers(&self, _reference: &Reference) -> Result<Vec<OciLayerDesc>> {
            self.resolve_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.layers.clone())
        }

        async fn pull_blob(
            &self,
            _reference: &Reference,
            digest: &str,
            out: &mut Vec<u8>,
        ) -> Result<()> {
            self.blob_calls.fetch_add(1, Ordering::SeqCst);
            let blob = self.blobs.get(digest).ok_or_else(|| {
                crate::error::Error::Artifact(format!("fake: no blob for {digest}"))
            })?;
            out.extend_from_slice(blob);
            Ok(())
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(bytes);
        let out: [u8; 32] = h.finalize().into();
        let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
        format!("sha256:{hex}")
    }

    fn build_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            for (path, body) in files {
                let mut h = tar::Header::new_gnu();
                h.set_size(body.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, path, *body).unwrap();
            }
            b.finish().unwrap();
        }
        buf
    }

    /// A gzip-compressed tar layer; returns `(bytes, digest, media_type)`.
    fn gzip_layer(files: &[(&str, &[u8])]) -> (Vec<u8>, String, String) {
        let tar = build_tar(files);
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&tar).unwrap();
        let gz = enc.finish().unwrap();
        let digest = sha256_hex(&gz);
        (
            gz,
            digest,
            "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
        )
    }

    /// A zstd-compressed tar layer; returns `(bytes, digest, media_type)`.
    fn zstd_layer(files: &[(&str, &[u8])]) -> (Vec<u8>, String, String) {
        let tar = build_tar(files);
        let z = zstd::stream::encode_all(std::io::Cursor::new(tar), 0).unwrap();
        let digest = sha256_hex(&z);
        (
            z,
            digest,
            "application/vnd.oci.image.layer.v1.tar+zstd".to_string(),
        )
    }

    // ART-3: a tag (non-`sha256:`) reference is the §10.2 (The stage model and the five
    // cache-key rules) provenance hard stop and must be rejected BEFORE any pull. A
    // tag-fallback pull that reached the puller reddens the
    // `resolve_calls == 0` assertion.
    #[tokio::test]
    async fn test_oci_tag_digest_rejected() {
        let fake = FakeOciPuller {
            layers: vec![],
            blobs: HashMap::new(),
            resolve_calls: AtomicUsize::new(0),
            blob_calls: AtomicUsize::new(0),
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("rootfs.erofs");
        let inputs = crate::artifact::StageInputs::default();
        let res = build_rootfs_with(
            &fake,
            "example.com/img",
            "latest",
            &inputs,
            &out,
            &crate::artifact::rootfs::PackOptions::default(),
        )
        .await;
        assert!(
            matches!(res, Err(crate::error::Error::Artifact(_))),
            "a tag-fallback (non-digest) pull must be rejected, got {res:?}"
        );
        assert_eq!(
            fake.resolve_calls.load(Ordering::SeqCst),
            0,
            "a rejected tag pull must not resolve any manifest"
        );
    }

    /// Removes the blobs a test seeded in the SHARED [`oci_cache_dir`](crate::artifact::oci_cache_dir),
    /// on the success and the panic path alike.
    ///
    /// A test's own fixtures are residue too (AGENTS.md, "Writing tests"), and here a leftover is
    /// not merely untidy: the tamper leg below writes corrupt bytes under a digest-derived name,
    /// and a corrupt blob left in the shared cache poisons the NEXT run's *cold* build, whose
    /// every-use re-verify rejects it. The blob contents carry a per-run nonce, so two concurrent
    /// test processes never name — or clean up — each other's files.
    #[cfg(feature = "am-fs-erofs")]
    struct CachedBlobGuard(Vec<std::path::PathBuf>);

    #[cfg(feature = "am-fs-erofs")]
    impl Drop for CachedBlobGuard {
        fn drop(&mut self) {
            for p in &self.0 {
                match std::fs::remove_file(p) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    // Never panic in `Drop` (it would abort an unwinding failure); report loud
                    // instead, since a leftover blob poisons the next run's cold build.
                    Err(e) => eprintln!(
                        "test residue: failed to remove the cached blob {}: {e}",
                        p.display()
                    ),
                }
            }
        }
    }

    // ART-3: drive the full pull→cache→re-verify→decode→pack chain through the fake, then a
    // cache HIT, then a hit from a DIFFERENT output dir, then a tamper — all in ONE test so the
    // CA-materialization tail (`CaManager::new()` on the shared artifacts dir) is never entered
    // concurrently by two test processes racing on it. This is the only unit test that reaches
    // that tail.
    //
    // Asserts: (1) cold build pulls every layer and packs a non-empty erofs — the zstd layer
    // proves decode-SELECTION, since a gzip decoder on zstd bytes would fail the tar read;
    // (2) a warm build re-verifies but does NOT re-pull cached blobs (blob_calls stays ==
    // layer count); (3) a build whose OUTPUT DIR is a different, empty directory still hits the
    // cache — the blob cache is sited on the artifacts dir, not on `out.parent()`, and an
    // output-relative cache re-pulled the digest-pinned builder base on every in-VM-builder run
    // (both pass an `out` inside a per-run `TempDir`); (4) a byte-corrupted cached blob with an
    // intact digest-derived filename is rejected on the hit path. Each inverse (skip re-verify on
    // hit, re-pull on hit, output-relative cache, wrong decoder) reddens a distinct assertion.
    #[cfg(feature = "am-fs-erofs")]
    #[tokio::test]
    async fn test_oci_pull_cache_hit_reverify_and_tamper() {
        // A per-run nonce in the layer content makes both blob digests — and therefore both
        // shared-cache filenames — unique to this run, so a concurrent or previous run can
        // neither serve nor corrupt this test's cache entries.
        let nonce = format!("{}-{}", std::process::id(), uuid::Uuid::new_v4());
        let (gz, gz_dig, gz_mt) = gzip_layer(&[
            ("lib/x86_64-linux-gnu/libc.so.6", b"ELF-libc"),
            ("etc/os-release", b"base"),
            ("etc/vmcell-test-nonce", nonce.as_bytes()),
        ]);
        let (zs, zs_dig, zs_mt) = zstd_layer(&[("marker.txt", nonce.as_bytes())]);
        let mut blobs = HashMap::new();
        blobs.insert(gz_dig.clone(), gz);
        blobs.insert(zs_dig.clone(), zs);
        let fake = FakeOciPuller {
            layers: vec![
                OciLayerDesc {
                    media_type: gz_mt,
                    digest: gz_dig.clone(),
                },
                OciLayerDesc {
                    media_type: zs_mt,
                    digest: zs_dig.clone(),
                },
            ],
            blobs,
            resolve_calls: AtomicUsize::new(0),
            blob_calls: AtomicUsize::new(0),
        };

        // The cache path is recomputed through the production composer, never a test-local
        // `join("oci-cache")`, so a siting change cannot leave this test asserting on a stale
        // location.
        let cache_file = crate::artifact::oci_cache_dir().join(gz_dig.replace(':', "-"));
        let _residue = CachedBlobGuard(vec![
            cache_file.clone(),
            crate::artifact::oci_cache_dir().join(zs_dig.replace(':', "-")),
        ]);

        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("rootfs.erofs");
        let steward = dir.path().join("steward");
        std::fs::write(&steward, b"#!steward").unwrap();
        let mut inputs = crate::artifact::StageInputs::default();
        inputs.artifacts.insert("steward".to_string(), steward);
        let digest = sha256_hex(b"manifest-bytes");

        // (1) Cold build: every layer pulled, erofs produced (gzip + zstd both decode).
        build_rootfs_with(
            &fake,
            "example.com/img",
            &digest,
            &inputs,
            &out,
            &crate::artifact::rootfs::PackOptions::default(),
        )
        .await
        .expect("cold build");
        assert_eq!(
            fake.blob_calls.load(Ordering::SeqCst),
            2,
            "cold build must pull every layer"
        );
        assert!(
            out.metadata().unwrap().len() > 0,
            "the packed erofs must be non-empty"
        );

        // (2) Warm build: cached blobs are re-verified but NOT re-pulled.
        build_rootfs_with(
            &fake,
            "example.com/img",
            &digest,
            &inputs,
            &out,
            &crate::artifact::rootfs::PackOptions::default(),
        )
        .await
        .expect("warm build");
        assert_eq!(
            fake.blob_calls.load(Ordering::SeqCst),
            2,
            "a cache hit must not re-pull the blobs"
        );
        assert_eq!(
            fake.resolve_calls.load(Ordering::SeqCst),
            2,
            "resolve runs on each build"
        );

        // (3) The cache is independent of the OUTPUT dir: build into a fresh, empty directory
        // (what both in-VM builders do — a per-run `TempDir`) and require no re-pull. With the
        // cache sited on `out.parent()` this directory has none, so both blobs are pulled again
        // and `blob_calls` reaches 4.
        let other_dir = tempfile::tempdir().expect("tempdir");
        let other_out = other_dir.path().join("builder_rootfs.erofs");
        build_rootfs_with(
            &fake,
            "example.com/img",
            &digest,
            &inputs,
            &other_out,
            &crate::artifact::rootfs::PackOptions::default(),
        )
        .await
        .expect("build into a different output dir");
        assert_eq!(
            fake.blob_calls.load(Ordering::SeqCst),
            2,
            "the blob cache must survive a change of output dir — an output-relative cache \
             re-pulls the digest-pinned base on every in-VM-builder run"
        );
        assert!(
            !other_dir.path().join("oci-cache").exists(),
            "the cache must not be created beside the stage output"
        );

        // (4) Tamper a cached blob (intact digest-derived filename) → rejected on the hit
        // path by the every-use re-verify.
        std::fs::write(&cache_file, b"tampered-cache-bytes").unwrap();
        let res = build_rootfs_with(
            &fake,
            "example.com/img",
            &digest,
            &inputs,
            &out,
            &crate::artifact::rootfs::PackOptions::default(),
        )
        .await;
        assert!(
            matches!(res, Err(crate::error::Error::Artifact(_))),
            "a tampered cached blob must be rejected on the hit path, got {res:?}"
        );
    }

    // §4.7 / §18 delta 8, at the seam every registry-driven rootfs build packs through: this
    // function must call the GENERAL tail, so a `rootfs` entry declaring `format: ext4` builds.
    //
    // It called `pack_erofs_with_injection`, the erofs-only door, which refuses any other format BY
    // NAME — so `vmcell build --rootfs-label <an ext4 label>` resolved the entry, missed the cache,
    // pulled every layer, and then died on `pack_erofs_with_injection was handed format: ext4`. The
    // `format` key was an accepted input no registry-driven build could honor, and delta 8's
    // producer was reachable only through the `unpinned_path` dev registration, which `bundle`
    // refuses by design.
    //
    // The assertion discriminates on EVERY host, which is what keeps this out of the skip manifest:
    // where the producer is available the pack must write a real ext4 superblock, and where it is
    // absent (or the `ext4-producer` feature is off) the refusal must be §4.7's own TYPED
    // `CapabilityUnavailable`. The door's refusal is an `Error::Artifact` naming itself, so it is
    // neither — the buggy call site reddens both ways.
    //
    // RED on the inverse (call `pack_erofs_with_injection` again): the `other` arm panics quoting
    // the door. The erofs leg at the end is the positive control — the same layers, the same fake,
    // the default format — so a pack that failed for a reason unrelated to the format cannot pass.
    #[cfg(feature = "am-fs-erofs")]
    #[tokio::test]
    async fn the_oci_stage_packs_through_the_general_tail_so_an_ext4_label_builds() {
        crate::artifact::rootfs::stabilize_ca();
        // Per-run nonce, for the same reason the chain test above carries one: the blob cache is
        // shared, so this layer's digest — and therefore its cache filename — must be this run's.
        let nonce = format!("{}-{}", std::process::id(), uuid::Uuid::new_v4());
        let (gz, gz_dig, gz_mt) = gzip_layer(&[
            ("lib/x86_64-linux-gnu/libc.so.6", b"ELF-libc"),
            ("etc/vmcell-test-nonce", nonce.as_bytes()),
        ]);
        let mut blobs = HashMap::new();
        blobs.insert(gz_dig.clone(), gz);
        let fake = FakeOciPuller {
            layers: vec![OciLayerDesc {
                media_type: gz_mt,
                digest: gz_dig.clone(),
            }],
            blobs,
            resolve_calls: AtomicUsize::new(0),
            blob_calls: AtomicUsize::new(0),
        };
        let _residue = CachedBlobGuard(vec![
            crate::artifact::oci_cache_dir().join(gz_dig.replace(':', "-")),
        ]);

        let dir = tempfile::tempdir().expect("tempdir");
        let steward = dir.path().join("steward");
        std::fs::write(&steward, b"#!steward").expect("write the steward stand-in");
        let mut inputs = crate::artifact::StageInputs::default();
        inputs.artifacts.insert("steward".to_string(), steward);
        let digest = sha256_hex(b"ext4-manifest-bytes");

        // The filename is composed through the one law, so it carries the declared format's
        // extension exactly as `RootfsStage::out_path` would.
        let out = dir.path().join(crate::artifact::rootfs::rootfs_filename(
            Some("acme"),
            crate::artifact::RootfsFormat::Ext4,
        ));
        let res = build_rootfs_with(
            &fake,
            "example.com/img",
            &digest,
            &inputs,
            &out,
            &crate::artifact::rootfs::PackOptions::new()
                .with_label(Some("acme"))
                .with_format(crate::artifact::RootfsFormat::Ext4),
        )
        .await;
        match res {
            Ok(outputs) => {
                // The ext4 superblock magic (`0xEF53`, little-endian, at byte 0x438 — offset 56 of
                // the superblock, which starts at 1024). Asserted on the BYTES rather than on
                // "the file exists", which an erofs image at an `.ext4` name would also satisfy.
                let image = std::fs::read(&out).expect("read the packed image");
                assert!(
                    image.len() > 0x43a,
                    "the packed image is too small to hold a superblock: {} bytes",
                    image.len()
                );
                assert_eq!(
                    &image[0x438..0x43a],
                    &[0x53, 0xef],
                    "the declared format must reach the emitter: no ext4 superblock magic at 0x438"
                );
                assert_eq!(
                    outputs
                        .artifacts
                        .get(&crate::artifact::rootfs::rootfs_artifact_key(Some("acme")))
                        .map(std::path::PathBuf::as_path),
                    Some(out.as_path()),
                    "the ext4 pack must register under its own label's key: {outputs:?}"
                );
            }
            // §4.7's own probe classifying an absent facility (no `mkfs.ext4`, too old, no
            // libarchive) or the `ext4-producer` feature compiled out. Honest either way — and it
            // still proves the request reached the FORMAT gate instead of the erofs door.
            Err(crate::error::Error::CapabilityUnavailable { op, needed }) => {
                assert!(op.contains("ext4"), "the op names the operation: {op}");
                assert!(
                    needed.contains("e2fsprogs")
                        || needed.contains("libarchive")
                        || needed.contains("ext4-producer"),
                    "the refusal must name the absent facility: {needed}"
                );
            }
            other => panic!(
                "an ext4 registry entry must pack (or be typed-refused by §4.7's probe), never die \
                 on the erofs-only door: {other:?}"
            ),
        }

        // Positive control: the same layers through the same fake at the DEFAULT format pack an
        // erofs image, so nothing above can pass because the pull or the merge was broken.
        let erofs_out = dir.path().join(crate::artifact::rootfs::rootfs_filename(
            Some("acme"),
            crate::artifact::RootfsFormat::Erofs,
        ));
        build_rootfs_with(
            &fake,
            "example.com/img",
            &digest,
            &inputs,
            &erofs_out,
            &crate::artifact::rootfs::PackOptions::new().with_label(Some("acme")),
        )
        .await
        .expect("the default format must still pack through the same seam");
        assert!(
            erofs_out.metadata().expect("stat the erofs image").len() > 0,
            "the erofs control must produce a non-empty image"
        );
    }

    // ART-4: a zstd-compressed layer must decode (via the `is_zstd_layer` selection) to its
    // non-empty tar content. A gzip decoder on zstd bytes would fail the tar read → red.
    #[test]
    fn test_zstd_layer_decodes_to_nonempty() {
        let (z, _dig, mt) = zstd_layer(&[("marker.txt", b"hello-zstd")]);
        assert!(is_zstd_layer(&mt));
        let decoder = zstd::stream::read::Decoder::new(std::io::Cursor::new(z)).unwrap();
        let mut archive = tar::Archive::new(decoder);
        let mut found = false;
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.path().unwrap().to_string_lossy() == "marker.txt" {
                let mut s = String::new();
                entry.read_to_string(&mut s).unwrap();
                assert_eq!(s, "hello-zstd");
                found = true;
            }
        }
        assert!(found, "zstd layer must decode to its non-empty tar content");
    }

    // M-ART-3: the ordered layer list must come from parsing the VERIFIED raw manifest
    // bytes, not a second, independently-fetched manifest. This exercises the parse-from-
    // verified-bytes mechanism that replaced the discarded-then-refetched second fetch: an
    // image manifest's layers are read straight out of its bytes, in order.
    #[test]
    fn test_parse_manifest_layers_from_verified_bytes() {
        let manifest_json = r#"{
            "schemaVersion": 2,
            "config": {"mediaType":"application/vnd.oci.image.config.v1+json",
                       "digest":"sha256:cfg","size":1},
            "layers": [
                {"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip",
                 "digest":"sha256:layer1","size":2},
                {"mediaType":"application/vnd.oci.image.layer.v1.tar+zstd",
                 "digest":"sha256:layer2","size":3}
            ]
        }"#;
        let layers = match parse_oci_manifest(manifest_json.as_bytes()).expect("parse") {
            OciManifest::Image(m) => map_layers(m),
            OciManifest::ImageIndex(_) => panic!("expected a single-platform image manifest"),
        };
        assert_eq!(layers.len(), 2, "both layers must be read from the bytes");
        assert_eq!(layers[0].digest, "sha256:layer1");
        assert_eq!(
            layers[1].media_type, "application/vnd.oci.image.layer.v1.tar+zstd",
            "layer order and media type must be preserved from the verified bytes"
        );
    }

    // M-ART-3: a multi-arch index must parse as `ImageIndex` (not accidentally as an empty
    // image manifest) so `resolve_layers` descends it by fetching + VERIFYING the platform
    // sub-manifest by its index-carried digest, rather than trusting a delegated second fetch.
    #[test]
    fn test_parse_manifest_distinguishes_index() {
        let index_json = r#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {"mediaType":"application/vnd.oci.image.manifest.v1+json",
                 "digest":"sha256:amd64","size":1,
                 "platform":{"architecture":"amd64","os":"linux"}}
            ]
        }"#;
        assert!(
            matches!(
                parse_oci_manifest(index_json.as_bytes()).expect("parse"),
                OciManifest::ImageIndex(_)
            ),
            "a multi-arch manifest list must parse as ImageIndex, not an image manifest"
        );
    }
}
