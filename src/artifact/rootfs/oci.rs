use crate::artifact::StageOutputs;
use crate::error::Result;
use oci_client::{Client, Reference};
use std::path::Path;

/// Builds a root filesystem by pulling from an OCI registry.
///
/// # Errors
/// Returns an error if the registry pull or unpacking fails.
pub async fn build_rootfs(
    image: &str,
    digest: &str,
    inputs: &crate::artifact::StageInputs,
    out: &Path,
) -> Result<StageOutputs> {
    let client = Client::default();
    let auth = oci_client::secrets::RegistryAuth::Anonymous;
    if !digest.starts_with("sha256:") {
        return Err(crate::error::Error::Artifact(format!(
            "OCI pull requires a digest starting with 'sha256:', got {}",
            digest
        )));
    }
    let reference_str = format!("{}@{}", image, digest);
    let reference = Reference::try_from(reference_str.as_str())
        .map_err(|e| crate::error::Error::Artifact(e.to_string()))?;

    let (manifest, _) = client
        .pull_image_manifest(&reference, &auth)
        .await
        .map_err(|e| crate::error::Error::Artifact(e.to_string()))?;

    let cache_dir = out.parent().unwrap_or(Path::new(".")).join("oci-cache");

    tokio::fs::create_dir_all(&cache_dir)
        .await
        .map_err(|e| crate::error::Error::Artifact(e.to_string()))?;

    let mut streams: Vec<Box<dyn std::io::Read + Send>> = Vec::new();
    let valid_media_types = [
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.oci.image.layer.v1.tar+zstd",
    ];

    for layer in manifest.layers {
        if !valid_media_types.contains(&layer.media_type.as_str()) {
            continue;
        }

        let digest_str = layer.digest.clone();
        let cache_path = cache_dir.join(digest_str.replace(':', "-"));

        if !cache_path.exists() {
            let mut blob_data = Vec::new();
            client
                .pull_blob(&reference, &layer, &mut blob_data)
                .await
                .map_err(|e| crate::error::Error::Artifact(e.to_string()))?;

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

        if layer.media_type.ends_with("zstd") {
            let decoder = zstd::stream::read::Decoder::new(file)
                .map_err(|e| crate::error::Error::Artifact(e.to_string()))?;
            streams.push(Box::new(decoder));
        } else {
            let decoder = flate2::read::GzDecoder::new(file);
            streams.push(Box::new(decoder));
        }
    }

    super::pack_erofs_with_injection(streams, inputs, out).await
}

/// Verifies `blob` against a `sha256:...` digest string.
fn verify_blob_digest(blob: &[u8], expected_digest: &str) -> Result<()> {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(blob);
    let hash = format!("sha256:{:x}", hasher.finalize());
    if hash != expected_digest {
        return Err(crate::error::Error::Artifact(format!(
            "blob digest mismatch: expected {}, got {}",
            expected_digest, hash
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
        let digest = format!("sha256:{:x}", h.finalize());

        // Correct cached content verifies.
        assert!(read_and_verify_cached_blob(&path, &digest).is_ok());

        // A tampered cache file must be rejected on use.
        std::fs::write(&path, b"tampered bytes").expect("write");
        assert!(
            read_and_verify_cached_blob(&path, &digest).is_err(),
            "tampered cached blob must be rejected on every use"
        );
    }
}
