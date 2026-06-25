use crate::error::Result;
use crate::artifact::StageOutputs;
use std::path::Path;
use oci_client::{Client, Reference};

/// Builds a root filesystem by pulling from an OCI registry.
pub async fn build_rootfs(image: &str, digest: &str, out: &Path) -> Result<StageOutputs> {
    let client = Client::default();
    let auth = oci_client::secrets::RegistryAuth::Anonymous;
    let reference_str = if digest.starts_with("sha256:") {
        format!("{}@{}", image, digest)
    } else {
        format!("{}:{}", image, digest)
    };
    let reference = Reference::try_from(reference_str.as_str())
        .map_err(|e| crate::error::Error::Artifact(e.to_string()))?;
    
    let (manifest, _) = client.pull_image_manifest(&reference, &auth).await
        .map_err(|e| crate::error::Error::Artifact(e.to_string()))?;
        
    let cache_dir = out.parent().unwrap_or(Path::new(".")).join("oci-cache");
        
    tokio::fs::create_dir_all(&cache_dir).await
        .map_err(|e| crate::error::Error::Artifact(e.to_string()))?;

    let mut streams: Vec<Box<dyn std::io::Read + Send>> = Vec::new();
    let valid_media_types = [
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
        "application/vnd.oci.image.layer.v1.tar+gzip"
    ];

    for layer in manifest.layers {
        if !valid_media_types.contains(&layer.media_type.as_str()) {
            continue;
        }
        
        let digest_str = layer.digest.clone();
        let cache_path = cache_dir.join(digest_str.replace(':', "-"));
        
        if !cache_path.exists() {
            let mut file = tokio::fs::File::create(&cache_path).await
                .map_err(|e| crate::error::Error::Artifact(e.to_string()))?;
            client.pull_blob(&reference, &layer, &mut file).await
                .map_err(|e| crate::error::Error::Artifact(e.to_string()))?;
        }
        
        let file = std::fs::File::open(&cache_path)
            .map_err(|e| crate::error::Error::Artifact(e.to_string()))?;
        let decoder = flate2::read::GzDecoder::new(file);
        streams.push(Box::new(decoder));
    }
    
    super::pack_erofs_with_injection(streams, out).await
}
