use crate::error::Result;
use crate::artifact::StageOutputs;
use std::path::Path;
use oci_client::{Client, Reference};

/// Builds a root filesystem by pulling from an OCI registry.
pub async fn build_rootfs(image: &str, digest: &str, out: &Path) -> Result<StageOutputs> {
    let mut client = Client::default();
    let auth = oci_client::secrets::RegistryAuth::Anonymous;
    let reference_str = if digest.starts_with("sha256:") {
        format!("{}@{}", image, digest)
    } else {
        format!("{}:{}", image, digest)
    };
    let reference = Reference::try_from(reference_str.as_str())
        .map_err(|e| crate::error::Error::Artifact(e.to_string()))?;
    
    // pull image layers.
    let oci_image = client.pull(&reference, &auth, vec![])
        .await
        .map_err(|e| crate::error::Error::Artifact(e.to_string()))?;
    
    let mut streams: Vec<Box<dyn std::io::Read + Send>> = Vec::new();
    for layer in oci_image.layers {
        let cursor = std::io::Cursor::new(layer.data);
        let decoder = flate2::read::GzDecoder::new(cursor);
        streams.push(Box::new(decoder));
    }
    
    super::pack_erofs_with_injection(streams, out).await
}
