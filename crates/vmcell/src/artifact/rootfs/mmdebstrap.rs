use crate::agent::ExecRequest;
use crate::artifact::{StageInputs, StageOutputs};
use crate::config::{Access, CachePolicy, Egress, NetConfig, RootfsSource, Share, VmConfig};
use crate::error::{Error, Result};
use crate::orchestrator::{MicroVm, VmidAllocator};
use crate::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::Path;

use std::time::Duration;

/// Builds a root filesystem using mmdebstrap inside a builder micro-VM.
///
/// # Errors
/// Returns an error if the VM boot or mmdebstrap process fails.
pub async fn build_rootfs(
    release: &str,
    inputs: &StageInputs,
    out: &Path,
    cid_alloc: std::sync::Arc<crate::vmm::CidAllocator>,
) -> Result<StageOutputs> {
    let vmlinux_path = inputs
        .artifacts
        .get("kernel")
        .ok_or_else(|| Error::Artifact("kernel artifact is required to boot builder VM".into()))?;

    let temp_dir = tempfile::TempDir::new().map_err(Error::Io)?;
    let builder_rootfs_path = temp_dir.path().join("builder_rootfs.erofs");

    // 1. Build builder rootfs using OCI source. Source the builder base image+digest from
    // the resolved pins (Stage 0 / pins.lock) so it cannot drift from the pinned rootfs.
    // The image and digest are resolved as one ATOMIC pair — never an independent fallback
    // that could mix a pinned image with a stale hardcoded digest (M-PIPE-2).
    let (builder_image, builder_digest) = resolve_builder_base(&inputs.pins)?;
    tracing::info!("Building builder VM rootfs from {}...", builder_image);
    super::oci::build_rootfs(
        &builder_image,
        &builder_digest,
        inputs,
        &builder_rootfs_path,
        // The builder VM uses the default glibc agent (its OCI base ships libc6).
        None,
    )
    .await?;

    // 2. Start builder VM. Shared resolver so this stage and the snapshot stage read
    // the SAME env var (VMCELL_CH_BIN) — no per-call-site CH-binary drift.
    let ch_bin = crate::artifact::ch_binary_path();
    let vmm = CloudHypervisor::new(ch_bin);
    // cid_alloc is passed in
    let vmid_alloc = VmidAllocator::new();

    let host_out_dir = tempfile::TempDir::new().map_err(Error::Io)?;
    let share = Share::new(
        "vmcell-out",
        host_out_dir.path().to_path_buf(),
        Access::ReadWrite,
        CachePolicy::Never,
    );

    let cfg = VmConfig::builder(
        vmlinux_path.clone(),
        RootfsSource::Erofs {
            image: builder_rootfs_path,
        },
    )
    .with_share(share)
    .net(NetConfig::Unprivileged {
        egress: Egress::Open,
        host_services_port: None,
    })
    .build()?;

    tracing::info!("Starting builder VM...");
    let mut vm = MicroVm::start(
        &vmm,
        cfg,
        cid_alloc.clone(),
        vmid_alloc,
        Box::new(crate::metrics::DefaultCgroupFs),
    )
    .await?;

    // Use a helper scope to ensure vm is shutdown on error
    let build_res = async {
        tracing::info!("Connecting to builder VM agent...");
        let agent = vm.agent(None, &crate::orchestrator::RealClock).await?;

        // 3. Install mmdebstrap in VM
        tracing::info!("Installing mmdebstrap inside builder VM...");
        let outcome_update = agent
            .exec(
                ExecRequest::new(vec!["apt-get".to_string(), "update".to_string()])
                    .with_timeout(Duration::from_secs(120)),
            )
            .await?;
        if outcome_update.code != 0 {
            return Err(Error::Artifact(format!(
                "apt-get update failed with code {}: {}",
                outcome_update.code,
                String::from_utf8_lossy(&outcome_update.stderr)
            )));
        }

        let outcome_install = agent
            .exec(
                ExecRequest::new(vec![
                    "apt-get".to_string(),
                    "install".to_string(),
                    "-y".to_string(),
                    "mmdebstrap".to_string(),
                    "ca-certificates".to_string(),
                ])
                .with_timeout(Duration::from_secs(240)),
            )
            .await?;
        if outcome_install.code != 0 {
            return Err(Error::Artifact(format!(
                "apt-get install mmdebstrap failed with code {}: {}",
                outcome_install.code,
                String::from_utf8_lossy(&outcome_install.stderr)
            )));
        }

        // 4. Run mmdebstrap inside builder VM
        tracing::info!("Running mmdebstrap inside builder VM...");
        let timestamp = inputs
            .pins
            .get("debian_snapshot_timestamp")
            .ok_or_else(|| Error::Artifact("Missing debian_snapshot_timestamp pin".into()))?;
        let mirror = format!(
            "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/{}/ {} main",
            timestamp, release
        );
        let outcome_mmdebstrap = agent
            .exec(
                ExecRequest::new(vec![
                    "mmdebstrap".to_string(),
                    "--variant=apt".to_string(),
                    "--include=curl,ca-certificates".to_string(),
                    release.to_string(),
                    "/vmcell-out/rootfs.tar".to_string(),
                    mirror,
                ])
                .with_timeout(Duration::from_secs(600)),
            )
            .await?;
        if outcome_mmdebstrap.code != 0 {
            return Err(Error::Artifact(format!(
                "mmdebstrap inside VM failed with code {}: {}",
                outcome_mmdebstrap.code,
                String::from_utf8_lossy(&outcome_mmdebstrap.stderr)
            )));
        }

        Ok(())
    }
    .await;

    // Shutdown builder VM
    tracing::info!("Shutting down builder VM...");
    let _ = vm.shutdown().await;

    build_res?;

    // 5. Pack target EROFS from the generated tarball
    let tar_path = host_out_dir.path().join("rootfs.tar");
    if !tar_path.exists() {
        return Err(Error::Artifact(
            "mmdebstrap succeeded but rootfs.tar is missing".into(),
        ));
    }

    let tar_file = std::fs::File::open(&tar_path).map_err(Error::Io)?;
    let tar_stream: Box<dyn std::io::Read + Send> = Box::new(tar_file);

    // The mmdebstrap source produces a full Debian rootfs (with libc6) and uses the default
    // glibc agent — no static-musl override.
    super::pack_erofs_with_injection(vec![tar_stream], inputs, out, None).await
}

/// Resolves the builder base image as an atomic `(image, digest)` pair from the
/// resolved pins, never mixing a pinned image with a hardcoded digest.
///
/// Precedence: the dedicated `builder_base_*` pins, else the `rootfs_*` pins. A
/// half-specified pair (image without digest, or vice-versa) or a completely
/// missing base is a hard error — a hardcoded fallback would mask a missing Stage-0
/// pin and could pin a mismatched `image@digest` reference (M-PIPE-2 / B5
/// "no fallback masking a missing upstream").
///
/// # Errors
/// Returns [`Error::Artifact`] if no pin pair is present, or only one half of a
/// pair is set.
fn resolve_builder_base(
    pins: &std::collections::HashMap<String, String>,
) -> Result<(String, String)> {
    for (img_key, dig_key) in [
        ("builder_base_image", "builder_base_digest"),
        ("rootfs_image", "rootfs_digest"),
    ] {
        match (pins.get(img_key), pins.get(dig_key)) {
            (Some(img), Some(dig)) => return Ok((img.clone(), dig.clone())),
            (Some(_), None) | (None, Some(_)) => {
                return Err(Error::Artifact(format!(
                    "builder base pin pair half-specified: exactly one of \
                     {img_key}/{dig_key} is set; provide both or neither"
                )));
            }
            (None, None) => {}
        }
    }
    Err(Error::Artifact(
        "missing builder base image+digest pins (builder_base_* or rootfs_*); \
         refusing hardcoded fallback (would pin a mismatched image@digest)"
            .into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::resolve_builder_base;
    use std::collections::HashMap;

    // Guards M-PIPE-2: image and digest must resolve as ONE atomic pair, never an
    // independent fallback. The buggy impl defaulted each half separately, so a
    // half-specified pin (image without digest) silently paired with a hardcoded
    // debian digest — a mismatched reference. Each branch below is red on that impl.
    #[test]
    fn test_resolve_builder_base_pairs_atomically() {
        // image without digest must error (not pair with a hardcoded digest).
        let mut half = HashMap::new();
        half.insert(
            "rootfs_image".to_string(),
            "docker.io/library/debian".to_string(),
        );
        assert!(
            resolve_builder_base(&half).is_err(),
            "image without digest must error, not pair with a hardcoded digest"
        );

        // digest without image must also error.
        let mut half2 = HashMap::new();
        half2.insert("rootfs_digest".to_string(), "sha256:abc".to_string());
        assert!(resolve_builder_base(&half2).is_err());

        // Completely missing base errors (no hardcoded fallback masks a missing pin).
        assert!(resolve_builder_base(&HashMap::new()).is_err());

        // A complete rootfs pair resolves atomically.
        let mut full = HashMap::new();
        full.insert("rootfs_image".to_string(), "img".to_string());
        full.insert("rootfs_digest".to_string(), "sha256:abc".to_string());
        assert_eq!(
            resolve_builder_base(&full).expect("pair"),
            ("img".to_string(), "sha256:abc".to_string())
        );

        // Dedicated builder pins take precedence over the rootfs pins.
        let mut both = full.clone();
        both.insert("builder_base_image".to_string(), "bimg".to_string());
        both.insert("builder_base_digest".to_string(), "sha256:def".to_string());
        assert_eq!(
            resolve_builder_base(&both).expect("pair"),
            ("bimg".to_string(), "sha256:def".to_string())
        );
    }
}
