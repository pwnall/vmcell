//! In-VM guest-kernel builder (design v20 §8.5).
//!
//! Where `vmcell`'s bootstrap kernel producers run on the host (`KernelStage` compiles
//! with `make`, `PrebuiltKernelStage` downloads a pinned prebuilt), this crate compiles a
//! kernel **inside a `vmcell` builder micro-VM**: the host downloads and SHA-verifies the
//! pinned kernel *source* tarball (provenance stays host-side), shares it **read-only** into
//! the builder VM, and the guest installs a toolchain and runs `make` to produce `vmlinux`,
//! which is copied back out over a read-write share.
//!
//! It is a [`vmcell::artifact::Stage`] so the composition root (`vmcell-cli`) can wire it
//! into a `vmcell` [`vmcell::artifact::Pipeline`] in place of a bootstrap kernel stage. It
//! depends on `vmcell` for VM lifecycle and reuses `vmcell`'s shared build utilities (the
//! OCI builder-base packer, the `HttpClient` seam, the blake3 hash helpers); `vmcell` has no
//! dependency on this crate (§10.1).
//!
//! ## The seed-kernel chicken-and-egg (§8.5)
//! Booting the builder VM needs a *pre-existing* working `vmlinux` — the **seed** — which
//! this stage reads from the `kernel` upstream artifact. That seed is produced by one of
//! `vmcell`'s bootstrap kernel stages (a pinned prebuilt, or the host-`make` compile), so the
//! bootstrap seed cannot be removed even once this in-VM path exists.
#![deny(missing_docs, unsafe_op_in_unsafe_fn, rustdoc::broken_intra_doc_links)]
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::dbg_macro
    )
)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use vmcell::artifact::kernel::HttpClient;
use vmcell::artifact::{CacheKey, Stage, StageInputs, StageOutputs};
use vmcell::config::{Access, CachePolicy, Egress, NetConfig, RootfsSource, Share, VmConfig};
use vmcell::error::{Error, Result};
use vmcell::orchestrator::{MicroVm, RealClock, VmidAllocator};
use vmcell::vmm::CidAllocator;
use vmcell::vmm::cloud_hypervisor::CloudHypervisor;
use vmcell::{ExecOutcome, ExecRequest};

/// A pipeline stage that compiles a `vmlinux` **inside a builder micro-VM** (§8.5).
///
/// Produces the `kernel` artifact exactly like the bootstrap kernel stages, so downstream
/// consumers cannot tell how it was built. Requires a seed kernel (the `kernel` upstream
/// artifact) to boot its own builder VM.
pub struct InVmKernelStage {
    /// HTTP client used to fetch the pinned kernel source tarball on the host.
    pub http_client: Arc<dyn HttpClient>,
    /// Optional kernel-version label selecting an entry from the `kernels` pins registry
    /// (mirrors [`vmcell::artifact::kernel::KernelStage`]); `None` builds the default `kernel`
    /// pin. A labelled stage builds `vmlinux-<label>` under a distinct cache + artifact key.
    pub label: Option<String>,
    /// Optional ordered set of named KConfig fragments layered onto the base config, resolved
    /// from the `kernel_fragments` pins registry (§8.3). Canonicalized to sorted order so the
    /// same set in any order hits the same cache.
    pub fragments: Option<Vec<String>>,
    /// CID allocator for the builder VM this stage boots.
    pub cid_alloc: Arc<CidAllocator>,
}

/// The fragment names, **sorted** and de-duplicated (§8.3): the on-disk `.config` append order
/// and the cache key are independent of the request order.
fn sorted_fragments(fragments: &Option<Vec<String>>) -> Vec<String> {
    let mut names = fragments.clone().unwrap_or_default();
    names.sort();
    names.dedup();
    names
}

/// The pins key holding the KConfig text for the named fragment (mirrors `KernelStage`).
fn fragment_pin_key(name: &str) -> String {
    format!("kernel_fragments_{name}")
}

/// The pins keys holding this kernel's source URL / SHA256 (label-aware, mirrors `KernelStage`).
fn url_pin_key(label: &Option<String>) -> String {
    match label {
        Some(l) => format!("kernel_{l}_source_url"),
        None => "kernel_source_url".to_string(),
    }
}
fn sha_pin_key(label: &Option<String>) -> String {
    match label {
        Some(l) => format!("kernel_{l}_source_sha256"),
        None => "kernel_source_sha256".to_string(),
    }
}

/// The filename suffix (`""` or `-<sanitized-label>`), sanitizing `.`→`-` so a dotted version
/// does not collide the `.cache_key` sidecar via `Path::with_extension` (mirrors `KernelStage`).
fn suffix(label: &Option<String>) -> String {
    label
        .as_ref()
        .map(|l| format!("-{}", l.replace('.', "-")))
        .unwrap_or_default()
}

/// The artifact-map key this stage registers its `vmlinux` under (`"kernel"` for the default,
/// `"kernel-<label>"` for a labelled build), matching the bootstrap kernel stages.
fn artifact_key(label: &Option<String>) -> String {
    match label {
        Some(l) => format!("kernel-{l}"),
        None => "kernel".to_string(),
    }
}

/// The full concatenated KConfig text appended after `make defconfig kvm_guest.config`: the
/// base `kernel_microvm_config` plus each requested fragment's text, in **sorted** order. A
/// requested fragment missing from the pins registry is a hard error — never a silent skip
/// that builds a kernel without the requested instrumentation (§8.3).
///
/// # Errors
/// [`Error::Artifact`] if a requested fragment name is absent from the pins.
fn kconfig_append(inputs: &StageInputs, fragments: &[String]) -> Result<String> {
    let mut out = inputs
        .pins
        .get("kernel_microvm_config")
        .ok_or_else(|| Error::Artifact("Missing kernel_microvm_config pin".into()))?
        .clone();
    for name in fragments {
        let frag = inputs.pins.get(&fragment_pin_key(name)).ok_or_else(|| {
            Error::Artifact(format!(
                "missing kernel fragment `{name}` in pins (expected key `{}`)",
                fragment_pin_key(name)
            ))
        })?;
        out.push('\n');
        out.push_str(frag);
    }
    Ok(out)
}

/// The ordered guest command sequence that extracts the shared source, installs a toolchain,
/// and compiles `vmlinux` (§8.5). Kept a **pure** function so the sequence is unit-testable
/// without a VM. `nproc` is passed so the build parallelism is explicit/testable.
///
/// The shared read-only source tarball is at `/vmcell-src/linux.tar.xz`, the KConfig append at
/// `/vmcell-src/kconfig-append`, and the output share is `/vmcell-out`.
fn build_commands() -> Vec<(&'static str, Vec<String>, Duration)> {
    let sh = |s: &str| vec!["sh".to_string(), "-c".to_string(), s.to_string()];
    vec![
        (
            "apt-get update",
            vec!["apt-get".into(), "update".into()],
            Duration::from_secs(120),
        ),
        (
            "apt-get install toolchain",
            vec![
                "apt-get".into(),
                "install".into(),
                "-y".into(),
                "--no-install-recommends".into(),
                "build-essential".into(),
                "bc".into(),
                "bison".into(),
                "flex".into(),
                "libelf-dev".into(),
                "libssl-dev".into(),
                "xz-utils".into(),
            ],
            Duration::from_secs(300),
        ),
        (
            "extract source",
            sh(
                "mkdir -p /build && tar -xf /vmcell-src/linux.tar.xz -C /build --strip-components=1",
            ),
            Duration::from_secs(180),
        ),
        (
            "make defconfig kvm_guest.config",
            sh("cd /build && make defconfig kvm_guest.config"),
            Duration::from_secs(120),
        ),
        (
            "append microvm config + fragments",
            sh("cat /vmcell-src/kconfig-append >> /build/.config"),
            Duration::from_secs(30),
        ),
        (
            "make olddefconfig",
            sh("cd /build && make olddefconfig"),
            Duration::from_secs(120),
        ),
        (
            "make vmlinux",
            sh("cd /build && make -j\"$(nproc)\" vmlinux"),
            // A cold kernel build is long (a KASAN build can be ~45–90 min, §8.4); bound it
            // generously rather than fall through a timeout to a false success.
            Duration::from_secs(7200),
        ),
        (
            "copy vmlinux out",
            sh("cp /build/vmlinux /vmcell-out/vmlinux"),
            Duration::from_secs(60),
        ),
    ]
}

/// Turns a guest [`ExecOutcome`] into a fail-loud [`Result`]: a non-zero exit at any step is a
/// hard [`Error::Artifact`] carrying the step name + stderr, never an "any-result → success"
/// swallow (§8.5, AGENTS.md failure-handling).
///
/// # Errors
/// [`Error::Artifact`] when `outcome.code != 0`.
fn check_step(step: &str, outcome: &ExecOutcome) -> Result<()> {
    if outcome.code != 0 {
        return Err(Error::Artifact(format!(
            "in-VM kernel build step `{step}` failed with code {}: {}",
            outcome.code,
            String::from_utf8_lossy(&outcome.stderr)
        )));
    }
    Ok(())
}

#[async_trait]
impl Stage for InVmKernelStage {
    fn name(&self) -> &str {
        self.label.as_deref().unwrap_or("kernel")
    }

    fn out_path(&self, target_dir: &Path) -> std::path::PathBuf {
        target_dir.join(format!("vmlinux{}", suffix(&self.label)))
    }

    fn cache_key(&self, inputs: &StageInputs) -> CacheKey {
        // Bump when this stage's build logic changes so stale kernels are not served.
        const STAGE_VERSION: u32 = 1;
        const SEP: &[u8] = b"\x1f";
        let mut hasher = blake3::Hasher::new();
        hasher.update(&STAGE_VERSION.to_le_bytes());
        hasher.update(SEP);
        hasher.update(b"in-vm");
        hasher.update(SEP);
        hasher.update(self.label.as_deref().unwrap_or_default().as_bytes());
        hasher.update(SEP);
        hasher.update(
            inputs
                .pins
                .get(&url_pin_key(&self.label))
                .map(String::as_bytes)
                .unwrap_or_default(),
        );
        hasher.update(SEP);
        hasher.update(
            inputs
                .pins
                .get(&sha_pin_key(&self.label))
                .map(String::as_bytes)
                .unwrap_or_default(),
        );
        hasher.update(SEP);
        hasher.update(
            inputs
                .pins
                .get("kernel_microvm_config")
                .map(String::as_bytes)
                .unwrap_or_default(),
        );
        // Fold the fragment set (name + KConfig content) in SORTED order (§8.3): the same set
        // in any order hashes identically, and editing a fragment's text invalidates the key.
        let fragments = sorted_fragments(&self.fragments);
        hasher.update(SEP);
        hasher.update(&(fragments.len() as u32).to_le_bytes());
        for name in &fragments {
            hasher.update(SEP);
            hasher.update(name.as_bytes());
            hasher.update(SEP);
            hasher.update(
                inputs
                    .pins
                    .get(&fragment_pin_key(name))
                    .map(String::as_bytes)
                    .unwrap_or_default(),
            );
        }
        // The compiled bytes depend on the in-guest toolchain, which comes from the builder
        // base image; fold its resolved image@digest so a builder-base bump invalidates the
        // kernel (mirrors the mmdebstrap rootfs builder). A resolution failure folds empty
        // strings; `run()` re-resolves and fails loud on a genuinely-missing pin.
        let (builder_image, builder_digest) =
            vmcell::artifact::rootfs::resolve_builder_base(&inputs.pins).unwrap_or_default();
        hasher.update(SEP);
        hasher.update(builder_image.as_bytes());
        hasher.update(SEP);
        hasher.update(builder_digest.as_bytes());
        CacheKey::new(format!("kernel-in-vm-{}", hasher.finalize().to_hex()))
    }

    async fn run(&self, inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        // The seed kernel that boots the builder VM (the chicken-and-egg, §8.5). Missing is a
        // hard error — never a boot from a fallback path.
        let seed_kernel = inputs.artifacts.get("kernel").cloned().ok_or_else(|| {
            Error::Artifact(
                "in-VM kernel builder needs a seed `kernel` artifact to boot its builder VM \
                 (produce one with the prebuilt or host-make bootstrap stage first, §8.5)"
                    .into(),
            )
        })?;

        // Host-fetch + SHA-verify the pinned kernel SOURCE (provenance stays host-side), then
        // stage it into a read-only share for the guest.
        let url = inputs
            .pins
            .get(&url_pin_key(&self.label))
            .ok_or_else(|| Error::Artifact(format!("Missing {} pin", url_pin_key(&self.label))))?;
        let expected_sha = inputs
            .pins
            .get(&sha_pin_key(&self.label))
            .ok_or_else(|| Error::Artifact(format!("Missing {} pin", sha_pin_key(&self.label))))?;

        let fragments = sorted_fragments(&self.fragments);
        let kconfig_append = kconfig_append(inputs, &fragments)?;

        let src_dir = tempfile::TempDir::new().map_err(Error::Io)?;
        let bytes = self.http_client.get(url).await?;
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&bytes);
        let got = format!("{:x}", hasher.finalize());
        if &got != expected_sha {
            return Err(Error::Artifact(format!(
                "kernel source tarball hash mismatch: expected {expected_sha}, got {got} (url {url})"
            )));
        }
        tokio::fs::write(src_dir.path().join("linux.tar.xz"), &bytes).await?;
        tokio::fs::write(src_dir.path().join("kconfig-append"), &kconfig_append).await?;

        // Builder-base rootfs via the OCI bootstrap source (its toolchain is apt-installed).
        let (builder_image, builder_digest) =
            vmcell::artifact::rootfs::resolve_builder_base(&inputs.pins)?;
        let builder_rootfs = src_dir.path().join("builder_rootfs.erofs");
        vmcell::artifact::rootfs::oci::build_rootfs(
            &builder_image,
            &builder_digest,
            inputs,
            &builder_rootfs,
            None,
        )
        .await?;

        // Read-only source share + read-write output share.
        let out_dir = tempfile::TempDir::new().map_err(Error::Io)?;
        let src_share = Share::new(
            "vmcell-src",
            src_dir.path().to_path_buf(),
            Access::ReadOnly,
            CachePolicy::Never,
        );
        let out_share = Share::new(
            "vmcell-out",
            out_dir.path().to_path_buf(),
            Access::ReadWrite,
            CachePolicy::Never,
        );

        // The builder VM boots on the PRIVILEGED network path with open egress so apt can
        // install the toolchain (§8.5 / v20 §16). This is a build-time developer/CI operation;
        // CAP_NET_ADMIN is acceptable there.
        let cfg = VmConfig::builder(
            seed_kernel,
            RootfsSource::Erofs {
                image: builder_rootfs,
            },
        )
        .with_share(src_share)
        .with_share(out_share)
        .net(NetConfig::Privileged {
            egress: Egress::Open,
            host_services_port: None,
        })
        .build()?;

        let vmm = CloudHypervisor::new(vmcell::artifact::ch_binary_path());
        let mut vm = MicroVm::start(
            &vmm,
            cfg,
            self.cid_alloc.clone(),
            VmidAllocator::new(),
            Box::new(vmcell::metrics::DefaultCgroupFs),
        )
        .await?;

        // Drive the build in a scope so the builder VM is torn down even on error.
        let build_res = async {
            let agent = vm.agent(None, &RealClock).await?;
            for (step, argv, timeout) in build_commands() {
                let outcome = agent
                    .exec(ExecRequest::new(argv).with_timeout(timeout))
                    .await?;
                check_step(step, &outcome)?;
            }
            Ok::<(), Error>(())
        }
        .await;

        // Surface a shutdown failure as a warning without masking the primary result.
        if let Err(e) = vm.shutdown().await {
            tracing::warn!("failed to shut down kernel-builder VM: {e}");
        }
        build_res?;

        // Copy the compiled vmlinux out — fail loud if the guest did not produce it (no
        // silent fallback to an empty/stale output).
        let produced = out_dir.path().join("vmlinux");
        if !produced.exists() {
            return Err(Error::Artifact(
                "in-VM kernel build reported success but produced no vmlinux on the output share"
                    .into(),
            ));
        }
        if let Some(parent) = out.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::copy(&produced, out).await?;

        let mut outputs = StageOutputs::default();
        outputs
            .artifacts
            .insert(artifact_key(&self.label), out.to_path_buf());
        Ok(outputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmcell::ExecOutcome;

    fn inputs() -> StageInputs {
        let mut i = StageInputs::default();
        i.pins
            .insert("kernel_source_url".into(), "http://example/k.tar.xz".into());
        i.pins.insert("kernel_source_sha256".into(), "abc".into());
        i.pins
            .insert("kernel_microvm_config".into(), "CONFIG_BASE=y\n".into());
        i.pins
            .insert("kernel_fragments_KASAN".into(), "CONFIG_KASAN=y\n".into());
        i.pins.insert(
            "kernel_fragments_LOCKDEP".into(),
            "CONFIG_LOCKDEP=y\n".into(),
        );
        i.pins.insert("rootfs_image".into(), "img".into());
        i.pins.insert("rootfs_digest".into(), "sha256:aaa".into());
        i
    }

    fn stage(fragments: Option<Vec<&str>>) -> InVmKernelStage {
        InVmKernelStage {
            http_client: Arc::new(vmcell::artifact::kernel::ReqwestClient),
            label: None,
            fragments: fragments.map(|v| v.into_iter().map(str::to_string).collect()),
            cid_alloc: Arc::new(CidAllocator::new()),
        }
    }

    // The guest command sequence must run defconfig → append → olddefconfig → make vmlinux →
    // copy-out IN ORDER. A reordering (e.g. olddefconfig before the append) would build the
    // wrong config; asserting the relative order catches that.
    #[test]
    fn test_build_commands_ordered() {
        let steps: Vec<&str> = build_commands().iter().map(|(n, _, _)| *n).collect();
        let idx = |needle: &str| steps.iter().position(|s| *s == needle).expect(needle);
        assert!(idx("make defconfig kvm_guest.config") < idx("append microvm config + fragments"));
        assert!(idx("append microvm config + fragments") < idx("make olddefconfig"));
        assert!(idx("make olddefconfig") < idx("make vmlinux"));
        assert!(idx("make vmlinux") < idx("copy vmlinux out"));
        // The toolchain must be installed before the compile.
        assert!(idx("apt-get install toolchain") < idx("make vmlinux"));
    }

    // A non-zero exit at any guest step is a HARD error (never swallowed). The inverse — an
    // "any-result → Ok" probe — would return Ok on code!=0 and redden this.
    #[test]
    fn test_check_step_nonzero_is_hard_error() {
        let bad = ExecOutcome::new(1, vec![], b"boom".to_vec());
        assert!(matches!(
            check_step("make vmlinux", &bad),
            Err(Error::Artifact(_))
        ));
        let ok = ExecOutcome::new(0, vec![], vec![]);
        assert!(check_step("make vmlinux", &ok).is_ok());
    }

    // §8.3: requesting a fragment absent from the pins is a hard error, not a silent skip that
    // builds an uninstrumented kernel.
    #[test]
    fn test_kconfig_append_missing_fragment_errors() {
        let res = kconfig_append(&inputs(), &["NOSUCH".to_string()]);
        assert!(matches!(res, Err(Error::Artifact(_))));
    }

    // §8.3: the append text folds the base config + each fragment's KConfig content.
    #[test]
    fn test_kconfig_append_includes_base_and_fragments() {
        let text = kconfig_append(&inputs(), &["KASAN".to_string()]).expect("append");
        assert!(text.contains("CONFIG_BASE=y"));
        assert!(text.contains("CONFIG_KASAN=y"));
    }

    // §8.3: the fragment set is content-addressed by its SORTED form — the same set in any
    // order hits the same cache key; the inverse (request-order folding) would differ.
    #[test]
    fn test_cache_key_fragment_order_invariant() {
        let i = inputs();
        let ab = stage(Some(vec!["KASAN", "LOCKDEP"]));
        let ba = stage(Some(vec!["LOCKDEP", "KASAN"]));
        assert_eq!(ab.cache_key(&i), ba.cache_key(&i));
    }

    // Adding a fragment must change the key (the set is part of the identity).
    #[test]
    fn test_cache_key_distinguishes_fragment_set() {
        let i = inputs();
        assert_ne!(
            stage(None).cache_key(&i),
            stage(Some(vec!["KASAN"])).cache_key(&i)
        );
    }

    // The compiled kernel depends on the toolchain, so re-pointing the builder-base digest
    // must invalidate the key (the inverse — not folding it — reuses a kernel built by a
    // different toolchain).
    #[test]
    fn test_cache_key_tracks_builder_base() {
        let s = stage(None);
        let a = inputs();
        let mut b = inputs();
        b.pins.insert("rootfs_digest".into(), "sha256:bbb".into());
        assert_ne!(s.cache_key(&a), s.cache_key(&b));
    }

    // A source-SHA bump (re-pointing the pin at new bytes) must invalidate the key.
    #[test]
    fn test_cache_key_tracks_source_sha() {
        let s = stage(None);
        let a = inputs();
        let mut b = inputs();
        b.pins.insert("kernel_source_sha256".into(), "def".into());
        assert_ne!(s.cache_key(&a), s.cache_key(&b));
    }
}
