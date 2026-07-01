//! Kernel artifact building.
//!
//! This module provides the `KernelStage` pipeline step, which downloads
//! and compiles a custom Linux kernel for the virtual machines.

use crate::artifact::{CacheKey, Stage, StageInputs, StageOutputs};
use crate::error::{Error, Result};
use std::path::Path;
use tokio::process::Command;

/// Interface for HTTP operations.
#[async_trait]
pub trait HttpClient: Send + Sync {
    /// Perform an HTTP GET request.
    async fn get(&self, url: &str) -> Result<Vec<u8>>;
}

/// A reqwest-based HTTP client.
pub struct ReqwestClient;
#[async_trait]
impl HttpClient for ReqwestClient {
    async fn get(&self, url: &str) -> Result<Vec<u8>> {
        let response = reqwest::get(url)
            .await
            .map_err(|e| Error::Artifact(format!("Failed to download: {}", e)))?;
        if !response.status().is_success() {
            return Err(Error::Artifact(format!(
                "Failed to download: status {}",
                response.status()
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| Error::Artifact(format!("Failed to read: {}", e)))?;
        Ok(bytes.to_vec())
    }
}

/// A pipeline stage that builds a Linux kernel image.
pub struct KernelStage {
    /// The HTTP client to use for downloading the kernel source.
    pub http_client: std::sync::Arc<dyn HttpClient>,
    /// Optional kernel-version label selecting an entry from the pins `kernels`
    /// registry (e.g. `"6.12.94"`). `None` builds the default `kernel` pin to
    /// `vmlinux`; a labelled stage builds `vmlinux-<label>` with its own cache and
    /// build dir, so multiple kernel versions coexist (the kernel-version benchmark
    /// dimension).
    pub label: Option<String>,
    /// Optional ordered set of named KConfig fragments to layer onto the base config
    /// (v15 §8.3 — the kernel config-fragment matrix: KASAN/KCOV/LOCKDEP/`slub_debug`/a
    /// driver). Each name is resolved to its KConfig text from the pins
    /// `kernel_fragments` registry (`kernel_fragments_<NAME>`) and appended before
    /// `make olddefconfig`. The cache key is content-addressed per (base + **sorted**
    /// fragment set + stage version), so requesting the same set in any order hits the
    /// same cache. Config-only fragments; PREEMPT_RT (patched source) and KCOV
    /// *extraction* (guest tooling) are out of scope.
    pub fragments: Option<Vec<String>>,
}

impl KernelStage {
    /// The fragment names for this stage, **sorted** and de-duplicated, so the cache
    /// key and the config-append order are independent of the request order (§8.3).
    fn sorted_fragments(&self) -> Vec<String> {
        let mut names: Vec<String> = self.fragments.clone().unwrap_or_default();
        names.sort();
        names.dedup();
        names
    }

    /// The pins key holding the KConfig text for the named fragment.
    fn fragment_pin_key(name: &str) -> String {
        format!("kernel_fragments_{name}")
    }

    /// The artifact filename suffix for this kernel (`""` or `-<sanitized-label>`).
    ///
    /// Sanitizes `.`→`-`: the pipeline derives the cache sidecar via
    /// `Path::with_extension`, which would treat the trailing `.NNN` of a dotted
    /// version as an extension and collide same-minor labels' sidecars
    /// (`vmlinux-6.6.143` → `vmlinux-6.6.cache_key`). The pins key and the cache-key
    /// *hash* keep the dotted label; only the on-disk filename is sanitized.
    fn suffix(&self) -> String {
        self.label
            .as_ref()
            .map(|l| format!("-{}", l.replace('.', "-")))
            .unwrap_or_default()
    }

    /// The pins key holding this kernel's source URL.
    fn url_pin_key(&self) -> String {
        match &self.label {
            Some(l) => format!("kernel_{l}_source_url"),
            None => "kernel_source_url".to_string(),
        }
    }

    /// The pins key holding this kernel's source SHA256.
    fn sha_pin_key(&self) -> String {
        match &self.label {
            Some(l) => format!("kernel_{l}_source_sha256"),
            None => "kernel_source_sha256".to_string(),
        }
    }

    /// The key under which this stage registers its built kernel in the
    /// [`StageOutputs`]/[`StageInputs`] artifact map.
    ///
    /// The default (unlabelled) kernel registers under `"kernel"` — the key every
    /// downstream stage (rootfs, snapshot) reads — while each labelled kernel
    /// registers under `"kernel-<label>"`. Without this, every labelled kernel
    /// collapsed onto the single `"kernel"` key and a multi-kernel `Artifacts` map
    /// lost all but one entry (M-PIPE-4).
    fn artifact_key(&self) -> String {
        match &self.label {
            Some(l) => format!("kernel-{l}"),
            None => "kernel".to_string(),
        }
    }
}

use async_trait::async_trait;

#[async_trait]
impl Stage for KernelStage {
    fn name(&self) -> &str {
        // Each labelled kernel stage must have a DISTINCT name so `reset_to` can
        // target exactly one of them; sharing `"kernel"` made every labelled stage
        // indistinguishable (M-PIPE-4). The default kernel keeps the name `"kernel"`.
        self.label.as_deref().unwrap_or("kernel")
    }

    fn out_path(&self, target_dir: &Path) -> std::path::PathBuf {
        target_dir.join(format!("vmlinux{}", self.suffix()))
    }

    fn cache_key(&self, inputs: &StageInputs) -> CacheKey {
        // Bump when this stage's build logic changes so stale kernels are not served.
        // v15: bumped to 2 with the config-fragment matrix (§8.3).
        const STAGE_VERSION: u32 = 2;
        // Unambiguous field separator: without it, label||url||sha||config are a flat
        // byte stream where e.g. (label="x", url="A") and (label="", url="xA") collide
        // to the same key (non-injective hash).
        const SEP: &[u8] = b"\x1f";
        let mut hasher = blake3::Hasher::new();
        hasher.update(&STAGE_VERSION.to_le_bytes());
        hasher.update(SEP);
        // The version label distinguishes coexisting kernel stages.
        hasher.update(self.label.as_deref().unwrap_or_default().as_bytes());
        hasher.update(SEP);
        hasher.update(
            inputs
                .pins
                .get(&self.url_pin_key())
                .map(|s| s.as_bytes())
                .unwrap_or_default(),
        );
        hasher.update(SEP);
        hasher.update(
            inputs
                .pins
                .get(&self.sha_pin_key())
                .map(|s| s.as_bytes())
                .unwrap_or_default(),
        );
        hasher.update(SEP);
        hasher.update(
            inputs
                .pins
                .get("kernel_microvm_config")
                .map(|s| s.as_bytes())
                .unwrap_or_default(),
        );
        // Fold the config fragments in SORTED order (§8.3): the same set requested in any
        // order must hash identically, and BOTH the fragment NAME and its KConfig CONTENT
        // (from the pins registry) must travel, so editing a fragment's text invalidates the
        // key. The per-fragment SEP plus the count keep distinct sets from colliding.
        let fragments = self.sorted_fragments();
        hasher.update(SEP);
        hasher.update(&(fragments.len() as u32).to_le_bytes());
        for name in &fragments {
            hasher.update(SEP);
            hasher.update(name.as_bytes());
            hasher.update(SEP);
            hasher.update(
                inputs
                    .pins
                    .get(&Self::fragment_pin_key(name))
                    .map(|s| s.as_bytes())
                    .unwrap_or_default(),
            );
        }
        CacheKey(format!("kernel-{}", hasher.finalize().to_hex()))
    }

    async fn run(&self, inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        let url_key = self.url_pin_key();
        let sha_key = self.sha_pin_key();
        let kernel_source_url = inputs
            .pins
            .get(&url_key)
            .ok_or_else(|| Error::Artifact(format!("Missing {url_key} pin")))?;
        let kernel_source_sha256 = inputs
            .pins
            .get(&sha_key)
            .ok_or_else(|| Error::Artifact(format!("Missing {sha_key} pin")))?;
        let microvm_config = inputs
            .pins
            .get("kernel_microvm_config")
            .ok_or_else(|| Error::Artifact("Missing kernel_microvm_config pin".into()))?;

        let workdir = out
            .parent()
            .unwrap_or(Path::new("."))
            .join(format!("kernel-build{}", self.suffix()));
        tokio::fs::create_dir_all(&workdir).await?;

        let tarball = workdir.join("linux.tar.xz");

        use sha2::Digest;
        let sha256_hex = |bytes: &[u8]| -> String {
            let mut hasher = sha2::Sha256::new();
            hasher.update(bytes);
            format!("{:x}", hasher.finalize())
        };

        // (Re)fetch the tarball when it is missing OR its content does not match the
        // pinned hash. The old code only checked existence, so a *bumped pin* left the
        // stale tarball at this fixed `linux.tar.xz` path and the verify below failed
        // ("hash mismatch") instead of re-downloading. A stale *extracted* source tree
        // under the same workdir would survive too, so on a mismatch purge the whole
        // build dir and re-fetch, letting extraction (gated on `Makefile`) re-run.
        let needs_fetch = match tokio::fs::read(&tarball).await {
            Ok(bytes) => sha256_hex(&bytes) != *kernel_source_sha256,
            Err(_) => true,
        };
        if needs_fetch {
            // Best-effort purge of any stale tarball + extracted tree (ignore "not found").
            let _ = tokio::fs::remove_dir_all(&workdir).await;
            tokio::fs::create_dir_all(&workdir).await?;
            let bytes = self.http_client.get(kernel_source_url).await?;
            tokio::fs::write(&tarball, &bytes).await?;
        }

        // Verify SHA256 of the (now fresh) tarball; a mismatch here means the URL served
        // content that does not match the pin — a provenance hard stop.
        let tarball_bytes = tokio::fs::read(&tarball).await?;
        let hash = sha256_hex(&tarball_bytes);
        if &hash != kernel_source_sha256 {
            return Err(Error::Artifact(format!(
                "Kernel source tarball hash mismatch: expected {}, got {} (url {})",
                kernel_source_sha256, hash, kernel_source_url
            )));
        }

        // We assume we need to extract if the Makefile doesn't exist
        if !workdir.join("Makefile").exists() {
            let tarball_path = tarball.clone();
            let workdir_path = workdir.clone();
            tokio::task::spawn_blocking(move || -> Result<()> {
                let tar_uncompressed_path = workdir_path.join("linux.tar");
                if !tar_uncompressed_path.exists() {
                    let xz_file = std::fs::File::open(&tarball_path)?;
                    let mut tar_file = std::fs::File::create(&tar_uncompressed_path)?;
                    lzma_rs::xz_decompress(&mut std::io::BufReader::new(xz_file), &mut tar_file)
                        .map_err(|e| Error::Artifact(format!("Decompression failed: {:?}", e)))?;
                }

                let tar_file_read = std::fs::File::open(&tar_uncompressed_path)?;
                let mut archive = tar::Archive::new(tar_file_read);
                for entry in archive.entries()? {
                    let mut file = entry?;
                    let path = file.path()?.into_owned();
                    let mut components = path.components();
                    if components.next().is_none() {
                        continue;
                    } // skip first component
                    let stripped_path: std::path::PathBuf = components.collect();
                    if stripped_path.as_os_str().is_empty() {
                        continue;
                    }
                    // Defense-in-depth: even though the tarball is SHA-pinned, never
                    // let an entry escape the build dir via a `..` or absolute/prefixed
                    // component (tar-slip). Fail loud rather than write outside workdir.
                    reject_path_traversal(&stripped_path)?;
                    let out_path = workdir_path.join(stripped_path);

                    if file.header().entry_type() == tar::EntryType::Directory {
                        std::fs::create_dir_all(&out_path)?;
                    } else {
                        if let Some(parent) = out_path.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        file.unpack(&out_path)?;
                    }
                }

                let _ = std::fs::remove_file(&tar_uncompressed_path);

                Ok(())
            })
            .await
            .expect("spawn_blocking failed")?;
        }

        let status = Command::new("make")
            .current_dir(&workdir)
            .env("HOSTCC", "gcc")
            .arg("defconfig")
            .arg("kvm_guest.config")
            .status()
            .await?;
        if !status.success() {
            return Err(Error::Subprocess(
                "Failed to generate base kernel config (make defconfig kvm_guest.config)".into(),
            ));
        }

        let config_path = workdir.join(".config");
        // Append our specific config on top
        let mut current_config = tokio::fs::read_to_string(&config_path).await?;
        current_config.push('\n');
        current_config.push_str(microvm_config);
        // Layer the requested KConfig fragments (§8.3) in SORTED order, so the on-disk
        // `.config` is deterministic regardless of request order. Each fragment's text comes
        // from the pins `kernel_fragments` registry; a missing fragment is a HARD ERROR —
        // never a silent skip that builds a kernel without the requested instrumentation.
        let fragments = self.sorted_fragments();
        for name in &fragments {
            let frag = inputs
                .pins
                .get(&Self::fragment_pin_key(name))
                .ok_or_else(|| {
                    Error::Artifact(format!(
                        "missing kernel fragment `{name}` in pins (expected key `{}`)",
                        Self::fragment_pin_key(name)
                    ))
                })?;
            current_config.push('\n');
            current_config.push_str(frag);
        }
        tokio::fs::write(&config_path, current_config).await?;

        let status = Command::new("make")
            .current_dir(&workdir)
            .env("HOSTCC", "gcc")
            .arg("olddefconfig")
            .status()
            .await?;
        if !status.success() {
            // Fail loud with the base + fragment context: `olddefconfig` returns non-zero when
            // a fragment's KConfig conflicts with the base or a dependency is missing (§8.3).
            return Err(Error::Artifact(format!(
                "make olddefconfig failed (kernel `{}`, fragments {:?}): a requested KConfig \
                 fragment is incompatible with the base config or a dependency is unmet",
                self.label.as_deref().unwrap_or("default"),
                fragments
            )));
        }

        let nproc = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let status = Command::new("make")
            .current_dir(&workdir)
            .env("CC", "gcc")
            .env("HOSTCC", "gcc")
            .arg("-j")
            .arg(nproc.to_string())
            .arg("vmlinux")
            .status()
            .await?;
        if !status.success() {
            return Err(Error::Subprocess("make vmlinux failed".into()));
        }

        tokio::fs::copy(workdir.join("vmlinux"), out).await?;

        Ok(kernel_outputs(out, &self.artifact_key()))
    }
}

/// Rejects a stripped tar entry path that would escape the extraction root via a
/// `..` component or an absolute/prefixed path (tar-slip defense-in-depth).
///
/// # Errors
/// Returns [`Error::Artifact`] if `stripped` contains a parent-dir, root, or
/// prefix component.
fn reject_path_traversal(stripped: &Path) -> Result<()> {
    use std::path::Component;
    if stripped.components().any(|c| {
        matches!(
            c,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(Error::Artifact(format!(
            "refusing kernel tarball entry with path traversal: {}",
            stripped.display()
        )));
    }
    Ok(())
}

/// Builds the [`StageOutputs`] for a kernel build, registering the built kernel under
/// `key` (`"kernel"` for the default, `"kernel-<label>"` for a labelled stage) so
/// downstream stages (snapshot, mmdebstrap builder) always see it on a cold build — not
/// only on a warm-cache hit. Omitting this on the cold path lets the snapshot stage fall
/// through to a `/tmp/vmlinux` fallback; collapsing every labelled kernel onto `"kernel"`
/// loses all but one entry in a multi-kernel `Artifacts` map (M-PIPE-4).
fn kernel_outputs(out: &Path, key: &str) -> StageOutputs {
    let mut outputs = StageOutputs::default();
    outputs.artifacts.insert(key.to_string(), out.to_path_buf());
    outputs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_cache_key() {
        let stage = KernelStage {
            http_client: std::sync::Arc::new(ReqwestClient),
            label: None,
            fragments: None,
        };

        let mut inputs1 = StageInputs::default();
        inputs1.pins.insert(
            "kernel_source_url".into(),
            "https://example.com/kernel".into(),
        );
        inputs1
            .pins
            .insert("kernel_source_sha256".into(), "dummy".into());
        inputs1
            .pins
            .insert("kernel_microvm_config".into(), "CONFIG_FOO=y\n".into());

        let mut inputs2 = inputs1.clone();
        inputs2
            .pins
            .insert("kernel_microvm_config".into(), "CONFIG_FOO=n\n".into());

        let mut inputs3 = inputs1.clone();
        inputs3
            .pins
            .insert("kernel_source_sha256".into(), "dummy2".into());

        assert_ne!(stage.cache_key(&inputs1), stage.cache_key(&inputs2));
        assert_ne!(stage.cache_key(&inputs1), stage.cache_key(&inputs3));
        assert_eq!(stage.cache_key(&inputs1), stage.cache_key(&inputs1));
    }

    // Guards ARTIFACT-PIPELINE-6: the cold build path must register the `kernel` artifact in
    // its outputs (like the warm-cache path does), or downstream stages lose it and fall
    // through to `/tmp/vmlinux`. A buggy `Ok(StageOutputs::default())` goes red here.
    #[test]
    fn test_kernel_outputs_registers_kernel_artifact() {
        let out = Path::new("/some/target/vmlinux");
        let outputs = kernel_outputs(out, "kernel");
        assert_eq!(
            outputs.artifacts.get("kernel").map(|p| p.as_path()),
            Some(out),
            "cold-build outputs must register the kernel artifact"
        );
    }

    // Guards M-PIPE-4: labelled kernel stages must have DISTINCT names (so `reset_to`
    // can target one) and register under DISTINCT artifact keys (so a multi-kernel
    // Artifacts map does not collapse to a single entry). The buggy impl returned
    // `"kernel"` for both name() and the artifact key regardless of label → red here.
    #[test]
    fn test_kernel_stage_name_and_key_distinct_per_label() {
        let mk = |label: Option<&str>| KernelStage {
            http_client: std::sync::Arc::new(ReqwestClient),
            label: label.map(str::to_string),
            fragments: None,
        };
        let default = mk(None);
        let k66 = mk(Some("6.6.143"));
        let k612 = mk(Some("6.12.94"));

        assert_eq!(default.name(), "kernel");
        assert_ne!(
            k66.name(),
            k612.name(),
            "labelled kernels must have distinct names"
        );
        assert_ne!(k66.name(), default.name());

        assert_eq!(default.artifact_key(), "kernel");
        assert_ne!(
            k66.artifact_key(),
            k612.artifact_key(),
            "labelled kernels must register under distinct artifact keys"
        );
        assert_ne!(k66.artifact_key(), default.artifact_key());
    }

    // Guards the LOW non-injective-hash finding: without a field delimiter the
    // concatenation label||url makes two distinct stages hash identically. Here
    // (label="x", url="A") and (label="", url="xA") collide on the buggy impl.
    #[test]
    fn test_kernel_cache_key_field_delimiter_injective() {
        let s1 = KernelStage {
            http_client: std::sync::Arc::new(ReqwestClient),
            label: Some("x".into()),
            fragments: None,
        };
        let mut i1 = StageInputs::default();
        i1.pins.insert("kernel_x_source_url".into(), "A".into());
        i1.pins.insert("kernel_x_source_sha256".into(), "B".into());
        i1.pins.insert("kernel_microvm_config".into(), "C".into());

        let s2 = KernelStage {
            http_client: std::sync::Arc::new(ReqwestClient),
            label: None,
            fragments: None,
        };
        let mut i2 = StageInputs::default();
        i2.pins.insert("kernel_source_url".into(), "xA".into());
        i2.pins.insert("kernel_source_sha256".into(), "B".into());
        i2.pins.insert("kernel_microvm_config".into(), "C".into());

        assert_ne!(
            s1.cache_key(&i1),
            s2.cache_key(&i2),
            "concatenating label||url without a delimiter makes the cache key non-injective"
        );
    }

    // ---- §8.3 kernel config-fragment matrix: cache-key behaviors (pure) ----

    fn frag_stage(fragments: Option<Vec<&str>>) -> KernelStage {
        KernelStage {
            http_client: std::sync::Arc::new(ReqwestClient),
            label: None,
            fragments: fragments.map(|v| v.into_iter().map(str::to_string).collect()),
        }
    }

    fn frag_inputs() -> StageInputs {
        let mut i = StageInputs::default();
        i.pins.insert("kernel_source_url".into(), "u".into());
        i.pins.insert("kernel_source_sha256".into(), "s".into());
        i.pins.insert("kernel_microvm_config".into(), "C".into());
        i.pins
            .insert("kernel_fragments_KASAN".into(), "CONFIG_KASAN=y\n".into());
        i.pins.insert(
            "kernel_fragments_LOCKDEP".into(),
            "CONFIG_LOCKDEP=y\n".into(),
        );
        i
    }

    // §8.3: the fragment set is content-addressed by its SORTED form, so requesting the
    // same fragments in a different order MUST hit the same cache key. The inverse —
    // folding fragments in request order — makes [KASAN,LOCKDEP] != [LOCKDEP,KASAN].
    #[test]
    fn test_kernel_cache_key_fragment_order_invariant() {
        let inputs = frag_inputs();
        let ab = frag_stage(Some(vec!["KASAN", "LOCKDEP"]));
        let ba = frag_stage(Some(vec!["LOCKDEP", "KASAN"]));
        assert_eq!(
            ab.cache_key(&inputs),
            ba.cache_key(&inputs),
            "fragment order must not change the cache key (sorted-set addressing)"
        );
    }

    // §8.3: the fragment SET is part of the key. A KASAN kernel must not share a cache
    // entry with the plain kernel (the inverse — ignoring fragments — collides them).
    #[test]
    fn test_kernel_cache_key_distinguishes_fragment_set() {
        let inputs = frag_inputs();
        let plain = frag_stage(None);
        let kasan = frag_stage(Some(vec!["KASAN"]));
        assert_ne!(
            plain.cache_key(&inputs),
            kasan.cache_key(&inputs),
            "adding a fragment must change the cache key"
        );
    }

    // §8.3: validity is content-addressed — editing a fragment's KConfig text (same name)
    // must invalidate the key, or a stale instrumented kernel is re-served.
    #[test]
    fn test_kernel_cache_key_tracks_fragment_content() {
        let stage = frag_stage(Some(vec!["KASAN"]));
        let i1 = frag_inputs();
        let mut i2 = frag_inputs();
        i2.pins
            .insert("kernel_fragments_KASAN".into(), "CONFIG_KASAN=n\n".into());
        assert_ne!(
            stage.cache_key(&i1),
            stage.cache_key(&i2),
            "editing a fragment's KConfig content must change the cache key"
        );
    }

    // Guards the LOW tar-slip finding: extraction must reject entries that escape the
    // build dir via `..`, an absolute path, or a prefix. A buggy impl with no check
    // would `join` these and write outside workdir; this helper makes them an error.
    #[test]
    fn test_reject_path_traversal() {
        assert!(reject_path_traversal(Path::new("kernel/Makefile")).is_ok());
        assert!(reject_path_traversal(Path::new("a/b/c.c")).is_ok());
        assert!(reject_path_traversal(Path::new("../etc/passwd")).is_err());
        assert!(reject_path_traversal(Path::new("a/../../b")).is_err());
        assert!(reject_path_traversal(Path::new("/abs/evil")).is_err());
    }
}
