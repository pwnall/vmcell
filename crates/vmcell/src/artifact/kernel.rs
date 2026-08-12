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
            .map_err(|e| Error::Artifact(format!("Failed to download: {e}")))?;
        if !response.status().is_success() {
            return Err(Error::Artifact(format!(
                "Failed to download: status {}",
                response.status()
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| Error::Artifact(format!("Failed to read: {e}")))?;
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
    /// (v15 §5.2, The config fragment — the kernel config-fragment matrix: KASAN/KCOV/LOCKDEP/`slub_debug`/a
    /// driver). Each name is resolved to its KConfig text from the pins
    /// `kernel_fragments` registry (`kernel_fragments_<NAME>`) and appended before
    /// `make olddefconfig`. The cache key is content-addressed per (base + **sorted**
    /// fragment set + stage version), so requesting the same set in any order hits the
    /// same cache. Config-only fragments; PREEMPT_RT (patched source) and KCOV
    /// *extraction* (guest tooling) are out of scope.
    pub fragments: Option<Vec<String>>,
}

/// The pins key holding the KConfig text for the named fragment (§5.2, The config fragment).
///
/// The **one** composer for the fragment→pin-key law: both compiling producers (this crate's
/// host-`make` [`KernelStage`] and the out-of-crate in-VM builder) resolve a fragment through it,
/// so the key shape cannot drift between them.
#[must_use]
pub fn fragment_pin_key(name: &str) -> String {
    format!("kernel_fragments_{name}")
}

/// The requested fragment names, **sorted** and de-duplicated (§5.2, The config fragment), so both
/// the cache key and the on-disk config-append order are independent of the request order.
///
/// Public for the same one-law reason as [`fragment_pin_key`]: the in-VM producer canonicalizes
/// its fragment set with this exact function, never a second copy of the sort+dedup.
#[must_use]
pub fn sorted_fragments(fragments: Option<&[String]>) -> Vec<String> {
    let mut names: Vec<String> = fragments.map(<[String]>::to_vec).unwrap_or_default();
    names.sort();
    names.dedup();
    names
}

/// The cache-key marker for a fragment whose KConfig text **resolved** from the pins registry,
/// prefixing the text itself.
const FRAGMENT_RESOLVED: &[u8] = b"c:";

/// The cache-key marker for a fragment name that resolved to **nothing** — no
/// `kernel_fragments_<NAME>` pin exists (§5.5, Kernel as a benchmark dimension).
///
/// Distinct from [`FRAGMENT_RESOLVED`] + empty text on purpose: the old fold used
/// `unwrap_or_default()`, so a fragment *absent* from the registry hashed identically to the same
/// fragment *present with empty KConfig text*. Those are different builds — the first is a
/// hard-error request, the second a legal no-op — and a shared key let the second's cached kernel
/// be served for the first until `run()` failed.
const FRAGMENT_MISSING: &[u8] = b"m:<missing-fragment>";

/// Folds a canonicalized (sorted, de-duplicated) fragment set into `hasher`: the set's size, then
/// each fragment's NAME and its resolved KConfig CONTENT — or the
/// distinct `FRAGMENT_MISSING` marker when the pins registry has no such fragment.
///
/// The **one** fragment fold both compiling producers call (§5.2, The config fragment; §10.2, The
/// stage model and the five cache-key rules): the name travels so two sets never collide, the
/// content travels so editing a fragment's text invalidates the key, and the missing marker travels
/// so an unresolvable fragment is not confused with an empty one.
pub fn fold_fragment_identity(
    hasher: &mut blake3::Hasher,
    pins: &std::collections::HashMap<String, String>,
    fragments: &[String],
) {
    /// Unambiguous field separator (matches each producer's own key fold).
    const SEP: &[u8] = b"\x1f";
    hasher.update(SEP);
    hasher.update(&(fragments.len() as u32).to_le_bytes());
    for name in fragments {
        hasher.update(SEP);
        hasher.update(name.as_bytes());
        hasher.update(SEP);
        match pins.get(&fragment_pin_key(name)) {
            Some(text) => {
                hasher.update(FRAGMENT_RESOLVED);
                hasher.update(text.as_bytes());
            }
            None => {
                hasher.update(FRAGMENT_MISSING);
            }
        }
    }
}

/// The KConfig text appended after `make defconfig kvm_guest.config`: the `base` micro-VM config
/// plus each requested fragment's registry text, in the given (already sorted) order.
///
/// The **one** append law both compiling producers use, so the host-`make` and in-VM builds layer
/// identical bytes for the same request. A requested fragment absent from the pins registry is a
/// HARD ERROR — never a silent skip that builds a kernel without the requested instrumentation
/// (§5.2, The config fragment).
///
/// # Errors
/// Returns [`Error::Artifact`] naming the fragment and the pin key it expected.
pub fn kconfig_append(
    base: &str,
    pins: &std::collections::HashMap<String, String>,
    fragments: &[String],
) -> Result<String> {
    let mut out = base.to_string();
    for name in fragments {
        let frag = pins.get(&fragment_pin_key(name)).ok_or_else(|| {
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

/// The on-disk filename **suffix** for a kernel label (`""` for the default kernel, `-<label>`
/// with `.` sanitized to `-` otherwise) — the **one** label-sanitization law (§5.6, The downstream
/// kernel toolkit).
///
/// The `.`→`-` sanitization is load-bearing: the pipeline derives a stage's cache sidecar with
/// `Path::with_extension`, which would treat the trailing `.NNN` of a dotted version as an
/// extension and collide same-minor labels (`vmlinux-6.6.143` → `vmlinux-6.6.cache_key`). The pins
/// key and the cache-key *hash* keep the dotted label; only the on-disk filename is sanitized.
///
/// Every producer composes its filename through this function and
/// [`kernel_label_from_filename`] is its inverse, so the rule cannot drift between the two: a
/// producer that stopped sanitizing would make `bundle`'s reader silently drop that kernel from
/// the manifest, which is what the round-trip gate pins.
#[must_use]
pub fn kernel_filename_suffix(label: Option<&str>) -> String {
    label
        .map(|l| format!("-{}", l.replace('.', "-")))
        .unwrap_or_default()
}

/// The on-disk artifact **filename** of a kernel image: `vmlinux` for the default kernel,
/// `vmlinux-<sanitized-label>` for a labelled one ([`kernel_filename_suffix`]).
///
/// The one composer every producer and every consumer of the artifacts dir uses — the host-`make`
/// [`KernelStage`], the out-of-crate in-VM builder, and the benchmark harness that resolves
/// `--kernel` to a path.
#[must_use]
pub fn kernel_filename(label: Option<&str>) -> String {
    format!("vmlinux{}", kernel_filename_suffix(label))
}

/// The inverse of [`kernel_filename`]: the on-disk label carried by a kernel artifact filename,
/// or `None` when `name` is not a labelled kernel image.
///
/// `vmcell bundle` walks the artifacts dir with this so the manifest covers every
/// `vmlinux-<label>` built by `build-kernels`, not just the default `vmlinux` (N-BIN-4).
///
/// The bare `vmlinux` (no suffix) and an empty label return `None`, and so does a remainder
/// containing `.`: [`kernel_filename_suffix`] sanitizes `.`→`-`, so every dotted `vmlinux-…` name
/// in the artifacts dir is one of a kernel's SIDECARS — `vmlinux-6-12-94.cache_key`, and now
/// `vmlinux-6-12-94.config` (§5.6). Without that rule `bundle` recorded the cache sidecar as a
/// kernel artifact named `kernel-6-12-94.cache_key`, and would have added the config the same way.
///
/// This is the *inverse* of the sanitization law and therefore lives beside it: the two are pinned
/// together by a round-trip gate over the real `kernels` registry, so neither half can move alone.
#[must_use]
pub fn kernel_label_from_filename(name: &str) -> Option<&str> {
    match name.strip_prefix("vmlinux-") {
        Some(label) if !label.is_empty() && !label.contains('.') => Some(label),
        _ => None,
    }
}

/// The **resolved-config sidecar** path for a built kernel image: `<vmlinux>.config` (§5.6, The
/// downstream kernel toolkit; §10.1, Artifacts produced).
///
/// The one composer for the sidecar name, so the producers that write it, the CLI that bundles it
/// and a downstream consumer that asserts against it all name the same file. It APPENDS the
/// extension instead of using `Path::with_extension`, which would eat the trailing `.NNN` of a
/// dotted filename (the same hazard the labelled kernel's filename suffix sanitizes for the `.cache_key`
/// sidecar) and silently point two labels at one config.
#[must_use]
pub fn resolved_config_path(vmlinux: &Path) -> std::path::PathBuf {
    let mut name = vmlinux.as_os_str().to_os_string();
    name.push(".config");
    std::path::PathBuf::from(name)
}

/// The [`StageOutputs`] artifact key of the resolved-config sidecar produced beside the kernel
/// registered under `kernel_key` (`"kernel"` → `"kernel-config"`, `"kernel-<label>"` →
/// `"kernel-<label>-config"`).
///
/// Registering the sidecar under its own key is what content-addresses it *with* the kernel: the
/// pipeline records the stage's whole artifact map in the cache sidecar, so a warm build republishes
/// the config path exactly like the `vmlinux` it belongs to.
#[must_use]
pub fn config_artifact_key(kernel_key: &str) -> String {
    format!("{kernel_key}-config")
}

/// Publishes a compiling producer's post-`olddefconfig` resolved config from `config_path` to the
/// [`resolved_config_path`] sidecar beside the built `vmlinux`, returning the sidecar path (§5.6,
/// The downstream kernel toolkit).
///
/// The **one** publish law both compiling producers call — the host-`make` [`KernelStage`] (whose
/// `.config` is left in the persistent build dir, overwritten by the next build of the same label)
/// and the out-of-crate in-VM builder (whose `.config` dies with the builder VM unless it is
/// shipped back on the output share). Neither may keep a second copy: the sidecar is the artifact a
/// fragment author asserts against, because `olddefconfig` silently drops any symbol whose
/// dependencies are unmet.
///
/// A missing or unreadable source config is a HARD ERROR naming `kernel` — never a skip that ships
/// a kernel with no evidence of what it contains.
///
/// # Errors
/// Returns [`Error::Artifact`] when `config_path` is absent or cannot be copied to the sidecar.
pub async fn publish_resolved_config(
    config_path: &Path,
    vmlinux: &Path,
    kernel: &str,
) -> Result<std::path::PathBuf> {
    let sidecar = resolved_config_path(vmlinux);
    tokio::fs::copy(config_path, &sidecar).await.map_err(|e| {
        Error::Artifact(format!(
            "kernel `{kernel}` compiled but its resolved config could not be published from {} \
             to {}: {e} (§5.6 — a kernel with no record of its own config is exactly the silent \
             fragment drop this artifact exists to catch)",
            config_path.display(),
            sidecar.display()
        ))
    })?;
    Ok(sidecar)
}

/// Removes a **stale** resolved-config sidecar left beside `vmlinux` by an earlier, *compiling*
/// producer (§5.6, The downstream kernel toolkit).
///
/// The counterpart of [`publish_resolved_config`], for the producer that emits no config at all:
/// [`PrebuiltKernelStage`] republishes the same `vmlinux` path with different bytes, and the
/// sidecar is picked up from the filesystem by `vmcell bundle`. Left in place, `bundle` would
/// digest-pin a config describing a *different* kernel as this kernel's `kernel-config` — a lying
/// artifact that silently passes the "assert against the result, not the fragment" check the
/// sidecar exists for.
///
/// An already-absent sidecar is success (the common case: nothing compiled here before).
///
/// # Errors
/// Returns [`Error::Artifact`] when an existing sidecar cannot be removed — never a swallowed
/// failure that leaves the stale file behind.
pub async fn clear_resolved_config(vmlinux: &Path) -> Result<()> {
    let sidecar = resolved_config_path(vmlinux);
    match tokio::fs::remove_file(&sidecar).await {
        Ok(()) => {
            tracing::info!(
                config = %sidecar.display(),
                "removed a stale resolved-config sidecar (this producer compiles nothing)"
            );
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Artifact(format!(
            "failed to remove the stale resolved config at {}: {e} — leaving it would let \
             `vmcell bundle` pin a config describing a different kernel (§5.6)",
            sidecar.display()
        ))),
    }
}

/// Rejects a **labelled** or **fragment-carrying** kernel request routed at the prebuilt bootstrap
/// seed (§5.4, The guest-kernel contract and the bootstrap seed; §5.6, The downstream kernel toolkit).
///
/// [`PrebuiltKernelStage`] downloads one digest-pinned `vmlinux`; it compiles nothing, so it can
/// honor neither a `kernels.<label>` selection nor a KConfig fragment set. Silently dropping both
/// (the pre-v30 behavior of the CLI's producer selector) handed back the default seed and reported
/// success — a labelled build that never happened. Every producer selector routes through this one
/// predicate rather than repeating the condition.
///
/// # Errors
/// Returns [`Error::Artifact`] naming the label and/or fragments that cannot be honored, and the
/// producers that can.
pub fn reject_labelled_prebuilt(label: Option<&str>, fragments: Option<&[String]>) -> Result<()> {
    let has_fragments = fragments.is_some_and(|f| !f.is_empty());
    if label.is_none() && !has_fragments {
        return Ok(());
    }
    Err(Error::Artifact(format!(
        "the prebuilt kernel seed cannot build label {:?} with fragments {:?}: it downloads one \
         digest-pinned vmlinux and compiles nothing — build a labelled or fragment-carrying kernel \
         with the host-make or in-VM producer instead (§5.4)",
        label.unwrap_or("<none>"),
        fragments.unwrap_or_default()
    )))
}

impl KernelStage {
    /// The fragment names for this stage, **sorted** and de-duplicated (the shared
    /// [`sorted_fragments`] law).
    fn sorted_fragments(&self) -> Vec<String> {
        sorted_fragments(self.fragments.as_deref())
    }

    /// The artifact filename suffix for this kernel — the shared
    /// [`kernel_filename_suffix`] law (`""` or `-<sanitized-label>`), never a second copy of the
    /// `.`→`-` rule.
    fn suffix(&self) -> String {
        kernel_filename_suffix(self.label.as_deref())
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
        // v15: bumped to 2 with the config-fragment matrix (§5.2, The config fragment).
        // v30 (§18 delta 3, cache-key rule 4): bumped to 3 — the fragment fold gained the distinct
        // missing-fragment marker AND the stage now emits the resolved-config sidecar, so no v2
        // output (which has no `.config` beside it) may be served.
        const STAGE_VERSION: u32 = 3;
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
        // Fold the config fragments in SORTED order through the shared fold (§5.2, The config
        // fragment): the same set requested in any order hashes identically, name + content both
        // travel, and an unresolvable fragment folds its own marker rather than empty bytes.
        fold_fragment_identity(&mut hasher, &inputs.pins, &self.sorted_fragments());
        CacheKey(format!("kernel-{}", hasher.finalize().to_hex()))
    }

    async fn run(&self, inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        // Which producer ran (§5.6, The downstream kernel toolkit): both compiling producers share
        // `name()` (the label), so the stage name cannot answer it — the log line must.
        tracing::info!(
            producer = "host-make",
            kernel = self.label.as_deref().unwrap_or("default"),
            fragments = ?self.sorted_fragments(),
            "building kernel"
        );
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
            // sha2 0.11 `finalize()` returns a `hybrid_array::Array` (no `LowerHex`).
            let out: [u8; 32] = hasher.finalize().into();
            out.iter().map(|b| format!("{b:02x}")).collect::<String>()
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
                "Kernel source tarball hash mismatch: expected {kernel_source_sha256}, got {hash} (url {kernel_source_url})"
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
                        .map_err(|e| Error::Artifact(format!("Decompression failed: {e:?}")))?;
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
                    let out_path = workdir_path.join(&stripped_path);

                    if file.header().entry_type() == tar::EntryType::Directory {
                        std::fs::create_dir_all(&out_path)?;
                    } else {
                        // Symlink-through defense-in-depth (L-ART-3): a tar symlink whose
                        // target escapes the build dir (an absolute path, or one climbing
                        // above the extraction root) would let a LATER entry write THROUGH it
                        // outside workdir. `unpack` (unlike `unpack_in`) does not guard this,
                        // so reject an escaping symlink at creation — then no such link exists
                        // for a subsequent entry to write through.
                        if file.header().entry_type() == tar::EntryType::Symlink
                            && let Some(target) = file.link_name().map_err(|e| {
                                Error::Artifact(format!("bad kernel tarball symlink: {e}"))
                            })?
                            && symlink_escapes(&stripped_path, &target)
                        {
                            return Err(Error::Artifact(format!(
                                "refusing kernel tarball symlink {} -> {} escaping \
                                         the build dir",
                                stripped_path.display(),
                                target.display()
                            )));
                        }
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
            .map_err(|e| Error::Artifact(format!("spawn_blocking extract failed: {e}")))??;
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
        // Append our specific config on top, then layer the requested KConfig fragments (§5.2, The
        // config fragment) in SORTED order through the shared `kconfig_append` law, so the on-disk
        // `.config` is deterministic regardless of request order and identical to what the in-VM
        // producer would append. A missing fragment is a HARD ERROR there — never a silent skip
        // that builds a kernel without the requested instrumentation.
        let mut current_config = tokio::fs::read_to_string(&config_path).await?;
        let fragments = self.sorted_fragments();
        current_config.push('\n');
        current_config.push_str(&kconfig_append(microvm_config, &inputs.pins, &fragments)?);
        tokio::fs::write(&config_path, current_config).await?;

        let status = Command::new("make")
            .current_dir(&workdir)
            .env("HOSTCC", "gcc")
            .arg("olddefconfig")
            .status()
            .await?;
        if !status.success() {
            // Fail loud with the base + fragment context: `olddefconfig` returns non-zero when
            // a fragment's KConfig conflicts with the base or a dependency is missing (§5.2, The config fragment).
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

        // The post-`olddefconfig` RESOLVED config, copied out beside the kernel (§5.6, The
        // downstream kernel toolkit): `olddefconfig` silently drops any symbol whose dependencies
        // are unmet, so a fragment author asserts against this artifact, not against the fragment
        // they asked for. Left in the persistent build dir it is overwritten by the next build of
        // the same label and purged by a pin bump — never content-addressed with its kernel.
        // A missing `.config` after a successful `olddefconfig` is a hard error, never a skip that
        // ships a kernel with no evidence of what it contains — the shared `publish_resolved_config`
        // law, the same one the in-VM producer publishes its share copy through.
        let sidecar = publish_resolved_config(
            &config_path,
            out,
            self.label.as_deref().unwrap_or("default"),
        )
        .await?;
        tracing::info!(
            producer = "host-make",
            kernel = self.label.as_deref().unwrap_or("default"),
            config = %sidecar.display(),
            "kernel built; resolved config written"
        );

        Ok(kernel_outputs(out, &self.artifact_key(), Some(&sidecar)))
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

/// Returns whether a symlink at `link_path` (relative to the extraction root) pointing at
/// `target` would resolve OUTSIDE the extraction root — i.e. an absolute target, or a
/// relative target whose `..` components climb above the root (L-ART-3). A legitimate
/// relative symlink that stays within the tree (including one using `..` that does not
/// escape, common in kernel source) returns `false`.
fn symlink_escapes(link_path: &Path, target: &Path) -> bool {
    use std::path::Component;
    if target.is_absolute() {
        return true;
    }
    // Depth of the symlink's PARENT directory below the root; each target component walks it.
    let mut depth: i64 = link_path
        .parent()
        .map(|p| p.components().count() as i64)
        .unwrap_or(0);
    for comp in target.components() {
        match comp {
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => return true,
        }
    }
    false
}

/// A pipeline stage that fetches a **prebuilt** `vmlinux` — the bootstrap kernel seed
/// (§5.4, The guest-kernel contract and the bootstrap seed). Where [`KernelStage`] compiles from source on the host, this stage downloads a
/// digest-pinned prebuilt kernel and verifies it against `kernel_prebuilt_sha256`, then
/// registers it under the `kernel` artifact key exactly like the compiled path.
///
/// This is the fast bootstrap seed: it needs no toolchain and no builder VM, so it is the
/// seed that lets the in-VM `vmcell-kernel-builder` boot its own builder VM (the
/// seed-kernel chicken-and-egg, §5.4, The guest-kernel contract and the bootstrap seed). It is only usable when a prebuilt kernel that
/// satisfies the §5.2 (The config fragment) built-in config is pinned; otherwise [`KernelStage`] (host-`make`)
/// remains the guaranteed fallback seed.
pub struct PrebuiltKernelStage {
    /// The HTTP client used to download the prebuilt kernel.
    pub http_client: std::sync::Arc<dyn HttpClient>,
}

#[async_trait]
impl Stage for PrebuiltKernelStage {
    fn name(&self) -> &str {
        "kernel"
    }

    fn out_path(&self, target_dir: &Path) -> std::path::PathBuf {
        target_dir.join("vmlinux")
    }

    fn cache_key(&self, inputs: &StageInputs) -> CacheKey {
        // Bump when this stage's fetch/verify logic changes so stale kernels are not served.
        const STAGE_VERSION: u32 = 1;
        const SEP: &[u8] = b"\x1f";
        let mut hasher = blake3::Hasher::new();
        hasher.update(&STAGE_VERSION.to_le_bytes());
        hasher.update(SEP);
        hasher.update(b"prebuilt");
        hasher.update(SEP);
        hasher.update(
            inputs
                .pins
                .get("kernel_prebuilt_url")
                .map(|s| s.as_bytes())
                .unwrap_or_default(),
        );
        hasher.update(SEP);
        hasher.update(
            inputs
                .pins
                .get("kernel_prebuilt_sha256")
                .map(|s| s.as_bytes())
                .unwrap_or_default(),
        );
        // Optional archive-extraction identity (§5.4, The guest-kernel contract and the bootstrap seed): a prebuilt shipped inside a tar
        // (e.g. the Kata kernel) is keyed on the archive member path + the archive's own
        // digest, so re-pointing either invalidates the extracted kernel.
        hasher.update(SEP);
        hasher.update(
            inputs
                .pins
                .get("kernel_prebuilt_archive_member")
                .map(|s| s.as_bytes())
                .unwrap_or_default(),
        );
        hasher.update(SEP);
        hasher.update(
            inputs
                .pins
                .get("kernel_prebuilt_archive_sha256")
                .map(|s| s.as_bytes())
                .unwrap_or_default(),
        );
        CacheKey(format!("kernel-prebuilt-{}", hasher.finalize().to_hex()))
    }

    async fn run(&self, inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        let url = inputs.pins.get("kernel_prebuilt_url").ok_or_else(|| {
            Error::Artifact(
                "Missing kernel_prebuilt_url pin (no prebuilt kernel seed is pinned; use the \
                 host-make or in-VM kernel builder instead)"
                    .into(),
            )
        })?;
        let expected_sha = inputs
            .pins
            .get("kernel_prebuilt_sha256")
            .ok_or_else(|| Error::Artifact("Missing kernel_prebuilt_sha256 pin".into()))?;

        let downloaded = self.http_client.get(url).await?;

        // The final `vmlinux` bytes: either the download directly, or a member extracted from a
        // verified archive (the Kata kernel ships inside a `.tar.zst`, §5.4, The guest-kernel contract and the bootstrap seed).
        let vmlinux_bytes = match inputs.pins.get("kernel_prebuilt_archive_member") {
            None => downloaded,
            Some(member) => {
                // Verify the ARCHIVE against its own pinned digest first (provenance hard stop),
                // then extract + re-verify the member against `kernel_prebuilt_sha256`.
                let archive_sha =
                    inputs.pins.get("kernel_prebuilt_archive_sha256").ok_or_else(|| {
                        Error::Artifact(
                            "kernel_prebuilt_archive_member is set but kernel_prebuilt_archive_sha256 \
                             is missing (both are required to verify the archive)"
                                .into(),
                        )
                    })?;
                let got = sha256_hex(&downloaded);
                if &got != archive_sha {
                    return Err(Error::Artifact(format!(
                        "prebuilt kernel archive hash mismatch: expected {archive_sha}, got {got} (url {url})"
                    )));
                }
                let member = member.clone();
                tokio::task::spawn_blocking(move || extract_tar_member(&downloaded, &member))
                    .await
                    .map_err(|e| {
                        Error::Artifact(format!("archive extraction task failed: {e}"))
                    })??
            }
        };

        let got = sha256_hex(&vmlinux_bytes);
        if &got != expected_sha {
            // Provenance hard stop: a prebuilt kernel is opaque bytes, so an intact digest
            // is the *only* integrity check — never accept a mismatch (§10.2, The stage model and the five cache-key rules, §5.4, The guest-kernel contract and the bootstrap seed).
            return Err(Error::Artifact(format!(
                "prebuilt kernel hash mismatch: expected {expected_sha}, got {got} (url {url})"
            )));
        }
        if let Some(parent) = out.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(out, &vmlinux_bytes).await?;
        // No resolved-config sidecar: this producer downloads an opaque prebuilt kernel and
        // compiles nothing, so it has no post-`olddefconfig` `.config` to emit (§5.6, recorded
        // honestly rather than faked).
        //
        // It shares `out_path` (`vmlinux`) with the host-`make` producer, so a config left by an
        // EARLIER compiling build of that path would now describe different bytes. `vmcell bundle`
        // picks the sidecar up by filesystem existence, so leaving it there digest-pins a config
        // describing a different kernel as this kernel's `kernel-config` — the exact lying
        // artifact the sidecar exists to prevent. Clear it as part of publishing.
        clear_resolved_config(out).await?;
        Ok(kernel_outputs(out, "kernel", None))
    }
}

/// The lowercase-hex SHA-256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    // sha2 0.11 `finalize()` returns a `hybrid_array::Array` (no `LowerHex`).
    let out: [u8; 32] = h.finalize().into();
    out.iter().map(|b| format!("{b:02x}")).collect()
}

/// Extracts a single regular-file member from a (optionally zstd-compressed) tar `archive`,
/// streaming so only the target member is held in memory. `member` is matched with any leading
/// `./` stripped from both sides. zstd is detected by its magic bytes, so a plain `.tar` also
/// works.
///
/// # Errors
/// [`Error::Artifact`] if decompression fails or the member is absent.
fn extract_tar_member(archive: &[u8], member: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    let cursor = std::io::Cursor::new(archive);
    // zstd magic: 0x28 0xB5 0x2F 0xFD.
    let reader: Box<dyn Read> = if archive.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        Box::new(
            zstd::stream::read::Decoder::new(cursor)
                .map_err(|e| Error::Artifact(format!("zstd decode failed: {e}")))?,
        )
    } else {
        Box::new(cursor)
    };
    let want = member.trim_start_matches("./");
    let mut tar = tar::Archive::new(reader);
    for entry in tar.entries()? {
        let mut e = entry?;
        let path = e.path()?.into_owned();
        let got = path.to_string_lossy();
        if got.trim_start_matches("./") == want {
            let mut buf = Vec::new();
            e.read_to_end(&mut buf).map_err(Error::Io)?;
            return Ok(buf);
        }
    }
    Err(Error::Artifact(format!(
        "archive member `{member}` not found in the prebuilt kernel archive"
    )))
}

/// Builds the [`StageOutputs`] for a kernel build, registering the built kernel under
/// `key` (`"kernel"` for the default, `"kernel-<label>"` for a labelled stage) so
/// downstream stages (snapshot, mmdebstrap builder) always see it on a cold build — not
/// only on a warm-cache hit. Omitting this on the cold path lets the snapshot stage fall
/// through to a `/tmp/vmlinux` fallback; collapsing every labelled kernel onto `"kernel"`
/// loses all but one entry in a multi-kernel `Artifacts` map (M-PIPE-4).
///
/// `resolved_config` registers the sidecar under [`config_artifact_key`] when the producer
/// **compiled** the kernel (§5.6, The downstream kernel toolkit). The prebuilt seed passes `None`:
/// it has no config to emit, and inventing an empty one would be a lying artifact.
fn kernel_outputs(out: &Path, key: &str, resolved_config: Option<&Path>) -> StageOutputs {
    let mut outputs = StageOutputs::default();
    outputs.artifacts.insert(key.to_string(), out.to_path_buf());
    if let Some(cfg) = resolved_config {
        outputs
            .artifacts
            .insert(config_artifact_key(key), cfg.to_path_buf());
    }
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
        let outputs = kernel_outputs(out, "kernel", None);
        assert_eq!(
            outputs.artifacts.get("kernel").map(|p| p.as_path()),
            Some(out),
            "cold-build outputs must register the kernel artifact"
        );
        // The prebuilt seed emits no resolved config, so none is registered (§5.6).
        assert!(
            !outputs.artifacts.contains_key("kernel-config"),
            "a producer with no resolved config must not register one"
        );
    }

    // §5.6 (The downstream kernel toolkit): a COMPILING producer registers its resolved-config
    // sidecar under its own artifact key, which is what carries it through the pipeline's cache
    // sidecar onto the warm path. RED on the inverse (writing the `.config` to disk but registering
    // only the kernel): the `kernel-6.12.94-config` lookup returns None.
    #[test]
    fn test_kernel_outputs_registers_resolved_config_sidecar() {
        let out = Path::new("/some/target/vmlinux-6-12-94");
        let cfg = resolved_config_path(out);
        let outputs = kernel_outputs(out, "kernel-6.12.94", Some(&cfg));
        assert_eq!(
            outputs
                .artifacts
                .get("kernel-6.12.94-config")
                .map(|p| p.as_path()),
            Some(cfg.as_path()),
            "a compiling producer must register its resolved-config sidecar"
        );
        assert_eq!(
            outputs.artifacts.get("kernel-6.12.94").map(|p| p.as_path()),
            Some(out),
            "the kernel itself stays registered under its own key"
        );
    }

    // §5.6: the sidecar composer APPENDS `.config` — `Path::with_extension` would eat the trailing
    // component of a dotted name and alias two labels onto one config. RED on the inverse
    // (`with_extension("config")`): the dotted case below yields `vmlinux-6.12.config`.
    #[test]
    fn test_resolved_config_path_appends_extension() {
        assert_eq!(
            resolved_config_path(Path::new("/a/vmlinux-6-12-94")),
            Path::new("/a/vmlinux-6-12-94.config")
        );
        assert_eq!(
            resolved_config_path(Path::new("/a/vmlinux")),
            Path::new("/a/vmlinux.config")
        );
        assert_eq!(
            resolved_config_path(Path::new("/a/vmlinux-6.12.94")),
            Path::new("/a/vmlinux-6.12.94.config"),
            "a dotted filename keeps its whole name"
        );
        assert_eq!(config_artifact_key("kernel"), "kernel-config");
        assert_eq!(
            config_artifact_key("kernel-6.6.143"),
            "kernel-6.6.143-config"
        );
    }

    // §5.6 GATE (delta 3, F3): the ONE label-sanitization law and its inverse must round-trip, on
    // the labels the shipped registry actually carries plus the dotted/undotted shapes a consumer
    // overlay can add. `vmcell bundle` walks the artifacts dir with `kernel_label_from_filename`,
    // so a producer emitting a name this reader rejects would SILENTLY drop that kernel from a
    // manifest that reads as "covered everything".
    // RED on the inverse (drop the `.`→`-` sanitization in `kernel_filename_suffix`, the shape the
    // producers had four separate copies of): `vmlinux-6.12.94` comes back `None`.
    #[test]
    fn test_kernel_filename_round_trips_through_the_label_law() {
        // The shipped registry's own labels, read through the resolver rather than retyped.
        let shipped: Vec<String> = crate::artifact::resolve_kernel_registry(None)
            .expect("the baseline registry resolves")
            .into_iter()
            .map(|e| e.label)
            .collect();
        assert!(
            shipped.iter().any(|l| l.contains('.')),
            "the baseline registry must still exercise a DOTTED label; got {shipped:?}"
        );
        let synthetic = ["ikconfig", "usbhost", "6.12.94", "a.b.c"].map(str::to_string);
        for label in shipped.iter().chain(synthetic.iter()) {
            let name = kernel_filename(Some(label));
            assert!(
                !name.trim_start_matches("vmlinux").contains('.'),
                "the on-disk name of `{label}` must carry no `.` (it would be read as a \
                 sidecar, and `Path::with_extension` would collide same-minor labels), got {name}"
            );
            assert_eq!(
                kernel_label_from_filename(&name).map(str::to_string),
                Some(label.replace('.', "-")),
                "`{label}`'s on-disk name must round-trip back through the reader"
            );
        }
        // The default kernel and the sidecars beside a labelled one are not labelled kernels.
        assert_eq!(kernel_label_from_filename(&kernel_filename(None)), None);
        assert_eq!(kernel_label_from_filename("vmlinux-"), None);
        assert_eq!(kernel_label_from_filename("rootfs.erofs"), None);
        let labelled = kernel_filename(Some("6.12.94"));
        for sidecar in [
            resolved_config_path(Path::new(&labelled)),
            Path::new(&labelled).with_extension("cache_key"),
        ] {
            assert_eq!(
                kernel_label_from_filename(&sidecar.to_string_lossy()),
                None,
                "a kernel's sidecar ({}) is not a kernel",
                sidecar.display()
            );
        }
    }

    // §5.6 GATE (delta 3, F5): the sidecar's CONTENT. `publish_resolved_config` is the one law
    // both compiling producers ship their post-`olddefconfig` `.config` through, and until now the
    // copy itself had zero tests. The config here is composed by the REAL `kconfig_append` law
    // with a fragment in the pins registry, so what is asserted is "the fragment's symbol reaches
    // the published sidecar", not "some bytes were copied".
    // RED on the inverse (drop the copy and return the path, the shape `run()` had before the
    // sidecar existed): the sidecar is absent.
    // What this canNOT see: `make olddefconfig` between the append and the copy — it may legally
    // drop a symbol whose dependencies are unmet, which is exactly why the sidecar exists. That
    // half is the live fragment build (§18 delta 3's live leg / delta 5's example workspace).
    #[tokio::test]
    async fn test_publish_resolved_config_carries_the_fragment_symbol() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut pins = std::collections::HashMap::new();
        pins.insert(
            fragment_pin_key("IKCONFIG"),
            "CONFIG_IKCONFIG=y\nCONFIG_IKCONFIG_PROC=y\n".to_string(),
        );
        let text = kconfig_append(
            "CONFIG_VIRTIO=y\n",
            &pins,
            &sorted_fragments(Some(&["IKCONFIG".to_string()])),
        )
        .expect("the fragment resolves");
        let workdir_config = dir.path().join(".config");
        std::fs::write(&workdir_config, &text).expect("write the producer's .config");

        let out = dir.path().join(kernel_filename(Some("ikconfig")));
        std::fs::write(&out, b"vmlinux-bytes").expect("write the kernel");
        let sidecar = publish_resolved_config(&workdir_config, &out, "ikconfig")
            .await
            .expect("publishing the resolved config");

        assert_eq!(sidecar, resolved_config_path(&out));
        let published = std::fs::read_to_string(&sidecar).expect("read the published sidecar");
        assert!(
            published.contains("CONFIG_IKCONFIG=y"),
            "the published sidecar must carry the fragment's symbol, got:\n{published}"
        );
        assert_eq!(
            published, text,
            "the sidecar is the resolved config VERBATIM, not a summary of it"
        );
        // And it is registered under its own artifact key beside the kernel, which is what
        // content-addresses it with the kernel across a warm build.
        let outputs = kernel_outputs(&out, "kernel-ikconfig", Some(&sidecar));
        assert_eq!(
            outputs.artifacts.get("kernel-ikconfig-config"),
            Some(&sidecar)
        );
    }

    // §5.6 GATE (delta 3, F5): a compiling producer that reports success but has no `.config` is a
    // HARD ERROR naming the kernel — never a skip that ships a kernel with no evidence of what it
    // contains. RED on the inverse (a best-effort `let _ = tokio::fs::copy(...)`): the call
    // returns Ok and the build silently ships no sidecar.
    #[tokio::test]
    async fn test_publish_resolved_config_hard_errors_when_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("vmlinux-ikconfig");
        std::fs::write(&out, b"vmlinux-bytes").expect("write the kernel");
        let res = publish_resolved_config(&dir.path().join("nope/.config"), &out, "ikconfig").await;
        match res {
            Err(Error::Artifact(m)) => assert!(
                m.contains("ikconfig") && m.contains(".config"),
                "the refusal must name the kernel and the config it wanted, got: {m}"
            ),
            other => panic!("expected a hard error for a missing resolved config, got {other:?}"),
        }
        assert!(
            !resolved_config_path(&out).exists(),
            "no sidecar may be invented when the producer emitted none"
        );
    }

    // §5.6 GATE (delta 3, F2): a producer that emits NO config must not leave an earlier
    // producer's config behind at the same `vmlinux` path. RED on the inverse (drop the
    // `clear_resolved_config` call): the stale sidecar survives, and `vmcell bundle` — which picks
    // it up by filesystem existence, not from the stage's artifact map — digest-pins a config
    // describing a DIFFERENT kernel as this kernel's `kernel-config`.
    #[tokio::test]
    async fn test_prebuilt_kernel_clears_a_stale_resolved_config() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("vmlinux");
        // The state a `vmcell build --kernel-source host-make` leaves behind.
        std::fs::write(&out, b"host-make-vmlinux").expect("write the old kernel");
        let stale = resolved_config_path(&out);
        std::fs::write(&stale, b"CONFIG_IKCONFIG=y\n").expect("write the old config");

        let body = b"prebuilt-vmlinux".to_vec();
        let stage = PrebuiltKernelStage {
            http_client: std::sync::Arc::new(FakeHttpClient {
                body: body.clone(),
                calls: AtomicUsize::new(0),
            }),
        };
        let mut inputs = StageInputs::default();
        inputs.pins.insert(
            "kernel_prebuilt_url".into(),
            "http://example/vmlinux".into(),
        );
        inputs
            .pins
            .insert("kernel_prebuilt_sha256".into(), sha256_hex(&body));
        let outputs = stage.run(&inputs, &out).await.expect("prebuilt seed runs");

        assert_eq!(
            std::fs::read(&out).expect("read the republished kernel"),
            body,
            "the prebuilt bytes replaced the compiled kernel at this path"
        );
        assert!(
            !stale.exists(),
            "the stale resolved config at {} must be gone — it describes the kernel that USED \
             to be at this path",
            stale.display()
        );
        assert!(
            !outputs.artifacts.contains_key("kernel-config"),
            "this producer compiles nothing, so it registers no config artifact"
        );
        // Idempotent: a second run with no sidecar present is not an error.
        stage
            .run(&inputs, &out)
            .await
            .expect("an absent sidecar is not a failure");
    }

    // §5.4/§5.6 GATE (delta 3): the prebuilt seed compiles nothing, so a label or a fragment set
    // routed at it is a TYPED refusal naming what cannot be honored — never the pre-v30 silent
    // drop that handed back the default seed and reported success. RED on the inverse (a producer
    // selector that ignores label/fragments on the prebuilt arm): both rejects below return Ok.
    #[test]
    fn test_reject_labelled_prebuilt() {
        // The positive control: an unlabelled, fragment-free seed request is exactly what this
        // producer is for.
        assert!(reject_labelled_prebuilt(None, None).is_ok());
        assert!(
            reject_labelled_prebuilt(None, Some(&[])).is_ok(),
            "an empty fragment list is not a fragment request"
        );

        let label = reject_labelled_prebuilt(Some("6.12.94"), None);
        match label {
            Err(Error::Artifact(m)) => assert!(
                m.contains("6.12.94") && m.contains("prebuilt"),
                "the refusal must name the label it cannot honor, got: {m}"
            ),
            other => panic!("expected a typed refusal for a labelled prebuilt, got {other:?}"),
        }

        let frags = reject_labelled_prebuilt(None, Some(&["KASAN".to_string()]));
        match frags {
            Err(Error::Artifact(m)) => assert!(
                m.contains("KASAN"),
                "the refusal must name the fragments it cannot honor, got: {m}"
            ),
            other => panic!("expected a typed refusal for prebuilt+fragments, got {other:?}"),
        }
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

    // ---- §5.2 (The config fragment) kernel config-fragment matrix: cache-key behaviors (pure) ----

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

    // §5.2 (The config fragment): the fragment set is content-addressed by its SORTED form, so requesting the
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

    // §5.2 (The config fragment): the fragment SET is part of the key. A KASAN kernel must not share a cache
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

    // §5.2 (The config fragment): validity is content-addressed — editing a fragment's KConfig text (same name)
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

    // §5.5 GATE (delta 3) — the MISSING-FRAGMENT MARKER. The honest inverse is *not* "two
    // different unresolvable names collide" (the count + each name were already folded, so that
    // case has always hashed apart — a test written that way passes on the unfixed code). The real
    // alias `unwrap_or_default()` created is between a fragment ABSENT from the pins registry and
    // the same fragment PRESENT with empty KConfig text: both folded zero bytes. They are different
    // builds — the first is a `run()` hard error, the second a legal no-op — so the second's cached
    // kernel could be served for the first. RED on the inverse (restore `.unwrap_or_default()` and
    // the two keys below become equal).
    #[test]
    fn test_kernel_cache_key_missing_fragment_marker() {
        let stage = frag_stage(Some(vec!["NOSUCH"]));

        // (a) `NOSUCH` is absent from the registry entirely.
        let absent = frag_inputs();
        assert!(
            !absent.pins.contains_key("kernel_fragments_NOSUCH"),
            "fixture premise: the fragment is unresolvable"
        );
        // (b) `NOSUCH` is present but its KConfig text is empty.
        let mut empty = frag_inputs();
        empty
            .pins
            .insert("kernel_fragments_NOSUCH".into(), String::new());

        assert_ne!(
            stage.cache_key(&absent),
            stage.cache_key(&empty),
            "an unresolvable fragment must not hash like a resolvable-but-empty one"
        );

        // And the same stage against the same pins is still stable (the marker is deterministic).
        assert_eq!(stage.cache_key(&absent), stage.cache_key(&absent));
        // Adding the empty fragment's text later must invalidate the key for the same reason.
        let mut nonempty = frag_inputs();
        nonempty
            .pins
            .insert("kernel_fragments_NOSUCH".into(), "CONFIG_X=y\n".into());
        assert_ne!(stage.cache_key(&empty), stage.cache_key(&nonempty));
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

    // L-ART-3: `symlink_escapes` flags exactly the symlinks that resolve OUTSIDE the
    // extraction root (absolute target, or `..` climbing above root) and allows legit
    // relative links (including in-tree `..`, common in kernel source). A no-op defense
    // (always `false`) reddens the escaping cases.
    #[test]
    fn test_symlink_escapes() {
        assert!(
            symlink_escapes(Path::new("dir"), Path::new("/etc")),
            "an absolute symlink target escapes"
        );
        assert!(
            symlink_escapes(Path::new("a/b"), Path::new("../../../etc")),
            "a relative target climbing above the root escapes"
        );
        assert!(
            !symlink_escapes(Path::new("a/b"), Path::new("../c")),
            "an in-tree relative target is allowed"
        );
        assert!(
            !symlink_escapes(
                Path::new("arch/x/include/asm"),
                Path::new("../../../include/asm-generic")
            ),
            "a deep in-tree kernel-style symlink is allowed"
        );
    }

    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A recording HTTP client (M-ART-9): serves canned bytes and counts `get()` calls, so
    /// the kernel provenance path (hash-mismatch hard stop, verify-or-purge) runs with no
    /// network.
    struct FakeHttpClient {
        body: Vec<u8>,
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl HttpClient for FakeHttpClient {
        async fn get(&self, _url: &str) -> Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.body.clone())
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(bytes);
        let out: [u8; 32] = h.finalize().into();
        out.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn kernel_inputs(sha: String) -> StageInputs {
        let mut i = StageInputs::default();
        i.pins
            .insert("kernel_source_url".into(), "http://example/k".into());
        i.pins.insert("kernel_source_sha256".into(), sha);
        i.pins
            .insert("kernel_microvm_config".into(), "CONFIG_X=y\n".into());
        i
    }

    // M-ART-9 (1): served bytes that do not match the pinned SHA are a provenance HARD STOP.
    // Dropping the hash check (accepting any bytes) would let run() proceed to a decode error
    // with a different message -> the "mismatch" assertion goes red.
    #[tokio::test]
    async fn test_kernel_hash_mismatch_hard_stops() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("vmlinux");
        let fake = std::sync::Arc::new(FakeHttpClient {
            body: b"wrong-bytes".to_vec(),
            calls: AtomicUsize::new(0),
        });
        let stage = KernelStage {
            http_client: fake.clone(),
            label: None,
            fragments: None,
        };
        // Pin the hash of DIFFERENT bytes, so the served content mismatches.
        let res = stage
            .run(&kernel_inputs(sha256_hex(b"right-bytes")), &out)
            .await;
        match res {
            Err(Error::Artifact(m)) => {
                assert!(
                    m.contains("mismatch"),
                    "expected a hash-mismatch stop, got: {m}"
                )
            }
            other => panic!("expected an Artifact hash-mismatch error, got {other:?}"),
        }
        assert_eq!(
            fake.calls.load(Ordering::SeqCst),
            1,
            "one fetch attempt precedes the mismatch stop"
        );
    }

    // M-ART-9 (2): a stale tarball on disk with a BUMPED pin must be re-fetched AND the stale
    // extracted tree purged. The old existence-only check saw the tarball present, skipped
    // the fetch (calls == 0) and kept the stale marker -> both assertions go red.
    #[tokio::test]
    async fn test_kernel_bumped_pin_refetches_and_purges() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("vmlinux");
        let workdir = dir.path().join("kernel-build");
        std::fs::create_dir_all(&workdir).unwrap();
        std::fs::write(workdir.join("linux.tar.xz"), b"old-tarball").unwrap();
        std::fs::write(workdir.join("stale_marker"), b"stale").unwrap();
        let fresh = b"fresh-bytes";
        let fake = std::sync::Arc::new(FakeHttpClient {
            body: fresh.to_vec(),
            calls: AtomicUsize::new(0),
        });
        let stage = KernelStage {
            http_client: fake.clone(),
            label: None,
            fragments: None,
        };
        // Bumped pin (hash of the fresh bytes != the stale tarball's hash). run() re-fetches
        // and purges the workdir, then fails at the xz-decompress of the non-xz fresh bytes —
        // AFTER the provenance behavior asserted below.
        let _ = stage.run(&kernel_inputs(sha256_hex(fresh)), &out).await;
        assert_eq!(
            fake.calls.load(Ordering::SeqCst),
            1,
            "a bumped pin (content mismatch) must re-fetch"
        );
        assert!(
            !workdir.join("stale_marker").exists(),
            "a bumped pin must purge the stale extracted tree"
        );
    }

    // §5.4 (The guest-kernel contract and the bootstrap seed) prebuilt bootstrap seed: a downloaded prebuilt kernel whose bytes do not match
    // the pinned SHA is a provenance HARD STOP (the digest is the only integrity check on
    // opaque prebuilt bytes). Dropping the check would write the wrong bytes and return Ok
    // -> the mismatch assertion goes red.
    #[tokio::test]
    async fn test_prebuilt_kernel_hash_mismatch_hard_stops() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("vmlinux");
        let fake = std::sync::Arc::new(FakeHttpClient {
            body: b"prebuilt-bytes".to_vec(),
            calls: AtomicUsize::new(0),
        });
        let stage = PrebuiltKernelStage {
            http_client: fake.clone(),
        };
        let mut inputs = StageInputs::default();
        inputs.pins.insert(
            "kernel_prebuilt_url".into(),
            "http://example/vmlinux".into(),
        );
        // Pin the SHA of DIFFERENT bytes.
        inputs
            .pins
            .insert("kernel_prebuilt_sha256".into(), sha256_hex(b"other-bytes"));
        match stage.run(&inputs, &out).await {
            Err(Error::Artifact(m)) => {
                assert!(m.contains("mismatch"), "expected a hash mismatch, got: {m}")
            }
            other => panic!("expected an Artifact hash-mismatch error, got {other:?}"),
        }
        assert!(
            !out.exists(),
            "a mismatched prebuilt kernel must not be written to the output path"
        );
    }

    // §5.4 (The guest-kernel contract and the bootstrap seed): a matching prebuilt is written and registered under the `kernel` artifact key
    // (so downstream consumers / a VM find it). The inverse (registering nothing, or a
    // different key) reddens the artifact-key assertion.
    #[tokio::test]
    async fn test_prebuilt_kernel_matching_writes_and_registers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("vmlinux");
        let body = b"good-prebuilt-vmlinux".to_vec();
        let fake = std::sync::Arc::new(FakeHttpClient {
            body: body.clone(),
            calls: AtomicUsize::new(0),
        });
        let stage = PrebuiltKernelStage {
            http_client: fake.clone(),
        };
        let mut inputs = StageInputs::default();
        inputs.pins.insert(
            "kernel_prebuilt_url".into(),
            "http://example/vmlinux".into(),
        );
        inputs
            .pins
            .insert("kernel_prebuilt_sha256".into(), sha256_hex(&body));
        let outputs = stage.run(&inputs, &out).await.expect("prebuilt build");
        assert_eq!(std::fs::read(&out).expect("read out"), body);
        assert_eq!(
            outputs.artifacts.get("kernel").map(|p| p.as_path()),
            Some(out.as_path()),
            "prebuilt stage must register the kernel artifact"
        );
    }

    // §5.4 (The guest-kernel contract and the bootstrap seed): a missing prebuilt pin is a fail-loud error, never a silent success (the
    // host-make builder is the fallback seed, chosen by the caller — not by a silent skip).
    #[tokio::test]
    async fn test_prebuilt_kernel_missing_pin_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("vmlinux");
        let fake = std::sync::Arc::new(FakeHttpClient {
            body: b"x".to_vec(),
            calls: AtomicUsize::new(0),
        });
        let stage = PrebuiltKernelStage { http_client: fake };
        let res = stage.run(&StageInputs::default(), &out).await;
        assert!(
            matches!(res, Err(Error::Artifact(_))),
            "a missing prebuilt pin must fail loud, got {res:?}"
        );
    }

    /// Builds a single-member `.tar.zst` in memory (mirrors how the Kata kernel ships, §5.4, The guest-kernel contract and the bootstrap seed).
    fn make_tar_zst(member: &str, content: &[u8]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, member, content)
                .expect("append");
            builder.finish().expect("finish");
        }
        zstd::stream::encode_all(std::io::Cursor::new(tar_bytes), 0).expect("zstd")
    }

    // §5.4 (The guest-kernel contract and the bootstrap seed): a prebuilt shipped inside a `.tar.zst` (the Kata case) is verified against the
    // ARCHIVE digest, the named member extracted, then re-verified against the member digest —
    // and written out. The inverse (writing the whole archive as the kernel) reddens the
    // content assertion.
    #[tokio::test]
    async fn test_prebuilt_kernel_archive_extracts_and_verifies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("vmlinux");
        let member_path = "./opt/kata/share/kata-containers/vmlinux-test";
        let member_content = b"REAL-VMLINUX-ELF-BYTES".to_vec();
        let archive = make_tar_zst(member_path, &member_content);
        let fake = std::sync::Arc::new(FakeHttpClient {
            body: archive.clone(),
            calls: AtomicUsize::new(0),
        });
        let stage = PrebuiltKernelStage { http_client: fake };
        let mut inputs = StageInputs::default();
        inputs
            .pins
            .insert("kernel_prebuilt_url".into(), "http://x/kata.tar.zst".into());
        inputs.pins.insert(
            "kernel_prebuilt_archive_sha256".into(),
            sha256_hex(&archive),
        );
        inputs
            .pins
            .insert("kernel_prebuilt_archive_member".into(), member_path.into());
        inputs
            .pins
            .insert("kernel_prebuilt_sha256".into(), sha256_hex(&member_content));
        stage
            .run(&inputs, &out)
            .await
            .expect("archive prebuilt build");
        assert_eq!(
            std::fs::read(&out).expect("read out"),
            member_content,
            "the extracted member (not the whole archive) must be written as vmlinux"
        );
    }

    // §5.4 (The guest-kernel contract and the bootstrap seed): a tampered archive (bytes not matching `archive_sha256`) is a provenance hard stop
    // before extraction — the archive digest is the integrity check on opaque compressed bytes.
    #[tokio::test]
    async fn test_prebuilt_kernel_archive_sha_mismatch_hard_stops() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("vmlinux");
        let archive = make_tar_zst("./vmlinux", b"content");
        let fake = std::sync::Arc::new(FakeHttpClient {
            body: archive,
            calls: AtomicUsize::new(0),
        });
        let stage = PrebuiltKernelStage { http_client: fake };
        let mut inputs = StageInputs::default();
        inputs
            .pins
            .insert("kernel_prebuilt_url".into(), "http://x/a.tar.zst".into());
        // Pin the WRONG archive digest.
        inputs.pins.insert(
            "kernel_prebuilt_archive_sha256".into(),
            sha256_hex(b"other"),
        );
        inputs
            .pins
            .insert("kernel_prebuilt_archive_member".into(), "./vmlinux".into());
        inputs
            .pins
            .insert("kernel_prebuilt_sha256".into(), sha256_hex(b"content"));
        match stage.run(&inputs, &out).await {
            Err(Error::Artifact(m)) => assert!(m.contains("archive hash mismatch"), "got {m}"),
            other => panic!("expected archive hash mismatch, got {other:?}"),
        }
        assert!(!out.exists());
    }

    // §5.4 (The guest-kernel contract and the bootstrap seed): a member absent from the archive is a hard error, never a silent empty/whole-archive
    // write.
    #[tokio::test]
    async fn test_prebuilt_kernel_archive_missing_member_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("vmlinux");
        let archive = make_tar_zst("./present", b"x");
        let fake = std::sync::Arc::new(FakeHttpClient {
            body: archive.clone(),
            calls: AtomicUsize::new(0),
        });
        let stage = PrebuiltKernelStage { http_client: fake };
        let mut inputs = StageInputs::default();
        inputs
            .pins
            .insert("kernel_prebuilt_url".into(), "http://x/a.tar.zst".into());
        inputs.pins.insert(
            "kernel_prebuilt_archive_sha256".into(),
            sha256_hex(&archive),
        );
        inputs
            .pins
            .insert("kernel_prebuilt_archive_member".into(), "./absent".into());
        inputs
            .pins
            .insert("kernel_prebuilt_sha256".into(), sha256_hex(b"x"));
        match stage.run(&inputs, &out).await {
            Err(Error::Artifact(m)) => assert!(m.contains("not found"), "got {m}"),
            other => panic!("expected member-not-found error, got {other:?}"),
        }
    }

    // M-ART-9 (3): a cached tarball whose CONTENT matches the pin must NOT be re-fetched. An
    // always-fetch regression would call get() -> the `== 0` assertion goes red.
    #[tokio::test]
    async fn test_kernel_matching_cache_skips_fetch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("vmlinux");
        let workdir = dir.path().join("kernel-build");
        std::fs::create_dir_all(&workdir).unwrap();
        let cached = b"cached-tarball-bytes";
        std::fs::write(workdir.join("linux.tar.xz"), cached).unwrap();
        let fake = std::sync::Arc::new(FakeHttpClient {
            body: b"unused".to_vec(),
            calls: AtomicUsize::new(0),
        });
        let stage = KernelStage {
            http_client: fake.clone(),
            label: None,
            fragments: None,
        };
        let _ = stage.run(&kernel_inputs(sha256_hex(cached)), &out).await;
        assert_eq!(
            fake.calls.load(Ordering::SeqCst),
            0,
            "a content-matching cached tarball must not be re-fetched"
        );
    }
}
