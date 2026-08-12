//! Root filesystem artifact building.
//!
//! This module provides the `RootfsStage` pipeline step, which creates a minimal root
//! filesystem for the virtual machines from an **OCI registry pull** — the in-`vmcell`
//! bootstrap rootfs source (host-native, no VM). The full-apt **`mmdebstrap`-inside-a-VM**
//! source now lives in the separate `vmcell-rootfs-builder` crate (§4.3, The rootfs-construction contract / §4.2, Rootfs sources and the one packer), which
//! calls [`pack_erofs_with_injection`](crate::artifact::rootfs::pack_erofs_with_injection) and
//! [`resolve_builder_base`](crate::artifact::rootfs::resolve_builder_base) here so every rootfs
//! source shares one inject/CA/erofs tail.

use crate::artifact::{CacheKey, Stage, StageInputs, StageOutputs};
use crate::error::{Error, Result};
use async_trait::async_trait;
use std::io::Read;
use std::path::{Path, PathBuf};

/// OCI registry pull source.
pub mod oci;

/// A caller-supplied file composed into the rootfs at pack time (design §4.2, FR-V4) — a
/// daemon, a CLI, a test fixture — so the image stays the artifact and per-boot `put_file`
/// pushes leave the hot path.
///
/// Regular files only in v1: symlinks and xattrs stay out, consistent with the recorded
/// PAX-xattr limitation. The whole pack tail buffers in memory, so a very large extra file
/// costs peak RSS; bulk data belongs on an extra virtio-blk image instead (§4.6).
///
/// Every field is validated at the pack tail, never silently coerced: `dest` must be absolute,
/// UTF-8 (it is a `String`), free of `..` components, must name a **file** — a trailing `/` or
/// a trailing `.` names the parent directory and is rejected — must not name a vmcell-owned
/// path ([`is_reserved_injection_path`]), and must not duplicate another extra file's dest;
/// `mode` must be permission bits only. An *interior* `.` component is folded away by the
/// packer's own normalizer rather than rejected, so `/a/./b` and `/a/b` are the same dest — and
/// therefore the same duplicate. A violation is a build-time [`Error::Artifact`] naming the
/// dest, never a silent overwrite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraFile {
    /// Absolute in-guest destination path, e.g. `/usr/local/bin/acme-daemon`.
    pub dest: String,
    /// Host path of the file to read at pack time.
    pub src: PathBuf,
    /// Explicit permission bits, e.g. `0o755`. Extra files do NOT inherit the packer's
    /// `bin`/`sbin` executable heuristic — the caller states what it means. Permission bits
    /// only (`<= 0o7777`): a full `st_mode` carrying `S_IFREG` is rejected, never truncated.
    pub mode: u32,
}

impl ExtraFile {
    /// Builds an [`ExtraFile`] from its three parts.
    pub fn new(dest: impl Into<String>, src: impl Into<PathBuf>, mode: u32) -> Self {
        Self {
            dest: dest.into(),
            src: src.into(),
            mode,
        }
    }
}

/// The directory holding the guest-tools multicall binary and its exec-PATH symlinks. Reserved
/// as a whole so a name the manifest has not grown yet (delta 7's `echo-server` was one) is
/// covered the moment it is added.
const VMCELL_TOOLS_DIR: &str = "vmcell-tools";

/// Whether `dest` names a path vmcell itself injects and therefore owns (invariant F5).
///
/// The ONE reserved-path list: it is *derived from* `rootfs_injection_manifest` rather than
/// restated, so the list cannot drift from what the packer actually bakes, plus the
/// `VMCELL_TOOLS_DIR` prefix rule that covers every multicall name — present or future.
/// A downstream [`ExtraFile`] whose dest hits it is a build-time [`Error::Artifact`]; vmcell's
/// own injections stay unconditional and authoritative (design §4.2, §13 invariant F5).
///
/// `dest` is normalized through the packer's own
/// [`normalize_path`](crate::artifact::tar2erofs) before comparison, so the absolute form the
/// caller writes (`/usr/sbin/vmcell-guest-agent`), a `.`-bearing evasion
/// (`/usr/sbin/./vmcell-guest-agent`), and the manifest's relative form
/// (`usr/sbin/vmcell-guest-agent`) all collapse to the same key. Comparing raw strings would
/// let the evasion shapes past the check and then silently lose to the vmcell injection.
#[cfg(feature = "am-fs-erofs")]
pub fn is_reserved_injection_path(dest: &str) -> bool {
    use crate::artifact::tar2erofs::normalize_path;
    let normalized = normalize_path(Path::new(dest));
    // The whole guest-tools directory, including names not yet in the manifest.
    let tools = Path::new(VMCELL_TOOLS_DIR);
    if normalized == tools || normalized.starts_with(tools) {
        return true;
    }
    // Every manifest dest, with all optional entries present so the check does not depend on
    // which features baked a CA or built guest-tools. The paths are never read here.
    let probe = Path::new("/dev/null");
    let (files, symlinks) = rootfs_injection_manifest(probe, Some(probe), Some(probe));
    files
        .iter()
        .any(|(d, _, _)| normalize_path(Path::new(d)) == normalized)
        || symlinks
            .iter()
            .any(|(l, _)| normalize_path(Path::new(l)) == normalized)
}

/// Validates the downstream extra files and returns them as owned, packer-ready
/// `(dest, src, mode)` triples in the caller's order (owned so they can cross into the
/// blocking pack task).
///
/// The injection tail is the validation boundary: an [`ExtraFile`] never passes through
/// `VmConfig`, so this is the only place its accepted input can be honored or rejected
/// (design §4.2). Every rejection names the offending dest.
///
/// # Errors
/// [`Error::Artifact`] if a dest is empty, relative, carries a `..` component, names a
/// directory rather than a file (a trailing `/` or a trailing `.`, including the bare `/`),
/// is [reserved](is_reserved_injection_path), or duplicates another extra file's normalized
/// dest; or if a mode carries bits outside `0o7777`. An *interior* `.` component is folded
/// away by [`normalize_path`](crate::artifact::tar2erofs), never rejected.
#[cfg(feature = "am-fs-erofs")]
fn validate_extra_files(extra: &[ExtraFile]) -> Result<Vec<(String, PathBuf, u16)>> {
    use crate::artifact::tar2erofs::normalize_path;
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(extra.len());
    for f in extra {
        let dest = f.dest.as_str();
        if !dest.starts_with('/') {
            return Err(Error::Artifact(format!(
                "injected extra file dest `{dest}` must be an absolute in-guest path"
            )));
        }
        // `normalize_path` POPS a `..`, so a dest carrying one would silently mean a different
        // path than it reads as. Reject it rather than resolve it. This runs BEFORE the
        // names-a-file check below, which would otherwise accept `/usr/local/../sbin/acme`
        // (its raw leaf and its normalized leaf agree).
        if Path::new(dest)
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(Error::Artifact(format!(
                "injected extra file dest `{dest}` must not contain a `..` component"
            )));
        }
        let normalized = normalize_path(Path::new(dest));
        // "Names a file, not a directory", DERIVED FROM THE NORMALIZED FORM: the dest's raw
        // final segment (the text after the last `/`) must be exactly the normalized path's
        // final component. A raw `dest.ends_with('/')` test is not that law — it accepts
        // `/opt/.`, whose raw leaf `.` normalizes away so the dest names the DIRECTORY `/opt`,
        // and `Path::components` folds a trailing `.` away too, so a component scan misses it
        // as well. Debian ships `/opt`, `/srv`, `/mnt` and `/media` as EMPTY directories, and
        // an empty dir clears the packer's "child under a non-directory parent" check, so
        // `--inject dest=/opt/.` would have silently replaced the directory with a regular
        // file. One law: everything downstream keys on `normalize_path`, so this guard does
        // too. An interior `.` (`/a/./b`) still folds away and is accepted.
        let raw_leaf = dest.rsplit('/').next().unwrap_or_default();
        if normalized.file_name() != Some(std::ffi::OsStr::new(raw_leaf)) {
            return Err(Error::Artifact(format!(
                "injected extra file dest `{dest}` must name a file, not a directory \
                 (a trailing `/` or `.` names the parent directory)"
            )));
        }
        if is_reserved_injection_path(dest) {
            return Err(Error::Artifact(format!(
                "injected extra file dest `{dest}` is a vmcell-owned injection path \
                 (the guest agent, the CA trust store, or /{VMCELL_TOOLS_DIR}); \
                 vmcell's own injections are authoritative and are never overwritten"
            )));
        }
        if !seen.insert(normalized.clone()) {
            return Err(Error::Artifact(format!(
                "injected extra file dest `{dest}` is listed twice; the last writer would \
                 silently win"
            )));
        }
        // The erofs node mode is 16-bit and the type bits are added by the packer. A full
        // `st_mode` (e.g. 0o100755) must be REJECTED, never narrowed with `as` into a wrong
        // permission set.
        if f.mode & !0o7777 != 0 {
            return Err(Error::Artifact(format!(
                "injected extra file dest `{dest}` has mode {:#o}: permission bits only \
                 (<= 0o7777); the file-type bits are set by the packer",
                f.mode
            )));
        }
        let mode = u16::try_from(f.mode).map_err(|_| {
            Error::Artifact(format!(
                "injected extra file dest `{dest}` has an out-of-range mode {:#o}",
                f.mode
            ))
        })?;
        out.push((f.dest.clone(), f.src.clone(), mode));
    }
    Ok(out)
}

/// A pipeline stage that builds a root filesystem from an OCI base image (the in-`vmcell`
/// bootstrap source, §4.2, Rootfs sources and the one packer). The in-VM `mmdebstrap` source is `vmcell-rootfs-builder`.
pub struct RootfsStage {
    /// Explicit `(image, digest)` override for the OCI source (v15 `oci2erofs`, §4.2, Rootfs sources and the one packer):
    /// `Some` ignores the pinned `rootfs_image`/`rootfs_digest` and pulls this digest-pinned
    /// base instead. `None` uses the pins (the default `vmcell build`).
    pub image_override: Option<(String, String)>,
    /// Static-musl guest agent to inject instead of the pipeline's default glibc agent
    /// (`oci2erofs --agent-musl`, §4.2, Rootfs sources and the one packer). When `Some`, the libc6-presence guard is skipped.
    pub agent_musl: Option<std::path::PathBuf>,
    /// Downstream files composed into the image at pack time (`oci2erofs --inject`, §4.2,
    /// FR-V4). Empty for the default `vmcell build`.
    pub extra: Vec<ExtraFile>,
}

/// The OCI rootfs stage's cache-key version. Bump when this stage's build logic or its folded
/// identity changes so stale outputs are not served — the rootfs is a warm-cache artifact, and
/// an identity-fold change without the bump serves a stale image while every test stays green.
///
/// v15: bumped to 2 with the oci2erofs image-override + agent-musl inputs.
/// v20: bumped to 3 — the shared injected-content fold (agent-musl + CA + guest-agent source)
/// moved into [`fold_rootfs_injection_identity`] (called first), which reorders the hashed byte
/// stream. A one-time OCI-rootfs rebuild is harmless.
/// v30 (§18 delta 6): bumped to 4 — the fold gained the sorted downstream extra-file triples.
///
/// Module-level (rather than a `fn`-local `const`) so the bump itself is assertable KVM-free:
/// `rootfs_stage_version_pins_the_delta6_bump`.
const OCI_ROOTFS_STAGE_VERSION: u32 = 4;

#[async_trait]
impl Stage for RootfsStage {
    fn name(&self) -> &str {
        "rootfs"
    }

    fn out_path(&self, target_dir: &std::path::Path) -> std::path::PathBuf {
        target_dir.join("rootfs.erofs")
    }

    fn cache_key(&self, inputs: &StageInputs) -> CacheKey {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&OCI_ROOTFS_STAGE_VERSION.to_le_bytes());
        // Fold the identity of everything the shared inject+pack tail bakes in (the optional
        // static-musl agent override, the deployment CA, the guest-agent source closure, the
        // downstream extra files) — ONE implementation, shared with the out-of-crate in-VM
        // rootfs builders (§4.3, The rootfs-construction contract).
        fold_rootfs_injection_identity(
            &mut hasher,
            inputs,
            self.agent_musl.as_deref(),
            &self.extra,
        );
        hasher.update(b"oci");
        // oci2erofs: the CLI-provided digest-pinned base is an INPUT (not a pin) and
        // must be content-addressed directly; otherwise a stale erofs is reused for a
        // different IMAGE@DIGEST. Fall back to the pins for the default `vmcell build`.
        let (image, digest) = match &self.image_override {
            Some((i, d)) => (i.as_str(), d.as_str()),
            None => (
                inputs
                    .pins
                    .get("rootfs_image")
                    .map(String::as_str)
                    .unwrap_or_default(),
                inputs
                    .pins
                    .get("rootfs_digest")
                    .map(String::as_str)
                    .unwrap_or_default(),
            ),
        };
        hasher.update(image.as_bytes());
        hasher.update(b"\0");
        hasher.update(digest.as_bytes());
        // Hash only the upstream artifacts this stage actually CONSUMES (ART-9), in a
        // deterministic key-sorted order over their on-disk content. Folding *every*
        // upstream artifact meant a `kernel` rebuild invalidated the OCI rootfs, which does
        // not depend on the kernel (the OCI source boots no VM). Scope the fold to the
        // injected `guest_agent` + `guest_tools` binaries (the base image is a pin/override,
        // not an artifact). The in-VM `mmdebstrap` source, which additionally consumes the
        // seed `kernel`, lives in `vmcell-rootfs-builder` and folds it in its own key.
        let consumed: &[&str] = &["guest_agent", "guest_tools"];
        let filtered: std::collections::HashMap<String, std::path::PathBuf> = inputs
            .artifacts
            .iter()
            .filter(|(k, _)| consumed.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        crate::artifact::hash_artifacts_sorted(&mut hasher, &filtered);
        CacheKey(format!("rootfs-{}", hasher.finalize().to_hex()))
    }

    async fn run(&self, inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        // oci2erofs (§4.2, Rootfs sources and the one packer): the CLI override pulls an explicit digest-pinned base;
        // the default `vmcell build` resolves the pinned Debian image from the pins.
        let (image, digest) = match &self.image_override {
            Some((i, d)) => (i.clone(), d.clone()),
            None => {
                let image = inputs
                    .pins
                    .get("rootfs_image")
                    .ok_or_else(|| Error::Artifact("Missing rootfs_image pin".into()))?;
                let digest = inputs
                    .pins
                    .get("rootfs_digest")
                    .ok_or_else(|| Error::Artifact("Missing rootfs_digest pin".into()))?;
                (image.clone(), digest.clone())
            }
        };
        oci::build_rootfs(
            &image,
            &digest,
            inputs,
            out,
            self.agent_musl.as_deref(),
            &self.extra,
        )
        .await
    }
}

/// Folds the identity of everything the shared inject+pack tail ([`pack_erofs_with_injection`])
/// bakes into a rootfs — the optional static-musl agent override (by CONTENT, H-ART-1), the
/// deployment proxy CA cert (M-ART-10), the guest-agent source closure, and the downstream
/// [`ExtraFile`]s — into `hasher`.
///
/// The extra files fold as `(dest, mode, content-hash)` triples in sorted-dest order (§4.2):
/// **content that travels, never the `src` path** (cache-key rule 3), and sorted so the
/// caller's `Vec` order is not part of the identity.
///
/// Every rootfs builder folds this identically: the in-`vmcell` OCI [`RootfsStage`] and the
/// out-of-crate in-VM sources (`vmcell-rootfs-builder`). Kept here so there is exactly ONE
/// implementation of the injected-content identity (§4.3, The rootfs-construction contract; AGENTS.md "don't triplicate;
/// extract") — a musl-agent/CA/agent rebuild then invalidates the cached erofs from any source.
///
/// Callers fold their own `STAGE_VERSION`, source discriminator, source-specific pins, and
/// consumed-artifact set (via [`crate::artifact::hash_artifacts_sorted`]) around this call.
#[cfg(feature = "pipeline")]
pub fn fold_rootfs_injection_identity(
    hasher: &mut blake3::Hasher,
    inputs: &StageInputs,
    agent_musl: Option<&Path>,
    extra: &[ExtraFile],
) {
    // The injected-agent identity: a static-musl override (folded by CONTENT, not path string,
    // since the GuestAgentStage is skipped on that path) vs. the default glibc agent. A read
    // failure folds a distinct marker; the resulting miss re-runs the build, which fails loud.
    match agent_musl {
        Some(p) => {
            hasher.update(b"agent-musl\0");
            match crate::artifact::hash_file(p) {
                Ok(h) => hasher.update(h.as_bytes()),
                Err(_) => hasher.update(format!("missing-agent-musl:{}", p.display()).as_bytes()),
            };
        }
        None => {
            hasher.update(b"agent-default\0");
        }
    }
    // The baked proxy CA cert content (M-ART-10): `run()` writes the deployment CA into the
    // rootfs as a side effect, so a CA rotation must invalidate the cached erofs or the guest
    // trusts the old CA and HTTPS intercept breaks silently. A read failure folds a marker.
    #[cfg(feature = "proxy")]
    {
        match crate::proxy::tls::CaManager::new().map(|m| m.ca_cert_pem().to_string()) {
            Ok(pem) => {
                hasher.update(b"ca\0");
                hasher.update(pem.as_bytes());
            }
            Err(e) => {
                hasher.update(format!("ca-read-error:{e}").as_bytes());
            }
        };
    }
    // The guest-agent source identity (travels via the resolved pins): rebuilding the agent
    // must invalidate the rootfs, otherwise a stale agent stays baked in.
    hasher.update(
        inputs
            .pins
            .get("guest_agent_src_hash")
            .map(String::as_bytes)
            .unwrap_or_default(),
    );
    // The downstream extra files (§4.2, §18 delta 6). Sorted by dest so the caller's Vec order
    // is not identity, and folded by CONTENT — a rebuilt binary at the SAME src path must
    // re-pack the image, and moving an unchanged binary to a different src path must not.
    // A read failure folds a dest-keyed marker; the resulting miss re-runs the pack, which
    // fails loud on the unreadable source.
    hasher.update(b"extra-files\0");
    let mut sorted: Vec<&ExtraFile> = extra.iter().collect();
    sorted.sort_by(|a, b| a.dest.cmp(&b.dest));
    for f in sorted {
        hasher.update(f.dest.as_bytes());
        hasher.update(b"\0");
        hasher.update(&f.mode.to_le_bytes());
        match crate::artifact::hash_file(&f.src) {
            Ok(h) => hasher.update(h.as_bytes()),
            Err(_) => hasher.update(format!("missing-extra:{}", f.dest).as_bytes()),
        };
    }
}

/// Resolves the builder-base image as an atomic `(image, digest)` pair from the resolved
/// pins, never mixing a pinned image with a hardcoded digest.
///
/// Public so the out-of-crate in-VM rootfs/kernel builders (`vmcell-rootfs-builder`,
/// `vmcell-kernel-builder`) resolve the builder-VM base image the *same* way the bootstrap
/// pipeline does — one resolver, no drift.
///
/// Precedence: the dedicated `builder_base_*` pins, else the `rootfs_*` pins. A
/// half-specified pair (image without digest, or vice-versa) or a completely missing base
/// is a hard error — a hardcoded fallback would mask a missing Stage-0 pin and could pin a
/// mismatched `image@digest` reference (M-PIPE-2 / B5 "no fallback masking a missing
/// upstream").
///
/// # Errors
/// Returns [`Error::Artifact`] if no pin pair is present, or only one half of a pair is set.
pub fn resolve_builder_base(
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

/// Shared logic to take a list of tar streams, insert the caller's `extra` files, inject the
/// agent and CA, and pack it into erofs.
///
/// The ONE inject+pack tail: every rootfs source routes through it (§4.3 obligation 3), so the
/// `libc6` scan, the `--agent-musl` opt-in, and the downstream `extra` files with their
/// reserved-path collision guard apply to every source for free. `extra` is validated FIRST —
/// before any I/O — so a bad dest or mode fails before the CA is written or a byte is packed.
///
/// # Errors
/// Returns an error if an `extra` entry is rejected — its `dest` must be an absolute UTF-8
/// path that **names a file** (a trailing `/` or a trailing `.` names the parent directory and
/// is refused), must carry no `..` component, and must be neither
/// [reserved](is_reserved_injection_path) nor a duplicate of another entry's normalized dest;
/// its `mode` must be permission bits only (`<= 0o7777`). An *interior* `.` component is
/// **accepted** and folded away by the packer's own normalizer (`/a/./b` == `/a/b`, and
/// therefore the same duplicate), matching [`ExtraFile`]'s contract. Also returns an error if
/// the erofs packing or file injection fails.
#[cfg(feature = "am-fs-erofs")]
pub async fn pack_erofs_with_injection(
    tar_streams: Vec<Box<dyn Read + Send>>,
    inputs: &StageInputs,
    out: &Path,
    agent_musl: Option<&Path>,
    extra: &[ExtraFile],
) -> Result<StageOutputs> {
    let out_buf = out.to_path_buf();

    // Validate the caller-supplied extras before any side effect (the CA write below is one):
    // the injection tail is the validation boundary, since an `ExtraFile` never passes through
    // `VmConfig` (design §4.2, invariant F5).
    let extra_validated = validate_extra_files(extra)?;

    // The injected agent. A user-supplied static-musl binary (`--agent-musl`, oci2erofs §4.2, Rootfs sources and the one packer)
    // overrides the pipeline's default glibc agent artifact; otherwise a missing default agent
    // is a hard error, never a boot from a world-writable, attacker-plantable `/tmp` path.
    let agent_path = match agent_musl {
        Some(p) => p.to_path_buf(),
        None => inputs
            .artifacts
            .get("guest_agent")
            .cloned()
            .ok_or_else(|| Error::Artifact("missing guest_agent upstream input".into()))?,
    };
    // The default (glibc) agent needs libc6 in the base; the static-musl agent does not.
    let require_libc6 = agent_musl.is_none();

    // Generate the proxy CA and actually WRITE it to the path we inject from. Without this
    // the injected `ca.pem` never exists and the erofs pack aborts (or, by dir coincidence,
    // bakes in a stale CA from a different directory).
    #[cfg(feature = "proxy")]
    let ca_path = {
        let ca_mgr = crate::proxy::tls::CaManager::new()?;
        let path = out.parent().unwrap_or(Path::new(".")).join("ca.pem");
        std::fs::write(&path, ca_mgr.ca_cert_pem()).map_err(Error::Io)?;
        path
    };

    // The guest test-helper (ip/curl/kvm-ok) is baked into the rootfs rather than
    // mounted as a virtio-fs share: virtiofsd cannot enter its sandbox
    // unprivileged, so a share fails in the unprivileged suite, whereas the erofs
    // rootfs is served over virtio-blk in both modes. Optional — builds that do
    // not run the GuestToolsStage simply omit it.
    let tools_path = inputs.artifacts.get("guest_tools").cloned();

    tokio::task::spawn_blocking(move || -> Result<StageOutputs> {
        // The CA is baked only under the `proxy` feature (it produced `ca_path` above).
        #[cfg(feature = "proxy")]
        let ca_opt: Option<&Path> = Some(ca_path.as_path());
        #[cfg(not(feature = "proxy"))]
        let ca_opt: Option<&Path> = None;
        let (injected_files, injected_symlinks) =
            rootfs_injection_manifest(agent_path.as_path(), ca_opt, tools_path.as_deref());
        // Explicit `Some(mode)`: extra files never inherit the `injected_file_mode` heuristic.
        let extra_files: Vec<InjectFile<'_>> = extra_validated
            .iter()
            .map(|(dest, src, mode)| (dest.as_str(), src.as_path(), Some(*mode)))
            .collect();

        let archives: Vec<tar::Archive<Box<dyn Read + Send>>> =
            tar_streams.into_iter().map(tar::Archive::new).collect();
        let image = crate::artifact::tar2erofs::tar_to_erofs(
            archives,
            extra_files,
            injected_files,
            injected_symlinks,
            require_libc6,
        )?;
        std::fs::write(&out_buf, image).map_err(|e| Error::Artifact(e.to_string()))?;
        let mut outputs = StageOutputs::default();
        outputs.artifacts.insert("rootfs".into(), out_buf);
        Ok(outputs)
    })
    .await
    .map_err(|e| Error::Artifact(e.to_string()))?
}

/// A `(dest_path, source_path, mode)` file injected into the rootfs after every layer is
/// merged. The dest widened from `&'static str` in v30 delta 6 so downstream [`ExtraFile`]
/// dests (owned `String`s) travel the same tail; `mode` is `None` for vmcell's own entries
/// (the `injected_file_mode` heuristic) and `Some(perm)` for an extra file. Aliased to the
/// packer's own type so there is one shape, not two.
#[cfg(feature = "am-fs-erofs")]
type InjectFile<'a> = crate::artifact::tar2erofs::InjectedFile<'a>;
/// A `(link_path, symlink_target)` injected into the rootfs.
#[cfg(feature = "am-fs-erofs")]
type InjectLink = (&'static str, &'static str);

/// The rootfs injection manifest: the single list of `(dest_path, source_path, mode)` files and
/// `(link, target)` symlinks baked into every rootfs. It is also what
/// [`is_reserved_injection_path`] derives the F5 reserved-dest list from, so a dest added here
/// becomes vmcell-owned in the same edit. Kept as ONE function so the SET of
/// injected paths is testable KVM-free — the rootfs is a warm-cache artifact (CI reuses the
/// image and never re-packs), so a dropped, mis-pathed, or wrong-moded injection is invisible
/// until a fresh pack. Two such regressions have shipped this way (guest-tools packed 0o644 when
/// it moved to `/vmcell-tools`; the `/etc/ssl/certs` trust store absent after the reqwest 0.13
/// bump), so the manifest is pinned by `rootfs_injection_manifest_pins_truststore_and_tools`.
///
/// `ca` is `Some` only when the `proxy` feature baked a deployment CA. When present it is
/// installed BOTH at the ca-certificates drop-in AND merged into the `/etc/ssl/certs` bundle the
/// rustls stack reads at client-build time (gt-curl-truststore): without the bundle, guest-tools
/// `curl` cannot even build a client, so plain-HTTP egress fails too. `tools` is `Some` when the
/// GuestToolsStage produced the `ip`/`curl`/`kvm-ok`/`echo-server` multicall; it lands under
/// `/vmcell-tools` (executable via `injected_file_mode`) with the four names symlinked to it.
#[cfg(feature = "am-fs-erofs")]
fn rootfs_injection_manifest<'a>(
    agent: &'a Path,
    ca: Option<&'a Path>,
    tools: Option<&'a Path>,
) -> (Vec<InjectFile<'a>>, Vec<InjectLink>) {
    // `None` mode: vmcell's own entries keep the `injected_file_mode` bin/sbin heuristic.
    let mut files: Vec<InjectFile<'a>> = vec![("usr/sbin/vmcell-guest-agent", agent, None)];
    if let Some(ca) = ca {
        files.push(("usr/local/share/ca-certificates/vmcell-ca.crt", ca, None));
        files.push(("etc/ssl/certs/ca-certificates.crt", ca, None));
    }
    let mut symlinks: Vec<InjectLink> = Vec::new();
    if let Some(tools) = tools {
        files.push(("vmcell-tools/vmcell-guest-tools", tools, None));
        // busybox-style multicall links resolved on the exec PATH (the guest agent prepends
        // /vmcell-tools).
        symlinks.push(("vmcell-tools/ip", "vmcell-guest-tools"));
        symlinks.push(("vmcell-tools/curl", "vmcell-guest-tools"));
        symlinks.push(("vmcell-tools/kvm-ok", "vmcell-guest-tools"));
        // The raw-vsock-dial / segment listener (§3.2, §6.5). Also the one applet
        // used as a custom `init=` target, which resolves this absolute path before
        // any agent exists — so the symlink, not just the multicall binary, is what
        // that boot depends on.
        symlinks.push(("vmcell-tools/echo-server", "vmcell-guest-tools"));
    }
    (files, symlinks)
}

/// Shared logic to take a tar stream, inject the agent and CA, and pack it into erofs.
#[cfg(not(feature = "am-fs-erofs"))]
pub async fn pack_erofs_with_injection(
    _tar_streams: Vec<Box<dyn Read + Send>>,
    _inputs: &StageInputs,
    _out: &Path,
    _agent_musl: Option<&Path>,
    _extra: &[ExtraFile],
) -> Result<StageOutputs> {
    // mkfs.erofs fallback requires extracting the tar to a directory, adding the files,
    // and running mkfs.erofs. We assume am-fs-erofs is used for now.
    Err(Error::Artifact(
        "am-fs-erofs feature is required for rootfs building".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn stage() -> RootfsStage {
        RootfsStage {
            image_override: None,
            agent_musl: None,
            extra: Vec::new(),
        }
    }

    fn stage_with(extra: Vec<ExtraFile>) -> RootfsStage {
        RootfsStage {
            image_override: None,
            agent_musl: None,
            extra,
        }
    }

    fn write_tmp(dir: &std::path::Path, name: &str, content: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, content).expect("write");
        p
    }

    // Guards ARTIFACT-PIPELINE-1 for the CONSUMED-artifact fold: the two artifacts this OCI
    // stage consumes (`guest_agent`, `guest_tools`) must fold order-independently over their
    // content. Inserted in opposite orders, the content-addressed key must be identical.
    #[test]
    fn test_rootfs_cache_key_order_independent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let agent = write_tmp(dir.path(), "guest_agent", b"agent-bytes");
        let tools = write_tmp(dir.path(), "guest_tools", b"tools-bytes");
        let mut a = StageInputs::default();
        a.artifacts.insert("guest_agent".to_string(), agent.clone());
        a.artifacts.insert("guest_tools".to_string(), tools.clone());
        let mut b = StageInputs::default();
        b.artifacts.insert("guest_tools".to_string(), tools);
        b.artifacts.insert("guest_agent".to_string(), agent);
        assert_eq!(stage().cache_key(&a), stage().cache_key(&b));
    }

    // Pins the rootfs injection MANIFEST — the set, paths, and roles of injected files — KVM-free.
    // The rootfs is a warm-cache artifact, so a dropped or mis-pathed injection is invisible until a
    // fresh pack; both shipped regressions were exactly that (guest-tools packed non-executable when
    // it moved to /vmcell-tools; the /etc/ssl/certs trust store absent after the reqwest 0.13 bump).
    // Red-on-inverse: dropping the `etc/ssl/certs` push fails the trust-store assert; dropping the
    // tools push fails the multicall asserts.
    #[cfg(feature = "am-fs-erofs")]
    #[test]
    fn rootfs_injection_manifest_pins_truststore_and_tools() {
        let agent = Path::new("/agent");
        let ca = Path::new("/ca.pem");
        let tools = Path::new("/tools");
        let (files, symlinks) = rootfs_injection_manifest(agent, Some(ca), Some(tools));
        let dests: Vec<&str> = files.iter().map(|(d, _, _)| *d).collect();
        // vmcell's own entries keep the `injected_file_mode` heuristic: only a downstream
        // `ExtraFile` states its mode explicitly (§4.2). A `Some(...)` here would mean the
        // manifest started hardcoding modes behind the pinned heuristic's back.
        assert!(
            files.iter().all(|(_, _, mode)| mode.is_none()),
            "manifest entries take the injected_file_mode heuristic, not an explicit mode"
        );

        // The guest-agent (PID 1) is always injected.
        assert!(dests.contains(&"usr/sbin/vmcell-guest-agent"));
        // With a CA: BOTH the drop-in AND the /etc/ssl/certs bundle the rustls stack reads at
        // client-build time. Missing the bundle => guest-tools curl can't build a client, so even
        // plain-HTTP egress fails (gt-curl-truststore).
        assert!(
            dests.contains(&"etc/ssl/certs/ca-certificates.crt"),
            "the CA must be merged into the /etc/ssl/certs trust-store bundle"
        );
        assert!(dests.contains(&"usr/local/share/ca-certificates/vmcell-ca.crt"));
        // The guest-tools multicall + its four exec-PATH names (`echo-server` is the
        // §3.2 raw-dial / §6.5 segment listener; a live dial gate fails with a
        // missing /vmcell-tools/echo-server if the symlink is dropped here).
        assert!(dests.contains(&"vmcell-tools/vmcell-guest-tools"));
        for name in ["ip", "curl", "kvm-ok", "echo-server"] {
            let link = format!("vmcell-tools/{name}");
            assert!(
                symlinks
                    .iter()
                    .any(|(l, t)| *l == link && *t == "vmcell-guest-tools"),
                "missing multicall symlink {link}"
            );
        }

        // No CA (the non-proxy build) => no trust-store bundle injected.
        let (files_np, _) = rootfs_injection_manifest(agent, None, Some(tools));
        assert!(
            !files_np
                .iter()
                .any(|(d, _, _)| *d == "etc/ssl/certs/ca-certificates.crt"),
            "no CA => no trust-store bundle"
        );
    }

    // F5's twin of the manifest pin: every dest vmcell injects — in BOTH the absolute form a
    // downstream caller writes and the relative form the manifest carries — must be reserved,
    // plus the whole `/vmcell-tools` directory (so a multicall name the manifest has not grown
    // yet is covered). RED on the inverse: a raw-string comparison misses the absolute and the
    // `.`/`//` evasion shapes; dropping the prefix rule misses `/vmcell-tools/anything`.
    #[cfg(feature = "am-fs-erofs")]
    #[test]
    fn is_reserved_injection_path_covers_every_vmcell_dest() {
        let probe = Path::new("/dev/null");
        let (files, symlinks) = rootfs_injection_manifest(probe, Some(probe), Some(probe));
        for dest in files
            .iter()
            .map(|(d, _, _)| *d)
            .chain(symlinks.iter().map(|(l, _)| *l))
        {
            assert!(
                is_reserved_injection_path(dest),
                "manifest dest {dest} must be reserved"
            );
            assert!(
                is_reserved_injection_path(&format!("/{dest}")),
                "the absolute form /{dest} must be reserved too"
            );
        }
        // Normalization-before-comparison: each of these names the guest agent.
        for evasion in [
            "/usr/sbin/./vmcell-guest-agent",
            "//usr/sbin/vmcell-guest-agent",
            "/usr/sbin//vmcell-guest-agent",
        ] {
            assert!(
                is_reserved_injection_path(evasion),
                "{evasion} normalizes onto a vmcell-owned dest and must be reserved"
            );
        }
        // The whole guest-tools dir, including names not yet in the manifest.
        assert!(is_reserved_injection_path("/vmcell-tools"));
        assert!(is_reserved_injection_path("/vmcell-tools/not-yet-a-name"));
        // Ordinary downstream destinations are NOT reserved (the positive control: without
        // it, an always-true predicate would pass every assertion above).
        for allowed in [
            "/usr/local/bin/acme-daemon",
            "/opt/acme/config.toml",
            "/etc/acme.conf",
            "/usr/sbin/other-daemon",
        ] {
            assert!(
                !is_reserved_injection_path(allowed),
                "{allowed} is a legitimate downstream dest and must not be reserved"
            );
        }
    }

    // F5's rejection battery at the one validation boundary (the pack tail). Each arm is a
    // silent-corruption class: a reserved dest would be overwritten by vmcell's own injection,
    // a duplicate dest would be silent last-writer-wins, a relative/`..` dest would land
    // somewhere other than where it reads, and a full `st_mode` narrowed with `as u16` would
    // pack the wrong permission set. RED on the inverse (no checks): every arm returns Ok.
    #[cfg(feature = "am-fs-erofs")]
    #[test]
    fn validate_extra_files_rejects_the_silent_corruption_classes() {
        let ok = |dest: &str, mode: u32| vec![ExtraFile::new(dest, "/src", mode)];
        // The positive control first: a legitimate spec validates.
        let good = validate_extra_files(&ok("/usr/local/bin/acme", 0o755)).expect("valid spec");
        assert_eq!(
            good,
            vec![(
                "/usr/local/bin/acme".to_string(),
                PathBuf::from("/src"),
                0o755u16
            )]
        );
        // The second positive control, pinning the accepted-input rule both rustdocs state: an
        // INTERIOR `.` component is folded away by the packer's normalizer, never rejected —
        // and the dest travels to the packer verbatim (the packer normalizes it again).
        // Without this the directory-naming arms below could be "fixed" by rejecting every
        // `.`, which would contradict the contract-surface rustdoc.
        assert_eq!(
            validate_extra_files(&ok("/usr/local/./bin/acme", 0o755)).expect("interior `.` is ok"),
            vec![(
                "/usr/local/./bin/acme".to_string(),
                PathBuf::from("/src"),
                0o755u16
            )]
        );

        for (label, spec) in [
            (
                "reserved: the guest agent",
                ok("/usr/sbin/vmcell-guest-agent", 0o755),
            ),
            (
                "reserved: the CA drop-in",
                ok("/usr/local/share/ca-certificates/vmcell-ca.crt", 0o644),
            ),
            (
                "reserved: the trust-store bundle",
                ok("/etc/ssl/certs/ca-certificates.crt", 0o644),
            ),
            (
                "reserved: a guest-tools name",
                ok("/vmcell-tools/curl", 0o755),
            ),
            (
                "reserved: an unlisted guest-tools name",
                ok("/vmcell-tools/future", 0o755),
            ),
            (
                "reserved: a `.`-bearing evasion",
                ok("/usr/sbin/./vmcell-guest-agent", 0o755),
            ),
            ("relative dest", ok("usr/local/bin/acme", 0o755)),
            ("trailing slash", ok("/usr/local/bin/", 0o755)),
            // The names-a-directory family a raw `dest.ends_with('/')` guard lets through.
            // `/opt/.` normalizes to `opt`, so the packer would have replaced Debian's EMPTY
            // `/opt` (or `/srv`, `/mnt`, `/media`) directory node with a regular file — the
            // empty case clears the "child under a non-directory parent" check, so it was
            // silent. RED on the inverse: reinstate `dest.len() > 1 && dest.ends_with('/')`
            // in place of the normalized-leaf comparison and these four arms return Ok.
            ("trailing `.` on a top-level dir", ok("/opt/.", 0o755)),
            (
                "trailing `.` on a nested dir",
                ok("/usr/local/bin/.", 0o755),
            ),
            ("trailing `./`", ok("/opt/./", 0o755)),
            ("the bare root dir via `.`", ok("/.", 0o755)),
            ("`..` component", ok("/usr/local/../sbin/acme", 0o755)),
            ("no file named", ok("/", 0o755)),
            ("empty dest", ok("", 0o755)),
            (
                "full st_mode instead of permission bits",
                ok("/usr/local/bin/acme", 0o100_755),
            ),
            (
                "duplicate dest",
                vec![
                    ExtraFile::new("/usr/local/bin/acme", "/a", 0o755),
                    ExtraFile::new("/usr/local/bin/acme", "/b", 0o644),
                ],
            ),
            (
                "duplicate dest via a `.` component",
                vec![
                    ExtraFile::new("/usr/local/bin/acme", "/a", 0o755),
                    ExtraFile::new("/usr/local/./bin/acme", "/b", 0o644),
                ],
            ),
        ] {
            let res = validate_extra_files(&spec);
            assert!(
                matches!(res, Err(Error::Artifact(_))),
                "{label} must be a hard Error::Artifact, got {res:?}"
            );
        }
    }

    // Quality-gates v4 row 6: the OCI stage's cache-key version must carry the v30 delta-6
    // bump. `fold_rootfs_injection_identity` grew the extra-file triples, so an un-bumped
    // version serves the previously-packed rootfs — which has no injected extra files — from
    // the warm cache while every KVM-free test stays green (the recorded v20 precedent).
    // RED on the inverse: reverting the const to 3.
    #[test]
    fn rootfs_stage_version_pins_the_delta6_bump() {
        assert_eq!(
            OCI_ROOTFS_STAGE_VERSION, 4,
            "the v30 delta-6 identity-fold change requires this stage-version bump; \
             without it a stale rootfs (no extra files) is served from the warm cache"
        );
    }

    // Cache-key rule 3 for the extra files: CONTENT travels, the `src` path does not.
    // (a) rebuilding an extra file in place must re-pack; (b) the same bytes reached by a
    // different host path must NOT; (c) the caller's Vec order is not identity (sorted fold);
    // (d) a mode change alone must re-pack. Each arm reddens a specific buggy fold: (a)/(b) a
    // path-string fold, (c) an unsorted fold, (d) a fold that omits the mode.
    #[test]
    fn test_rootfs_key_tracks_extra_file_content_mode_and_not_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = write_tmp(dir.path(), "acme", b"acme-v1");
        let b = write_tmp(dir.path(), "other", b"other-v1");
        let inputs = StageInputs::default();

        let one = vec![ExtraFile::new("/usr/local/bin/acme", &a, 0o755)];
        let k_base = stage_with(one.clone()).cache_key(&inputs);

        // No extras at all must differ from one extra (the fold is reached).
        assert_ne!(
            k_base,
            stage().cache_key(&inputs),
            "an injected extra file must change the rootfs key"
        );

        // (a) rebuilt CONTENT at the SAME path invalidates.
        std::fs::write(&a, b"acme-v2-rebuilt-at-same-path").expect("write");
        let k_rebuilt = stage_with(one.clone()).cache_key(&inputs);
        assert_ne!(
            k_base, k_rebuilt,
            "a rebuilt extra file at the same src path must invalidate the rootfs key"
        );

        // (b) the SAME content at a DIFFERENT src path does not.
        let moved = write_tmp(dir.path(), "acme-moved", b"acme-v2-rebuilt-at-same-path");
        let k_moved = stage_with(vec![ExtraFile::new("/usr/local/bin/acme", &moved, 0o755)])
            .cache_key(&inputs);
        assert_eq!(
            k_rebuilt, k_moved,
            "the src PATH must not be identity — only its content (cache-key rule 3)"
        );

        // (c) the caller's Vec order is not identity.
        let fwd = vec![
            ExtraFile::new("/usr/local/bin/acme", &a, 0o755),
            ExtraFile::new("/etc/acme.conf", &b, 0o644),
        ];
        let rev: Vec<ExtraFile> = fwd.iter().rev().cloned().collect();
        assert_eq!(
            stage_with(fwd).cache_key(&inputs),
            stage_with(rev).cache_key(&inputs),
            "the extra-file fold is sorted by dest, so Vec order must not change the key"
        );

        // (d) a mode change alone invalidates.
        let k_mode =
            stage_with(vec![ExtraFile::new("/usr/local/bin/acme", &a, 0o644)]).cache_key(&inputs);
        assert_ne!(
            k_rebuilt, k_mode,
            "changing only the mode must invalidate the rootfs key (the packed perms differ)"
        );

        // A different DEST for the same content also invalidates.
        let k_dest =
            stage_with(vec![ExtraFile::new("/usr/local/bin/acme2", &a, 0o755)]).cache_key(&inputs);
        assert_ne!(k_rebuilt, k_dest, "the dest is part of the identity");
    }

    // ART-9: the OCI rootfs does NOT consume the kernel (it boots no VM), so a kernel
    // rebuild must NOT invalidate the OCI rootfs key. Folding *all* upstream artifacts (the
    // bug) reddens the assertion. (The in-VM `mmdebstrap` source, which consumes the seed
    // kernel, folds it in its own key in `vmcell-rootfs-builder`.)
    #[test]
    fn test_rootfs_oci_key_ignores_kernel() {
        let dir = tempfile::tempdir().expect("tempdir");
        let kernel = write_tmp(dir.path(), "vmlinux", b"kernel-v1");
        let mut inputs = StageInputs::default();
        inputs
            .artifacts
            .insert("kernel".to_string(), kernel.clone());

        let oci = stage();
        let oci_k1 = oci.cache_key(&inputs);
        std::fs::write(&kernel, b"kernel-v2-rebuilt").expect("write");
        let oci_k2 = oci.cache_key(&inputs);
        assert_eq!(
            oci_k1, oci_k2,
            "a kernel rebuild must NOT invalidate the OCI rootfs key (kernel not consumed)"
        );
    }

    // Guards ARTIFACT-PIPELINE-2: hashing the path STRING (not content) leaves the key
    // unchanged when a rebuilt upstream artifact lands at the same path.
    #[test]
    fn test_rootfs_cache_key_tracks_upstream_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = write_tmp(dir.path(), "guest_agent", b"agent-v1");
        let mut inputs = StageInputs::default();
        inputs
            .artifacts
            .insert("guest_agent".to_string(), p.clone());
        let k1 = stage().cache_key(&inputs);
        std::fs::write(&p, b"agent-v2-rebuilt-at-same-path").expect("write");
        let k2 = stage().cache_key(&inputs);
        assert_ne!(
            k1, k2,
            "rebuilt upstream content must change the rootfs key"
        );
    }

    // Guards ARTIFACT-PIPELINE-2: the rootfs key omitting `guest_agent_src_hash` lets a
    // stale agent stay baked in; folding it in makes the key sensitive to it.
    #[test]
    fn test_rootfs_cache_key_tracks_guest_agent_src_hash() {
        let mut a = StageInputs::default();
        a.pins
            .insert("guest_agent_src_hash".to_string(), "hash-aaa".to_string());
        let mut b = StageInputs::default();
        b.pins
            .insert("guest_agent_src_hash".to_string(), "hash-bbb".to_string());
        assert_ne!(stage().cache_key(&a), stage().cache_key(&b));
    }

    // H-ART-1: the injected static-musl agent must be folded by CONTENT, not by its path
    // string. When `agent_musl` is set the GuestAgentStage is skipped, so the agent has no
    // other content identity in the key — rebuilding it at the SAME path must invalidate the
    // rootfs. The buggy path-string fold leaves k1 == k2 (same path) -> red here.
    #[test]
    fn test_rootfs_agent_musl_key_tracks_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let agent = write_tmp(dir.path(), "agent-musl", b"musl-v1");
        let s = RootfsStage {
            image_override: None,
            agent_musl: Some(agent.clone()),
            extra: Vec::new(),
        };
        let inputs = StageInputs::default();
        let k1 = s.cache_key(&inputs);
        // Rebuild the musl agent in place at the SAME path.
        std::fs::write(&agent, b"musl-v2-rebuilt-at-same-path").expect("write");
        let k2 = s.cache_key(&inputs);
        assert_ne!(
            k1, k2,
            "a rebuilt agent-musl at the same path must invalidate the rootfs key (H-ART-1)"
        );
    }

    // Guards M-PIPE-2 (moved from the mmdebstrap module with `resolve_builder_base`): image
    // and digest must resolve as ONE atomic pair, never an independent fallback that pairs a
    // pinned image with a hardcoded digest. Each branch is red on the buggy per-half-default
    // impl. The in-VM builder crates rely on this shared resolver.
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

    // Guards ARTIFACT-PIPELINE-3: a missing guest_agent input must be a hard error, never a
    // silent boot from a world-writable `/tmp/guest_agent`.
    #[cfg(feature = "am-fs-erofs")]
    #[tokio::test]
    async fn test_pack_erofs_missing_agent_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("rootfs.erofs");
        let inputs = StageInputs::default();
        let res = pack_erofs_with_injection(vec![], &inputs, &out, None, &[]).await;
        assert!(
            matches!(res, Err(Error::Artifact(_))),
            "missing guest_agent must be a hard error, got {res:?}"
        );
    }

    // The extras are validated BEFORE any side effect: this call has no `guest_agent` either,
    // yet the reserved-dest error is what surfaces — proving the check runs ahead of the CA
    // write and the pack. The buggy order (validate inside/after the blocking pack) reports the
    // missing-agent error instead, and would already have written the CA to disk.
    #[cfg(feature = "am-fs-erofs")]
    #[tokio::test]
    async fn test_pack_erofs_rejects_reserved_extra_dest_before_any_io() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("rootfs.erofs");
        let inputs = StageInputs::default();
        let extra = [ExtraFile::new(
            "/usr/sbin/vmcell-guest-agent",
            dir.path().join("evil"),
            0o755,
        )];
        let err = pack_erofs_with_injection(vec![], &inputs, &out, None, &extra)
            .await
            .expect_err("a reserved extra dest must be rejected");
        let Error::Artifact(msg) = &err else {
            panic!("expected Error::Artifact, got {err:?}");
        };
        assert!(
            msg.contains("vmcell-owned injection path"),
            "the reserved-dest check must run before the missing-agent check, got: {msg}"
        );
        assert!(
            !out.exists() && !dir.path().join("ca.pem").exists(),
            "nothing may be written before the extras are validated"
        );
    }
}
