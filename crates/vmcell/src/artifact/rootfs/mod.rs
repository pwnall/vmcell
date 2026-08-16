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

/// The **flattened pins key** a rootfs's `sub_key` resolves to: `rootfs_<sub_key>` for the default
/// rootfs, `rootfs_<label>_<sub_key>` for a labelled one (§10.5, the artifact registry).
///
/// The **one** composer for the rootfs→pin-key law, in both directions of the pins pipeline, exactly
/// as [`crate::artifact::kernel::kernel_pin_key`] is for kernels: the flattener EMITS through it and
/// every consumer READS through it, so producer and consumer cannot drift into a silent
/// `Missing rootfs_… pin`.
///
/// **The default label emits the un-suffixed key on purpose.** `rootfs.default` flattens to
/// `rootfs_image`/`rootfs_digest` — the exact keys every pre-v33 reader already uses, including
/// `resolve_builder_base`, which picks the image that builds *kernels*. Reshaping the namespace
/// therefore cannot silently repoint a consumer the reshape was never about, and §10.5's
/// "canonical artifacts stay byte-identical for a cell that names no label" holds by construction
/// rather than by promise.
///
/// The label keeps its dots (`rootfs_12.4_image`): only the on-disk FILENAME is sanitized
/// ([`rootfs_filename_suffix`]), because a pins key never becomes a path.
#[must_use]
pub fn rootfs_pin_key(label: Option<&str>, sub_key: &str) -> String {
    match label {
        Some(l) => format!("rootfs_{l}_{sub_key}"),
        None => format!("rootfs_{sub_key}"),
    }
}

/// The [`StageOutputs`]/[`StageInputs`] **artifact-map key** a rootfs producer registers its packed
/// image under: `"rootfs"` for the default, `"rootfs-<label>"` for a labelled one.
///
/// The **one** composer for the rootfs→artifact-key law, mirroring
/// [`crate::artifact::kernel::kernel_artifact_key`]. Sharing `"rootfs"` across labels would collapse
/// every labelled rootfs onto one entry and a multi-rootfs `Artifacts` map would lose all but one —
/// the M-PIPE-4 defect, one kind over.
///
/// The label keeps its dots, exactly like [`rootfs_pin_key`] — this key is a map key, never a path.
#[must_use]
pub fn rootfs_artifact_key(label: Option<&str>) -> String {
    match label {
        Some(l) => format!("rootfs-{l}"),
        None => "rootfs".to_string(),
    }
}

/// The on-disk filename **suffix** for a rootfs label (`""` for the default, `-<label>` with `.`
/// sanitized to `-` otherwise) — the **one** rootfs label-sanitization law (§10.5).
///
/// Sanitized for the same reason the kernel's is: the pipeline derives a stage's cache sidecar with
/// `Path::with_extension`, so a dotted label would collide same-prefix labels on one `.cache_key`.
/// The pins key and the cache-key *hash* keep the dotted label; only the filename is sanitized.
#[must_use]
pub fn rootfs_filename_suffix(label: Option<&str>) -> String {
    label
        .map(|l| format!("-{}", l.replace('.', "-")))
        .unwrap_or_default()
}

/// The on-disk artifact filename **stem** of a packed rootfs: `rootfs` for the default,
/// `rootfs-<sanitized-label>` for a labelled one — the name without a format extension.
///
/// The stem, not the filename, is what a rootfs's sidecars are named after:
/// `Stage::cache_sidecar_path` and [`crate::feature::feature_manifest_path`] both derive theirs
/// with `Path::with_extension`, so `rootfs-a.erofs` and `rootfs-a.ext4` share one
/// `rootfs-a.cache_key` and one `rootfs-a.features`. That makes the stem the registry's
/// collision key (§18 delta 8), and [`rootfs_filename`] the one place a format extension is
/// appended to it.
#[must_use]
pub fn rootfs_artifact_stem(label: Option<&str>) -> String {
    format!("rootfs{}", rootfs_filename_suffix(label))
}

/// The on-disk artifact **filename** of a packed rootfs: `rootfs.erofs` for the default,
/// `rootfs-<sanitized-label>.ext4` for a labelled ext4 one (§18 delta 8).
///
/// The one composer every producer and every consumer of the artifacts dir uses. `format` is a
/// **required** parameter rather than a defaulted one: three production sites name a rootfs file
/// (the image stage's `out_path`, the declaration stage's `out_path`, and the registry's collision
/// key), all three must agree with the entry that declares the format, and a call site that could
/// omit it is a call site that silently writes `rootfs-<label>.erofs` over an ext4 artifact's key.
#[must_use]
pub fn rootfs_filename(label: Option<&str>, format: RootfsFormat) -> String {
    format!("{}.{}", rootfs_artifact_stem(label), format.name())
}

/// The inverse of [`rootfs_filename`]: the on-disk label **and format** carried by a rootfs
/// artifact filename, or `None` when `name` is not a labelled rootfs image.
///
/// `vmcell bundle` walks the artifacts dir with this so the manifest covers every
/// `rootfs-<label>.erofs` **and** every `rootfs-<label>.ext4`, not just the default — the N-BIN-4
/// defect class, re-armed by the registry, disarmed here, and re-armed a second time by delta 8's
/// second format until this law learned it.
///
/// It returns the format alongside the label because a caller that needs one usually needs both
/// (the bundle walk names the artifact by key and its sidecar by path), and because two functions
/// reading the same string are two laws that drift: an inverse that only stripped a suffix and a
/// separate one that only read it would eventually disagree about which suffixes are rootfs images.
///
/// The bare `rootfs.erofs` returns `None`, and so does anything that is not a known format
/// extension: a `rootfs-debian.cache_key` sidecar must not read as an artifact named
/// `rootfs-debian`, which is exactly how `bundle` once recorded a kernel's cache sidecar as a
/// kernel. A remainder containing `.` also returns `None`, because [`rootfs_filename_suffix`]
/// sanitizes `.`→`-`, so no filename this law produces can carry one.
///
/// This is the *inverse* of the sanitization law and lives beside it: the two are pinned together
/// by a round-trip gate over **both** formats, so neither half can move alone and neither format
/// can be mistaken for the other's.
#[must_use]
pub fn rootfs_artifact_from_filename(name: &str) -> Option<(&str, RootfsFormat)> {
    // Every format's extension, from the ONE roster — so a format added to `RootfsFormat` cannot
    // leave this walk blind to its artifacts, which is the shape of the N-BIN-4 defect one kind
    // over.
    let (stem, format) = RootfsFormat::ALL.into_iter().find_map(|f| {
        name.strip_suffix(&format!(".{}", f.name()))
            .map(|stem| (stem, f))
    })?;
    match stem.strip_prefix("rootfs-") {
        Some(label) if !label.is_empty() && !label.contains('.') => Some((label, format)),
        _ => None,
    }
}

/// The per-artifact extended-attribute policy (§4.7) — §10.4 contract surface under this name.
///
/// Defined in [`crate::artifact`], which is compiled in **every** feature configuration, because
/// the policy is declared on a `rootfs` registry entry ([`crate::artifact::RootfsRegistryEntry`],
/// §18 delta 7) and that parser is ungated, while this module is gated on `pipeline` and the packer
/// on `am-fs-erofs`. Re-exported here because `rootfs` is where the §10.4 list puts it, beside
/// [`pack_erofs_with_injection`] and [`ExtraFile`], and because a consumer reads it off
/// [`PackOptions::xattrs`].
pub use crate::artifact::XattrPolicy;

/// Which filesystem an artifact's image is packed as (§4.7) — §10.4 contract surface under this
/// name.
///
/// Defined in [`crate::artifact`] for the same forced reason [`XattrPolicy`] is: the format is
/// declared on a `rootfs` registry entry ([`crate::artifact::RootfsRegistryEntry::format`], §18
/// delta 8) and that parser is ungated, while this module is gated on `pipeline`. Re-exported here
/// because `rootfs` is where the §10.4 list puts the artifact-shaping types, beside
/// [`pack_rootfs_with_injection`] and [`XattrPolicy`], and because a consumer reads it off
/// [`PackOptions::format`].
pub use crate::artifact::RootfsFormat;

/// What the one inject+pack tail is told, beyond the tar streams themselves (design §4.2/§10.5).
///
/// Grown by **field**, never by positional argument — the `HostEnv` idiom AGENTS.md prescribes for
/// a seam that keeps learning new facts. `pack_erofs_with_injection` is §10.4 contract surface, and
/// v33 alone hands it two new ones (delta 6's applet roster, delta 7's xattr policy); two more
/// parameters would be two more ledgered signature breaks, and the third one would be somebody
/// else's problem.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct PackOptions {
    /// Inject this prebuilt static-musl steward instead of the pipeline's default glibc one
    /// (`oci2erofs --steward-musl`). When set, the libc6-presence guard is skipped.
    pub steward_musl: Option<PathBuf>,
    /// Downstream files composed into the image at pack time (`--inject`, §4.2 FR-V4).
    pub extra: Vec<ExtraFile>,
    /// The handler applet roster to emit as `<tools_dir>/<applet>` symlinks.
    ///
    /// Empty means the DEFAULT handler's roster ([`vmcell_protocol::GUEST_TOOLS_APPLETS`]) — the
    /// const the guest binary's dispatch table is compile-time asserted against. A registered
    /// consumer handler supplies its own, strict-parsed from its registry entry (§10.5).
    pub applets: Vec<String>,
    /// The registry label whose image this pack produces — `None` is the default rootfs (§10.5).
    ///
    /// The tail registers its output under [`rootfs_artifact_key`] of this label, which is the only
    /// reason the tail is told about it: it packs the same way either way. It hardcoded `"rootfs"`
    /// instead until v33 delta 6c, so **every** labelled rootfs registered under the default key —
    /// the M-PIPE-4 collapse `rootfs_artifact_key`'s own rustdoc exists to forbid, live in the one
    /// path that produces vmcell's canonical image. Nothing caught it because a map-key mismatch is
    /// not a compile error and the default label's key is the same either way.
    pub label: Option<String>,
    /// What the packer does with the source layers' extended attributes (§4.7, §18 delta 7).
    ///
    /// A **field**, not a parameter of the tail, for the reason this struct exists at all. Default
    /// [`XattrPolicy::Strip`], which is the pre-v33 behavior byte-for-byte — so an existing caller
    /// that never mentions it packs the same image it always did.
    pub xattrs: XattrPolicy,
    /// Which filesystem the tail packs the merged tree into (§4.7, §18 delta 8).
    ///
    /// Default [`RootfsFormat::Erofs`], the pre-delta-8 behavior byte-for-byte. The merge, the
    /// injections, the `libc6` scan, the reserved-path law, the parent synthesis and the
    /// [`XattrPolicy`] above all run **before** this field is consulted, which is the whole point:
    /// §4.7's *"consuming the same merged-tar tail … inherited for free"* is true because there is
    /// still exactly one merge, and this field only chooses which emitter it is handed to.
    pub format: RootfsFormat,
}

impl PackOptions {
    /// The defaults: no musl steward, no downstream files, the default handler's applet roster.
    ///
    /// A constructor rather than a struct expression because this type is `#[non_exhaustive]` — the
    /// whole point of the struct is that it grows, and an out-of-crate builder (`vmcell-rootfs-
    /// builder`) must not have to be edited when it does.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Injects a prebuilt static-musl steward instead of the pipeline's default glibc one.
    #[must_use]
    pub fn with_steward_musl(mut self, steward_musl: Option<PathBuf>) -> Self {
        self.steward_musl = steward_musl;
        self
    }

    /// Composes downstream files into the image at pack time (§4.2 FR-V4).
    #[must_use]
    pub fn with_extra(mut self, extra: Vec<ExtraFile>) -> Self {
        self.extra = extra;
        self
    }

    /// Sets the handler applet roster (§10.5); empty means the default handler's.
    #[must_use]
    pub fn with_applets(mut self, applets: Vec<String>) -> Self {
        self.applets = applets;
        self
    }

    /// Sets the registry label the packed image is registered under (§10.5); `None` is the default.
    #[must_use]
    pub fn with_label(mut self, label: Option<&str>) -> Self {
        self.label = label.map(str::to_string);
        self
    }

    /// Sets the artifact's extended-attribute policy (§4.7); the default is
    /// [`XattrPolicy::Strip`].
    #[must_use]
    pub fn with_xattrs(mut self, xattrs: XattrPolicy) -> Self {
        self.xattrs = xattrs;
        self
    }

    /// Sets the filesystem the tail packs into (§4.7, §18 delta 8); the default is
    /// [`RootfsFormat::Erofs`].
    #[must_use]
    pub fn with_format(mut self, format: RootfsFormat) -> Self {
        self.format = format;
        self
    }

    /// The roster to inject: this options' own, or the default handler's.
    ///
    /// The one place the two rosters meet on the packer side, so no injection site has to know
    /// which kind of handler it is packing — and an *empty* roster can never reach the manifest,
    /// which would inject the binary with no symlinks and turn every custom-`init=` target into a
    /// guest kernel panic.
    #[must_use]
    #[cfg(feature = "am-fs-erofs")]
    pub fn applet_roster(&self) -> Vec<String> {
        if self.applets.is_empty() {
            default_applet_roster()
        } else {
            self.applets.clone()
        }
    }
}

/// The directory holding the guest-tools multicall binary and its exec-PATH symlinks. Reserved
/// as a whole so a name the manifest has not grown yet (delta 7's `echo-server` was one) is
/// covered the moment it is added.
const VMCELL_TOOLS_DIR: &str = "vmcell-tools";

/// The multicall binary's file name inside [`VMCELL_TOOLS_DIR`] — the target every applet
/// symlink the manifest emits points at.
const GUEST_TOOLS_MULTICALL_BIN: &str = "vmcell-guest-tools";

/// The DEFAULT handler's applet roster: [`vmcell_protocol::GUEST_TOOLS_APPLETS`], owned.
///
/// One place converts the shared const into the `Vec<String>` the manifest takes, so a caller that
/// wants "whatever vmcell ships" never re-spells the const and never accidentally passes an empty
/// roster (which would inject the binary with no symlinks — a rootfs whose custom-`init=` targets
/// all vanish, exit 2, guest kernel panic).
#[cfg(feature = "am-fs-erofs")]
fn default_applet_roster() -> Vec<String> {
    vmcell_protocol::GUEST_TOOLS_APPLETS
        .iter()
        .map(|a| (*a).to_string())
        .collect()
}

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
/// caller writes (`/usr/sbin/vmcell-steward`), a `.`-bearing evasion
/// (`/usr/sbin/./vmcell-steward`), and the manifest's relative form
/// (`usr/sbin/vmcell-steward`) all collapse to the same key. Comparing raw strings would
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
    // The DEFAULT roster here, deliberately: a consumer handler's applet names are not vmcell's to
    // reserve, and they do not need to be — the whole-directory prefix rule above already reserves
    // `<tools_dir>/<anything>`, including names no manifest has grown yet.
    let (files, symlinks) =
        rootfs_injection_manifest(probe, Some(probe), Some(probe), &default_applet_roster());
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
                 (the steward, the CA trust store, or /{VMCELL_TOOLS_DIR}); \
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

/// Fuzz-only entry point onto `validate_extra_files`, the F5 injection-dest law (non-default
/// `fuzzing` feature; see the feature's stanza in `Cargo.toml`).
///
/// [`is_reserved_injection_path`] is already public, but it is only *half* of the law — the escapes
/// this validator actually caught were normal-form ones (`/usr/sbin/./vmcell-steward`, whose
/// raw string is not a reserved path, and `/opt/.`, whose raw leaf normalizes away), plus the
/// duplicate-dest case. Fuzzing the public half alone would report coverage of the reserved-list
/// membership test while missing every shape that defeated it. Reads no file: an
/// [`ExtraFile`]'s `src` is opened by the packer, never by this validator, so the entry point stays
/// pure.
///
/// # Errors
/// Propagates `validate_extra_files`'s [`Error::Artifact`] rejection verbatim.
#[cfg(all(feature = "fuzzing", feature = "am-fs-erofs"))]
pub fn fuzz_validate_extra_files(extra: &[ExtraFile]) -> Result<Vec<(String, PathBuf, u16)>> {
    validate_extra_files(extra)
}

/// A pipeline stage that builds a root filesystem from an OCI base image (the in-`vmcell`
/// bootstrap source, §4.2, Rootfs sources and the one packer). The in-VM `mmdebstrap` source is `vmcell-rootfs-builder`.
///
/// `#[non_exhaustive]` as of v33 delta 6, for the reason `VmConfig` already carries it: this struct
/// grows a field every time the artifact layer learns a new property, and each of those was a
/// `constructible_struct_adds_*_field` break for as long as it stayed constructible. Build it
/// through [`RootfsStage::new`] / [`RootfsStage::labelled`] and the `with_*` setters.
#[non_exhaustive]
pub struct RootfsStage {
    /// Explicit `(image, digest)` override for the OCI source (v15 `oci2erofs`, §4.2, Rootfs sources and the one packer):
    /// `Some` ignores the pinned `rootfs_image`/`rootfs_digest` and pulls this digest-pinned
    /// base instead. `None` uses the pins (the default `vmcell build`).
    pub image_override: Option<(String, String)>,
    /// Static-musl steward to inject instead of the pipeline's default glibc steward
    /// (`oci2erofs --steward-musl`, §4.2, Rootfs sources and the one packer). When `Some`, the libc6-presence guard is skipped.
    pub steward_musl: Option<std::path::PathBuf>,
    /// Downstream files composed into the image at pack time (`oci2erofs --inject`, §4.2,
    /// FR-V4). Empty for the default `vmcell build`.
    pub extra: Vec<ExtraFile>,
    /// The handler applet roster injected as `<tools_dir>/<applet>` symlinks. Empty is the default
    /// handler's roster; a registered handler (§10.5) supplies its own.
    pub applets: Vec<String>,
    /// This artifact's extended-attribute policy (§4.7, v33 delta 7) — declared in its registry
    /// entry, folded into the cache key, and handed to the one pack tail. Default
    /// [`XattrPolicy::Strip`].
    pub xattrs: XattrPolicy,
    /// The filesystem this artifact is packed as (§4.7, v33 delta 8) — declared in its registry
    /// entry, folded into the cache key, handed to the one pack tail, **and** appended to this
    /// stage's `out_path`. Default [`RootfsFormat::Erofs`].
    pub format: RootfsFormat,
    /// The `rootfs` registry label this stage builds (§10.5, v33 delta 6) — `None` is
    /// `rootfs.default`, which resolves to today's inputs and today's filename.
    ///
    /// Private, with [`RootfsStage::labelled`] as the only way to set it, because [`Stage::name`]
    /// returns a `&str` and therefore has to read a *precomputed* name: a public `label` beside a
    /// public `stage_name` would let a caller set one without the other and get a stage whose
    /// identity disagrees with its output path.
    label: Option<String>,
    /// [`Stage::name`]'s return value, composed from `label` at construction.
    stage_name: String,
}

impl Default for RootfsStage {
    fn default() -> Self {
        Self::new()
    }
}

impl RootfsStage {
    /// The default rootfs stage: `rootfs.default`, `rootfs.erofs`, no injections.
    ///
    /// Byte-identical in every observable to the pre-v33 `RootfsStage { image_override: None,
    /// steward_musl: None, extra: vec![] }` struct literal.
    #[must_use]
    pub fn new() -> Self {
        Self::labelled(None)
    }

    /// A stage building the named registry label; `None` is the default rootfs.
    #[must_use]
    pub fn labelled(label: Option<&str>) -> Self {
        RootfsStage {
            image_override: None,
            steward_musl: None,
            extra: Vec::new(),
            applets: Vec::new(),
            xattrs: XattrPolicy::default(),
            format: RootfsFormat::default(),
            label: label.map(str::to_string),
            // The artifact key IS the stage name for this kind, so a labelled stage cannot collide
            // with the default one on the pipeline's cache sidecar — the §5.1 hazard recorded for
            // `InVmKernelStage` vs `PrebuiltKernelStage`, one kind over.
            stage_name: rootfs_artifact_key(label),
        }
    }

    /// Sets the explicit `(image, digest)` override (`oci2erofs`'s digest-pinned base).
    #[must_use]
    pub fn with_image_override(mut self, image: String, digest: String) -> Self {
        self.image_override = Some((image, digest));
        self
    }

    /// Sets the static-musl steward to inject instead of the pipeline's default.
    #[must_use]
    pub fn with_steward_musl(mut self, steward_musl: Option<std::path::PathBuf>) -> Self {
        self.steward_musl = steward_musl;
        self
    }

    /// Sets the downstream files composed into the image at pack time.
    #[must_use]
    pub fn with_extra(mut self, extra: Vec<ExtraFile>) -> Self {
        self.extra = extra;
        self
    }

    /// The registry label this stage builds, as the key composers take it.
    #[must_use]
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Sets the handler applet roster to inject (§10.5) — empty means the default handler's.
    #[must_use]
    pub fn with_applets(mut self, applets: Vec<String>) -> Self {
        self.applets = applets;
        self
    }

    /// Sets this artifact's extended-attribute policy (§4.7) — the `xattrs` key of its registry
    /// entry. The default is [`XattrPolicy::Strip`].
    #[must_use]
    pub fn with_xattrs(mut self, xattrs: XattrPolicy) -> Self {
        self.xattrs = xattrs;
        self
    }

    /// Sets this artifact's filesystem format (§4.7, §18 delta 8) — the `format` key of its
    /// registry entry. The default is [`RootfsFormat::Erofs`].
    ///
    /// It moves both this stage's `out_path` and its `cache_key`, deliberately: an ext4 artifact
    /// is a *different file* from the erofs one, not the same file packed differently, so the two
    /// never overwrite each other and never serve each other's cache entry.
    #[must_use]
    pub fn with_format(mut self, format: RootfsFormat) -> Self {
        self.format = format;
        self
    }

    /// The F7 dev path-override registered for this stage's label, if any (§10.5, §18 delta 6c).
    ///
    /// The **one** place this stage decides "is this label unpinned?", read by `cache_key` and by
    /// `run` so the identity and the build can never disagree about which shape they are serving —
    /// the two-readers drift that the `image`/`digest` pair above already pays for with a duplicated
    /// `match`.
    ///
    /// An explicit [`RootfsStage::with_image_override`] wins: `oci2erofs` names a digest-pinned base
    /// on the invocation itself, which is a stronger statement of intent than anything a registry
    /// entry carries, and the two are never both set by any shipped call site.
    fn unpinned_path(&self, inputs: &StageInputs) -> Option<std::path::PathBuf> {
        inputs
            .pins
            .get(&rootfs_pin_key(
                self.label(),
                crate::artifact::registry::UNPINNED_PATH_KEY,
            ))
            .map(std::path::PathBuf::from)
    }

    /// What this stage tells the one inject+pack tail.
    #[must_use]
    pub fn pack_options(&self) -> PackOptions {
        PackOptions {
            steward_musl: self.steward_musl.clone(),
            extra: self.extra.clone(),
            applets: self.applets.clone(),
            // The SAME policy `cache_key` folds, so the identity and the packed bytes can never
            // disagree about which attributes the image is supposed to carry.
            xattrs: self.xattrs,
            // The SAME format `out_path` names the file after and `cache_key` folds, so the
            // filename, the identity and the emitter the tail picks are one declaration.
            format: self.format,
            // The SAME label the stage's name, out_path and pin keys are composed from, so the key
            // the tail registers under and the key `RootfsStage::publish_unpinned` registers under
            // are one law rather than two that agree only for the default label.
            label: self.label.clone(),
        }
    }
}

/// The OCI rootfs stage's cache-key version. Bump when this stage's build logic or its folded
/// identity changes so stale outputs are not served — the rootfs is a warm-cache artifact, and
/// an identity-fold change without the bump serves a stale image while every test stays green.
///
/// v15: bumped to 2 with the oci2erofs image-override + steward-musl inputs.
/// v20: bumped to 3 — the shared injected-content fold (steward-musl + CA + steward source)
/// moved into [`fold_rootfs_injection_identity`] (called first), which reorders the hashed byte
/// stream. A one-time OCI-rootfs rebuild is harmless.
/// v30 (§18 delta 6): bumped to 4 — the fold gained the sorted downstream extra-file triples.
/// v33 (§18 delta 6c): bumped to 5 — the fold gained the F7 `unpinned_path` dev-override arm
/// (registration path + the pointed-at file's content hash). The arm is *conditional*, so no
/// artifacts dir in existence can hold a key this change would silently re-serve — the bump is the
/// project's identity-fold discipline applied anyway, and one OCI-rootfs re-pack is harmless.
/// v33 (§18 delta 7): bumped to 6 — [`fold_rootfs_injection_identity`] gained the [`XattrPolicy`]
/// **and** the applet roster (the delta-6b gap: the roster decides which `<tools_dir>/<applet>`
/// symlinks are baked, and it had never been folded at all, so two registered handlers over one
/// multicall binary shared a key and shipped different images). One bump covers both, because both
/// landed before this version was ever released. This one is NOT conditional: the policy folds on
/// every key, including `Strip`'s, so every existing key moves and every rootfs re-packs once. That
/// is the point — an artifacts dir that already holds a `Strip`-packed image must not serve it
/// under a key that now means "whatever this artifact's declaration says", and a *policy* change
/// with an unmoved key would serve an image whose attributes contradict its own manifest.
/// v33 (§18 delta 8): bumped to 7 — [`fold_rootfs_injection_identity`] gained the
/// [`RootfsFormat`]. Like the policy, it folds on every key including the default `Erofs`'s. The
/// format also moves the artifact's *filename*, so an unmoved key could not actually serve the
/// wrong bytes here — the bump is the identity-fold discipline applied anyway, and one re-pack is
/// harmless.
///
/// Module-level (rather than a `fn`-local `const`) so the bump itself is assertable KVM-free:
/// `rootfs_stage_version_pins_the_identity_fold_bumps`.
const OCI_ROOTFS_STAGE_VERSION: u32 = 7;

#[async_trait]
impl Stage for RootfsStage {
    fn name(&self) -> &str {
        &self.stage_name
    }

    fn out_path(&self, target_dir: &std::path::Path) -> std::path::PathBuf {
        target_dir.join(rootfs_filename(self.label(), self.format))
    }

    fn cache_key(&self, inputs: &StageInputs) -> CacheKey {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&OCI_ROOTFS_STAGE_VERSION.to_le_bytes());
        // Fold the identity of everything the shared inject+pack tail bakes in (the optional
        // static-musl steward override, the deployment CA, the steward source closure, the
        // downstream extra files, the applet roster, the xattr policy) — ONE implementation,
        // shared with the out-of-crate in-VM rootfs builders (§4.3, The rootfs-construction
        // contract).
        //
        // Through `pack_options()` — the SAME struct `run` packs with — so what this key claims
        // and what the tail bakes cannot drift. Handing the fold individual fields is what let the
        // delta-6b applet roster go unfolded for a whole release.
        fold_rootfs_injection_identity(&mut hasher, inputs, &self.pack_options());
        hasher.update(b"oci");
        // oci2erofs: the CLI-provided digest-pinned base is an INPUT (not a pin) and
        // must be content-addressed directly; otherwise a stale erofs is reused for a
        // different IMAGE@DIGEST. Fall back to the pins for the default `vmcell build`.
        match (&self.image_override, self.unpinned_path(inputs)) {
            // The F7 dev override (§10.5, §18 delta 6c). A digest registration's identity is the
            // digest, and folding the string is enough because the string IS the promise. An
            // UNPINNED registration promises nothing — it means "whatever is at that location
            // today" — so its identity has to be READ FROM THE FILE, or editing the pointed-at
            // image would leave the artifacts dir serving yesterday's bytes under a key that
            // still says "this is mine". Path AND content, both: the path so two labels pointing
            // at different files are two artifacts even when the bytes momentarily agree, the
            // content hash so an in-place edit re-keys.
            (None, Some(path)) => {
                hasher.update(b"unpinned\0");
                hasher.update(path.as_os_str().as_encoded_bytes());
                hasher.update(b"\0");
                match crate::artifact::hash_file(&path) {
                    Ok(h) => hasher.update(h.as_bytes()),
                    // A read failure must NOT degrade to a stable, content-blind key that hits a
                    // stale cache (ART-11, the `GuestToolsStage` precedent). Fold a DISTINCT error
                    // marker so the key cannot collide with a good one; the resulting miss drives
                    // `run`, which fails hard naming the label and the path.
                    Err(e) => hasher.update(format!("unpinned-rootfs-read-error:{e}").as_bytes()),
                };
            }
            (image_override, _) => {
                let (image, digest) = match image_override {
                    Some((i, d)) => (i.as_str(), d.as_str()),
                    None => (
                        inputs
                            .pins
                            .get(&rootfs_pin_key(self.label(), "image"))
                            .map(String::as_str)
                            .unwrap_or_default(),
                        inputs
                            .pins
                            .get(&rootfs_pin_key(self.label(), "digest"))
                            .map(String::as_str)
                            .unwrap_or_default(),
                    ),
                };
                hasher.update(image.as_bytes());
                hasher.update(b"\0");
                hasher.update(digest.as_bytes());
            }
        }
        // Hash only the upstream artifacts this stage actually CONSUMES (ART-9), in a
        // deterministic key-sorted order over their on-disk content. Folding *every*
        // upstream artifact meant a `kernel` rebuild invalidated the OCI rootfs, which does
        // not depend on the kernel (the OCI source boots no VM). Scope the fold to the
        // injected `steward` + `guest_tools` binaries (the base image is a pin/override,
        // not an artifact). The in-VM `mmdebstrap` source, which additionally consumes the
        // seed `kernel`, lives in `vmcell-rootfs-builder` and folds it in its own key.
        let consumed: &[&str] = &["steward", "guest_tools"];
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
        // The F7 dev override (§10.5, §18 delta 6c): the label's image IS the registered file, so
        // this stage publishes it instead of packing one. Honoring it here is not decoration — an
        // accepted input that changes no behavior is the accept-then-ignore class the whole pins
        // schema is strict about, and an `unpinned_path` that parsed but built the OCI base anyway
        // would be exactly that, with a `warn!` claiming otherwise.
        if self.image_override.is_none()
            && let Some(path) = self.unpinned_path(inputs)
        {
            return self.publish_unpinned(&path, out).await;
        }
        // oci2erofs (§4.2, Rootfs sources and the one packer): the CLI override pulls an explicit digest-pinned base;
        // the default `vmcell build` resolves the pinned Debian image from the pins.
        let (image, digest) = match &self.image_override {
            Some((i, d)) => (i.clone(), d.clone()),
            None => {
                let (image_key, digest_key) = (
                    rootfs_pin_key(self.label(), "image"),
                    rootfs_pin_key(self.label(), "digest"),
                );
                let missing = |key: &str| {
                    Error::Artifact(format!(
                        "Missing {key} pin: the `rootfs` registry (§10.5) resolved no `{}` entry                          with that key — register it in a pins overlay, or drop the label to                          build the default rootfs",
                        self.label()
                            .unwrap_or(crate::artifact::registry::DEFAULT_LABEL),
                    ))
                };
                let image = inputs
                    .pins
                    .get(&image_key)
                    .ok_or_else(|| missing(&image_key))?;
                let digest = inputs
                    .pins
                    .get(&digest_key)
                    .ok_or_else(|| missing(&digest_key))?;
                (image.clone(), digest.clone())
            }
        };
        oci::build_rootfs(&image, &digest, inputs, out, &self.pack_options()).await
    }
}

impl RootfsStage {
    /// Publishes an F7 dev path-override's file as this label's image (§10.5, §18 delta 6c).
    ///
    /// The registered file is the *finished* image, not a base to pack from — that is what "a
    /// development registration with a path" means for a kind whose artifact is a single packed
    /// file, and it is the only reading under which the operator gets what they pointed at. Nothing
    /// is injected into it: the steward, the tools and the CA are baked by the packer, and this
    /// shape has no packer, so an operator overriding the image owns its contents. The declaration
    /// sidecar beside it still travels ([`RootfsFeaturesStage`]), which is how an override that
    /// removes a capability can still say so.
    ///
    /// # Errors
    /// [`Error::Artifact`] naming the label AND the path when the file cannot be read — the two
    /// facts an operator needs, because an unpinned registration's whole failure mode is that the
    /// path stopped being true since the day it was written.
    async fn publish_unpinned(&self, path: &Path, out: &Path) -> Result<StageOutputs> {
        let label = self
            .label()
            .unwrap_or(crate::artifact::registry::DEFAULT_LABEL);
        if let Some(parent) = out.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(Error::Io)?;
        }
        // `copy`, not a symlink: the artifacts dir is a published tree that `bundle`, the cache's
        // content hash and every consumer read as bytes, and a dangling link would turn "the path
        // stopped being true" from this loud error into a mystery at boot.
        tokio::fs::copy(path, out).await.map_err(|e| {
            Error::Artifact(format!(
                "rootfs `{label}` is registered through the `{}` dev override at {}, which could \
                 not be read: {e}. An unpinned registration means \"whatever is at that path \
                 today\" (§10.5, F7) — point it at a readable image, or register a digest",
                crate::artifact::registry::UNPINNED_PATH_KEY,
                path.display()
            ))
        })?;
        let mut outputs = StageOutputs::default();
        outputs
            .artifacts
            .insert(rootfs_artifact_key(self.label()), out.to_path_buf());
        Ok(outputs)
    }
}

/// The [`StageOutputs`] artifact key of the §7.4 feature-declaration sidecar produced beside the
/// rootfs registered under `rootfs_key` (`"rootfs"` → `"rootfs-features"`, `"rootfs-<label>"` →
/// `"rootfs-<label>-features"`).
///
/// DERIVED from the payload's key rather than re-composed from the label, exactly as
/// [`crate::artifact::kernel::config_artifact_key`] is for the kernel's resolved-config sidecar:
/// registering the sidecar under its own key is what content-addresses it *with* the artifact it
/// describes, and deriving the name means the two keys cannot come to disagree about which label
/// they belong to.
#[must_use]
pub fn features_artifact_key(rootfs_key: &str) -> String {
    format!("{rootfs_key}-features")
}

/// The feature-declaration stage's cache-key version. Bump when this stage's emission logic or its
/// folded identity changes, so a stale sidecar is not served.
///
/// Module-level (rather than a `fn`-local `const`) for the same reason
/// [`OCI_ROOTFS_STAGE_VERSION`] is: the bump itself stays assertable KVM-free.
const ROOTFS_FEATURES_STAGE_VERSION: u32 = 1;

/// Emits the **feature-manifest sidecar** beside a packed rootfs — the travel form of the
/// `rootfs.<label>.features` declaration its registry entry carries (§7.4, §10.5; §18 delta 6c).
///
/// The registry entry is the one authority and this sidecar is how the declaration reaches a cell
/// that only ever sees the built artifact: [`crate::feature::FeatureDeclaration::load_beside`]
/// reads it at boot, and `resolve_cell_features` intersects it into the cell's feature set. Without
/// a producer the reader has nothing to read and every artifact reports the baseline — which is how
/// the canonical rootfs came to claim `xattr_preserved` while its packer stripped every xattr.
///
/// # Why this is its own stage rather than a sibling artifact of [`RootfsStage`]
///
/// §7.4's cache-identity split, verbatim: *"a build-affecting property (`xattrs`, §4.7) folds into
/// the **image** identity and re-packs; a declaration-only edit re-emits the **sidecar**
/// (content-addressed on its own) and leaves the image key unmoved — a declaration change must not
/// rebuild the image it describes."* Both simpler shapes get exactly one half of that right:
///
/// * folding `features` into [`RootfsStage::cache_key`] re-packs a multi-minute image because
///   somebody wrote down a fact *about* it, which is the half the design forbids by name;
/// * emitting from `RootfsStage::run` (the kernel's resolved-config shape) never re-emits at all,
///   because a declaration-only edit leaves the image key unmoved, a warm hit republishes the
///   recorded artifacts, and `run` is not called on a hit — so the edited declaration would sit in
///   `pins.json` and never reach the artifact.
///
/// A separately content-addressed stage is the only shape that gets both halves; the
/// `a_declaration_edit_moves_the_sidecar_key_and_not_the_image_key` gate is what pins it.
///
/// # Why it emits even when the declaration is empty
///
/// An empty declaration renders to the manifest's two comment lines and parses back to empty
/// stances, which is semantically **identical** to an absent sidecar (both are
/// [`crate::feature::FeatureDeclaration::baseline`]) — so unconditional emission changes nothing
/// for an undeclared label, and it removes the stale-sidecar hazard entirely. The conditional
/// alternative needs a remover for the "this label stopped declaring things" transition —
/// [`crate::artifact::kernel::clear_resolved_config`] is exactly that, and it exists because the
/// kernel's sidecar *is* conditional. One law with no second path beats two laws that have to agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootfsFeaturesStage {
    /// The `rootfs` registry label whose declaration travels; `None` is `rootfs.default`.
    ///
    /// Private for the same reason [`RootfsStage`]'s is: [`Stage::name`] returns a `&str` and so
    /// reads a precomputed name, and a public label beside a public name would let a caller set one
    /// without the other.
    label: Option<String>,
    /// The stances to render, keyed by the parsed [`crate::feature::Feature`] — so the only way to
    /// populate it is through the registry parser, which is the only place `Feature::parse` runs.
    features: std::collections::BTreeMap<crate::feature::Feature, bool>,
    /// [`Stage::name`]'s return value, composed from `label` at construction.
    stage_name: String,
}

impl RootfsFeaturesStage {
    /// The declaration producer for the registry label `label`; `None` is `rootfs.default`.
    ///
    /// The declaration starts empty — [`RootfsFeaturesStage::with_features`] states it, from the
    /// registry entry the image stage beside it resolves from.
    #[must_use]
    pub fn labelled(label: Option<&str>) -> Self {
        RootfsFeaturesStage {
            label: label.map(str::to_string),
            features: std::collections::BTreeMap::new(),
            // The sidecar's artifact key IS its stage name, mirroring `RootfsStage`, so a labelled
            // declaration stage cannot collide with the default one on the pipeline's own sidecar.
            stage_name: features_artifact_key(&rootfs_artifact_key(label)),
        }
    }

    /// Sets the stances this stage renders — the `features` map of the **same** registry entry the
    /// image stage beside it was built from ([`crate::artifact::resolve_rootfs_entry`]).
    ///
    /// Label and declaration are set separately, and deliberately so: the sidecar's name is derived
    /// from the image's filename, so the label this stage carries must be the one
    /// [`RootfsStage::labelled`] carries in the same pipeline — including the `Some("default")` vs
    /// `None` spelling, which the two composers treat as different files. A constructor that took
    /// the entry and normalized the label itself would silently produce `rootfs.features` beside a
    /// `rootfs-default.erofs`, which is exactly the pairing this split makes visible at the call
    /// site.
    #[must_use]
    pub fn with_features(
        mut self,
        features: std::collections::BTreeMap<crate::feature::Feature, bool>,
    ) -> Self {
        self.features = features;
        self
    }

    /// The registry label this stage declares for, as the key composers take it.
    #[must_use]
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }
}

#[async_trait]
impl Stage for RootfsFeaturesStage {
    fn name(&self) -> &str {
        &self.stage_name
    }

    fn out_path(&self, target_dir: &std::path::Path) -> std::path::PathBuf {
        // Both laws, called and never re-spelled: `rootfs_filename` names the image this
        // declaration is about, and `feature_manifest_path` is the one sidecar-name composer the
        // READER (`FeatureDeclaration::load_beside`) goes through.
        //
        // The format is the DEFAULT here and this stage carries no format field, which is a
        // derivation rather than an omission (§18 delta 8): `feature_manifest_path` REPLACES the
        // extension, so `rootfs-a.erofs` and `rootfs-a.ext4` both name `rootfs-a.features` — one
        // declaration for one label, whichever filesystem its image happens to be. The reader gets
        // the same answer because it derives the same way from the real image path. The coupling is
        // load-bearing and not obvious, so it is pinned:
        // `the_declaration_sidecar_is_one_file_for_both_formats`.
        crate::feature::feature_manifest_path(
            &target_dir.join(rootfs_filename(self.label(), RootfsFormat::default())),
        )
    }

    fn cache_sidecar_path(&self, out: &Path) -> PathBuf {
        // APPEND, never the default replace: `rootfs.features`.with_extension("cache_key") is
        // `rootfs.cache_key` — the RootfsStage's OWN sidecar — so the default would have the two
        // stages overwrite each other's metadata and re-pack the image on every build forever.
        // See `Stage::cache_sidecar_path` for the whole rationale.
        let mut name = out.as_os_str().to_os_string();
        name.push(".cache_key");
        PathBuf::from(name)
    }

    fn cache_key(&self, _inputs: &StageInputs) -> CacheKey {
        // The declaration and nothing else. Deliberately blind to the pins' `(image, digest)` and
        // to every upstream artifact: this stage describes the image, it does not build it, so
        // folding what the image folds would re-emit a byte-identical sidecar on every re-pack —
        // and, read the other way, would tempt somebody to fold the declaration into the image.
        let mut hasher = blake3::Hasher::new();
        hasher.update(&ROOTFS_FEATURES_STAGE_VERSION.to_le_bytes());
        hasher.update(self.stage_name.as_bytes());
        hasher.update(b"\0");
        for (feature, stance) in &self.features {
            // `Feature::name()` is F6's one token spelling — the same bytes the manifest carries,
            // so the key moves exactly when the emitted file would.
            hasher.update(feature.name().as_bytes());
            hasher.update(if *stance { b"=true\0" } else { b"=false\0" });
        }
        CacheKey(format!("rootfs-features-{}", hasher.finalize().to_hex()))
    }

    async fn run(&self, _inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        // `source` is `None` because provenance is the READER's to assign: `load_beside` is handed
        // the `Source` of the axis it is loading for, and a source baked in here would be a second,
        // stale answer to a question the reader already answers.
        let declaration = crate::feature::FeatureDeclaration {
            source: None,
            stances: self.features.clone(),
        };
        tokio::fs::write(out, declaration.render_manifest())
            .await
            .map_err(|e| {
                Error::Artifact(format!(
                    "cannot write the feature manifest {}: {e} — the declaration in \
                     `rootfs.{}.features` would never reach the artifact it describes (§7.4)",
                    out.display(),
                    self.label()
                        .unwrap_or(crate::artifact::registry::DEFAULT_LABEL)
                ))
            })?;
        let mut outputs = StageOutputs::default();
        // Registered under its own key, the `config_artifact_key` shape one kind over: that is what
        // puts the sidecar in the `Artifacts` map every downstream reader (`vmcell bundle`
        // included) names files through, and what content-addresses it with the image it describes.
        // Writing the file without registering it produces an artifact nothing can cite.
        outputs.artifacts.insert(
            features_artifact_key(&rootfs_artifact_key(self.label())),
            out.to_path_buf(),
        );
        Ok(outputs)
    }
}

/// Folds the identity of everything the shared inject+pack tail ([`pack_erofs_with_injection`])
/// bakes into a rootfs — the optional static-musl steward override (by CONTENT, H-ART-1), the
/// deployment proxy CA cert (M-ART-10), the steward source closure, the downstream
/// [`ExtraFile`]s, the handler applet roster, and the artifact's [`XattrPolicy`] — into `hasher`.
///
/// The extra files fold as `(dest, mode, content-hash)` triples in sorted-dest order (§4.2):
/// **content that travels, never the `src` path** (cache-key rule 3), and sorted so the
/// caller's `Vec` order is not part of the identity.
///
/// Every rootfs builder folds this identically: the in-`vmcell` OCI [`RootfsStage`] and the
/// out-of-crate in-VM sources (`vmcell-rootfs-builder`). Kept here so there is exactly ONE
/// implementation of the injected-content identity (§4.3, The rootfs-construction contract; AGENTS.md "don't triplicate;
/// extract") — a musl-steward/CA/steward rebuild then invalidates the cached erofs from any source.
///
/// # Why it takes the whole [`PackOptions`]
///
/// It took the individual inputs positionally until v33 delta 7, and the delta-6b applet roster was
/// simply never handed to it: two registered handlers with different rosters over one multicall
/// binary produced the SAME key and DIFFERENT images, so the warm cache served the first roster and
/// every custom-`init=` target the second declared resolved to nothing. The struct the tail packs
/// with is now the struct the identity folds, destructured **exhaustively** below — so the next
/// field somebody adds to `PackOptions` is a compile error here until its author decides whether it
/// is part of the artifact's identity. A forgotten fold cannot be a silent stale-cache hit again.
///
/// Callers fold their own `STAGE_VERSION`, source discriminator, source-specific pins, and
/// consumed-artifact set (via [`crate::artifact::hash_artifacts_sorted`]) around this call.
#[cfg(feature = "pipeline")]
pub fn fold_rootfs_injection_identity(
    hasher: &mut blake3::Hasher,
    inputs: &StageInputs,
    options: &PackOptions,
) {
    // EXHAUSTIVE on purpose (see the rustdoc above): `PackOptions` is `#[non_exhaustive]`, but this
    // is its defining crate, so a new field lands here as `error[E0027]: pattern does not mention
    // field` rather than as a rootfs that silently re-serves a stale image.
    let PackOptions {
        steward_musl,
        extra,
        // Folded at the tail through `options.applet_roster()` — the RESOLVER, not this raw field:
        // an empty roster MEANS the default handler's, so folding the field itself would give an
        // undeclared roster and an explicit spelling of the same names two keys for one image.
        applets: _,
        // The one field deliberately NOT folded: `label` names the artifact, not its contents, and
        // two labels resolving to the same base pack byte-identical images — the same-digest,
        // two-labels byte-identity gate delta 6c landed.
        label: _,
        xattrs,
        format,
    } = options;
    let (steward_musl, xattrs, format) = (steward_musl.as_deref(), *xattrs, *format);
    // The injected-steward identity: a static-musl override (folded by CONTENT, not path string,
    // since the StewardStage is skipped on that path) vs. the default glibc steward. A read
    // failure folds a distinct marker; the resulting miss re-runs the build, which fails loud.
    match steward_musl {
        Some(p) => {
            hasher.update(b"steward-musl\0");
            match crate::artifact::hash_file(p) {
                Ok(h) => hasher.update(h.as_bytes()),
                Err(_) => hasher.update(format!("missing-steward-musl:{}", p.display()).as_bytes()),
            };
        }
        None => {
            hasher.update(b"steward-default\0");
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
    // The steward source identity (travels via the resolved pins): rebuilding the steward
    // must invalidate the rootfs, otherwise a stale steward stays baked in.
    hasher.update(
        inputs
            .pins
            .get("steward_src_hash")
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
    // The artifact's xattr policy (§4.7, §18 delta 7). A policy change is an IDENTITY change:
    // the same base layers packed under `Preserve` and under `Strip` are two different images,
    // so serving one from the other's warm cache would hand a consumer an image that contradicts
    // its own feature manifest. Folded UNCONDITIONALLY — including `Strip`'s token — because a
    // fold that only spoke up for the non-default value would make `Preserve`→`Strip` collide
    // with an artifact that never declared anything, which is the direction that loses data.
    // `XattrPolicy::name()` is the one spelling, shared with the registry parser, so the key
    // moves exactly when the declaration a consumer wrote would.
    hasher.update(b"xattrs\0");
    hasher.update(xattrs.name().as_bytes());
    hasher.update(b"\0");
    // The handler applet roster (§10.5, §18 delta 6b — folded here since delta 7). The roster
    // decides which `<tools_dir>/<applet>` SYMLINKS the tail bakes; the multicall binary's content
    // is identical either way, so nothing else in this key moves when the roster does. Two
    // registered handlers over one binary with different rosters are two images, and an unfolded
    // roster served the first one's symlink set to the second one's cells — every custom-`init=`
    // target it declared resolving to nothing (exit 2, or a guest kernel panic).
    //
    // Through `applet_roster()`, the one resolver the packer itself calls, so "no roster declared"
    // and "the default roster spelled out" are one identity. In the CALLER's order, deliberately
    // unsorted — `rootfs_injection_manifest` emits the symlinks in exactly that order, and this
    // fold does not assume the packer canonicalizes the order away. Over-keying a reordered roster
    // costs one re-pack; under-keying serves the wrong symlink set, which is a guest kernel panic.
    hasher.update(b"applets\0");
    for applet in options.applet_roster() {
        hasher.update(applet.as_bytes());
        hasher.update(b"\0");
    }
    // The artifact's filesystem format (§4.7, §18 delta 8). The same merged tree emitted as erofs
    // and as ext4 is two images, so the fold is the same law the xattr policy above gets — and
    // unconditional for the same reason, even though the format also moves the artifact's
    // FILENAME. Relying on the filename to keep the two apart would make this key's honesty depend
    // on a second law, and `RootfsFeaturesStage` beside it already shares one sidecar stem across
    // both formats.
    hasher.update(b"format\0");
    hasher.update(format.name().as_bytes());
    hasher.update(b"\0");
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

/// The erofs-only door onto [`pack_rootfs_with_injection`] — §10.4 lists this name, so it stays.
///
/// It **refuses** a [`PackOptions`] naming any other format rather than silently overriding it: the
/// format is an accepted input, and a door whose name promises erofs cannot quietly honor a request
/// for something else nor quietly ignore one (law F1). A caller that wants to choose calls
/// [`pack_rootfs_with_injection`], which is the one tail either way.
///
/// # Errors
/// As [`pack_rootfs_with_injection`], plus [`Error::Artifact`] when `options.format` is not
/// [`RootfsFormat::Erofs`].
#[cfg(feature = "am-fs-erofs")]
pub async fn pack_erofs_with_injection(
    tar_streams: Vec<Box<dyn Read + Send>>,
    inputs: &StageInputs,
    out: &Path,
    options: &PackOptions,
) -> Result<StageOutputs> {
    if options.format != RootfsFormat::Erofs {
        return Err(Error::Artifact(format!(
            "`pack_erofs_with_injection` was handed `format: {}` (§4.7): this door packs erofs by \
             name. Call `pack_rootfs_with_injection`, which is the same tail and honors every \
             format",
            options.format.name()
        )));
    }
    pack_rootfs_with_injection(tar_streams, inputs, out, options).await
}

/// Shared logic to take a list of tar streams, insert the caller's `extra` files, inject the
/// steward and CA, and pack it into the format the artifact declares.
///
/// The ONE inject+pack tail: every rootfs source routes through it (§4.3 obligation 3), so the
/// `libc6` scan, the `--steward-musl` opt-in, and the downstream `extra` files with their
/// reserved-path collision guard apply to every source for free. `extra` is validated FIRST —
/// before any I/O — so a bad dest or mode fails before the CA is materialized or a byte is packed.
///
/// [`PackOptions::format`] chooses the **emitter**, and only the emitter (§4.7, §18 delta 8): the
/// merge, the injections and every law above run identically for both, which is what makes §4.7's
/// "inherited for free" true. The default is erofs and packs the pre-delta-8 bytes exactly.
///
/// # Errors
/// Returns an error if an `extra` entry is rejected — its `dest` must be an absolute UTF-8
/// path that **names a file** (a trailing `/` or a trailing `.` names the parent directory and
/// is refused), must carry no `..` component, and must be neither
/// [reserved](is_reserved_injection_path) nor a duplicate of another entry's normalized dest;
/// its `mode` must be permission bits only (`<= 0o7777`). An *interior* `.` component is
/// **accepted** and folded away by the packer's own normalizer (`/a/./b` == `/a/b`, and
/// therefore the same duplicate), matching [`ExtraFile`]'s contract. Also returns an error if the
/// packing or file injection fails, and — for [`RootfsFormat::Ext4`] — the typed
/// [`Error::CapabilityUnavailable`] when the external producer's version gate refuses (§4.7).
#[cfg(feature = "am-fs-erofs")]
pub async fn pack_rootfs_with_injection(
    tar_streams: Vec<Box<dyn Read + Send>>,
    inputs: &StageInputs,
    out: &Path,
    options: &PackOptions,
) -> Result<StageOutputs> {
    let steward_musl = options.steward_musl.as_deref();
    let extra = options.extra.as_slice();
    let applets = options.applet_roster();
    // `Copy`, so they cross into the blocking task below without a clone or a borrow.
    let xattr_policy = options.xattrs;
    let format = options.format;
    let out_buf = out.to_path_buf();
    // Composed here (not inside the blocking task) so the label borrow ends before the move.
    let artifact_key = rootfs_artifact_key(options.label.as_deref());

    // Validate the caller-supplied extras before any side effect (the CA write below is one):
    // the injection tail is the validation boundary, since an `ExtraFile` never passes through
    // `VmConfig` (design §4.2, invariant F5).
    let extra_validated = validate_extra_files(extra)?;

    // The ext4 route's version gate runs HERE — after the pure validation above, and before the CA
    // is materialized, before a layer is read, before a byte is packed — so an absent or too-old
    // e2fsprogs refuses in milliseconds rather than after a multi-minute merge (§4.7: "probed
    // fail-loud … never a silent mis-build"). The probe itself spawns a process and writes a
    // scratch image, which is why it sits after the extras check rather than before it: `extra` is
    // validated before ANY I/O, and this is I/O.
    //
    // The result is a RECEIPT the emitter needs to exist: `RootfsEmitter::Ext4` carries an
    // `Ext4Producer`, which nothing but the probe can construct, so a pack that skipped the gate is
    // not a bug this file has to test for — it does not compile.
    let emitter = emitter_for(format)?;

    // The injected steward. A user-supplied static-musl binary (`--steward-musl`, oci2erofs §4.2, Rootfs sources and the one packer)
    // overrides the pipeline's default glibc steward artifact; otherwise a missing default steward
    // is a hard error, never a boot from a world-writable, attacker-plantable `/tmp` path.
    let steward_path = match steward_musl {
        Some(p) => p.to_path_buf(),
        None => inputs
            .artifacts
            .get("steward")
            .cloned()
            .ok_or_else(|| Error::Artifact("missing steward upstream input".into()))?,
    };
    // The default (glibc) steward needs libc6 in the base; the static-musl steward does not.
    let require_libc6 = steward_musl.is_none();

    // Materialize the deployment CA and inject it from the ONE file `CaManager` publishes —
    // `<artifacts-dir>/ca.pem`, written under the `.ca.lock` flock as a temp-then-rename.
    //
    // This tail used to `std::fs::write` its own copy of the same bytes to
    // `<out.parent()>/ca.pem`. On the canonical `vmcell build` path that IS the published CA, so
    // the copy was a bare, unlocked truncate-then-write straight through the publish protocol,
    // handing a concurrent `CaManager::new()` a window in which the (cert, key) pair reads as
    // half-present; off that path it injected whatever `ca.pem` happened to sit beside the output.
    // Naming the published file removes both. `new()` mints the pair when absent, so it exists by
    // the time we name it — and if it has since been deleted, the injection below fails loud
    // naming the path instead of baking a stale or foreign CA.
    #[cfg(feature = "proxy")]
    let ca_path = crate::proxy::tls::CaManager::new()?.ca_cert_path();

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
        let (injected_files, injected_symlinks) = rootfs_injection_manifest(
            steward_path.as_path(),
            ca_opt,
            tools_path.as_deref(),
            &applets,
        );
        // The manifest's link paths are owned (composed per applet-roster entry); borrow them
        // back for the packer, whose signature is unchanged. `injected_symlinks` outlives the
        // call, so the borrows are valid for it.
        let injected_symlink_refs: Vec<(&str, &str)> = injected_symlinks
            .iter()
            .map(|(link, target)| (link.as_str(), *target))
            .collect();
        // Explicit `Some(mode)`: extra files never inherit the `injected_file_mode` heuristic.
        let extra_files: Vec<InjectFile<'_>> = extra_validated
            .iter()
            .map(|(dest, src, mode)| (dest.as_str(), src.as_path(), Some(*mode)))
            .collect();

        let archives: Vec<tar::Archive<Box<dyn Read + Send>>> =
            tar_streams.into_iter().map(tar::Archive::new).collect();
        // The format chose the EMITTER, and nothing above this line: both arms hand the same
        // archives, the same extras, the same injections, the same `require_libc6` and the same
        // `XattrPolicy` to the same merge (§4.7, §18 delta 8).
        match emitter {
            RootfsEmitter::Erofs => {
                let image = crate::artifact::tar2erofs::tar_to_erofs(
                    archives,
                    extra_files,
                    injected_files,
                    injected_symlink_refs,
                    require_libc6,
                    xattr_policy,
                )?;
                std::fs::write(&out_buf, image).map_err(|e| Error::Artifact(e.to_string()))?;
            }
            RootfsEmitter::Ext4(producer) => {
                let merged_tar = crate::artifact::tar2erofs::merge_to_tar(
                    archives,
                    extra_files,
                    injected_files,
                    injected_symlink_refs,
                    require_libc6,
                    xattr_policy,
                )?;
                pack_merged_tar_as_ext4(producer, &merged_tar, &out_buf)?;
            }
        }
        let mut outputs = StageOutputs::default();
        // Through the ONE artifact-key law, never the bare literal: `rootfs_artifact_key(None)` IS
        // `"rootfs"`, so the default label's key is byte-identical, while a labelled pack stops
        // registering under the default's key and overwriting it on the artifact map.
        outputs.artifacts.insert(artifact_key, out_buf);
        Ok(outputs)
    })
    .await
    .map_err(|e| Error::Artifact(e.to_string()))?
}

/// What an ext4 emitter needs in hand to run: a **probed** producer.
///
/// With the `ext4-producer` feature off there is none, and the alias is
/// [`std::convert::Infallible`] rather than a unit — which makes [`RootfsEmitter::Ext4`]
/// unconstructible in that configuration, so the tail's ext4 arm is statically dead instead of
/// being a runtime refusal somebody has to remember to write.
#[cfg(all(feature = "am-fs-erofs", feature = "ext4-producer"))]
type Ext4Route = crate::artifact::ext4::Ext4Producer;
/// The `ext4-producer`-off form of [`Ext4Route`] — uninhabited; see the enabled alias.
#[cfg(all(feature = "am-fs-erofs", not(feature = "ext4-producer")))]
type Ext4Route = std::convert::Infallible;

/// Which emitter the one pack tail will hand the merged tree to, **with the probe already run**.
///
/// A carrier, not a second copy of [`RootfsFormat`]: the format is the *declaration* and this is
/// the *receipt*. The ext4 arm holds an [`crate::artifact::ext4::Ext4Producer`], which nothing but
/// the version probe can construct, so "packed ext4 without running the gate" is not a state this
/// file has to test against — it does not compile.
#[cfg(feature = "am-fs-erofs")]
#[derive(Debug)]
enum RootfsEmitter {
    /// The default: no external tool, nothing to probe.
    Erofs,
    /// §4.7's ext4 producer, already past both halves of its version gate.
    ///
    /// With the feature off, `Ext4Route` is [`std::convert::Infallible`] and this variant has no
    /// inhabitant — `emitter_for` still *names* it (which is what keeps the law one function), and
    /// the `.map` that would build it can never run.
    Ext4(Ext4Route),
}

/// Runs §4.7's producer probe for `format` and returns the emitter that survived it.
///
/// **ONE function in every feature configuration**, deliberately — only [`ext4_route`] below is
/// cfg'd. A cfg'd pair here would be two copies of the format→emitter law, and the off copy is
/// precisely the one no test in this workspace can run (vmcell's dev-dependency cycle re-enables
/// `default`, so `--all-targets` always has the feature on). Written this way, the off copy cannot
/// drift because it does not exist: `RootfsFormat::Ext4` maps `ext4_route()`'s success into
/// [`RootfsEmitter::Ext4`] and has no path to [`RootfsEmitter::Erofs`] at all, so "a build without
/// the producer silently packs the default format" is a compile error rather than a behavior a gate
/// has to catch.
///
/// # Errors
/// [`Error::CapabilityUnavailable`] / [`Error::Io`] / [`Error::Artifact`] exactly as
/// [`ext4_route`] classifies them.
#[cfg(feature = "am-fs-erofs")]
fn emitter_for(format: RootfsFormat) -> Result<RootfsEmitter> {
    match format {
        RootfsFormat::Erofs => Ok(RootfsEmitter::Erofs),
        RootfsFormat::Ext4 => ext4_route().map(RootfsEmitter::Ext4),
    }
}

/// Where an [`Ext4Route`] comes from: §4.7's version probe, both halves.
///
/// # Errors
/// [`Error::CapabilityUnavailable`] / [`Error::Io`] / [`Error::Artifact`] exactly as
/// [`crate::artifact::ext4::Ext4Producer::probe`] classifies them.
#[cfg(all(feature = "am-fs-erofs", feature = "ext4-producer"))]
fn ext4_route() -> Result<Ext4Route> {
    crate::artifact::ext4::Ext4Producer::probe()
}

/// The `ext4-producer`-off form: an ext4 request is a **capability that was compiled out**, refused
/// with the typed error, never silently packed as erofs.
///
/// A feature gate may remove a capability, never change semantics (AGENTS.md) — and packing the
/// default format for an artifact that declared `ext4` would be the second thing. That cannot
/// happen here even by mistake: the return type is `Result<Infallible>`, whose `Ok` variant has no
/// inhabitant, so `Err` is the only value this function is *able* to produce.
///
/// # Errors
/// Always [`Error::CapabilityUnavailable`].
#[cfg(all(feature = "am-fs-erofs", not(feature = "ext4-producer")))]
fn ext4_route() -> Result<Ext4Route> {
    Err(Error::CapabilityUnavailable {
        op: "ext4 rootfs pack (§4.7)".to_string(),
        needed: "the `ext4-producer` feature, which this build of `vmcell` was compiled without"
            .to_string(),
    })
}

/// Hands the merged tar to the probed producer.
///
/// # Errors
/// As [`crate::artifact::ext4::Ext4Producer::pack`].
#[cfg(all(feature = "am-fs-erofs", feature = "ext4-producer"))]
fn pack_merged_tar_as_ext4(producer: Ext4Route, merged_tar: &[u8], out: &Path) -> Result<()> {
    producer.pack(merged_tar, out)
}

/// The `ext4-producer`-off form: [`Ext4Route`] is uninhabited there, so this body is the empty
/// match that says so — the arm is unreachable by construction rather than by convention.
#[cfg(all(feature = "am-fs-erofs", not(feature = "ext4-producer")))]
fn pack_merged_tar_as_ext4(producer: Ext4Route, _merged_tar: &[u8], _out: &Path) -> Result<()> {
    match producer {}
}

/// A `(dest_path, source_path, mode)` file injected into the rootfs after every layer is
/// merged. The dest widened from `&'static str` in v30 delta 6 so downstream [`ExtraFile`]
/// dests (owned `String`s) travel the same tail; `mode` is `None` for vmcell's own entries
/// (the `injected_file_mode` heuristic) and `Some(perm)` for an extra file. Aliased to the
/// packer's own type so there is one shape, not two.
#[cfg(feature = "am-fs-erofs")]
type InjectFile<'a> = crate::artifact::tar2erofs::InjectedFile<'a>;
/// A `(link_path, symlink_target)` injected into the rootfs.
///
/// The link path is owned because the guest-tools links are *composed* per
/// [`vmcell_protocol::GUEST_TOOLS_APPLETS`] entry rather than written out as literals; the
/// target is still `'static` (every link points at the one multicall binary). The packer's
/// `tar_to_erofs` signature is unchanged — the pack tail borrows these back into `&str`.
#[cfg(feature = "am-fs-erofs")]
type InjectLink = (String, &'static str);

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
/// GuestToolsStage produced the multicall binary; it lands under `/vmcell-tools` (executable via
/// `injected_file_mode`) with one symlink per
/// [`vmcell_protocol::GUEST_TOOLS_APPLETS`] entry pointing at it. Those names are **derived**,
/// never restated here: design §4.4 requires this manifest and the guest binary's dispatch table
/// to agree, and while both were literals a one-sided edit stayed green and shipped twice
/// (docs/81 m22). The guest side is compile-time pinned to the same const, so the drift is now
/// unrepresentable rather than merely tested for.
#[cfg(feature = "am-fs-erofs")]
fn rootfs_injection_manifest<'a>(
    steward: &'a Path,
    ca: Option<&'a Path>,
    tools: Option<&'a Path>,
    applets: &[String],
) -> (Vec<InjectFile<'a>>, Vec<InjectLink>) {
    // `None` mode: vmcell's own entries keep the `injected_file_mode` bin/sbin heuristic.
    let mut files: Vec<InjectFile<'a>> = vec![("usr/sbin/vmcell-steward", steward, None)];
    if let Some(ca) = ca {
        files.push(("usr/local/share/ca-certificates/vmcell-ca.crt", ca, None));
        files.push(("etc/ssl/certs/ca-certificates.crt", ca, None));
    }
    let mut symlinks: Vec<InjectLink> = Vec::new();
    if let Some(tools) = tools {
        files.push(("vmcell-tools/vmcell-guest-tools", tools, None));
        // busybox-style multicall links resolved on the exec PATH (the steward prepends
        // its tools dir) — ONE per roster entry. There is deliberately no name literal here:
        // `echo-server` (the §3.2 raw-vsock-dial / §6.5 segment listener) is also one of the
        // applets used as a custom `init=` target, which resolves its absolute path before any
        // steward exists — so a symlink this manifest forgot to emit is a guest kernel panic, not
        // a missing test helper.
        //
        // The roster is a PARAMETER as of v33 delta 6 (§10.5), not the shared const read directly:
        // the const is the DEFAULT handler's roster, the one the guest binary's dispatch table is
        // compile-time asserted against. A registered consumer handler has no such const to assert
        // against, so its roster comes from its registry entry — strict-parsed there, and reaching
        // here as data. `HandlerRegistryEntry::applet_roster` is where the two meet, so no
        // injection site has to know which kind it is holding.
        for applet in applets {
            symlinks.push((
                format!("{VMCELL_TOOLS_DIR}/{applet}"),
                GUEST_TOOLS_MULTICALL_BIN,
            ));
        }
    }
    (files, symlinks)
}

/// Shared logic to take a tar stream, inject the steward and CA, and pack it into erofs.
#[cfg(not(feature = "am-fs-erofs"))]
pub async fn pack_erofs_with_injection(
    tar_streams: Vec<Box<dyn Read + Send>>,
    inputs: &StageInputs,
    out: &Path,
    options: &PackOptions,
) -> Result<StageOutputs> {
    pack_rootfs_with_injection(tar_streams, inputs, out, options).await
}

/// Shared logic to take a tar stream, inject the steward and CA, and pack it into the declared
/// format.
#[cfg(not(feature = "am-fs-erofs"))]
pub async fn pack_rootfs_with_injection(
    _tar_streams: Vec<Box<dyn Read + Send>>,
    _inputs: &StageInputs,
    _out: &Path,
    _options: &PackOptions,
) -> Result<StageOutputs> {
    // The MERGE lives behind `am-fs-erofs`, and both emitters consume it (§18 delta 8), so the
    // ext4 route needs that feature too — it is not an "erofs-only" gate any more, whatever its
    // name says. mkfs.erofs as a fallback would require extracting the tar to a directory, adding
    // the files, and running mkfs.erofs. We assume am-fs-erofs is used for now.
    Err(Error::Artifact(
        "am-fs-erofs feature is required for rootfs building".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    /// Both feature configurations of the format→emitter law, each compiled only where it applies.
    ///
    /// The `ext4-producer`-OFF arm is why that feature is in `default` rather than inside
    /// `pipeline`: a feature `pipeline` implied could never be off in any configuration cargo can
    /// build, and its refusal would be unreachable code nobody had compiled. `cargo hack
    /// --feature-powerset` builds `pipeline` without it, and this is what runs there.
    ///
    /// RED on the inverse (off): return `Ok(RootfsEmitter::Erofs)` for `Ext4` and an artifact that
    /// declared ext4 is silently packed as erofs — a feature gate changing semantics rather than
    /// removing a capability, which AGENTS.md forbids by name.
    #[cfg(all(feature = "am-fs-erofs", not(feature = "ext4-producer")))]
    #[test]
    fn without_the_producer_feature_an_ext4_request_is_a_typed_capability_refusal() {
        assert!(
            matches!(emitter_for(RootfsFormat::Erofs), Ok(RootfsEmitter::Erofs)),
            "the default format never needed the feature"
        );
        match emitter_for(RootfsFormat::Ext4) {
            Err(Error::CapabilityUnavailable { op, needed }) => {
                assert!(op.contains("ext4"), "the op names the operation: {op}");
                assert!(
                    needed.contains("ext4-producer"),
                    "the refusal must name the feature that was compiled out: {needed}"
                );
            }
            other => panic!(
                "an ext4 request in a build without the producer must be a typed capability \
                 refusal, never a silent erofs pack: {other:?}"
            ),
        }
    }

    /// The `ext4-producer`-ON arm: the emitter for `Ext4` carries a **probed** producer, which is
    /// the receipt the pack tail runs on.
    ///
    /// There is deliberately no test for "packed ext4 without probing": `RootfsEmitter::Ext4`
    /// carries an `Ext4Producer` and nothing but the probe constructs one, so that state does not
    /// compile. This asserts the shape that makes it so, which is the part a refactor could undo.
    #[cfg(all(feature = "am-fs-erofs", feature = "ext4-producer"))]
    #[test]
    fn the_ext4_emitter_carries_a_probed_producer() {
        assert!(
            matches!(emitter_for(RootfsFormat::Erofs), Ok(RootfsEmitter::Erofs)),
            "the default format runs no probe at all"
        );
        match emitter_for(RootfsFormat::Ext4) {
            Ok(RootfsEmitter::Ext4(producer)) => assert!(
                producer.version() >= crate::artifact::ext4::MIN_E2FSPROGS_VERSION,
                "the carried producer is the one the gate accepted: {:?}",
                producer.version()
            ),
            // A host without e2fsprogs takes the typed refusal, which is the honest outcome and
            // still proves the probe ran on this path.
            Err(Error::CapabilityUnavailable { needed, .. }) => assert!(
                needed.contains("e2fsprogs") || needed.contains("libarchive"),
                "the refusal must name the absent facility: {needed}"
            ),
            other => panic!("the ext4 emitter must be probed or typed-refused: {other:?}"),
        }
    }

    /// Materialize the shared proxy CA ONCE, before any test below folds it into a cache key.
    ///
    /// Every rootfs cache key folds the deployment CA's PEM (`fold_rootfs_injection_identity`), and
    /// `CaManager::new()` reads it from the process-GLOBAL artifacts dir, minting it when absent.
    /// Its cache and lock are process-global — but nextest gives every test its own PROCESS, so on a
    /// cold artifacts dir (any CI runner) hundreds of test processes race to materialize the same
    /// `ca.pem` / `ca.key`.
    ///
    /// The pair is published as TWO renames. A process that looks between them sees
    /// `cert_exists != key_exists` and gets the deliberate `partial CA in …` refusal, which the fold
    /// turns into `ca-read-error:…` — and errors are NOT cached, so the very next call in the same
    /// process folds the real PEM. Two keys computed either side of that window differ for a reason
    /// that has nothing to do with what the test asserts. Seen exactly once in CI, as
    /// `test_rootfs_cache_key_order_independent` reporting two unequal hashes on a cold runner.
    ///
    /// One SUCCESSFUL call closes the window for the rest of the process: `CaManager::new_in`'s fast
    /// path then returns the cached PEM without touching the filesystem. The retry exists because
    /// this call can itself land in another process's publish window; the transient is bounded by
    /// two renames, so a few short waits cover it, and a CA that is genuinely half-committed still
    /// fails loudly here — naming the real problem instead of a mystified key mismatch.
    #[cfg(feature = "proxy")]
    fn stabilize_ca() {
        let mut last = String::new();
        for _ in 0..50 {
            match crate::proxy::tls::CaManager::new() {
                Ok(_) => return,
                Err(e) => {
                    last = e.to_string();
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            }
        }
        panic!("the shared proxy CA never materialized; last error: {last}");
    }

    /// Without the `proxy` feature no CA is folded, so there is nothing to stabilize.
    #[cfg(not(feature = "proxy"))]
    fn stabilize_ca() {}

    fn stage() -> RootfsStage {
        RootfsStage::new()
    }

    fn stage_with(extra: Vec<ExtraFile>) -> RootfsStage {
        RootfsStage::new().with_extra(extra)
    }

    fn write_tmp(dir: &std::path::Path, name: &str, content: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, content).expect("write");
        p
    }

    // Guards ARTIFACT-PIPELINE-1 for the CONSUMED-artifact fold: the two artifacts this OCI
    // stage consumes (`steward`, `guest_tools`) must fold order-independently over their
    // content. Inserted in opposite orders, the content-addressed key must be identical.
    #[test]
    fn test_rootfs_cache_key_order_independent() {
        stabilize_ca();
        let dir = tempfile::tempdir().expect("tempdir");
        let steward = write_tmp(dir.path(), "steward", b"steward-bytes");
        let tools = write_tmp(dir.path(), "guest_tools", b"tools-bytes");
        let mut a = StageInputs::default();
        a.artifacts.insert("steward".to_string(), steward.clone());
        a.artifacts.insert("guest_tools".to_string(), tools.clone());
        let mut b = StageInputs::default();
        b.artifacts.insert("guest_tools".to_string(), tools);
        b.artifacts.insert("steward".to_string(), steward);
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
        let steward = Path::new("/steward");
        let ca = Path::new("/ca.pem");
        let tools = Path::new("/tools");
        let (files, symlinks) =
            rootfs_injection_manifest(steward, Some(ca), Some(tools), &default_applet_roster());
        let dests: Vec<&str> = files.iter().map(|(d, _, _)| *d).collect();
        // vmcell's own entries keep the `injected_file_mode` heuristic: only a downstream
        // `ExtraFile` states its mode explicitly (§4.2). A `Some(...)` here would mean the
        // manifest started hardcoding modes behind the pinned heuristic's back.
        assert!(
            files.iter().all(|(_, _, mode)| mode.is_none()),
            "manifest entries take the injected_file_mode heuristic, not an explicit mode"
        );

        // The steward (PID 1) is always injected.
        assert!(dests.contains(&"usr/sbin/vmcell-steward"));
        // With a CA: BOTH the drop-in AND the /etc/ssl/certs bundle the rustls stack reads at
        // client-build time. Missing the bundle => guest-tools curl can't build a client, so even
        // plain-HTTP egress fails (gt-curl-truststore).
        assert!(
            dests.contains(&"etc/ssl/certs/ca-certificates.crt"),
            "the CA must be merged into the /etc/ssl/certs trust-store bundle"
        );
        assert!(dests.contains(&"usr/local/share/ca-certificates/vmcell-ca.crt"));
        // The guest-tools multicall + one exec-PATH symlink per applet. The roster walked
        // here is `vmcell_protocol::GUEST_TOOLS_APPLETS` — the SAME const the manifest emits
        // from and the guest binary's dispatch table is compile-time pinned to. It is
        // deliberately NOT re-typed: a third literal beside the two real ones is precisely
        // what let a one-sided edit stay green twice (docs/81 m22). This asserts what the
        // const cannot: that the manifest still emits a link per entry, at the right path,
        // pointing at the multicall binary — dropping the `for` loop above reddens on the
        // count, and mis-pathing it reddens on the membership check.
        assert!(dests.contains(&"vmcell-tools/vmcell-guest-tools"));
        assert!(
            !vmcell_protocol::GUEST_TOOLS_APPLETS.is_empty(),
            "an empty roster would make the loop below vacuous"
        );
        assert_eq!(
            symlinks.len(),
            vmcell_protocol::GUEST_TOOLS_APPLETS.len(),
            "the manifest must emit exactly one multicall symlink per applet, no more"
        );
        for name in vmcell_protocol::GUEST_TOOLS_APPLETS {
            let link = format!("{VMCELL_TOOLS_DIR}/{name}");
            assert!(
                symlinks
                    .iter()
                    .any(|(l, t)| *l == link && *t == GUEST_TOOLS_MULTICALL_BIN),
                "missing multicall symlink {link}"
            );
        }

        // No CA (the non-proxy build) => no trust-store bundle injected.
        let (files_np, _) =
            rootfs_injection_manifest(steward, None, Some(tools), &default_applet_roster());
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
        // The DEFAULT roster here, deliberately: a consumer handler's applet names are not vmcell's to
        // reserve, and they do not need to be — the whole-directory prefix rule above already reserves
        // `<tools_dir>/<anything>`, including names no manifest has grown yet.
        let (files, symlinks) =
            rootfs_injection_manifest(probe, Some(probe), Some(probe), &default_applet_roster());
        for dest in files
            .iter()
            .map(|(d, _, _)| *d)
            .chain(symlinks.iter().map(|(l, _)| l.as_str()))
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
        // Normalization-before-comparison: each of these names the steward.
        for evasion in [
            "/usr/sbin/./vmcell-steward",
            "//usr/sbin/vmcell-steward",
            "/usr/sbin//vmcell-steward",
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
                "reserved: the steward",
                ok("/usr/sbin/vmcell-steward", 0o755),
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
                ok("/usr/sbin/./vmcell-steward", 0o755),
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

    // Quality-gates v4 row 6, carried forward: the OCI stage's cache-key version must be bumped by
    // every change to what the stage FOLDS, because an un-bumped version serves the
    // previously-packed rootfs from the warm cache while every KVM-free test stays green (the
    // recorded v20 precedent). Three bumps live behind this literal today: v30 delta 6 (→ 4, the
    // extra-file triples entering `fold_rootfs_injection_identity`), v33 delta 6c (→ 5, the F7
    // `unpinned_path` arm) and v33 delta 7 (→ 6, the `XattrPolicy` AND the delta-6b applet roster,
    // which had never been folded — one bump, because neither shipped in a released version).
    //
    // A literal-value assertion on purpose: it is a TRIPWIRE, not a derivation, so it goes red on
    // the next fold change and forces the author to state which bump they are making. RED on the
    // inverse: reverting the const to 5.
    #[test]
    fn rootfs_stage_version_pins_the_identity_fold_bumps() {
        assert_eq!(
            OCI_ROOTFS_STAGE_VERSION, 7,
            "an identity-fold change requires this stage-version bump; without it a stale rootfs \
             is served from the warm cache. If you changed what `cache_key` folds, bump the const \
             and this literal together and record the reason in the const's doc comment"
        );
    }

    // §18 delta 7: an xattr-policy change is an ARTIFACT-IDENTITY change and must re-pack. The
    // same base packed under `Preserve` and under `Strip` are two different images, so a shared
    // key would serve one where the other was declared — and, through the derived
    // `Feature::XattrPreserved`, an image that contradicts its own feature manifest.
    //
    // RED on the inverse: delete the `xattrs` fold at the tail of
    // `fold_rootfs_injection_identity` — the two keys collapse to one.
    #[test]
    fn rootfs_key_tracks_the_xattr_policy() {
        stabilize_ca();
        let inputs = StageInputs::default();
        let strip = RootfsStage::new().with_xattrs(XattrPolicy::Strip);
        let preserve = RootfsStage::new().with_xattrs(XattrPolicy::Preserve);
        assert_ne!(
            strip.cache_key(&inputs),
            preserve.cache_key(&inputs),
            "changing the xattr policy must invalidate the rootfs cache key (§4.7): the packed \
             image differs, so serving the other one from the warm cache ships an artifact whose \
             attributes contradict its declaration"
        );
    }

    // Migration is free, half 2 (§18 delta 7: "cache key unmoved"). Stated honestly: the
    // STAGE_VERSION bump moves every key by design, so "unmoved" cannot mean "equal to the
    // pre-delta-7 key" — nothing could assert that without also asserting the bump did not
    // happen. What it CAN mean, and what a consumer actually feels, is that *not declaring a
    // policy* is identical to declaring the default: a `rootfs` entry with no `xattrs` key and one
    // that says `"strip"` are the same artifact, so adding the key to a pins overlay to write down
    // what was already true does not re-pack anything.
    //
    // The byte half of the same claim lives in `tar2erofs`:
    // `the_default_policy_packs_the_pre_delta7_bytes`.
    //
    // RED on the inverse: give `XattrPolicy` a third variant as its `Default`, or fold the
    // `Option<XattrPolicy>`-style "was it declared?" bit instead of the resolved policy.
    #[test]
    fn an_undeclared_policy_is_the_default_policy() {
        stabilize_ca();
        let inputs = StageInputs::default();
        assert_eq!(
            RootfsStage::new().cache_key(&inputs),
            RootfsStage::new()
                .with_xattrs(XattrPolicy::Strip)
                .cache_key(&inputs),
            "declaring `xattrs: strip` must be byte-identical to declaring nothing — otherwise \
             writing down the default re-packs every artifact that does it"
        );
        assert_eq!(
            PackOptions::new().xattrs,
            XattrPolicy::Strip,
            "the pack tail's default is the same default"
        );
    }

    // §18 delta 6b's gap, closed in delta 7: the applet roster IS artifact identity. The roster
    // decides which `<tools_dir>/<applet>` symlinks are baked and nothing else in the key moves
    // with it — the multicall binary's content is identical either way — so two registered
    // handlers over one binary with different rosters produced the SAME key and DIFFERENT images.
    // The warm cache then served the first roster, and every custom-`init=` target the second one
    // declared resolved to nothing: exit 2, or a guest kernel panic for an `init=` target.
    //
    // RED on the inverse: delete the `applets` fold at the tail of
    // `fold_rootfs_injection_identity` — the first two keys collapse to one.
    #[test]
    fn rootfs_key_tracks_the_applet_roster() {
        stabilize_ca();
        let inputs = StageInputs::default();
        let key =
            |applets: Vec<String>| RootfsStage::new().with_applets(applets).cache_key(&inputs);
        let one = key(vec!["ip".into(), "curl".into()]);
        assert_ne!(
            one,
            key(vec!["ip".into()]),
            "changing the applet roster must invalidate the rootfs cache key (§10.5): the baked \
             symlink set differs, so the warm cache would serve an image whose custom-`init=` \
             targets do not exist"
        );
        // Non-vacuity: the gate must not pass merely because every roster keys differently from
        // every other. The SAME roster is the SAME artifact.
        assert_eq!(
            one,
            key(vec!["ip".into(), "curl".into()]),
            "the same roster must key the same — a key that moves without the image moving \
             re-packs a multi-minute artifact for nothing"
        );
        // And the resolver's law reaches the identity: an empty roster MEANS the default handler's,
        // so writing the default out by hand must not re-pack. This is what folding
        // `applet_roster()` rather than the raw `applets` field buys.
        assert_eq!(
            RootfsStage::new().cache_key(&inputs),
            key(default_applet_roster()),
            "an undeclared roster is the default roster; spelling it out must be the same artifact"
        );
        assert_ne!(
            RootfsStage::new().cache_key(&inputs),
            key(vec!["ip".into()]),
            "…and the previous assertion must not be vacuous: a NON-default roster still differs \
             from the undeclared one"
        );
    }

    // Cache-key rule 3 for the extra files: CONTENT travels, the `src` path does not.
    // (a) rebuilding an extra file in place must re-pack; (b) the same bytes reached by a
    // different host path must NOT; (c) the caller's Vec order is not identity (sorted fold);
    // (d) a mode change alone must re-pack. Each arm reddens a specific buggy fold: (a)/(b) a
    // path-string fold, (c) an unsorted fold, (d) a fold that omits the mode.
    #[test]
    fn test_rootfs_key_tracks_extra_file_content_mode_and_not_order() {
        stabilize_ca();
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
        stabilize_ca();
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
        stabilize_ca();
        let dir = tempfile::tempdir().expect("tempdir");
        let p = write_tmp(dir.path(), "steward", b"steward-v1");
        let mut inputs = StageInputs::default();
        inputs.artifacts.insert("steward".to_string(), p.clone());
        let k1 = stage().cache_key(&inputs);
        std::fs::write(&p, b"steward-v2-rebuilt-at-same-path").expect("write");
        let k2 = stage().cache_key(&inputs);
        assert_ne!(
            k1, k2,
            "rebuilt upstream content must change the rootfs key"
        );
    }

    // Guards ARTIFACT-PIPELINE-2: the rootfs key omitting `steward_src_hash` lets a
    // stale steward stay baked in; folding it in makes the key sensitive to it.
    #[test]
    fn test_rootfs_cache_key_tracks_steward_src_hash() {
        stabilize_ca();
        let mut a = StageInputs::default();
        a.pins
            .insert("steward_src_hash".to_string(), "hash-aaa".to_string());
        let mut b = StageInputs::default();
        b.pins
            .insert("steward_src_hash".to_string(), "hash-bbb".to_string());
        assert_ne!(stage().cache_key(&a), stage().cache_key(&b));
    }

    // H-ART-1: the injected static-musl steward must be folded by CONTENT, not by its path
    // string. When `steward_musl` is set the StewardStage is skipped, so the steward has no
    // other content identity in the key — rebuilding it at the SAME path must invalidate the
    // rootfs. The buggy path-string fold leaves k1 == k2 (same path) -> red here.
    #[test]
    fn test_rootfs_steward_musl_key_tracks_content() {
        stabilize_ca();
        let dir = tempfile::tempdir().expect("tempdir");
        let steward = write_tmp(dir.path(), "steward-musl", b"musl-v1");
        let s = RootfsStage::new().with_steward_musl(Some(steward.clone()));
        let inputs = StageInputs::default();
        let k1 = s.cache_key(&inputs);
        // Rebuild the musl steward in place at the SAME path.
        std::fs::write(&steward, b"musl-v2-rebuilt-at-same-path").expect("write");
        let k2 = s.cache_key(&inputs);
        assert_ne!(
            k1, k2,
            "a rebuilt steward-musl at the same path must invalidate the rootfs key (H-ART-1)"
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

    // Guards ARTIFACT-PIPELINE-3: a missing steward input must be a hard error, never a
    // silent boot from a world-writable `/tmp/steward`.
    #[cfg(feature = "am-fs-erofs")]
    #[tokio::test]
    async fn test_pack_erofs_missing_steward_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("rootfs.erofs");
        let inputs = StageInputs::default();
        let res = pack_erofs_with_injection(vec![], &inputs, &out, &PackOptions::default()).await;
        assert!(
            matches!(res, Err(Error::Artifact(_))),
            "missing steward must be a hard error, got {res:?}"
        );
    }

    // The extras are validated BEFORE any side effect: this call has no `steward` either,
    // yet the reserved-dest error is what surfaces — proving the check runs ahead of the CA
    // materialization (which MINTS the pair when it is absent) and the pack. The buggy order
    // (validate inside/after the blocking pack) reports the missing-steward error instead.
    #[cfg(feature = "am-fs-erofs")]
    #[tokio::test]
    async fn test_pack_erofs_rejects_reserved_extra_dest_before_any_io() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("rootfs.erofs");
        let inputs = StageInputs::default();
        let extra = [ExtraFile::new(
            "/usr/sbin/vmcell-steward",
            dir.path().join("evil"),
            0o755,
        )];
        let err = pack_erofs_with_injection(
            vec![],
            &inputs,
            &out,
            &PackOptions {
                extra: extra.to_vec(),
                ..PackOptions::default()
            },
        )
        .await
        .expect_err("a reserved extra dest must be rejected");
        let Error::Artifact(msg) = &err else {
            panic!("expected Error::Artifact, got {err:?}");
        };
        assert!(
            msg.contains("vmcell-owned injection path"),
            "the reserved-dest check must run before the missing-steward check, got: {msg}"
        );
        // Nothing at all may land in the staging dir — asserted over its whole content rather
        // than over one known filename, so any future side effect ahead of the validation
        // (not just the output or a CA copy) reddens this.
        let leftovers: Vec<String> = std::fs::read_dir(dir.path())
            .expect("read the staging dir")
            .map(|e| {
                e.expect("dir entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert!(
            leftovers.is_empty(),
            "nothing may be written before the extras are validated, found {leftovers:?}"
        );
    }

    // NET-4: the inject+pack tail must never write the PUBLISHED CA. `<artifacts-dir>/ca.pem` is
    // published by `CaManager` alone — under the `.ca.lock` flock, temp-then-rename — and this
    // tail used to `std::fs::write` the same bytes over it with no lock held. Same content, but a
    // truncate-then-write is a window in which a concurrent `CaManager::new()` reads the
    // (cert, key) pair as half-present and takes the `partial CA in …` refusal. On the canonical
    // `vmcell build` path the stage output sits IN the artifacts dir, so the sentinel below stands
    // exactly where that write landed.
    //
    // RED on the inverse (restore `std::fs::write(&path, ca_mgr.ca_cert_pem())` on
    // `<out.parent()>/ca.pem`): the sentinel comes back as the real PEM. The second half is the
    // positive control — the CA the manager published is still baked into the image, so "stop
    // writing it" cannot be satisfied by dropping the injection.
    #[cfg(all(feature = "am-fs-erofs", feature = "proxy"))]
    #[tokio::test]
    async fn pack_tail_never_writes_the_published_ca() {
        stabilize_ca();
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("rootfs.erofs");

        let sentinel = "-----BEGIN CERTIFICATE-----\nsentinel-not-the-published-ca\n";
        let beside_the_output = dir.path().join("ca.pem");
        std::fs::write(&beside_the_output, sentinel).expect("seed the sentinel");

        // A static-musl steward: `require_libc6` is then false, so the tail packs with no layers.
        let musl = dir.path().join("steward-musl");
        std::fs::write(&musl, b"#!static-steward").expect("write the steward stand-in");

        let inputs = StageInputs::default();
        pack_erofs_with_injection(
            vec![],
            &inputs,
            &out,
            &PackOptions {
                steward_musl: Some(musl.clone()),
                ..PackOptions::default()
            },
        )
        .await
        .expect("the pack must succeed");

        assert_eq!(
            std::fs::read_to_string(&beside_the_output).expect("read the sentinel back"),
            sentinel,
            "the pack tail must not write ca.pem — only CaManager publishes it, under .ca.lock"
        );

        let pem = crate::proxy::tls::CaManager::new()
            .expect("the CA must be materialized")
            .ca_cert_pem()
            .to_string();
        let image = std::fs::read(&out).expect("read the packed image");
        assert!(
            image.windows(pem.len()).any(|w| w == pem.as_bytes()),
            "the PUBLISHED CA must still be baked into the image (it is injected from the file \
             CaManager published, not from a copy this tail wrote)"
        );
    }

    // §10.5 / §18 delta 6c: the inject+pack TAIL registers its output under the one artifact-key
    // law, `rootfs_artifact_key(label)` — not the bare `"rootfs"` literal it hardcoded, which
    // collapsed every labelled rootfs onto the default's entry (the M-PIPE-4 defect
    // `rootfs_artifact_key`'s own rustdoc names, live in the path that packs vmcell's canonical
    // image). Nothing else could have caught it: an artifact-map key is a `String`, so a producer
    // registering under a name no consumer reads is not a compile error, and the two keys are
    // IDENTICAL for the default label — which is the only label the suite used to pack.
    //
    // Two halves, because a gate binds the call site and not just the predicate:
    //   1. the tail keys off the label it is HANDED (both legs, real packs);
    //   2. `RootfsStage` hands it the same label its name, out_path and pin keys are composed from.
    //
    // RED on the inverse: restore `outputs.artifacts.insert("rootfs".into(), out_buf)` and the
    // labelled leg fails naming both keys; drop `label` from `RootfsStage::pack_options()` and
    // half 2 fails while half 1 still passes — the "green predicate beside an unchanged call site"
    // shape, kept visible on purpose.
    #[cfg(all(feature = "am-fs-erofs", feature = "proxy"))]
    #[tokio::test]
    async fn the_pack_tail_registers_under_the_labelled_artifact_key() {
        stabilize_ca();
        let dir = tempfile::tempdir().expect("tempdir");
        // A static-musl steward stand-in: `require_libc6` is then false, so the tail packs with no
        // layers and the test needs no registry.
        let musl = dir.path().join("steward-musl");
        std::fs::write(&musl, b"#!static-steward").expect("write the steward stand-in");
        let inputs = StageInputs::default();

        let pack = async |label: Option<&str>| -> StageOutputs {
            let out = dir.path().join(rootfs_filename(label, RootfsFormat::Erofs));
            pack_erofs_with_injection(
                vec![],
                &inputs,
                &out,
                &PackOptions::new()
                    .with_steward_musl(Some(musl.clone()))
                    .with_label(label),
            )
            .await
            .expect("the pack must succeed")
        };

        // The default label's key is UNMOVED — `rootfs_artifact_key(None)` is `"rootfs"`, the key
        // `SnapshotStage` and every pre-v33 reader look up. This half must stay byte-identical or
        // the fix would have been a break.
        let default_out = pack(None).await;
        assert_eq!(
            default_out
                .artifacts
                .get(&rootfs_artifact_key(None))
                .map(PathBuf::as_path),
            Some(
                dir.path()
                    .join(rootfs_filename(None, RootfsFormat::Erofs))
                    .as_path()
            ),
            "the default label must still register under `rootfs`: {default_out:?}"
        );

        // The labelled leg: its own key, and NOT the default's — the assertion the bug failed.
        let labelled_out = pack(Some("acme")).await;
        assert_eq!(
            labelled_out
                .artifacts
                .get(&rootfs_artifact_key(Some("acme")))
                .map(PathBuf::as_path),
            Some(
                dir.path()
                    .join(rootfs_filename(Some("acme"), RootfsFormat::Erofs))
                    .as_path(),
            ),
            "a labelled pack must register under `{}`: {labelled_out:?}",
            rootfs_artifact_key(Some("acme"))
        );
        assert!(
            !labelled_out
                .artifacts
                .contains_key(&rootfs_artifact_key(None)),
            "a labelled pack must not also claim the DEFAULT key — that is the collapse: a \
             pipeline building both would keep whichever ran last, and every consumer of \
             `artifacts[\"rootfs\"]` would silently read the wrong image: {labelled_out:?}"
        );

        // Half 2, the call site: the stage hands the tail the same label it composes its own name,
        // out_path and pin keys from. Without this the tail could be perfectly correct and still
        // never see a label.
        for label in [None, Some("acme")] {
            assert_eq!(
                RootfsStage::labelled(label).pack_options().label.as_deref(),
                label,
                "`RootfsStage::labelled({label:?})` must tell the pack tail which label it packs"
            );
        }
    }

    // §18 delta 7's CALL-SITE SCAN, the half a `PackOptions` unit test cannot see: the stage's
    // declared policy must actually REACH the tail. `RootfsStage::run` builds its options through
    // `pack_options()` and nowhere else, so pinning the accessor pins the pack — and the same
    // accessor is what `cache_key` reads, which is what keeps the identity and the bytes agreeing.
    //
    // RED on the inverse: drop the `xattrs` line from `RootfsStage::pack_options()` — the stage
    // then folds `Preserve` into its key (the sibling test stays green) and packs `Strip`, which
    // is precisely the shape that ships an image contradicting its own cache key.
    #[test]
    fn the_stages_xattr_policy_reaches_the_pack_tail() {
        for policy in [XattrPolicy::Strip, XattrPolicy::Preserve] {
            assert_eq!(
                RootfsStage::new().with_xattrs(policy).pack_options().xattrs,
                policy,
                "`RootfsStage::with_xattrs({policy:?})` must tell the pack tail which policy it \
                 packs under"
            );
        }
        // And the default stage declares the default, so a caller that never mentions the policy
        // packs exactly what it always packed.
        assert_eq!(RootfsStage::new().pack_options().xattrs, XattrPolicy::Strip);
    }
}
