//! The **handler** artifact kind: the binary injected at the guest tools path (design §10.5, v33
//! delta 6).
//!
//! The third kind, and the one §10.5 says was "not an artifact at all" before v33: `GuestToolsStage`
//! built from the workspace unconditionally, in both `cache_key` and `run`, with no prebuilt escape
//! hatch. A consumer who wanted their own in-guest helper had to fork the pins file or push a binary
//! per boot through `PutFile` — which caps at `MAX_FRAME_BYTES` and cannot set an executable mode.
//!
//! The `default` entry names today's workspace build, so the shipped behavior is byte-identical and
//! merely *stated in data* instead of hardcoded. A registered entry is a digest with a verified
//! fetch (F7), and carries its own `applets` roster — which is why the `GUEST_TOOLS_APPLETS`
//! const-assert binds the **default** handler only.

use std::path::Path;

use crate::error::{Error, Result};

/// The **flattened pins key** a handler's `sub_key` resolves to: `handler_<sub_key>` for the default
/// handler, `handler_<label>_<sub_key>` for a labelled one (§10.5).
///
/// The **one** composer for the handler→pin-key law, mirroring
/// [`crate::artifact::kernel::kernel_pin_key`] and
/// [`crate::artifact::rootfs::rootfs_pin_key`]: the flattener EMITS through it and every consumer
/// READS through it, so producer and consumer cannot drift into a silent `Missing handler_… pin`.
///
/// Singular `handler_` against the plural `handlers` namespace, deliberately and exactly as
/// `kernel_<label>_source_url` reads against `kernels`: the namespace names a collection, a pin
/// names one member of it.
#[must_use]
pub fn handler_pin_key(label: Option<&str>, sub_key: &str) -> String {
    match label {
        Some(l) => format!("handler_{l}_{sub_key}"),
        None => format!("handler_{sub_key}"),
    }
}

/// The [`crate::artifact::StageOutputs`] **artifact-map key** a handler producer registers its
/// binary under: `"guest_tools"` for the default, `"guest_tools-<label>"` for a labelled one.
///
/// The default keeps the pre-v33 key on purpose — the rootfs pack tail reads
/// `inputs.artifacts["guest_tools"]`, and a rename would be a break with no benefit. The kind is
/// `handler` in the schema and `guest_tools` on the artifact map; that is one fact with two
/// audiences, not two facts.
#[must_use]
pub fn handler_artifact_key(label: Option<&str>) -> String {
    match label {
        Some(l) => format!("guest_tools-{l}"),
        None => "guest_tools".to_string(),
    }
}

/// The on-disk filename **suffix** for a handler label (`""` for the default, `-<label>` with `.`
/// sanitized to `-` otherwise) — the **one** handler label-sanitization law (§10.5).
#[must_use]
pub fn handler_filename_suffix(label: Option<&str>) -> String {
    label
        .map(|l| format!("-{}", l.replace('.', "-")))
        .unwrap_or_default()
}

/// The on-disk artifact **filename** of a built handler: `guest_tools` for the default,
/// `guest_tools-<sanitized-label>` for a labelled one.
#[must_use]
pub fn handler_filename(label: Option<&str>) -> String {
    format!("guest_tools{}", handler_filename_suffix(label))
}

/// The inverse of [`handler_filename`]: the on-disk label carried by a handler artifact filename,
/// or `None` when `name` is not a labelled handler.
///
/// The bare `guest_tools` returns `None`; so does a remainder containing `.`, which — since
/// [`handler_filename_suffix`] sanitizes `.`→`-` — can only be a sidecar
/// (`guest_tools-acme.cache_key`).
#[must_use]
pub fn handler_label_from_filename(name: &str) -> Option<&str> {
    match name.strip_prefix("guest_tools-") {
        Some(label) if !label.is_empty() && !label.contains('.') => Some(label),
        _ => None,
    }
}

/// Where one handler's bytes come from — the three **registration** shapes §10.5 allows,
/// exhaustively (F7), plus the one per-run **override** that is not a registration at all
/// ([`HandlerSource::Prebuilt`], §4.2).
///
/// The split is R7's: a registration is a durable claim that outlives the session that made it, so
/// it is a digest; an override is a deliberate per-run act by an operator who knows what they are
/// pointing at, exactly as `VMCELL_KERNEL`/`VMCELL_ROOTFS` are. Only the first three are ever
/// produced by the `handlers` entry parser — no pins key resolves to `Prebuilt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandlerSource {
    /// `"build": "workspace:<crate>"` — compiled from a workspace member.
    ///
    /// Legal only in vmcell's committed baseline, for vmcell-owned defaults, where identity is the
    /// source-closure hash the cache already folds. A consumer overlay carrying one is rejected
    /// naming the digest route: a workspace build in a consumer's overlay would name a crate that
    /// consumer's workspace does not have, and "build whatever is at that name today" is precisely
    /// what a registry may not mean.
    WorkspaceBuild {
        /// The workspace member to build, e.g. `vmcell-guest-tools`.
        crate_name: String,
    },
    /// A digest-pinned download — the consumer form, authoritative and verified before use.
    Registered {
        /// The `sha256:<64 lowercase hex>` digest of the handler binary. Authoritative: the `source` below is
        /// a fetch *instruction*, and a digest stored but never checked has passing output
        /// identical to its not-running output.
        digest: String,
        /// Where to fetch it from.
        url: String,
    },
    /// `"unpinned_path": "/path/to/handler"` — the **dev path-override** (§10.5, F7), the third and
    /// last shape.
    ///
    /// The one shape whose identity is not a digest: it means "whatever is at that location today",
    /// which is exactly why it is a *development* registration. The consequences follow from that
    /// one sentence and are enforced rather than documented — the stage reads the file's content
    /// hash into its cache key (so editing the file re-keys the artifact), resolution `warn!`s, and
    /// `vmcell bundle` refuses an artifacts dir whose resolved pins name one, because a bundle is a
    /// durable provenance claim and this shape cannot make one.
    UnpinnedPath {
        /// The local file whose bytes **are** the handler, exactly as registered.
        path: std::path::PathBuf,
    },
    /// `vmcell oci2-erofs --tools <path>` — a prebuilt handler binary injected verbatim, the
    /// missing mirror of `--steward-musl` (§4.2, §18 delta 7).
    ///
    /// **Not a registration shape.** No pins key produces it and the `handlers` entry parser never
    /// returns it; it exists so a repack can run from **outside a vmcell checkout**, where the
    /// workspace build ([`HandlerSource::WorkspaceBuild`]) has no sources to compile and would
    /// otherwise leave the operator with a rootfs carrying no applets.
    ///
    /// **Its identity is the file's content hash and nothing else** — never the path string (F4
    /// rule 3), exactly as the `--steward-musl` fold works. That is the one place it differs from
    /// [`HandlerSource::UnpinnedPath`], and the difference is the shapes': an unpinned
    /// *registration* is a durable line in a pins file, so the path it names is part of what was
    /// registered, while `--tools` is a per-run argument whose path is scratch — a CI job staging
    /// the same binary under a fresh temp dir every run must hit the cache, not re-pack.
    Prebuilt {
        /// The local file whose bytes are injected as the handler.
        path: std::path::PathBuf,
    },
}

/// One entry of the merged `handlers` registry (§10.5, v33 delta 6).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HandlerRegistryEntry {
    /// The registry label — the `handlers.<label>` key and the `guest_tools-<label>` artifact name.
    pub label: String,
    /// Where this handler's bytes come from.
    pub source: HandlerSource,
    /// The applet roster injected as `<tools_dir>/<applet>` symlinks beside the binary.
    ///
    /// Empty for the default entry, whose roster is [`vmcell_protocol::GUEST_TOOLS_APPLETS`] — the
    /// const the guest binary's dispatch table is compile-time asserted against. A consumer's
    /// handler has no such const to assert against, so its roster is data, strict-parsed here.
    pub applets: Vec<String>,
}

impl HandlerRegistryEntry {
    /// The applet roster to inject for this entry: its own, or the default handler's shared const.
    ///
    /// The one place the two rosters meet, so no injection site has to know which kind of entry it
    /// is holding.
    #[must_use]
    pub fn applet_roster(&self) -> Vec<String> {
        if self.applets.is_empty() {
            vmcell_protocol::GUEST_TOOLS_APPLETS
                .iter()
                .map(|a| (*a).to_string())
                .collect()
        } else {
            self.applets.clone()
        }
    }
}

/// Parses one `handlers.<label>` entry — **strictly** (§10.5, F7).
///
/// Exactly one registration shape per entry: `build`, `digest`, or the `unpinned_path` dev
/// override — never two and never none. "Nothing else parses" is F7's own wording, and it is what
/// keeps a registry entry from meaning "whatever is at that location today" **by accident**; the
/// override is the one shape that means it deliberately, under its own named key, and pays for it
/// at `bundle`.
///
/// # Errors
/// [`Error::Artifact`] naming the label and what is wrong with it.
pub(crate) fn handler_registry_entry(
    label: &str,
    spec: &serde_json::Value,
) -> Result<HandlerRegistryEntry> {
    use crate::artifact::registry::UNPINNED_PATH_KEY;
    let obj = spec.as_object().ok_or_else(|| {
        Error::Artifact(format!(
            "pins `handlers.{label}` must be an object naming exactly one registration shape: \
             `build` (a workspace member, vmcell's own defaults only), `digest` + `source.url`, or \
             `{UNPINNED_PATH_KEY}` (the dev override)"
        ))
    })?;
    for key in obj.keys() {
        if !matches!(key.as_str(), "build" | "digest" | "source" | "applets")
            && key != UNPINNED_PATH_KEY
        {
            return Err(Error::Artifact(format!(
                "pins `handlers.{label}` carries unknown key `{key}`; a silently ignored \
                 declaration is one a consumer builds a fixture on (known keys: build, digest, \
                 source, applets, {UNPINNED_PATH_KEY})"
            )));
        }
    }

    let build = obj.get("build").and_then(|v| v.as_str());
    let digest = obj.get("digest").and_then(|v| v.as_str());
    let unpinned = obj.get(UNPINNED_PATH_KEY);
    // The shape-exclusivity law is the shared one (`reject_multiple_registration_shapes`), applied
    // to this kind's three shape keys. Checked BEFORE any of them is read, so an entry naming two
    // shapes is refused naming both rather than silently resolving to whichever the match arm
    // below happens to reach first.
    crate::artifact::registry::reject_multiple_registration_shapes(
        "handlers",
        label,
        &[
            ("build", build.is_some()),
            ("digest", digest.is_some()),
            (UNPINNED_PATH_KEY, unpinned.is_some()),
        ]
        .iter()
        .filter(|(_, present)| *present)
        .map(|(k, _)| *k)
        .collect::<Vec<_>>(),
    )?;
    if let Some(value) = unpinned {
        let path = crate::artifact::registry::unpinned_path_registration("handlers", label, value)?;
        return Ok(HandlerRegistryEntry {
            label: label.to_string(),
            source: HandlerSource::UnpinnedPath { path },
            applets: handler_entry_applets(label, obj)?,
        });
    }
    let source = match (build, digest) {
        // Unreachable by construction — the exclusivity law above already refused it — but written
        // as a refusal rather than an `unreachable!` because a future fourth shape landing without
        // its exclusivity entry must fail loud, not panic in a library.
        (Some(_), Some(_)) => {
            return Err(Error::Artifact(format!(
                "pins `handlers.{label}` names BOTH `build` and `digest`: an entry has exactly one \
                 registration shape, or the two could disagree about which bytes the label means"
            )));
        }
        (None, None) => {
            return Err(Error::Artifact(format!(
                "pins `handlers.{label}` names none of `build`, `digest` or `{UNPINNED_PATH_KEY}`: \
                 registration is a digest (§10.5, F7) — an absent source would make the label mean \
                 \"whatever is at that location today\", which no consumer's provenance discipline \
                 can cite"
            )));
        }
        (Some(build), None) => {
            let crate_name = build.strip_prefix("workspace:").ok_or_else(|| {
                Error::Artifact(format!(
                    "pins `handlers.{label}.build` must be `workspace:<crate>`, got `{build}`"
                ))
            })?;
            if crate_name.is_empty() {
                return Err(Error::Artifact(format!(
                    "pins `handlers.{label}.build` names no crate after `workspace:`"
                )));
            }
            HandlerSource::WorkspaceBuild {
                crate_name: crate_name.to_string(),
            }
        }
        (None, Some(digest)) => {
            crate::artifact::registry::reject_unpinned_digest("handlers", label, digest)?;
            let url = obj
                .get("source")
                .and_then(|s| s.get("url"))
                .and_then(|v| v.as_str())
                .filter(|u| !u.is_empty())
                .ok_or_else(|| {
                    Error::Artifact(format!(
                        "pins `handlers.{label}` pins a digest but names no `source.url` to fetch \
                         it from; the digest is authoritative and the source is the instruction \
                         verified against it"
                    ))
                })?;
            HandlerSource::Registered {
                digest: digest.to_string(),
                url: url.to_string(),
            }
        }
    };

    let applets = handler_entry_applets(label, obj)?;
    if let HandlerSource::WorkspaceBuild { .. } = source
        && !applets.is_empty()
    {
        return Err(Error::Artifact(format!(
            "pins `handlers.{label}` names both a workspace `build` and an `applets` roster: a \
             workspace handler's roster is `vmcell_protocol::GUEST_TOOLS_APPLETS`, the const its \
             dispatch table is compile-time asserted against, so a second roster here could only \
             disagree with it"
        )));
    }

    Ok(HandlerRegistryEntry {
        label: label.to_string(),
        source,
        applets,
    })
}

/// Parses one entry's `applets` roster — strict-parsed, because the const-assert that keeps the
/// default handler's roster honest binds the **default** handler only.
///
/// Extracted so the digest shape and the `unpinned_path` shape read one roster law: an unpinned
/// handler is a consumer's own binary exactly as a registered one is, so its roster is data too,
/// and a second inline copy of this parse is how the two shapes come to accept different names.
///
/// # Errors
/// [`Error::Artifact`] naming the label when the value is not an array of non-empty bare names.
fn handler_entry_applets(
    label: &str,
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<String>> {
    let Some(value) = obj.get("applets") else {
        return Ok(Vec::new());
    };
    let array = value.as_array().ok_or_else(|| {
        Error::Artifact(format!(
            "pins `handlers.{label}.applets` must be an array of applet names \
             (e.g. [\"acme-probe\"]), each injected as one `<tools_dir>/<name>` symlink"
        ))
    })?;
    array
        .iter()
        .map(|item| match item.as_str() {
            // A name that is not a bare file name would inject a symlink outside the tools
            // dir, which `is_reserved_injection_path` guards for vmcell's own paths but
            // cannot guard for a roster it is handed.
            Some(name)
                if !name.is_empty() && !name.contains('/') && name != "." && name != ".." =>
            {
                Ok(name.to_string())
            }
            _ => Err(Error::Artifact(format!(
                "pins `handlers.{label}.applets` must hold non-empty bare NAMES with no \
                 path separator, got {item}"
            ))),
        })
        .collect::<Result<Vec<String>>>()
}

/// The lowercase-hex SHA-256 of `bytes`, as the registry's digests are written.
#[must_use]
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    let out: [u8; 32] = h.finalize().into();
    out.iter().map(|b| format!("{b:02x}")).collect()
}

/// Verifies fetched `bytes` against a registered `digest`, failing loud on a mismatch.
///
/// **The verification is the whole assertion** (§10.5): a digest stored and never checked has
/// passing output identical to its not-running output, which is why the delta's gate corrupts one
/// byte of a cached blob and demands the build fail naming the mismatch.
///
/// # Errors
/// [`Error::Artifact`] naming the label, the expected digest and the one actually computed.
pub(crate) fn verify_handler_digest(label: &str, digest: &str, bytes: &[u8]) -> Result<()> {
    let expected = digest.strip_prefix("sha256:").unwrap_or(digest);
    let got = sha256_hex(bytes);
    if got == expected {
        return Ok(());
    }
    Err(Error::Artifact(format!(
        "handler `{label}` digest mismatch: pins say sha256:{expected}, the fetched bytes are \
         sha256:{got}. Registration is a digest and the digest is authoritative — vmcell will not \
         inject bytes it cannot identify."
    )))
}

/// Whether `path` names a file whose bytes match `digest` — the offline cache-hit check.
pub(crate) async fn cached_blob_matches(path: &Path, digest: &str) -> bool {
    match tokio::fs::read(path).await {
        Ok(bytes) => sha256_hex(&bytes) == digest.strip_prefix("sha256:").unwrap_or(digest),
        Err(_) => false,
    }
}
