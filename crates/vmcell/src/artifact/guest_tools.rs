use crate::artifact::handler::{
    HandlerSource, cached_blob_matches, handler_artifact_key, handler_filename,
    verify_handler_digest,
};
use crate::artifact::kernel::{HttpClient, ReqwestClient};
use crate::artifact::{CacheKey, Stage, StageInputs, StageOutputs};
use crate::error::{Error, Result};
use async_trait::async_trait;
use std::path::Path;
use std::sync::Arc;

/// A pipeline stage that produces one **handler** artifact — the guest binary baked into the rootfs
/// at the tools path (design §10.5, v33 delta 6).
///
/// The default handler is `vmcell-guest-tools`, the test-helper multicall binary (the
/// `ip`/`curl`/`kvm-ok`/`echo-server`/`mini-init` stand-ins), built from the workspace exactly as
/// before v33 — now *stated in data* by `handlers.default` instead of hardcoded here. A registered
/// handler is a digest-pinned download, verified before it is published (F7).
///
/// Baking (rather than a virtio-fs share) is what lets the unprivileged egress test use the tools:
/// virtiofsd cannot enter its `--sandbox namespace` without privileges, so a share would fail
/// unprivileged, whereas the erofs rootfs is served over virtio-blk in both modes.
pub struct GuestToolsStage {
    /// The `handlers` registry label this stage produces; `None` is `handlers.default`.
    label: Option<String>,
    /// Where the bytes come from. `None` means the pre-v33 behavior — build
    /// `vmcell-guest-tools` from the workspace — which is also what `handlers.default` resolves to.
    source: Option<HandlerSource>,
    /// [`Stage::name`]'s return value, composed from `label` at construction (the same precomputed
    /// -name reason `RootfsStage` carries).
    stage_name: String,
    /// The fetch seam for a registered handler. Unused by the workspace-build path.
    http_client: Arc<dyn HttpClient>,
}

impl std::fmt::Debug for GuestToolsStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestToolsStage")
            .field("label", &self.label)
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl Default for GuestToolsStage {
    fn default() -> Self {
        Self::new()
    }
}

impl GuestToolsStage {
    /// The default handler stage: `handlers.default`, built from the workspace.
    ///
    /// Byte-identical in every observable to the pre-v33 `GuestToolsStage {}`.
    #[must_use]
    pub fn new() -> Self {
        Self::labelled(None, None)
    }

    /// A stage producing the named registry label from `source`; `None`/`None` is the default.
    ///
    /// **The reserved `default` spelling normalizes to `None`** — through
    /// [`crate::artifact::registry::registry_label`], the one predicate that says the default label
    /// contributes no suffix. §10.5's "canonical artifacts stay byte-identical for a cell that names
    /// no label" is a claim about the artifact, and `Some("default")` composed `guest_tools-default`:
    /// a different stage name, artifact key, output file and cache key than the omitted spelling, for
    /// the one entry both spell. `vmcell build --handler-label default` — committed pins, no overlay
    /// — was that build, and it packed a rootfs the labelled artifact never reached.
    ///
    /// Normalized here, at the one intake, because every observable this stage has (`name`,
    /// `out_path`, `cache_key`, the published artifact key) derives from the stored label: a caller
    /// that normalized at its own composition root would fix its own path and leave the next one.
    #[must_use]
    pub fn labelled(label: Option<&str>, source: Option<HandlerSource>) -> Self {
        let label = label.and_then(crate::artifact::registry::registry_label);
        GuestToolsStage {
            label: label.map(str::to_string),
            source,
            stage_name: handler_artifact_key(label),
            http_client: Arc::new(ReqwestClient),
        }
    }

    /// Replaces the fetch seam (tests drive a recording client rather than the network).
    #[must_use]
    pub fn with_http_client(mut self, client: Arc<dyn HttpClient>) -> Self {
        self.http_client = client;
        self
    }

    /// The registry label this stage produces, as the key composers take it.
    #[must_use]
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// The workspace member this stage compiles, for a workspace-build handler.
    fn workspace_crate(&self) -> &str {
        match &self.source {
            Some(HandlerSource::WorkspaceBuild { crate_name }) => crate_name,
            // `None` is the pre-v33 default, which is `handlers.default`'s own `build` value.
            _ => "vmcell-guest-tools",
        }
    }
}

#[async_trait]
impl Stage for GuestToolsStage {
    fn name(&self) -> &str {
        &self.stage_name
    }

    fn out_path(&self, target_dir: &Path) -> std::path::PathBuf {
        target_dir.join(handler_filename(self.label()))
    }

    fn cache_key(&self, _inputs: &StageInputs) -> CacheKey {
        // Bump when this stage's build logic changes so a stale helper is not served.
        // Bumped to 2 with the Cargo.lock-aware closure hash.
        // Bumped to 3 with v33 delta 6: the stage folds its registration identity (label + source),
        // so a registered handler cannot be served from a workspace build's cache entry.
        // Bumped to 4 with v33 delta 6c: the fold gained the F7 `unpinned_path` arm.
        const STAGE_VERSION: u32 = 4;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&STAGE_VERSION.to_le_bytes());
        hasher.update(self.label().unwrap_or_default().as_bytes());
        hasher.update(b"\0");
        match &self.source {
            Some(HandlerSource::Registered { digest, url }) => {
                // A registered handler's identity IS its digest: the fetch is an instruction, and
                // re-pointing the url without moving the digest must not re-download (and moving
                // the digest must invalidate, which is what makes the verify meaningful).
                hasher.update(b"registered\0");
                hasher.update(digest.as_bytes());
                hasher.update(b"\0");
                hasher.update(url.as_bytes());
            }
            Some(HandlerSource::UnpinnedPath { path }) => {
                // The F7 dev override (§10.5, §18 delta 6c). A registered handler's identity is its
                // digest because the digest IS the promise; an unpinned one promises nothing — it
                // means "whatever is at that location today" — so its identity is read FROM THE
                // FILE. Path and content both: the path so two labels pointing at different files
                // stay two artifacts, the content hash so an in-place `cargo build` of the pointed
                // -at helper re-keys instead of re-baking yesterday's binary into the rootfs.
                hasher.update(b"unpinned\0");
                hasher.update(path.as_os_str().as_encoded_bytes());
                hasher.update(b"\0");
                match crate::artifact::hash_file(path) {
                    Ok(h) => hasher.update(h.as_bytes()),
                    // A read failure folds a DISTINCT marker rather than degrading to a stable,
                    // content-blind key that hits a stale cache — the same ART-11 rule the
                    // workspace arm below applies to its closure hash.
                    Err(e) => hasher.update(format!("unpinned-handler-read-error:{e}").as_bytes()),
                };
            }
            Some(HandlerSource::Prebuilt { path }) => {
                // The `--tools` per-run override (§4.2, §18 delta 7). Its identity is the file's
                // CONTENT and nothing else — the path string is deliberately NOT folded (F4 rule
                // 3), so the same binary staged under a fresh temp dir on every CI run is one
                // artifact rather than one per run. This is where it parts company with
                // `UnpinnedPath` above, whose path IS part of the registration that was written
                // down. A read failure folds a distinct marker rather than degrading to a stable,
                // content-blind key that hits a stale cache — the same ART-11 rule the other
                // path-shaped arms apply.
                hasher.update(b"prebuilt\0");
                match crate::artifact::hash_file(path) {
                    Ok(h) => hasher.update(h.as_bytes()),
                    Err(e) => hasher.update(format!("prebuilt-handler-read-error:{e}").as_bytes()),
                };
            }
            Some(HandlerSource::WorkspaceBuild { .. }) | None => {
                hasher.update(b"workspace\0");
                hasher.update(self.workspace_crate().as_bytes());
                hasher.update(b"\0");
                // Fold the helper's FULL source closure — its `.rs` source PLUS `Cargo.lock`
                // — so a change rebuilds it and, transitively (via the rootfs stage's content
                // hash of this artifact), re-bakes the rootfs. Folding `Cargo.lock` is what
                // catches a dependency bump: the helper links reqwest/rustls, so a bump
                // changes the BUILT binary while the `.rs` is byte-identical. The old
                // source-only hash missed that and re-served a stale ip/curl/kvm-ok helper.
                match self
                    .require_source_checkout()
                    .and_then(|root| crate::artifact::guest_tools_closure_hash(&root))
                {
                    Ok(h) => hasher.update(h.as_bytes()),
                    // A read failure must NOT silently degrade to a stable, content-blind key
                    // that hits a stale cache (the old `if let Ok(content)` swallow). Fold the
                    // error so the key cannot collide with a good one; the resulting cache miss
                    // drives `run()`, which recomputes via the same Result helper and fails hard
                    // with the real cause.
                    Err(e) => hasher.update(format!("guest-tools-closure-error:{e}").as_bytes()),
                };
            }
        }
        CacheKey(format!("guest-tools-{}", hasher.finalize().to_hex()))
    }

    async fn run(&self, _inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        match &self.source {
            Some(HandlerSource::Registered { digest, url }) => {
                self.publish_registered(out, digest, url).await?;
            }
            Some(HandlerSource::UnpinnedPath { path }) => {
                self.publish_unpinned(out, path).await?;
            }
            Some(HandlerSource::Prebuilt { path }) => {
                self.publish_prebuilt(out, path).await?;
            }
            Some(HandlerSource::WorkspaceBuild { .. }) | None => {
                self.publish_workspace_build(out).await?;
            }
        }
        let mut outputs = StageOutputs::default();
        outputs
            .artifacts
            .insert(handler_artifact_key(self.label()), out.to_path_buf());
        Ok(outputs)
    }
}

impl GuestToolsStage {
    /// The **one** "can a workspace build even happen here" answer (§4.2, §18 delta 7), shared by
    /// [`Stage::cache_key`]'s workspace arm and [`Self::publish_workspace_build`].
    ///
    /// A workspace build is the one handler shape that needs vmcell's own sources on disk. Outside
    /// a checkout there are none, and the pre-delta-7 code asked [`crate::artifact::workspace_root`]
    /// — which *always* answers, falling back to the caller's own directory — so a repack from a
    /// consumer's workspace either shelled `cargo build -p vmcell-guest-tools` into that
    /// workspace or died on a bare "binary source missing at …" naming a path the operator never
    /// wrote. Neither says what to pass. This does.
    ///
    /// Inside a checkout it returns exactly what `workspace_root()` returns, so the default
    /// stage's cache key is unmoved by delta 7.
    ///
    /// # Errors
    /// [`Error::Artifact`] naming the crate that cannot be built, the directory searched, and the
    /// two ways to supply the binary instead (`--tools`, or a digest-pinned registration).
    fn require_source_checkout(&self) -> Result<std::path::PathBuf> {
        let crate_name = self.workspace_crate();
        crate::artifact::vmcell_source_root().ok_or_else(|| {
            Error::Artifact(format!(
                "cannot build `{crate_name}` here: this is not a vmcell source checkout (no \
                 `crates/vmcell-protocol/Cargo.toml` above {}), and a workspace build is the one \
                 handler shape that needs vmcell's own sources. Pass `--tools <path>` with a \
                 prebuilt `{crate_name}` binary — the mirror of `--steward-musl` (§4.2) — or \
                 register a digest-pinned handler (§10.5). Refusing rather than packing a rootfs \
                 with no applets in it.",
                crate::artifact::workspace_root().display()
            ))
        })
    }

    /// Publishes the `--tools` per-run override's bytes as this label's handler (§4.2, §18 delta
    /// 7) — no build, no download, and therefore no cargo and no checkout.
    ///
    /// The mirror of `--steward-musl`, which skips its stage entirely; a handler has nowhere to be
    /// skipped *to* (the rootfs pack tail reads the artifact map), so the stage stays and its
    /// source becomes the file.
    ///
    /// # Errors
    /// [`Error::Artifact`] naming the flag AND the path when the file cannot be read: `--tools` is
    /// an operator's per-run claim about a file, and a claim that is wrong must not degrade into a
    /// silent workspace build.
    async fn publish_prebuilt(&self, out: &Path, path: &Path) -> Result<()> {
        if let Some(parent) = out.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::copy(path, out).await.map_err(|e| {
            Error::Artifact(format!(
                "`--tools {}` could not be read: {e}. It must name a prebuilt \
                 `{}` binary (§4.2, the `--steward-musl` mirror)",
                path.display(),
                self.workspace_crate()
            ))
        })?;
        // Same reason the registered and unpinned arms set it: the handler is exec'd in-guest
        // through the tools-dir symlinks and the packer's mode heuristic reads the injected file's
        // own mode. Set unconditionally rather than copied, so a binary that lost its exec bit in
        // transit (a CI artifact unzipped, say) still boots.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            tokio::fs::set_permissions(out, std::fs::Permissions::from_mode(0o755)).await?;
        }
        Ok(())
    }

    /// Compiles the handler from a workspace member and publishes it at `out`.
    async fn publish_workspace_build(&self, out: &Path) -> Result<()> {
        // v15 workspace: the helper is its own member crate, built by `-p` from the
        // workspace root into the shared workspace `target/`. `require_source_checkout` is the one
        // predicate that says whether those sources are here at all (§4.2, §18 delta 7) — asked
        // BEFORE `cargo` is spawned, so a consumer-position run is refused naming `--tools`
        // instead of compiling into somebody else's workspace.
        let ws_root = self.require_source_checkout()?;
        // Fail hard if the helper's source closure (`.rs` source + `Cargo.lock`) is
        // unreadable — never silently build and serve a stale helper. Mirrors the
        // steward stage's run()-side hard stop; the returned hash is needed only
        // for its error effect here.
        crate::artifact::guest_tools_closure_hash(&ws_root)?;

        let crate_name = self.workspace_crate();
        // Built dynamically (no crt-static): the helper links reqwest/rustls
        // (aws-lc-rs C code) which does not link cleanly fully-static, and the
        // Debian rootfs ships glibc, so a dynamic binary runs there. The helper
        // only talks to the proxy/host by IP, so static-glibc DNS limits never
        // apply.
        let build_status = tokio::process::Command::new("cargo")
            .current_dir(&ws_root)
            .arg("build")
            .arg("--release")
            .arg("--target")
            .arg("x86_64-unknown-linux-gnu")
            .arg("-p")
            .arg(crate_name)
            .status()
            .await?;
        if !build_status.success() {
            return Err(Error::Subprocess(format!("Failed to build {crate_name}")));
        }

        let target_dir = std::env::var("CARGO_TARGET_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| ws_root.join("target"));
        let tools_path = target_dir.join(format!("x86_64-unknown-linux-gnu/release/{crate_name}"));

        tokio::fs::copy(tools_path, out).await.map_err(Error::Io)?;
        Ok(())
    }

    /// Publishes an F7 dev path-override's local file as this label's handler (§10.5, §18 delta
    /// 6c) — no download, and therefore no digest to verify against.
    ///
    /// There is deliberately nothing to verify here: the shape's whole meaning is "whatever is at
    /// that location today", and a check invented for it would be a provenance claim vmcell cannot
    /// back. What replaces the verify is the *identity* — `cache_key` reads the file's content hash
    /// — plus the resolution `warn!` and `bundle`'s refusal.
    ///
    /// # Errors
    /// [`Error::Artifact`] naming the label AND the path when the file cannot be read: an unpinned
    /// registration's whole failure mode is that the path stopped being true since it was written.
    async fn publish_unpinned(&self, out: &Path, path: &Path) -> Result<()> {
        let label = self.label().unwrap_or("default");
        if let Some(parent) = out.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::copy(path, out).await.map_err(|e| {
            Error::Artifact(format!(
                "handler `{label}` is registered through the `{}` dev override at {}, which could \
                 not be read: {e}. An unpinned registration means \"whatever is at that path \
                 today\" (§10.5, F7) — point it at a readable binary, or register a digest + \
                 `source.url`",
                crate::artifact::registry::UNPINNED_PATH_KEY,
                path.display()
            ))
        })?;
        // Same reason the registered arm sets it: the handler is exec'd in-guest through the
        // tools-dir symlinks, and the packer's mode heuristic reads the injected file's own mode.
        // Set unconditionally rather than copied from the source file, so a dev override that lost
        // its exec bit (a `cargo build` output moved through a zip, say) still boots.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            tokio::fs::set_permissions(out, std::fs::Permissions::from_mode(0o755)).await?;
        }
        Ok(())
    }

    /// Fetches a registered handler, **verifies it against its digest**, and publishes it at `out`.
    ///
    /// The verification is the whole assertion (§10.5): a digest stored and never checked has
    /// passing output identical to its not-running output. The cache hit is digest-keyed too, so an
    /// already-correct blob at `out` skips the fetch entirely — offline-friendly by the same rule
    /// that makes it safe.
    async fn publish_registered(&self, out: &Path, digest: &str, url: &str) -> Result<()> {
        let label = self.label().unwrap_or("default");
        if cached_blob_matches(out, digest).await {
            return Ok(());
        }
        let bytes = self.http_client.get(url).await?;
        verify_handler_digest(label, digest, &bytes)?;
        if let Some(parent) = out.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(out, &bytes).await?;
        // The handler is exec'd in-guest through the tools-dir symlinks, so it has to be
        // executable on the host side too — the packer's mode heuristic reads the injected file's
        // own mode. A downloaded blob arrives 0644.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            tokio::fs::set_permissions(out, std::fs::Permissions::from_mode(0o755)).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::handler::sha256_hex;

    /// A recording fetch seam: no network, and it reports what it was asked for.
    struct FakeHttp {
        body: Vec<u8>,
        calls: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait]
    impl HttpClient for FakeHttp {
        async fn get(&self, url: &str) -> Result<Vec<u8>> {
            self.calls.lock().expect("lock").push(url.to_string());
            Ok(self.body.clone())
        }
    }

    fn registered(digest: &str) -> HandlerSource {
        HandlerSource::Registered {
            digest: digest.to_string(),
            url: "https://example.invalid/acme-handler".to_string(),
        }
    }

    // F7's core claim, and the one the design says the gate must corrupt a byte to prove: the
    // digest is AUTHORITATIVE, so bytes that do not match it are refused rather than published.
    // RED on a `publish_registered` that writes first and verifies never — which is exactly the
    // shape whose passing output is identical to its not-running output.
    #[tokio::test]
    async fn a_registered_handler_whose_bytes_do_not_match_its_digest_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("guest_tools-acme");
        let http = Arc::new(FakeHttp {
            body: b"the wrong bytes".to_vec(),
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let stage = GuestToolsStage::labelled(
            Some("acme"),
            Some(registered(&format!(
                "sha256:{}",
                sha256_hex(b"the right bytes")
            ))),
        )
        .with_http_client(http.clone());

        let err = stage
            .run(&StageInputs::default(), &out)
            .await
            .expect_err("a digest mismatch is a provenance hard stop");
        assert!(
            err.to_string().contains("digest mismatch"),
            "the failure must name the mismatch: {err}"
        );
        assert!(
            !out.exists(),
            "refused bytes must not be published — a consumer that reads the artifact anyway would \
             get exactly what the verify rejected"
        );

        // Positive control: the same fetch with the digest that matches publishes, so the refusal
        // is about the bytes and not about registered handlers in general.
        let stage = GuestToolsStage::labelled(
            Some("acme"),
            Some(registered(&format!(
                "sha256:{}",
                sha256_hex(b"the wrong bytes")
            ))),
        )
        .with_http_client(http);
        stage
            .run(&StageInputs::default(), &out)
            .await
            .expect("matching bytes publish");
        assert_eq!(
            tokio::fs::read(&out).await.expect("read"),
            b"the wrong bytes"
        );
    }

    // A digest-keyed cache hit skips the fetch entirely — offline-friendly by the same rule that
    // makes it safe (§10.5's "the fetch stays cacheable and offline-friendly"). RED on a `run` that
    // re-downloads unconditionally: the call count goes to 1.
    #[tokio::test]
    async fn an_already_correct_blob_skips_the_fetch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("guest_tools-acme");
        tokio::fs::write(&out, b"already here").await.expect("seed");
        let http = Arc::new(FakeHttp {
            body: b"already here".to_vec(),
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let stage = GuestToolsStage::labelled(
            Some("acme"),
            Some(registered(&format!(
                "sha256:{}",
                sha256_hex(b"already here")
            ))),
        )
        .with_http_client(http.clone());
        stage
            .run(&StageInputs::default(), &out)
            .await
            .expect("the cached blob satisfies the registration");
        assert!(
            http.calls.lock().expect("lock").is_empty(),
            "a blob that already matches the digest must not be re-fetched"
        );

        // And a CORRUPTED cached blob is not trusted: one flipped byte and the fetch runs again.
        tokio::fs::write(&out, b"already herX")
            .await
            .expect("corrupt");
        stage
            .run(&StageInputs::default(), &out)
            .await
            .expect("the corrupt blob is replaced");
        assert_eq!(
            http.calls.lock().expect("lock").len(),
            1,
            "a cached blob whose digest no longer matches must be re-fetched, not served"
        );
    }

    // The stage's identity folds its registration, so a registered handler cannot be served from a
    // workspace build's cache entry — nor one digest's blob from another digest's key.
    #[tokio::test]
    async fn the_cache_key_folds_the_registration_identity() {
        let inputs = StageInputs::default();
        let ws = GuestToolsStage::new().cache_key(&inputs);
        let a = GuestToolsStage::labelled(
            Some("acme"),
            Some(registered(&format!("sha256:{}", "a".repeat(64)))),
        )
        .cache_key(&inputs);
        let b = GuestToolsStage::labelled(
            Some("acme"),
            Some(registered(&format!("sha256:{}", "b".repeat(64)))),
        )
        .cache_key(&inputs);
        assert_ne!(ws, a, "a registered handler is not a workspace build");
        assert_ne!(a, b, "two digests are two artifacts");

        // And the DEFAULT stage's key is unmoved by the label plumbing: `handlers.default` resolves
        // to the same workspace build it always did.
        let explicit_default = GuestToolsStage::labelled(
            None,
            Some(HandlerSource::WorkspaceBuild {
                crate_name: "vmcell-guest-tools".to_string(),
            }),
        )
        .cache_key(&inputs);
        assert_eq!(
            ws, explicit_default,
            "naming the default registration explicitly must not move the default's cache key"
        );
    }

    // F7's dev override, honored (§10.5, §18 delta 6c). Three claims, because an accepted-but-
    // ignored override would satisfy any two of them:
    //
    //  1. the pointed-at BYTES are what gets published — asserted on content, never on "the file
    //     exists", which a workspace build would also satisfy;
    //  2. editing the pointed-at file MOVES the stage's cache key, because an unpinned registration
    //     means "whatever is at that location today" and an identity read from the registration
    //     alone would serve yesterday's binary forever;
    //  3. a path that does not exist is a loud error naming the label AND the path.
    //
    // RED on the inverse, three ways: (1) a `run` arm that falls through to the workspace build —
    // the published bytes are a compiled binary, not the fixture's; (2) a `cache_key` that folds
    // only the path string — the two keys in claim 2 are equal; (3) a `publish_unpinned` that
    // swallows the copy error — `run` returns Ok with no file at `out`.
    #[tokio::test]
    async fn an_unpinned_handler_publishes_the_pointed_at_bytes_and_tracks_their_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("my-handler");
        std::fs::write(&src, b"#!/bin/sh\necho v1\n").expect("seed the override target");
        let out = dir.path().join("guest_tools-acme");
        let unpinned = |p: &std::path::Path| HandlerSource::UnpinnedPath {
            path: p.to_path_buf(),
        };
        let stage = GuestToolsStage::labelled(Some("acme"), Some(unpinned(&src)));

        // 1. The bytes.
        stage
            .run(&StageInputs::default(), &out)
            .await
            .expect("the dev override publishes");
        assert_eq!(
            tokio::fs::read(&out)
                .await
                .expect("read the published file"),
            b"#!/bin/sh\necho v1\n",
            "the override's own bytes must be published, not a workspace build's"
        );
        // …executable, because the guest execs it through the tools-dir symlinks and the packer's
        // mode heuristic reads the injected file's own mode.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&out).expect("stat").permissions().mode() & 0o111,
                0o111,
                "a published handler must be executable"
            );
        }

        // 2. The identity tracks the FILE's content, not the registration string.
        let inputs = StageInputs::default();
        let before = stage.cache_key(&inputs);
        std::fs::write(&src, b"#!/bin/sh\necho v2\n").expect("edit the override target");
        assert_ne!(
            before,
            stage.cache_key(&inputs),
            "editing the pointed-at file must re-key: an unpinned registration's identity is read \
             from the file, because the registration itself promises nothing"
        );
        // …and an UNRELATED file moving does not, which is what makes the claim above non-vacuous
        // (a key that folded the whole directory would also pass the edit leg).
        let unrelated = dir.path().join("something-else");
        std::fs::write(&unrelated, b"noise").expect("write");
        let after_edit = stage.cache_key(&inputs);
        std::fs::write(&unrelated, b"more noise").expect("rewrite");
        assert_eq!(
            after_edit,
            stage.cache_key(&inputs),
            "a file this registration does not name must not move its key"
        );
        // Two labels pointing at DIFFERENT files are two artifacts even when the bytes agree.
        let twin = dir.path().join("twin-handler");
        std::fs::write(&twin, b"#!/bin/sh\necho v2\n").expect("write");
        assert_ne!(
            stage.cache_key(&inputs),
            GuestToolsStage::labelled(Some("acme"), Some(unpinned(&twin))).cache_key(&inputs),
            "two paths are two registrations, even with momentarily identical bytes"
        );

        // 3. A path that is not there is loud, and names both facts.
        let gone = dir.path().join("never-existed");
        let err = GuestToolsStage::labelled(Some("acme"), Some(unpinned(&gone)))
            .run(&StageInputs::default(), &dir.path().join("out-missing"))
            .await
            .expect_err("an unreadable override path is a hard stop");
        let msg = err.to_string();
        assert!(
            msg.contains("acme"),
            "the failure must name the label: {msg}"
        );
        assert!(
            msg.contains(&gone.display().to_string()),
            "the failure must name the path: {msg}"
        );
    }

    // §4.2's `--tools` half (v33 delta 7): a prebuilt handler is injected VERBATIM — no cargo, no
    // download, no checkout. Three claims, because an accepted-but-ignored `--tools` would satisfy
    // any two:
    //
    //  1. the pointed-at BYTES are published — asserted on content, never on "the file exists",
    //     which a workspace build would also satisfy;
    //  2. the published file is executable, because the guest execs it through the tools-dir
    //     symlinks and the packer's mode heuristic reads the injected file's own mode;
    //  3. a path that cannot be read is a loud error naming the FLAG and the path — never a
    //     silent fall-through to the workspace build, which is how an operator ends up with an
    //     image carrying no applets.
    //
    // The "does not shell out to cargo" half of the gate cannot be asserted in-process (PATH is
    // process-global) and lives in `tests/repack_outside_checkout.rs`, which sets it on a child.
    #[tokio::test]
    async fn a_prebuilt_handler_publishes_the_pointed_at_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("prebuilt-guest-tools");
        std::fs::write(&src, b"#!/bin/sh\necho prebuilt\n").expect("seed the --tools target");
        let out = dir.path().join("guest_tools");
        let stage =
            GuestToolsStage::labelled(None, Some(HandlerSource::Prebuilt { path: src.clone() }));

        stage
            .run(&StageInputs::default(), &out)
            .await
            .expect("`--tools` publishes");
        assert_eq!(
            tokio::fs::read(&out)
                .await
                .expect("read the published file"),
            b"#!/bin/sh\necho prebuilt\n",
            "`--tools`'s own bytes must be published, not a workspace build's"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&out).expect("stat").permissions().mode() & 0o111,
                0o111,
                "a published handler must be executable"
            );
        }

        let gone = dir.path().join("never-existed");
        let err =
            GuestToolsStage::labelled(None, Some(HandlerSource::Prebuilt { path: gone.clone() }))
                .run(&StageInputs::default(), &dir.path().join("out-missing"))
                .await
                .expect_err("an unreadable `--tools` path is a hard stop");
        let msg = err.to_string();
        assert!(
            msg.contains("--tools"),
            "the failure must name the flag the operator typed: {msg}"
        );
        assert!(
            msg.contains(&gone.display().to_string()),
            "the failure must name the path: {msg}"
        );
    }

    // F4 rule 3, on the shape the design names explicitly (§4.2): `--tools`'s identity is the
    // binary's CONTENT and nothing else, so a CI job that stages the same binary under a fresh
    // temp dir on every run hits the cache instead of re-packing. Its inverse — folding the path
    // string — is the defect this pins.
    //
    // The last leg is the *contrast*, and it is deliberate: `UnpinnedPath` (delta 6c) folds the
    // path TOO, because there the path is part of a registration somebody wrote down. Both
    // behaviors are pinned here so that a later "these two are the same thing, unify them" edit
    // reddens with the reason attached rather than silently changing one of them.
    #[test]
    fn the_prebuilt_key_is_the_content_not_the_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let inputs = StageInputs::default();
        let here = dir.path().join("here/vmcell-guest-tools");
        let there = dir.path().join("there/vmcell-guest-tools");
        for p in [&here, &there] {
            std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
            std::fs::write(p, b"the same binary").expect("write");
        }
        let prebuilt = |p: &std::path::Path| {
            GuestToolsStage::labelled(
                None,
                Some(HandlerSource::Prebuilt {
                    path: p.to_path_buf(),
                }),
            )
            .cache_key(&inputs)
        };
        assert_eq!(
            prebuilt(&here),
            prebuilt(&there),
            "the same binary at two paths is ONE artifact: `--tools` folds the content hash, never \
             the path string (F4 rule 3, §4.2)"
        );
        // …and the claim is not vacuous, which the equality alone cannot show: editing the file
        // at the SAME path must re-key.
        let before = prebuilt(&here);
        std::fs::write(&here, b"a different binary").expect("rewrite");
        assert_ne!(
            before,
            prebuilt(&here),
            "a changed binary at the same path must re-key, or yesterday's helper gets re-baked"
        );
        // …and a prebuilt override is not a workspace build, so it cannot be served from one's
        // cache entry.
        assert_ne!(
            prebuilt(&here),
            GuestToolsStage::new().cache_key(&inputs),
            "`--tools` bytes and a workspace build are two artifacts"
        );

        // The contrast (see the comment above): the registry's unpinned dev override folds the
        // path as well, so the same bytes at two paths stay two artifacts THERE.
        std::fs::write(&here, b"the same binary").expect("restore");
        let unpinned = |p: &std::path::Path| {
            GuestToolsStage::labelled(
                Some("acme"),
                Some(HandlerSource::UnpinnedPath {
                    path: p.to_path_buf(),
                }),
            )
            .cache_key(&inputs)
        };
        assert_ne!(
            unpinned(&here),
            unpinned(&there),
            "delta 6c's `unpinned_path` deliberately folds the path (a registration names one \
             location); if this ever equalizes, the two shapes have been unified — decide which \
             identity law wins and say so, do not let it drift"
        );
    }

    // The artifact key and the output path both derive from the label through the one law, so a
    // labelled handler cannot collide with the default on either.
    #[test]
    fn the_label_reaches_the_stage_name_and_the_out_path() {
        let dir = std::path::Path::new("/artifacts");
        assert_eq!(GuestToolsStage::new().name(), "guest_tools");
        assert_eq!(
            GuestToolsStage::new().out_path(dir),
            dir.join("guest_tools")
        );
        let acme = GuestToolsStage::labelled(Some("acme"), None);
        assert_eq!(acme.name(), "guest_tools-acme");
        assert_eq!(acme.out_path(dir), dir.join("guest_tools-acme"));
    }

    // §10.5's reserved default label, at the handler kind's one intake: `--handler-label default`
    // and no `--handler-label` are the SAME request, so they must compose the same artifact — every
    // observable, not merely the same registry entry.
    //
    // The defect this pins built a *different* artifact under the explicit spelling —
    // `guest_tools-default`, its own stage name, output file and cache key — while the rootfs pack
    // tail went looking for the handler the operator had named. So the assertion is over all four
    // observables at once: a normalization applied to the stage name but not to the cache key would
    // still split the warm cache.
    //
    // RED on the inverse (drop the `registry_label` call from `labelled`): the name, the out_path,
    // the cache key and the published artifact key all come back with the `-default` suffix. The
    // `acme` legs are what keep it non-vacuous — a `labelled` that ignored its label entirely would
    // pass every equality above and fail those.
    #[tokio::test]
    async fn the_explicit_default_handler_label_is_the_omitted_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("prebuilt-guest-tools");
        std::fs::write(&src, b"#!/bin/sh\necho default-spelling\n")
            .expect("seed the --tools target");
        let prebuilt = || {
            Some(HandlerSource::Prebuilt {
                path: src.to_path_buf(),
            })
        };
        let target = std::path::Path::new("/artifacts");
        let inputs = StageInputs::default();

        let omitted = GuestToolsStage::labelled(None, prebuilt());
        let explicit =
            GuestToolsStage::labelled(Some(crate::artifact::registry::DEFAULT_LABEL), prebuilt());
        assert_eq!(
            explicit.label(),
            None,
            "the reserved label IS the absent one"
        );
        assert_eq!(explicit.name(), omitted.name());
        assert_eq!(explicit.out_path(target), omitted.out_path(target));
        assert_eq!(
            explicit.cache_key(&inputs),
            omitted.cache_key(&inputs),
            "the two spellings must share one cache entry, or a warm artifacts dir re-fetches and \
             re-publishes the same bytes under a second name"
        );

        // …and the key the ROOTFS pack tail reads the binary from, which is the one that mattered:
        // the tail looks up `handler_artifact_key(label)`, so an artifact published under
        // `guest_tools-default` reached no image at all.
        let out = dir.path().join(handler_filename(explicit.label()));
        let published = explicit
            .run(&inputs, &out)
            .await
            .expect("the prebuilt override publishes");
        assert_eq!(
            published.artifacts.keys().collect::<Vec<_>>(),
            vec![&handler_artifact_key(None)],
            "`--handler-label default` must publish under the DEFAULT key and no other: {published:?}"
        );

        // Non-vacuity: a label that is NOT the reserved one keeps every one of those apart.
        let acme = GuestToolsStage::labelled(Some("acme"), prebuilt());
        assert_eq!(acme.label(), Some("acme"));
        assert_ne!(acme.name(), omitted.name());
        assert_ne!(acme.out_path(target), omitted.out_path(target));
        assert_ne!(acme.cache_key(&inputs), omitted.cache_key(&inputs));
    }
}
