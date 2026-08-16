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
    #[must_use]
    pub fn labelled(label: Option<&str>, source: Option<HandlerSource>) -> Self {
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
        const STAGE_VERSION: u32 = 3;
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
                match crate::artifact::guest_tools_closure_hash(&crate::artifact::workspace_root())
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
    /// Compiles the handler from a workspace member and publishes it at `out`.
    async fn publish_workspace_build(&self, out: &Path) -> Result<()> {
        // v15 workspace: the helper is its own member crate, built by `-p` from the
        // workspace root into the shared workspace `target/`.
        let ws_root = crate::artifact::workspace_root();
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
}
