use crate::artifact::{CacheKey, Stage, StageInputs, StageOutputs};
use crate::error::{Error, Result};
use async_trait::async_trait;
use std::path::Path;

/// A pipeline stage that builds the steward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StewardStage {}

impl StewardStage {
    /// Cache key anchored at an explicit workspace `ws_root`, so the source-closure fold is
    /// unit-testable against a fixture tree without touching the real workspace.
    ///
    /// Folds the steward's FULL source closure directly (M-ART-8), mirroring
    /// [`crate::artifact::guest_tools::GuestToolsStage`]. The old `steward_src_hash` pin
    /// fold degenerated to the empty string in any pipeline that did not run `ResolvePinsStage`
    /// to populate it, giving a stable, content-blind key that re-served a stale steward forever
    /// — the stage does not actually need the pin to travel. A closure-hash read failure folds
    /// a distinct error marker (never `unwrap_or_default()`'s `""`), so the resulting cache
    /// miss drives `run()`, which fails hard with the real cause.
    fn cache_key_for_root(&self, ws_root: &Path) -> CacheKey {
        // Bump when this stage's build logic changes so a stale steward is not served.
        // Bumped to 2 with the source-closure-hash key (M-ART-8).
        const STAGE_VERSION: u32 = 2;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&STAGE_VERSION.to_le_bytes());
        match crate::artifact::steward_closure_hash(ws_root) {
            Ok(h) => hasher.update(h.as_bytes()),
            Err(e) => hasher.update(format!("steward-closure-error:{e}").as_bytes()),
        };
        CacheKey(format!("steward-{}", hasher.finalize().to_hex()))
    }
}

#[async_trait]
impl Stage for StewardStage {
    fn name(&self) -> &str {
        "steward"
    }

    fn out_path(&self, target_dir: &Path) -> std::path::PathBuf {
        target_dir.join("steward")
    }

    fn cache_key(&self, _inputs: &StageInputs) -> CacheKey {
        self.cache_key_for_root(&crate::artifact::workspace_root())
    }

    async fn run(&self, _inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        // v15 workspace: the steward is its own member crate, built by `-p` from the
        // workspace root — not a feature of this crate, as it was pre-v15 — into the
        // shared workspace `target/`.
        let ws_root = crate::artifact::workspace_root();
        let build_status = tokio::process::Command::new("cargo")
            .current_dir(&ws_root)
            .env("RUSTFLAGS", "-C target-feature=+crt-static")
            .arg("build")
            .arg("--release")
            .arg("--target")
            .arg("x86_64-unknown-linux-gnu")
            .arg("-p")
            .arg("vmcell-steward")
            .status()
            .await?;
        if !build_status.success() {
            return Err(Error::Subprocess("Failed to build vmcell-steward".into()));
        }

        let target_dir = std::env::var("CARGO_TARGET_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| ws_root.join("target"));
        let steward_path = target_dir.join("x86_64-unknown-linux-gnu/release/vmcell-steward");

        tokio::fs::copy(steward_path, out)
            .await
            .map_err(Error::Io)?;

        let mut outputs = StageOutputs::default();
        outputs
            .artifacts
            .insert("steward".into(), out.to_path_buf());
        Ok(outputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a fixture workspace the closure hash can actually resolve: a `Cargo.lock` in the
    /// real generated shape naming both path members, each member's `Cargo.toml`, and the steward's
    /// mandatory `src/main.rs` entry point.
    ///
    /// The lock is load-bearing, not decoration. `crate_closure_hash` DERIVES the closure set from
    /// it rather than hardcoding a crate list (which is the point — every hand-maintained copy of
    /// that list has gone stale), so a stub lock makes the whole key collapse to one error marker
    /// and every `assert_ne!` below compare two identical markers. That is exactly how this gate
    /// silently stopped testing anything when the closure moved to lock-derivation: it kept
    /// passing an assertion whose two sides were the same failure.
    fn fixture_ws() -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("tempdir");
        let steward_src = root.path().join("crates/vmcell-steward/src");
        let proto_src = root.path().join("crates/vmcell-protocol/src");
        std::fs::create_dir_all(&steward_src).expect("mkdir steward src");
        std::fs::create_dir_all(&proto_src).expect("mkdir protocol src");
        std::fs::write(steward_src.join("main.rs"), b"fn main() {}").expect("write bin");
        std::fs::write(steward_src.join("lib.rs"), b"pub fn reaper() {}").expect("write lib");
        std::fs::write(proto_src.join("lib.rs"), b"pub struct Msg;").expect("write proto");
        for pkg in ["vmcell-steward", "vmcell-protocol"] {
            std::fs::write(
                root.path().join("crates").join(pkg).join("Cargo.toml"),
                format!("[package]\nname = \"{pkg}\"\nversion = \"0.1.0\"\n").as_bytes(),
            )
            .expect("write manifest");
        }
        std::fs::write(
            root.path().join("Cargo.lock"),
            "# This file is automatically @generated by Cargo.\nversion = 4\n\n\
             [[package]]\nname = \"postcard\"\nversion = \"1.1.3\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n\
             [[package]]\nname = \"vmcell-steward\"\nversion = \"0.1.0\"\ndependencies = [\n \
             \"postcard\",\n \"vmcell-protocol\",\n]\n\n\
             [[package]]\nname = \"vmcell-protocol\"\nversion = \"0.1.0\"\ndependencies = [\n \
             \"postcard\",\n]\n",
        )
        .expect("write lock");
        root
    }

    // M-ART-8: the steward cache key must track the steward's FULL source closure, not a
    // (possibly-absent) `steward_src_hash` pin that degenerates to a constant, content-
    // blind key. We mutate a NON-wrapper steward file (main.rs unchanged) in a fixture
    // workspace and assert the key changes. The buggy pin/wrapper-only key stays constant
    // regardless of the source change -> red here.
    #[test]
    fn test_steward_cache_key_tracks_steward_source_closure() {
        let root = fixture_ws();
        let steward_src = root.path().join("crates/vmcell-steward/src");

        let stage = StewardStage {};
        let k1 = stage.cache_key_for_root(root.path());
        // The fixture must RESOLVE, or both sides below are the same error marker and the
        // assertion is vacuous — the failure mode this gate itself fell into.
        assert!(
            crate::artifact::steward_closure_hash(root.path()).is_ok(),
            "the fixture workspace must resolve, or the assertions below compare error markers"
        );
        // Mutate the steward implementation (main.rs is byte-identical), so a pin/wrapper-only
        // key would be UNCHANGED here.
        std::fs::write(
            steward_src.join("lib.rs"),
            b"pub fn reaper() { /* fixed */ }",
        )
        .expect("rewrite lib");
        let k2 = stage.cache_key_for_root(root.path());
        assert_ne!(
            k1, k2,
            "a steward source change must invalidate the steward cache key (M-ART-8)"
        );
    }

    // The steward links `vmcell-protocol`, so an edit THERE changes the built binary too. This is
    // the guest-tools hole (docs/81 m22 follow-up) asserted on the steward's own closure: the
    // hand-maintained list that missed `vmcell-protocol` shipped a stale rootfs whose guest half
    // disagreed with the host.
    #[test]
    fn test_steward_cache_key_tracks_a_linked_workspace_crate() {
        let root = fixture_ws();
        let stage = StewardStage {};
        let k1 = stage.cache_key_for_root(root.path());
        std::fs::write(
            root.path().join("crates/vmcell-protocol/src/lib.rs"),
            b"pub struct Msg; pub const APPLETS: &[&str] = &[\"ip\"];",
        )
        .expect("rewrite proto");
        let k2 = stage.cache_key_for_root(root.path());
        assert_ne!(
            k1, k2,
            "an edit to a crate the steward links must invalidate its cache key (M-ART-8)"
        );
    }

    // M-ART-8 hard-stop half: a missing steward source closure folds a distinct error marker
    // (not the empty string), so its key differs from a valid one and the miss drives run().
    #[test]
    fn test_steward_cache_key_missing_source_is_distinct() {
        let empty = tempfile::tempdir().expect("tempdir");
        let missing_key = StewardStage {}.cache_key_for_root(empty.path());
        assert!(
            crate::artifact::steward_closure_hash(empty.path()).is_err(),
            "an empty tree must be the hard-stop arm"
        );

        let root = fixture_ws();
        assert!(
            crate::artifact::steward_closure_hash(root.path()).is_ok(),
            "the fixture must be the RESOLVING arm — comparing two error markers proves nothing"
        );
        let present_key = StewardStage {}.cache_key_for_root(root.path());

        assert_ne!(
            missing_key, present_key,
            "a missing steward source must fold a distinct marker, not alias a valid key (M-ART-8)"
        );
    }
}
