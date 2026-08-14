use std::path::Path;
use vmcell::artifact::{Cache, Pipeline, StageOutputs};
use vmcell::error::Result;

mod common;

#[derive(Debug, Clone, PartialEq, Eq)]
struct DummyStage {
    name: String,
    content: String,
}

#[async_trait::async_trait]
impl vmcell::artifact::Stage for DummyStage {
    fn name(&self) -> &str {
        &self.name
    }

    fn out_path(&self, target_dir: &Path) -> std::path::PathBuf {
        target_dir.join(&self.name)
    }

    fn cache_key(&self, _inputs: &vmcell::artifact::StageInputs) -> vmcell::artifact::CacheKey {
        vmcell::artifact::CacheKey::new(self.content.clone())
    }

    async fn run(
        &self,
        _inputs: &vmcell::artifact::StageInputs,
        out: &Path,
    ) -> Result<StageOutputs> {
        std::fs::write(out, &self.content).unwrap();
        Ok(StageOutputs::default())
    }
}

#[tokio::test]
async fn test_pipeline_reset_to() {
    // OWNED (`common::TempTree`): `create` keeps the clear-then-create prologue, and the guard's
    // `Drop` replaces the trailing `remove_dir_all` that every panicking assert below skipped.
    let scratch = common::TempTree::create(&format!("vmcell-test-pipeline-{}", std::process::id()));
    let tmp_dir = scratch.path().to_path_buf();

    let cache = Cache::default();

    let pipeline = Pipeline::new(tmp_dir.clone())
        .add_stage(Box::new(DummyStage {
            name: "stage1".to_string(),
            content: "content1".to_string(),
        }))
        .add_stage(Box::new(DummyStage {
            name: "stage2".to_string(),
            content: "content2".to_string(),
        }))
        .add_stage(Box::new(DummyStage {
            name: "stage3".to_string(),
            content: "content3".to_string(),
        }));

    // Initial run
    let _inputs = vmcell::artifact::StageInputs::default();
    let _res = pipeline.build(&cache).await.unwrap();

    assert!(tmp_dir.join("stage1").exists());
    assert!(tmp_dir.join("stage2").exists());
    assert!(tmp_dir.join("stage3").exists());

    // Reset to stage2
    pipeline.reset_to("stage2", &cache).unwrap();

    assert!(tmp_dir.join("stage1").exists());
    assert!(!tmp_dir.join("stage2").exists(), "stage2 should be removed");
    assert!(!tmp_dir.join("stage3").exists(), "stage3 should be removed");
    assert!(!tmp_dir.join("stage2.cache_key").exists());
    assert!(!tmp_dir.join("stage3.cache_key").exists());

    // reset_to on an unknown stage name must error, not silently succeed.
    assert!(
        pipeline.reset_to("nonexistent", &cache).is_err(),
        "reset_to on an unknown stage name must return Err"
    );

    // No trailing removal: `scratch` owns the tree and drops here (and on any panic above).
}

// ARTIFACT-PIPELINE-10. reset_to(stage) must invalidate the named stage and every stage AFTER
// it, but nothing before. With a kernel -> rootfs -> snapshot pipeline, reset_to("rootfs")
// rebuilds rootfs + snapshot only; the upstream kernel stays cached.
#[tokio::test]
async fn test_pipeline_reset_subset_rebuilds_downstream_only() {
    // OWNED: `reserve`, not `create` — the pipeline creates its own target dir.
    let scratch = common::TempTree::reserve(&format!(
        "vmcell-test-pipeline-reset-sub-{}",
        std::process::id()
    ));
    let tmp_dir = scratch.path().to_path_buf();
    let cache = Cache::default();

    let kc = Arc::new(AtomicUsize::new(0));
    let rc = Arc::new(AtomicUsize::new(0));
    let sc = Arc::new(AtomicUsize::new(0));

    let pipeline = Pipeline::new(tmp_dir.clone())
        .add_stage(Box::new(CountingStage {
            name: "kernel".into(),
            content: "kernel-content".into(),
            run_count: kc.clone(),
        }))
        .add_stage(Box::new(CountingStage {
            name: "rootfs".into(),
            content: "rootfs-content".into(),
            run_count: rc.clone(),
        }))
        .add_stage(Box::new(CountingStage {
            name: "snapshot".into(),
            content: "snapshot-content".into(),
            run_count: sc.clone(),
        }));

    // Cold build: every stage runs exactly once.
    pipeline.build(&cache).await.unwrap();
    assert_eq!(kc.load(Ordering::SeqCst), 1);
    assert_eq!(rc.load(Ordering::SeqCst), 1);
    assert_eq!(sc.load(Ordering::SeqCst), 1);

    // Reset from the middle stage: rootfs + snapshot are invalidated; the kernel is NOT.
    pipeline.reset_to("rootfs", &cache).unwrap();
    assert!(
        tmp_dir.join("kernel").exists(),
        "kernel artifact must survive reset_to(rootfs)"
    );
    assert!(!tmp_dir.join("rootfs").exists());
    assert!(!tmp_dir.join("snapshot").exists());

    // Rebuild: only the reset subset runs again; the cached kernel is skipped.
    pipeline.build(&cache).await.unwrap();
    assert_eq!(
        kc.load(Ordering::SeqCst),
        1,
        "kernel must NOT rebuild after reset_to(rootfs)"
    );
    assert_eq!(rc.load(Ordering::SeqCst), 2, "rootfs must rebuild");
    assert_eq!(sc.load(Ordering::SeqCst), 2, "snapshot must rebuild");

    // No trailing removal: `scratch` owns the tree and drops here (and on any panic above).
}

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Clone)]
struct CountingStage {
    name: String,
    content: String,
    run_count: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl vmcell::artifact::Stage for CountingStage {
    fn name(&self) -> &str {
        &self.name
    }

    fn out_path(&self, target_dir: &Path) -> std::path::PathBuf {
        target_dir.join(&self.name)
    }

    fn cache_key(&self, _inputs: &vmcell::artifact::StageInputs) -> vmcell::artifact::CacheKey {
        vmcell::artifact::CacheKey::new(self.content.clone())
    }

    async fn run(
        &self,
        _inputs: &vmcell::artifact::StageInputs,
        out: &Path,
    ) -> Result<StageOutputs> {
        self.run_count.fetch_add(1, Ordering::SeqCst);
        std::fs::write(out, &self.content).unwrap();
        Ok(StageOutputs::default())
    }
}

#[tokio::test]
async fn test_pipeline_warm_cache_skips() {
    // OWNED: `reserve`, not `create` — the pipeline creates its own target dir.
    let scratch =
        common::TempTree::reserve(&format!("vmcell-test-pipeline-warm-{}", std::process::id()));
    let tmp_dir = scratch.path().to_path_buf();
    let cache = Cache::default();

    let count = Arc::new(AtomicUsize::new(0));
    let stage = CountingStage {
        name: "stage1".into(),
        content: "content".into(),
        run_count: count.clone(),
    };

    let pipeline = Pipeline::new(tmp_dir.clone()).add_stage(Box::new(stage.clone()));

    // Run 1
    pipeline.build(&cache).await.unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);

    // Run 2
    pipeline.build(&cache).await.unwrap();
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "Warm cache should skip run"
    );

    // No trailing removal: `scratch` owns the tree and drops here (and on any panic above).
}

// ARTIFACT-PIPELINE-10 / TESTS-FEATURES-4. Exercises a REAL stage (`SnapshotStage`) whose
// cache key depends on its inputs, instead of the constant-keyed `DummyStage` which could not
// catch the real cache-key bugs. The key folds STAGE_VERSION (=1, u32 LE) then every upstream
// artifact in *key-sorted* order, hashing each artifact's on-disk CONTENT (never its absolute
// path) — see src/artifact/mod.rs::hash_artifacts_sorted and src/artifact/snapshot.rs.
#[tokio::test]
async fn test_pipeline_determinism() {
    use vmcell::artifact::Stage;
    use vmcell::artifact::StageInputs;
    use vmcell::artifact::snapshot::SnapshotStage;

    // GOLDEN snapshot cache key over the six artifacts below (content-hashed, key-sorted).
    // Any regression — a stage-version bump, unsorted HashMap iteration (ARTIFACT-PIPELINE-1),
    // a switch back to path-string hashing (ARTIFACT-PIPELINE-2), or a changed prefix — moves
    // this value and turns the assertions red. Updated for M-ART-7: the key now folds the pinned
    // Cloud Hypervisor build identity (`b"ch\0"` + the `cloud_hypervisor` pin, empty here since
    // these `StageInputs` carry no pins) so a CH upgrade invalidates stale snapshots.
    const GOLDEN: &str =
        "snapshot-c0eefc0b98188b0370cade71e26726806ea4cdc99fe4270851105e92859d088c";

    // Identical (key, content) artifacts. inputs_a and inputs_b place the SAME content under
    // two DIFFERENT directories and insert it in OPPOSITE order: a content-addressed,
    // order-independent key must be identical for both — and equal to GOLDEN.
    let entries: [(&str, &[u8]); 6] = [
        ("alpha", b"alpha-bytes"),
        ("bravo", b"bravo-bytes"),
        ("kernel", b"kernel-bytes"),
        ("mike", b"mike-bytes"),
        ("rootfs", b"rootfs-bytes"),
        ("zulu", b"zulu-bytes"),
    ];

    let dir1 = tempfile::tempdir().unwrap();
    let dir2 = tempfile::tempdir().unwrap();

    let mut inputs_a = StageInputs::default();
    for (i, (k, content)) in entries.iter().enumerate() {
        let p = dir1.path().join(format!("a{i}"));
        std::fs::write(&p, content).unwrap();
        inputs_a.artifacts.insert((*k).to_string(), p);
    }

    let mut inputs_b = StageInputs::default();
    for (i, (k, content)) in entries.iter().enumerate().rev() {
        let p = dir2.path().join(format!("b{i}"));
        std::fs::write(&p, content).unwrap();
        inputs_b.artifacts.insert((*k).to_string(), p);
    }

    let stage = SnapshotStage {
        cid_alloc: std::sync::Arc::new(vmcell::vmm::CidAllocator::new()),
        vmid_alloc: vmcell::orchestrator::VmidAllocator::new(),
    };

    let key_a = stage.cache_key(&inputs_a);
    let key_b = stage.cache_key(&inputs_b);

    // Order- and path-independence (content-addressing): same content at different paths,
    // inserted in opposite order, must yield one key. An unsorted fold or a path-string fold
    // makes these diverge.
    assert_eq!(
        key_a, key_b,
        "snapshot cache key must be order- and path-independent (content-addressed)"
    );
    // Pinned golden: locks the fold structure + stage version against silent drift.
    assert_eq!(key_a.0, GOLDEN, "snapshot cache key drifted from golden");
}

#[tokio::test]
async fn test_pipeline_tampered_digest_aborts() {
    // OWNED: `reserve`, not `create` — the pipeline creates its own target dir.
    let scratch =
        common::TempTree::reserve(&format!("vmcell-test-pipeline-tamp-{}", std::process::id()));
    let tmp_dir = scratch.path().to_path_buf();
    let cache = Cache::default();

    let count = Arc::new(AtomicUsize::new(0));
    let stage = CountingStage {
        name: "stage1".into(),
        content: "content".into(),
        run_count: count.clone(),
    };

    let pipeline = Pipeline::new(tmp_dir.clone()).add_stage(Box::new(stage.clone()));

    // Initial build
    pipeline.build(&cache).await.unwrap();

    // Tamper with the artifact
    std::fs::write(tmp_dir.join("stage1"), "tampered").unwrap();

    let res = pipeline.build(&cache).await;
    assert!(
        res.is_err(),
        "Tampered artifact should cause pipeline to abort"
    );

    // No trailing removal: `scratch` owns the tree and drops here (and on any panic above).
}

// ART-2: `reset_to` must PURGE a directory output (the snapshot stage's shape), not error
// on `EISDIR`. The old `remove_file`-only path returned Err on a directory — so the
// previously-misnamed `test_reset_to_propagates_remove_error` locked in the WRONG behavior
// by asserting Err on a dir. Here the artifact IS a non-empty directory with an intact
// `.cache_key`; reset_to must succeed and remove both. The old EISDIR-propagating impl
// returns Err → the `.expect(...)` below goes red on it.
#[tokio::test]
async fn test_reset_to_purges_directory_output() {
    // OWNED: `create` keeps the clear-then-create prologue this test relies on.
    let scratch =
        common::TempTree::create(&format!("vmcell-test-reset-dir-{}", std::process::id()));
    let tmp_dir = scratch.path().to_path_buf();
    let cache = Cache::default();

    let pipeline = Pipeline::new(tmp_dir.clone()).add_stage(Box::new(DummyStage {
        name: "snapshot".to_string(),
        content: "content1".to_string(),
    }));

    // The artifact is a NON-EMPTY directory (a snapshot dir) with an intact `.cache_key`.
    let art = tmp_dir.join("snapshot");
    std::fs::create_dir_all(art.join("mem")).unwrap();
    std::fs::write(art.join("state.json"), b"state").unwrap();
    std::fs::write(art.join("mem/pages.bin"), b"pages").unwrap();
    std::fs::write(tmp_dir.join("snapshot.cache_key"), b"{}").unwrap();

    pipeline
        .reset_to("snapshot", &cache)
        .expect("reset_to must purge a directory output, not EISDIR-error");
    assert!(
        !art.exists(),
        "reset_to must remove the snapshot directory output"
    );
    assert!(
        !tmp_dir.join("snapshot.cache_key").exists(),
        "reset_to must remove the .cache_key sidecar too"
    );

    // No trailing removal: `scratch` owns the tree and drops here (and on any panic above).
}

#[derive(Clone)]
struct DirStage {
    name: String,
    key: String,
    /// `(relative path within the output dir, bytes)`.
    files: Vec<(String, Vec<u8>)>,
    run_count: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl vmcell::artifact::Stage for DirStage {
    fn name(&self) -> &str {
        &self.name
    }

    fn out_path(&self, target_dir: &Path) -> std::path::PathBuf {
        target_dir.join(&self.name)
    }

    fn cache_key(&self, _inputs: &vmcell::artifact::StageInputs) -> vmcell::artifact::CacheKey {
        vmcell::artifact::CacheKey::new(self.key.clone())
    }

    async fn run(
        &self,
        _inputs: &vmcell::artifact::StageInputs,
        out: &Path,
    ) -> Result<StageOutputs> {
        self.run_count.fetch_add(1, Ordering::SeqCst);
        std::fs::create_dir_all(out).unwrap();
        for (rel, bytes) in &self.files {
            let p = out.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(p, bytes).unwrap();
        }
        Ok(StageOutputs::default())
    }
}

// ART-1: a DIRECTORY stage output (the snapshot stage's shape) must be cached and
// content-verified. `hash_file` `File::open`ed the dir and `EISDIR`-ed into the `warn!`
// arm, so no `.cache_key` sidecar was ever written and the stage re-ran on every build.
// Here the sidecar must exist after the first build, and the warm build must SKIP the stage
// (run count stays 1). The old code reddens both assertions.
#[tokio::test]
async fn test_pipeline_dir_output_cached_and_stable() {
    // OWNED: `reserve`, not `create` — the pipeline creates its own target dir.
    let scratch =
        common::TempTree::reserve(&format!("vmcell-test-pipeline-dir-{}", std::process::id()));
    let tmp_dir = scratch.path().to_path_buf();
    let cache = Cache::default();

    let count = Arc::new(AtomicUsize::new(0));
    let pipeline = Pipeline::new(tmp_dir.clone()).add_stage(Box::new(DirStage {
        name: "snapshot".into(),
        key: "snap-key".into(),
        files: vec![
            ("state.json".into(), b"state".to_vec()),
            ("mem/pages.bin".into(), b"pages".to_vec()),
        ],
        run_count: count.clone(),
    }));

    pipeline.build(&cache).await.unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(
        tmp_dir.join("snapshot").is_dir(),
        "directory output must exist"
    );
    assert!(
        tmp_dir.join("snapshot.cache_key").exists(),
        "a directory output must write a .cache_key sidecar (ART-1)"
    );

    // Warm rebuild: the directory content hash is stable and verified, so the stage is
    // skipped instead of re-running.
    pipeline.build(&cache).await.unwrap();
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "directory output must be cached across runs (stable content hash)"
    );

    // No trailing removal: `scratch` owns the tree and drops here (and on any panic above).
}

// ART-1: a byte-corrupted file INSIDE a cached directory output, with the `.cache_key`
// sidecar left intact, must be rejected on the hit path (the tamper contract) — exactly
// like a tampered single-file artifact. The old code never wrote a sidecar for a dir, so it
// silently rebuilt (returning Ok) → this `is_err` goes red on it.
#[tokio::test]
async fn test_pipeline_dir_output_tamper_rejected() {
    // OWNED: `reserve`, not `create` — the pipeline creates its own target dir.
    let scratch = common::TempTree::reserve(&format!(
        "vmcell-test-pipeline-dir-tamp-{}",
        std::process::id()
    ));
    let tmp_dir = scratch.path().to_path_buf();
    let cache = Cache::default();

    let count = Arc::new(AtomicUsize::new(0));
    let pipeline = Pipeline::new(tmp_dir.clone()).add_stage(Box::new(DirStage {
        name: "snapshot".into(),
        key: "snap-key".into(),
        files: vec![
            ("state.json".into(), b"state".to_vec()),
            ("mem/pages.bin".into(), b"pages".to_vec()),
        ],
        run_count: count.clone(),
    }));

    pipeline.build(&cache).await.unwrap();

    // Corrupt one file inside the directory; keep the sidecar intact.
    std::fs::write(tmp_dir.join("snapshot/mem/pages.bin"), b"tampered").unwrap();

    let res = pipeline.build(&cache).await;
    assert!(
        res.is_err(),
        "a corrupted file inside a cached directory output must abort on the hit path"
    );

    // No trailing removal: `scratch` owns the tree and drops here (and on any panic above).
}

// §18 delta 1 / §10.2 (The stage model and the five cache-key rules) — ARTIFACT HONESTY.
// `resolved_pins.json` is a published artifact (`outputs.artifacts["resolved_pins"]`, and the
// `pins` entry of `vmcell bundle`), so with an overlay in play it must be the MERGED document —
// a verbatim copy of either input would ship a lying artifact naming pins the build did not use.
// Buggy impls this guards: (a) `run()` writing the committed baseline verbatim (the pre-overlay
// code) — the `downstream.example` assert goes red; (b) `run()` writing the OVERLAY verbatim — the
// `microvm_config` assert goes red, since the overlay never carried one; (c) a document-level
// namespace replacement — same assert. The no-overlay leg pins §18 delta 1's migration promise —
// "no overlay ⇒ baseline behavior byte-identical" — by comparing the published BYTES against the
// committed `pins.json`, not the parsed document: a re-render through `to_string_pretty` reflows
// whitespace and re-orders keys, which every field-equality assert in this test happily accepts
// while silently changing a published, content-addressed artifact. Buggy impl this catches:
// dropping `run()`'s verbatim `None` arm so both arms render the parsed document.
#[tokio::test]
async fn resolve_pins_publishes_the_merged_document() {
    use vmcell::artifact::Stage as _;

    /// The same bytes `ResolvePinsStage` embeds as its baseline. Read here from the repo root, so
    /// this is an independent copy of the promise, not the constant under test.
    const COMMITTED_PINS: &str = include_str!("../../../pins.json");

    // OWNED: `create` — this test writes the overlay file into the dir itself.
    let scratch =
        common::TempTree::create(&format!("vmcell-test-pins-overlay-{}", std::process::id()));
    let tmp_dir = scratch.path().to_path_buf();

    let overlay_path = tmp_dir.join("overlay.json");
    std::fs::write(
        &overlay_path,
        r#"{ "kernel": { "source_url": "https://downstream.example/linux.tar.xz" } }"#,
    )
    .unwrap();

    let inputs = vmcell::artifact::StageInputs::default();

    // No overlay: the published document is the committed baseline, verbatim.
    let baseline_out = tmp_dir.join("resolved_pins_baseline.json");
    let stage = vmcell::artifact::ResolvePinsStage { overlay_file: None };
    let baseline_outputs = stage.run(&inputs, &baseline_out).await.unwrap();
    let baseline_bytes = std::fs::read_to_string(&baseline_out).unwrap();
    assert_eq!(
        baseline_bytes, COMMITTED_PINS,
        "with no overlay the published artifact must be the committed pins.json BYTE-FOR-BYTE \
         (§18 delta 1's migration promise); a re-render moves this content-addressed artifact"
    );
    let baseline_doc: serde_json::Value = serde_json::from_str(&baseline_bytes).unwrap();

    // With an overlay: the published document carries the override AND the baseline's siblings.
    let merged_out = tmp_dir.join("resolved_pins_merged.json");
    let stage = vmcell::artifact::ResolvePinsStage {
        overlay_file: Some(overlay_path.clone()),
    };
    let merged_outputs = stage.run(&inputs, &merged_out).await.unwrap();
    let merged_doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&merged_out).unwrap()).unwrap();

    assert_eq!(
        merged_doc["kernel"]["source_url"].as_str(),
        Some("https://downstream.example/linux.tar.xz"),
        "the published artifact must carry the overlay's override, not the baseline's URL"
    );
    assert_eq!(
        merged_doc["kernel"]["microvm_config"], baseline_doc["kernel"]["microvm_config"],
        "the published artifact must keep the baseline siblings the merge preserved"
    );
    assert_eq!(
        merged_doc["kernels"], baseline_doc["kernels"],
        "an untouched namespace must be published unchanged"
    );

    // The propagated pin map and the published document agree — one resolution, not two.
    assert_eq!(
        merged_outputs
            .pins
            .get("kernel_source_url")
            .map(String::as_str),
        Some("https://downstream.example/linux.tar.xz")
    );
    assert_eq!(
        merged_outputs.pins.get("kernel_microvm_config"),
        baseline_outputs.pins.get("kernel_microvm_config")
    );
    assert_eq!(
        merged_outputs.artifacts.get("resolved_pins"),
        Some(&merged_out)
    );

    // No trailing removal: `scratch` owns the tree and drops here (and on any panic above).
}

// ── The residue gate for the tests' OWN scratch trees (`common::TempTree`) ──────────────────────
//
// The codebase's residue discipline — assert the artifact EXISTED, then that it is GONE once its
// owner drops — applied to the test harness itself. It lives in this KVM-free binary so it runs in
// the default `kind(test)` subset on any host.
//
// The defect it guards: a scratch path cleaned by a trailing `let _ = remove_dir_all(&dir)` at the
// bottom of a test body is NOT cleaned when an assertion between creation and that line panics,
// and a nextest retry re-runs the whole body — so one flaky live test leaked once per attempt.
// `tests/snapshot_restore.rs` had no removal on any path, and its ~129 MB guest-RAM snapshot dirs
// filled this host's `/tmp` until the daemon suite went red on `Disk quota exceeded`.
//
// RED ON THE INVERSE: empty `TempTree::drop`'s body (or make it return before `remove_tree`) and
// both `must be GONE` assertions below flip — the success leg and the panic leg independently.
#[test]
fn temp_tree_removes_its_tree_on_success_and_on_panic() {
    // Success leg: the tree exists while owned, and is gone once the owner drops.
    let path = {
        let tree =
            common::TempTree::create(&format!("vmcell-test-temptree-ok-{}", std::process::id()));
        std::fs::write(tree.join("payload.bin"), b"residue").unwrap();
        assert!(
            tree.path().is_dir(),
            "the owned tree {} must exist before its owner drops (precheck; without it the \
             assertion below is vacuous)",
            tree.path().display()
        );
        tree.path().to_path_buf()
    };
    assert!(
        !path.exists(),
        "the owned tree {} must be GONE after its owner drops (success path)",
        path.display()
    );

    // Panic leg: the SAME must hold when the body between creation and the end of scope panics —
    // which is exactly what the trailing `remove_dir_all` calls this helper replaced could not do.
    let path =
        std::env::temp_dir().join(format!("vmcell-test-temptree-panic-{}", std::process::id()));
    let seen = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen_in = seen.clone();
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let tree = common::TempTree::create(&format!(
            "vmcell-test-temptree-panic-{}",
            std::process::id()
        ));
        std::fs::write(tree.join("payload.bin"), b"residue").unwrap();
        seen_in.store(tree.path().is_dir(), std::sync::atomic::Ordering::SeqCst);
        panic!("simulated assertion failure between creation and end of scope");
    }));
    assert!(unwound.is_err(), "the closure must actually have panicked");
    assert!(
        seen.load(std::sync::atomic::Ordering::SeqCst),
        "the owned tree {} must have existed before the panic (precheck; without it the \
         assertion below is vacuous)",
        path.display()
    );
    assert!(
        !path.exists(),
        "the owned tree {} must be GONE after an unwind through its owner (panic path)",
        path.display()
    );
}

// `VMCELL_KEEP_TEST_TEMP` is an ACCEPTED INPUT, so it is honored or rejected — never silently
// ignored (AGENTS.md "Fail loud"). Both halves are driven WITHOUT touching the process-global
// environment (`keep_from_env_value` takes the value; `retain()` sets the same flag per site),
// because a `set_var` here would race every other test in this binary under plain `cargo test`.
// RED on the inverse: make `keep_from_env_value` fall through to `false` on an unknown value and
// the reject leg goes green-on-nothing; empty the `keep` early-return in `TempTree::drop` and the
// retention leg flips.
#[test]
fn keep_temp_env_is_honored_or_rejected() {
    use std::ffi::OsStr;

    // Honored, both ways round.
    assert!(!common::keep_from_env_value(None), "unset means remove");
    assert!(!common::keep_from_env_value(Some(OsStr::new(""))));
    assert!(!common::keep_from_env_value(Some(OsStr::new("0"))));
    assert!(common::keep_from_env_value(Some(OsStr::new("1"))));

    // Rejected: an unparseable value must fail loud, not silently mean "remove".
    let rejected =
        std::panic::catch_unwind(|| common::keep_from_env_value(Some(OsStr::new("yes"))));
    assert!(
        rejected.is_err(),
        "an unknown {} value must be rejected, not silently treated as \"remove\"",
        common::KEEP_TEMP_ENV
    );

    // And the flag it sets actually suppresses the removal: the retained tree survives its owner.
    // Removed by hand afterwards so this gate does not itself leak.
    let kept = {
        let t =
            common::TempTree::create(&format!("vmcell-test-temptree-keep-{}", std::process::id()))
                .retain();
        t.path().to_path_buf()
    };
    assert!(
        kept.is_dir(),
        "a retained tree ({}=1 / `retain()`) must survive its owner for post-mortem inspection",
        common::KEEP_TEMP_ENV
    );
    std::fs::remove_dir_all(&kept).expect("hand-cleanup of the deliberately retained tree");
}
