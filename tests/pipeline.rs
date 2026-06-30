use imp_testing::artifact::{Cache, Pipeline, StageOutputs};
use imp_testing::error::Result;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
struct DummyStage {
    name: String,
    content: String,
}

#[async_trait::async_trait]
impl imp_testing::artifact::Stage for DummyStage {
    fn name(&self) -> &str {
        &self.name
    }

    fn out_path(&self, target_dir: &Path) -> std::path::PathBuf {
        target_dir.join(&self.name)
    }

    fn cache_key(
        &self,
        _inputs: &imp_testing::artifact::StageInputs,
    ) -> imp_testing::artifact::CacheKey {
        imp_testing::artifact::CacheKey::new(self.content.clone())
    }

    async fn run(
        &self,
        _inputs: &imp_testing::artifact::StageInputs,
        out: &Path,
    ) -> Result<StageOutputs> {
        std::fs::write(out, &self.content).unwrap();
        Ok(StageOutputs::default())
    }
}

#[tokio::test]
async fn test_pipeline_reset_to() {
    let tmp_dir = std::env::temp_dir().join(format!("imp-test-pipeline-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).unwrap();

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
    let _inputs = imp_testing::artifact::StageInputs::default();
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

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

// ARTIFACT-PIPELINE-10. reset_to(stage) must invalidate the named stage and every stage AFTER
// it, but nothing before. With a kernel -> rootfs -> snapshot pipeline, reset_to("rootfs")
// rebuilds rootfs + snapshot only; the upstream kernel stays cached.
#[tokio::test]
async fn test_pipeline_reset_subset_rebuilds_downstream_only() {
    let tmp_dir = std::env::temp_dir().join(format!(
        "imp-test-pipeline-reset-sub-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp_dir);
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

    let _ = std::fs::remove_dir_all(&tmp_dir);
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
impl imp_testing::artifact::Stage for CountingStage {
    fn name(&self) -> &str {
        &self.name
    }

    fn out_path(&self, target_dir: &Path) -> std::path::PathBuf {
        target_dir.join(&self.name)
    }

    fn cache_key(
        &self,
        _inputs: &imp_testing::artifact::StageInputs,
    ) -> imp_testing::artifact::CacheKey {
        imp_testing::artifact::CacheKey::new(self.content.clone())
    }

    async fn run(
        &self,
        _inputs: &imp_testing::artifact::StageInputs,
        out: &Path,
    ) -> Result<StageOutputs> {
        self.run_count.fetch_add(1, Ordering::SeqCst);
        std::fs::write(out, &self.content).unwrap();
        Ok(StageOutputs::default())
    }
}

#[tokio::test]
async fn test_pipeline_warm_cache_skips() {
    let tmp_dir =
        std::env::temp_dir().join(format!("imp-test-pipeline-warm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_dir);
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

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

// ARTIFACT-PIPELINE-10 / TESTS-FEATURES-4. Exercises a REAL stage (`SnapshotStage`) whose
// cache key depends on its inputs, instead of the constant-keyed `DummyStage` which could not
// catch the real cache-key bugs. The key folds STAGE_VERSION (=1, u32 LE) then every upstream
// artifact in *key-sorted* order, hashing each artifact's on-disk CONTENT (never its absolute
// path) — see src/artifact/mod.rs::hash_artifacts_sorted and src/artifact/snapshot.rs.
#[tokio::test]
async fn test_pipeline_determinism() {
    use imp_testing::artifact::Stage;
    use imp_testing::artifact::StageInputs;
    use imp_testing::artifact::snapshot::SnapshotStage;

    // GOLDEN snapshot cache key over the six artifacts below (content-hashed, key-sorted).
    // Any regression — a stage-version bump, unsorted HashMap iteration (ARTIFACT-PIPELINE-1),
    // a switch back to path-string hashing (ARTIFACT-PIPELINE-2), or a changed prefix — moves
    // this value and turns the assertions red.
    const GOLDEN: &str =
        "snapshot-63fe6180ba1188682df001dc5be51fd97213504612c90e0ff44b83aa4169c34a";

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
        cid_alloc: std::sync::Arc::new(imp_testing::vmm::CidAllocator::new()),
        vmid_alloc: imp_testing::orchestrator::VmidAllocator::new(),
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
    let tmp_dir =
        std::env::temp_dir().join(format!("imp-test-pipeline-tamp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_dir);
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

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

// M-PIPE-1: reset_to must INVALIDATE the named stage, so a failed artifact removal
// must surface as Err — not a swallowed `let _ =` that reports Ok while leaving a
// VALID cached artifact behind (the next build would then serve the stale artifact).
// We force the removal to fail by making the artifact path a NON-EMPTY DIRECTORY,
// which `remove_file` cannot delete (a non-NotFound error). The buggy swallowing
// impl returns Ok here → this assertion goes red.
#[tokio::test]
async fn test_reset_to_propagates_remove_error() {
    let tmp_dir = std::env::temp_dir().join(format!("imp-test-reset-err-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let cache = Cache::default();

    let pipeline = Pipeline::new(tmp_dir.clone()).add_stage(Box::new(DummyStage {
        name: "stage1".to_string(),
        content: "content1".to_string(),
    }));

    // Make the artifact path a non-empty directory so `remove_file` fails with a
    // non-NotFound error (EISDIR / permission-shaped), which reset_to must propagate.
    let art = tmp_dir.join("stage1");
    std::fs::create_dir_all(&art).unwrap();
    std::fs::write(art.join("inner"), b"block-removal").unwrap();

    let res = pipeline.reset_to("stage1", &cache);
    assert!(
        res.is_err(),
        "reset_to must propagate a failed artifact removal, not report Ok"
    );

    let _ = std::fs::remove_dir_all(&tmp_dir);
}
