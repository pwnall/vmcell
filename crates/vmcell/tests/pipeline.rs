use std::path::Path;
use vmcell::artifact::{Cache, Pipeline, StageOutputs};
use vmcell::error::Result;

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
    let tmp_dir = std::env::temp_dir().join(format!("vmcell-test-pipeline-{}", std::process::id()));
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

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

// ARTIFACT-PIPELINE-10. reset_to(stage) must invalidate the named stage and every stage AFTER
// it, but nothing before. With a kernel -> rootfs -> snapshot pipeline, reset_to("rootfs")
// rebuilds rootfs + snapshot only; the upstream kernel stays cached.
#[tokio::test]
async fn test_pipeline_reset_subset_rebuilds_downstream_only() {
    let tmp_dir = std::env::temp_dir().join(format!(
        "vmcell-test-pipeline-reset-sub-{}",
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
    let tmp_dir =
        std::env::temp_dir().join(format!("vmcell-test-pipeline-warm-{}", std::process::id()));
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
    use vmcell::artifact::Stage;
    use vmcell::artifact::StageInputs;
    use vmcell::artifact::snapshot::SnapshotStage;

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
    let tmp_dir =
        std::env::temp_dir().join(format!("vmcell-test-pipeline-tamp-{}", std::process::id()));
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

// ART-2: `reset_to` must PURGE a directory output (the snapshot stage's shape), not error
// on `EISDIR`. The old `remove_file`-only path returned Err on a directory — so the
// previously-misnamed `test_reset_to_propagates_remove_error` locked in the WRONG behavior
// by asserting Err on a dir. Here the artifact IS a non-empty directory with an intact
// `.cache_key`; reset_to must succeed and remove both. The old EISDIR-propagating impl
// returns Err → the `.expect(...)` below goes red on it.
#[tokio::test]
async fn test_reset_to_purges_directory_output() {
    let tmp_dir =
        std::env::temp_dir().join(format!("vmcell-test-reset-dir-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).unwrap();
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

    let _ = std::fs::remove_dir_all(&tmp_dir);
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
    let tmp_dir =
        std::env::temp_dir().join(format!("vmcell-test-pipeline-dir-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_dir);
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

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

// ART-1: a byte-corrupted file INSIDE a cached directory output, with the `.cache_key`
// sidecar left intact, must be rejected on the hit path (the tamper contract) — exactly
// like a tampered single-file artifact. The old code never wrote a sidecar for a dir, so it
// silently rebuilt (returning Ok) → this `is_err` goes red on it.
#[tokio::test]
async fn test_pipeline_dir_output_tamper_rejected() {
    let tmp_dir = std::env::temp_dir().join(format!(
        "vmcell-test-pipeline-dir-tamp-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp_dir);
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

    let _ = std::fs::remove_dir_all(&tmp_dir);
}
