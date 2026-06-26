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
        imp_testing::artifact::CacheKey(self.content.clone())
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

    let mut pipeline = Pipeline {
        stages: vec![],
        target_dir: tmp_dir.clone(),
    };
    pipeline.stages.push(Box::new(DummyStage {
        name: "stage1".to_string(),
        content: "content1".to_string(),
    }));
    pipeline.stages.push(Box::new(DummyStage {
        name: "stage2".to_string(),
        content: "content2".to_string(),
    }));
    pipeline.stages.push(Box::new(DummyStage {
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
        imp_testing::artifact::CacheKey(self.content.clone())
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

    let pipeline = Pipeline {
        stages: vec![Box::new(stage.clone())],
        target_dir: tmp_dir.clone(),
    };

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

#[tokio::test]
async fn test_pipeline_determinism() {
    let tmp_dir1 =
        std::env::temp_dir().join(format!("imp-test-pipeline-det1-{}", std::process::id()));
    let tmp_dir2 =
        std::env::temp_dir().join(format!("imp-test-pipeline-det2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_dir1);
    let _ = std::fs::remove_dir_all(&tmp_dir2);

    let stage1 = DummyStage {
        name: "stage".into(),
        content: "data".into(),
    };

    let pipeline1 = Pipeline {
        stages: vec![Box::new(stage1.clone())],
        target_dir: tmp_dir1.clone(),
    };
    let pipeline2 = Pipeline {
        stages: vec![Box::new(stage1.clone())],
        target_dir: tmp_dir2.clone(),
    };

    let cache = Cache::default();
    pipeline1.build(&cache).await.unwrap();
    pipeline2.build(&cache).await.unwrap();

    let data1 = std::fs::read(tmp_dir1.join("stage")).unwrap();
    let data2 = std::fs::read(tmp_dir2.join("stage")).unwrap();
    assert_eq!(data1, data2);

    let key1 = std::fs::read_to_string(tmp_dir1.join("stage.cache_key")).unwrap();
    let key2 = std::fs::read_to_string(tmp_dir2.join("stage.cache_key")).unwrap();
    assert_eq!(key1, key2);

    let _ = std::fs::remove_dir_all(&tmp_dir1);
    let _ = std::fs::remove_dir_all(&tmp_dir2);
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

    let pipeline = Pipeline {
        stages: vec![Box::new(stage.clone())],
        target_dir: tmp_dir.clone(),
    };

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
