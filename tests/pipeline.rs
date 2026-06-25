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
