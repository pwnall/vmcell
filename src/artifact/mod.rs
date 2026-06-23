use crate::error::Result;
pub mod kernel;
pub mod rootfs;
pub mod snapshot;
#[cfg(feature = "experiment-erofs")]
pub mod tar2erofs;

use std::path::Path;

pub struct StageInputs {}
pub struct StageOutputs {}
#[allow(dead_code)]
pub struct CacheKey(String);

use async_trait::async_trait;

#[async_trait]
pub trait Stage: Send + Sync {
    fn name(&self) -> &str;
    fn cache_key(&self, inputs: &StageInputs) -> CacheKey;
    async fn run(&self, inputs: &StageInputs, out: &Path) -> Result<StageOutputs>;
}

pub struct Cache {}
pub struct Artifacts {}

pub struct Pipeline {
    pub stages: Vec<Box<dyn Stage>>,
}

impl Pipeline {
    pub async fn build(&self, _cache: &Cache) -> Result<Artifacts> {
        let out_dir = Path::new("/tmp/imp-artifacts");
        tokio::fs::create_dir_all(out_dir)
            .await
            .map_err(crate::error::Error::Io)?;

        for stage in &self.stages {
            let out_path = if stage.name() == "kernel" {
                out_dir.join("vmlinux")
            } else if stage.name() == "rootfs" {
                out_dir.join("rootfs.ext4")
            } else {
                out_dir.join(stage.name())
            };

            if out_path.exists() {
                println!("Skipping stage {} (cached)", stage.name());
                continue;
            }

            println!("Running stage {}", stage.name());
            stage.run(&StageInputs {}, &out_path).await?;
        }

        Ok(Artifacts {})
    }

    pub fn reset_to(&self, _stage: &str, _cache: &Cache) -> Result<()> {
        Ok(())
    }
}
