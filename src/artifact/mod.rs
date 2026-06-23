use crate::error::Result;
/// Kernel building stage.
pub mod kernel;
/// Root filesystem building stage.
pub mod rootfs;
/// Snapshot building stage.
pub mod snapshot;
/// Tar to EROFS conversion utility.
#[cfg(feature = "experiment-erofs")]
pub mod tar2erofs;

use std::path::Path;

/// Inputs for an artifact building stage.
pub struct StageInputs {}

/// Outputs from an artifact building stage.
pub struct StageOutputs {}

/// A cache key that uniquely identifies the inputs to a stage.
#[allow(dead_code)]
pub struct CacheKey(String);

use async_trait::async_trait;

/// A building block of the artifact pipeline.
#[async_trait]
pub trait Stage: Send + Sync {
    /// The name of this stage.
    fn name(&self) -> &str;
    /// Computes a cache key based on the stage configuration and inputs.
    fn cache_key(&self, inputs: &StageInputs) -> CacheKey;
    /// Executes the stage, building the output artifact at the given path.
    ///
    /// # Errors
    /// Returns an error if the build fails.
    async fn run(&self, inputs: &StageInputs, out: &Path) -> Result<StageOutputs>;
}

/// Cache for previously built artifacts.
pub struct Cache {}
/// Artifacts resulting from a pipeline build.
pub struct Artifacts {}

/// A pipeline of stages to build all necessary test VM artifacts.
pub struct Pipeline {
    /// The sequence of stages to run.
    pub stages: Vec<Box<dyn Stage>>,
}

impl Pipeline {
    /// Builds all artifacts in the pipeline.
    ///
    /// # Errors
    /// Returns an error if any stage fails.
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

    /// Resets the pipeline to run a specific stage again.
    ///
    /// # Errors
    /// Returns an error if the reset fails.
    pub fn reset_to(&self, _stage: &str, _cache: &Cache) -> Result<()> {
        Ok(())
    }
}
