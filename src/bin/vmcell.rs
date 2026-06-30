use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Build,
    /// Build every kernel in the pins `kernels` registry to `vmlinux-<label>`.
    BuildKernels,
    Run,
    Exec,
    Ls,
    Rm,
    Stats,
}

fn main() -> vmcell::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("valid async runtime config")
        .block_on(async_main())
}

async fn async_main() -> vmcell::Result<()> {
    let cli = Cli::parse();
    dispatch(&cli.command).await
}

/// Builds the typed error returned by a subcommand that is not yet implemented.
///
/// These subcommands must fail loud — a typed, matchable error that drives a
/// non-zero exit — rather than printing fake success. Printing "Running VM..."
/// and returning `Ok(())` while doing nothing is the "skip == pass" failure in
/// CLI form: it impersonates a completed operation.
fn not_implemented(subcommand: &str) -> vmcell::Error {
    vmcell::Error::Unsupported {
        vmm: "vmcell".to_string(),
        feature: format!("subcommand `{subcommand}` is not yet implemented"),
    }
}

async fn dispatch(command: &Commands) -> vmcell::Result<()> {
    match command {
        Commands::Build => {
            println!("Building artifacts...");
            let pipeline = vmcell::artifact::Pipeline::new(vmcell::artifact::artifacts_dir())
                .add_stage(Box::new(vmcell::artifact::ResolvePinsStage {
                    pins_file: std::path::PathBuf::from("pins.json"),
                }))
                .add_stage(Box::new(vmcell::artifact::kernel::KernelStage {
                    http_client: std::sync::Arc::new(vmcell::artifact::kernel::ReqwestClient),
                    label: None,
                }))
                .add_stage(Box::new(vmcell::artifact::guest_agent::GuestAgentStage {}))
                .add_stage(Box::new(vmcell::artifact::guest_tools::GuestToolsStage {}))
                .add_stage(Box::new(vmcell::artifact::rootfs::RootfsStage {
                    source: vmcell::artifact::rootfs::RootfsBuildSource::Oci,
                    cid_alloc: std::sync::Arc::new(vmcell::vmm::CidAllocator::new()),
                }));
            pipeline.build(&vmcell::artifact::Cache::default()).await?;
            println!("Artifacts built successfully.");
            Ok(())
        }
        Commands::BuildKernels => {
            // Build each kernel in the `kernels` registry to its own `vmlinux-<label>`
            // (the kernel-version dimension), so multiple versions coexist for the
            // cross-kernel benchmark sweep. Reuses the labelled `KernelStage`; each has
            // its own cache sidecar and build dir.
            let pins_file = std::path::PathBuf::from("pins.json");
            let content = std::fs::read_to_string(&pins_file).map_err(vmcell::Error::Io)?;
            let json: serde_json::Value = serde_json::from_str(&content)
                .map_err(|e| vmcell::Error::Artifact(format!("pins.json parse: {e}")))?;
            let labels: Vec<String> = json
                .get("kernels")
                .and_then(|k| k.as_object())
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();
            if labels.is_empty() {
                return Err(vmcell::Error::Artifact(
                    "no `kernels` registry in pins.json".to_string(),
                ));
            }
            println!("Building kernels: {}", labels.join(", "));
            let mut pipeline = vmcell::artifact::Pipeline::new(vmcell::artifact::artifacts_dir())
                .add_stage(Box::new(vmcell::artifact::ResolvePinsStage {
                    pins_file: pins_file.clone(),
                }));
            for label in &labels {
                println!("  - kernel {label} -> vmlinux-{label}");
                pipeline = pipeline.add_stage(Box::new(vmcell::artifact::kernel::KernelStage {
                    http_client: std::sync::Arc::new(vmcell::artifact::kernel::ReqwestClient),
                    label: Some(label.clone()),
                }));
            }
            pipeline.build(&vmcell::artifact::Cache::default()).await?;
            println!("Kernels built: {}", labels.join(", "));
            Ok(())
        }
        Commands::Run => Err(not_implemented("run")),
        Commands::Exec => Err(not_implemented("exec")),
        Commands::Ls => Err(not_implemented("ls")),
        Commands::Rm => Err(not_implemented("rm")),
        Commands::Stats => Err(not_implemented("stats")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Buggy impl this guards: run/exec/ls/rm/stats printed fake success and
    // returned Ok(()), impersonating a completed operation. Each must instead
    // surface a typed, matchable error so the process exits non-zero.
    #[test]
    fn unimplemented_subcommands_fail_loud() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("test runtime");
        for command in [
            Commands::Run,
            Commands::Exec,
            Commands::Ls,
            Commands::Rm,
            Commands::Stats,
        ] {
            let err = rt
                .block_on(dispatch(&command))
                .expect_err("an unimplemented subcommand must return an error");
            assert!(
                matches!(err, vmcell::Error::Unsupported { .. }),
                "expected Error::Unsupported, got {err:?}"
            );
        }
    }
}
