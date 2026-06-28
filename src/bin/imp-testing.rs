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

fn main() -> imp_testing::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("valid async runtime config")
        .block_on(async_main())
}

async fn async_main() -> imp_testing::Result<()> {
    let cli = Cli::parse();
    dispatch(&cli.command).await
}

/// Builds the typed error returned by a subcommand that is not yet implemented.
///
/// These subcommands must fail loud — a typed, matchable error that drives a
/// non-zero exit — rather than printing fake success. Printing "Running VM..."
/// and returning `Ok(())` while doing nothing is the "skip == pass" failure in
/// CLI form: it impersonates a completed operation.
fn not_implemented(subcommand: &str) -> imp_testing::Error {
    imp_testing::Error::Unsupported {
        vmm: "imp-testing".to_string(),
        feature: format!("subcommand `{subcommand}` is not yet implemented"),
    }
}

async fn dispatch(command: &Commands) -> imp_testing::Result<()> {
    match command {
        Commands::Build => {
            println!("Building artifacts...");
            let pipeline = imp_testing::artifact::Pipeline {
                target_dir: std::path::PathBuf::from("target/imp-artifacts"),
                stages: vec![
                    Box::new(imp_testing::artifact::ResolvePinsStage {
                        pins_file: std::path::PathBuf::from("pins.json"),
                    }),
                    Box::new(imp_testing::artifact::kernel::KernelStage {
                        http_client: std::sync::Arc::new(
                            imp_testing::artifact::kernel::ReqwestClient,
                        ),
                        label: None,
                    }),
                    Box::new(imp_testing::artifact::guest_agent::GuestAgentStage {}),
                    Box::new(imp_testing::artifact::guest_tools::GuestToolsStage {}),
                    Box::new(imp_testing::artifact::rootfs::RootfsStage {
                        source: imp_testing::artifact::rootfs::RootfsBuildSource::Oci,
                        cid_alloc: std::sync::Arc::new(imp_testing::vmm::CidAllocator::new()),
                    }),
                ],
            };
            pipeline
                .build(&imp_testing::artifact::Cache::default())
                .await?;
            println!("Artifacts built successfully.");
            Ok(())
        }
        Commands::BuildKernels => {
            // Build each kernel in the `kernels` registry to its own `vmlinux-<label>`
            // (the kernel-version dimension), so multiple versions coexist for the
            // cross-kernel benchmark sweep. Reuses the labelled `KernelStage`; each has
            // its own cache sidecar and build dir.
            let pins_file = std::path::PathBuf::from("pins.json");
            let content = std::fs::read_to_string(&pins_file).map_err(imp_testing::Error::Io)?;
            let json: serde_json::Value = serde_json::from_str(&content)
                .map_err(|e| imp_testing::Error::Artifact(format!("pins.json parse: {e}")))?;
            let labels: Vec<String> = json
                .get("kernels")
                .and_then(|k| k.as_object())
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();
            if labels.is_empty() {
                return Err(imp_testing::Error::Artifact(
                    "no `kernels` registry in pins.json".to_string(),
                ));
            }
            println!("Building kernels: {}", labels.join(", "));
            let mut stages: Vec<Box<dyn imp_testing::artifact::Stage>> =
                vec![Box::new(imp_testing::artifact::ResolvePinsStage {
                    pins_file: pins_file.clone(),
                })];
            for label in &labels {
                println!("  - kernel {label} -> vmlinux-{label}");
                stages.push(Box::new(imp_testing::artifact::kernel::KernelStage {
                    http_client: std::sync::Arc::new(imp_testing::artifact::kernel::ReqwestClient),
                    label: Some(label.clone()),
                }));
            }
            imp_testing::artifact::Pipeline {
                target_dir: std::path::PathBuf::from("target/imp-artifacts"),
                stages,
            }
            .build(&imp_testing::artifact::Cache::default())
            .await?;
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
                matches!(err, imp_testing::Error::Unsupported { .. }),
                "expected Error::Unsupported, got {err:?}"
            );
        }
    }
}
