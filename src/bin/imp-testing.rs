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
        .unwrap()
        .block_on(async_main())
}

use serde::Deserialize;

#[derive(Deserialize)]
struct Pins {
    kernel: KernelPins,
    rootfs: RootfsPins,
}

#[derive(Deserialize)]
struct KernelPins {
    source_url: String,
    source_sha256: String,
    microvm_config: String,
}

#[derive(Deserialize)]
struct RootfsPins {
    image: String,
    digest: String,
}

async fn async_main() -> imp_testing::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Build => {
            println!("Building artifacts...");
            let pins_str = std::fs::read_to_string("pins.json")
                .unwrap_or_else(|_| panic!("Failed to read pins.json"));
            let pins: Pins = serde_json::from_str(&pins_str).expect("Failed to parse pins.json");

            let pipeline = imp_testing::artifact::Pipeline {
                target_dir: std::path::PathBuf::from("target/imp-artifacts"),
                stages: vec![
                    Box::new(imp_testing::artifact::kernel::KernelStage {
                        kernel_source_url: pins.kernel.source_url,
                        kernel_source_sha256: pins.kernel.source_sha256,
                        microvm_config: pins.kernel.microvm_config,
                    }),
                    Box::new(imp_testing::artifact::guest_agent::GuestAgentStage {}),
                    Box::new(imp_testing::artifact::rootfs::RootfsStage {
                        source: imp_testing::artifact::rootfs::RootfsBuildSource::Oci {
                            image: pins.rootfs.image,
                            digest: pins.rootfs.digest,
                        },
                    }),
                ],
            };
            pipeline
                .build(&imp_testing::artifact::Cache::default())
                .await?;
            println!("Artifacts built successfully.");
        }
        Commands::Run => println!("Running VM..."),
        Commands::Exec => println!("Executing command..."),
        Commands::Ls => println!("Listing VMs..."),
        Commands::Rm => println!("Removing VM..."),
        Commands::Stats => println!("Stats..."),
    }

    Ok(())
}
