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

async fn async_main() -> imp_testing::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Build => {
            println!("Building artifacts...");
            let pipeline = imp_testing::artifact::Pipeline {
                target_dir: std::path::PathBuf::from("target/imp-artifacts"),
                stages: vec![
                    Box::new(imp_testing::artifact::ResolvePinsStage {
                        pins_file: std::path::PathBuf::from("pins.json"),
                    }),
                    Box::new(imp_testing::artifact::kernel::KernelStage {}),
                    Box::new(imp_testing::artifact::guest_agent::GuestAgentStage {}),
                    Box::new(imp_testing::artifact::rootfs::RootfsStage {
                        source: imp_testing::artifact::rootfs::RootfsBuildSource::Oci,
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
