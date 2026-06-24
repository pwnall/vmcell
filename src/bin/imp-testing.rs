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
                stages: vec![
                    Box::new(imp_testing::artifact::kernel::KernelStage {
                        kernel_source_url: "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.9.tar.xz".into(),
                        microvm_config: "CONFIG_PVH=y\nCONFIG_SYSTEM_TRUSTED_KEYS=\"\"\nCONFIG_SYSTEM_REVOCATION_KEYS=\"\"\nCONFIG_MODULE_SIG=n\nCONFIG_PCI=y\nCONFIG_VIRTIO=y\nCONFIG_VIRTIO_PCI=y\nCONFIG_VIRTIO_MMIO=y\nCONFIG_VIRTIO_BLK=y\nCONFIG_VIRTIO_NET=y\nCONFIG_VIRTIO_CONSOLE=y\nCONFIG_HW_RANDOM_VIRTIO=y\nCONFIG_VIRTIO_BALLOON=y\nCONFIG_VSOCKETS=y\nCONFIG_VIRTIO_VSOCKETS=y\nCONFIG_VHOST_VSOCK=y\nCONFIG_FUSE_FS=y\nCONFIG_VIRTIO_FS=y\nCONFIG_EROFS_FS=y\nCONFIG_EROFS_FS_ZIP=y\nCONFIG_OVERLAY_FS=y\nCONFIG_TMPFS=y\nCONFIG_EXT4_FS=y\nCONFIG_SERIAL_8250=y\nCONFIG_SERIAL_8250_CONSOLE=y\nCONFIG_DEVTMPFS=y\nCONFIG_DEVTMPFS_MOUNT=y\nCONFIG_PARAVIRT=y\nCONFIG_KVM_GUEST=y\nCONFIG_KVM=y\nCONFIG_KVM_INTEL=y\nCONFIG_KVM_AMD=y\n".into(),
                    }),
                    Box::new(imp_testing::artifact::rootfs::RootfsStage {
                        source: imp_testing::artifact::rootfs::RootfsBuildSource::Mmdebstrap {
                            release: "bookworm".into(),
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
