use clap::Parser;
use std::time::{Duration, Instant};
use std::sync::Arc;
use std::path::PathBuf;

use imp_testing::config::{VmConfig, RootfsSource, NetConfig};
use imp_testing::vmm::{Vmm, VmInstance, CidAllocator};
use imp_testing::orchestrator::{TestVm, VmidAllocator};

#[derive(Parser, Debug)]
#[command(author, version, about = "Macro-benchmarking harness for Imp-testing VMs")]
struct Args {
    #[arg(long, default_value = "cloud-hypervisor")]
    backend: String,
    
    #[arg(long, default_value_t = 10)]
    iterations: usize,
    
    #[arg(long, default_value_t = 3)]
    warmup: usize,
}

fn report(name: &str, latencies: &mut Vec<u128>) {
    if latencies.is_empty() {
        println!("{}: No successful runs", name);
        return;
    }
    latencies.sort_unstable();
    let count = latencies.len() as f64;
    let p50 = latencies[(count * 0.5) as usize];
    let p95 = latencies[(count * 0.95).floor() as usize];
    let p99 = latencies[(count * 0.99).floor() as usize];
    let max = latencies.last().unwrap();
    
    println!("{}: count={} p50={}ms p95={}ms p99={}ms max={}ms", name, latencies.len(), p50, p95, p99, max);
}

async fn run_bench<V: Vmm>(vmm: &V, name: &str, args: &Args, allocator: Arc<VmidAllocator>, is_restore: bool) {
    println!("Starting benchmark: {}", name);
    let mut latencies = Vec::new();
    
    let artifacts_dir = std::env::var("IMP_ARTIFACTS_DIR").unwrap_or_else(|_| "/tmp/imp-artifacts".into());
    let cfg = VmConfig::builder(
        PathBuf::from(&artifacts_dir).join("vmlinux"),
        RootfsSource::Erofs { image: PathBuf::from(&artifacts_dir).join("rootfs.erofs") }
    )
        .vcpus(1)
        .mem_mib(256)
        .build()
        .unwrap();
    let cid_allocator = CidAllocator::new();

    let snap_dir = std::env::temp_dir().join(format!("imp-bench-snap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&snap_dir);

    if is_restore {
        println!("Creating baseline snapshot for restore benchmark...");
        let mut base_vm = match TestVm::start(vmm, cfg.clone(), &cid_allocator, allocator.clone()).await {
            Ok(vm) => vm,
            Err(e) => {
                println!("Failed to start base VM for snapshotting: {}", e);
                return;
            }
        };
        if let Err(e) = base_vm.agent().await {
            println!("Failed to connect to base VM agent: {}", e);
            let _ = base_vm.shutdown().await;
            return;
        }
        std::fs::create_dir_all(&snap_dir).unwrap();
        if let Err(e) = base_vm.instance_mut().snapshot(&snap_dir).await {
            println!("Failed to take snapshot of base VM: {}", e);
            let _ = base_vm.shutdown().await;
            let _ = std::fs::remove_dir_all(&snap_dir);
            return;
        }
        let _ = base_vm.shutdown().await;
    }
    
    for i in 0..(args.iterations + args.warmup) {
        if !is_restore {
            // Drop page cache for cold boot
            let _ = std::process::Command::new("sudo")
                .arg("sh").arg("-c").arg("echo 3 > /proc/sys/vm/drop_caches")
                .status();
        }
        
        let start = Instant::now();
        let vm_res = if is_restore {
            TestVm::restore(vmm, &snap_dir, cfg.clone(), &cid_allocator, allocator.clone()).await
        } else {
            TestVm::start(vmm, cfg.clone(), &cid_allocator, allocator.clone()).await
        };
        
        match vm_res {
            Ok(mut vm) => {
                if let Ok(_agent) = vm.agent().await {
                    let elapsed = start.elapsed().as_millis();
                    if i >= args.warmup {
                        latencies.push(elapsed);
                    }
                }
                let _ = vm.shutdown().await;
            },
            Err(e) => {
                println!("Run failed (expected if artifacts/KVM are missing): {}", e);
                break;
            }
        }
    }
    
    if is_restore {
        let _ = std::fs::remove_dir_all(&snap_dir);
    }
    
    report(name, &mut latencies);
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    println!("Running benchmarks with backend: {}", args.backend);
    
    let allocator = Arc::new(VmidAllocator::new());
    
    match args.backend.as_str() {
        #[cfg(feature = "cloud-hypervisor")]
        "cloud-hypervisor" => {
            let vmm = imp_testing::vmm::cloud_hypervisor::CloudHypervisor::new("cloud-hypervisor");
            println!("Capabilities: {:?}", vmm.capabilities());
            run_bench(&vmm, "Cold Boot", &args, allocator.clone(), false).await;
            if vmm.capabilities().snapshot_restore {
                run_bench(&vmm, "Warm Restore", &args, allocator.clone(), true).await;
            }
        },
        #[cfg(feature = "firecracker")]
        "firecracker" => {
            let vmm = imp_testing::vmm::firecracker::Firecracker::new("firecracker");
            println!("Capabilities: {:?}", vmm.capabilities());
            run_bench(&vmm, "Cold Boot", &args, allocator.clone(), false).await;
            if vmm.capabilities().snapshot_restore {
                run_bench(&vmm, "Warm Restore", &args, allocator.clone(), true).await;
            }
        },
        #[cfg(feature = "qemu")]
        "qemu" => {
            let vmm = imp_testing::vmm::qemu::Qemu::new("qemu-system-x86_64");
            println!("Capabilities: {:?}", vmm.capabilities());
            run_bench(&vmm, "Cold Boot", &args, allocator.clone(), false).await;
            if vmm.capabilities().snapshot_restore {
                run_bench(&vmm, "Warm Restore", &args, allocator.clone(), true).await;
            }
        },
        _ => {
            println!("Unsupported backend or feature not enabled");
        }
    }
    
    Ok(())
}
