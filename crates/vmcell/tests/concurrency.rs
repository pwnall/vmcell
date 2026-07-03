use vmcell::MicroVm;
use vmcell::config::{RootfsSource, VmConfig};
use vmcell::vmm::VmInstance;

mod common;

vmm_matrix_test!(concurrency, |vmm| {
    test_concurrency_impl(&vmm).await;
});

async fn test_concurrency_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    let vmlinux = common::get_vmlinux();
    let rootfs = common::get_rootfs();

    let cfg = VmConfig::builder(vmlinux, RootfsSource::Erofs { image: rootfs })
        .network_disabled()
        .build()
        .unwrap();

    let cid_alloc = std::sync::Arc::new(vmcell::vmm::CidAllocator::new());
    let vmid_alloc = vmcell::orchestrator::VmidAllocator::new();

    // M-TEST-3: drive N>=3 `MicroVm::start` futures CONCURRENTLY (`join_all`) on the
    // SHARED allocators, so simultaneous creation actually races the CID / VMID /
    // netns / nft allocators. The old serial `for` loop `.await`ed each start before
    // the next, so no two creations ever overlapped and an allocator TOCTOU race was
    // untestable. N=3 (not 2) also catches an off-by-one that only repeats every 3rd
    // allocation. A degenerate or unsynchronized allocator that hands out a duplicate
    // CID / VMID / socket path under contention fails the distinctness asserts below.
    let start_futures: Vec<_> = (0..3)
        .map(|_| {
            MicroVm::start(
                vmm,
                cfg.clone(),
                cid_alloc.clone(),
                vmid_alloc.clone(),
                Box::new(vmcell::metrics::DefaultCgroupFs),
            )
        })
        .collect();

    let mut vms = Vec::new();
    for res in futures::future::join_all(start_futures).await {
        vms.push(res.expect("Failed to start VM"));
    }

    // Assert all booted successfully and have distinct VMIDs, guest CIDs, and vsock paths
    let mut vmids = std::collections::HashSet::new();
    let mut vsocks = std::collections::HashSet::new();
    let mut cids = std::collections::HashSet::new();
    for vm in &vms {
        assert!(vmids.insert(vm.vmid()));
        assert!(vsocks.insert(vm.instance().vsock_path().to_path_buf()));
        assert!(cids.insert(vm.instance().guest_cid()));
    }

    for mut vm in vms {
        let agent = match vm
            .agent(
                Some(std::time::Duration::from_secs(180)),
                &vmcell::orchestrator::RealClock,
            )
            .await
        {
            Ok(a) => a,
            Err(e) => {
                if let Ok(log) = std::fs::read_to_string(vm.instance().serial_log()) {
                    println!("VM Serial log on connect timeout:\n{}", log);
                }
                panic!("Failed to connect to agent: {}", e);
            }
        };
        let outcome = match agent
            .exec(vmcell::agent::ExecRequest::new(vec!["true".to_string()]))
            .await
        {
            Ok(o) => o,
            Err(e) => {
                if let Ok(log) = std::fs::read_to_string(vm.instance().serial_log()) {
                    println!("VM Serial log:\n{}", log);
                }
                panic!("exec failed: {}", e);
            }
        };
        assert_eq!(outcome.code, 0, "Execution should succeed");
        vm.shutdown().await.expect("Failed to shut down VM");
    }
}
