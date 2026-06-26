use imp_testing::TestVm;
use imp_testing::agent::protocol::ExecRequest;
use imp_testing::config::{RootfsSource, VmConfig};
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::PathBuf;
use std::process::Command;

mod common;

#[tokio::test]
#[ignore]
async fn test_host_endpoint_ch() {
    let vmm = CloudHypervisor::new(common::ch_bin());
    test_host_endpoint_impl(&vmm).await;
}

#[cfg(feature = "firecracker")]
#[tokio::test]
#[ignore]
async fn test_host_endpoint_fc() {
    let vmm = imp_testing::vmm::firecracker::Firecracker::new(common::fc_bin());
    if !imp_testing::vmm::Vmm::capabilities(&vmm).unprivileged_vhost_user_net {
        println!("Skipping: vhost-user-net not supported");
        return;
    }
    test_host_endpoint_impl(&vmm).await;
}

#[cfg(feature = "qemu")]
#[tokio::test]
#[ignore]
async fn test_host_endpoint_qemu() {
    let vmm = imp_testing::vmm::qemu::Qemu::new(common::qemu_bin());
    if !imp_testing::vmm::Vmm::capabilities(&vmm).unprivileged_vhost_user_net {
        println!("Skipping: vhost-user-net not supported");
        return;
    }
    test_host_endpoint_impl(&vmm).await;
}

async fn test_host_endpoint_impl<V: imp_testing::vmm::Vmm>(vmm: &V) {
    let _ = env_logger::builder().is_test(true).try_init();
    let vmlinux = PathBuf::from("/tmp/imp-artifacts/vmlinux");
    let rootfs = PathBuf::from("/tmp/imp-artifacts/rootfs.erofs");

    let mut cfg = VmConfig::builder(vmlinux, RootfsSource::Erofs { image: rootfs })
        .build()
        .unwrap();
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    cfg.net = imp_testing::config::NetConfig::Rootless {
        egress: imp_testing::config::Egress::Open,
        host_services_port: Some(port),
    };

    let cid_alloc = std::sync::Arc::new(imp_testing::vmm::CidAllocator::new());
    let vmid_alloc = imp_testing::orchestrator::VmidAllocator::new();
    let mut vm = TestVm::start(
        vmm,
        cfg,
        cid_alloc.clone(),
        vmid_alloc,
        Box::new(imp_testing::metrics::DefaultCgroupFs),
    )
    .await
    .expect("Failed to start VM");

    let host_ip = format!("10.200.{}.1", vm.vmid());

    let mut child = Command::new("python3")
        .args([
            "-m",
            "http.server",
            &port.to_string(),
            "--bind",
            "127.0.0.1",
        ])
        .spawn()
        .expect("Failed to start http.server");

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let agent = vm
        .agent(None, &imp_testing::orchestrator::RealClock)
        .await
        .expect("Failed to connect to agent");

    // Give network time to come up in guest
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let ip_a = agent
        .exec(ExecRequest::new(vec!["ip".into(), "a".into()]))
        .await
        .unwrap();
    assert_eq!(
        ip_a.code,
        0,
        "ip a failed: {:?}",
        String::from_utf8_lossy(&ip_a.stderr)
    );
    println!("Guest IP A:\n{}", String::from_utf8_lossy(&ip_a.stdout));
    let ip_r = agent
        .exec(ExecRequest::new(vec!["ip".into(), "route".into()]))
        .await
        .unwrap();
    assert_eq!(
        ip_r.code,
        0,
        "ip route failed: {:?}",
        String::from_utf8_lossy(&ip_r.stderr)
    );
    println!("Guest IP Route:\n{}", String::from_utf8_lossy(&ip_r.stdout));
    let ip_n = agent
        .exec(ExecRequest::new(vec!["ip".into(), "neigh".into()]))
        .await
        .unwrap();
    assert_eq!(
        ip_n.code,
        0,
        "ip neigh failed: {:?}",
        String::from_utf8_lossy(&ip_n.stderr)
    );
    println!("Guest IP Neigh:\n{}", String::from_utf8_lossy(&ip_n.stdout));

    let outcome = agent
        .exec(ExecRequest::new(vec![
            "curl".into(),
            "--max-time".into(),
            "5".into(),
            "-v".into(),
            format!("http://{}:{}/", host_ip, port),
        ]))
        .await
        .expect("Exec failed");

    let _ = child.kill();
    let _ = child.wait();

    assert_eq!(
        outcome.code,
        0,
        "curl failed: {:?}",
        String::from_utf8_lossy(&outcome.stderr)
    );
    let stdout = String::from_utf8_lossy(&outcome.stdout);
    assert!(
        stdout.contains("Directory listing") || stdout.contains("html"),
        "Output did not contain expected HTTP response: {}",
        stdout
    );

    vm.shutdown().await.expect("Shutdown failed");
}
