use imp_testing::TestVm;
use imp_testing::agent::protocol::ExecRequest;
use imp_testing::config::{RootfsSource, VmConfig};
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::PathBuf;
use std::process::Command;

#[tokio::test]
async fn test_host_endpoint() {
    let _ = env_logger::builder().is_test(true).try_init();
    let ch = CloudHypervisor::new("cloud-hypervisor");
    let vmlinux = PathBuf::from("/tmp/imp-artifacts/vmlinux");
    let rootfs = PathBuf::from("/tmp/imp-artifacts/rootfs.erofs");

    let mut cfg = VmConfig::builder(vmlinux, RootfsSource::Erofs { image: rootfs }).build().unwrap();
    cfg.net = imp_testing::config::NetConfig::Rootless {
        egress: imp_testing::config::Egress::Open,
        host_services: true,
    };

    let mut vm = TestVm::start(&ch, cfg).await.expect("Failed to start VM");

    let host_ip = format!("10.200.{}.1", vm.vmid());

    let mut child = Command::new("python3")
        .args(["-m", "http.server", "8080", "--bind", "127.0.0.1"])
        .spawn()
        .expect("Failed to start http.server");

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let mut agent = vm.agent().await.expect("Failed to connect to agent");

    // Give network time to come up in guest
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let ip_a = agent.exec(ExecRequest::new(vec!["ip".into(), "a".into()])).await.unwrap();
    println!("Guest IP A:\n{}", String::from_utf8_lossy(&ip_a.stdout));
    let ip_r = agent.exec(ExecRequest::new(vec!["ip".into(), "route".into()])).await.unwrap();
    println!("Guest IP Route:\n{}", String::from_utf8_lossy(&ip_r.stdout));
    let ip_n = agent.exec(ExecRequest::new(vec!["ip".into(), "neigh".into()])).await.unwrap();
    println!("Guest IP Neigh:\n{}", String::from_utf8_lossy(&ip_n.stdout));

    let outcome = agent
        .exec(ExecRequest::new(vec![
                "curl".into(),
                "-v".into(),
                format!("http://{}:8080/", host_ip),
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
