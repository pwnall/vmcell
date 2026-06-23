use imp_testing::TestVm;
use imp_testing::agent::protocol::ExecRequest;
use imp_testing::config::{RootfsSource, VmConfig};
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::PathBuf;
use std::process::Command;

#[tokio::test]
async fn test_host_endpoint() {

    let ch = CloudHypervisor::new("cloud-hypervisor");
    let vmlinux = PathBuf::from("/tmp/imp-artifacts/vmlinux");
    let rootfs = PathBuf::from("/tmp/imp-artifacts/rootfs.ext4");

    let mut cfg = VmConfig::builder(
        vmlinux,
        RootfsSource::Erofs {
                image: rootfs,
            },
    )
    .build();
    cfg.net = imp_testing::config::NetConfig::Privileged { egress: imp_testing::config::Egress::Open, host_services: true };

    let mut vm = TestVm::start(&ch, cfg).await.expect("Failed to start VM");

    let netns_name = vm.netns.as_ref().unwrap().name.clone();
    let host_ip = vm.netns.as_ref().unwrap().host_ip();

    let mut child = Command::new("ip")
        .args([
            "netns",
            "exec",
            &netns_name,
            "python3",
            "-m",
            "http.server",
            "8080",
        ])
        .spawn()
        .expect("Failed to start http.server");

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let mut agent = vm.agent().await.expect("Failed to connect to agent");

    // Give network time to come up in guest
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let outcome = agent
        .exec(ExecRequest {
            argv: vec![
                "curl".into(),
                "-s".into(),
                format!("http://{}:8080/", host_ip),
            ],
            env: vec![],
            cwd: None,
        })
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
