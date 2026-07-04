use std::time::Duration;
use vmcell::config::{RootfsSource, VmConfig};
use vmcell::orchestrator::RealClock;
use vmcell_artifact_validator::checks;

mod common;

// The boot contract (kernel banner → agent-ready → exec round-trip) is the extracted
// `checks::*` the artifact validator runs; this test drives them on the built artifacts so a
// regression in either reddens here AND in the validator (single source of truth, v20 §8.5).
vmm_matrix_test!(boot, |vmm| {
    test_boot_impl(&vmm).await;
});

async fn test_boot_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    let cfg = VmConfig::builder(
        common::get_vmlinux(),
        RootfsSource::Erofs {
            image: common::get_rootfs(),
        },
    )
    .network_disabled()
    .build()
    .unwrap();

    let mut vm = common::start_vm(vmm, cfg).await;

    checks::kernel_banner(&vm)
        .await
        .expect("kernel must print the Linux banner");

    let agent = vm
        .agent(Some(Duration::from_secs(60)), &RealClock)
        .await
        .expect("agent must reach ready");
    checks::agent_exec_roundtrip(agent)
        .await
        .expect("exec must round-trip");
    checks::agent_put_file_roundtrip(agent)
        .await
        .expect("put_file must round-trip");

    vm.shutdown().await.expect("Failed to shutdown VM");
}
