use vmcell::agent::protocol::ExecRequest;
use vmcell::config::{RootfsSource, VmConfig};
use vmcell::orchestrator::MicroVm;

mod common;

vmm_matrix_test!(nested_virt, |vmm| {
    require_cap!(vmcell::vmm::Vmm::capabilities(&vmm), nested_virt, vmm);
    test_nested_virt_impl(&vmm).await;
});

// H-TEST-3: capability-honesty pin for `nested_virt`. A require_cap! skip is an
// invisible nextest PASS, so if a backend's `nested_virt` flipped false the
// nested_virt leg would go dark silently. This non-KVM pin fixes the documented
// value per backend so the flip reddens here. Inverse: flip any asserted value.
#[test]
fn capability_honesty_nested_virt() {
    #[cfg(feature = "cloud-hypervisor")]
    assert!(
        vmcell::vmm::Vmm::capabilities(&vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(
            common::ch_bin()
        ))
        .nested_virt,
        "CH (primary) must support nested_virt; a false silently skips nested_virt::cloud_hypervisor"
    );
    #[cfg(feature = "firecracker")]
    assert!(
        !vmcell::vmm::Vmm::capabilities(&vmcell::vmm::firecracker::Firecracker::new(
            common::fc_bin()
        ))
        .nested_virt,
        "FC must NOT advertise nested_virt; a true here hides a real gap"
    );
    #[cfg(feature = "qemu")]
    assert!(
        vmcell::vmm::Vmm::capabilities(&vmcell::vmm::qemu::Qemu::new(common::qemu_bin()))
            .nested_virt,
        "QEMU must support nested_virt; a false silently skips nested_virt::qemu"
    );
}

// H-TEST-3: capability-honesty pin for `virtio_console`. This flag has no dedicated
// matrix integration leg, so its descriptor value is pinned here alongside the
// other guest-visible-feature capability. FC has no virtio-console device
// (`console=hvc0` with no device silences the log), so it must advertise false; CH
// and QEMU expose `hvc0` and must advertise true. A regression flipping any of
// these — e.g. FC->true, which would let a VirtioConsole config through and silence
// the serial log — reddens here. Inverse: flip any asserted value.
#[test]
fn capability_honesty_virtio_console() {
    #[cfg(feature = "cloud-hypervisor")]
    assert!(
        vmcell::vmm::Vmm::capabilities(&vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(
            common::ch_bin()
        ))
        .virtio_console,
        "CH must advertise virtio_console (it attaches hvc0)"
    );
    #[cfg(feature = "firecracker")]
    assert!(
        !vmcell::vmm::Vmm::capabilities(&vmcell::vmm::firecracker::Firecracker::new(
            common::fc_bin()
        ))
        .virtio_console,
        "FC must NOT advertise virtio_console (no hvc0 device); a true would silence the serial log on a VirtioConsole config"
    );
    #[cfg(feature = "qemu")]
    assert!(
        vmcell::vmm::Vmm::capabilities(&vmcell::vmm::qemu::Qemu::new(common::qemu_bin()))
            .virtio_console,
        "QEMU must advertise virtio_console (it attaches hvc0)"
    );
}

async fn test_nested_virt_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    let kernel = common::get_vmlinux();
    let rootfs_image = common::get_rootfs();

    let mut cfg = VmConfig::builder(
        kernel,
        RootfsSource::Erofs {
            image: rootfs_image,
        },
    )
    .network_disabled()
    .build()
    .unwrap();

    // Enable nested virtualization
    cfg.nested_virt = true;

    let env = vmcell::HostEnv::hermetic();
    let mut vm = MicroVm::start(vmm, cfg, &env)
        .await
        .expect("Failed to start VM");

    let agent = match vm.agent(None).await {
        Ok(a) => a,
        Err(e) => {
            use vmcell::vmm::VmInstance;
            let log = tokio::fs::read_to_string(vm.instance().serial_log())
                .await
                .unwrap_or_default();
            panic!("Failed to connect to agent: {e}\nSerial log:\n{log}");
        }
    };

    // The positive nested-virt contract is the extracted `checks::nested_kvm_ok` the validator
    // runs (§8.5); driving it here keeps one implementation.
    vmcell_artifact_validator::checks::nested_kvm_ok(agent)
        .await
        .expect("nested /dev/kvm must be exposed with nested_virt = true");

    vm.shutdown().await.expect("Failed to shutdown VM");
}

// L-TEST-6: negative control. The positive test above asserts `kvm-ok` exits 0
// with `nested_virt = true`; alone that is failing-capable only while a guest
// without VMX passthrough happens to lack /dev/kvm. If a backend change ever made
// VMX exposure UNCONDITIONAL, the flag would become a no-op with no red test. This
// control boots the SAME config with `nested_virt = false` and asserts `kvm-ok`
// exits NON-zero, pinning the flag as the causal lever: if disabling it no longer
// removes nested virt, this goes red.
vmm_matrix_test!(nested_virt_disabled, |vmm| {
    require_cap!(vmcell::vmm::Vmm::capabilities(&vmm), nested_virt, vmm);
    test_nested_virt_disabled_impl(&vmm).await;
});

async fn test_nested_virt_disabled_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    let kernel = common::get_vmlinux();
    let rootfs_image = common::get_rootfs();

    let mut cfg = VmConfig::builder(
        kernel,
        RootfsSource::Erofs {
            image: rootfs_image,
        },
    )
    .network_disabled()
    .build()
    .unwrap();

    // Explicitly DISABLE nested virtualization (the lever under test).
    cfg.nested_virt = false;

    let env = vmcell::HostEnv::hermetic();
    let mut vm = MicroVm::start(vmm, cfg, &env)
        .await
        .expect("Failed to start VM");

    let agent = match vm.agent(None).await {
        Ok(a) => a,
        Err(e) => {
            use vmcell::vmm::VmInstance;
            let log = tokio::fs::read_to_string(vm.instance().serial_log())
                .await
                .unwrap_or_default();
            panic!("Failed to connect to agent: {e}\nSerial log:\n{log}");
        }
    };

    // `kvm-ok` is NOT a causal probe for `nested_virt`: `-cpu host` exposes VMX
    // unconditionally, so L1 `/dev/kvm` exists regardless. What `nested_virt`
    // actually controls is the guest KVM's *nested* (L2) module parameter
    // (`kvm-{intel,amd}.nested`, set on the cmdline). With `nested_virt = false`
    // the cmdline emits `nested=0`, so the param must read `N`/`0`. If disabling the
    // flag no longer flips this param (e.g. the token stops being emitted, or the
    // kernel default leaks through), this goes red — pinning the flag as the causal
    // lever.
    let result = agent
        .exec(ExecRequest::new(vec![
            "sh".to_string(),
            "-c".to_string(),
            "cat /sys/module/kvm_intel/parameters/nested 2>/dev/null || \
             cat /sys/module/kvm_amd/parameters/nested 2>/dev/null"
                .to_string(),
        ]))
        .await
        .expect("Failed to read the kvm nested parameter");
    let nested = String::from_utf8_lossy(&result.stdout).trim().to_string();
    println!("kvm nested param (nested_virt=false): {nested:?}");
    assert!(
        matches!(nested.as_str(), "N" | "0"),
        "the guest KVM `nested` parameter must be disabled (N/0) when nested_virt is \
         false; got {nested:?} — a Y/1 means the flag is a no-op (the cmdline token \
         was dropped or the kernel default leaked through)"
    );

    vm.shutdown().await.expect("Failed to shutdown VM");
}
