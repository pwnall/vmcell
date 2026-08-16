use vmcell::config::{KernelVerbosity, RootfsSource, VmConfig};

mod common;

// §5.3 (The kernel command line): a custom `init=` override boots a different PID 1 (replacing the vmcell guest
// steward), so the vsock control plane is gone. This is a DATA-PLANE proof on the primary
// backend: boot with `init=/bin/sh` at Verbose verbosity (loglevel=7, so the kernel's
// `KERN_INFO` init-exec line prints) and assert the serial log shows the kernel ran the
// overridden init — the same class of assertion as the boot test's kernel banner. Then
// assert `steward()` fails LOUD (§13, Cross-cutting invariants), not hangs, because there is no steward to talk to.
//
// CH-only: this is a backend-agnostic host-side cmdline feature, so one primary-backend
// data-plane proof suffices; QEMU/FC would only add non-standard-boot flake.
#[cfg(feature = "cloud-hypervisor")]
#[tokio::test]
#[ignore = "needs KVM"]
async fn custom_init_boots_and_disables_control_plane() {
    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());

    let cfg = VmConfig::builder(
        common::get_vmlinux(),
        RootfsSource::Erofs {
            image: common::get_rootfs(),
        },
    )
    // `/bin/sh` exists in the base rootfs (existing tests exec `sh -c …`). Verbose so
    // the kernel prints its `Run <init> as init process` line to the serial console.
    .init("/bin/sh")
    .kernel_verbosity(KernelVerbosity::Verbose)
    .network_disabled()
    .build()
    .unwrap();

    let mut vm = common::start_vm(&vmm, cfg).await;

    // The kernel's own boot log is the data plane here (as with the `Linux version`
    // banner check): it names the init it exec'd. Poll the serial log for it.
    let log = vmcell::vmm::VmInstance::serial_log(vm.instance()).to_path_buf();
    let mut ran_custom_init = false;
    for _ in 0..150 {
        if let Ok(content) = tokio::fs::read_to_string(&log).await
            && content.contains("Run /bin/sh as init process")
        {
            ran_custom_init = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        ran_custom_init,
        "kernel serial log did not show it ran the overridden init=/bin/sh within 15s (log {})",
        log.display()
    );

    // The control plane is gone, so `steward()` must fail loud immediately rather than hang
    // connecting to a nonexistent listener. v33 delta 4 re-words the message from the init
    // spelling to the DECLARED PLACEMENT: this config sets `init` and names no placement, so the
    // derived default is `StewardPlacement::None` — the same semantics, said out loud. §3.5
    // records that this assertion moves with the message.
    let err = vm
        .steward(Some(std::time::Duration::from_secs(2)))
        .await
        .expect_err("steward() must fail loud when no steward is expected");
    assert!(
        matches!(err, vmcell::Error::Steward(_))
            && err.to_string().contains("StewardPlacement::None"),
        "expected a fail-loud placement Steward error, got {err:?}"
    );

    vm.kill().await.unwrap();
}
