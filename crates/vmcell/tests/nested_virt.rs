use vmcell::config::{RootfsSource, VmConfig};
use vmcell::orchestrator::MicroVm;
use vmcell::steward::protocol::ExecRequest;

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
        !vmcell::vmm::Vmm::capabilities(&vmcell_firecracker::Firecracker::new(common::fc_bin()))
            .nested_virt,
        "FC must NOT advertise nested_virt; a true here hides a real gap"
    );
    #[cfg(feature = "qemu")]
    assert!(
        vmcell::vmm::Vmm::capabilities(&vmcell_qemu::Qemu::new(common::qemu_bin())).nested_virt,
        "QEMU must support nested_virt; a false silently skips nested_virt::qemu"
    );
    #[cfg(feature = "crosvm")]
    assert!(
        !vmcell::vmm::Vmm::capabilities(&vmcell_crosvm::Crosvm::new(common::crosvm_bin()))
            .nested_virt,
        "crosvm must NOT advertise nested_virt (documented-unsupported); a true here hides a real gap"
    );
}

// H-TEST-3: capability-honesty pin for `virtio_console`, the KVM-free half of the pair. Its live
// half is `virtio_console` below (docs/90 T3 — this pin used to say in its own comment that the
// flag "has no dedicated matrix integration leg", which is what made the descriptor value the only
// evidence on record). FC has no virtio-console device (`console=hvc0` with no device silences the
// log), so it must advertise false; CH and QEMU expose `hvc0` and must advertise true. A
// regression flipping any of these — e.g. FC->true, which would let a VirtioConsole config through
// and silence the serial log — reddens here, and a flip to false would make the live leg's
// `require_cap!` skip go dark. Inverse: flip any asserted value.
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
        !vmcell::vmm::Vmm::capabilities(&vmcell_firecracker::Firecracker::new(common::fc_bin()))
            .virtio_console,
        "FC must NOT advertise virtio_console (no hvc0 device); a true would silence the serial log on a VirtioConsole config"
    );
    #[cfg(feature = "qemu")]
    assert!(
        vmcell::vmm::Vmm::capabilities(&vmcell_qemu::Qemu::new(common::qemu_bin())).virtio_console,
        "QEMU must advertise virtio_console (it attaches hvc0)"
    );
    #[cfg(feature = "crosvm")]
    assert!(
        vmcell::vmm::Vmm::capabilities(&vmcell_crosvm::Crosvm::new(common::crosvm_bin()))
            .virtio_console,
        "crosvm must advertise virtio_console (--serial hardware=virtio-console exposes hvc0)"
    );
}

// docs/90 T3: `ConsoleMode::VirtioConsole` booted, on the data plane. Three backends advertise
// `virtio_console` and nothing ever booted one: the pin above was the whole record, and the only
// live evidence anywhere was `bench-vm`'s console table, which is not a gate.
//
// The failure this catches is specifically nasty because it is SILENT. Under `VirtioConsole` the
// device wiring (CH's `serial: Off` + `console: File` pair, QEMU's `virtio-serial-pci` +
// `virtconsole`) and the cmdline's `console=hvc0` token are driven by the same `cfg.console_mode`
// but emitted in different places. Desync them and `serial.log` simply stays empty — and an empty
// serial log is indistinguishable from a quiet boot, on the one configuration that has already
// given up early-boot capture.
//
// Two data-plane assertions, one per half of that desync:
//   * the guest's ACTIVE console is `hvc0` (`/sys/class/tty/console/active`) — the cmdline token
//     took effect, so `/dev/console` really is the virtio console and not the 8250 UART;
//   * a marker the guest writes to `/dev/console` arrives in the host's `serial.log` — the device
//     the VMM attached really sinks to that file.
//
// `require_cap!` makes the Firecracker skip honest (FC has no hvc0 device; the pin above is what
// keeps that skip from going dark). crosvm's leg compiles under `--features crosvm` and runs in
// `just test-crosvm`, which is where its `--serial hardware=virtio-console` claim — previously an
// arg-builder unit test and nothing else — gets its live evidence. MEASURED 2026-08-17: CH, QEMU
// **and crosvm** all pass this leg; FC records `SKIP firecracker virtio_console`.
//
// RED ON THE INVERSE: make `console_devices` return the `Uart` pair for `VirtioConsole` (or drop
// the `console` device) and the marker never reaches `serial.log`; change the cmdline token to
// `ttyS0` while leaving the device wiring alone and the active-console assertion fires first.
vmm_matrix_test!(virtio_console, |vmm| {
    require_cap!(vmcell::vmm::Vmm::capabilities(&vmm), virtio_console, vmm);
    test_virtio_console_impl(&vmm).await;
});

/// The marker the guest writes to `/dev/console`. Distinctive enough that a kernel or steward line
/// cannot produce it by accident.
const HVC_MARKER: &str = "VMCELL-HVC0-MARKER";

async fn test_virtio_console_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    let cfg = VmConfig::builder(
        common::get_vmlinux(),
        RootfsSource::Erofs {
            image: common::get_rootfs(),
        },
    )
    .console_mode(vmcell::config::ConsoleMode::VirtioConsole)
    .network_disabled()
    .build()
    .unwrap();

    let mut vm = common::start_vm(vmm, cfg).await;
    let log = vmcell::vmm::VmInstance::serial_log(vm.instance()).to_path_buf();

    let steward = vm
        .steward(Some(std::time::Duration::from_secs(60)))
        .await
        .expect("steward must reach ready under VirtioConsole");
    // One exec for both halves: report the active console on stdout (over vsock, so it arrives
    // whatever the console is doing) and write the marker to /dev/console.
    let outcome = steward
        .exec(ExecRequest::new(vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("cat /sys/class/tty/console/active; echo {HVC_MARKER} > /dev/console; echo ok"),
        ]))
        .await
        .expect("exec must round-trip over vsock");
    let stdout = String::from_utf8_lossy(&outcome.stdout).into_owned();
    assert_eq!(outcome.code, 0, "console probe script failed: {outcome:?}");
    assert!(
        stdout.lines().any(|l| l.trim() == "hvc0"),
        "the guest's active console must be hvc0 under ConsoleMode::VirtioConsole — a ttyS0 here \
         means the cmdline `console=` token desynced from the device wiring; stdout={stdout:?}"
    );

    // The write goes through the virtio-console device and the VMM's file sink, so poll rather
    // than read once.
    let mut arrived = false;
    for _ in 0..100 {
        if let Ok(content) = tokio::fs::read_to_string(&log).await
            && content.contains(HVC_MARKER)
        {
            arrived = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    if !arrived {
        let content = tokio::fs::read_to_string(&log).await.unwrap_or_default();
        panic!(
            "a guest write to /dev/console did not reach serial.log within 10s under \
             ConsoleMode::VirtioConsole — the virtio-console device is not sinking to the file \
             (log {}, {} bytes):\n{content}",
            log.display(),
            content.len()
        );
    }

    vm.shutdown()
        .await
        .expect("shutdown after the console probe");
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

    let steward = match vm.steward(None).await {
        Ok(a) => a,
        Err(e) => {
            use vmcell::vmm::VmInstance;
            let log = tokio::fs::read_to_string(vm.instance().serial_log())
                .await
                .unwrap_or_default();
            panic!("Failed to connect to steward: {e}\nSerial log:\n{log}");
        }
    };

    // The positive nested-virt contract is the extracted `checks::nested_kvm_ok` the validator
    // runs (§4.4, The in-rootfs guest-tools helper); driving it here keeps one implementation.
    vmcell_artifact_validator::checks::nested_kvm_ok(steward)
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

    let steward = match vm.steward(None).await {
        Ok(a) => a,
        Err(e) => {
            use vmcell::vmm::VmInstance;
            let log = tokio::fs::read_to_string(vm.instance().serial_log())
                .await
                .unwrap_or_default();
            panic!("Failed to connect to steward: {e}\nSerial log:\n{log}");
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
    let result = steward
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
