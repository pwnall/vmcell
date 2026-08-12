//! Host-USB passthrough (design §2.4, v30 §18 delta 9 — FR-V5).
//!
//! Deliberately split by what can be proven without a designated device. Everything but
//! the last is KVM-free and binary-free, and runs in `just test-unit` / `just ci` under
//! `--all-features`:
//!
//! * `capability_honesty_usb_host_passthrough` — the per-backend stance across ALL FOUR
//!   backends (QEMU true; CH / Firecracker / crosvm false).
//! * `incapable_backends_refuse_a_usb_config_at_create` — the three incapable backends
//!   refuse typed from the REAL `create()`, with QEMU as the positive control.
//! * `usbhost_kernel_label_and_fragment_are_pinned` — the live leg's guest kernel is
//!   buildable from the committed pins (a recipe naming an unbuildable kernel is an
//!   un-runnable gate) and stays a GENERIC vmcell-owned fragment (G1).
//! * `qemu_refuses_a_usb_device_absent_from_the_host` — the capable backend refuses a
//!   device this host does not have, because QEMU itself accepts it in silence.
//! * `usb_passthrough_qemu` — the live leg, `#[ignore]`d and **QEMU-only**, run by the
//!   opt-in `just test-usb-passthrough` recipe against a designated host device.
//!
//! The argv half — that the requested devices actually reach QEMU's command line — is
//! pinned in `vmcell-qemu` over the composed `Command` (`qemu_full_argv_splices_the_usb_
//! fragment`), where it can go red without a VM.
//!
//! Why the live leg is NOT a `vmm_matrix_test!` + `require_cap!`: `require_cap!` PANICS
//! ("SKIP == PASS ERROR") when the *primary* backend lacks the capability, and
//! cloud-hypervisor is honest-`false` here — `usb_host_passthrough` is the first flag
//! whose primary-backend stance is `false`. A matrix leg would therefore hard-fail
//! `usb_passthrough::cloud_hypervisor` on every KVM host. Scoping the live leg to the
//! QEMU arm explicitly is a recorded deviation — docs/implementation-notes.md,
//! "v30 delta 9 — host-USB passthrough", under *Deviations from the §18 sketch*.

use vmcell::config::{RootfsSource, UsbHostDevice, VmConfig};

mod common;

/// The env var naming the designated, disposable host device as `<vid>:<pid>` (hex, as
/// printed by `lsusb`). Set by the `just test-usb-passthrough` recipe, which refuses to
/// run without it. Read only by the QEMU-only live leg.
#[cfg(feature = "qemu")]
const USB_DEVICE_ENV: &str = "VMCELL_TEST_USB_DEVICE";

// H-TEST-3 capability-honesty pin, the ninth flag. A backend that silently flipped this
// `true` would emit (or silently drop) USB argv with nothing asserting on it, and one
// flipped `false` on QEMU would turn every USB config into a typed refusal with the live
// leg skipping quietly. KVM-free: it constructs the backends but never boots them.
// Inverse: flip any asserted value in the corresponding `capabilities()` literal.
#[test]
fn capability_honesty_usb_host_passthrough() {
    #[cfg(feature = "cloud-hypervisor")]
    assert!(
        !vmcell::vmm::Vmm::capabilities(&vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(
            common::ch_bin()
        ))
        .usb_host_passthrough,
        "CH has no upstream USB device model; a true would silently drop the requested device \
         instead of refusing it at create()"
    );
    #[cfg(feature = "firecracker")]
    assert!(
        !vmcell::vmm::Vmm::capabilities(&vmcell_firecracker::Firecracker::new(common::fc_bin()))
            .usb_host_passthrough,
        "FC's minimal device model has no USB controller; a true would silently drop the device"
    );
    #[cfg(feature = "qemu")]
    assert!(
        vmcell::vmm::Vmm::capabilities(&vmcell_qemu::Qemu::new(common::qemu_bin()))
            .usb_host_passthrough,
        "QEMU is the one backend that attaches a host USB device (qemu-xhci + usb-host, §2.4); \
         a false would make every USB config a typed refusal and silently skip the live leg"
    );
    #[cfg(feature = "crosvm")]
    assert!(
        !vmcell::vmm::Vmm::capabilities(&vmcell_crosvm::Crosvm::new(common::crosvm_bin()))
            .usb_host_passthrough,
        "vmcell always launches crosvm with --no-usb (its xhci is not Suspendable, §2.5), so there \
         is no bus to attach to; a true would silently drop the device"
    );
}

// The non-QEMU backends must REFUSE a USB config rather than boot a guest without the
// device the caller asked for. This drives the REAL `create()` — the refusal runs before
// any spawn, so it is KVM-free, needs no VMM binary on PATH, and needs no artifacts (the
// kernel/rootfs paths below are never opened). Inverse: drop the
// `reject_usb_host_devices` call from a backend's `create()` and its arm here reddens with
// a spawn error instead of the typed refusal. The feature string is the `VmmCapabilities`
// field name (N-VMM-1), which is what a caller matches on.
#[tokio::test]
async fn incapable_backends_refuse_a_usb_config_at_create() {
    fn usb_config() -> VmConfig {
        VmConfig::builder(
            std::path::PathBuf::from("/nonexistent/vmlinux"),
            RootfsSource::Erofs {
                image: std::path::PathBuf::from("/nonexistent/rootfs.erofs"),
            },
        )
        .with_usb_host_device(UsbHostDevice::new(0x1d6b, 0x0002))
        // Keeps the FC/crosvm net and share guards (which run before the USB one) from
        // firing first, so the assertion below is about USB and nothing else.
        .network_disabled()
        .build()
        .expect("a single non-zero USB device on a non-snapshotting config must build")
    }
    fn res() -> vmcell::vmm::PerVmResources {
        vmcell::vmm::PerVmResources {
            cgroup_name: "vmcell-usb-refusal-test".to_string(),
            tap_name: None,
            netns_name: None,
            segment: None,
            vhost_user_socket: None,
            vmid: 1,
            guest_cid: 3,
            tmp_dir: std::path::PathBuf::from("/nonexistent/vmcell-usb-refusal-test"),
        }
    }
    fn assert_refuses(err: &vmcell::error::Error, vmm_id: &str) {
        assert!(
            matches!(err, vmcell::error::Error::Unsupported { vmm, feature }
                if vmm == vmm_id && feature == "usb_host_passthrough"),
            "expected Unsupported{{vmm: {vmm_id:?}, feature: \"usb_host_passthrough\"}}, got {err:?}"
        );
    }
    // `DefaultCgroupFs` is never touched: the refusal returns first.
    let cgroups = vmcell::metrics::DefaultCgroupFs;

    #[cfg(feature = "cloud-hypervisor")]
    {
        let created = vmcell::vmm::Vmm::create(
            &vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin()),
            &usb_config(),
            &res(),
            &cgroups,
        )
        .await;
        let Err(err) = created else {
            panic!("CH must refuse a host USB device");
        };
        assert_refuses(&err, "cloud-hypervisor");
    }
    #[cfg(feature = "firecracker")]
    {
        let created = vmcell::vmm::Vmm::create(
            &vmcell_firecracker::Firecracker::new(common::fc_bin()),
            &usb_config(),
            &res(),
            &cgroups,
        )
        .await;
        let Err(err) = created else {
            panic!("FC must refuse a host USB device");
        };
        assert_refuses(&err, "firecracker");
    }
    #[cfg(feature = "crosvm")]
    {
        let created = vmcell::vmm::Vmm::create(
            &vmcell_crosvm::Crosvm::new(common::crosvm_bin()),
            &usb_config(),
            &res(),
            &cgroups,
        )
        .await;
        let Err(err) = created else {
            panic!("crosvm must refuse a host USB device");
        };
        assert_refuses(&err, "crosvm");
    }
    // Positive control: the capable backend does NOT refuse the same list (an over-broad
    // refusal that ignored the capability flag would redden here). Asserted on the shared
    // predicate rather than on `create()` — QEMU proceeds past it into a real spawn, which
    // is the live leg's job, not this KVM-free test's.
    #[cfg(feature = "qemu")]
    {
        let caps = vmcell::vmm::Vmm::capabilities(&vmcell_qemu::Qemu::new(common::qemu_bin()));
        vmcell::vmm::reject_usb_host_devices("qemu", &caps, &[UsbHostDevice::new(0x1d6b, 0x0002)])
            .expect("QEMU must accept a host USB device");
    }
}

// v30 §18 delta 9 GATE (the live leg's kernel): `just test-usb-passthrough` boots a
// `vmlinux-usbhost` build, so that label must be BUILDABLE from the committed pins through
// the §5.6 toolkit — a recipe pointing at a kernel nobody can build is an un-runnable
// gate, which is exactly how the argv splice went unguarded. KVM-free and toolchain-free:
// it resolves the registry, not a build. Inverse: remove `kernels.usbhost` (or its
// `fragments` key, or the `kernel_fragments.USBHOST` text) from pins.json and this reddens.
#[test]
fn usbhost_kernel_label_and_fragment_are_pinned() {
    let registry =
        vmcell::artifact::resolve_kernel_registry(None).expect("the baseline registry resolves");
    let entry = registry
        .iter()
        .find(|e| e.label == "usbhost")
        .unwrap_or_else(|| {
            panic!(
                "pins `kernels.usbhost` is missing, so `vmcell build-kernels`/\
                 `build_labelled_kernel(\"usbhost\")` cannot produce the kernel \
                 `just test-usb-passthrough` requires; registry holds {:?}",
                registry.iter().map(|e| &e.label).collect::<Vec<_>>()
            )
        });
    // The LABEL alone must determine the build (§5.5) — a `kernels.usbhost` without its
    // `fragments` key would build a USB-less kernel and the live leg would die at NOBUS.
    assert_eq!(
        entry.fragments,
        vec!["USBHOST".to_string()],
        "the usbhost label must declare its KConfig fragment"
    );

    // The artifact the recipe tells the operator to point `VMCELL_KERNEL` at.
    let stage = vmcell::artifact::kernel::KernelStage {
        http_client: std::sync::Arc::new(vmcell::artifact::kernel::ReqwestClient),
        label: Some(entry.label.clone()),
        fragments: Some(entry.fragments.clone()),
    };
    assert_eq!(
        vmcell::artifact::Stage::out_path(&stage, std::path::Path::new("/t")),
        std::path::PathBuf::from("/t/vmlinux-usbhost"),
        "the usbhost label must produce `vmlinux-usbhost` (§2.4, the justfile recipe)"
    );

    let pins = vmcell::artifact::resolve_pins(None).expect("the baseline pins resolve");
    let key = vmcell::artifact::kernel::fragment_pin_key("USBHOST");
    let fragment = pins
        .get(&key)
        .unwrap_or_else(|| panic!("pins `kernel_fragments.USBHOST` is missing (key `{key}`)"));
    // Generic host-controller support: xhci (what `-device qemu-xhci` presents), USB core,
    // and ONE class-smoke driver — enough to enumerate a device and bind a class.
    for symbol in [
        "CONFIG_USB=y",
        "CONFIG_USB_PCI=y",
        "CONFIG_USB_XHCI_HCD=y",
        "CONFIG_USB_XHCI_PCI=y",
        "CONFIG_USB_HID=y",
    ] {
        assert!(
            fragment.contains(symbol),
            "the usbhost fragment must carry {symbol}; got {fragment:?}"
        );
    }
    // G1 (vmcell ships mechanisms, never consumer content): this is vmcell's own
    // capability-gate fragment — the one defended exception shape — and must NEVER carry
    // the consumer usbip/gadget closure FR-V5 withdrew.
    for banned in ["USBIP", "VHCI_HCD", "DUMMY_HCD", "USB_GADGET", "USB_G_"] {
        assert!(
            !fragment.contains(banned),
            "the usbhost fragment must stay generic; it names {banned} — that closure is \
             consumer content (G1, §2.4)"
        );
    }
    // Premise the live leg's NOBUS diagnostic rests on: the DEFAULT kernel has no USB at
    // all, which is why the fragment (and this label) exist.
    let base = pins
        .get("kernel_microvm_config")
        .expect("the baseline carries kernel_microvm_config");
    assert!(
        !base.contains("CONFIG_USB"),
        "the stock vmcell kernel config must stay USB-free (the fragment is what adds it)"
    );
}

// The capable backend must not silently degrade either. MEASURED (QEMU 10.2.1,
// 2026-08-11): `-device usb-host,vendorid=0xdead,productid=0xbeef` for a device that is
// not attached starts QEMU normally, reaches QMP `prelaunch`, and says NOTHING — the
// guest just gets an empty xhci bus. So QEMU's `create()` resolves every requested id
// pair to its `/dev/bus/usb` node first and fails loud. KVM-free and binary-free: the
// refusal returns before any spawn. Inverse: drop the `require_usb_host_devices` call
// from `Qemu::create()` and this reddens (create proceeds to spawn instead of refusing).
#[cfg(feature = "qemu")]
#[tokio::test]
async fn qemu_refuses_a_usb_device_absent_from_the_host() {
    let cfg = VmConfig::builder(
        std::path::PathBuf::from("/nonexistent/vmlinux"),
        RootfsSource::Erofs {
            image: std::path::PathBuf::from("/nonexistent/rootfs.erofs"),
        },
    )
    // 0xdead:0xbeef is not a real USB assignment, so no host can match it.
    .with_usb_host_device(UsbHostDevice::new(0xdead, 0xbeef))
    .network_disabled()
    .build()
    .expect("a single non-zero USB device on a non-snapshotting config must build");
    let res = vmcell::vmm::PerVmResources {
        cgroup_name: "vmcell-usb-absent-test".to_string(),
        tap_name: None,
        netns_name: None,
        segment: None,
        vhost_user_socket: None,
        vmid: 1,
        guest_cid: 3,
        tmp_dir: std::path::PathBuf::from("/nonexistent/vmcell-usb-absent-test"),
    };
    let created = vmcell::vmm::Vmm::create(
        &vmcell_qemu::Qemu::new(common::qemu_bin()),
        &cfg,
        &res,
        &vmcell::metrics::DefaultCgroupFs,
    )
    .await;
    let Err(err) = created else {
        panic!("QEMU must refuse a USB device that is not attached to this host");
    };
    assert!(
        matches!(&err, vmcell::error::Error::Vmm(m) if m.contains("host USB passthrough")),
        "expected a loud host-USB precheck failure, got {err:?}"
    );
}

/// Parses `VMCELL_TEST_USB_DEVICE` (`<vid>:<pid>`, hex, `lsusb` form).
///
/// Returns `None` when the variable is **unset** — the designated-device facility is
/// absent, which is the ordinary state of every CI/dev host and of `just test-privileged`.
/// A *set but malformed* value is a hard panic: it is an accepted input, so it is honored
/// or rejected, never silently treated as "no device" (AGENTS.md "fail loud").
#[cfg(feature = "qemu")]
fn designated_device() -> Option<UsbHostDevice> {
    let raw = std::env::var(USB_DEVICE_ENV).ok()?;
    let parse = |s: &str, what: &str| -> u16 {
        let s = s.trim().trim_start_matches("0x");
        u16::from_str_radix(s, 16).unwrap_or_else(|e| {
            panic!("{USB_DEVICE_ENV}={raw:?}: {what} {s:?} is not 16-bit hex ({e})")
        })
    };
    let (vid, pid) = raw
        .split_once(':')
        .unwrap_or_else(|| panic!("{USB_DEVICE_ENV}={raw:?} must be <vid>:<pid> (e.g. 1d6b:0002)"));
    Some(UsbHostDevice::new(
        parse(vid, "vendor id"),
        parse(pid, "product id"),
    ))
}

// The LIVE leg (design §2.4 / §18 delta 9): boots a QEMU VM with `-device qemu-xhci` +
// `-device usb-host,…` and asserts the guest kernel ENUMERATED the designated device —
// reading its `idVendor`/`idProduct` back out of guest sysfs (a positive identity on real
// guest data, not a proxy signal like "QEMU did not exit"), plus a class smoke check that
// the device's descriptors were fetched (`bNumInterfaces >= 1`), which a merely-addressed
// but un-enumerated device would fail.
//
// Run it with `just test-usb-passthrough` on a KVM host with a blessed runner, a
// designated disposable device in `VMCELL_TEST_USB_DEVICE`, and `VMCELL_KERNEL` pointing
// at the `vmlinux-usbhost` build (the generic xhci/USB-core fragment; the stock vmcell
// kernel carries no USB driver, and this test says so when the bus is missing).
//
// Absent device => a RECORDED skip, not a silent green: `just test-privileged` selects
// `kind(test) & !(unprivileged|smoltcp)` with `--features qemu --run-ignored all`, so this
// test IS compiled and selected there; hard-failing on every KVM host without a designated
// device would make the privileged suite unrunnable. The skip goes through the same
// `record_capability_skip` recorder `require_cap!` uses, so it lands in
// `$VMCELL_SKIP_MANIFEST` for review (the deviation from "skips go through require_cap!
// only" is recorded in docs/implementation-notes.md, "v30 delta 9 — host-USB
// passthrough"; `require_cap!` itself cannot be used — it panics for the primary backend,
// which is honest-false here).
#[cfg(feature = "qemu")]
#[tokio::test]
#[ignore = "needs KVM, QEMU, a usbhost kernel, and a designated host USB device"]
async fn usb_passthrough_qemu() {
    let Some(device) = designated_device() else {
        common::record_capability_skip("qemu", "usb_host_passthrough_no_designated_device");
        println!(
            "SKIP: no designated host USB device ({USB_DEVICE_ENV} unset); run \
             `just test-usb-passthrough`"
        );
        return;
    };

    let cfg = VmConfig::builder(
        common::get_vmlinux(),
        RootfsSource::Erofs {
            image: common::get_rootfs(),
        },
    )
    .with_usb_host_device(device)
    .network_disabled()
    .build()
    .expect("a single non-zero USB device on a non-snapshotting config must build");

    let vmm = vmcell_qemu::Qemu::new(common::qemu_bin());
    let mut vm = common::start_vm(&vmm, cfg).await;
    let agent = vm
        .agent(Some(std::time::Duration::from_secs(60)))
        .await
        .expect("agent ready");

    // Walk guest sysfs for the device: print `<idVendor> <idProduct> <bNumInterfaces>`
    // for the matching node. Reads real kernel enumeration state, in-guest.
    let script = format!(
        "test -d /sys/bus/usb/devices || {{ echo NOBUS; exit 3; }}; \
         for d in /sys/bus/usb/devices/*; do \
           [ -f \"$d/idVendor\" ] || continue; \
           v=$(cat \"$d/idVendor\"); p=$(cat \"$d/idProduct\"); \
           if [ \"$v\" = \"{vid:04x}\" ] && [ \"$p\" = \"{pid:04x}\" ]; then \
             echo \"FOUND $v $p $(cat \"$d/bNumInterfaces\" 2>/dev/null | tr -d ' ')\"; \
           fi; \
         done",
        vid = device.vendor_id,
        pid = device.product_id
    );
    let out = agent
        .exec(vmcell::ExecRequest::new(vec![
            "sh".to_string(),
            "-c".to_string(),
            script,
        ]))
        .await
        .expect("sysfs scan exec");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_ne!(
        out.code, 3,
        "guest has no /sys/bus/usb — the kernel lacks xhci/USB-core support; point \
         VMCELL_KERNEL at the `vmlinux-usbhost` build (§2.4)"
    );
    assert_eq!(
        out.code,
        0,
        "sysfs scan failed: {stdout} / {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let found = stdout
        .lines()
        .find_map(|l| l.strip_prefix("FOUND "))
        .unwrap_or_else(|| {
            panic!(
                "guest did not enumerate {:04x}:{:04x}; sysfs scan said: {stdout:?}",
                device.vendor_id, device.product_id
            )
        });
    let mut fields = found.split_whitespace();
    // Positive identity on the guest's OWN data: the ids the guest kernel read off the
    // device equal the ones the config asked QEMU to attach.
    assert_eq!(
        fields.next(),
        Some(format!("{:04x}", device.vendor_id).as_str()),
        "guest idVendor mismatch in {found:?}"
    );
    assert_eq!(
        fields.next(),
        Some(format!("{:04x}", device.product_id).as_str()),
        "guest idProduct mismatch in {found:?}"
    );
    // Class smoke check: descriptors were fetched, so this is a fully enumerated device,
    // not merely an addressed one.
    let ifaces: u32 = fields
        .next()
        .unwrap_or("0")
        .parse()
        .unwrap_or_else(|e| panic!("bNumInterfaces in {found:?} is not a number ({e})"));
    assert!(
        ifaces >= 1,
        "the passed-through device reports {ifaces} interfaces — it was addressed but its \
         configuration descriptors were never read ({found:?})"
    );

    vm.kill().await.unwrap();
}
