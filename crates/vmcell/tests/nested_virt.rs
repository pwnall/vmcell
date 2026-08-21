use vmcell::config::{Access, CachePolicy, RootfsSource, Share, VmConfig};
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
    //
    // The reader is [`read_guest_kvm_nested_param`], shared with the `nested_virt = true`
    // half in `nested_virt_l2_boot`: the two legs are one differential (same config, one
    // variable) and a second copy of the probe would let the halves drift into asking the
    // guest two different questions.
    let nested = read_guest_kvm_nested_param(steward).await;
    println!("kvm nested param (nested_virt=false): {nested:?}");
    assert!(
        matches!(nested.as_str(), "N" | "0"),
        "the guest KVM `nested` parameter must be disabled (N/0) when nested_virt is \
         false; got {nested:?} — a Y/1 means the flag is a no-op (the cmdline token \
         was dropped or the kernel default leaked through)"
    );

    vm.shutdown().await.expect("Failed to shutdown VM");
}

/// Reads the guest KVM module's `nested` parameter, trimmed (`Y`/`N`, or `1`/`0` on a kernel that
/// renders the bool numerically) — Intel first, AMD as the fallback, because only one of the two
/// modules is loaded on any given host.
///
/// **One reader, two legs.** `nested_virt_disabled` asserts it reads `N`/`0` and
/// `nested_virt_l2_boot` asserts it reads `Y`/`1`; those two boots are the same config differing in
/// exactly one variable (`cfg.nested_virt`), which is only true while both halves ask the guest the
/// *same* question. A second copy of this shell drifted is a differential that no longer
/// differentiates.
async fn read_guest_kvm_nested_param(steward: &mut vmcell::StewardClient) -> String {
    let out = steward
        .exec(ExecRequest::new(vec![
            "sh".to_string(),
            "-c".to_string(),
            "cat /sys/module/kvm_intel/parameters/nested 2>/dev/null || \
             cat /sys/module/kvm_amd/parameters/nested 2>/dev/null"
                .to_string(),
        ]))
        .await
        .expect("Failed to read the kvm nested parameter");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

// -------------------------------------------------------------------------------------------------
// docs/92 Tier D — an actual L2 guest, booted INSIDE the L1 guest
// -------------------------------------------------------------------------------------------------

// docs/requirements.md feature-checklist item 7 asks for "Nested virtualization, so the harness can
// run its own VMs". Everything that validated it — `nested_virt` above, `checks::nested_kvm_ok`,
// the validator's `nested.kvm_ok` — stops at `open("/dev/kvm")`. Opening a device node is a PROXY
// for "can run its own VMs", and the two answers come apart exactly where it matters: KVM
// initializes (so the node exists and opens) but cannot actually execute a guest — VMXON refusing
// under the L0, an L1 CPUID that advertises VMX without the MSRs `kvm_intel` needs, a guest-kernel
// config that keeps `/dev/kvm` and loses the entry path. Every one of those ships a green
// `kvm-ok`.
//
// So this leg boots a REAL L2 inside the L1 and asserts on the L2's own userspace output.
//
// ## Mechanism
//
// Three read-only virtio-fs shares carry the payload into the L1 — the L2 VMM binary plus its
// config, the kernel's directory, the rootfs image's directory — and the steward runs the L2 VMM
// in-guest. The VMM's stdout **is** the L2 serial console, and it returns over the vsock exec
// channel, so there is no host-side file to poll and no second transport to get wrong.
//
// The L2 boots **vmcell's own kernel and rootfs**: no new artifact, no new build step, and the
// thing proven to run nested is the artifact pair the harness actually ships.
//
// ### Why Firecracker is the in-guest L2 VMM
//
// It is `static-pie` — no dynamic loader, no glibc coupling to whatever the rootfs happens to ship
// — 3.4 MB, and it needs nothing but `/dev/kvm`, two files and `--no-api --config-file`. Cloud
// Hypervisor and crosvm are dynamically linked (a host built against a newer glibc than the rootfs
// silently stops running in-guest), and QEMU is not a single file. This is the *payload*, not a
// backend: `vmcell-firecracker` is not involved, and FC's own matrix leg skips through
// `require_cap!` (it advertises `nested_virt: false`), so FC is never both L1 and L2. The binary is
// resolved through `common::fc_bin()` — the one `VMCELL_FC_BIN` resolver — and an absent one is a
// hard failure, not a skip: this leg's home is `just test-privileged`, which compiles
// `--features firecracker` and therefore already requires that binary for FC's own matrix legs.
//
// ### Why the shares point at the artifact directories
//
// The kernel and the rootfs are ~150 MB together and `TempTree` lives under the host temp dir. A
// per-run copy of them there is the shape that filled this host's tmpfs and reddened the daemon
// suite with `EDQUOT` (the ~129 MB snapshot fixture). Only the 3.4 MB VMM binary and its JSON —
// genuinely this test's own files — are copied into the owned tree; the artifacts are exported
// where they already are, read-only.
//
// ## What is asserted, and why it is a line and not a substring
//
// The L2's init is `/bin/echo -- <per-run marker>`, so the marker is on the L2 **kernel command
// line**, and the L2 kernel echoes its command line during boot. A `contains()` assertion would
// therefore be satisfied by an L2 that panicked before reaching userspace — a weaker fact than the
// one this leg claims. The assertion is that the marker appears as a **line of its own**, which
// only `/bin/echo` running as PID 1 of the L2 can produce. `l2_userspace_marker_present` is that
// discriminator, and the KVM-free gate below pins it against two REAL captured logs.
//
// The marker is a fresh UUID per run (a positive identity, not "different from last time"), and it
// exists nowhere in the L1: the host writes it only into the JSON the L2 VMM reads.
//
// ## Scope — this is a REQUIREMENT proof, not a new causality claim for the flag
//
// Do not read this leg as "an L2 boots iff `nested_virt`". `cfg.nested_virt`'s only effect anywhere
// in the tree is the `kvm-{intel,amd}.nested=0|1` cmdline pair, and that parameter governs whether
// the L1's KVM exposes VMX to *its* guests (an L3) — not whether the L1 can run an L2. The L1's
// ability to run an L2 comes from the L0's nested KVM plus the backend's unconditional VMX
// exposure, which is the same fact `nested_virt_disabled` records when it refuses to probe
// `/dev/kvm` for causality. The flag's causality therefore stays pinned where that leg put it, and
// this leg supplies the missing half of that differential: `Y`/`1` here under `nested_virt = true`,
// `N`/`0` there under `false`, through the one shared `read_guest_kvm_nested_param`.
//
// ## RED ON THE INVERSE
//
// Measured 2026-08-21 on this host, with the identical mechanism run outside an L1 (same FC binary,
// same vmlinux, same rootfs.erofs, same boot args): with `init=/bin/true` — an L2 that boots and
// never runs the marker — the captured console carries the marker **twice as a substring and zero
// times as a line**, so the shipped assertion fails while a `contains()` passes. Those two logs are
// the fixtures of `l2_marker_is_a_line_the_kernel_cmdline_echo_cannot_forge`. In the live leg an L1
// that cannot execute a guest never gets that far: the L2 VMM fails during KVM setup, so what comes
// back is its own diagnostic and no guest console at all — no marker in any form.
//
// MEASURED 2026-08-21, all on this host, outside an L1: the composers below rendered against host
// paths boot an L2 to userspace and print the marker (exit 0, 23 KB of captured console, 1.8 s),
// through the same `sh -c` script the guest runs — which is also what proves the copied VMM binary
// keeps its exec bit. The two KVM-free gates below run everywhere. The LIVE leg was written but NOT
// executed by its author (the blessed runner was stale mid-pass); it is on the orchestrator's
// privileged run.

/// The in-guest mount tag for this leg's own files (the L2 VMM binary and its JSON).
const L2_TOOLS_TAG: &str = "vmcell-l2-tools";
/// The in-guest mount tag for the directory holding the kernel artifact.
const L2_KERNEL_TAG: &str = "vmcell-l2-kernel";
/// The in-guest mount tag for the directory holding the rootfs image.
const L2_ROOTFS_TAG: &str = "vmcell-l2-rootfs";
/// The name the L2 VMM binary is copied under — role, not brand, because the guest-side reader of a
/// failure message cares which layer it is.
const L2_VMM_FILE: &str = "l2-vmm";
/// The L2 VMM's single-JSON config, beside the binary in the same share.
const L2_CONFIG_FILE: &str = "l2-vmm.json";
/// L1 memory: the default 128 MiB has no room for an L2 plus its VMM. Sized for the L2's own
/// [`L2_MEM_MIB`] plus the L1's page cache of a 54 MB kernel read over virtio-fs, with headroom.
const L1_MEM_MIB: u32 = 1024;
/// L2 memory. 128 MiB is vmcell's own default cell size and boots this kernel+rootfs pair to
/// userspace (measured: 1.8 s, host-side).
const L2_MEM_MIB: u32 = 128;
/// How long the guest gives the whole L2 boot before `timeout` kills it. Well under nextest's
/// `integration` profile terminate-after, so a wedged L2 surfaces as this leg's own diagnostic
/// (captured console + exit 124) rather than as a killed test binary.
const L2_BUDGET_SECS: u32 = 180;

/// Whether THIS HOST can host a guest that itself runs a guest — the precondition this leg needs and
/// that no backend capability answers.
///
/// `capabilities().nested_virt` is a claim about the BACKEND (it emits `kvm-{intel,amd}.nested=1`
/// on the L1's cmdline); whether the L1 can actually run an L2 comes from the L0. Two host facts
/// decide it, and both are read rather than assumed:
///
/// * **the host is itself a guest** — then our L1 is an L2 and its guest would be an L3, which
///   mainstream KVM does not support. This is the CI case: a hosted runner is a VM, so the leg
///   timed out there while passing on bare metal, and the timeout named the vsock round trip
///   rather than the reason. `systemd-detect-virt` answers it (`none` = bare metal).
/// * **the host's KVM module has nesting off** — no L1 gets VMX at all.
///
/// Returns `false` to mean "genuinely absent, record a skip". A probe that cannot RUN is a broken
/// host, not an absent facility, and panics — the same split `probe_ext4_or_record_skip` draws.
fn host_can_nest_two_levels() -> bool {
    let out = std::process::Command::new("systemd-detect-virt")
        .output()
        .unwrap_or_else(|e| panic!("systemd-detect-virt must be runnable to decide this leg: {e}"));
    // Exit 1 with `none` on stdout is its documented "not a VM" answer, so the status is not the
    // signal — the word is.
    let virt = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if virt.is_empty() {
        panic!("systemd-detect-virt printed nothing; this probe cannot decide and must not guess");
    }
    if virt != "none" {
        eprintln!(
            "nested_virt_l2_boot: this host is itself a guest ({virt}), so the L2 this leg boots \
             would be an L3 — a facility mainstream KVM does not provide. Recording the skip."
        );
        return false;
    }
    // Read whichever vendor module is loaded; absent means no KVM nesting to have.
    for param in [
        "/sys/module/kvm_intel/parameters/nested",
        "/sys/module/kvm_amd/parameters/nested",
    ] {
        if let Ok(v) = std::fs::read_to_string(param) {
            let v = v.trim();
            if v == "Y" || v == "1" {
                return true;
            }
            eprintln!(
                "nested_virt_l2_boot: {param} reads {v:?} — nesting is off. Recording the skip."
            );
            return false;
        }
    }
    eprintln!(
        "nested_virt_l2_boot: neither kvm_intel nor kvm_amd exposes a `nested` parameter. \
               Recording the skip."
    );
    false
}

vmm_matrix_test!(nested_virt_l2_boot, |vmm| {
    require_cap!(vmcell::vmm::Vmm::capabilities(&vmm), nested_virt, vmm);
    // The payload has to reach the guest somehow; on the two backends that advertise `nested_virt`
    // (CH, QEMU) virtio-fs is the road. A backend advertising one and not the other skips honestly
    // here instead of failing on a missing mount.
    require_cap!(vmcell::vmm::Vmm::capabilities(&vmm), virtio_fs_shares, vmm);
    // The HOST half, which no capability flag covers. `require_cap!` cannot express it — it reads a
    // `VmmCapabilities` field and panics for the primary backend — so this is the recorded-skip
    // shape the ext4 battery uses for a genuinely absent host facility.
    if !host_can_nest_two_levels() {
        common::record_capability_skip(
            vmcell::vmm::Vmm::id(&vmm),
            "nested_l2_host_cannot_nest_two_levels",
        );
        return;
    }
    test_nested_virt_l2_boot_impl(&vmm).await;
});

/// Whether `log` carries `marker` as a **line of its own** — the write only an L2 userspace process
/// can have made.
///
/// The load-bearing half is line-versus-substring, not the `trim()`: a serial console renders `\n`
/// as `\r\n`, and `str::lines` already strips that trailing `\r`, so the trim only absorbs
/// whatever padding a console leaves around the write. Measured, not assumed — a raw `line ==
/// marker` still passes the gate below, and the comment that claimed otherwise was wrong.
fn l2_userspace_marker_present(log: &str, marker: &str) -> bool {
    log.lines().any(|line| line.trim() == marker)
}

/// The tail of a captured console, for a failure message: enough to diagnose, bounded so one red
/// test does not render a whole guest-controlled stream (the `capped_debug` rule, test-side).
fn log_tail(log: &str) -> &str {
    const LOG_TAIL_BYTES: usize = 8 * 1024;
    let want = log.len().saturating_sub(LOG_TAIL_BYTES);
    let start = (want..=log.len())
        .find(|i| log.is_char_boundary(*i))
        .unwrap_or(log.len());
    &log[start..]
}

/// Resolves a binary name the way a shell would: a name carrying a separator is a path, a bare name
/// is looked up on `PATH`.
///
/// `common::fc_bin()` returns whatever `VMCELL_FC_BIN` says or the bare `firecracker`, and this leg
/// must **copy** that file into a share rather than exec it here, so the bare form has to be
/// resolved to a path first.
fn resolve_binary(name: &str) -> Option<std::path::PathBuf> {
    let named = std::path::Path::new(name);
    if named.components().count() > 1 {
        return named.is_file().then(|| named.to_path_buf());
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// The file name of an artifact, checked to be a plain ASCII component before it is interpolated
/// into JSON and into a `sh -c` script.
///
/// Both artifact paths are caller-supplied in the downstream configuration (`VMCELL_KERNEL` /
/// `VMCELL_ROOTFS`), so this is an accepted input: honored or rejected loudly, never quoted into a
/// shell word and hoped for.
fn artifact_file_name(path: &std::path::Path, env_var: &str) -> String {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_else(|| panic!("{env_var} artifact {path:?} has no UTF-8 file name"));
    assert!(
        !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+')),
        "{env_var} artifact file name {name:?} must be plain ASCII ([A-Za-z0-9._+-]): this leg \
         interpolates it into the L2 VMM's JSON config and into a `sh -c` script inside the guest"
    );
    name.to_string()
}

/// The in-guest path of `file` inside `share`, read off the share's own `guest_path` rather than
/// re-derived as `/<tag>` — the mount point is `Share`'s law, and a test-local `format!` of it is a
/// second copy of that law.
fn guest_path_in(share: &Share, file: &str) -> String {
    let joined = share.guest_path.join(file);
    joined
        .to_str()
        .unwrap_or_else(|| panic!("guest path {joined:?} must be UTF-8"))
        .to_string()
}

/// The L2's kernel command line.
///
/// `console=ttyS0` because the L2 VMM's own stdout **is** that UART — this is the whole capture
/// path, and it is why the leg needs no host-side file. `panic=1 reboot=k` is what makes the L2 VMM
/// exit on its own once init is gone, so nothing depends on the in-guest `timeout` firing.
///
/// `init=/bin/echo -- <marker>`: everything the kernel sees after `--` reaches init as argv, so PID
/// 1 of the L2 prints the marker to that console and exits. `/bin/echo` comes from vmcell's own
/// rootfs (a Debian base); this leg adds no tool to the image.
fn l2_boot_args(marker: &str) -> String {
    format!(
        "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro rootfstype=erofs \
         init=/bin/echo -- {marker}"
    )
}

/// The L2 VMM's single-JSON configuration, in the guest's own path namespace.
///
/// The `drives` stanza is **mandatory** in this schema, not decoration: measured 2026-08-21,
/// Firecracker v1.16 refuses a config without it ("Invalid JSON: missing field") and never reaches
/// KVM at all. The one drive is vmcell's own rootfs image, read-only, which is what gives the L2 a
/// `/bin/echo` to run.
fn l2_config(guest_kernel: &str, guest_rootfs: &str, marker: &str) -> serde_json::Value {
    serde_json::json!({
        "boot-source": {
            "kernel_image_path": guest_kernel,
            "boot_args": l2_boot_args(marker),
        },
        "drives": [{
            "drive_id": "rootfs",
            "path_on_host": guest_rootfs,
            "is_root_device": true,
            "is_read_only": true,
        }],
        "machine-config": { "vcpu_count": 1, "mem_size_mib": L2_MEM_MIB },
    })
}

/// The in-guest script that boots the L2.
///
/// The setup checks fail with their own tokens so a red test says WHICH layer broke: an unmounted
/// share, a payload that lost its exec bit and a guest with no `/dev/kvm` are three different
/// findings, and none of them should read as "the L2 did not boot". `</dev/null` because the VMM
/// treats stdin as the guest's serial input, and `2>&1` because its own diagnostics go to stderr
/// while the guest console goes to stdout — one stream is what the exec channel returns.
fn l2_boot_script(
    guest_vmm: &str,
    guest_config: &str,
    guest_kernel: &str,
    guest_rootfs: &str,
) -> String {
    format!(
        "set -u\n\
         for f in {guest_vmm} {guest_config} {guest_kernel} {guest_rootfs}; do\n\
         [ -r \"$f\" ] || {{ echo \"L2-SETUP-UNREADABLE $f\"; exit 90; }}\n\
         done\n\
         [ -x {guest_vmm} ] || {{ echo \"L2-SETUP-NOEXEC {guest_vmm}\"; exit 91; }}\n\
         [ -c /dev/kvm ] || {{ echo \"L2-SETUP-NO-DEV-KVM\"; exit 92; }}\n\
         exec timeout {L2_BUDGET_SECS} {guest_vmm} --no-api --config-file {guest_config} \
         </dev/null 2>&1\n"
    )
}

async fn test_nested_virt_l2_boot_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    let kernel = common::get_vmlinux();
    let rootfs = common::get_rootfs();
    let kernel_file = artifact_file_name(&kernel, "VMCELL_KERNEL");
    let rootfs_file = artifact_file_name(&rootfs, "VMCELL_ROOTFS");
    let kernel_dir = kernel
        .parent()
        .unwrap_or_else(|| panic!("kernel artifact {kernel:?} must live in a directory"))
        .to_path_buf();
    let rootfs_dir = rootfs
        .parent()
        .unwrap_or_else(|| panic!("rootfs artifact {rootfs:?} must live in a directory"))
        .to_path_buf();

    let l2_vmm_name = common::fc_bin();
    let l2_vmm_path = resolve_binary(&l2_vmm_name).unwrap_or_else(|| {
        panic!(
            "the in-guest L2 VMM binary {l2_vmm_name:?} was not found (neither a path nor on \
             PATH). This leg boots a real L2 inside the guest and carries Firecracker in as the \
             payload because it is statically linked; point VMCELL_FC_BIN at one, or install \
             `firecracker` — the same binary this suite's own Firecracker matrix legs need."
        )
    });

    // OWNED: `TempTree`'s `Drop` clears the tree on the panic path too, and it is declared BEFORE
    // the VM so it outlives the virtiofsd exporting it (locals drop in reverse).
    let tmp = common::TempTree::create(&format!(
        "vmcell-test-nested-l2-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let tools_dir = tmp.join("tools");
    std::fs::create_dir_all(&tools_dir).expect("create the L2 payload directory");
    // `fs::copy` carries the permission bits, so the copy stays executable in the guest.
    std::fs::copy(&l2_vmm_path, tools_dir.join(L2_VMM_FILE)).unwrap_or_else(|e| {
        panic!("copying the L2 VMM {l2_vmm_path:?} into the share failed: {e}")
    });

    let tools_share = Share::new(
        L2_TOOLS_TAG,
        &tools_dir,
        Access::ReadOnly,
        CachePolicy::Auto,
    );
    let kernel_share = Share::new(
        L2_KERNEL_TAG,
        &kernel_dir,
        Access::ReadOnly,
        CachePolicy::Auto,
    );
    let rootfs_share = Share::new(
        L2_ROOTFS_TAG,
        &rootfs_dir,
        Access::ReadOnly,
        CachePolicy::Auto,
    );
    let guest_vmm = guest_path_in(&tools_share, L2_VMM_FILE);
    let guest_config = guest_path_in(&tools_share, L2_CONFIG_FILE);
    let guest_kernel = guest_path_in(&kernel_share, &kernel_file);
    let guest_rootfs = guest_path_in(&rootfs_share, &rootfs_file);

    // The one fact the L2 has to produce. Fresh per run, so a stale console from an earlier boot
    // cannot satisfy this leg.
    let marker = format!("VMCELL-L2-{}", uuid::Uuid::new_v4().simple());
    std::fs::write(
        tools_dir.join(L2_CONFIG_FILE),
        serde_json::to_vec_pretty(&l2_config(&guest_kernel, &guest_rootfs, &marker))
            .expect("serialize the L2 VMM config"),
    )
    .expect("write the L2 VMM config into the share");

    let cfg = VmConfig::builder(
        &kernel,
        RootfsSource::Erofs {
            image: rootfs.clone(),
        },
    )
    .vcpus(2)
    .mem_mib(L1_MEM_MIB)
    .nested_virt(true)
    .with_share(tools_share)
    .with_share(kernel_share)
    .with_share(rootfs_share)
    .network_disabled()
    .build()
    .expect("build the L1 config");

    let mut vm = common::start_vm(vmm, cfg).await;
    let steward = vm
        .steward(Some(std::time::Duration::from_secs(60)))
        .await
        .expect("the L1 steward must reach ready");

    // Half one of the differential with `nested_virt_disabled`: the flag's own token, this time on
    // the `true` side. Same config, same reader, one variable.
    let nested = read_guest_kvm_nested_param(steward).await;
    println!("kvm nested param (nested_virt=true): {nested:?}");
    assert!(
        matches!(nested.as_str(), "Y" | "1"),
        "the guest KVM `nested` parameter must be enabled (Y/1) when nested_virt is true; got \
         {nested:?} — the `kvm-{{intel,amd}}.nested=1` token was dropped from the command line, \
         which is the same lever `nested_virt_disabled` pins from the other side"
    );

    // Half two: an L2, actually booted. The setup checks fail with their own tokens so a red test
    // says WHICH layer broke — an unmounted share and a guest that cannot open /dev/kvm are very
    // different findings, and neither should look like "the L2 did not boot".
    let script = l2_boot_script(&guest_vmm, &guest_config, &guest_kernel, &guest_rootfs);
    let outcome = steward
        .exec(ExecRequest::new(vec![
            "sh".to_string(),
            "-c".to_string(),
            script,
        ]))
        .await
        .expect("the L2 boot must round-trip over vsock");
    let console = String::from_utf8_lossy(&outcome.stdout).into_owned();
    assert!(
        l2_userspace_marker_present(&console, &marker),
        "no L2 userspace write reached the captured console: the marker {marker:?} never appeared \
         as a line of its own, so an L2 guest did not run `/bin/echo` as its PID 1 inside this \
         L1 — `/dev/kvm` opening in the guest is not the same claim, and this is the leg that \
         tells them apart. L2 VMM exit code {} (124 = the in-guest {L2_BUDGET_SECS}s budget, \
         90/91/92 = a setup token above). marker-as-substring present: {}. \
         stderr tail:\n{}\ncaptured console tail:\n{}",
        outcome.code,
        console.contains(&marker),
        log_tail(&String::from_utf8_lossy(&outcome.stderr)),
        log_tail(&console),
    );

    vm.shutdown().await.expect("shutdown after the L2 boot");
}

// The KVM-free half of the leg above: the discriminator that separates "an L2 ran userspace" from
// "the marker appears somewhere in the log", pinned against two REAL captured consoles.
//
// Both fixtures are verbatim excerpts (trailing `\r` included — a serial console renders CRLF) of
// Firecracker boots of vmcell's own vmlinux + rootfs.erofs, taken 2026-08-21, differing in exactly
// one variable: `init=/bin/echo` versus `init=/bin/true`. The `/bin/true` boot is a complete,
// healthy L2 that simply never wrote the marker — and its console still contains the marker twice,
// because the L2 kernel echoes its own command line. That is the trap.
//
// RED ON THE INVERSE (run 2026-08-21): implement `l2_userspace_marker_present` with
// `log.contains(marker)` and the negative leg fails — "an L2 that never reached the marker must NOT
// satisfy the discriminator". Dropping the `trim()` is NOT an inverse: `str::lines` strips the
// serial console's `\r` on its own, which is why that half is documented as belt-and-braces there
// rather than claimed as a second guard here.
#[test]
fn l2_marker_is_a_line_the_kernel_cmdline_echo_cannot_forge() {
    const MARKER: &str = "VMCELL-L2-MARKER-abc123";
    const USERSPACE_RAN: &str = concat!(
        "[    0.010939] Kernel command line: console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro rootfstype=erofs init=/bin/echo pci=off root=/dev/vda ro virtio_mmio.device=4K@0xc0001000:5 -- VMCELL-L2-MARKER-abc123\r\n",
        "[    0.697569] Run /bin/echo as init process\r\n",
        "VMCELL-L2-MARKER-abc123\r\n",
        "[    0.706265] Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000000\r\n",
    );
    const USERSPACE_NEVER_ECHOED: &str = concat!(
        "[    0.010910] Kernel command line: console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro rootfstype=erofs init=/bin/true pci=off root=/dev/vda ro virtio_mmio.device=4K@0xc0001000:5 -- VMCELL-L2-MARKER-abc123\r\n",
        "[    0.665953] Run /bin/true as init process\r\n",
        "[    0.681508] Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000000\r\n",
    );

    assert!(
        l2_userspace_marker_present(USERSPACE_RAN, MARKER),
        "an L2 whose PID 1 echoed the marker must satisfy the discriminator"
    );
    assert!(
        !l2_userspace_marker_present(USERSPACE_NEVER_ECHOED, MARKER),
        "an L2 that never reached the marker must NOT satisfy the discriminator"
    );
    // The negative leg is only worth anything while the trap is really in the fixture: this is what
    // makes `!present` above a discrimination rather than a log that simply lacks the string.
    assert!(
        USERSPACE_NEVER_ECHOED.contains(MARKER),
        "the negative fixture must still CONTAIN the marker (the L2 kernel echoes its command \
         line) — otherwise the assertion above proves nothing about substring-versus-line"
    );
}

// The other KVM-free half: the composed L2 configuration, pinned on the facts that were MEASURED
// against a real Firecracker (2026-08-21, this host) rather than assumed from documentation — the
// composers here are what that boot actually ran, with only the paths differing between the host
// rehearsal and the in-guest run.
//
//   * `drives` is a REQUIRED field of this schema. Dropping it does not produce a diskless L2, it
//     produces `Invalid JSON: missing field `drives`` and no VM at all.
//   * the drive is read-only, because it is vmcell's own rootfs image exported into the L1 over a
//     read-only virtio-fs share: an L2 VMM opening it read-write fails before `KVM_CREATE_VM`.
//   * the marker is the LAST thing on the L2 command line, after `--`, which is the kernel's own
//     rule for handing argv to init.
//   * the exec line keeps `--no-api --config-file`, `</dev/null` (the VMM reads stdin as the L2's
//     serial input) and `2>&1` (its diagnostics are on stderr, the L2 console on stdout, and the
//     exec channel returns one of them).
//
// RED ON THE INVERSE: flip `is_read_only`, drop the `drives` stanza, move the marker before `--`,
// or drop either redirection from the exec line, and one of these fires.
#[test]
fn l2_config_and_script_are_the_shape_the_measured_boot_needed() {
    let config = l2_config("/k/vmlinux", "/r/rootfs.erofs", "MARK");

    assert_eq!(config["boot-source"]["kernel_image_path"], "/k/vmlinux");
    let args = config["boot-source"]["boot_args"]
        .as_str()
        .expect("boot_args must be a string");
    assert!(
        args.contains("console=ttyS0"),
        "the L2 console must be the UART the VMM's stdout is; got {args:?}"
    );
    assert!(
        args.ends_with("init=/bin/echo -- MARK"),
        "the marker must be the tail of the command line, after `--`, or the kernel never hands it \
         to init as argv; got {args:?}"
    );

    let drives = config["drives"]
        .as_array()
        .expect("`drives` is a required field of this schema, not optional decoration");
    assert_eq!(drives.len(), 1, "one root drive: {drives:?}");
    assert_eq!(drives[0]["path_on_host"], "/r/rootfs.erofs");
    assert_eq!(drives[0]["is_root_device"], true);
    assert_eq!(
        drives[0]["is_read_only"], true,
        "the image arrives over a READ-ONLY virtio-fs share; a read-write drive fails to open"
    );
    assert_eq!(config["machine-config"]["mem_size_mib"], L2_MEM_MIB);

    let script = l2_boot_script(
        "/t/l2-vmm",
        "/t/l2-vmm.json",
        "/k/vmlinux",
        "/r/rootfs.erofs",
    );
    let exec_line = script
        .lines()
        .last()
        .expect("the script's last line is the exec");
    assert!(
        exec_line.starts_with(&format!("exec timeout {L2_BUDGET_SECS} /t/l2-vmm ")),
        "the L2 VMM must be exec'd under the in-guest budget; got {exec_line:?}"
    );
    assert!(
        exec_line.contains("--no-api --config-file /t/l2-vmm.json"),
        "the VMM must read the composed config with no API socket; got {exec_line:?}"
    );
    assert!(
        exec_line.contains("</dev/null") && exec_line.contains("2>&1"),
        "stdin is the L2's serial input and the VMM's own log is on stderr, so both redirections \
         are load-bearing; got {exec_line:?}"
    );
    for path in [
        "/t/l2-vmm",
        "/t/l2-vmm.json",
        "/k/vmlinux",
        "/r/rootfs.erofs",
    ] {
        assert!(
            script.contains(path),
            "every payload path is readability-checked before the boot, so a missing share names \
             itself; {path} is absent from:\n{script}"
        );
    }
}
