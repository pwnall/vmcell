//! Live confinement gate: the state a **running VMM** actually carries (design §12.2, Layer 1 —
//! the VMM's own seccomp filter / §12.3, Layer 2 — the jailer-equivalent (JailSpec + apply_jail) /
//! invariant §13, Cross-cutting invariants).
//!
//! `tests/jail_hardening.rs` gates the pre-exec mechanism thoroughly — and entirely against a
//! `/bin/cat` stand-in spawned through `build_vmm_cmd`. The link the stand-in structurally cannot
//! reach is the one that matters: that a real Cloud Hypervisor process, after `apply_jail` and
//! after CH's own start-up, is *still* confined. Everything between the two — CH re-arming its
//! signal handlers, installing its own filters, spawning vcpu/api/device threads — happens after
//! the last assertion the stand-in can make.
//!
//! Cloud-hypervisor only, on purpose. The pid resolution and the observable both key off the
//! primary backend: CH's `--seccomp true|false` is the one backend lever that flips a *loaded
//! filter* on the live process (FC's is `--no-seccomp`, QEMU's `-sandbox`, and crosvm always runs
//! `--disable-sandbox` and confines through the Layer-2 deny-list instead), and QEMU additionally
//! spawns helper daemons into the same scratch dir, so "the VMM pid" stops being one process.
//! The per-backend argv composition is pinned KVM-free by each backend's own seccomp-argv tests.

mod common;

use vmcell::config::{JailConfig, RootfsSource, VmConfig, VmmSeccomp};

/// `CAP_NET_ADMIN`'s kernel number, from the ONE crate that owns the privileged vocabulary
/// (`libc` exports no `CAP_*` numbers) — the same route `tests/jail_hardening.rs` takes.
const CAP_NET_ADMIN: u64 = 1u64 << (vmcell_privilege::Cap::NET_ADMIN as u64);

/// A `/proc/<pid>/status` (or `/proc/<pid>/task/<tid>/status`) field, by its exact label.
fn status_field(status: &str, label: &str) -> Option<String> {
    status
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{label}:")))
        .map(|v| v.trim().to_string())
}

/// The status field parsed as a `u64`, panicking with the raw text when it does not parse — a
/// kernel that renamed or reshaped the field must fail loud, never silently read as absent.
fn status_u64(status: &str, label: &str, radix: u32) -> u64 {
    let raw = status_field(status, label)
        .unwrap_or_else(|| panic!("/proc status has no {label}: field:\n{status}"));
    u64::from_str_radix(&raw, radix)
        .unwrap_or_else(|e| panic!("{label} field {raw:?} does not parse in base {radix}: {e}"))
}

/// The pid of the live VMM process serving `vmid`'s per-VM scratch directory.
///
/// Keyed on the scratch-directory name composed by the ONE law
/// ([`vmcell::naming::scratch_dir_name`]), never a test-local `format!`: that name carries both
/// `(pid, vmid)`, so it cannot match another process's VM even at the same vmid, and a rename of
/// the layout moves this matcher with it. Re-scanned on every call so a recycled pid cannot be
/// mistaken for the VMM, and a zombie (empty `cmdline`) does not count.
///
/// Fails loud on anything other than exactly one match: zero means the VMM already died (the
/// assertions below would then be vacuous), and more than one means the marker stopped being
/// specific to a single process, which silently picks an arbitrary one.
fn vmm_pid_for_vmid(vmid: u32) -> libc::pid_t {
    let marker = vmcell::naming::scratch_dir_name(
        vmcell::naming::DEFAULT_RESOURCE_PREFIX,
        std::process::id(),
        vmid,
    );
    let mut found = Vec::new();
    let entries = std::fs::read_dir("/proc").expect("read /proc");
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<libc::pid_t>().ok()) else {
            continue;
        };
        let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        let argv = String::from_utf8_lossy(&raw).replace('\0', " ");
        if argv.contains("cloud-hypervisor") && argv.contains(&marker) {
            found.push(pid);
        }
    }
    assert_eq!(
        found.len(),
        1,
        "expected exactly one live cloud-hypervisor process for scratch dir {marker:?}, found \
         {found:?} — a zero means the VMM is already gone (the confinement assertions would be \
         vacuous), a >1 means the marker is no longer specific to one process"
    );
    found[0]
}

/// Every thread's `(tid, Seccomp, Seccomp_filters)` triple for `pid`. CH installs its filters
/// **per thread** (vmm, api, vcpu, device), so the thread-group leader's mode alone does not
/// answer "is this VMM confined".
fn thread_seccomp(pid: libc::pid_t) -> Vec<(libc::pid_t, u64, u64)> {
    let mut out = Vec::new();
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return out;
    };
    for entry in tasks.flatten() {
        let Some(tid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<libc::pid_t>().ok())
        else {
            continue;
        };
        let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/status")) else {
            // A thread that exited between the readdir and the read is not a datum.
            continue;
        };
        out.push((
            tid,
            status_u64(&status, "Seccomp", 10),
            status_u64(&status, "Seccomp_filters", 10),
        ));
    }
    out
}

/// The config both legs boot, parameterized by the two confinement levers under test.
/// `network_disabled` so the leg needs KVM and nothing else — no netns, no caps.
fn confinement_cfg(jail: JailConfig, seccomp: VmmSeccomp) -> VmConfig {
    VmConfig::builder(
        common::get_vmlinux(),
        RootfsSource::Erofs {
            image: common::get_rootfs(),
        },
    )
    .jail(jail)
    .vmm_seccomp(seccomp)
    .network_disabled()
    .build()
    .expect("confinement config must build")
}

// T6 (docs/90 §5): the confinement state of a RUNNING VMM, which no gate asserted. Boots a real
// Cloud Hypervisor under the SHIPPED defaults (`JailConfig::hardened()` + `VmmSeccomp::Enforcing`),
// resolves its pid, and reads `/proc/<pid>/status` back: `NoNewPrivs=1` (set by `apply_jail`'s
// prctl in the pre-exec window and inherited by every CH thread) and a **loaded seccomp filter**
// on the VMM's threads.
//
// RED ON THE INVERSE, in the same test and on the same host: the control boots the identical
// config with `JailConfig::disabled()` + `VmmSeccomp::Disabled` and asserts `NoNewPrivs=0` with
// **zero** filtered threads. That control is what makes this a gate rather than an observation —
// delete `apply_jail`'s `PR_SET_NO_NEW_PRIVS`, or stop passing `--seccomp` to CH, and the positive
// leg goes red while the control still passes; leave both in place and flip the control's levers
// to the defaults and the control goes red instead. Neither value can be green for an
// environmental reason: they are read off two processes booted seconds apart from one config
// function.
#[cfg(feature = "cloud-hypervisor")]
#[tokio::test]
#[ignore = "needs KVM"]
async fn running_vmm_carries_no_new_privs_and_a_loaded_seccomp_filter() {
    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    // ONE env for both boots, and each VM SCOPED so its teardown runs before the next one starts.
    // Both halves are load-bearing, and the second was measured the hard way: `common::start_vm`
    // builds its own `HostEnv::hermetic()` per call, so two calls both draw vmid 1 and therefore the
    // same `<prefix>-vm-<pid>-1/vsock.sock` path — and a UDS `bind` onto an existing path is
    // `EADDRINUSE` whether or not anything still listens on it. Killing the first VMM is not
    // enough; the scratch dir has to be *reclaimed*, which is the `MicroVm` guard's `Drop`. With
    // the block, the second boot cannot collide, and `vmm_pid_for_vmid`'s exactly-one assertion
    // cannot be confused by a still-live predecessor at the same vmid.
    let env = vmcell::HostEnv::hermetic();

    // The shipped defaults, stated explicitly so the leg reads as the claim it makes.
    let (pid, hardened_nnp, hardened_threads) = {
        let mut vm = vmcell::orchestrator::MicroVm::start(
            &vmm,
            confinement_cfg(JailConfig::hardened(), VmmSeccomp::Enforcing),
            &env,
        )
        .await
        .expect("start the hardened VM");
        let pid = vmm_pid_for_vmid(vm.vmid());
        let status =
            std::fs::read_to_string(format!("/proc/{pid}/status")).expect("read VMM status");
        let nnp = status_u64(&status, "NoNewPrivs", 10);
        let threads = thread_seccomp(pid);
        println!("hardened VMM pid {pid}: NoNewPrivs={nnp} threads={threads:?}");
        vm.kill().await.expect("kill hardened VM");
        (pid, nnp, threads)
    };

    // The control: both levers off, same everything else.
    let (ctl_nnp, ctl_threads) = {
        let mut ctl = vmcell::orchestrator::MicroVm::start(
            &vmm,
            confinement_cfg(JailConfig::disabled(), VmmSeccomp::Disabled),
            &env,
        )
        .await
        .expect("start the control VM");
        let ctl_pid = vmm_pid_for_vmid(ctl.vmid());
        let ctl_status = std::fs::read_to_string(format!("/proc/{ctl_pid}/status"))
            .expect("read control status");
        let nnp = status_u64(&ctl_status, "NoNewPrivs", 10);
        let threads = thread_seccomp(ctl_pid);
        println!("control VMM pid {ctl_pid}: NoNewPrivs={nnp} threads={threads:?}");
        ctl.kill().await.expect("kill control VM");
        (nnp, threads)
    };

    assert_eq!(
        hardened_nnp, 1,
        "a running VMM booted with JailConfig::hardened() must carry NoNewPrivs=1 \
         (apply_jail's prctl); got {hardened_nnp}"
    );
    assert_eq!(
        ctl_nnp, 0,
        "the control (JailConfig::disabled()) must leave NoNewPrivs=0 — otherwise the assertion \
         above proves nothing about apply_jail; got {ctl_nnp}"
    );

    // MEASURED (2026-08-17, CH under `--seccomp true`): the thread-group **leader** reads
    // `Seccomp: 0` and every thread it spawns reads `Seccomp: 2` with 1–2 loaded filters —
    // `[(leader, 0, 0), (_, 2, 1), (_, 2, 1), (_, 2, 2), (_, 2, 2), (_, 2, 2)]`. CH installs its
    // filters per thread (vmm, api, vcpu, signal-handler, device), and the leader only parses argv
    // and waits, so nothing filters it — vmcell's own Layer-2 deny-list, which WOULD, ships
    // opt-in-off (`JailConfig::seccomp_deny_list`). So the honest claim is "no thread that touches
    // guest input is unconfined", asserted over the non-leader set rather than over a thread count
    // that a CH release could legitimately change.
    let non_leader: Vec<_> = hardened_threads
        .iter()
        .filter(|(tid, _, _)| *tid != pid)
        .collect();
    assert!(
        !non_leader.is_empty(),
        "a running VMM must have spawned worker threads to assert about; threads were \
         {hardened_threads:?}"
    );
    let unconfined: Vec<_> = non_leader
        .iter()
        .filter(|(_, mode, filters)| *mode != 2 || *filters < 1)
        .collect();
    assert!(
        unconfined.is_empty(),
        "every non-leader thread of a VMM booted with VmmSeccomp::Enforcing must be in \
         SECCOMP_MODE_FILTER (2) with a loaded filter; these were not: {unconfined:?} of \
         {hardened_threads:?}"
    );
    let ctl_filtered: Vec<_> = ctl_threads
        .iter()
        .filter(|(_, mode, filters)| *mode != 0 || *filters != 0)
        .collect();
    assert!(
        ctl_filtered.is_empty(),
        "the control (VmmSeccomp::Disabled) must run with NO loaded filter — otherwise the \
         assertion above proves nothing about the --seccomp argument; filtered threads were \
         {ctl_filtered:?} of {ctl_threads:?}"
    );
}

// T6's second half: the AMBIENT set of a running VMM. `clear_ambient_caps` ships **false**
// (Appendix A reversal 9 — a restored CH's `TapSetMac` and FC's tap re-open both `EPERM` without
// the inherited `CAP_NET_ADMIN`), and until now the only evidence for that was a forked stand-in.
// This asserts it on the real VMM process: with the shipped hardened jail, the child's `CapAmb`
// equals the parent's, `CAP_NET_ADMIN` included.
//
// PRIVILEGED-ONLY, for the same reason `jail_hardening.rs`'s ambient leg is: an unprivileged
// process has an EMPTY ambient set, so "the VMM's ambient set is intact" reads 0 == 0 and a jail
// that cleared it would pass. The precondition below therefore ASSERTS (never skips) that this
// process holds ambient `CAP_NET_ADMIN` — i.e. that it runs under the blessed runner.
//
// Red on the inverse: flip `JailConfig::hardened()`'s `clear_ambient_caps` to `true` (or make
// `apply_jail` clear unconditionally) and the equality fails with the VMM at 0 and the parent at
// its delivered set.
#[cfg(feature = "cloud-hypervisor")]
#[tokio::test]
#[ignore = "needs KVM + the blessed runner's ambient capability set (privileged suite)"]
async fn running_vmm_inherits_the_ambient_capability_set() {
    let own = std::fs::read_to_string("/proc/self/status").expect("read own status");
    let own_amb = status_u64(&own, "CapAmb", 16);
    assert_eq!(
        own_amb & CAP_NET_ADMIN,
        CAP_NET_ADMIN,
        "this leg needs CAP_NET_ADMIN in this process's AMBIENT set — run it through the blessed \
         runner (`just bless` + `just test-privileged`); with an empty ambient set the assertion \
         below would read 0 == 0 and pass against a jail that cleared it (CapAmb {own_amb:#018x})"
    );

    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    let mut vm = common::start_vm(
        &vmm,
        confinement_cfg(JailConfig::hardened(), VmmSeccomp::Enforcing),
    )
    .await;
    let pid = vmm_pid_for_vmid(vm.vmid());
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("read VMM status");
    let vmm_amb = status_u64(&status, "CapAmb", 16);
    vm.kill().await.expect("kill VM");

    assert_eq!(
        vmm_amb, own_amb,
        "the shipped hardened jail must NOT clear the VMM's ambient set (Appendix A reversal 9): \
         VMM CapAmb {vmm_amb:#018x} != this process's {own_amb:#018x}"
    );
}
