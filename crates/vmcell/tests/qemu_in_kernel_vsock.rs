//! Increment-2 gate (design §2.4): a `snapshotting` QEMU VM boots on the **in-kernel
//! `vhost-vsock`** transport and the host agent round-trips an `exec` over **AF_VSOCK**,
//! with no external `vhost-device-vsock` daemon.
//!
//! This isolates the AF_VSOCK host transport — experiment E3's explicitly *un-run*
//! step (`/dev/vhost-vsock` wasn't openable in that sandbox) — from snapshot/restore,
//! so a transport failure is diagnosed here rather than tangled with `migrate`. Needs
//! KVM, `CAP_NET_ADMIN` (privileged tap), and an openable `/dev/vhost-vsock` — the
//! blessed runner's `CAP_DAC_OVERRIDE` provides the last (it is `root:kvm 0660`).
//!
//! QEMU-specific by construction: only QEMU has the in-kernel-vsock-vs-daemon fork;
//! CH/FC always terminate vsock inside the VMM, so there is no matrix here.

#![cfg(feature = "qemu")]

use vmcell::agent::protocol::ExecRequest;
use vmcell::config::{Egress, NetConfig, RootfsSource, VmConfig, VsockTransport};
use vmcell::orchestrator::MicroVm;
use vmcell::vmm::{Qemu, VmInstance, VsockEndpoint};

mod common;

#[tokio::test]
#[ignore = "needs KVM + /dev/vhost-vsock (blessed runner CAP_DAC_OVERRIDE) + CAP_NET_ADMIN"]
async fn qemu_in_kernel_vsock_boot_and_exec() {
    // Reap any orphaned vmcell-net-* namespaces from a prior aborted run so this
    // privileged-tap test's vmid cannot collide with a leak (the capability runner
    // holds CAP_SYS_ADMIN + CAP_DAC_OVERRIDE — no sudo).
    common::clean_vmcell_netns();

    // Gate on the effective CAP_NET_ADMIN (the runner grants it ambiently), not euid.
    if !common::has_cap_net_admin() {
        panic!(
            "SKIP: in-kernel vhost-vsock needs CAP_NET_ADMIN for privileged tap networking; \
             not present in the effective capability set"
        );
    }

    let kernel = common::get_vmlinux();
    let rootfs = common::get_rootfs();
    let vmm = Qemu::new(common::qemu_bin());

    // `snapshotting = true` selects the in-kernel vhost-vsock transport (§2.4) and is
    // privileged-gated at build() — hence the Privileged/tap network below.
    let mut cfg = VmConfig::builder(kernel, RootfsSource::Erofs { image: rootfs })
        .snapshotting(true)
        .build()
        .expect("build snapshotting QEMU config");
    cfg.net = NetConfig::Privileged {
        egress: Egress::Open,
    };

    let env = vmcell::HostEnv::hermetic();
    let mut vm = MicroVm::start(&vmm, cfg, &env)
        .await
        .expect("start snapshotting QEMU (in-kernel vhost-vsock)");

    // The transport MUST be AF_VSOCK, not the external-daemon AF_UNIX bridge — the
    // whole point of the in-kernel path. RED if `uses_in_kernel_vsock` / the endpoint
    // wiring regresses to the daemon.
    let endpoint = vm.instance().vsock_endpoint();
    assert!(
        matches!(endpoint, VsockEndpoint::Vsock { .. }),
        "snapshotting QEMU must expose an AF_VSOCK endpoint, got {endpoint:?}"
    );
    let serial_path = vm.instance().serial_log().to_path_buf();

    // The load-bearing check: the host agent completes the connect + `Ready` handshake
    // over AF_VSOCK (no `CONNECT`/`OK` prologue) and a real command round-trips.
    let agent = match vm.agent(None).await {
        Ok(a) => a,
        Err(e) => {
            let log = std::fs::read_to_string(&serial_path).unwrap_or_default();
            panic!("agent connect over AF_VSOCK failed: {e}\nSERIAL LOG:\n{log}");
        }
    };
    let out = agent
        .exec(ExecRequest::new(vec![
            "echo".into(),
            "in-kernel-vsock-ok".into(),
        ]))
        .await
        .expect("exec over AF_VSOCK");
    assert_eq!(
        out.code,
        0,
        "exec failed over AF_VSOCK: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "in-kernel-vsock-ok"
    );

    vm.shutdown().await.expect("graceful shutdown");
}

/// Task B (docs/qemu-follow-ups.md): a **non-snapshot** QEMU opts into the in-kernel
/// vhost-vsock transport via `vsock_transport: InKernel`, decoupled from `snapshotting`.
/// Proves the transport selection is no longer tied to `snapshotting`: the VM boots on
/// AF_VSOCK (shedding the external-daemon bring-up flake) without being snapshot-eligible.
/// RED on the inverse (the old `snapshotting`-only predicate): a non-snapshot VM would
/// take the external-daemon AF_UNIX path and the `VsockEndpoint::Vsock` assert reddens.
#[tokio::test]
#[ignore = "needs KVM + /dev/vhost-vsock (blessed runner CAP_DAC_OVERRIDE) + CAP_NET_ADMIN"]
async fn qemu_non_snapshot_in_kernel_vsock_via_transport_knob() {
    common::clean_vmcell_netns();

    if !common::has_cap_net_admin() {
        panic!(
            "SKIP: in-kernel vhost-vsock needs CAP_NET_ADMIN for privileged tap networking; \
             not present in the effective capability set"
        );
    }

    let kernel = common::get_vmlinux();
    let rootfs = common::get_rootfs();
    let vmm = Qemu::new(common::qemu_bin());

    // NOT snapshotting: the in-kernel transport is selected purely by the transport knob.
    let mut cfg = VmConfig::builder(kernel, RootfsSource::Erofs { image: rootfs })
        .vsock_transport(VsockTransport::InKernel)
        .build()
        .expect("build non-snapshot in-kernel-vsock QEMU config");
    assert!(
        !cfg.snapshotting,
        "this VM must NOT be snapshotting — the transport knob alone selects in-kernel"
    );
    cfg.net = NetConfig::Privileged {
        egress: Egress::Open,
    };

    let env = vmcell::HostEnv::hermetic();
    let mut vm = MicroVm::start(&vmm, cfg, &env)
        .await
        .expect("start non-snapshot in-kernel-vsock QEMU");

    let endpoint = vm.instance().vsock_endpoint();
    assert!(
        matches!(endpoint, VsockEndpoint::Vsock { .. }),
        "a non-snapshot QEMU with vsock_transport=InKernel must expose an AF_VSOCK \
         endpoint, got {endpoint:?}"
    );
    let serial_path = vm.instance().serial_log().to_path_buf();

    let agent = match vm.agent(None).await {
        Ok(a) => a,
        Err(e) => {
            let log = std::fs::read_to_string(&serial_path).unwrap_or_default();
            panic!("agent connect over AF_VSOCK failed: {e}\nSERIAL LOG:\n{log}");
        }
    };
    let out = agent
        .exec(ExecRequest::new(vec![
            "echo".into(),
            "non-snapshot-in-kernel-ok".into(),
        ]))
        .await
        .expect("exec over AF_VSOCK");
    assert_eq!(
        out.code,
        0,
        "exec failed over AF_VSOCK: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "non-snapshot-in-kernel-ok"
    );

    vm.shutdown().await.expect("graceful shutdown");
}
