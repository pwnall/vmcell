//! Zygote suspend/resume fan-out integration test (§8.4, The zygote fan-out and the OverlayStore seam).
//!
//! Boots one VM to agent-ready, **suspends** it into a zygote, then mints many
//! identical clones by copy-on-write-copying the suspend image. Asserts the
//! properties that make fan-out correct:
//!
//! - On a host-path-rotating backend (CH): a **concurrent** pool of N clones,
//!   each with a distinct vmid, a distinct guest MAC (`mac_math(vmid)`), a
//!   distinct host vsock path, and a working `exec` — all alive at once.
//! - The zygote **master is immutable**: its `config.json` is byte-identical
//!   after the fan-out, even though the single-use restore path rewrites that
//!   file in place (§8.1, The warm-snapshot path and the eligibility law, §13, Cross-cutting invariants) — proof each clone restored from its own copy.
//! - On a verbatim-rebind backend (FC): a concurrent fan-out (N>1) is a typed
//!   `Error::Unsupported`, while a single clone still works (§8.4, The zygote fan-out and the OverlayStore seam, gate).
//!
//! `#[ignore = "needs KVM"]` via `vmm_matrix_test!`; skips backends without
//! `snapshot_restore` visibly (H-TEST-3), never silently.

use std::collections::HashSet;
use vmcell::Zygote;
use vmcell::agent::protocol::ExecRequest;
use vmcell::config::{Egress, NetConfig, RootfsSource, VmConfig};
use vmcell::orchestrator::MicroVm;
use vmcell::vmm::{VmInstance, Vmm};

mod common;

vmm_matrix_test!(zygote_fan_out, |vmm| {
    require_cap!(vmcell::vmm::Vmm::capabilities(&vmm), snapshot_restore, vmm);
    zygote_fan_out_impl(&vmm).await;
});

async fn zygote_fan_out_impl<V: Vmm>(vmm: &V) {
    // Reap any orphaned vmcell-net-* namespaces so a leak from a prior aborted run
    // cannot collide with a clone's vmid (no sudo; capability runner, §13, Cross-cutting invariants).
    common::clean_vmcell_netns();
    if !common::has_cap_net_admin() {
        panic!(
            "SKIP: zygote fan-out needs CAP_NET_ADMIN for privileged tap networking; \
             not present in the effective capability set"
        );
    }

    let kernel = common::get_vmlinux();
    let rootfs = common::get_rootfs();
    // Snapshot-eligible base config: erofs rootfs, privileged (tap) network, no
    // vhost-user device (§13, Cross-cutting invariants). One factory so every clone restores with the same
    // config (with a fresh vmid injected by the orchestrator).
    let base_cfg = || {
        let mut cfg = VmConfig::builder(
            kernel.clone(),
            RootfsSource::Erofs {
                image: rootfs.clone(),
            },
        )
        .build()
        .expect("valid base config");
        cfg.net = NetConfig::Privileged {
            egress: Egress::Open,
        };
        // QEMU snapshot needs the in-kernel vhost-vsock transport (§2.4); no-op for CH/FC.
        cfg.snapshotting = true;
        cfg
    };

    let id = uuid::Uuid::new_v4();
    let master_dir =
        std::env::temp_dir().join(format!("vmcell-zygote-{}-{}", std::process::id(), id));
    if master_dir.exists() {
        std::fs::remove_dir_all(&master_dir).unwrap();
    }
    std::fs::create_dir_all(&master_dir).unwrap();

    let env = vmcell::HostEnv::hermetic();

    // 1. Boot a base VM to agent-ready, then SUSPEND it into a zygote.
    let mut base = MicroVm::start(vmm, base_cfg(), &env)
        .await
        .expect("start base VM");
    if let Err(e) = base.agent(None).await {
        let log = std::fs::read_to_string(base.instance().serial_log()).unwrap_or_default();
        println!("BASE SERIAL LOG:\n{log}");
        panic!("base agent connect failed: {e}");
    }
    let zygote = Zygote::suspend(&mut base, base_cfg(), &master_dir)
        .await
        .expect("suspend base into a zygote");
    base.shutdown().await.expect("shutdown base VM");

    // Capture the master's config.json bytes to prove immutability across cloning
    // (the CH single-use restore path rewrites this file in place; the zygote path
    // must not, §13, Cross-cutting invariants). FC snapshots have no config.json — `None` there.
    let master_cfg_before = std::fs::read(master_dir.join("config.json")).ok();

    println!("zygote CoW support: {:?}", zygote.probe_cow_support());

    if Vmm::capabilities(vmm).restore_rotates_host_paths {
        // CH tier: mint a CONCURRENT pool.
        const N: usize = 3;
        let mut clones = zygote
            .spawn_clones(vmm, N, &env)
            .await
            .expect("concurrent zygote fan-out");
        assert_eq!(clones.len(), N, "fan-out must produce N live clones");

        let mut vmids: HashSet<u32> = HashSet::new();
        let mut macs: HashSet<String> = HashSet::new();
        let mut vsocks: HashSet<String> = HashSet::new();
        for (i, vm) in clones.iter_mut().enumerate() {
            let vmid = vm.vmid();
            assert!(vmids.insert(vmid), "clone {i} vmid {vmid} must be distinct");
            let vsock = vm
                .instance()
                .vsock_path()
                .to_str()
                .expect("utf8 vsock path")
                .to_string();
            assert!(
                vsocks.insert(vsock.clone()),
                "clone {i} vsock path {vsock} must be distinct"
            );

            // Each clone is independently agent-reachable and execs correctly.
            let log_path = vm.instance().serial_log().to_path_buf();
            let agent_res = vm.agent(None).await;
            if let Err(e) = &agent_res {
                let log = std::fs::read_to_string(&log_path).unwrap_or_default();
                println!("CLONE {i} SERIAL LOG:\n{log}");
                panic!("clone {i} agent connect failed: {e}");
            }
            let out = agent_res
                .unwrap()
                .exec(ExecRequest::new(vec!["echo".into(), format!("clone-{i}")]))
                .await
                .unwrap();
            assert_eq!(out.code, 0, "clone {i} exec must succeed");
            assert_eq!(
                String::from_utf8_lossy(&out.stdout).trim(),
                format!("clone-{i}")
            );

            // The per-clone resync rotated the network identity to THIS clone's
            // vmid: the in-guest MAC must equal mac_math(vmid). Distinct vmids ⇒
            // distinct MACs, so no two concurrent clones share an L2 identity.
            let mac_out = vm
                .agent(None)
                .await
                .unwrap()
                .exec(ExecRequest::new(vec![
                    "cat".into(),
                    "/sys/class/net/eth0/address".into(),
                ]))
                .await
                .unwrap();
            let mac = String::from_utf8_lossy(&mac_out.stdout).trim().to_string();
            let expected = vmcell::net::mac_math(vmid).expect("mac_math(clone vmid)");
            assert_eq!(
                mac, expected,
                "clone {i} guest MAC must equal mac_math(vmid={vmid})"
            );
            assert!(macs.insert(mac), "clone {i} MAC must be distinct");
        }

        // Master immutability: N in-place-rewriting restores must not have touched
        // the master's config.json (each restored from its own CoW copy).
        if let Some(before) = master_cfg_before {
            let after =
                std::fs::read(master_dir.join("config.json")).expect("read master config.json");
            assert_eq!(
                before, after,
                "zygote master config.json must be byte-identical after fan-out (§12.12)"
            );
        }

        for (i, vm) in clones.into_iter().enumerate() {
            vm.shutdown()
                .await
                .unwrap_or_else(|e| panic!("clone {i} shutdown failed: {e}"));
        }
    } else {
        // FC tier: concurrent fan-out is gated off (verbatim vsock rebind); a
        // single clone still works.
        let many = zygote.spawn_clones(vmm, 2, &env).await;
        // Don't `{:?}` the Ok arm — that would force `V::Instance: Debug`. A stray
        // Ok pool (the bug) is dropped here (ordered teardown) as the test panics.
        match many {
            Err(vmcell::Error::Unsupported { .. }) => {}
            Err(e) => {
                panic!("concurrent FC fan-out must be Unsupported, got a different error: {e}")
            }
            Ok(_pool) => panic!(
                "concurrent fan-out on a verbatim-rebind backend must be Unsupported, but it succeeded"
            ),
        }

        let mut one = zygote
            .spawn_clone(vmm, &env)
            .await
            .expect("a single zygote clone works on any snapshot backend");
        let out = one
            .agent(None)
            .await
            .expect("single clone agent")
            .exec(ExecRequest::new(vec!["echo".into(), "one".into()]))
            .await
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "one");
        one.shutdown().await.expect("shutdown single clone");
    }

    let _ = std::fs::remove_dir_all(&master_dir);
}
