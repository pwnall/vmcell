//! QEMU restore rotates the host-global guest CID (§2.4, `restore_rotates_host_paths`).
//!
//! Focused red-on-inverse guard for the CID-rotation change: snapshot a QEMU VM at its
//! baked CID `X`, reserve `X` so the restore is forced to draw a *different* fresh CID
//! `Y`, restore, and prove (a) `migrate-incoming` completes with the destination
//! `-device guest-cid=Y != X`, and (b) the guest agent answers at `(Y, 5000)` and a
//! command round-trips. RED on the inverse (a `restore()` that reused the baked CID):
//! `guest_cid()` would come back as `X == original_cid` and the `assert_ne!` reddens.
//!
//! `guest-cid` is a QEMU device *property*, not part of the migration stream, so restore
//! *can* program a fresh CID; the guest's cached CID in migrated RAM does not make it
//! unreachable at the new CID (validated here). This is the property that makes
//! concurrent QEMU zygote fan-out sound — each clone binds its own CID on the
//! host-global vhost-vsock namespace (see `zygote.rs` for the concurrent pool).
//!
//! Needs KVM, `CAP_NET_ADMIN` (privileged tap), and an openable `/dev/vhost-vsock` (the
//! blessed runner's `CAP_DAC_OVERRIDE` — it is `root:kvm 0660`). QEMU-specific: only
//! QEMU rotates a host-global resource (CH rotates AF_UNIX paths; FC does not rotate).

#![cfg(feature = "qemu")]

use vmcell::agent::protocol::ExecRequest;
use vmcell::config::{Egress, NetConfig, RootfsSource, VmConfig};
use vmcell::orchestrator::MicroVm;
use vmcell::vmm::{VmInstance, VsockEndpoint};
use vmcell_qemu::Qemu;

mod common;

#[tokio::test]
#[ignore = "needs KVM + /dev/vhost-vsock (blessed runner CAP_DAC_OVERRIDE) + CAP_NET_ADMIN"]
async fn qemu_restore_with_rotated_cid_reaches_agent() {
    common::clean_vmcell_netns();

    if !common::has_cap_net_admin() {
        panic!(
            "SKIP: CID-rotation restore needs CAP_NET_ADMIN for privileged tap networking; \
             not present in the effective capability set"
        );
    }

    let kernel = common::get_vmlinux();
    let rootfs = common::get_rootfs();
    let vmm = Qemu::new(common::qemu_bin());

    let base_cfg = || {
        let mut cfg = VmConfig::builder(
            kernel.clone(),
            RootfsSource::Erofs {
                image: rootfs.clone(),
            },
        )
        .snapshotting(true)
        .build()
        .expect("build snapshotting QEMU config");
        cfg.net = NetConfig::Privileged {
            egress: Egress::Open,
        };
        cfg
    };

    let id = uuid::Uuid::new_v4();
    // OWNED (`common::TempTree`): the trailing `remove_dir_all` this used to rely on is skipped by
    // every panicking assertion below, and a snapshot dir is guest-RAM-sized.
    let scratch = common::TempTree::reserve(&format!(
        "vmcell-qemu-cid-rotation-{}-{}",
        std::process::id(),
        id
    ));
    let snapshot_dir = scratch.path().to_path_buf();

    let env = vmcell::HostEnv::hermetic();

    // Block 1 — snapshot a snapshotting QEMU at its baked CID (X).
    let original_cid;
    {
        let mut vm = MicroVm::start(&vmm, base_cfg(), &env)
            .await
            .expect("start snapshotting QEMU");

        let serial = vm.instance().serial_log().to_path_buf();
        let agent = match vm.agent(None).await {
            Ok(a) => a,
            Err(e) => {
                let log = std::fs::read_to_string(&serial).unwrap_or_default();
                panic!("pre-snapshot agent connect failed: {e}\nSERIAL LOG:\n{log}");
            }
        };
        let out = agent
            .exec(ExecRequest::new(vec!["echo".into(), "pre-snap".into()]))
            .await
            .expect("pre-snapshot exec");
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "pre-snap");

        original_cid = vm.instance().guest_cid();
        assert!(
            matches!(vm.instance().vsock_endpoint(), VsockEndpoint::Vsock { .. }),
            "source must be on the in-kernel AF_VSOCK transport"
        );

        std::fs::create_dir_all(&snapshot_dir).unwrap();
        vm.snapshot(&snapshot_dir).await.expect("snapshot");
        vm.shutdown().await.expect("shutdown source");
    }

    // Sleep so the host clock advances past the guest's suspended clock (as
    // snapshot_restore.rs does), keeping the post-restore resync meaningful.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Force the restored VM to draw a CID Y != X: the source's CID was freed on
    // shutdown, so reserve it and the orchestrator's fresh `cids.allocate()` on the
    // restore path must return a strictly higher, distinct CID.
    env.cids
        .reserve(original_cid)
        .expect("source CID is free after shutdown; reserving forces a distinct restore CID");

    // Block 2 — restore with a fresh (rotated) CID and check the agent answers there.
    {
        let mut vm = match MicroVm::restore(&vmm, &snapshot_dir, base_cfg(), &env).await {
            Ok(vm) => vm,
            Err(e) => panic!(
                "migrate-incoming failed with a rotated device CID (source cid={original_cid}): {e}"
            ),
        };

        let new_cid = vm.instance().guest_cid();
        assert_ne!(
            new_cid, original_cid,
            "restored CID must differ from the source's baked CID — a restore that reused \
             the baked CID (the inverse of the rotation change) reddens here"
        );
        assert!(
            matches!(vm.instance().vsock_endpoint(), VsockEndpoint::Vsock { cid, .. } if cid == new_cid),
            "restored endpoint must be AF_VSOCK at the rotated CID {new_cid}"
        );

        // The load-bearing data-plane check: connect over AF_VSOCK at (Y, 5000) and
        // round-trip an exec. This is the first post-restore agent() call, so it also
        // drives the resync. A guest unreachable at the rotated CID would time out here.
        let serial = vm.instance().serial_log().to_path_buf();
        let agent = match vm.agent(None).await {
            Ok(a) => a,
            Err(e) => {
                let log = std::fs::read_to_string(&serial).unwrap_or_default();
                panic!(
                    "restore completed but the agent is UNREACHABLE at the rotated \
                     cid={new_cid} (source cid={original_cid}): {e}\nSERIAL LOG:\n{log}"
                );
            }
        };
        let out = agent
            .exec(ExecRequest::new(vec![
                "echo".into(),
                "rotated-cid-ok".into(),
            ]))
            .await
            .expect("post-restore exec at rotated CID");
        assert_eq!(
            out.code,
            0,
            "exec at rotated CID failed: {:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "rotated-cid-ok"
        );

        vm.shutdown().await.expect("shutdown restored");
    }
    // No trailing removal: `scratch` owns the tree and drops here (and on any panic above).
}
