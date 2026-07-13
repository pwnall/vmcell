use vmcell::config::{BlockDevice, DiskIoLimit, RootfsSource, VmConfig};

mod common;

// §4.6 (Extra virtio-blk devices and disk-I/O throttling): extra virtio-blk devices are attached AFTER the root disk, so they enumerate
// `/dev/vdb`, `/dev/vdc`, … in order. This is a DATA-PLANE test (AGENTS.md "assert on
// the data plane"): it reads a marker written into a read-only extra image back off
// `/dev/vdb` in-guest, and round-trips a marker through a read-write extra disk
// (`/dev/vdc`) — proving attach, ordering, the readonly flag, and raw exposure, not a
// proxy signal. Every backend boots off virtio-blk, so extra virtio-blk is universally
// supported (no `require_cap!` gating).
vmm_matrix_test!(extra_block, |vmm| {
    test_extra_block_impl(&vmm).await;
});

/// Writes a `size`-byte raw image at `path` with `marker` at offset 0, zero-padded.
fn write_raw_image(path: &std::path::Path, marker: &[u8], size: usize) {
    let mut bytes = vec![0u8; size];
    bytes[..marker.len()].copy_from_slice(marker);
    std::fs::write(path, &bytes).expect("write raw disk image");
}

async fn test_extra_block_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    let id = uuid::Uuid::new_v4();
    let tmp = std::env::temp_dir().join(format!("vmcell-test-blk-{}-{}", std::process::id(), id));
    std::fs::create_dir_all(&tmp).unwrap();
    // /dev/vdb: a read-only image seeded with a marker at its start.
    let ro_img = tmp.join("ro.raw");
    write_raw_image(&ro_img, b"VMCELLRO", 1 << 20);
    // /dev/vdc: a blank read-write scratch image.
    let rw_img = tmp.join("rw.raw");
    write_raw_image(&rw_img, b"", 1 << 20);

    let cfg = VmConfig::builder(
        common::get_vmlinux(),
        RootfsSource::Erofs {
            image: common::get_rootfs(),
        },
    )
    .with_extra_disk(BlockDevice::read_only(&ro_img))
    .with_extra_disk(BlockDevice::read_write(&rw_img))
    .network_disabled()
    .build()
    .unwrap();

    let mut vm = common::start_vm(vmm, cfg).await;
    let agent = vm
        .agent(Some(std::time::Duration::from_secs(60)))
        .await
        .expect("agent must reach ready");

    // Read the RO marker off /dev/vdb; write a marker to the RW /dev/vdc and read it
    // back. `dd`/`printf` are coreutils, present in the base rootfs.
    let script = "dd if=/dev/vdb bs=8 count=1 2>/dev/null; \
                  printf VMCELLRW | dd of=/dev/vdc bs=8 count=1 conv=notrunc 2>/dev/null; \
                  dd if=/dev/vdc bs=8 count=1 2>/dev/null";
    let outcome = agent
        .exec(vmcell::ExecRequest::new(vec![
            "sh".to_string(),
            "-c".to_string(),
            script.to_string(),
        ]))
        .await
        .expect("exec must round-trip over vsock");
    let stdout = String::from_utf8_lossy(&outcome.stdout);
    assert_eq!(outcome.code, 0, "read/write script failed: {outcome:?}");
    assert!(
        stdout.contains("VMCELLRO"),
        "read-only extra disk /dev/vdb marker not read back in-guest: stdout={stdout:?}"
    );
    assert!(
        stdout.contains("VMCELLRW"),
        "read-write extra disk /dev/vdc round-trip failed in-guest: stdout={stdout:?}"
    );

    vm.kill().await.unwrap();
    let _ = std::fs::remove_dir_all(&tmp);
}

// §4.6 (Extra virtio-blk devices and disk-I/O throttling): disk-I/O fault injection — a DiskIoLimit throttles the device's bandwidth. This
// is a self-calibrating DATA-PLANE test: read an un-throttled disk (/dev/vdb) and a
// throttled one (/dev/vdc, 1 MiB/s) of the same size in the same VM, and assert the
// throttled read is both slow in absolute terms AND much slower than the un-throttled
// baseline on this host — so a broken/absent limiter (both reads fast) reddens without
// depending on the host's raw disk speed. Every backend has a native rate limiter (CH
// `rate_limiter_config`, FC `rate_limiter`, QEMU `throttling.*`).
vmm_matrix_test!(extra_block_io_throttle, |vmm| {
    test_io_throttle_impl(&vmm).await;
});

async fn test_io_throttle_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    const MIB: usize = 1 << 20;
    let id = uuid::Uuid::new_v4();
    let tmp = std::env::temp_dir().join(format!(
        "vmcell-test-throttle-{}-{}",
        std::process::id(),
        id
    ));
    std::fs::create_dir_all(&tmp).unwrap();
    // Two 4 MiB disks: vdb unlimited (baseline), vdc capped at 1 MiB/s.
    let fast_img = tmp.join("fast.raw");
    write_raw_image(&fast_img, b"", 4 * MIB);
    let slow_img = tmp.join("slow.raw");
    write_raw_image(&slow_img, b"", 4 * MIB);

    let cfg = VmConfig::builder(
        common::get_vmlinux(),
        RootfsSource::Erofs {
            image: common::get_rootfs(),
        },
    )
    .with_extra_disk(BlockDevice::read_only(&fast_img))
    .with_extra_disk(
        BlockDevice::read_only(&slow_img).with_io_limit(DiskIoLimit::bandwidth(MIB as u64)),
    )
    .network_disabled()
    .build()
    .unwrap();

    let mut vm = common::start_vm(vmm, cfg).await;
    let agent = vm
        .agent(Some(std::time::Duration::from_secs(60)))
        .await
        .expect("agent ready");

    // Read 4 MiB off each disk cold, timing the exec host-side. A 1 MiB/s cap on a
    // 4 MiB read with a 1 MiB burst floors the throttled read at ~3s.
    async fn timed_read(
        agent: &mut vmcell::agent::AgentClient,
        dev: &str,
    ) -> (vmcell::ExecOutcome, u128) {
        let start = std::time::Instant::now();
        let out = agent
            .exec(vmcell::ExecRequest::new(vec![
                "dd".to_string(),
                format!("if={dev}"),
                "of=/dev/null".to_string(),
                "bs=1M".to_string(),
                "count=4".to_string(),
            ]))
            .await
            .expect("dd read");
        (out, start.elapsed().as_millis())
    }

    let (fast, fast_ms) = timed_read(agent, "/dev/vdb").await;
    assert_eq!(fast.code, 0, "un-throttled read failed: {fast:?}");
    let (slow, slow_ms) = timed_read(agent, "/dev/vdc").await;
    assert_eq!(slow.code, 0, "throttled read failed: {slow:?}");

    assert!(
        slow_ms >= 1500,
        "throttled 4 MiB read at 1 MiB/s must take >= 1.5s (a 4 MiB read is <0.2s unthrottled); \
         got {slow_ms}ms — the io_limit rate limiter did not take effect"
    );
    assert!(
        slow_ms > fast_ms.saturating_mul(3),
        "throttled read ({slow_ms}ms) must be far slower than the un-throttled baseline \
         ({fast_ms}ms) on this host"
    );

    vm.kill().await.unwrap();
    let _ = std::fs::remove_dir_all(&tmp);
}

// §4.6 (Extra virtio-blk devices and disk-I/O throttling): "plain virtio-blk composes with snapshot" (§17, Open gaps and future capabilities) — the V:high headline
// claim, proven on the DATA PLANE. A marker written into a writable extra disk before
// snapshot must be readable off `/dev/vdb` after a restore into a fresh VM. Extra disks
// are plain virtio-blk (not vhost-user), so they do NOT disqualify snapshot (§13, Cross-cutting invariants);
// CH/FC restore reconstruct the disk from the snapshot config at its recorded (stable)
// path, so the extra image lives OUTSIDE the per-VM scratch dir. Skips QEMU (no
// snapshot); the `snapshot_restore` capability-honesty pin lives in snapshot_restore.rs.
vmm_matrix_test!(extra_block_survives_snapshot, |vmm| {
    require_cap!(vmcell::vmm::Vmm::capabilities(&vmm), snapshot_restore, vmm);
    test_extra_block_snapshot_impl(&vmm).await;
});

async fn test_extra_block_snapshot_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    use vmcell::orchestrator::MicroVm;

    // Snapshot runs the privileged tap path (design §13, Cross-cutting invariants), which needs CAP_NET_ADMIN —
    // granted ambiently by the capability runner. Reap orphan netns first (no sudo).
    common::clean_vmcell_netns();
    if !common::has_cap_net_admin() {
        panic!("SKIP: extra-disk snapshot needs CAP_NET_ADMIN for privileged tap networking");
    }

    let id = uuid::Uuid::new_v4();
    let tmp =
        std::env::temp_dir().join(format!("vmcell-test-blksnap-{}-{}", std::process::id(), id));
    std::fs::create_dir_all(&tmp).unwrap();
    // The extra disk image lives at a STABLE path (not the per-VM scratch dir) so the
    // path CH/FC record in the snapshot config is still valid at restore.
    let disk_img = tmp.join("data.raw");
    write_raw_image(&disk_img, b"", 1 << 20);
    let snapshot_dir = tmp.join("snap");
    std::fs::create_dir_all(&snapshot_dir).unwrap();

    let env = vmcell::HostEnv::hermetic();

    let mk_cfg = || {
        VmConfig::builder(
            common::get_vmlinux(),
            RootfsSource::Erofs {
                image: common::get_rootfs(),
            },
        )
        .with_extra_disk(BlockDevice::read_write(&disk_img))
        .net(vmcell::config::NetConfig::Privileged {
            egress: vmcell::config::Egress::Open,
        })
        .build()
        .unwrap()
    };

    // Block 1: boot with the extra disk, write a marker to /dev/vdb, snapshot.
    let original_vmid;
    {
        let mut vm = MicroVm::start(vmm, mk_cfg(), &env)
            .await
            .expect("start VM with extra disk");
        let agent = vm
            .agent(Some(std::time::Duration::from_secs(60)))
            .await
            .expect("agent ready");
        // `sync` so the guest write reaches the host image file before the snapshot
        // pauses the VM.
        let w = agent
            .exec(vmcell::ExecRequest::new(vec![
                "sh".to_string(),
                "-c".to_string(),
                "printf VMCELLSNAP | dd of=/dev/vdb bs=16 count=1 conv=notrunc 2>/dev/null; sync"
                    .to_string(),
            ]))
            .await
            .expect("write marker to extra disk");
        assert_eq!(w.code, 0, "in-guest write to /dev/vdb failed: {w:?}");

        original_vmid = vm.vmid();
        vm.snapshot(&snapshot_dir).await.expect("snapshot");
        vm.shutdown().await.expect("shutdown after snapshot");
    }

    // Reserve the original vmid so the restore is forced onto a fresh one (mirrors
    // snapshot_restore.rs: proves the extra disk survives independent of vmid rotation).
    env.vmids
        .reserve(original_vmid)
        .expect("original vmid is free after shutdown");

    // Block 2: restore into a fresh VM and read the marker back off /dev/vdb.
    {
        let mut vm = MicroVm::restore(vmm, &snapshot_dir, mk_cfg(), &env)
            .await
            .expect("restore VM with extra disk");
        assert_ne!(vm.vmid(), original_vmid, "restore must get a fresh vmid");

        // First post-restore agent() call carries the mandatory resync (RealClock).
        let outcome = vm
            .agent(Some(std::time::Duration::from_secs(60)))
            .await
            .expect("agent ready after restore")
            .exec(vmcell::ExecRequest::new(vec![
                "sh".to_string(),
                "-c".to_string(),
                "dd if=/dev/vdb bs=16 count=1 2>/dev/null".to_string(),
            ]))
            .await
            .expect("read /dev/vdb after restore");
        let stdout = String::from_utf8_lossy(&outcome.stdout);
        assert!(
            stdout.contains("VMCELLSNAP"),
            "extra virtio-blk marker did not survive snapshot→restore (composes-with-snapshot \
             claim): stdout={stdout:?}"
        );

        vm.shutdown().await.expect("shutdown restored VM");
    }

    let _ = std::fs::remove_dir_all(&tmp);
}
