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
    // OWNED (`common::TempTree`): the trailing `remove_dir_all` is skipped by every panicking
    // assertion below, and each leg writes multi-MiB raw disk images.
    let tmp = common::TempTree::create(&format!("vmcell-test-blk-{}-{}", std::process::id(), id));
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
    let steward = vm
        .steward(Some(std::time::Duration::from_secs(60)))
        .await
        .expect("steward must reach ready");

    // Read the RO marker off /dev/vdb; write a marker to the RW /dev/vdc and read it
    // back. `dd`/`printf` are coreutils, present in the base rootfs.
    let script = "dd if=/dev/vdb bs=8 count=1 2>/dev/null; \
                  printf VMCELLRW | dd of=/dev/vdc bs=8 count=1 conv=notrunc 2>/dev/null; \
                  dd if=/dev/vdc bs=8 count=1 2>/dev/null";
    let outcome = steward
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
    // No trailing removal: `tmp` owns the tree and drops here (and on any panic above).
}

// §4.6 (Extra virtio-blk devices and disk-I/O throttling): disk-I/O fault injection — a DiskIoLimit throttles the device's bandwidth. This
// is a self-calibrating DATA-PLANE test: read an un-throttled disk (/dev/vdb) and a
// throttled one (/dev/vdc, 1 MiB/s) of the same size in the same VM, and assert the
// throttled read is both slow in absolute terms AND much slower than the un-throttled
// baseline on this host — so a broken/absent limiter (both reads fast) reddens without
// depending on the host's raw disk speed. Every backend has a native rate limiter (CH
// `rate_limiter_config`, FC `rate_limiter`, QEMU `throttling.*`).
vmm_matrix_test!(extra_block_io_throttle, |vmm| {
    // crosvm has no per-drive rate limiter (`--block` exposes no bandwidth/iops key), so it
    // self-skips this data-plane test rather than failing it; CH/FC/QEMU all have one. The
    // descriptor value is pinned KVM-free in `capability_honesty_disk_io_throttle` below.
    require_cap!(vmcell::vmm::Vmm::capabilities(&vmm), disk_io_throttle, vmm);
    test_io_throttle_impl(&vmm).await;
});

// H-TEST-3: capability-honesty pin for `disk_io_throttle`. A `require_cap!` skip is an invisible
// nextest PASS, so if crosvm's flag silently flipped `true` the throttle leg would run and hard-fail
// (crosvm rejects a throttled disk at create); if a throttling backend flipped `false` its leg would
// go dark. This non-KVM pin fixes the documented per-backend values. Inverse: flip any asserted value.
#[test]
fn capability_honesty_disk_io_throttle() {
    #[cfg(feature = "cloud-hypervisor")]
    assert!(
        vmcell::vmm::Vmm::capabilities(&vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(
            common::ch_bin()
        ))
        .disk_io_throttle,
        "CH has a native rate limiter; a false silently skips extra_block_io_throttle::cloud_hypervisor"
    );
    #[cfg(feature = "firecracker")]
    assert!(
        vmcell::vmm::Vmm::capabilities(&vmcell_firecracker::Firecracker::new(common::fc_bin()))
            .disk_io_throttle,
        "FC has a native rate limiter; a false silently skips extra_block_io_throttle::firecracker"
    );
    #[cfg(feature = "qemu")]
    assert!(
        vmcell::vmm::Vmm::capabilities(&vmcell_qemu::Qemu::new(common::qemu_bin()))
            .disk_io_throttle,
        "QEMU has native throttling; a false silently skips extra_block_io_throttle::qemu"
    );
    #[cfg(feature = "crosvm")]
    assert!(
        !vmcell::vmm::Vmm::capabilities(&vmcell_crosvm::Crosvm::new(common::crosvm_bin()))
            .disk_io_throttle,
        "crosvm must NOT advertise disk_io_throttle (--block has no bandwidth/iops key); a true would \
         hard-fail extra_block_io_throttle::crosvm at create"
    );
}

async fn test_io_throttle_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    const MIB: usize = 1 << 20;
    let id = uuid::Uuid::new_v4();
    // OWNED (`common::TempTree`): see `test_extra_block_impl` — same leak-on-panic shape, and
    // this leg writes two 4 MiB images.
    let tmp = common::TempTree::create(&format!(
        "vmcell-test-throttle-{}-{}",
        std::process::id(),
        id
    ));
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
    let steward = vm
        .steward(Some(std::time::Duration::from_secs(60)))
        .await
        .expect("steward ready");

    // Read 4 MiB off each disk cold, timing the exec host-side. A 1 MiB/s cap on a
    // 4 MiB read with a 1 MiB burst floors the throttled read at ~3s.
    async fn timed_read(
        steward: &mut vmcell::steward::StewardClient,
        dev: &str,
    ) -> (vmcell::ExecOutcome, u128) {
        let start = std::time::Instant::now();
        let out = steward
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

    let (fast, fast_ms) = timed_read(steward, "/dev/vdb").await;
    assert_eq!(fast.code, 0, "un-throttled read failed: {fast:?}");
    let (slow, slow_ms) = timed_read(steward, "/dev/vdc").await;
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
    // No trailing removal: `tmp` owns the tree and drops here (and on any panic above).
}

// docs/90 T4: the `DiskIoLimit::iops` half, which had no live leg at all — the bandwidth leg above
// was the only evidence that `with_io_limit` reaches a rate limiter, and `iops` travels a
// DIFFERENT field on every backend (CH's `ops` token bucket, FC's `ops`, QEMU's
// `throttling.iops-total`). A caller who asks for a 50-IOPS disk and silently gets an unlimited one
// is testing their retry logic against nothing.
//
// Same self-calibrating shape as the bandwidth leg, deliberately: two disks in ONE VM, /dev/vdb
// un-throttled as the in-VM baseline and /dev/vdc capped, so a broken limiter (both reads fast)
// reddens without depending on the host's raw disk speed. What differs is the workload — the cap
// is on OPERATIONS, so the read has to be many small ones. `iflag=direct` is what makes each 4 KiB
// read its own device request: without O_DIRECT the guest page cache's readahead coalesces the
// whole file into a handful of large requests, which a 50-IOPS cap would not notice, and the leg
// would pass against an absent limiter.
//
// RED ON THE INVERSE: drop `iops` from a backend's rate-limiter builder (CH/FC `ops`, QEMU's
// `throttling.iops-total`) and the throttled read finishes as fast as the baseline — both the
// absolute floor and the ratio go red. (Demonstrated by raising the cap to 1_000_000 IOPS:
// `vdb 19ms, vdc 14ms` and "the iops rate limiter did not take effect".)
//
// MEASURED 2026-08-17, all three throttling backends: CH `vdb 10ms / vdc 5067ms`, FC
// `vdb 9ms / vdc 4362ms`, QEMU `vdb 13ms / vdc 5882ms`; crosvm records
// `SKIP crosvm disk_io_throttle`.
vmm_matrix_test!(extra_block_iops_throttle, |vmm| {
    // Same skip as the bandwidth leg: crosvm's `--block` exposes no iops key either. The
    // descriptor value is pinned KVM-free by `capability_honesty_disk_io_throttle` above.
    require_cap!(vmcell::vmm::Vmm::capabilities(&vmm), disk_io_throttle, vmm);
    test_iops_throttle_impl(&vmm).await;
});

/// The requested IOPS cap, and the number of 4 KiB direct reads each leg issues. 300 requests
/// against a 50-IOPS bucket floors the throttled read at ~5s (the first `IOPS_CAP` are the initial
/// bucket, the rest refill at `IOPS_CAP`/s); the same 300 reads off an un-throttled page-cached
/// host file finish in tens of milliseconds.
const IOPS_CAP: u64 = 50;
const IOPS_READS: usize = 300;

async fn test_iops_throttle_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    const MIB: usize = 1 << 20;
    let id = uuid::Uuid::new_v4();
    // OWNED (`common::TempTree`): see `test_extra_block_impl` — same leak-on-panic shape.
    let tmp = common::TempTree::create(&format!("vmcell-test-iops-{}-{}", std::process::id(), id));
    // 4 MiB each, comfortably more than the 300 * 4 KiB = 1.2 MiB each leg reads.
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
    .with_extra_disk(BlockDevice::read_only(&slow_img).with_io_limit(DiskIoLimit::iops(IOPS_CAP)))
    .network_disabled()
    .build()
    .unwrap();

    let mut vm = common::start_vm(vmm, cfg).await;
    let steward = vm
        .steward(Some(std::time::Duration::from_secs(120)))
        .await
        .expect("steward ready");

    /// Issues `IOPS_READS` 4 KiB O_DIRECT reads off `dev`, timing the exec host-side.
    async fn timed_direct_reads(
        steward: &mut vmcell::steward::StewardClient,
        dev: &str,
    ) -> (vmcell::ExecOutcome, u128) {
        let start = std::time::Instant::now();
        let out = steward
            .exec(vmcell::ExecRequest::new(vec![
                "dd".to_string(),
                format!("if={dev}"),
                "of=/dev/null".to_string(),
                "bs=4096".to_string(),
                format!("count={IOPS_READS}"),
                // One device request per read: O_DIRECT bypasses the page cache, so readahead
                // cannot coalesce 300 small reads into a few large ones and hide an IOPS cap.
                "iflag=direct".to_string(),
            ]))
            .await
            .expect("dd direct read");
        (out, start.elapsed().as_millis())
    }

    let (fast, fast_ms) = timed_direct_reads(steward, "/dev/vdb").await;
    assert_eq!(
        fast.code, 0,
        "un-throttled direct read failed (does this guest's dd support iflag=direct?): {fast:?}"
    );
    let (slow, slow_ms) = timed_direct_reads(steward, "/dev/vdc").await;
    assert_eq!(slow.code, 0, "throttled direct read failed: {slow:?}");
    println!("iops={IOPS_CAP}: {IOPS_READS} direct 4K reads — vdb {fast_ms}ms, vdc {slow_ms}ms");

    // Floor: 300 requests through a 50/s bucket cannot complete faster than ~5s; 2.5s is half
    // that, leaving room for the bucket's initial fill and refill granularity while staying an
    // order of magnitude above the un-throttled time.
    assert!(
        slow_ms >= 2500,
        "{IOPS_READS} direct 4 KiB reads at {IOPS_CAP} IOPS must take >= 2.5s; got {slow_ms}ms — \
         the iops rate limiter did not take effect"
    );
    assert!(
        slow_ms > fast_ms.saturating_mul(3),
        "the throttled read ({slow_ms}ms) must be far slower than the un-throttled baseline \
         ({fast_ms}ms) in the same VM on this host"
    );

    vm.kill().await.unwrap();
    // No trailing removal: `tmp` owns the tree and drops here (and on any panic above).
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
    // OWNED (`common::TempTree`): this leg also holds a guest-RAM-sized snapshot dir under `tmp`.
    let tmp = common::TempTree::create(&format!(
        "vmcell-test-blksnap-{}-{}",
        std::process::id(),
        id
    ));
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
        // QEMU snapshot needs the in-kernel vhost-vsock transport (§2.4); no-op for CH/FC.
        .snapshotting(true)
        .build()
        .unwrap()
    };

    // Block 1: boot with the extra disk, write a marker to /dev/vdb, snapshot.
    let original_vmid;
    {
        let mut vm = MicroVm::start(vmm, mk_cfg(), &env)
            .await
            .expect("start VM with extra disk");
        let steward = vm
            .steward(Some(std::time::Duration::from_secs(60)))
            .await
            .expect("steward ready");
        // `sync` so the guest write reaches the host image file before the snapshot
        // pauses the VM.
        let w = steward
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

        // First post-restore steward() call carries the mandatory resync (RealClock).
        let outcome = vm
            .steward(Some(std::time::Duration::from_secs(60)))
            .await
            .expect("steward ready after restore")
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

    // No trailing removal: `tmp` owns the tree and drops here (and on any panic above).
}
