use vmcell::config::{RootfsSource, VmConfig};
use vmcell::orchestrator::MicroVm;
use vmcell::steward::protocol::ExecRequest;
use vmcell::vmm::VmInstance;

mod common;

/// The in-guest TCP port the data-plane leg's `echo-server` listens on (delta 7's guest-tools
/// applet, as in `segment.rs` — no new guest code, law C6 untouched).
const EGRESS_ECHO_PORT: u16 = 7101;

/// The host-side client of that echo server, run INSIDE the VM's own network namespace.
///
/// A privileged VM holds only its `/30` tap — no veth, no uplink — so the only host endpoint on
/// its data plane is the tap's gateway address inside `vmcell-net-<vmid>`; a socket's netns is
/// fixed at `socket()` time, so the client has to be created there (`NetSegment::dial_tcp`'s
/// pattern, which is `pub(crate)`-gated for the per-VM netns, hence the `ip netns exec` shell-out
/// the rest of this suite already uses for `nft`/`tc`). `python3` is the same host dependency
/// `host_endpoint.rs` / `egress_proxy.rs` already require.
///
/// Bounded, never a hang: an unplumbed tap answers no ARP, so the connect must time out rather
/// than block the suite — 2 s × the 20 attempts below is ~50 s to a loud red, while a listener
/// that is merely still starting is refused immediately and gets the full retry budget.
const HOST_ECHO_CLIENT_PY: &str = "\
import socket,sys
s=socket.create_connection((sys.argv[1],int(sys.argv[2])),2)
s.settimeout(2)
s.sendall(sys.argv[3].encode())
buf=b''
while len(buf)<len(sys.argv[3]):
    c=s.recv(4096)
    if not c: break
    buf+=c
s.close()
sys.stdout.buffer.write(buf)
";

vmm_matrix_test!(snapshot_restore, |vmm| {
    require_cap!(vmcell::vmm::Vmm::capabilities(&vmm), snapshot_restore, vmm);
    test_snapshot_restore_impl(&vmm).await;
});

/// Leaves `echo-server --tcp` listening on [`EGRESS_ECHO_PORT`] inside `vm`.
///
/// Re-runnable: a second copy simply fails to bind and exits, so the post-restore call is a no-op
/// when the pre-snapshot listener resumed with the guest.
async fn start_guest_echo_server<V: vmcell::vmm::Vmm>(vm: &mut MicroVm<V>) {
    let started = vm
        .steward(None)
        .await
        .expect("steward for the echo server")
        .exec(ExecRequest::new(vec![
            "sh".into(),
            "-c".into(),
            format!(
                "/vmcell-tools/echo-server --tcp 0.0.0.0:{EGRESS_ECHO_PORT} </dev/null \
                 >/tmp/echo.log 2>&1 &"
            ),
        ]))
        .await
        .expect("spawning the echo-server must succeed");
    assert_eq!(
        started.code,
        0,
        "backgrounding the echo-server failed: {}",
        String::from_utf8_lossy(&started.stderr)
    );
}

/// One host→guest→host byte exchange over the VM's tap, from inside netns `netns`. `None` on any
/// failure (the guest listener is not up yet, or nothing is plumbed).
fn host_echo_once(netns: &str, guest_ip: std::net::Ipv4Addr, payload: &str) -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["netns", "exec", netns, "python3", "-c", HOST_ECHO_CLIENT_PY])
        .args([
            guest_ip.to_string(),
            EGRESS_ECHO_PORT.to_string(),
            payload.to_string(),
        ])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The `ip -o link show` view **inside** the VM's netns — the diagnostic that names the M1 defect
/// directly (an orphan `<prefix>-tap-<old vmid>`, down and unbridged, beside the plumbed one).
///
/// `nsenter --net=<path>` is `segment.rs`'s proven idiom, and **stderr is folded into the result**:
/// the first cut used `ip netns exec … ip …`, whose exec failure goes to stderr only, so the live
/// red printed an empty listing — a diagnostic that silently says nothing is worse than none.
fn links_in_netns(netns: &str) -> String {
    match std::process::Command::new("nsenter")
        .arg(format!("--net=/var/run/netns/{netns}"))
        .args(["ip", "-o", "link", "show"])
        .output()
    {
        Ok(out) => format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
        Err(e) => format!("<listing links in {netns} failed: {e}>"),
    }
}

/// Asserts the guest actually MOVES A BYTE over its tap: the payload the guest echoes back is
/// data that left the guest through `eth0`, not a proxy signal.
///
/// docs/78 M1 (`fc-restore-rebinds-baked-tap-name-dead-data-plane`): FC's `/snapshot/load` used to
/// carry no `network_overrides`, so a restore re-opened the snapshot's BAKED
/// `<prefix>-tap-<old vmid>` — which, under the runner's ambient `CAP_NET_ADMIN`, `TUNSETIFF`
/// silently *creates* as a fresh, down, unbridged tap. Restore then "succeeds", the guest's resync
/// rotates its address onto the new `/30`, and every packet drops into the orphan. Nothing in this
/// file could see it: the `/proc/net/route` assertion above reads guest-side TEXT and the steward
/// transport is vsock, not the tap. This leg is the data plane itself, so it reddens on that
/// backend behavior — and it retro-covers CH's `net[].tap` restore-config rewrite (§8.2) and
/// crosvm/QEMU's fresh `--net tap-name=`/netdev on the same run.
///
/// Backend-independent by construction: the guest address is rotated by the SHARED post-restore
/// resync on every backend, and the netns/tap names are the one `vmcell::naming` law, so unlike
/// the host-socket identity above there is no `restore_rotates_host_paths` branch to take — that
/// flag scopes the vsock/serial paths, not the tap.
async fn assert_guest_egress_byte<V: vmcell::vmm::Vmm>(vm: &mut MicroVm<V>, phase: &str) {
    let vmid = vm.vmid();
    let netns = vm
        .netns()
        .expect("a privileged VM owns a per-VM netns")
        .name
        .clone();
    let (_host_ip, guest_ip, _cidr) = vmcell::net::ip_math(vmid).expect("ip_math for the vmid");
    let payload = format!("EGRESS-BYTE-{phase}-{vmid}");

    start_guest_echo_server(vm).await;

    // Retried while the guest listener comes up — the failure being guarded is a permanently dead
    // data plane, not a slow start.
    for _ in 0..20 {
        if host_echo_once(&netns, guest_ip, &payload).as_deref() == Some(payload.as_str()) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    let echo_log = vm
        .steward(None)
        .await
        .expect("steward for the echo-server log")
        .exec(ExecRequest::new(vec!["cat".into(), "/tmp/echo.log".into()]))
        .await
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_else(|e| format!("<unreadable: {e}>"));
    panic!(
        "{phase}: the guest never moved a byte out over its tap (expected {payload:?} echoed back \
         from {guest_ip}:{EGRESS_ECHO_PORT} inside {netns}). Links in {netns}:\n{}\nguest \
         /tmp/echo.log:\n{echo_log}",
        links_in_netns(&netns)
    );
}

async fn test_snapshot_restore_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    // Reap any orphaned vmcell-net-* namespaces from a prior aborted run so this
    // privileged-tap test's vmid cannot collide with a leak (no sudo needed; the
    // capability runner holds CAP_SYS_ADMIN + CAP_DAC_OVERRIDE).
    common::clean_vmcell_netns();

    let kernel = common::get_vmlinux();
    let rootfs_image = common::get_rootfs();

    let id = uuid::Uuid::new_v4();
    // OWNED (`common::TempTree`): a guest-RAM snapshot is ~129 MB per backend per run, and this
    // test used to remove it on no path at all — the pre-emptive `remove_dir_all` it did carry
    // could never match, because the name carries a fresh UUID. The guard's `Drop` removes it on
    // the success path AND on the panic path, so a failed live leg cannot leak it either.
    let scratch = common::TempTree::reserve(&format!(
        "vmcell-test-snapshot-restore-{}-{}",
        std::process::id(),
        id
    ));
    let snapshot_dir = scratch.path().to_path_buf();

    // `mut`: block 2 swaps `env.clock` for an injected `FakeClock` before restore so the one-shot
    // post-restore resync is driven by a controlled time (design §18, Delta register: changes from the validated v27 build — delta 1 folded the clock seam
    // into `HostEnv`; `steward()` no longer takes a clock argument).
    let mut env = vmcell::HostEnv::hermetic();

    // Design §17 (Open gaps and future capabilities), crosvm item 7: hold the LOWEST
    // guest CID across block 1, so the source VM draws a higher one. `CidAllocator::allocate` hands
    // the lowest free CID, so releasing this one just before the restore makes the RESTORE's fresh
    // allocation take it — which leaves the source's baked CID both FREE and NOT re-drawn at
    // restore time. That combination is what the reservation leg below needs: free, so the
    // orchestrator's `CidGuard` can actually claim it (a claim the test held instead would be
    // indistinguishable from the guard's own — one allocator, one set entry, no refcount); and not
    // re-drawn, so `baked != fresh` and neither the crosvm `assert_eq` nor the QEMU `assert_ne`
    // below is vacuous.
    let low_cid = env
        .cids
        .allocate()
        .expect("the lowest guest CID is free on a hermetic env");

    // 1. Create a VM and take a snapshot
    {
        // TESTS-LIFECYCLE-6: gate on the effective CAP_NET_ADMIN (the §13 (Cross-cutting invariants)
        // capability runner grants it ambiently), not euid==0.
        if !common::has_cap_net_admin() {
            panic!(
                "SKIP: snapshot/restore needs CAP_NET_ADMIN for privileged tap networking; \
                 not present in the effective capability set"
            );
        }

        let mut cfg = VmConfig::builder(
            kernel.clone(),
            RootfsSource::Erofs {
                image: rootfs_image.clone(),
            },
        )
        .build()
        .unwrap();
        cfg.net = vmcell::config::NetConfig::Privileged {
            egress: vmcell::config::Egress::Open,
        };
        // QEMU snapshot needs the in-kernel vhost-vsock transport (§2.4), selected by
        // snapshotting=true; a no-op flag for CH/FC (they snapshot regardless). Both the
        // snapshot and the restore config carry it so the topology stays congruent.
        cfg.snapshotting = true;

        let mut vm = MicroVm::start(vmm, cfg, &env)
            .await
            .expect("Failed to start VM");

        let steward = match vm.steward(None).await {
            Ok(a) => a,
            Err(e) => {
                let log = std::fs::read_to_string(vm.instance().serial_log()).unwrap_or_default();
                println!("SERIAL LOG:\n{log}");
                panic!("Failed to connect to steward: {e}");
            }
        };

        // Capture pre-snapshot MAC
        let mac_out = steward
            .exec(ExecRequest::new(vec![
                "cat".into(),
                "/sys/class/net/eth0/address".into(),
            ]))
            .await
            .unwrap();
        assert_eq!(
            mac_out.code,
            0,
            "Failed to get MAC address: {:?}",
            String::from_utf8_lossy(&mac_out.stderr)
        );
        let pre_mac = String::from_utf8_lossy(&mac_out.stdout).trim().to_string();

        let time_out = steward
            .exec(ExecRequest::new(vec!["date".into(), "+%s".into()]))
            .await
            .unwrap();
        assert_eq!(
            time_out.code,
            0,
            "Failed to get time: {:?}",
            String::from_utf8_lossy(&time_out.stderr)
        );
        let pre_time: i64 = String::from_utf8_lossy(&time_out.stdout)
            .trim()
            .parse()
            .unwrap();

        // THE POSITIVE CONTROL for the post-restore data-plane leg (docs/78 M1). The same
        // exchange, on the same VM, over the tap the CREATE path plumbed — so a red after restore
        // means "the restore lost the tap", never "the echo tool is missing" or "python3/`ip netns
        // exec` cannot run here". It also leaves the listener running into the snapshot.
        assert_guest_egress_byte(&mut vm, "pre-snapshot").await;

        let original_cid = vm.instance().guest_cid();

        std::fs::create_dir_all(&snapshot_dir).unwrap();
        vm.snapshot(&snapshot_dir)
            .await
            .expect("Failed to create snapshot");

        // TESTS-LIFECYCLE-2: capture a reference CSPRNG sample. `snapshot()`
        // auto-resumes the VM, so its `/dev/urandom` state is exactly what the
        // snapshot froze. A restore that does NOT reseed will resume from this
        // identical frozen state and replay these same bytes; the orchestrator's
        // native post-restore reseed (a 32-byte /dev/hwrng → /dev/urandom copy in
        // the steward's `handle_resync`, §8.2, Restore correctness: a restored VM is not a fresh VM) is what must perturb them.
        // NOTE: the test never issues its own reseed — it only
        // reads /dev/urandom here and after restore and asserts they differ.
        let ref_rng = vm
            .steward(None)
            .await
            .unwrap()
            .exec(ExecRequest::new(vec![
                "head".into(),
                "-c".into(),
                "32".into(),
                "/dev/urandom".into(),
            ]))
            .await
            .unwrap();
        assert_eq!(
            ref_rng.code,
            0,
            "reference /dev/urandom read failed: {:?}",
            String::from_utf8_lossy(&ref_rng.stderr)
        );
        assert_eq!(
            ref_rng.stdout.len(),
            32,
            "expected 32 bytes of reference entropy"
        );
        std::fs::write(snapshot_dir.join("pre_urandom.bin"), &ref_rng.stdout).unwrap();

        let original_vmid = vm.vmid();
        let original_vsock = vm.instance().vsock_path().to_str().unwrap().to_string();
        vm.shutdown().await.expect("Failed to shutdown VM");

        // Write test state so it can be asserted in block 2
        std::fs::write(snapshot_dir.join("pre_mac.txt"), pre_mac).unwrap();
        std::fs::write(snapshot_dir.join("pre_time.txt"), pre_time.to_string()).unwrap();
        std::fs::write(
            snapshot_dir.join("original_cid.txt"),
            original_cid.to_string(),
        )
        .unwrap();
        std::fs::write(snapshot_dir.join("original_vsock.txt"), original_vsock).unwrap();
        std::fs::write(
            snapshot_dir.join("original_vmid.txt"),
            original_vmid.to_string(),
        )
        .unwrap();
    }

    // Sleep to ensure the host clock advances past the guest's suspended clock
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // 2. Restore from snapshot
    {
        let mut cfg = VmConfig::builder(
            kernel.clone(),
            RootfsSource::Erofs {
                image: rootfs_image.clone(),
            },
        )
        .build()
        .unwrap();
        cfg.net = vmcell::config::NetConfig::Privileged {
            egress: vmcell::config::Egress::Open,
        };
        // QEMU snapshot needs the in-kernel vhost-vsock transport (§2.4), selected by
        // snapshotting=true; a no-op flag for CH/FC (they snapshot regardless). Both the
        // snapshot and the restore config carry it so the topology stays congruent.
        cfg.snapshotting = true;

        // M-TEST-RESTORE: hold the ORIGINAL vmid so the allocator is forced to hand
        // the restored VM a DIFFERENT one. MAC (`mac_math(vmid)`) and the vsock path
        // (`vmcell-vm-{pid}-{vmid}`) are pure functions of the vmid; the original VM was
        // already torn down (freeing its vmid), so without this the allocator could
        // re-hand the same vmid and the rotation asserts would pass on a no-op (or
        // fail spuriously ~1/254). Reserving it guarantees new_vmid != original_vmid.
        let original_vmid: u32 = std::fs::read_to_string(snapshot_dir.join("original_vmid.txt"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        env.vmids
            .reserve(original_vmid)
            .expect("original vmid is free after block 1 shutdown; reserving forces a new vmid");

        // Same intent as the vmid reservation — force the restore's fresh `cids.allocate()` to
        // hand a CID DIFFERENT from the source's, so the QEMU rotation assert and the crosvm
        // baked-reuse assert below are both non-vacuous — but taken from the other side, by
        // RELEASING `low_cid` (held since before block 1) instead of by holding the source's.
        // §17 (crosvm item 7): holding `original_cid` across the restore would hide the property
        // this leg now also asserts, namely that the ORCHESTRATOR reserves the baked CID a
        // non-rotating AF_VSOCK backend re-programs. Harmless for CH/FC, whose identity assert is
        // path-based.
        let original_cid: u32 = std::fs::read_to_string(snapshot_dir.join("original_cid.txt"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(
            low_cid < original_cid,
            "the source VM must have drawn a CID above the held low one ({low_cid}), or the \
             restore's fresh allocation could coincide with the baked cid={original_cid}"
        );
        env.cids.release(low_cid);

        // Drive the one-shot post-restore clock resync from an INJECTED FakeClock (≈ pre_time +
        // 1000s), captured on `env.clock` BEFORE restore. The orchestrator fires the resync on the
        // FIRST steward() after restore using the clock captured at construction (design §18, Delta register: changes from the validated v27 build — delta 1
        // — steward() no longer takes a clock arg); a resync that ignored the injected clock would
        // land near real wall-clock time (≈ pre_time). The assertion near the end proves it.
        let pre_time: i64 = std::fs::read_to_string(snapshot_dir.join("pre_time.txt"))
            .unwrap()
            .parse()
            .unwrap();
        let fake_time_secs = (pre_time + 1000) as u64;
        env.clock = std::sync::Arc::new(vmcell::orchestrator::FakeClock {
            time: std::time::UNIX_EPOCH + std::time::Duration::from_secs(fake_time_secs),
        });

        let mut vm = MicroVm::restore(vmm, &snapshot_dir, cfg, &env)
            .await
            .expect("Failed to restore VM");

        let new_vmid = vm.vmid();
        assert_ne!(
            new_vmid, original_vmid,
            "the restored VM must receive a vmid distinct from the held original"
        );

        // This implicitly tests vsock reconnect and CID rotation because the steward
        // client connects using the restored VM's newly allocated CID. It is also
        // the first post-restore steward() call, so it carries the one-shot clock
        // resync — driven here by the injected FakeClock.
        let log_path = vm.instance().serial_log().to_path_buf();
        let steward_res = vm.steward(None).await;
        if steward_res.is_err() {
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            println!("SERIAL LOG ON ERROR:\n{log}");
            panic!(
                "Failed to connect to steward: {:?}",
                steward_res.err().unwrap()
            );
        }
        let result = steward_res
            .unwrap()
            .exec(ExecRequest::new(vec![
                "echo".to_string(),
                "restored".to_string(),
            ]))
            .await
            .unwrap();
        if String::from_utf8_lossy(&result.stdout).trim() != "restored" {
            let log = std::fs::read_to_string(vm.instance().serial_log()).unwrap();
            println!("SERIAL LOG:\n{log}");
            panic!("Exec failed. Outcome: {result:?}");
        }

        // H-VMM-1 ("rotate everything"): the restore/zygote path rotated the vmid,
        // so the guest must have rotated its eth0 IP + default route to the NEW
        // vmid's /30 (via the native resync's SIOCSIFADDR + route ioctls) — the old
        // behavior left the guest on the ORIGINAL vmid's dead /30 with silently dead
        // egress. Read the guest's route table and assert the default route goes via
        // the rotated gateway (host_ip of the new vmid). `/proc/net/route` prints the
        // gateway as a little-endian hex u32. Reddens if the IP/route was not rotated
        // (the guest keeps the original gateway) — i.e. exactly the H-VMM-1 defect.
        let (host_ip, _guest_ip, _cidr) =
            vmcell::net::ip_math(new_vmid).expect("ip_math for the rotated vmid");
        let expected_gw_hex = format!("{:08X}", u32::from_le_bytes(host_ip.octets()));
        let route = vm
            .steward(None)
            .await
            .expect("steward after restore")
            .exec(ExecRequest::new(vec![
                "cat".to_string(),
                "/proc/net/route".to_string(),
            ]))
            .await
            .expect("read /proc/net/route");
        let route_table = String::from_utf8_lossy(&route.stdout);
        let default_via_rotated_gw = route_table.lines().any(|line| {
            let mut f = line.split_whitespace();
            let _iface = f.next();
            let dest = f.next();
            let gw = f.next();
            dest == Some("00000000") && gw.is_some_and(|g| g.eq_ignore_ascii_case(&expected_gw_hex))
        });
        assert!(
            default_via_rotated_gw,
            "post-restore guest default route must go via the rotated gateway {host_ip} \
             (hex {expected_gw_hex}); guest /proc/net/route:\n{route_table}"
        );

        // …and the route table is guest-side TEXT: it is identical whether or not the host end of
        // the link is plumbed. This is the DATA PLANE (docs/78 M1) — a byte that actually left the
        // guest through eth0 and came back — with the pre-snapshot exchange as its control.
        assert_guest_egress_byte(&mut vm, "post-restore").await;

        let new_cid = vm.instance().guest_cid();
        assert!(
            (vmcell::vmm::MIN_GUEST_CID..=vmcell::vmm::MAX_GUEST_CID).contains(&new_cid),
            "restored VM must have a valid guest CID, got {new_cid}"
        );

        // Design §17 (Open gaps and future capabilities), crosvm item 7: the CID a restored VM
        // ANSWERS ON is out of the allocatable pool for its whole lifetime — whichever CID that is.
        // On a rotating backend that is the fresh allocation its own `CidGuard` holds; on a
        // non-rotating AF_VSOCK backend
        // (crosvm bakes the CID into the snapshot and refuses a rotated `--vsock cid=`) it is the
        // BAKED one, which no allocator held before this fix. crosvm's vsock is in-kernel, so the
        // CID is a HOST-GLOBAL identity, not a per-scratch-dir path: a later VM drawing it collides
        // with this live one. The crosvm branch below proves this is not vacuously the VM's own.
        assert!(
            env.cids.reserve(new_cid).is_err(),
            "the guest CID {new_cid} the restored VM answers on must not be reallocatable while \
             that VM is live"
        );

        let original_vsock =
            std::fs::read_to_string(snapshot_dir.join("original_vsock.txt")).unwrap();
        let new_vsock = vm.instance().vsock_path().to_str().unwrap();
        // The host-side identity contract is per-backend, declared by
        // `restore_rotates_host_paths` (the capability descriptor is the contract).
        // What "identity" means is per-transport, so each branch asserts the one that
        // is real for its backend — the opposite outcome reddens it.
        if vmcell::vmm::Vmm::capabilities(vmm).restore_rotates_host_paths {
            match vm.instance().vsock_endpoint() {
                // CH: the restore config-rewrite moves the AF_UNIX vsock socket into the
                // NEW VM's scratch dir, so the path rotates and embeds the new vmid.
                vmcell::vmm::VsockEndpoint::Unix { .. } => {
                    assert_ne!(
                        original_vsock, new_vsock,
                        "Vsock path should be rotated after restore"
                    );
                    // M-TEST-RESTORE: assert the REAL socket path embeds the rotated
                    // vmid, not merely that it differs — proving the path reflects the
                    // new identity rather than a coincidental string difference.
                    // Recomputed through `vmcell::naming` (law F2), never a test-local
                    // `format!`: a hand-rolled copy of the scratch-dir spelling drifts
                    // silently when the composer changes and the assert goes vacuous
                    // (docs/78 §6, `test-local-scratch-name-format`).
                    let expected_scratch = vmcell::naming::scratch_dir_name(
                        vmcell::naming::DEFAULT_RESOURCE_PREFIX,
                        std::process::id(),
                        new_vmid,
                    );
                    assert!(
                        new_vsock.contains(&expected_scratch),
                        "restored vsock path {new_vsock} must embed the rotated vmid {new_vmid} \
                         (expected scratch dir {expected_scratch})"
                    );
                }
                // QEMU in-kernel vhost-vsock: identity is the guest CID (its
                // `vsock_path` is a vestigial per-scratch-dir file). Restore programs a
                // FRESH `res.guest_cid`, which is `low_cid` — released just before the
                // restore and the lowest free CID — while the source baked a HIGHER one,
                // so the two differ by construction and a restore that reused the baked
                // CID (the inverse of the rotation change, §2.4) reddens the `assert_ne`.
                vmcell::vmm::VsockEndpoint::Vsock { cid, .. } => {
                    assert_ne!(
                        cid, original_cid,
                        "QEMU restore must rotate the guest CID off the source's baked \
                         cid={original_cid} (§2.4), got {cid}"
                    );
                }
            }
        } else {
            // A non-rotating backend re-binds the snapshot's baked host-side vsock identity verbatim;
            // what "identity" is depends on the transport (symmetric to the rotating branch above).
            match vm.instance().vsock_endpoint() {
                // FC: verbatim rebind of the snapshot's baked AF_UNIX vsock path
                // (`PUT /snapshot/load` re-binds it verbatim; no load-time override exists
                // in v1.16). The steward reconnect above already proved the rebound transport
                // functional; a rotated path here would mean FC diverged from its capability.
                vmcell::vmm::VsockEndpoint::Unix { .. } => {
                    assert_eq!(
                        new_vsock,
                        original_vsock.as_str(),
                        "an AF_UNIX non-rotating backend must re-bind the \
                         snapshot's baked vsock path verbatim"
                    );
                }
                // crosvm in-kernel vhost-vsock: identity is the guest CID, but unlike QEMU crosvm
                // BAKES the CID into the snapshot and rejects a rotated `--vsock cid=` on restore
                // ("Virtio vsock incorrect cid for restore"), so `restore()` reuses the baked CID
                // verbatim (`restore_rotates_host_paths: false`). The restore's own fresh
                // allocation is `low_cid`, so a backend that (wrongly) rotated would hand a
                // DIFFERENT one — this `assert_eq` reddens on that inverse. The reconnect above
                // already proved the rebound CID live.
                vmcell::vmm::VsockEndpoint::Vsock { cid, .. } => {
                    assert_eq!(
                        cid, original_cid,
                        "a non-rotating AF_VSOCK backend (crosvm) must reuse the snapshot's baked \
                         cid={original_cid} verbatim, got {cid}"
                    );
                    // §17 (crosvm item 7), the non-vacuity control for the reservation assert
                    // above: the CID this VM answers on is NOT the one the orchestrator allocated
                    // for it. The fresh allocation is `low_cid`, and it is held too — so TWO distinct
                    // CIDs are out of the pool, which only the orchestrator's baked-CID adoption
                    // (`CidGuard::adopt_baked_cid`) explains. Red on the inverse: drop that
                    // adoption and the baked CID is reallocatable while this VM is live.
                    assert_ne!(
                        cid, low_cid,
                        "the baked CID must differ from the restore's own fresh allocation, or \
                         the reservation assert above is the VM's own guard"
                    );
                    assert!(
                        env.cids.reserve(low_cid).is_err(),
                        "the restored VM's own freshly allocated CID {low_cid} is held too, so \
                         the held baked cid={original_cid} is the ADOPTED one"
                    );
                }
            }
        }

        let pre_mac = std::fs::read_to_string(snapshot_dir.join("pre_mac.txt")).unwrap();
        let mac_out = vm
            .steward(None)
            .await
            .unwrap()
            .exec(ExecRequest::new(vec![
                "cat".into(),
                "/sys/class/net/eth0/address".into(),
            ]))
            .await
            .unwrap();
        assert_eq!(
            mac_out.code,
            0,
            "Failed to get post-snapshot MAC address: {:?}",
            String::from_utf8_lossy(&mac_out.stderr)
        );
        let post_mac = String::from_utf8_lossy(&mac_out.stdout).trim().to_string();
        assert!(!pre_mac.is_empty(), "MAC address should not be empty");
        // M-TEST-RESTORE: assert the IN-GUEST MAC equals mac_math(new_vmid) — the
        // positive identity proving the rotation set the correct new value. If the
        // rotation did not run, the guest keeps mac_math(original_vmid), which differs
        // from mac_math(new_vmid) (new != original, enforced above), so this goes red.
        // `assert_ne!(pre, post)` alone can pass on a no-op when a re-handed vmid
        // happens to yield an identical MAC.
        let expected_mac = vmcell::net::mac_math(new_vmid).expect("mac_math(new_vmid)");
        assert_eq!(
            post_mac, expected_mac,
            "post-restore guest MAC must equal mac_math(new_vmid={new_vmid})"
        );
        assert_ne!(
            pre_mac, post_mac,
            "MAC address should be rotated after restore"
        );

        // TESTS-LIFECYCLE-1: the resync on the first post-restore steward() call set
        // the guest clock from the injected FakeClock (≈ pre_time + 1000s), NOT
        // from real wall-clock time. `restored` is already false, so this read does
        // not re-trigger a resync.
        let time_out = vm
            .steward(None)
            .await
            .unwrap()
            .exec(ExecRequest::new(vec!["date".into(), "+%s".into()]))
            .await
            .unwrap();
        assert_eq!(
            time_out.code,
            0,
            "Failed to get post-snapshot time: {:?}",
            String::from_utf8_lossy(&time_out.stderr)
        );
        let post_time: i64 = String::from_utf8_lossy(&time_out.stdout)
            .trim()
            .parse()
            .unwrap();
        // Equals the injected clock value, allowing a few seconds of guest ticking
        // between the resync and this read. A resync that ignored the injected
        // Clock (e.g. used RealClock) would land ≈1000s lower, near `pre_time`, and
        // fail the lower bound.
        assert!(
            post_time >= fake_time_secs as i64 && post_time < fake_time_secs as i64 + 30,
            "clock resync must set the guest clock to the INJECTED FakeClock time (≈{fake_time_secs}), got {post_time}; \
             a resync that ignored the injected Clock would land near real wall-clock time (≈{pre_time})"
        );

        // TESTS-LIFECYCLE-2 (reseed isolation): the typed `restore_reseed_applied()`
        // is the failing-capable control — it directly asserts the orchestrator's
        // post-restore reseed command ran and returned exit 0. It is set on the first
        // post-restore steward() call (already made above). The byte-diff below is
        // corroboration only: it fails on gross replay, NOT on a skipped reseed,
        // because the reference and post-restore /dev/urandom reads occur at different
        // CRNG stream offsets and differ even without any reseed (M-TEST-1). This
        // typed assert is the load-bearing red-on-inverse guard: a silent
        // best-effort failure yields Some(false)/None and flips it red.
        assert_eq!(
            vm.restore_reseed_applied(),
            Some(true),
            "the post-restore CSPRNG reseed must have APPLIED (exit 0); a silent \
             best-effort failure would leave the restored VM replaying predictable RNG state"
        );

        // Corroboration (NOT load-bearing): verify the frozen RNG state was
        // perturbed. The two reads occur at different CRNG stream offsets, so they
        // differ by construction even without a reseed — this catches only gross
        // replay, not a skipped reseed. The true guard is `restore_reseed_applied()`
        // above; the test issues NO reseed of its own.
        let pre_urandom = std::fs::read(snapshot_dir.join("pre_urandom.bin")).unwrap();
        let post_rng = vm
            .steward(None)
            .await
            .unwrap()
            .exec(ExecRequest::new(vec![
                "head".into(),
                "-c".into(),
                "32".into(),
                "/dev/urandom".into(),
            ]))
            .await
            .unwrap();
        assert_eq!(
            post_rng.code,
            0,
            "post-restore /dev/urandom read failed: {:?}",
            String::from_utf8_lossy(&post_rng.stderr)
        );
        assert_eq!(post_rng.stdout.len(), 32, "expected 32 bytes of entropy");
        assert_eq!(
            pre_urandom.len(),
            32,
            "reference entropy sample missing/short"
        );
        assert_ne!(
            pre_urandom, post_rng.stdout,
            "post-restore CSPRNG output must differ from the snapshot-frozen reference: the \
             orchestrator's restore-path reseed (head -c 32 /dev/hwrng > /dev/urandom) must \
             perturb it. Identical bytes mean the reseed did not run and the restored VM is \
             replaying predictable RNG state."
        );

        vm.shutdown().await.expect("Failed to shutdown restored VM");

        // §17 (crosvm item 7): the reservation is a lease, not a leak — teardown returns the CID
        // the VM answered on. Red on the inverse: a `CidGuard::drop` that releases only its own
        // `cid` leaves the adopted baked CID permanently out of the pool.
        assert_eq!(
            env.cids
                .reserve(new_cid)
                .expect("the CID the restored VM answered on is released on teardown"),
            new_cid
        );
    }
}

/// The argv of the single live process whose command line names something inside `scratch` — the
/// VMM this VM is actually running on, read straight out of the host process table.
///
/// Selected by the **per-VM scratch directory** (`--api-socket <scratch>/api.sock`), which is
/// independent of the `--restore` argument the caller then asserts on: selecting the process by
/// the very token under test would make the assertion vacuous. The restore source lives in a
/// different directory (the per-leg snapshot copy), so it cannot satisfy this predicate.
///
/// Loud on anything but exactly one match: zero means the scratch-dir spelling moved and the scan
/// is looking at nothing (the `gate misconfigured` shape, never a silent pass), more than one
/// means a leaked VMM from an earlier leg is still alive and the argv read would be ambiguous.
fn vmm_argv_in_scratch(scratch: &std::path::Path) -> Vec<String> {
    let prefix = format!("{}/", scratch.display());
    let mut found: Vec<Vec<String>> = Vec::new();
    for entry in std::fs::read_dir("/proc").expect("the host /proc must be readable") {
        let Ok(entry) = entry else { continue };
        if entry
            .file_name()
            .to_str()
            .is_none_or(|n| n.parse::<u32>().is_err())
        {
            continue;
        }
        // A pid can exit between the readdir and the read; that is not a failure.
        let Ok(raw) = std::fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let argv: Vec<String> = raw
            .split(|b| *b == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect();
        if argv.iter().any(|arg| arg.starts_with(&prefix)) {
            found.push(argv);
        }
    }
    assert_eq!(
        found.len(),
        1,
        "expected exactly one live VMM process naming the scratch dir {}, found {}: {found:#?}",
        scratch.display(),
        found.len()
    );
    found.pop().expect("length checked above")
}

/// The value of the live VMM's `--restore` argument, or a loud panic naming the whole argv.
fn restore_arg_of(argv: &[String]) -> String {
    let at = argv
        .iter()
        .position(|arg| arg == "--restore")
        .unwrap_or_else(|| panic!("the restored VMM's argv carries no `--restore`: {argv:#?}"));
    argv.get(at + 1)
        .unwrap_or_else(|| panic!("`--restore` is the last argv entry: {argv:#?}"))
        .clone()
}

/// D1 (docs/todo.md, "Shipped config knobs still never applied in a live boot"): both **non-default**
/// [`vmcell::config::RestoreMode`]s, performed as real restores.
///
/// Until this leg, `Eager` and `Lazy` were shipped, documented and applied in no integration test at
/// all — the only caller outside the crate was `vmcell-bench`, a tracked metric rather than a gate.
/// A knob nobody boots is a claim nobody makes (AGENTS.md rule 4).
///
/// **Cloud-Hypervisor-only, and that is the honest scope.** The `prefault=on|off` modifier is a CH
/// `--restore` argument; no other backend has an equivalent selector. The other three are honest
/// about it rather than silent: `Lazy` is a typed `Unsupported { feature: "lazy_restore" }` on
/// Firecracker, QEMU and crosvm through the one shared
/// `vmm::reject_unadvertised_capabilities`, gated by a unit test in each backend crate, and `Eager`
/// is what those three *do* — Firecracker's `backend_type: "File"`, QEMU's and crosvm's eager
/// loads — so requesting it is honored, not dropped. Restoring three more backends here to watch
/// `Eager` change nothing would cost three snapshot+restore cycles for no assertion.
///
/// **What this leg proves.** For each non-default mode: the restore really happens under that mode
/// (the argument reaches the argv of the live `cloud-hypervisor` process, read from `/proc`), and
/// the guest that comes back **moves a byte** — the same host→guest→host exchange over the VM's own
/// tap that `snapshot_restore` asserts post-restore, with the identical pre-snapshot exchange as
/// its positive control.
///
/// **What it does NOT prove.** Nothing here observes the *paging* behavior `prefault` selects: a
/// leg that showed the VM booting under the flag would say the same thing if CH ignored the token.
/// The honest split is that the composed argument is pinned exactly (here on a live process, and
/// KVM-free in `cloud_hypervisor.rs`'s `every_restore_mode_reaches_the_composed_argv_as_its_prefault_modifier`),
/// and that CH honors `prefault` is CH's contract, measured — not asserted — by `bench-vm`'s
/// `--restore-mode` sweep (docs/benchmark-results.md, ≈1.5× faster resume under lazy).
///
/// **Exactly one variable.** Both legs restore from a private copy of the SAME snapshot, through
/// the same config builder, differing only in `restore_mode` — the tuning battery's shape. The
/// copies go through `env.overlay` (invariant S4, the one CoW seam) rather than a second
/// hand-rolled copier, and each leg's copy is dropped before the next is minted, so the peak extra
/// disk is one snapshot, not two. A restore rewrites its snapshot's `config.json` **in place**
/// (§8.2), which is why each leg gets its own copy instead of re-restoring the master twice.
/// [`MicroVm::restore_cow`] would mint that copy for us, but it puts it at an internal path inside
/// the VM's own scratch dir — so the exact-equality assertion on the `--restore` value below would
/// have to hard-code that internal spelling. The copy is made here instead, through the same seam,
/// so the source path the assertion recomputes is one this test owns.
///
/// Red on the inverse: hand `spawn_ch` a hardcoded `RestoreMode::Default` instead of
/// `cfg.restore_mode` — the seam the KVM-free pin structurally cannot cross, since it composes the
/// `--restore` value itself — and both legs redden on the missing modifier. Swap CH's
/// `prefault=on`/`prefault=off` arms and both redden naming the other token. Break the restored
/// data plane (drop the `net[].tap` rewrite of §8.2) and `assert_guest_egress_byte` reddens.
#[cfg(feature = "cloud-hypervisor")]
#[tokio::test]
#[ignore = "needs KVM"]
async fn non_default_restore_modes_ship_their_prefault_argument_and_restore_a_live_guest() {
    use vmcell::config::RestoreMode;
    use vmcell::vmm::cloud_hypervisor::CloudHypervisor;

    let vmm = CloudHypervisor::new(common::ch_bin());
    let caps = vmcell::vmm::Vmm::capabilities(&vmm);
    require_cap!(caps, snapshot_restore, vmm);
    // `Lazy` is refused pre-spawn by the shared `reject_unadvertised_capabilities` unless the
    // backend advertises it, so the Lazy leg below is only reachable on a backend that does.
    require_cap!(caps, lazy_restore, vmm);

    common::clean_vmcell_netns();
    if !common::has_cap_net_admin() {
        panic!(
            "SKIP: the restore-mode legs need CAP_NET_ADMIN for privileged tap networking; \
             not present in the effective capability set"
        );
    }

    let kernel = common::get_vmlinux();
    let rootfs_image = common::get_rootfs();

    // OWNED: a CH guest-RAM snapshot is ~129 MB; the guard removes it on the success path AND on
    // the panic path, so a red leg cannot leak it into the host tmpfs.
    let scratch = common::TempTree::create(&format!(
        "vmcell-test-restore-mode-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let master_snapshot = scratch.join("snapshot");

    let env = vmcell::HostEnv::hermetic();

    // The ONE config the whole test varies: everything but `restore_mode` is fixed here.
    let mk_cfg = |mode: RestoreMode| {
        VmConfig::builder(
            kernel.clone(),
            RootfsSource::Erofs {
                image: rootfs_image.clone(),
            },
        )
        .net(vmcell::config::NetConfig::Privileged {
            egress: vmcell::config::Egress::Open,
        })
        .snapshotting(true)
        .restore_mode(mode)
        .build()
        .expect("build the restore-mode config")
    };

    // Take the master snapshot from a VM booted at the DEFAULT mode: `restore_mode` is consumed by
    // `restore()`, never by `create()`, so the source VM must not vary with the legs.
    {
        let mut vm = MicroVm::start(&vmm, mk_cfg(RestoreMode::Default), &env)
            .await
            .expect("start the source VM");
        vm.steward(None).await.expect("steward on the source VM");
        // THE POSITIVE CONTROL for both legs' data-plane assertion, on the same VM over the tap
        // the create path plumbed — so a red after a restore means "this mode's restore lost the
        // data plane", never "python3 / the echo applet cannot run on this host". It also leaves
        // the listener running into the snapshot.
        assert_guest_egress_byte(&mut vm, "pre-snapshot").await;
        std::fs::create_dir_all(&master_snapshot).expect("create the snapshot dir");
        vm.snapshot(&master_snapshot).await.expect("snapshot");
        vm.shutdown().await.expect("shut down the source VM");
    }

    for (mode, want_modifier, other_modifier) in [
        (RestoreMode::Eager, ",prefault=on", ",prefault=off"),
        (RestoreMode::Lazy, ",prefault=off", ",prefault=on"),
    ] {
        // A private copy per leg, through the one CoW seam (S4). Dropped at the end of the
        // iteration, so at most one copy exists at a time.
        let leg = common::TempTree::reserve(&format!(
            "vmcell-test-restore-mode-leg-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        env.overlay
            .clone_tree(&master_snapshot, leg.path())
            .expect("clone the master snapshot for this leg");

        let mut vm = MicroVm::restore(&vmm, leg.path(), mk_cfg(mode), &env)
            .await
            .unwrap_or_else(|e| panic!("restore under {mode:?} failed: {e}"));

        // The SHIPPED argument, on the live VMM process — the half the KVM-free pin cannot reach,
        // because it composes the `--restore` value itself instead of reading `cfg.restore_mode`
        // through `spawn_ch`.
        let scratch_dir = vm
            .instance()
            .vsock_path()
            .parent()
            .expect("the per-VM vsock socket lives inside the VM's scratch dir")
            .to_path_buf();
        let argv = vmm_argv_in_scratch(&scratch_dir);
        let restore_arg = restore_arg_of(&argv);
        assert_eq!(
            restore_arg,
            format!("source_url=file://{}{want_modifier}", leg.path().display()),
            "the live cloud-hypervisor restored under {mode:?} must carry that mode's modifier; \
             full argv: {argv:#?}"
        );
        assert!(
            !restore_arg.contains(other_modifier),
            "the {mode:?} leg must not carry {other_modifier:?}: {restore_arg}"
        );

        // THE DATA PLANE: a byte that actually left the restored guest through eth0 and came back,
        // the same assertion `snapshot_restore` makes post-restore — not vsock liveness and not an
        // exit code standing in for it.
        assert_guest_egress_byte(&mut vm, &format!("post-restore-{mode:?}")).await;

        vm.shutdown()
            .await
            .unwrap_or_else(|e| panic!("shut down the {mode:?}-restored VM: {e}"));

        // Residue, both halves: the copy demonstrably EXISTED (so the CoW clone above was not a
        // no-op the restore silently tolerated), and it is GONE once its owner drops — here on the
        // success path and equally on the panic path of every assertion above, before the next leg
        // mints one. Skipped under the documented post-mortem retention opt-in, whose whole
        // purpose is to leave the tree behind.
        assert!(
            leg.path().join("config.json").exists(),
            "the leg's snapshot copy must have existed before its owner drops it"
        );
        let leg_path = leg.path().to_path_buf();
        let retained = std::env::var_os(common::KEEP_TEMP_ENV).is_some();
        drop(leg);
        assert!(
            retained || !leg_path.exists(),
            "the leg's snapshot copy must be gone once its owner drops: {}",
            leg_path.display()
        );
    }
}

/// The KVM-free half of the leg above: the `/proc` scan and the argv reader it depends on, driven
/// against real processes this test spawns.
///
/// Why it exists: the live leg's whole argv assertion rests on `vmm_argv_in_scratch` finding the
/// right process, and that helper needs no VMM to be wrong. A scan that matched nothing, or that
/// matched a *sibling* directory sharing the scratch dir's name as a prefix
/// (`…-vm-1-7` vs `…-vm-1-70`), would take the live leg down with it — or, worse, hand it the wrong
/// process's argv. So it runs everywhere `just test-unit` runs, not only on a KVM host.
///
/// Red on the inverse: drop the trailing `/` from `vmm_argv_in_scratch`'s prefix and the decoy
/// process matches too, so the exactly-one assertion inside the helper reddens; make the scan
/// return every process (or none) and the equality below reddens.
#[test]
fn the_scratch_dir_process_scan_finds_exactly_the_right_argv() {
    let scratch = common::TempTree::create(&format!(
        "vmcell-test-procscan-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let wanted = scratch.join("api.sock");
    // A DECOY whose path shares the scratch dir's name as a string prefix but is a different
    // directory — the boundary a naive `starts_with` on the bare path would cross.
    let decoy_dir = format!("{}-sibling", scratch.path().display());
    let decoy = format!("{decoy_dir}/api.sock");

    // `; true` keeps the shell alive with its ORIGINAL argv: a bare `sh -c 'sleep 30'` execs
    // `sleep` and the path (passed as `$0`) vanishes from the process table with it.
    let spawn = |marker: &str| {
        std::process::Command::new("sh")
            .args(["-c", "sleep 30; true", marker])
            .spawn()
            .expect("spawn the scan fixture")
    };
    let mut target = spawn(&wanted.display().to_string());
    let mut decoy_proc = spawn(&decoy);
    // Both children are in the table before the scan reads it.
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Scan first, kill second: the children must be reaped even when the assertions below panic.
    let scanned = std::panic::catch_unwind(|| vmm_argv_in_scratch(scratch.path()));
    for child in [&mut target, &mut decoy_proc] {
        let _ = child.kill();
        let _ = child.wait();
    }
    let argv = scanned.expect("the scan must find exactly one process under the scratch dir");

    assert_eq!(
        argv,
        vec![
            "sh".to_string(),
            "-c".to_string(),
            "sleep 30; true".to_string(),
            wanted.display().to_string(),
        ],
        "the scan must return the target's whole argv, not the decoy's"
    );

    // The argv reader: the value is whatever follows `--restore`, even when an earlier argument
    // merely looks like one.
    let argv = [
        "cloud-hypervisor",
        "--seccomp",
        "true",
        "--restore",
        "source_url=file:///snap,prefault=off",
        "--api-socket",
        "/x/api.sock",
    ]
    .map(String::from);
    assert_eq!(
        restore_arg_of(&argv),
        "source_url=file:///snap,prefault=off"
    );
}
