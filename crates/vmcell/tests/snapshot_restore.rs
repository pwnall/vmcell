use vmcell::agent::protocol::ExecRequest;
use vmcell::config::{RootfsSource, VmConfig};
use vmcell::orchestrator::MicroVm;
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
        .agent(None)
        .await
        .expect("agent for the echo server")
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
/// file could see it: the `/proc/net/route` assertion above reads guest-side TEXT and the agent
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
        .agent(None)
        .await
        .expect("agent for the echo-server log")
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
    // into `HostEnv`; `agent()` no longer takes a clock argument).
    let mut env = vmcell::HostEnv::hermetic();

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

        let agent = match vm.agent(None).await {
            Ok(a) => a,
            Err(e) => {
                let log = std::fs::read_to_string(vm.instance().serial_log()).unwrap_or_default();
                println!("SERIAL LOG:\n{log}");
                panic!("Failed to connect to agent: {e}");
            }
        };

        // Capture pre-snapshot MAC
        let mac_out = agent
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

        let time_out = agent
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
        // the agent's `handle_resync`, §8.2, Restore correctness: a restored VM is not a fresh VM) is what must perturb them.
        // NOTE: the test never issues its own reseed — it only
        // reads /dev/urandom here and after restore and asserts they differ.
        let ref_rng = vm
            .agent(None)
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

        // Symmetric to the vmid reservation: hold the source's (now-freed) guest CID so
        // the restore path's fresh `cids.allocate()` is forced to hand a DIFFERENT one.
        // This makes the QEMU CID-rotation assertion below non-vacuous — without it the
        // freed CID could be re-handed and `new_cid` could coincidentally equal
        // `original_cid`, so a `restore()` that reused the baked CID would slip the
        // assert. Harmless for CH/FC, whose identity assert is path-based.
        let original_cid: u32 = std::fs::read_to_string(snapshot_dir.join("original_cid.txt"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        env.cids
            .reserve(original_cid)
            .expect("original CID is free after block 1 shutdown; reserving forces a new CID");

        // Drive the one-shot post-restore clock resync from an INJECTED FakeClock (≈ pre_time +
        // 1000s), captured on `env.clock` BEFORE restore. The orchestrator fires the resync on the
        // FIRST agent() after restore using the clock captured at construction (design §18, Delta register: changes from the validated v27 build — delta 1
        // — agent() no longer takes a clock arg); a resync that ignored the injected clock would
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

        // This implicitly tests vsock reconnect and CID rotation because the agent
        // client connects using the restored VM's newly allocated CID. It is also
        // the first post-restore agent() call, so it carries the one-shot clock
        // resync — driven here by the injected FakeClock.
        let log_path = vm.instance().serial_log().to_path_buf();
        let agent_res = vm.agent(None).await;
        if agent_res.is_err() {
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            println!("SERIAL LOG ON ERROR:\n{log}");
            panic!("Failed to connect to agent: {:?}", agent_res.err().unwrap());
        }
        let result = agent_res
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
            .agent(None)
            .await
            .expect("agent after restore")
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
            (3..=254).contains(&new_cid),
            "restored VM must have a valid guest CID, got {new_cid}"
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
                // FRESH `res.guest_cid`; block 2 reserved the source's CID, so the fresh
                // one MUST differ — a restore that reused the baked CID (the inverse of
                // the rotation change, §2.4) reddens the `assert_ne`.
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
                // in v1.16). The agent reconnect above already proved the rebound transport
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
                // verbatim (`restore_rotates_host_paths: false`). Block 2 reserved the source's CID, so
                // a backend that (wrongly) rotated it would hand a DIFFERENT one — this `assert_eq`
                // reddens on that inverse. The reconnect above already proved the rebound CID live.
                vmcell::vmm::VsockEndpoint::Vsock { cid, .. } => {
                    assert_eq!(
                        cid, original_cid,
                        "a non-rotating AF_VSOCK backend (crosvm) must reuse the snapshot's baked \
                         cid={original_cid} verbatim, got {cid}"
                    );
                }
            }
        }

        let pre_mac = std::fs::read_to_string(snapshot_dir.join("pre_mac.txt")).unwrap();
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

        // TESTS-LIFECYCLE-1: the resync on the first post-restore agent() call set
        // the guest clock from the injected FakeClock (≈ pre_time + 1000s), NOT
        // from real wall-clock time. `restored` is already false, so this read does
        // not re-trigger a resync.
        let time_out = vm
            .agent(None)
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
        // post-restore agent() call (already made above). The byte-diff below is
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
            .agent(None)
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
    }
}
