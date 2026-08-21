//! The v30 §18 delta 8 **live** battery for VM-to-VM segments (§6.5, VM-to-VM segments).
//!
//! Everything here touches the kernel — bridges, enslaved taps, namespaces, `netem` qdiscs — which
//! is exactly what the recording `FakeNetlink`/`FakeVmm` doubles are blind to. The KVM-free legs
//! (`segment_ip_math`, the naming lockstep, the slot free-list, the allocator race, every `build()`
//! rejection, and the member-teardown ordering) live beside their code as unit tests; the design
//! marks *these* legs non-optional.
//!
//! The in-guest data plane is driven with the `echo-server` guest-tools applet (`--tcp`, delta 7)
//! as the listener and bash's `/dev/tcp` net-redirection as the client, so no new guest code is
//! needed for either side (law C6 stays untouched).

use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use vmcell::MicroVm;
use vmcell::config::{Egress, NetConfig, RootfsSource, VmConfig};
use vmcell::net::{Impairment, NetSegment};
use vmcell::steward::protocol::ExecRequest;
use vmcell::vmm::Vmm;

mod common;

/// The in-guest TCP port every member's `echo-server` listens on.
const ECHO_PORT: u16 = 7100;

/// A bounded budget for one guest-to-guest exchange.
const EXCHANGE_TIMEOUT_SECS: u32 = 8;

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

/// Panics with the SKIP-is-not-a-PASS message unless the process holds `CAP_NET_ADMIN`.
///
/// Segments are privileged-capability-class; the blessed capability runner is what makes this
/// suite runnable unprivileged, so an absent capability is a real failure, not a skip.
fn require_privileged_net() {
    if !common::has_cap_net_admin() {
        panic!(
            "SKIP: vm-to-vm segments need CAP_NET_ADMIN for the bridge + enslaved taps; not \
             present in the effective capability set (run under the blessed runner, `just bless`)"
        );
    }
}

/// A config for a segment member of `segment`.
fn member_cfg(segment: &NetSegment) -> VmConfig {
    VmConfig::builder(
        common::get_vmlinux(),
        RootfsSource::Erofs {
            image: common::get_rootfs(),
        },
    )
    .net(NetConfig::Segment {
        segment: segment.clone(),
    })
    .build()
    .expect("a segment member config must build")
}

/// A config for an ordinary privileged (off-segment) VM — the negative control's dialer.
fn off_segment_cfg() -> VmConfig {
    VmConfig::builder(
        common::get_vmlinux(),
        RootfsSource::Erofs {
            image: common::get_rootfs(),
        },
    )
    .net(NetConfig::Privileged {
        egress: Egress::Open,
    })
    .build()
    .expect("an off-segment config must build")
}

/// The `HostEnv` every live leg here uses.
///
/// Hermetic except for the **shared** segment-id allocator: with the hermetic one, `/tmp/vmcell-segid`
/// is never consulted, so the cross-process claim law this delta extracted was exercised only against
/// unit-test temp dirs — and two vmcell processes on one host could name the same `<prefix>-seg-<id>`
/// (before the search start was clock-seeded, they *always* did). Pointing the battery at
/// `shared()` makes the real rendezvous arbitrate, and the residue leg asserts its lock file's
/// lifecycle.
fn segment_env() -> vmcell::HostEnv {
    let mut env = vmcell::HostEnv::hermetic();
    env.segids = vmcell::orchestrator::SegmentIdAllocator::shared();
    env
}

/// The cross-process lock file a `shared()` segment-id claim leaves on the host.
fn segid_lock_path(segid: u32) -> std::path::PathBuf {
    std::path::Path::new("/tmp/vmcell-segid").join(format!("{segid}.lock"))
}

/// Leaves `echo-server --tcp` listening on [`ECHO_PORT`] inside `vm`.
///
/// Used for members *and* for the off-segment control, so the negative leg's dialer has a positive
/// control it passes itself.
async fn start_echo_server<V: Vmm>(vm: &mut MicroVm<V>) {
    let steward = vm.steward(None).await.expect("steward for the echo server");
    let started = steward
        .exec(ExecRequest::new(vec![
            "sh".into(),
            "-c".into(),
            format!(
                "/vmcell-tools/echo-server --tcp 0.0.0.0:{ECHO_PORT} </dev/null \
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

/// Boots a member of `segment` and leaves `echo-server --tcp` listening on [`ECHO_PORT`].
async fn start_member<V: Vmm>(vmm: &V, segment: &NetSegment, env: &vmcell::HostEnv) -> MicroVm<V> {
    let mut vm = MicroVm::start(vmm, member_cfg(segment), env)
        .await
        .expect("a segment member must boot");

    // The member has NO per-VM netns — its tap lives in the segment's.
    assert!(
        vm.netns().is_none(),
        "a segment member must not own a per-VM netns"
    );
    let membership = vm
        .segment_membership()
        .expect("a member must carry its membership")
        .clone();
    assert_eq!(membership.netns, segment.netns_name());

    let steward = vm.steward(None).await.expect("member steward");
    // Prove the guest actually took the address the `ip=` token carried, from the shared math —
    // not a proxy signal like "the exec succeeded".
    let (gateway, guest_ip, _) = membership.addresses().expect("segment addresses");
    let addrs = steward
        .exec(ExecRequest::new(vec![
            "/vmcell-tools/ip".into(),
            "addr".into(),
            "show".into(),
            "eth0".into(),
        ]))
        .await
        .expect("ip addr show");
    let addrs_out = String::from_utf8_lossy(&addrs.stdout).into_owned();
    assert!(
        addrs_out.contains(&guest_ip.to_string()),
        "the guest must carry its segment address {guest_ip} (gateway {gateway}): {addrs_out}"
    );

    start_echo_server(&mut vm).await;
    vm
}

/// The bash `/dev/tcp` one-liner that connects to `addr:port`, sends `payload`, and prints exactly
/// `payload.len()` echoed bytes back.
///
/// bash's net-redirection is the client side, so the segment data plane needs **zero** new guest
/// code. `timeout` bounds it so a partitioned link fails fast instead of hanging the suite.
fn echo_probe_cmd(addr: &std::net::Ipv4Addr, port: u16, payload: &str) -> Vec<String> {
    vec![
        "timeout".into(),
        EXCHANGE_TIMEOUT_SECS.to_string(),
        "bash".into(),
        "-c".into(),
        format!(
            "exec 3<>/dev/tcp/{addr}/{port} && printf '{payload}' >&3 && head -c {} <&3",
            payload.len()
        ),
    ]
}

/// Runs [`echo_probe_cmd`] in `vm` and returns `(exit_code, stdout)`.
async fn echo_probe<V: Vmm>(
    vm: &mut MicroVm<V>,
    addr: &std::net::Ipv4Addr,
    port: u16,
    payload: &str,
) -> (i32, String) {
    let steward = vm.steward(None).await.expect("steward for the echo probe");
    let out = steward
        .exec(ExecRequest::new(echo_probe_cmd(addr, port, payload)))
        .await
        .expect("the echo probe must run");
    (out.code, String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Retries [`echo_probe`] until it echoes `payload`, so the host never races the in-guest listener
/// coming up. Only the *connect* is retried — never an assertion.
async fn echo_probe_until_ok<V: Vmm>(
    vm: &mut MicroVm<V>,
    addr: &std::net::Ipv4Addr,
    port: u16,
    payload: &str,
    attempts: u32,
) -> String {
    let mut last = String::new();
    for _ in 0..attempts {
        let (code, out) = echo_probe(vm, addr, port, payload).await;
        if code == 0 && out == payload {
            return out;
        }
        last = format!("code {code}, stdout {out:?}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("the in-guest echo probe to {addr}:{port} never succeeded; last: {last}");
}

/// Whether `ip -o link show` output lists interface `name`.
///
/// Matches the whole name **token** (`3: vmcell-tap-11: <BROADCAST…>`), never a bare substring:
/// `contains("vmcell-tap-1")` matches the `vmcell-tap-11` line, so a residue assertion would
/// report a departed tap as still present — and its mirror would pass vacuously. Both directions
/// of that defect were observed live. A `master <bridge>` field on another line is the same trap
/// for the bridge name, and the token match rules it out too.
fn link_listed(ip_output: &str, name: &str) -> bool {
    ip_output
        .lines()
        .any(|line| line.split_whitespace().nth(1) == Some(&format!("{name}:")))
}

/// The `ip -o link show` view **inside** the segment namespace — the one residue view.
///
/// Deliberately not `tc qdisc show`: `tc` lists only interfaces that are UP, and a leaked tap is
/// typically DOWN (nothing brought it up, or its VMM is gone). Verified on this host: a tap left
/// behind by a failed enslave is absent from `tc qdisc show` and present in `ip -o link show` — so
/// every `!present` assertion built on `tc` passed vacuously against exactly the residue it exists
/// to catch.
fn links_in_segment(segment: &NetSegment) -> String {
    let out = std::process::Command::new("nsenter")
        .arg(format!("--net={}", segment.netns_path().display()))
        .args(["ip", "-o", "link", "show"])
        .output()
        .expect("nsenter ip link must be runnable");
    assert!(
        out.status.success(),
        "listing links in {} failed: {}",
        segment.netns_name(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

// ---------------------------------------------------------------------------------------------
// Legs
// ---------------------------------------------------------------------------------------------

vmm_matrix_test!(segment_two_vm_tcp_both_directions, |vmm| {
    segment_two_vm_tcp_both_directions_impl(&vmm).await;
});

/// Two members of one segment complete a TCP round-trip **in both directions**, and a third
/// off-segment VM's dial to **both** members is refused — with the on-segment positive control
/// against the same two targets.
async fn segment_two_vm_tcp_both_directions_impl<V: Vmm>(vmm: &V) {
    let _ = env_logger::builder().is_test(true).try_init();
    common::clean_vmcell_netns();
    require_privileged_net();

    let env = segment_env();
    let segment = NetSegment::new(vmcell::naming::DEFAULT_RESOURCE_PREFIX, &env)
        .expect("segment creation must succeed under CAP_NET_ADMIN");

    let mut a = start_member(vmm, &segment, &env).await;
    let mut b = start_member(vmm, &segment, &env).await;

    let a_ip = a
        .segment_membership()
        .expect("member a")
        .addresses()
        .expect("a addresses")
        .1;
    let b_ip = b
        .segment_membership()
        .expect("member b")
        .addresses()
        .expect("b addresses")
        .1;
    assert_ne!(a_ip, b_ip, "two members must hold distinct addresses");

    // A → B and B → A: the data plane itself, a byte-exact echo, not a liveness proxy.
    let a_to_b = echo_probe_until_ok(&mut a, &b_ip, ECHO_PORT, "PING-A-TO-B", 20).await;
    assert_eq!(a_to_b, "PING-A-TO-B");
    let b_to_a = echo_probe_until_ok(&mut b, &a_ip, ECHO_PORT, "PING-B-TO-A", 20).await;
    assert_eq!(b_to_a, "PING-B-TO-A");

    // The negative control: a third VM OFF the segment (its own netns, its own /30) reaches
    // NEITHER member.
    let mut outsider = MicroVm::start(vmm, off_segment_cfg(), &env)
        .await
        .expect("the off-segment VM must boot");
    assert!(
        outsider.netns().is_some(),
        "the off-segment control must own a per-VM netns"
    );

    // THE DIALER'S OWN positive control, and it has to be this one: an off-segment privileged VM
    // holds only its /30 tap — no veth, no uplink — so it can reach nothing at all, which makes
    // "the probe reached nothing" and "isolation held" the same observation. Proven: a probe
    // mutated to `sh -c "exit 1"` (never opens a socket) left this leg green. So the same
    // `echo_probe_until_ok`, from the same guest, must first reach a listener it IS allowed to
    // reach — its own loopback — before its refusals mean anything.
    start_echo_server(&mut outsider).await;
    let loopback = std::net::Ipv4Addr::LOCALHOST;
    let self_echo =
        echo_probe_until_ok(&mut outsider, &loopback, ECHO_PORT, "DIALER-WORKS", 20).await;
    assert_eq!(
        self_echo, "DIALER-WORKS",
        "the outsider's dialer must work before its refusals can mean anything"
    );

    for target in [&a_ip, &b_ip] {
        let (code, out) = echo_probe(&mut outsider, target, ECHO_PORT, "SHOULD-NOT-ARRIVE").await;
        assert_ne!(
            code, 0,
            "an off-segment VM must not reach segment member {target} (stdout {out:?})"
        );
        assert!(
            out.is_empty(),
            "an off-segment VM must receive no echoed bytes from {target}: {out:?}"
        );
    }

    // Re-run the positive control AFTER the negative one, so "the target stopped listening" cannot
    // masquerade as isolation.
    let post = echo_probe_until_ok(&mut a, &b_ip, ECHO_PORT, "STILL-UP", 10).await;
    assert_eq!(post, "STILL-UP");

    outsider.shutdown().await.expect("outsider shutdown");
    a.shutdown().await.expect("member a shutdown");
    b.shutdown().await.expect("member b shutdown");
}

vmm_matrix_test!(segment_host_dial_tcp_reaches_a_member, |vmm| {
    segment_host_dial_tcp_impl(&vmm).await;
});

/// `NetSegment::dial_tcp` reaches a member listener from the **host** (FR-V3's privileged shape),
/// and a dead port on the same member is a bounded typed error, never a hang.
async fn segment_host_dial_tcp_impl<V: Vmm>(vmm: &V) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _ = env_logger::builder().is_test(true).try_init();
    common::clean_vmcell_netns();
    require_privileged_net();

    let env = segment_env();
    let segment =
        NetSegment::new(vmcell::naming::DEFAULT_RESOURCE_PREFIX, &env).expect("segment creation");
    let member = start_member(vmm, &segment, &env).await;
    let member_ip = member
        .segment_membership()
        .expect("membership")
        .addresses()
        .expect("addresses")
        .1;

    // The host's socket is created INSIDE the segment netns, so it can reach the bridge subnet
    // that is invisible from the root namespace.
    let mut stream = None;
    for _ in 0..20 {
        match segment
            .dial_tcp(
                SocketAddrV4::new(member_ip, ECHO_PORT),
                Duration::from_secs(5),
            )
            .await
        {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
    let mut stream = stream.expect("dial_tcp must reach the member listener");
    stream
        .write_all(b"HOST-DIAL")
        .await
        .expect("write to the member");
    let mut buf = [0u8; 9];
    stream
        .read_exact(&mut buf)
        .await
        .expect("the member must echo the bytes back");
    assert_eq!(&buf, b"HOST-DIAL");
    drop(stream);

    // A dead port on the SAME member is refused inside the bound — the typed, never-a-hang half
    // of the contract. The positive control is the exchange that just succeeded.
    let started = Instant::now();
    let err = segment
        .dial_tcp(
            SocketAddrV4::new(member_ip, ECHO_PORT + 1),
            Duration::from_secs(5),
        )
        .await
        .expect_err("a dead port must be refused, not accepted");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "a dead-port dial must fail inside its bound, took {:?}",
        started.elapsed()
    );
    assert!(
        matches!(
            err,
            vmcell::error::Error::Io(_) | vmcell::error::Error::Timeout(_)
        ),
        "a dead-port dial must be a typed Io/Timeout error, got {err:?}"
    );

    member.shutdown().await.expect("member shutdown");
}

/// Times three back-to-back echo exchanges from `vm` to `ip`, asserting each one succeeds.
///
/// The wall clock is measured host-side around the `exec`, so it includes the (constant) vsock
/// round trip — which is exactly why the impairment assertion compares a *delta*, not an absolute.
async fn time_exchanges<V: Vmm>(vm: &mut MicroVm<V>, ip: std::net::Ipv4Addr) -> Duration {
    let started = Instant::now();
    for i in 0..3u32 {
        let payload = format!("RTT{i}");
        let (code, out) = echo_probe(vm, &ip, ECHO_PORT, &payload).await;
        assert_eq!(code, 0, "the timed exchange must succeed: {out:?}");
        assert_eq!(out, payload);
    }
    started.elapsed()
}

vmm_matrix_test!(segment_netem_delay_shifts_the_round_trip, |vmm| {
    segment_netem_delay_impl(&vmm).await;
});

/// A `tc netem` 50 ms delay on the member taps measurably shifts the guest↔guest round trip.
///
/// Deliberately its own leg, separate from the loss/partition one below: a bridge that silently
/// healed a partition would still pass a delay-only gate.
async fn segment_netem_delay_impl<V: Vmm>(vmm: &V) {
    let _ = env_logger::builder().is_test(true).try_init();
    common::clean_vmcell_netns();
    require_privileged_net();

    let env = segment_env();
    let segment =
        NetSegment::new(vmcell::naming::DEFAULT_RESOURCE_PREFIX, &env).expect("segment creation");
    let mut a = start_member(vmm, &segment, &env).await;
    let b = start_member(vmm, &segment, &env).await;
    let b_ip = b
        .segment_membership()
        .expect("membership")
        .addresses()
        .expect("addresses")
        .1;
    let (a_vmid, b_vmid) = (a.vmid(), b.vmid());

    // Warm up (and prove the link works) before timing anything.
    echo_probe_until_ok(&mut a, &b_ip, ECHO_PORT, "WARMUP", 20).await;

    let baseline = time_exchanges(&mut a, b_ip).await;

    // The impairment is a VALUE, built and validated once, then applied to each member through
    // the typed API (§17, Segment refinements). It degrades traffic flowing *toward* each guest,
    // so a connect + echo crosses it several times per exchange.
    let slow = Impairment::builder()
        .delay(Duration::from_millis(50))
        .build()
        .expect("a 50 ms delay is a legal impairment");
    for vmid in [a_vmid, b_vmid] {
        segment
            .impair_member(vmid, &slow)
            .unwrap_or_else(|e| panic!("impairing member {vmid} failed: {e}"));
    }

    let delayed = time_exchanges(&mut a, b_ip).await;

    // Remove the impairment before asserting, so a failed assertion still leaves a clean segment;
    // the clears are checked after the property, so a clear failure never masks the real result.
    let cleared: Vec<_> = [a_vmid, b_vmid]
        .into_iter()
        .map(|vmid| (vmid, segment.clear_impairment(vmid)))
        .collect();

    // Three exchanges, each crossing >= 2 delayed hops (SYN + the echo), on two impaired taps:
    // the floor is deliberately loose (the point is a measurable shift, not a precise model).
    assert!(
        delayed > baseline + Duration::from_millis(150),
        "50 ms netem on both member taps must measurably shift the guest-to-guest round trip: \
         baseline {baseline:?}, delayed {delayed:?}"
    );
    for (vmid, outcome) in cleared {
        outcome.unwrap_or_else(|e| panic!("clearing member {vmid}'s impairment failed: {e}"));
    }

    // Clearing twice is a no-op, not an error: the second call's postcondition already holds.
    segment
        .clear_impairment(a_vmid)
        .expect("clearing an unimpaired member must succeed");

    // The link recovers once the qdisc is gone — the impairment was the cause, not a coincidence.
    let recovered = echo_probe_until_ok(&mut a, &b_ip, ECHO_PORT, "RECOVERED", 10).await;
    assert_eq!(recovered, "RECOVERED");

    a.shutdown().await.expect("member a shutdown");
    b.shutdown().await.expect("member b shutdown");
}

vmm_matrix_test!(segment_netem_loss_partitions_and_heals, |vmm| {
    segment_netem_loss_impl(&vmm).await;
});

/// `netem loss 100%` on one member tap partitions the link — an in-flight dial times out — and the
/// link works again once the qdisc is removed.
async fn segment_netem_loss_impl<V: Vmm>(vmm: &V) {
    let _ = env_logger::builder().is_test(true).try_init();
    common::clean_vmcell_netns();
    require_privileged_net();

    let env = segment_env();
    let segment =
        NetSegment::new(vmcell::naming::DEFAULT_RESOURCE_PREFIX, &env).expect("segment creation");
    let mut a = start_member(vmm, &segment, &env).await;
    let b = start_member(vmm, &segment, &env).await;
    let b_ip = b
        .segment_membership()
        .expect("membership")
        .addresses()
        .expect("addresses")
        .1;
    let b_vmid = b.vmid();

    // Positive control first: the link works before the partition.
    echo_probe_until_ok(&mut a, &b_ip, ECHO_PORT, "BEFORE", 20).await;

    let partition = Impairment::builder()
        .loss_percent(100)
        .build()
        .expect("total loss is a legal impairment");
    segment
        .impair_member(b_vmid, &partition)
        .unwrap_or_else(|e| panic!("partitioning member {b_vmid} failed: {e}"));

    let (code, stdout) = echo_probe(&mut a, &b_ip, ECHO_PORT, "PARTITIONED").await;

    // Heal before asserting so a red leg still leaves the segment usable for teardown.
    let healed_ok = segment.clear_impairment(b_vmid);

    assert_ne!(
        code, 0,
        "a 100% loss qdisc must partition the link (stdout {stdout:?})"
    );
    assert!(
        stdout.is_empty(),
        "no bytes may cross a fully-lossy link: {stdout:?}"
    );
    healed_ok.unwrap_or_else(|e| panic!("clearing member {b_vmid}'s impairment failed: {e}"));

    // …and it heals: the SAME probe succeeds once the qdisc is gone.
    let healed = echo_probe_until_ok(&mut a, &b_ip, ECHO_PORT, "HEALED", 20).await;
    assert_eq!(healed, "HEALED");

    a.shutdown().await.expect("member a shutdown");
    b.shutdown().await.expect("member b shutdown");
}

vmm_matrix_test!(segment_last_holder_teardown_leaves_no_residue, |vmm| {
    segment_residue_impl(&vmm).await;
});

/// The segment namespace exists **before** the last holder drops and is gone **after** — and a
/// member's own teardown leaves its tap gone while the namespace survives for its sibling.
async fn segment_residue_impl<V: Vmm>(vmm: &V) {
    let _ = env_logger::builder().is_test(true).try_init();
    common::clean_vmcell_netns();
    require_privileged_net();

    let env = segment_env();
    let segment =
        NetSegment::new(vmcell::naming::DEFAULT_RESOURCE_PREFIX, &env).expect("segment creation");
    let netns_path = segment.netns_path();
    let bridge = segment.bridge_name().to_string();
    let segid_lock = segid_lock_path(segment.segid());

    // Exists BEFORE (a residue check that never observed the artifact proves nothing).
    assert!(
        netns_path.exists(),
        "the segment namespace must exist once created: {}",
        netns_path.display()
    );
    // …including the CROSS-PROCESS claim: with the hermetic allocator `/tmp/vmcell-segid` is never
    // consulted, so this assertion is what proves the shared claim law arbitrates on a real host
    // (and that another vmcell process cannot draw this segid while the segment lives).
    assert!(
        segid_lock.exists(),
        "a shared segid claim must leave its cross-process lock file: {}",
        segid_lock.display()
    );
    let links_out = links_in_segment(&segment);
    assert!(
        link_listed(&links_out, &bridge),
        "the bridge {bridge} must exist inside the segment namespace: {links_out}"
    );

    let keeper = start_member(vmm, &segment, &env).await;
    let leaver = start_member(vmm, &segment, &env).await;
    let leaver_tap = leaver
        .segment_membership()
        .expect("membership")
        .tap_name
        .clone();
    let keeper_tap = keeper
        .segment_membership()
        .expect("membership")
        .tap_name
        .clone();
    assert_eq!(segment.active_slots().len(), 2, "two slots are in use");

    // One member leaves: its tap goes, the namespace and the sibling's tap stay.
    leaver.shutdown().await.expect("leaver shutdown");
    let after_leave_out = links_in_segment(&segment);
    assert!(
        !link_listed(&after_leave_out, &leaver_tap),
        "the departed member's tap {leaver_tap} must be gone: {after_leave_out}"
    );
    assert!(
        link_listed(&after_leave_out, &keeper_tap),
        "the remaining member's tap {keeper_tap} must survive its sibling's teardown: \
         {after_leave_out}"
    );
    assert!(
        netns_path.exists(),
        "the namespace must survive while a member still holds the segment"
    );
    assert_eq!(
        segment.active_slots().len(),
        1,
        "the departed member's slot must return to the free list"
    );

    // The last member leaves; the namespace still survives because the TEST holds a handle.
    keeper.shutdown().await.expect("keeper shutdown");
    assert!(
        netns_path.exists(),
        "the namespace must survive while this test still holds a `NetSegment`"
    );

    // Gone AFTER the last holder drops — the namespace, and the id claim with it.
    drop(segment);
    assert!(
        !netns_path.exists(),
        "the segment namespace must be removed when the last holder drops: {}",
        netns_path.display()
    );
    assert!(
        !segid_lock.exists(),
        "the cross-process segid claim must be released with the segment: {}",
        segid_lock.display()
    );
}

/// A second member carrying a vmid the segment already holds is refused, and the **live** member
/// of that vmid keeps its tap *and* its datapath.
///
/// The L1 defect this guards, reproduced live before the fix: `claim_member` accepted the
/// duplicate, `create_persistent_tap_in_ns` then failed `EBUSY` (the live member's VMM holds that
/// interface open), and the failure path deleted the tap **by name** — the live member's, in the
/// shared segment namespace — severing its datapath with nothing logged. Two hermetic `HostEnv`s
/// in one process is exactly how two vmcell processes on one host behave, and is why the vmid is
/// pinned here rather than left to the allocator.
///
/// Cloud-hypervisor only: the mechanism is entirely host-side (netlink + the claim path), so
/// running it on every backend would buy three copies of the same evidence.
#[cfg(feature = "cloud-hypervisor")]
#[tokio::test]
#[ignore = "needs KVM"]
async fn segment_duplicate_vmid_is_refused_without_touching_the_live_member() {
    let _ = env_logger::builder().is_test(true).try_init();
    common::clean_vmcell_netns();
    require_privileged_net();

    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    let env = segment_env();
    let segment =
        NetSegment::new(vmcell::naming::DEFAULT_RESOURCE_PREFIX, &env).expect("segment creation");
    let a = start_member(&vmm, &segment, &env).await;
    let a_vmid = a.vmid();
    let a_tap = a.segment_membership().expect("membership").tap_name.clone();
    let a_ip = a
        .segment_membership()
        .expect("membership")
        .addresses()
        .expect("addresses")
        .1;

    // Observe the artifact BEFORE: the tap is there and the member answers.
    let before_out = links_in_segment(&segment);
    assert!(
        link_listed(&before_out, &a_tap),
        "the live member's tap must exist before the refused claim: {before_out}"
    );
    dial_and_echo(&segment, a_ip, "BEFORE-DUP").await;

    // A second env is a second process's allocator: it hands out the same vmid happily.
    let dup_cfg = VmConfig::builder(
        common::get_vmlinux(),
        RootfsSource::Erofs {
            image: common::get_rootfs(),
        },
    )
    .net(NetConfig::Segment {
        segment: segment.clone(),
    })
    .vmid(a_vmid)
    .build()
    .expect("a duplicate-vmid member config still builds (the refusal is the segment's)");
    let err = MicroVm::start(&vmm, dup_cfg, &segment_env())
        .await
        .expect_err("a second member with a live member's vmid must be refused");
    assert!(
        matches!(err, vmcell::error::Error::Config(_)),
        "the duplicate vmid must be refused as an invalid input at construction, got {err:?}"
    );
    assert!(
        err.to_string().contains("already holds slot"),
        "the refusal must name the conflict it found: {err}"
    );

    // The live member is untouched: its tap, its slot, and — the point — its datapath.
    let after_out = links_in_segment(&segment);
    assert!(
        link_listed(&after_out, &a_tap),
        "the refused claim must not delete the live member's tap {a_tap}: {after_out}"
    );
    assert_eq!(
        segment.active_slots().len(),
        1,
        "the refused claim must neither consume nor release a slot"
    );
    dial_and_echo(&segment, a_ip, "AFTER-DUP").await;

    a.shutdown().await.expect("member shutdown");
}

/// Host-side echo through `segment.dial_tcp`, retried while the guest listener comes up.
///
/// Used as a *liveness* assertion on a member's datapath: a tap that is listed but detached from
/// the bridge would still pass a name check, and not this.
#[cfg(feature = "cloud-hypervisor")]
async fn dial_and_echo(segment: &NetSegment, ip: std::net::Ipv4Addr, payload: &str) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    for attempt in 0..20 {
        let Ok(mut stream) = segment
            .dial_tcp(SocketAddrV4::new(ip, ECHO_PORT), Duration::from_secs(5))
            .await
        else {
            tokio::time::sleep(Duration::from_millis(500)).await;
            continue;
        };
        stream.write_all(payload.as_bytes()).await.expect("write");
        let mut buf = vec![0u8; payload.len()];
        stream.read_exact(&mut buf).await.expect("echo back");
        assert_eq!(
            String::from_utf8_lossy(&buf),
            payload,
            "the member's datapath must echo (attempt {attempt})"
        );
        return;
    }
    panic!("the member at {ip} never answered on its segment datapath ({payload})");
}

/// `setup_tap_on_bridge` reclaims the tap **it** created when a later step fails — the cleanup
/// contract that lets `claim_member` stop deleting by name in a shared namespace.
///
/// No VM at all: this is the netlink layer's own gate. Buggy impl guarded: dropping the internal
/// cleanup leaves the half-created tap behind, so the next claim of that vmid trips over it.
#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN"]
async fn segment_setup_tap_on_bridge_reclaims_the_tap_it_created_when_enslaving_fails() {
    use vmcell::net::tap::Netlink as _;

    let _ = env_logger::builder().is_test(true).try_init();
    common::clean_vmcell_netns();
    require_privileged_net();

    let env = segment_env();
    let segment =
        NetSegment::new(vmcell::naming::DEFAULT_RESOURCE_PREFIX, &env).expect("segment creation");
    let netlink = vmcell::net::tap::RtNetlink;
    let tap = vmcell::naming::tap_name(vmcell::naming::DEFAULT_RESOURCE_PREFIX, 199);

    // The enslave step fails (no such bridge) AFTER the tap was created.
    let err = netlink
        .setup_tap_on_bridge(segment.netns_name(), &tap, "vmcell-no-such-br")
        .expect_err("enslaving to a nonexistent bridge must fail");
    assert!(
        matches!(err, vmcell::error::Error::Network(_)),
        "expected a typed Network error, got {err:?}"
    );
    let after_fail_out = links_in_segment(&segment);
    assert!(
        !link_listed(&after_fail_out, &tap),
        "a failed enslave must leave behind no half-created tap: {after_fail_out}"
    );

    // Positive control: the same call against the real bridge creates and keeps the tap.
    netlink
        .setup_tap_on_bridge(segment.netns_name(), &tap, segment.bridge_name())
        .expect("the allowed path must succeed");
    let after_ok_out = links_in_segment(&segment);
    assert!(
        link_listed(&after_ok_out, &tap),
        "the successful enslave must leave the tap in place: {after_ok_out}"
    );

    netlink
        .delete_link(segment.netns_name(), &tap)
        .expect("clean up the tap");
}

/// The residue helper's own gate: `link_listed` must not confuse `vmcell-tap-1` with
/// `vmcell-tap-11`, nor match a name that appears only as another link's `master`.
///
/// KVM-free, because the defect it guards is pure string handling — and it is exactly the defect
/// the full privileged suite caught in this battery once the vmid allocator drew that pair.
#[test]
fn link_listed_matches_whole_interface_names_only() {
    let out = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN \\    link/loopback\n\
               2: vmcell-br-1: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP \\    link/ether\n\
               3: vmcell-tap-11: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN master vmcell-br-1\n";
    assert!(
        link_listed(out, "vmcell-tap-11"),
        "the listed tap must match — including a DOWN one, which `tc qdisc show` omits entirely"
    );
    assert!(
        !link_listed(out, "vmcell-tap-1"),
        "a PREFIX of a listed name must not count as present — the bare-substring bug"
    );
    assert!(link_listed(out, "vmcell-br-1"), "the bridge matches too");
    assert!(!link_listed(out, "vmcell-tap-2"), "an absent tap is absent");
    assert!(
        !link_listed(out, "master"),
        "a field VALUE on another link's line is not an interface of that name"
    );
}

/// The orphan sweep reclaims a leaked `<prefix>-seg-*` namespace against **segids**, and leaves a
/// foreign-prefix segment untouched.
///
/// KVM-free but privileged (it plants and reaps real namespaces), so it lives with the live
/// battery rather than the unit tests.
#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN"]
async fn segment_orphan_sweep_reclaims_leaked_namespaces() {
    use vmcell::net::tap::Netlink as _;

    let _ = env_logger::builder().is_test(true).try_init();
    common::clean_vmcell_netns();
    require_privileged_net();

    let netlink = vmcell::net::tap::RtNetlink;
    // A leaked segment under OUR prefix, and one under a foreign prefix that must not be touched.
    let orphan = vmcell::naming::segment_netns_name(vmcell::naming::DEFAULT_RESOURCE_PREFIX, 231);
    let foreign = vmcell::naming::segment_netns_name("acme", 232);
    let _ = netlink.delete_netns(&orphan);
    let _ = netlink.delete_netns(&foreign);
    netlink
        .add_netns(&orphan)
        .expect("plant the orphan segment");
    netlink
        .add_netns(&foreign)
        .expect("plant the foreign segment");

    let orphan_path = std::path::Path::new("/var/run/netns").join(&orphan);
    let foreign_path = std::path::Path::new("/var/run/netns").join(&foreign);
    assert!(
        orphan_path.exists(),
        "the orphan must exist before the sweep"
    );
    assert!(foreign_path.exists(), "the foreign one must exist too");

    let report = vmcell::orchestrator::sweep_orphans(
        &vmcell::orchestrator::HostOrphanScanner::new(vmcell::naming::DEFAULT_RESOURCE_PREFIX),
        &netlink,
        &vmcell::metrics::DefaultCgroupFs,
        &std::collections::BTreeSet::new(),
        &std::collections::BTreeSet::new(),
    );

    assert!(
        report.segment_netns.contains(&orphan),
        "the leaked segment namespace must be reclaimed: {:?}",
        report.segment_netns
    );
    assert!(
        !orphan_path.exists(),
        "the reclaimed namespace must be gone from /var/run/netns"
    );
    assert!(
        foreign_path.exists(),
        "a foreign-prefix segment must be left alone by our sweep"
    );

    netlink
        .delete_netns(&foreign)
        .expect("clean up the foreign segment");
}
