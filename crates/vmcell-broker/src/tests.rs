//! KVM-free, root-free gates for the setup broker (design §12.4, Layer 3 — the setup broker (network surface never holds caps)). The protocol codec
//! (round-trip + over-cap reject), the dispatch logic against recording fakes (call-order,
//! teardown, sweep-only-dead, spawn-forward-work), and both transports (threaded + forked).

use super::*;
use std::io::Cursor;
use std::sync::{Arc, Mutex};

// ---- recording fakes over the pub vmcell seams ----------------------------------------------

#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<String>>>);
impl Log {
    fn push(&self, s: impl Into<String>) {
        self.0.lock().expect("log lock").push(s.into());
    }
    fn calls(&self) -> Vec<String> {
        self.0.lock().expect("log lock").clone()
    }
}

struct FakeNetlink {
    log: Log,
}
impl Netlink for FakeNetlink {
    fn add_netns(&self, name: &str) -> vmcell::error::Result<()> {
        self.log.push(format!("add_netns:{name}"));
        Ok(())
    }
    fn setup_tap(
        &self,
        _netns: &str,
        tap_name: &str,
        _vmid: u32,
    ) -> vmcell::error::Result<Option<tun_tap::Iface>> {
        self.log.push(format!("setup_tap:{tap_name}"));
        Ok(None)
    }
    fn delete_netns(&self, name: &str) -> vmcell::error::Result<()> {
        self.log.push(format!("delete_netns:{name}"));
        Ok(())
    }
    fn setup_tproxy_routing(&self, netns: &str) -> vmcell::error::Result<()> {
        self.log.push(format!("setup_tproxy_routing:{netns}"));
        Ok(())
    }
}

#[derive(Default)]
struct FakeNft {
    log: Log,
    fail: bool,
}
impl NftApplier for FakeNft {
    fn apply_rules(&self, netns: &str, _rules: &str) -> vmcell::error::Result<()> {
        self.log.push(format!("apply_rules:{netns}"));
        if self.fail {
            return Err(vmcell::error::Error::Network("fake: nft apply fail".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct FakeCgroups {
    log: Log,
    fail: bool,
}
impl std::fmt::Debug for Log {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Log").finish()
    }
}
impl CgroupFs for FakeCgroups {
    fn create_slice(
        &self,
        name: &str,
        _limits: &vmcell::config::ResourceLimits,
    ) -> vmcell::error::Result<()> {
        self.log.push(format!("create_slice:{name}"));
        Ok(())
    }
    fn delete_slice(&self, name: &str) -> vmcell::error::Result<()> {
        self.log.push(format!("delete_slice:{name}"));
        if self.fail {
            return Err(vmcell::error::Error::Cgroup(
                "fake: cgroup delete fail".into(),
            ));
        }
        Ok(())
    }
    fn read_stats(&self, _name: &str) -> vmcell::error::Result<vmcell::ResourceUsage> {
        // Never reached by any dispatch path; ResourceUsage is #[non_exhaustive] so we cannot
        // construct one here — return an error rather than fabricate a value.
        Err(vmcell::error::Error::Cgroup("fake: no stats".into()))
    }
    fn add_task(&self, _name: &str, _pid: u32) -> vmcell::error::Result<()> {
        Ok(())
    }
}

struct FakeScanner {
    netns: Vec<String>,
}
impl OrphanScanner for FakeScanner {
    fn scan_netns(&self) -> Vec<String> {
        self.netns.clone()
    }
    fn scan_cgroup_slices(&self) -> Vec<String> {
        Vec::new()
    }
    fn scan_scratch_dirs(&self) -> Vec<std::path::PathBuf> {
        Vec::new()
    }
}

/// A recording backend sharing one netlink log across every `new_netlink()`, plus fake
/// nft/cgroups/scanner — so a test can assert the exact call order with no root.
struct FakeBackend {
    net_log: Log,
    nft: FakeNft,
    cgroups: FakeCgroups,
    scanner_netns: Vec<String>,
}
impl FakeBackend {
    fn new() -> Self {
        Self {
            net_log: Log::default(),
            nft: FakeNft::default(),
            cgroups: FakeCgroups::default(),
            scanner_netns: Vec::new(),
        }
    }
    fn with_scanner_netns(mut self, names: Vec<String>) -> Self {
        self.scanner_netns = names;
        self
    }
    fn with_nft_fail(mut self) -> Self {
        self.nft.fail = true;
        self
    }
    fn with_cgroup_fail(mut self) -> Self {
        self.cgroups.fail = true;
        self
    }
}
impl BrokerBackend for FakeBackend {
    fn new_netlink(&self) -> Box<dyn Netlink> {
        Box::new(FakeNetlink {
            log: self.net_log.clone(),
        })
    }
    fn nft(&self) -> &dyn NftApplier {
        &self.nft
    }
    fn cgroups(&self) -> &dyn CgroupFs {
        &self.cgroups
    }
    fn new_scanner(&self, _prefix: &str) -> Box<dyn OrphanScanner> {
        Box::new(FakeScanner {
            netns: self.scanner_netns.clone(),
        })
    }
}

// ---- codec ----------------------------------------------------------------------------------

// Guards §12.4 (Layer 3 — the setup broker (network surface never holds caps)) framing: every request/reply variant round-trips through the length-prefixed
// postcard codec. Inverse: a codec that mis-frames (wrong length, truncation) reddens here.
#[test]
fn codec_round_trips_requests_and_replies() {
    let reqs = [
        BrokerRequest::Health,
        BrokerRequest::SetupNetwork {
            vmid: 7,
            prefix: "vmcell".into(),
            proxy_port: Some(8080),
        },
        BrokerRequest::CreateCgroup {
            vmid: 7,
            prefix: "vmcell".into(),
            limits: BrokerLimits {
                mem_max_mib: Some(256),
                cpu_max_pct: Some(50),
                pids_max: Some(128),
                io_max: Some(BrokerIoMax {
                    device: "8:0".into(),
                    rbps: Some(1_000_000),
                    wbps: None,
                    riops: None,
                    wiops: None,
                }),
            },
        },
        BrokerRequest::SpawnVmm {
            vmid: 9,
            argv: vec!["cloud-hypervisor".into(), "--api-socket".into()],
            netns: "vmcell-net-9".into(),
            cgroup: "vmcell-vm-9".into(),
        },
        BrokerRequest::Teardown {
            vmid: 9,
            prefix: "vmcell".into(),
        },
        BrokerRequest::Sweep {
            prefix: "acme".into(),
            live_vmids: vec![1, 2, 3],
        },
        BrokerRequest::Shutdown,
    ];
    for req in &reqs {
        let mut buf = Vec::new();
        send_msg(&mut buf, req).expect("send");
        let got: BrokerRequest = recv_msg(&mut Cursor::new(buf)).expect("recv");
        assert_eq!(&got, req, "request must round-trip");
    }

    let replies = [
        BrokerReply::Done,
        BrokerReply::NetworkReady {
            tap: "vmcell-tap-7".into(),
            netns: "vmcell-net-7".into(),
            host_ip: "10.200.8.1".into(),
        },
        BrokerReply::CgroupReady {
            name: "vmcell-vm-9.scope".into(),
        },
        BrokerReply::SweepDone {
            netns: vec!["vmcell-net-1".into()],
            cgroup_slices: vec![],
            scratch_dirs: vec!["/tmp/x".into()],
        },
        BrokerReply::Error("boom".into()),
    ];
    for reply in &replies {
        let mut buf = Vec::new();
        send_msg(&mut buf, reply).expect("send");
        let got: BrokerReply = recv_msg(&mut Cursor::new(buf)).expect("recv");
        assert_eq!(&got, reply, "reply must round-trip");
    }
}

// Guards §12.4 (Layer 3 — the setup broker (network surface never holds caps)) over-cap reject BEFORE allocation: a length prefix larger than the cap is
// rejected without allocating that many bytes. Inverse: a reader that trusts the length would
// try to allocate/read `MAX+1` bytes (here it would then block on EOF); this asserts the typed
// InvalidData reject fires first.
#[test]
fn read_frame_rejects_over_cap_length_before_allocating() {
    let bogus_len = (MAX_BROKER_FRAME_BYTES + 1) as u32;
    let buf = bogus_len.to_be_bytes().to_vec(); // length prefix only — no body follows
    let err = read_frame(&mut Cursor::new(buf)).expect_err("over-cap length must be rejected");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

// A write of an over-cap payload is rejected too (the sender never emits an unframeable frame).
#[test]
fn write_frame_rejects_over_cap_payload() {
    let mut sink = Vec::new();
    let payload = vec![0u8; MAX_BROKER_FRAME_BYTES + 1];
    let err = write_frame(&mut sink, &payload).expect_err("over-cap payload must be rejected");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(
        sink.is_empty(),
        "nothing must be written for a rejected frame"
    );
}

// ---- dispatch -------------------------------------------------------------------------------

// Guards §12.4 (Layer 3 — the setup broker (network surface never holds caps)): SetupNetwork drives the netns create through the injected netlink (add_netns
// then setup_tap, in order) and, with a proxy_port, emits the nft ruleset. Inverse: a dispatch
// that skipped the netlink seam (or reordered create) reddens on the call log.
#[test]
fn dispatch_setup_network_calls_netlink_then_nft() {
    let backend = FakeBackend::new();
    let net_log = backend.net_log.clone();
    let nft_log = backend.nft.log.clone();
    let mut srv = BrokerServer::new(backend);

    let reply = srv.dispatch(BrokerRequest::SetupNetwork {
        vmid: 7,
        prefix: "vmcell".into(),
        proxy_port: Some(3128),
    });
    match reply {
        BrokerReply::NetworkReady {
            tap,
            netns,
            host_ip,
        } => {
            assert_eq!(tap, vmcell::naming::tap_name("vmcell", 7));
            assert_eq!(netns, vmcell::naming::netns_name("vmcell", 7));
            assert!(!host_ip.is_empty(), "a gateway IP must be reported");
        }
        other => panic!("expected NetworkReady, got {other:?}"),
    }

    let calls = net_log.calls();
    let add = calls.iter().position(|c| c.starts_with("add_netns:"));
    let tap = calls.iter().position(|c| c.starts_with("setup_tap:"));
    assert!(
        add.is_some() && tap.is_some(),
        "netns create must go through the netlink seam: {calls:?}"
    );
    assert!(add < tap, "add_netns must precede setup_tap: {calls:?}");
    assert!(
        nft_log
            .calls()
            .iter()
            .any(|c| c.starts_with("apply_rules:")),
        "a proxy_port must emit the nft ruleset: {:?}",
        nft_log.calls()
    );
}

// Guards §12.4 (Layer 3 — the setup broker (network surface never holds caps)): CreateCgroup writes the slice; Teardown deletes both the netns (owned from a
// prior SetupNetwork) and the cgroup slice, in that reverse order. Inverse: a teardown that
// dropped the cgroup delete (a leak) reddens on the missing delete_slice.
#[test]
fn dispatch_create_cgroup_then_teardown_deletes_netns_and_cgroup() {
    let backend = FakeBackend::new();
    let net_log = backend.net_log.clone();
    let cg_log = backend.cgroups.log.clone();
    let mut srv = BrokerServer::new(backend);

    // Set up a netns first so Teardown has one to delete.
    srv.dispatch(BrokerRequest::SetupNetwork {
        vmid: 3,
        prefix: "vmcell".into(),
        proxy_port: None,
    });

    let name = vmcell::naming::cgroup_slice_name("vmcell", 3);
    let reply = srv.dispatch(BrokerRequest::CreateCgroup {
        vmid: 3,
        prefix: "vmcell".into(),
        limits: BrokerLimits {
            mem_max_mib: Some(64),
            ..BrokerLimits::default()
        },
    });
    assert_eq!(reply, BrokerReply::CgroupReady { name: name.clone() });
    assert!(
        cg_log.calls().contains(&format!("create_slice:{name}")),
        "create must write the slice: {:?}",
        cg_log.calls()
    );

    let reply = srv.dispatch(BrokerRequest::Teardown {
        vmid: 3,
        prefix: "vmcell".into(),
    });
    assert_eq!(reply, BrokerReply::Done);
    assert!(
        net_log
            .calls()
            .iter()
            .any(|c| c.starts_with("delete_netns:")),
        "teardown must delete the netns: {:?}",
        net_log.calls()
    );
    assert!(
        cg_log.calls().contains(&format!("delete_slice:{name}")),
        "teardown must delete the cgroup slice: {:?}",
        cg_log.calls()
    );
}

// Guards §12.4 (Layer 3 — the setup broker (network surface never holds caps)): Sweep reclaims only the DEAD ids (not in live_vmids). With scanner netns for
// vmids 1,2,3 and live={2}, only 1 and 3 are reaped. Inverse: a sweep that ignored live_vmids
// would reap 2 as well (reddening the "must not reap the live id" assertion).
#[test]
fn dispatch_sweep_reaps_only_dead_ids() {
    let names: Vec<String> = [1u32, 2, 3]
        .iter()
        .map(|&v| vmcell::naming::netns_name("vmcell", v))
        .collect();
    let backend = FakeBackend::new().with_scanner_netns(names.clone());
    let mut srv = BrokerServer::new(backend);

    let reply = srv.dispatch(BrokerRequest::Sweep {
        prefix: "vmcell".into(),
        live_vmids: vec![2],
    });
    match reply {
        BrokerReply::SweepDone { netns, .. } => {
            assert!(
                netns.contains(&vmcell::naming::netns_name("vmcell", 1)),
                "dead vmid 1 must be reaped: {netns:?}"
            );
            assert!(
                netns.contains(&vmcell::naming::netns_name("vmcell", 3)),
                "dead vmid 3 must be reaped: {netns:?}"
            );
            assert!(
                !netns.contains(&vmcell::naming::netns_name("vmcell", 2)),
                "the LIVE vmid 2 must NOT be reaped: {netns:?}"
            );
        }
        other => panic!("expected SweepDone, got {other:?}"),
    }
}

// Guards §17 (Open gaps and future capabilities) honesty: the live jailed-VMM spawn is forward work, so SpawnVmm refuses fail-loud
// rather than pretending to spawn. Inverse: a handler that returned Done (a silent no-op) reddens.
#[test]
fn dispatch_spawn_vmm_refuses_as_forward_work() {
    let mut srv = BrokerServer::new(FakeBackend::new());
    let reply = srv.dispatch(BrokerRequest::SpawnVmm {
        vmid: 1,
        argv: vec!["cloud-hypervisor".into()],
        netns: "vmcell-net-1".into(),
        cgroup: "vmcell-vm-1".into(),
    });
    match reply {
        BrokerReply::Error(msg) => assert!(
            msg.contains("forward step") || msg.contains("§17"),
            "SpawnVmm must refuse fail-loud as forward work, got: {msg}"
        ),
        other => panic!("SpawnVmm must not silently succeed, got {other:?}"),
    }
}

// Guards SetupNetwork's nft-emit failure branch AND its netns-reclaim-on-failure residue: when
// emit_proxy_rules errors, dispatch returns Error and the created netns is dropped (reclaimed),
// NOT left registered. Inverse: a handler that inserted `ns` before emitting nft (leaking on
// failure) shows no delete_netns in the log and reddens. Reachable only with the fake's fail-arm.
#[test]
fn dispatch_setup_network_nft_failure_reclaims_netns() {
    let backend = FakeBackend::new().with_nft_fail();
    let net_log = backend.net_log.clone();
    let mut srv = BrokerServer::new(backend);

    let reply = srv.dispatch(BrokerRequest::SetupNetwork {
        vmid: 4,
        prefix: "vmcell".into(),
        proxy_port: Some(3128),
    });
    match reply {
        BrokerReply::Error(msg) => assert!(
            msg.contains("emit nft ruleset"),
            "expected the nft-emit error, got: {msg}"
        ),
        other => panic!("nft failure must surface as Error, got {other:?}"),
    }
    assert!(
        net_log
            .calls()
            .iter()
            .any(|c| c.starts_with("delete_netns:")),
        "the netns created before the nft failure must be reclaimed (delete_netns): {:?}",
        net_log.calls()
    );
}

// broker-hostip: an out-of-range vmid makes host_ip() (via ip_math, valid range
// 1..=254) error; the broker must FAIL LOUD (BrokerReply::Error "host ip: ...")
// rather than mask it into an empty gateway with unwrap_or_default(). RED on the
// pre-fix unwrap_or_default(), which returned NetworkReady{host_ip:""}. proxy_port is
// None so this isolates the NetworkReady host_ip path (not emit_proxy_rules), and the
// created netns must still be reclaimed (ns dropped on the error return).
#[test]
fn dispatch_setup_network_out_of_range_vmid_fails_loud_on_host_ip() {
    let backend = FakeBackend::new();
    let net_log = backend.net_log.clone();
    let mut srv = BrokerServer::new(backend);
    let reply = srv.dispatch(BrokerRequest::SetupNetwork {
        vmid: 0,
        prefix: "vmcell".into(),
        proxy_port: None,
    });
    match reply {
        BrokerReply::Error(msg) => assert!(
            msg.contains("host ip"),
            "an out-of-range vmid must fail loud on host_ip, got: {msg}"
        ),
        other => {
            panic!("out-of-range vmid must not yield an empty-gateway NetworkReady, got {other:?}")
        }
    }
    assert!(
        net_log
            .calls()
            .iter()
            .any(|c| c.starts_with("delete_netns:")),
        "the netns created before the host_ip failure must be reclaimed: {:?}",
        net_log.calls()
    );
}

// Guards Teardown's error-aggregation join: a failing cgroup delete must surface as Error (not a
// silently-Done teardown). Inverse: a teardown that swallowed the delete_slice error reddens.
#[test]
fn dispatch_teardown_aggregates_delete_errors() {
    let backend = FakeBackend::new().with_cgroup_fail();
    let mut srv = BrokerServer::new(backend);
    srv.dispatch(BrokerRequest::SetupNetwork {
        vmid: 6,
        prefix: "vmcell".into(),
        proxy_port: None,
    });
    let reply = srv.dispatch(BrokerRequest::Teardown {
        vmid: 6,
        prefix: "vmcell".into(),
    });
    match reply {
        BrokerReply::Error(msg) => assert!(
            msg.contains("delete cgroup slice"),
            "teardown must aggregate the cgroup delete error, got: {msg}"
        ),
        other => panic!("a failing delete must not report Done, got {other:?}"),
    }
}

// ---- transports -----------------------------------------------------------------------------

// Guards §12.4 (Layer 3 — the setup broker (network surface never holds caps)): the whole serve loop + framing over a REAL socketpair (threaded, no fork
// hazard). Client drives Health -> SetupNetwork -> Shutdown and the broker thread ends cleanly.
#[test]
fn threaded_transport_round_trips_over_socketpair() {
    let (a, b) = UnixStream::pair().expect("socketpair");
    let handle = std::thread::spawn(move || {
        let mut srv = BrokerServer::new(FakeBackend::new());
        serve(&mut srv, b).expect("serve");
    });

    let mut client = BrokerClient::new(a);
    assert_eq!(
        client.request(&BrokerRequest::Health).expect("health"),
        BrokerReply::Done
    );
    let reply = client
        .request(&BrokerRequest::SetupNetwork {
            vmid: 5,
            prefix: "vmcell".into(),
            proxy_port: None,
        })
        .expect("setup");
    assert!(
        matches!(reply, BrokerReply::NetworkReady { .. }),
        "got {reply:?}"
    );
    assert_eq!(client.shutdown().expect("shutdown"), BrokerReply::Done);

    handle.join().expect("broker thread");
}

// Guards §12.4 (Layer 3 — the setup broker (network surface never holds caps)): the real fork transport ([`spawn_broker_with`]) — the child forks, serves, and
// answers Health over the pair; shutdown + reap leave no zombie. Health touches no backend, so
// this is root-free. (Only the LIVE cap-drop + jailed spawn are the KVM step, §17, Open gaps and future capabilities.)
#[test]
fn fork_transport_health_round_trips_and_reaps() {
    let (mut client, mut child) = spawn_broker_with(FakeBackend::new()).expect("fork broker");
    assert_eq!(
        client.request(&BrokerRequest::Health).expect("health"),
        BrokerReply::Done
    );
    assert_eq!(client.shutdown().expect("shutdown"), BrokerReply::Done);
    // reap() returns the decoded exit status, proving it actually reaped (WEXITSTATUS) rather
    // than blind-latching. A clean serve loop exits 0. Inverse: a reap that returned None
    // unconditionally (or latched before waitpid) reddens here.
    assert_eq!(child.reap(), Some(0), "a clean broker child must exit 0");
}

// Guards the fail-loud rule for the forked serve loop: a framing fault in the child must
// exit NON-ZERO, not swallow-and-_exit(0). Inverse: the pre-fix `let _ = serve(..); _exit(0)`
// (or a status-discarding reap) reddens here — reap() would report Some(0)/None instead of Some(1).
#[test]
fn fork_transport_serve_error_exits_nonzero() {
    let (mut client, mut child) = spawn_broker_with(FakeBackend::new()).expect("fork broker");
    // A 2-byte body is an incomplete/invalid postcard varint for BrokerRequest, so the child's
    // recv_msg returns InvalidData (NOT a clean UnexpectedEof) and serve() returns Err.
    write_frame(&mut client.sock, &[0xFFu8, 0xFF]).expect("write malformed frame");
    assert_eq!(
        child.reap(),
        Some(1),
        "a serve() framing error must make the broker child exit non-zero (fail loud)"
    );
}
