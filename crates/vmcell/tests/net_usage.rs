//! Per-VM network byte counters (§7.1, What is read and enforced; §17, Open gaps and future
//! capabilities): the **data-plane** gate for [`vmcell::net::NetUsageTarget`].
//!
//! The KVM-free halves of this law — the tap→guest direction inversion, the saturating delta, the
//! typed refusal for the mode that has no tap — are unit tests in `vmcell::net::usage`, next to the
//! predicates they falsify. What no fake can see is the part this file exists for: that the target
//! names an interface the *kernel* actually has, in a namespace this process can enter, and that
//! its counters move by what really crossed the wire. `FakeVmm` moves no bytes and the recording
//! `Netlink` fakes have no netlink behind them, so both would report a perfectly plausible zero.
//!
//! Cloud Hypervisor only, and that is a scope claim rather than an omission: the counters are a
//! property of the **host-side tap** and the namespace it lives in, both created by `vmcell`'s own
//! `NetNamespace` before any VMM is spawned. Nothing in the read path is backend-specific, so a
//! four-backend matrix here would re-boot the same host object three more times to re-measure the
//! same kernel counter (CH is the primary backend — AGENTS.md).

use hudsucker::Body;
use hyper::Response;
use vmcell::MicroVm;
use vmcell::config::{Egress, ProxyConfig, RootfsSource, VmConfig};
use vmcell::net::NetUsageTarget;
use vmcell::proxy::doubles::TestDouble;
use vmcell::steward::protocol::ExecRequest;
use vmcell::vmm::VmInstance;

mod common;

/// The body the in-netns MITM double serves, and the size the guest must end up holding.
///
/// 4 MiB is chosen to be **unambiguous against the noise floor**: a booted VM's tap has already
/// carried ARP, the DHCP-free `ip=` bring-up and the steward's own traffic, and the assertions below
/// bound the transfer from both sides. It is also far above anything the reverse direction can
/// produce for this transfer (pure ACKs), which is what makes the vantage assertion sharp.
const BODY_BYTES: usize = 4 * 1024 * 1024;

/// Where the guest parks the download. `/tmp` is the tmpfs overlay over the read-only erofs root
/// (§4.1, The erofs read-only base + tmpfs overlay), so it is writable in-guest.
const GUEST_SINK: &str = "/tmp/vmcell-net-usage.bin";

/// The netns-scoped counters move by what the guest actually transferred, on the privileged tap
/// path, **and in the right direction**.
///
/// SHAPE. One asymmetric transfer: the guest pulls [`BODY_BYTES`] through the per-VM egress proxy
/// (which `Egress::Filtered` starts *inside* this VM's namespace, §6.4, The transparent egress
/// proxy) and sends back only a request line and ACKs. So the ingress counter must move by ≈ the
/// body while the egress counter stays two orders of magnitude below it — an echo would have been
/// symmetric, and symmetric traffic cannot tell a correct mapping from a swapped one.
///
/// POSITIVE CONTROL, on the data plane rather than a proxy signal: the guest `stat`s the file it
/// downloaded and it is exactly [`BODY_BYTES`] long. A counter delta is only evidence if the bytes
/// really moved; without this leg a wedged proxy and a broken counter read look identical (both
/// "no delta").
///
/// RED ON THE INVERSE (each one checked to fail before this test was accepted):
/// * swap either mapping line in `NetUsage::from_tap_stats64` → the vantage assertions fail (the
///   ingress delta lands on `guest_tx_bytes`);
/// * point `NetUsageTarget::for_vm` at anything but the VM's own tap (`lo`, the host's `eth0`) →
///   the deltas collapse to ≈0 and the lower bound fails;
/// * drop the `setns` and read in the root namespace → `link … not found`, a loud error rather
///   than a zero.
#[cfg(feature = "cloud-hypervisor")]
#[tokio::test]
#[ignore = "needs KVM"]
async fn net_usage_counters_track_a_real_transfer_on_the_tap_path() {
    let _ = env_logger::builder().is_test(true).try_init();

    // Privileged tap networking needs CAP_NET_ADMIN; gate VISIBLY (panic-skip with a reason, the
    // house rule) — never skip-as-pass.
    assert!(
        common::has_cap_net_admin(),
        "SKIP: per-VM network byte counters need the privileged tap path (CAP_NET_ADMIN); not \
         present in the effective capability set"
    );
    common::clean_vmcell_netns();

    let vmlinux = common::get_vmlinux();
    let rootfs = common::get_rootfs();

    // A deterministic 4 MiB body served by an in-netns MITM double, so the transfer needs no
    // upstream network at all: `Egress::Filtered` starts the proxy inside this VM's namespace and
    // the guest reaches it at `gateway:proxy_port`.
    let body: Vec<u8> = (0..BODY_BYTES)
        .map(|i| u8::try_from(i % 251).expect("i % 251 fits a u8"))
        .collect();
    let mut proxy_cfg = ProxyConfig::default();
    proxy_cfg.doubles = std::sync::Arc::new(std::sync::RwLock::new(vec![TestDouble {
        matcher: Box::new(|req| {
            req.method() != hyper::Method::CONNECT && req.uri().host() == Some("example.com")
        }),
        responder: Box::new(move |_req| {
            Response::builder()
                .status(200)
                .body(Body::from(body.clone()))
                .expect("static response builds")
        }),
    }]));

    let mut cfg = VmConfig::builder(vmlinux, RootfsSource::Erofs { image: rootfs })
        .build()
        .expect("VmConfig");
    cfg.net = vmcell::config::NetConfig::Privileged {
        egress: Egress::Filtered(proxy_cfg),
    };

    let env = vmcell::HostEnv::hermetic();
    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    let mut vm = MicroVm::start(&vmm, cfg, &env)
        .await
        .expect("start a privileged Filtered VM");

    let proxy_port = vm
        .proxy()
        .expect("privileged Filtered egress must start a proxy")
        .port;
    let (gateway_ip, _guest_ip, _cidr) = vmcell::net::ip_math(vm.vmid()).expect("ip_math");

    // THE TARGET, through the one law — the same two accessors a caller has.
    let target = NetUsageTarget::for_vm(vm.netns(), vm.segment_membership())
        .expect("a privileged VM has a tap in a namespace");
    assert_eq!(
        target.netns(),
        vmcell::naming::netns_name(vmcell::naming::DEFAULT_RESOURCE_PREFIX, vm.vmid()),
        "the target must name this VM's OWN namespace"
    );
    assert_eq!(
        target.interface(),
        vmcell::naming::tap_name(vmcell::naming::DEFAULT_RESOURCE_PREFIX, vm.vmid()),
        "the target must name this VM's OWN tap"
    );

    let before = target.read().expect("baseline counter read");

    let steward = match vm.steward(Some(std::time::Duration::from_secs(120))).await {
        Ok(s) => s,
        Err(e) => {
            let log = std::fs::read_to_string(vm.instance().serial_log()).unwrap_or_default();
            panic!("Failed to connect to steward: {e}\nSERIAL LOG:\n{log}");
        }
    };

    let fetch = steward
        .exec(
            ExecRequest::new(vec![
                "curl".into(),
                "-4".into(),
                "--max-time".into(),
                "120".into(),
                "-o".into(),
                GUEST_SINK.into(),
                "http://example.com/big.bin".into(),
            ])
            .with_env(vec![(
                "http_proxy".to_string(),
                format!("http://{gateway_ip}:{proxy_port}"),
            )]),
        )
        .await
        .expect("exec the in-guest fetch");
    assert_eq!(
        fetch.code,
        0,
        "the in-guest fetch must succeed (it is this test's positive control): {}",
        String::from_utf8_lossy(&fetch.stderr)
    );

    // POSITIVE CONTROL on the data plane: the bytes are IN THE GUEST, not merely "no error".
    let sized = steward
        .exec(ExecRequest::new(vec![
            "stat".into(),
            "-c".into(),
            "%s".into(),
            GUEST_SINK.into(),
        ]))
        .await
        .expect("stat the downloaded file");
    assert_eq!(sized.code, 0, "stat {GUEST_SINK} failed: {sized:?}");
    assert_eq!(
        String::from_utf8_lossy(&sized.stdout).trim(),
        BODY_BYTES.to_string(),
        "the guest must hold the whole body before any counter claim is made"
    );

    let after = target.read().expect("post-transfer counter read");
    let delta = after.since(before);

    // INGRESS moved by the body, plus link/TCP framing and nothing like a second copy of it.
    let body = u64::try_from(BODY_BYTES).expect("BODY_BYTES fits a u64");
    assert!(
        delta.guest_rx_bytes >= body,
        "the guest received {BODY_BYTES} bytes of payload, so its ingress counter must be at \
         least that: {delta:?}"
    );
    assert!(
        delta.guest_rx_bytes <= body + body / 4,
        "ingress must be the body plus framing, not a multiple of it: {delta:?}"
    );

    // THE VANTAGE, which is the assertion an echo could never make: the reverse direction carried
    // only the request and ACKs. A swapped tap→guest mapping puts the 4 MiB here and reddens.
    assert!(
        delta.guest_tx_bytes > 0,
        "the guest sent the request and its ACKs, so egress must have moved at all: {delta:?}"
    );
    assert!(
        delta.guest_tx_bytes < body / 8,
        "egress carried a request line and ACKs, never the body — a delta this large means the \
         tap's rx/tx were read from the wrong vantage: {delta:?}"
    );

    // Packets move with the bytes, in both directions.
    assert!(
        delta.guest_rx_packets > 0 && delta.guest_tx_packets > 0,
        "both packet counters must move for a completed TCP transfer: {delta:?}"
    );

    vm.shutdown().await.expect("shutdown");
}

/// The mode that structurally **cannot** be read is a typed refusal on the public API — not an
/// all-zero [`vmcell::net::NetUsage`] that reads as a measurement (§7.2, The fail-loud capability
/// contract and `HostCapabilities`, rule 2).
///
/// KVM-free and privilege-free: the unprivileged smoltcp NAT's datapath is a vhost-user device with
/// no tap and no namespace anywhere, so the refusal is decidable from the two accessors alone. The
/// in-crate twin matches the same variant; this leg exists because the *re-exported* path
/// (`vmcell::net::NetUsageTarget`) is the one a consumer calls, and a `pub use` that stopped
/// exporting it is invisible to a unit test.
#[test]
fn a_vm_with_no_tap_anywhere_gets_a_typed_capability_refusal() {
    let err = NetUsageTarget::for_vm(None, None)
        .expect_err("no namespace and no segment membership must not yield a target");
    match err {
        vmcell::error::Error::CapabilityUnavailable { op, needed } => {
            assert_eq!(op, "per-VM network byte counters");
            assert!(needed.contains("smoltcp"), "got {needed:?}");
        }
        other => panic!("expected a typed CapabilityUnavailable, got {other:?}"),
    }
}

/// A namespace that is not there is a loud error, never zeroed counters.
///
/// Runs anywhere (no KVM, no `CAP_SYS_ADMIN`): opening `/var/run/netns/<absent>` fails before any
/// `setns` is attempted, so this leg pins the "unread is not zero" half of §7.1 rule 3 on the read
/// path itself — the half `NetUsage`'s missing `Default` makes unrepresentable, checked from the
/// outside.
#[test]
fn reading_an_absent_namespace_fails_loudly() {
    let target = NetUsageTarget::new("vmcell-net-absent-for-this-test", "vmcell-tap-absent");
    let err = target
        .read()
        .expect_err("an absent namespace must not produce a reading");
    assert!(
        matches!(err, vmcell::error::Error::Network(_)),
        "got {err:?}"
    );
}
