//! The live battery for `vmcell::net_sys::create_tap_in_current_netns` — the one `TUNSETIFF` in the
//! crate, and everything the unmaintained `tun-tap` crate (with the whole `tokio 0.1` subtree behind
//! it) used to supply.
//!
//! **No VM.** Creating a tap needs `CAP_NET_ADMIN` and nothing else, so these legs run on the
//! blessed capability runner without KVM, without artifacts, and without a boot. That matters
//! because before this file `Netlink::setup_tap` — the per-VM arm, reached on every privileged boot
//! — had **no** live leg of its own: every test that touched it went through a full VM, so the
//! ioctl's own properties (which flags were set, whether persistence took, which namespace the
//! interface landed in) were only ever observed through a VM that happened to come up. The
//! `FakeNetlink` doubles are blind to all four by construction: they touch no kernel at all.
//!
//! Each leg asserts a **kernel-observable** fact off `ip -d link show`, not a proxy signal:
//! `type tap` is `IFF_TAP`, `pi off` is `IFF_NO_PI`, `persist on` is `TUNSETPERSIST`, and presence
//! in the target namespace paired with absence from the host's is the namespace-at-`open()` law.

use vmcell::net::tap::Netlink as _;

mod common;

/// Panics with the SKIP-is-not-a-PASS message unless the process holds `CAP_NET_ADMIN`.
///
/// `TUNSETIFF` is privileged-capability-class; the blessed capability runner is what makes this
/// suite runnable unprivileged, so an absent capability is a real failure, not a skip.
///
/// Probes the **effective** set, while every kernel-observable assertion below runs through an
/// `ip`/`nsenter` subprocess and so depends on the **ambient** set. Under the blessed runner the two
/// coincide by construction (`BLESSED_FILE_CAPS` raises both), which is the only documented way to
/// run this file — but they are different sets, and if they ever diverged these legs would fail
/// pointing at the product instead of at the environment.
fn require_privileged_net() {
    if !common::has_cap_net_admin() {
        panic!(
            "SKIP: creating a tap needs CAP_NET_ADMIN for TUNSETIFF; not present in the effective \
             capability set (run under the blessed runner, `just bless`)"
        );
    }
}

/// A named network namespace that deletes itself on the way out — **including the panic path**.
///
/// Deleting the namespace reaps every interface still inside it, so a leg that panics between the
/// tap create and its cleanup leaves no residue for the next run to trip over. Deliberately built
/// on the `Netlink` seam rather than `NetNamespace::create`, which sets up a tap of its own and so
/// is partly the code under test.
struct NetnsFixture {
    name: String,
}

impl NetnsFixture {
    fn create(name: String) -> Self {
        vmcell::net::tap::RtNetlink
            .add_netns(&name)
            .unwrap_or_else(|e| panic!("creating the fixture namespace {name} must succeed: {e}"));
        Self { name }
    }

    fn path(&self) -> std::path::PathBuf {
        std::path::Path::new("/var/run/netns").join(&self.name)
    }
}

impl Drop for NetnsFixture {
    fn drop(&mut self) {
        let _unused = vmcell::net::tap::RtNetlink.delete_netns(&self.name);
    }
}

/// The vmid this suite's fixtures are named after.
///
/// It is **not** protected by being high: `VmidAllocator::allocate` walks `seeded_id_order(clock,
/// 254)`, a nanosecond-seeded rotation over the whole `1..=254` space precisely so no id is tried
/// first, so 231 is exactly as likely to be handed out as 1. What protects these legs is that
/// nextest's `serial-host` group runs them one at a time — `.config/nextest.toml`'s
/// `package(~vmcell) & kind(test) & !binary(proptests)` override selects this binary — and that
/// every leg sweeps `clean_vmcell_netns()` first, so a crashed earlier run cannot collide either.
const FIXTURE_VMID: u32 = 231;

/// `ip -d link show dev <name>` **inside** `netns` — the detailed view that renders the tun/tap
/// flags. `-d` is the whole point: without it `ip` prints no `tun type tap pi off` line at all, so
/// every flag assertion below would have to fall back to a proxy signal.
fn link_details_in(netns: &std::path::Path, name: &str) -> Option<String> {
    let out = std::process::Command::new("nsenter")
        .arg(format!("--net={}", netns.display()))
        .args(["ip", "-d", "link", "show", "dev", name])
        .output()
        .expect("nsenter ip -d link must be runnable");
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Whether `ip -o link show` in the **host** namespace lists interface `name`.
///
/// Matches the whole name token rather than a bare substring, but note which way that cuts here:
/// every caller **negates** this, so narrowing the match makes a `false` easier to get, not harder.
/// It buys a *spurious red* — `vmcell-tap-231` must not be reported present because `vmcell-tap-23`
/// is — and nothing more. What keeps the negations from passing vacuously is the exit-status
/// assertion below: a failing `ip` yields empty stdout, which every caller would otherwise read as
/// "nothing in the host namespace", quietly turning the leak gate AND the reaper into no-ops.
fn listed_in_host_netns(name: &str) -> bool {
    let out = std::process::Command::new("ip")
        .args(["-o", "link", "show"])
        .output()
        .expect("ip link must be runnable");
    assert!(
        out.status.success(),
        "listing host-namespace links failed, so an absence here would be meaningless: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .any(|line| line.split_whitespace().nth(1) == Some(&format!("{name}:")))
}

/// Reaps `name` from the **host** namespace if it is there, reporting whether it had to.
///
/// The host namespace is the one place [`NetnsFixture`] cannot clean, and it is exactly where a
/// broken build puts the tap: the failure this file's namespace leg exists to catch *is* "the
/// interface went to the host namespace instead", and the tap it leaves there is `TUNSETPERSIST`'d,
/// so it outlives the run. Without this, one red run poisons every later one — the next run's own
/// precheck trips over the previous run's residue and reports a pre-existing interface rather than
/// the defect. Measured while proving the namespace leg can go red, which is the only way to reach
/// this path.
///
/// `ip` inherits `CAP_NET_ADMIN` from the blessed runner's **ambient** set, so no elevation is
/// needed beyond what the suite already runs with.
/// **Best-effort and loud**, never panicking: this runs from a [`HostTapReaper`] `Drop`, and a panic
/// in a destructor *during unwinding* aborts the process — which would skip [`NetnsFixture`]'s own
/// `Drop` (declared earlier, so it runs later) and strand the fixture namespace and everything in
/// it. That is the residue class this function exists to close, so it must not create a worse one.
/// Every other test `Drop` in the tree is non-panicking for the same reason.
fn reap_from_host_netns(name: &str) -> bool {
    if !listed_in_host_netns(name) {
        return false;
    }
    match std::process::Command::new("ip")
        .args(["link", "delete", name])
        .output()
    {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            eprintln!(
                "tap_create: leaked host-namespace interface {name} could NOT be reaped: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            false
        }
        Err(e) => {
            eprintln!("tap_create: could not run `ip link delete {name}`: {e}");
            false
        }
    }
}

/// Reaps a host-namespace leak of `name` on the way out, **including the panic path**.
struct HostTapReaper<'a>(&'a str);

impl Drop for HostTapReaper<'_> {
    fn drop(&mut self) {
        if reap_from_host_netns(self.0) {
            eprintln!(
                "tap_create: reaped {} from the HOST namespace — the tap was created outside \
                 in_netns",
                self.0
            );
        }
    }
}

/// The tap comes up as a **layer-2, no-packet-info, persistent** interface — the three properties
/// the `TUNSETIFF` flag word and the `TUNSETPERSIST` that follows it exist to produce.
///
/// Every assertion reads the kernel's own view (`ip -d`), not the return value of the call that set
/// it. Buggy impls guarded, each proven red by mutation:
///
/// * `IFF_TAP` → `IFF_TUN` in `TAP_NO_PI_FLAGS`: the interface comes up `type tun`, so every frame
///   the VMM writes is interpreted as layer 3.
/// * dropping `IFF_NO_PI`: `pi on`, and the kernel prepends a 4-byte `tun_pi` header to every frame.
/// * dropping the `set_tun_persist` call: `ip` finds no interface at all, because it died with the
///   fd `create_persistent_tap_in_ns` drops — the single-opener discipline's whole mechanism.
/// * `TUNSETIFF` mis-typed as `TUNSETPERSIST` at the call site (which the `net_sys` ABI pin
///   structurally cannot see, since it pins the constants and not which one is issued): no interface
///   is created.
#[test]
#[ignore = "needs CAP_NET_ADMIN"]
fn tap_is_created_layer2_without_packet_info_and_persists_past_our_fd() {
    let _unused = env_logger::builder().is_test(true).try_init();
    common::clean_vmcell_netns();
    require_privileged_net();

    let netns = NetnsFixture::create(vmcell::naming::netns_name(
        vmcell::naming::DEFAULT_RESOURCE_PREFIX,
        FIXTURE_VMID,
    ));
    let tap = vmcell::naming::tap_name(vmcell::naming::DEFAULT_RESOURCE_PREFIX, FIXTURE_VMID);
    // This leg only ever looks inside the fixture namespace, so it would not NOTICE a tap that
    // landed in the host's — but under the hoist it persists one there all the same, and the run
    // that does notice is the next one. Reaping is cheap; a leak that only bites a later invocation
    // is the residue class this file already had to learn once.
    let _reaper = HostTapReaper(&tap);

    vmcell::net::tap::RtNetlink
        .setup_tap(&netns.name, &tap, FIXTURE_VMID)
        .expect("setting up the tap must succeed under CAP_NET_ADMIN");

    // `setup_tap` has already dropped the creating fd by the time it returns, so an interface
    // visible here is one TUNSETPERSIST kept alive — that is the persistence assertion, not a
    // separate step.
    let details = link_details_in(&netns.path(), &tap)
        .unwrap_or_else(|| panic!("{tap} must exist in {} after setup_tap", netns.name));

    assert!(
        details.contains("tun type tap"),
        "IFF_TAP must produce a layer-2 tap, not a tun: {details}"
    );
    assert!(
        details.contains("pi off"),
        "IFF_NO_PI must suppress the 4-byte packet-info header: {details}"
    );
    assert!(
        details.contains("persist on"),
        "TUNSETPERSIST must have taken, or the interface would not have outlived our fd: {details}"
    );
}

/// The namespace-at-`open()` law: the tap lands in the namespace the create ran **inside**, and is
/// absent from the host's.
///
/// The kernel binds a tap to the namespace of whoever opened `/dev/net/tun`, not to the namespace
/// the `TUNSETIFF` runs in — `tun_chr_open` stores it on the `tun_file`'s socket and
/// `__tun_chr_ioctl` reads it back from there. So hoisting the open out of
/// `create_persistent_tap_in_ns`'s `in_netns` closure — the natural tidy-up now that the open and
/// the ioctl are two visible statements instead of one opaque `tun-tap` call — silently creates
/// every tap in the **host** namespace. Nothing about that is loud: the call returns `Ok`, and it
/// surfaces one step later at an in-namespace `rtnetlink` lookup.
///
/// **Order matters, and the obvious order hides the defect.** Under the hoist, `setup_tap` FAILS —
/// the tap is in the host namespace, so its own in-namespace `rtnetlink` lookup finds nothing — so
/// an `.expect()` on the result would panic first and the host would never be looked at. The leg
/// would still go red, but via the `.expect`, leaving the absence assertion something that has
/// never once been evaluated in its failing direction. Worse, asserting presence-in-the-namespace
/// first makes absence-from-the-host a logical *consequence* of it (a netdevice lives in exactly
/// one namespace), so it could not fail even in principle. The result is therefore captured, the
/// host checked first, and only then is the call's own success asserted as the positive control.
#[test]
#[ignore = "needs CAP_NET_ADMIN"]
fn tap_lands_in_the_target_netns_and_not_the_host() {
    let _unused = env_logger::builder().is_test(true).try_init();
    common::clean_vmcell_netns();
    require_privileged_net();

    let netns = NetnsFixture::create(vmcell::naming::netns_name(
        vmcell::naming::DEFAULT_RESOURCE_PREFIX,
        FIXTURE_VMID,
    ));
    let tap = vmcell::naming::tap_name(vmcell::naming::DEFAULT_RESOURCE_PREFIX, FIXTURE_VMID);

    // Sweep an earlier run's leak before starting — the same auto-heal `clean_vmcell_netns()` above
    // does for namespaces, and what stops one red run from making every later one report a
    // pre-existing interface instead of the defect. The assertion after it is a backstop for a reap
    // that failed, not proof the reap took: `reap_from_host_netns` already returns `false` unless
    // the name was absent or `ip link delete` succeeded, so it holds on both branches. (It is
    // conditional for a mechanical reason: `ip link delete` on an absent device exits non-zero, so
    // an unconditional reap would report a failure on every clean run.)
    if reap_from_host_netns(&tap) {
        eprintln!("tap_create: reaped a stale host-namespace {tap} left by an earlier run");
    }
    assert!(
        !listed_in_host_netns(&tap),
        "{tap} still exists in the host namespace and could not be reaped; the gate below would \
         report a stale leak rather than this run's"
    );
    let _reaper = HostTapReaper(&tap);

    let created = vmcell::net::tap::RtNetlink.setup_tap(&netns.name, &tap, FIXTURE_VMID);

    // The gate, evaluated before anything can short-circuit it.
    assert!(
        !listed_in_host_netns(&tap),
        "{tap} leaked into the host namespace — the /dev/net/tun open ran outside in_netns \
         (setup_tap returned {created:?})"
    );
    // Positive controls: the call succeeded, and the interface really is in the namespace — without
    // both, a tap that was never created at all would satisfy the assertion above vacuously.
    created.expect("setting up the tap must succeed under CAP_NET_ADMIN");
    assert!(
        link_details_in(&netns.path(), &tap).is_some(),
        "positive control: {tap} must be present in {}",
        netns.name
    );
}

/// An over-long tap name is refused **before** any interface is created, not silently truncated.
///
/// `tun-tap`'s C shim did `strncpy(ifr.ifr_name, name, IFNAMSIZ - 1)`, so a 20-byte name brought an
/// interface up as its first 15 bytes and the failure surfaced far from the composer that
/// overflowed. This is the live half of `net_sys`'s `an_over_long_or_unencodable_tap_name_is_
/// refused_not_truncated` unit test: that one proves the encoder returns `Err`, this one proves no
/// interface exists on either name afterwards — which is the part a fake cannot see.
///
/// The truncated name is checked too, and deliberately: it is the only spelling under which the old
/// behavior leaves residue, so a leg that checked the requested name alone would pass against
/// exactly the defect it exists to catch.
///
/// RED on: removing **both** the length check and the read-back — which is precisely the shape
/// `tun-tap` shipped, since its shim had neither. `vmcell-tap-far-` then exists and this leg says
/// so. Removing either one alone leaves it green, and that is worth stating rather than claiming a
/// tighter inverse than it has: the length check refuses first, and if it did not, the read-back
/// would refuse before `TUNSETPERSIST` so the interface would die with the fd. The read-back's own
/// gate is `a_tap_name_the_kernel_expands_is_refused_and_leaves_nothing_behind`; the length check's
/// is `net_sys`'s `an_over_long_or_unencodable_tap_name_is_refused_not_truncated`.
#[test]
#[ignore = "needs CAP_NET_ADMIN"]
fn an_over_long_tap_name_creates_no_interface_under_any_name() {
    let _unused = env_logger::builder().is_test(true).try_init();
    common::clean_vmcell_netns();
    require_privileged_net();

    let netns = NetnsFixture::create(vmcell::naming::netns_name(
        vmcell::naming::DEFAULT_RESOURCE_PREFIX,
        FIXTURE_VMID,
    ));
    let over_long = "vmcell-tap-far-too-long";
    let truncated = &over_long[..15];

    let err = vmcell::net::tap::RtNetlink
        .setup_tap(&netns.name, over_long, FIXTURE_VMID)
        .expect_err("an over-long interface name must be refused");
    assert!(
        matches!(err, vmcell::error::Error::Network(_)),
        "expected a typed Network error, got {err:?}"
    );

    for name in [over_long, truncated] {
        assert!(
            link_details_in(&netns.path(), name).is_none(),
            "a refused name must leave no interface behind, but {name} exists"
        );
    }

    // Positive control: the same call with a name that fits does create the interface, so the
    // absences above are the rejection and not a namespace nothing can be created in.
    let ok_name = vmcell::naming::tap_name(vmcell::naming::DEFAULT_RESOURCE_PREFIX, FIXTURE_VMID);
    let _reaper = HostTapReaper(&ok_name);
    vmcell::net::tap::RtNetlink
        .setup_tap(&netns.name, &ok_name, FIXTURE_VMID)
        .expect("the allowed path must succeed");
    assert!(
        link_details_in(&netns.path(), &ok_name).is_some(),
        "positive control: {ok_name} must be created"
    );
}

/// A name the kernel **expands** rather than takes verbatim is refused by the read-back.
///
/// This is the leg that gates the read-back comparison, and it exists because nothing else does:
/// dropping the read-back alone is invisible to every other test here (measured), since the length
/// check in front of it already refuses the truncation case. `%d` is the reachable input that slips
/// past the length check — `"vmcell-tap-%d"` is 13 bytes — and that the kernel then renames:
/// `dev_get_valid_name` substitutes the first free index, so a caller asking for one name silently
/// gets another, and the VMM would later be pointed at an interface that does not exist.
///
/// Reachable **at the `Netlink` seam**, to be precise, not through vmcell's own orchestration:
/// `naming::tap_name` is the only in-tree composer and `validate_resource_prefix` admits no `%`.
/// The seam is public and ledgered, so an out-of-tree implementor or a direct `setup_tap` call is
/// the caller this defends — which is the same reason the seam validates at all.
///
/// The residue half matters as much as the error: `TUNSETIFF` really did create `vmcell-tap-0`, and
/// what removes it is that the read-back fails **before** `TUNSETPERSIST`, so the interface dies
/// with the fd. Asserting only on the error would pass while leaking an interface per call.
///
/// RED on: dropping the read-back comparison in `create_tap_in_current_netns` — the call returns
/// `Ok` and `vmcell-tap-0` is left persisted in the namespace.
#[test]
#[ignore = "needs CAP_NET_ADMIN"]
fn a_tap_name_the_kernel_expands_is_refused_and_leaves_nothing_behind() {
    let _unused = env_logger::builder().is_test(true).try_init();
    common::clean_vmcell_netns();
    require_privileged_net();

    let netns = NetnsFixture::create(vmcell::naming::netns_name(
        vmcell::naming::DEFAULT_RESOURCE_PREFIX,
        FIXTURE_VMID,
    ));
    let pattern = "vmcell-tap-%d";
    assert!(
        pattern.len() < 16,
        "the pattern must be short enough to pass the length check, or this leg gates that instead"
    );

    let err = vmcell::net::tap::RtNetlink
        .setup_tap(&netns.name, pattern, FIXTURE_VMID)
        .expect_err("a name the kernel would expand must be refused");
    match &err {
        vmcell::error::Error::Network(msg) => assert!(
            msg.contains("vmcell-tap-0") && msg.contains(pattern),
            "the error must name both what the kernel chose and what was asked for: {msg}"
        ),
        other => panic!("expected a typed Network error, got {other:?}"),
    }

    // The expanded interface was genuinely created by the ioctl; refusing before TUNSETPERSIST is
    // what removes it. Nothing but `lo` may remain.
    let out = std::process::Command::new("nsenter")
        .arg(format!("--net={}", netns.path().display()))
        .args(["ip", "-o", "link", "show"])
        .output()
        .expect("nsenter ip link must be runnable");
    let links = String::from_utf8_lossy(&out.stdout);
    let names: Vec<&str> = links
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1))
        .collect();
    assert_eq!(
        names,
        vec!["lo:"],
        "a refused expansion must leave the namespace with nothing but lo: {links}"
    );
}
