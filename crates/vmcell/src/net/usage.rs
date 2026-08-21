//! Per-VM network byte counters: the **netns-scoped** usage type (§7.1, What is read and enforced;
//! §17, Open gaps and future capabilities).
//!
//! §7.1 states the separation this module exists to honor: cgroup v2 exposes **no** per-cgroup
//! network accounting, and [`ResourceUsage`](crate::metrics::ResourceUsage)'s read path holds only
//! the cgroup name — not the VM's namespace or interface — so a `net_rx_bytes` field beside
//! `mem_current_mib` could only ever be the always-zero lie that rule forbids. The counters
//! therefore live in their own type, read through their own scope: **one interface, inside one
//! network namespace**.
//!
//! # Which interface, and from whose vantage
//!
//! The interface is the **host-side tap** — the per-VM tap in the VM's own namespace
//! (`<prefix>-tap-<vmid>` in `<prefix>-net-<vmid>`), or the member tap in the shared segment
//! namespace (§6.5, VM-to-VM segments). It is the only end of the wire the host owns: the guest's
//! `eth0` is a device in the guest kernel, reachable only by asking the steward, and it does not
//! exist as a host object at all.
//!
//! A tap's own `rx`/`tx` are named from the **host kernel's** vantage and are therefore *inverted*
//! relative to the guest's:
//!
//! | tap counter | what the kernel counted | what it means for the VM |
//! |---|---|---|
//! | `rx_bytes` | frames the VMM **wrote into** the tap fd | the guest **transmitted** them (egress) |
//! | `tx_bytes` | frames the kernel **sent to** the VMM | the guest **received** them (ingress) |
//!
//! (`tun_get_user` — the write path — bumps the device's *rx* counters; `tun_put_user` — the read
//! path — bumps *tx*.) Reading that table backwards produces numbers that are plausible forever, so
//! [`NetUsage`]'s fields are named from the **guest's** vantage (`guest_tx_bytes` is egress) and the
//! inversion happens in exactly one place — the private `NetUsage::from_tap_stats64`, an
//! implementation detail of [`NetUsageTarget::read`] — with a unit test that reddens if the two are
//! swapped.
//!
//! # Why netlink and not `/sys/class/net/<if>/statistics`
//!
//! §17 sketches this read as `/sys/class/net/<if>/statistics` *inside the VM netns*. **That premise
//! does not hold as written, and the correction is recorded here rather than re-derived**: sysfs's
//! net subsystem is namespace-tagged **per superblock**, captured when the filesystem was
//! *mounted*, not per calling thread. `setns(CLONE_NEWNET)` moves the thread and leaves the
//! inherited `/sys` mount describing the namespace it was mounted in — which is why `ip netns exec`
//! unshares the mount namespace and re-mounts `/sys` ("mount a version of /sys that describes the
//! network namespace", iproute2 `netns_exec`). Observed directly on this tree's host: inside a
//! fresh network namespace holding only `lo`, `ls /sys/class/net` still listed the *root*
//! namespace's `wlp170s0`/`enx…` while `ip link` listed `lo` alone. A sysfs read after a bare
//! `setns` would therefore answer about the root namespace — `ENOENT` for a tap that only exists
//! inside the VM's namespace, and, worse, the **host's** counters for any name that happens to
//! collide.
//!
//! A netlink socket has the opposite and exactly-right property: its namespace is fixed at
//! `socket()` time, which is the documented reason `net_sys::setns_net` exists. So the read
//! is one `RTM_GETLINK` for the named interface, issued from a socket created *after* the move, and
//! `IFLA_STATS64` carries the same `rtnl_link_stats64` fields sysfs would have rendered as text.
//! Nothing in production spells `/sys/class/net`; this module's `counter_reader_gate` holds both
//! halves of that.

use crate::error::{Error, Result};
use futures::stream::TryStreamExt;
use netlink_packet_route::link::{LinkAttribute, Stats64};

/// The `op` every typed refusal from this module carries (§7.2, The fail-loud capability contract
/// and `HostCapabilities`), so a caller matches one string instead of guessing at prose.
const OP: &str = "per-VM network byte counters";

/// Per-VM network byte counters, measured on the VM's **host-side tap** and named from the
/// **guest's** vantage (§7.1, What is read and enforced).
///
/// Produced only by [`NetUsageTarget::read`]. There is deliberately **no** `Default`: an all-zero
/// value is indistinguishable from a real reading of an idle VM, and §7.1's rule 3 — "an unread
/// counter reported as `0` is the same lie as a missing one" — is enforced here by making the
/// unread state *unrepresentable* rather than by a `read_ok` boolean. A counter this type cannot
/// read is an [`Error`], never a zero (see [`NetUsageTarget::read`] for which error).
///
/// The counters are the tap's, so they measure what crossed the **wire**, not what the VM was
/// allowed to do with it: on a `Filtered` egress path a frame the nft ruleset later drops has
/// already been counted here, and a segment member's counters include guest↔guest traffic that
/// never left the segment (§6.5, VM-to-VM segments).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetUsage {
    /// Bytes the **guest transmitted** (egress), i.e. the tap's `rx_bytes`.
    pub guest_tx_bytes: u64,
    /// Frames the **guest transmitted**, i.e. the tap's `rx_packets`.
    pub guest_tx_packets: u64,
    /// Bytes **delivered to the guest** (ingress), i.e. the tap's `tx_bytes`.
    pub guest_rx_bytes: u64,
    /// Frames **delivered to the guest**, i.e. the tap's `tx_packets`.
    pub guest_rx_packets: u64,
}

impl NetUsage {
    /// The **one** place the host-vantage tap counters are re-expressed in the guest's vantage
    /// (`tap.rx → guest.tx`, `tap.tx → guest.rx`).
    ///
    /// A pure function so the inversion is falsifiable without a VM: `tap_counters_are_inverted…`
    /// feeds it four distinct values and reddens if any pair is swapped. Every other route to a
    /// [`NetUsage`] goes through here.
    fn from_tap_stats64(tap: &Stats64) -> Self {
        Self {
            guest_tx_bytes: tap.rx_bytes,
            guest_tx_packets: tap.rx_packets,
            guest_rx_bytes: tap.tx_bytes,
            guest_rx_packets: tap.tx_packets,
        }
    }

    /// What crossed the tap **between** an earlier reading and this one.
    ///
    /// Saturating, and that is the honest arm rather than a convenience: interface counters are
    /// monotonic only for as long as the interface lives, and a tap is created fresh per VM, so
    /// subtracting readings taken across a teardown would otherwise underflow-panic (debug) or wrap
    /// to a nonsense delta (release). A saturated `0` says "nothing I can attribute", which is what
    /// the caller can defend.
    #[must_use]
    pub fn since(&self, earlier: Self) -> Self {
        Self {
            guest_tx_bytes: self.guest_tx_bytes.saturating_sub(earlier.guest_tx_bytes),
            guest_tx_packets: self
                .guest_tx_packets
                .saturating_sub(earlier.guest_tx_packets),
            guest_rx_bytes: self.guest_rx_bytes.saturating_sub(earlier.guest_rx_bytes),
            guest_rx_packets: self
                .guest_rx_packets
                .saturating_sub(earlier.guest_rx_packets),
        }
    }
}

/// One interface inside one network namespace — the scope a [`NetUsage`] read is taken in.
///
/// Built either generally ([`NetUsageTarget::new`], for a harness that wants the bridge's or a
/// second interface's counters) or through the **one per-VM law**, [`NetUsageTarget::for_vm`],
/// which answers "which interface carries *this VM's* traffic" from the same two accessors a
/// `MicroVm` exposes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetUsageTarget {
    netns: String,
    interface: String,
}

impl NetUsageTarget {
    /// A target naming `interface` inside the network namespace `netns` (a `/var/run/netns` name,
    /// never a path — the layout is [`crate::net::tap`]'s law and is composed there).
    #[must_use]
    pub fn new(netns: impl Into<String>, interface: impl Into<String>) -> Self {
        Self {
            netns: netns.into(),
            interface: interface.into(),
        }
    }

    /// The network-namespace name this target reads in.
    #[must_use]
    pub fn netns(&self) -> &str {
        &self.netns
    }

    /// The interface name this target reads.
    #[must_use]
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// **The one law** for which interface carries a VM's traffic, from the two things a VM can
    /// have: its own per-VM namespace ([`NetNamespace`](crate::net::NetNamespace)) or a slot in a
    /// shared segment ([`SegmentMembership`](crate::net::SegmentMembership)). Exactly one of them
    /// is `Some` on a networked privileged VM — pass both accessors straight through and let this
    /// decide, rather than branching at the call site.
    ///
    /// # Errors
    /// * [`Error::CapabilityUnavailable`] when **neither** is present. That is the unprivileged
    ///   smoltcp NAT (§6.1, The two operating modes): its datapath is a vhost-user device and a
    ///   userspace stack, with no tap and no namespace anywhere, so there is no interface whose
    ///   counters could be read. §7.2 rule 2 makes that a typed, matchable refusal naming the
    ///   missing facility — never an all-zero [`NetUsage`], which would read as a measurement.
    ///   `NetConfig::None` reaches the same refusal for the same reason.
    /// * [`Error::Network`] when **both** are present. A VM is in its own namespace or in a
    ///   segment, never both ([`MicroVm::netns`](crate::MicroVm::netns) is documented to be `None`
    ///   for a member), so this is a corrupted caller state and is refused loudly rather than
    ///   silently preferring one.
    pub fn for_vm(
        netns: Option<&crate::net::NetNamespace>,
        membership: Option<&crate::net::SegmentMembership>,
    ) -> Result<Self> {
        match (netns, membership) {
            (Some(ns), None) => Ok(Self::new(ns.name.clone(), ns.tap_name.clone())),
            (None, Some(m)) => Ok(Self::new(m.netns.clone(), m.tap_name.clone())),
            (None, None) => Err(Error::CapabilityUnavailable {
                op: OP.to_string(),
                needed: "a tap interface in a network namespace (the privileged datapath); the \
                         unprivileged smoltcp NAT has neither"
                    .to_string(),
            }),
            (Some(ns), Some(m)) => Err(Error::Network(format!(
                "VM holds both a per-VM netns ({}) and segment membership ({}); exactly one carries \
                 its traffic",
                ns.name, m.netns
            ))),
        }
    }

    /// Reads this target's counters, **inside** its network namespace.
    ///
    /// Blocking, and cheap: it runs one `RTM_GETLINK` on a thread created for the call and joined
    /// before it returns — the same shape every [`Netlink`](crate::net::tap::Netlink) method uses,
    /// and for the same reason (`setns(CLONE_NEWNET)` moves the *calling* thread, so it must never
    /// be a pooled runtime worker). It carries no deadline parameter because it has no remote peer
    /// to wait on: the exchange is a local kernel round-trip on a socket this call created, exactly
    /// like the tap setup beside it.
    ///
    /// # Errors
    /// * [`Error::Network`] if the namespace cannot be opened or entered (no `CAP_SYS_ADMIN`, or the
    ///   namespace is gone), if the netlink exchange fails, or if the interface does not exist in
    ///   that namespace.
    /// * [`Error::CapabilityUnavailable`] if the link exists but the kernel returned no
    ///   `IFLA_STATS64` attribute — an absent facility, reported as one (§7.2 rule 2) rather than
    ///   as zeroed counters.
    pub fn read(&self) -> Result<NetUsage> {
        let interface = self.interface.as_str();
        let stats = crate::net::tap::in_netns(&self.netns, move || {
            crate::net::tap::run_with_rtnetlink(move |handle| async move {
                let msg = handle
                    .link()
                    .get()
                    .match_name(interface.to_string())
                    .execute()
                    .try_next()
                    .await
                    .map_err(|e| format!("get link {interface} err: {e}"))?
                    .ok_or_else(|| format!("link {interface} not found"))?;
                // `Ok(None)` — not a sentinel string — is "the link is there, the kernel sent no
                // IFLA_STATS64", so the caller below can map it to the typed absence without
                // matching on a message fragment (invariant F6).
                Ok(msg.attributes.into_iter().find_map(|attr| match attr {
                    LinkAttribute::Stats64(s) => Some(s),
                    _ => None,
                }))
            })
        })?
        .map_err(Error::Network)?;

        let stats = stats.ok_or_else(|| Error::CapabilityUnavailable {
            op: OP.to_string(),
            needed: format!(
                "IFLA_STATS64 on {} in netns {} (the kernel returned the link without 64-bit \
                 counters)",
                self.interface, self.netns
            ),
        })?;
        Ok(NetUsage::from_tap_stats64(&stats))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Stats64` with four distinct byte/packet values, so no pair of fields can be swapped
    /// without the assertions below moving.
    fn distinct_tap_stats() -> Stats64 {
        let mut s = Stats64::default();
        s.rx_bytes = 1_000_003;
        s.rx_packets = 71;
        s.tx_bytes = 2_000_017;
        s.tx_packets = 113;
        s
    }

    // THE DIRECTION LAW. A tap's counters are the HOST kernel's vantage; `NetUsage`'s are the
    // guest's, and the two are inverted. RED ON THE INVERSE: swap either mapping line in
    // `from_tap_stats64` (`guest_tx_bytes: tap.tx_bytes`) and this reddens — which is the whole
    // point, because a swapped mapping produces numbers that stay plausible forever.
    #[test]
    fn tap_counters_are_inverted_into_the_guests_vantage() {
        let tap = distinct_tap_stats();
        let usage = NetUsage::from_tap_stats64(&tap);
        assert_eq!(
            usage.guest_tx_bytes, tap.rx_bytes,
            "the guest TRANSMITS what the VMM wrote into the tap fd — the tap's rx"
        );
        assert_eq!(usage.guest_tx_packets, tap.rx_packets);
        assert_eq!(
            usage.guest_rx_bytes, tap.tx_bytes,
            "the guest RECEIVES what the kernel sent to the VMM — the tap's tx"
        );
        assert_eq!(usage.guest_rx_packets, tap.tx_packets);
        // …and the four values really are distinct, so the four assertions above are four
        // constraints and not one (a non-vacuity check on this test's own fixture).
        let seen = std::collections::BTreeSet::from([
            usage.guest_tx_bytes,
            usage.guest_tx_packets,
            usage.guest_rx_bytes,
            usage.guest_rx_packets,
        ]);
        assert_eq!(seen.len(), 4, "the fixture must not alias two fields");
    }

    #[test]
    fn since_is_a_per_field_saturating_delta() {
        let earlier = NetUsage::from_tap_stats64(&distinct_tap_stats());
        let mut later_tap = distinct_tap_stats();
        later_tap.rx_bytes += 4096;
        later_tap.tx_packets += 7;
        let later = NetUsage::from_tap_stats64(&later_tap);

        let delta = later.since(earlier);
        assert_eq!(delta.guest_tx_bytes, 4096);
        assert_eq!(delta.guest_rx_packets, 7);
        assert_eq!(delta.guest_rx_bytes, 0);
        assert_eq!(delta.guest_tx_packets, 0);

        // The teardown case: a fresh tap's counters are BELOW the previous one's. Saturating, so
        // this is `0` and not a panic or a wrapped 18-exabyte delta.
        assert_eq!(earlier.since(later).guest_tx_bytes, 0);
    }

    // §7.2 rule 2 / the mode that structurally cannot be read: the unprivileged smoltcp NAT has no
    // tap and no namespace, so the answer is a TYPED refusal naming the absent facility — matched
    // on the VARIANT and its `op` field, never on a substring of the rendered message (F6). RED ON
    // THE INVERSE: return `Ok(Self::new("", ""))` from the `(None, None)` arm and the read that
    // follows would report an interface that does not exist; this reddens first.
    #[test]
    fn the_unprivileged_nat_is_a_typed_capability_refusal() {
        let err = NetUsageTarget::for_vm(None, None)
            .expect_err("no netns and no segment must not yield a target");
        match err {
            Error::CapabilityUnavailable { op, needed } => {
                assert_eq!(op, OP);
                assert!(
                    needed.contains("smoltcp"),
                    "the refusal must name the mode that cannot be read, got {needed:?}"
                );
            }
            other => panic!("expected CapabilityUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn a_segment_member_reads_its_own_tap_in_the_segment_namespace() {
        let membership = crate::net::SegmentMembership {
            netns: "vmcell-seg-3".to_string(),
            tap_name: "vmcell-tap-9".to_string(),
            segid: 3,
            slot: 1,
        };
        let target = NetUsageTarget::for_vm(None, Some(&membership)).expect("segment target");
        assert_eq!(target.netns(), "vmcell-seg-3");
        assert_eq!(target.interface(), "vmcell-tap-9");
    }

    /// A `Netlink` that touches nothing, so [`crate::net::NetNamespace`] — whose `name`/`tap_name`
    /// are what `for_vm` must read — is constructible without `CAP_NET_ADMIN`.
    #[derive(Debug)]
    struct InertNetlink;

    impl crate::net::tap::Netlink for InertNetlink {
        fn add_netns(&self, _name: &str) -> Result<()> {
            Ok(())
        }
        fn setup_tap(&self, _netns: &str, _tap_name: &str, _vmid: u32) -> Result<()> {
            Ok(())
        }
        fn create_bridge(
            &self,
            _netns: &str,
            _bridge: &str,
            _gateway: std::net::Ipv4Addr,
            _prefix_len: u8,
        ) -> Result<()> {
            Ok(())
        }
        fn setup_tap_on_bridge(&self, _netns: &str, _tap: &str, _bridge: &str) -> Result<()> {
            Ok(())
        }
        fn delete_link(&self, _netns: &str, _link: &str) -> Result<()> {
            Ok(())
        }
        fn delete_netns(&self, _name: &str) -> Result<()> {
            Ok(())
        }
        fn setup_tproxy_routing(&self, _netns: &str) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_per_vm_target_is_the_namespaces_own_names_never_a_recomposition() {
        let vmid = 42;
        let ns = crate::net::NetNamespace::create(
            crate::naming::DEFAULT_RESOURCE_PREFIX,
            vmid,
            Box::new(InertNetlink),
        )
        .expect("an inert Netlink cannot fail");
        let target = NetUsageTarget::for_vm(Some(&ns), None).expect("per-VM target");
        // Recomputed through `vmcell::naming` (law F2), never a test-local `format!`.
        assert_eq!(
            target.netns(),
            crate::naming::netns_name(crate::naming::DEFAULT_RESOURCE_PREFIX, vmid)
        );
        assert_eq!(
            target.interface(),
            crate::naming::tap_name(crate::naming::DEFAULT_RESOURCE_PREFIX, vmid)
        );
    }

    // A VM cannot be in two places. RED ON THE INVERSE: make the `(Some, Some)` arm prefer either
    // side and this reddens.
    #[test]
    fn holding_both_a_netns_and_a_membership_is_refused_loudly() {
        let ns = crate::net::NetNamespace::create(
            crate::naming::DEFAULT_RESOURCE_PREFIX,
            7,
            Box::new(InertNetlink),
        )
        .expect("an inert Netlink cannot fail");
        let membership = crate::net::SegmentMembership {
            netns: "vmcell-seg-1".to_string(),
            tap_name: "vmcell-tap-7".to_string(),
            segid: 1,
            slot: 1,
        };
        let err = NetUsageTarget::for_vm(Some(&ns), Some(&membership))
            .expect_err("both cannot be true at once");
        assert!(matches!(err, Error::Network(_)), "got {err:?}");
    }
}

/// Call-site gate for the two halves of "the netns-scoped counter read is spelled once": the
/// `IFLA_STATS64` decode lives in this file alone, and **no** production site reads
/// `/sys/class/net`.
///
/// The second half is not hygiene — it is this module's whole correction. §17 sketched the read as
/// a sysfs read inside the VM netns; sysfs's net view is tagged per **superblock**, so after a bare
/// `setns` it still describes the namespace `/sys` was mounted in (module docs above carry the
/// observation and iproute2's own remount). A future sysfs read would therefore answer about the
/// *root* namespace, and it would look completely reasonable in review. Nothing about writing one
/// is a compile error, so a scan is the only thing that can go red on it.
///
/// Non-vacuity is the audit's own arm, not a side effect: [`audit`] is handed the file set, and an
/// empty set is `gate misconfigured` rather than a clean verdict (the repo's zero-file-scan
/// doctrine, docs/90 G4). `the_audit_reports_an_empty_tree_as_a_misconfiguration` drives exactly
/// that leg.
#[cfg(test)]
mod counter_reader_gate {
    use std::collections::BTreeMap;

    /// The `IFLA_STATS64` decode, as it must appear in the one file that owns it.
    const STATS_NEEDLE: &str = "LinkAttribute::Stats64";

    /// A sysfs net read, with the opening quote so prose and comments (this file is full of both)
    /// are not call sites.
    const SYSFS_NEEDLE: &str = "\"/sys/class/net";

    /// Files the scan must have opened for any verdict to mean anything: the law's own file, the
    /// two other `net` modules a second reader would most plausibly land in, and the orchestrator
    /// that owns `MicroVm`.
    const MUST_SCAN: &[&str] = &[
        "net/usage.rs",
        "net/tap.rs",
        "net/segment.rs",
        "orchestrator.rs",
    ];

    /// `(file relative to `crates/vmcell/src`, production occurrences)` for [`STATS_NEEDLE`].
    /// One row, because there is one reader.
    const STATS_ROSTER: &[(&str, usize)] = &[("net/usage.rs", 1)];

    /// [`SYSFS_NEEDLE`]'s roster is **empty**, and that is the claim: no production site reads
    /// sysfs for net counters, because after `setns` it answers about the wrong namespace.
    const SYSFS_ROSTER: &[(&str, usize)] = &[];

    /// The verdict, as a pure function of the file set — so the misconfiguration arm below is
    /// drivable without deleting the tree.
    ///
    /// `Err` on: an empty scan, a scan that missed a `MUST_SCAN` file, or a roster mismatch in
    /// either direction (an extra call site *and* a law that moved or vanished).
    fn audit(
        sources: &[(String, String)],
        needle: &str,
        roster: &[(&str, usize)],
        must_scan: &[&str],
    ) -> Result<(), String> {
        if sources.is_empty() {
            return Err(format!(
                "gate misconfigured: the scan for {needle:?} read ZERO files. The only way to open \
                 nothing is to have been pointed at nothing; a verdict over an empty tree is \
                 vacuous, not clean"
            ));
        }
        for required in must_scan {
            if !sources.iter().any(|(rel, _)| rel == required) {
                return Err(format!(
                    "gate misconfigured: the scan for {needle:?} never read {required}; it is \
                     walking the wrong tree and would pass vacuously"
                ));
            }
        }
        let found: BTreeMap<&str, usize> = sources
            .iter()
            .map(|(rel, text)| (rel.as_str(), text.matches(needle).count()))
            .filter(|(_, count)| *count > 0)
            .collect();
        let expected: BTreeMap<&str, usize> = roster.iter().copied().collect();
        if found == expected {
            Ok(())
        } else {
            Err(format!(
                "the {needle:?} law must be spelled ONLY by its roster. found={found:?} \
                 expected={expected:?}. An extra entry is a second reader — route it through \
                 `NetUsageTarget::read` / `NetUsage::from_tap_stats64` instead. A missing or moved \
                 entry means the law itself was renamed or relocated; move the row with it in the \
                 same change"
            ))
        }
    }

    #[test]
    fn the_stats64_decode_is_spelled_once() {
        let sources = crate::net::tap::netns_layout_gate::production_sources();
        audit(&sources, STATS_NEEDLE, STATS_ROSTER, MUST_SCAN).expect("stats64 reader roster");
    }

    #[test]
    fn no_production_site_reads_sysfs_for_net_counters() {
        let sources = crate::net::tap::netns_layout_gate::production_sources();
        audit(&sources, SYSFS_NEEDLE, SYSFS_ROSTER, MUST_SCAN).expect("sysfs net-counter roster");
    }

    // THE ZERO-FILE ARM, driven rather than asserted about: an empty file set is a loud
    // misconfiguration, never a green `ok`. RED ON THE INVERSE: delete `audit`'s `sources.is_empty()`
    // guard and this test's first leg starts returning `Ok(())` for the sysfs needle, whose roster
    // is empty and therefore matches an empty scan perfectly — which is exactly how a gate wears a
    // green verdict on a tree it never read.
    #[test]
    fn the_audit_reports_an_empty_tree_as_a_misconfiguration() {
        let empty: Vec<(String, String)> = Vec::new();
        let err = audit(&empty, SYSFS_NEEDLE, SYSFS_ROSTER, MUST_SCAN)
            .expect_err("an empty tree must not be a clean verdict");
        assert!(err.contains("gate misconfigured"), "got {err}");

        // …and a non-empty scan that simply missed the law's own file is the same class of
        // misconfiguration, not a passing tree.
        let partial = vec![("net/segment.rs".to_string(), String::new())];
        let err = audit(&partial, STATS_NEEDLE, STATS_ROSTER, MUST_SCAN)
            .expect_err("a scan missing the law's file must not pass");
        assert!(err.contains("gate misconfigured"), "got {err}");
    }

    // The needles are countable, and prose is not a call site — the comparison both rosters rest on.
    #[test]
    fn the_gate_reddens_on_a_second_reader_and_on_a_re_planted_sysfs_read() {
        let smuggled_stats = "match a { LinkAttribute::Stats64(s) => s.rx_bytes, _ => 0 }";
        let mut sources: Vec<(String, String)> = MUST_SCAN
            .iter()
            .map(|f| ((*f).to_string(), String::new()))
            .collect();
        sources[0].1 = STATS_NEEDLE.to_string();
        let mut with_second = sources.clone();
        with_second[2].1 = smuggled_stats.to_string();
        assert!(
            audit(&sources, STATS_NEEDLE, STATS_ROSTER, MUST_SCAN).is_ok(),
            "the roster must accept exactly its one reader"
        );
        assert!(
            audit(&with_second, STATS_NEEDLE, STATS_ROSTER, MUST_SCAN).is_err(),
            "a second decode site must redden"
        );

        let mut with_sysfs = sources.clone();
        with_sysfs[1].1 = "std::fs::read(\"/sys/class/net/eth0/statistics/rx_bytes\")".to_string();
        assert!(
            audit(&with_sysfs, SYSFS_NEEDLE, SYSFS_ROSTER, MUST_SCAN).is_err(),
            "a re-planted sysfs read must redden"
        );
        let prose = "// /sys/class/net is namespace-tagged per superblock";
        let mut with_prose = sources.clone();
        with_prose[1].1 = prose.to_string();
        assert!(
            audit(&with_prose, SYSFS_NEEDLE, SYSFS_ROSTER, MUST_SCAN).is_ok(),
            "a comment is not a call site — the needle carries the opening quote"
        );
    }
}
