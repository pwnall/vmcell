//! VM-to-VM segments (§6.5, VM-to-VM segments) — the opt-in shared L2 domain two guests reach each
//! other through.
//!
//! A segment is **where the taps live**, not a new datapath: one network namespace per segment
//! (`<prefix>-seg-<segid>`) holding one Linux bridge (`<prefix>-br-<segid>`) with the gateway
//! address, and each member's tap (still `<prefix>-tap-<vmid>`, still `TUNSETPERSIST`'d and opened
//! only by the VMM) created *in that namespace* and enslaved to the bridge. The VMM child enters
//! the namespace through the same `build_vmm_cmd` pre-exec `setns` a per-VM namespace uses — a
//! different namespace *name*, zero new spawn logic — and the guest still learns its address from
//! the kernel `ip=` token, so PID 1 grows no netlink and no new code (law C6).
//!
//! Lifetime is `Arc`-ownership: every member `MicroVm` holds a clone of the [`NetSegment`] handle,
//! so the namespace and bridge are removed only when the **last** holder drops. That makes the
//! "never delete a netns under a live VMM" hazard structural rather than a rule: a member's
//! teardown necessarily precedes the segment's, because the member holds the `Arc`. Member
//! teardown releases the member's *slot* and *tap*; it never touches the namespace.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::net::tap::Netlink;

/// The prefix length of a segment's shared subnet (`10.201.<s>.0/24`, §6.5).
const SEGMENT_PREFIX_LEN: u8 = 24;

/// What [`NetConfig::Segment`](crate::config::NetConfig::Segment) carries.
///
/// An alias rather than a distinct type: the handle is already cheap to clone (one `Arc`), so a
/// separate reference wrapper would only add a layer.
pub type NetSegmentRef = NetSegment;

/// One member's place in a segment, carried on the exhaustive
/// [`PerVmResources`](crate::vmm::PerVmResources) so every backend must acknowledge segments to
/// compile, and read by
/// [`build_kernel_cmdline`](crate::config::build_kernel_cmdline) to emit the member's `ip=` token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentMembership {
    /// The segment's network-namespace name (`<prefix>-seg-<segid>`) — the namespace the VMM
    /// `setns`es into, in place of a per-VM one.
    pub netns: String,
    /// This member's tap inside that namespace (`<prefix>-tap-<vmid>`).
    pub tap_name: String,
    /// The segment id, which drives the third octet via
    /// [`segment_ip_math`](crate::net::segment_ip_math).
    pub segid: u32,
    /// This member's 1-based slot in the segment, which drives the host octet (`.slot + 1`).
    pub slot: u32,
}

impl SegmentMembership {
    /// The member's IPv4 address, its gateway (the bridge), and its CIDR — through the one
    /// [`segment_ip_math`](crate::net::segment_ip_math) law.
    ///
    /// # Errors
    /// Propagates the range errors of [`segment_ip_math`](crate::net::segment_ip_math).
    pub fn addresses(&self) -> Result<(Ipv4Addr, Ipv4Addr, String)> {
        crate::net::segment_ip_math(self.segid, self.slot)
    }
}

// -------------------------------------------------------------------------------------------
// Link impairment (design §17, Segment refinements — "a typed netem/impairment API")
// -------------------------------------------------------------------------------------------

/// The iproute2 binary the impairment transport shells out to.
const TC_BINARY: &str = "tc";

/// The ceiling on a single [`Impairment`] delay or jitter component.
///
/// Not a taste call: `netem`'s classic `tc_netem_qopt.latency`/`jitter` fields are **u32 psched
/// ticks**, and on the ~1 ns/tick clock every modern kernel runs, a value at or above 2³² ns
/// (≈4.295 s) is unrepresentable in them — beyond it `tc` depends on the optional 64-bit
/// attributes, so what the kernel installs stops being a property of this API. Four seconds is the
/// largest whole second inside that bound. An over-ceiling delay is refused at construction rather
/// than accepted and silently reinterpreted, which is also the shape that catches the units bug
/// (`from_secs` where `from_millis` was meant).
pub const MAX_IMPAIRMENT_DELAY: Duration = Duration::from_secs(4);

/// A **link impairment**: what gets applied to one segment member's tap, as a first-class value
/// rather than a hand-spelled `tc` argv (design §17, Segment refinements).
///
/// Apply one with [`NetSegment::impair_member`] and remove it with
/// [`NetSegment::clear_impairment`]. Every field is validated at construction
/// ([`ImpairmentBuilder::build`]), so an impairment that exists is an impairment `tc` will accept.
///
/// # Direction
///
/// `netem` shapes **egress** from the interface it sits on, and a member's tap is written by the
/// host bridge — so an impairment on member *X* degrades the traffic flowing **toward X's guest**,
/// not away from it. A round-trip test therefore impairs *both* members' taps; a one-sided
/// partition needs only one.
///
/// # Transport, and what it does not give you
///
/// The impairment is installed by running `tc` inside the segment's network namespace, not over
/// `rtnetlink`. That is a deliberate, recorded limit rather than an oversight: the `rtnetlink`
/// stack in this tree (`netlink-packet-route` 0.33) types exactly two qdiscs — `fq_codel` and
/// `ingress` — and `TcOption::Other(DefaultNla)` is the only door left for netem, i.e. exactly the
/// hand-assembled `TcMessage`s design §17 records as this item's blocker. Verified against the
/// version in the lockfile, not assumed. So this type makes the **surface** typed — one validated
/// value, one composer, one call site per segment — while the **transport** stays a subprocess.
///
/// What that costs: a `fork`/`exec` per call; a dependency on iproute2 being installed (an absent
/// `tc` is a typed [`Error::CapabilityUnavailable`], an absent facility, never a silent no-op); and
/// diagnostics that are `tc`'s stderr rather than a kernel errno. It is the same shape, and the
/// same precedent, as this module's `nft` rule application. What it does give: the impairment is a
/// value that can be built, compared, logged and passed around; the netem argv is composed in
/// exactly one place ([`Impairment::netem_args`]) instead of once per harness; and a nonsense
/// impairment is refused before any host state is touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Impairment {
    delay: Option<Duration>,
    jitter: Option<Duration>,
    loss_percent: Option<u8>,
}

impl Impairment {
    /// Starts building an impairment. At least one component must be set before
    /// [`ImpairmentBuilder::build`].
    #[must_use]
    pub fn builder() -> ImpairmentBuilder {
        ImpairmentBuilder {
            delay: None,
            jitter: None,
            loss_percent: None,
        }
    }

    /// The one-way delay this impairment adds, if any.
    #[must_use]
    pub fn delay(&self) -> Option<Duration> {
        self.delay
    }

    /// The delay jitter, if any. Only ever `Some` alongside [`Impairment::delay`].
    #[must_use]
    pub fn jitter(&self) -> Option<Duration> {
        self.jitter
    }

    /// The whole-percent packet loss this impairment applies, if any.
    #[must_use]
    pub fn loss_percent(&self) -> Option<u8> {
        self.loss_percent
    }

    /// The `netem` parameter words this impairment means — **the one composer**, and the only
    /// place in the tree that spells a netem argv (`scripts/ban-inline-netem-argv.sh` is that
    /// law's grep-ban).
    ///
    /// Public so a harness that must drive `tc` itself — a different namespace, a different
    /// interface, an `ingress` mirred setup — composes the same words instead of writing a second,
    /// divergent copy. Returns the parameters *after* the literal `netem`, in `tc`'s own usage
    /// order (delay, then jitter as delay's positional second argument, then loss).
    ///
    /// Durations render in **microseconds**, `netem`'s finest unit: milliseconds would silently
    /// floor a sub-millisecond delay to `0ms`, which `tc` accepts and the kernel then ignores.
    #[must_use]
    pub fn netem_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(delay) = self.delay {
            args.push("delay".to_string());
            args.push(format!("{}us", delay.as_micros()));
            // `netem`'s jitter is delay's positional second argument, never a `jitter` keyword —
            // `tc` rejects `jitter` outright, which is why it is composed here and not by a caller.
            if let Some(jitter) = self.jitter {
                args.push(format!("{}us", jitter.as_micros()));
            }
        }
        if let Some(loss) = self.loss_percent {
            args.push("loss".to_string());
            args.push(format!("{loss}%"));
        }
        args
    }
}

/// Builder for [`Impairment`]. Every accepted value is honored or rejected at
/// [`build`](ImpairmentBuilder::build).
#[derive(Debug, Clone)]
pub struct ImpairmentBuilder {
    delay: Option<Duration>,
    jitter: Option<Duration>,
    loss_percent: Option<u8>,
}

impl ImpairmentBuilder {
    /// Adds a fixed one-way delay to traffic entering the impaired member's guest.
    #[must_use]
    pub fn delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    /// Adds uniform jitter around [`delay`](ImpairmentBuilder::delay), which must also be set.
    #[must_use]
    pub fn jitter(mut self, jitter: Duration) -> Self {
        self.jitter = Some(jitter);
        self
    }

    /// Drops `percent` of the packets entering the impaired member's guest. `100` is a full
    /// partition.
    #[must_use]
    pub fn loss_percent(mut self, percent: u8) -> Self {
        self.loss_percent = Some(percent);
        self
    }

    /// Validates and freezes the impairment.
    ///
    /// # Errors
    /// [`Error::Config`] when the impairment names nothing (a no-op the caller did not mean —
    /// removing an impairment is [`NetSegment::clear_impairment`], not an empty one), when a delay
    /// or jitter is zero or exceeds [`MAX_IMPAIRMENT_DELAY`], when jitter is set without a delay
    /// (`netem` has no such shape — `tc` refuses it), or when loss exceeds 100 percent.
    pub fn build(self) -> Result<Impairment> {
        for (what, value) in [("delay", self.delay), ("jitter", self.jitter)] {
            let Some(value) = value else { continue };
            if value.is_zero() {
                return Err(Error::Config(format!(
                    "impairment {what} must be non-zero: a zero {what} is an impairment that does \
                     not impair, which `tc` accepts and the kernel then ignores"
                )));
            }
            if value > MAX_IMPAIRMENT_DELAY {
                return Err(Error::Config(format!(
                    "impairment {what} {value:?} exceeds the {MAX_IMPAIRMENT_DELAY:?} ceiling \
                     netem's u32 psched-tick field can represent"
                )));
            }
        }
        if self.jitter.is_some() && self.delay.is_none() {
            return Err(Error::Config(
                "impairment jitter needs a delay to vary around: netem carries jitter as delay's \
                 positional second argument and has no jitter-only shape"
                    .to_string(),
            ));
        }
        if let Some(loss) = self.loss_percent
            && loss > 100
        {
            return Err(Error::Config(format!(
                "impairment loss {loss}% exceeds 100%"
            )));
        }
        if self.delay.is_none() && self.loss_percent.is_none() {
            return Err(Error::Config(
                "an impairment must name at least one of delay or loss; use \
                 NetSegment::clear_impairment to remove one"
                    .to_string(),
            ));
        }
        Ok(Impairment {
            delay: self.delay,
            jitter: self.jitter,
            loss_percent: self.loss_percent,
        })
    }
}

/// Renders a `tc` invocation that ran and refused, naming the argv and its stderr — one renderer,
/// so both impairment verbs report the same shape.
fn tc_failed(what: &str, args: &[String], out: &std::process::Output) -> Error {
    let code = out
        .status
        .code()
        .map_or_else(|| "terminated by signal".to_string(), |c| c.to_string());
    Error::Subprocess(format!(
        "{what} failed: `{TC_BINARY} {}` exited {code}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    ))
}

/// Turns a failed `tc` **spawn** into the typed error its cause deserves (§7.2 capability honesty):
/// an absent binary is an absent *facility*, not a broken one.
fn classify_tc_spawn_error(e: std::io::Error) -> Error {
    if e.kind() == std::io::ErrorKind::NotFound {
        return Error::CapabilityUnavailable {
            op: "segment link impairment".to_string(),
            needed: format!(
                "the iproute2 `{TC_BINARY}` binary on PATH (install iproute2); the impairment \
                 transport is a subprocess because the rtnetlink stack types no netem options"
            ),
        };
    }
    Error::Io(e)
}

/// The state one segment owns, released in [`Drop`] when the last [`NetSegment`] handle goes.
struct SegmentInner {
    prefix: String,
    netns: String,
    bridge: String,
    gateway: Ipv4Addr,
    /// Slots currently handed out (1-based) and the **vmid** occupying each. A member's slot
    /// returns here on its teardown, so a long-lived segment recycles addresses instead of
    /// exhausting them; the vmid is carried so [`NetSegment::claim_member`] can refuse a second
    /// member with a vmid this segment already holds (two equal vmids name **one** tap in **one**
    /// namespace).
    slots: Mutex<std::collections::BTreeMap<u32, u32>>,
    netlink: Box<dyn Netlink>,
    /// Releases the segment id when the segment dies. Declared last so it drops *after* the
    /// namespace removal below — the id must not be reusable while its namespace still exists.
    segid_guard: crate::orchestrator::SegmentIdGuard,
}

impl Drop for SegmentInner {
    fn drop(&mut self) {
        // The last holder is gone, so no VMM can still be inside: every member `MicroVm` holds an
        // `Arc` clone, and a member releases it only after its own VMM process group is reaped.
        // Removing the namespace also reaps the bridge and any tap still inside it.
        if let Err(e) = self.netlink.delete_netns(&self.netns) {
            tracing::warn!(
                "NetSegment drop: failed to delete segment netns {}: {}",
                self.netns,
                e
            );
        }
    }
}

/// A shared L2 segment: a cheap-clone, RAII handle to one netns + bridge (§6.5).
///
/// Create one with [`NetSegment::new`], hand a clone to each member VM through
/// [`NetConfig::Segment`](crate::config::NetConfig::Segment), and drop them all to reclaim the
/// namespace.
#[derive(Clone)]
pub struct NetSegment(Arc<SegmentInner>);

impl std::fmt::Debug for NetSegment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The injected `Netlink` is not `Debug`; print the identity that matters.
        f.debug_struct("NetSegment")
            .field("netns", &self.0.netns)
            .field("bridge", &self.0.bridge)
            .field("gateway", &self.0.gateway)
            .field("segid", &self.0.segid_guard.segid)
            .finish_non_exhaustive()
    }
}

/// Handle **identity**, not structural equality: two handles compare equal exactly when they point
/// at the same segment (`Arc::ptr_eq`).
///
/// Required because [`NetConfig`](crate::config::NetConfig) derives `PartialEq`/`Eq`. The same
/// discipline [`Lineage`](crate::Lineage)'s cross-allocator ancestry check uses: two *different*
/// segments that happen to hold equal ids (from two allocators) are never equal.
impl PartialEq for NetSegment {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for NetSegment {}

impl NetSegment {
    /// Creates a segment: claims a segment id from `env.segids`, creates the namespace
    /// `<prefix>-seg-<segid>` holding the bridge `<prefix>-br-<segid>` with the gateway address,
    /// ready for members.
    ///
    /// `prefix` goes through the **same** single validator
    /// [`VmConfigBuilder::build`](crate::config::VmConfigBuilder::build) uses
    /// ([`validate_resource_prefix`](crate::naming::validate_resource_prefix)) — one law; the F2
    /// name/sweep lockstep and the `IFNAMSIZ` budget both rest on it.
    ///
    /// # Errors
    /// - [`Error::Config`] if `prefix` is invalid.
    /// - [`Error::CapabilityUnavailable`] if the host does not offer the privileged network
    ///   datapath (`CAP_NET_ADMIN` + `CAP_SYS_ADMIN` + a reachable `/var/run/netns`) — segments are
    ///   privileged-capability-class only, and this is probed, never presumed.
    /// - [`Error::Exhaustion`] if no segment id is free, or [`Error::Network`] if the namespace or
    ///   bridge cannot be created.
    pub fn new(prefix: &str, env: &crate::env::HostEnv) -> Result<Self> {
        let caps = crate::hostcaps::HostCapabilities::probe();
        if !caps.privileged_net_available() {
            return Err(Error::CapabilityUnavailable {
                op: "vm-to-vm segment creation".to_string(),
                needed: "effective CAP_NET_ADMIN and CAP_SYS_ADMIN and a reachable /var/run/netns \
                         (segments are privileged-capability-class; run under the blessed \
                         capability runner, `just bless`)"
                    .to_string(),
            });
        }
        Self::create_with_netlink(prefix, env, Box::new(crate::net::tap::RtNetlink))
    }

    /// The seam-injected constructor, for in-crate unit tests only: no capability probe, so the
    /// whole create → claim → teardown ordering is drivable through a recording [`Netlink`] fake
    /// with no privileges and no kernel.
    #[cfg(test)]
    pub(crate) fn with_netlink_for_test(
        prefix: &str,
        env: &crate::env::HostEnv,
        netlink: Box<dyn Netlink>,
    ) -> Result<Self> {
        Self::create_with_netlink(prefix, env, netlink)
    }

    /// The seam-injected constructor behind [`NetSegment::new`]: everything except the capability
    /// probe, so a unit test can drive the whole create/claim/teardown ordering through a recording
    /// [`Netlink`] fake with no privileges.
    fn create_with_netlink(
        prefix: &str,
        env: &crate::env::HostEnv,
        netlink: Box<dyn Netlink>,
    ) -> Result<Self> {
        crate::naming::validate_resource_prefix(prefix).map_err(Error::Config)?;

        let segid_guard = crate::orchestrator::SegmentIdGuard::claim(&env.segids)?;
        let segid = segid_guard.segid;
        let netns = crate::naming::segment_netns_name(prefix, segid);
        let bridge = crate::naming::segment_bridge_name(prefix, segid);
        // Slot 1 is the first member; the gateway is `.1` and belongs to the bridge.
        let (gateway, _, _) = crate::net::segment_ip_math(segid, 1)?;

        netlink.add_netns(&netns)?;
        // Same discipline as `NetNamespace::create`: `Self` is not constructed yet, so `Drop`
        // cannot reclaim the namespace — tear it back down here if the bridge fails.
        if let Err(e) = netlink.create_bridge(&netns, &bridge, gateway, SEGMENT_PREFIX_LEN) {
            if let Err(cleanup_err) = netlink.delete_netns(&netns) {
                tracing::warn!(
                    "NetSegment::new: failed to clean up netns {} after create_bridge error: {}",
                    netns,
                    cleanup_err
                );
            }
            return Err(e);
        }

        Ok(Self(Arc::new(SegmentInner {
            prefix: prefix.to_string(),
            netns,
            bridge,
            gateway,
            slots: Mutex::new(std::collections::BTreeMap::new()),
            netlink,
            segid_guard,
        })))
    }

    /// The resource prefix this segment was created with.
    ///
    /// [`VmConfigBuilder::build`](crate::config::VmConfigBuilder::build) refuses a member whose own
    /// `resource_prefix` differs, so one prefix names — and sweeps — every resource in the domain
    /// (law F2).
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.0.prefix
    }

    /// This segment's id (`1..=`[`crate::net::MAX_SEGMENT_ID`]).
    #[must_use]
    pub fn segid(&self) -> u32 {
        self.0.segid_guard.segid
    }

    /// The segment's network-namespace name (`<prefix>-seg-<segid>`).
    #[must_use]
    pub fn netns_name(&self) -> &str {
        &self.0.netns
    }

    /// The segment's network-namespace path, for a harness's own tooling — e.g.
    /// `nsenter --net=<path> ip -o link show`. Link impairment has a typed surface of its own
    /// ([`NetSegment::impair_member`]) and does not need this.
    #[must_use]
    pub fn netns_path(&self) -> std::path::PathBuf {
        // One law: the `/var/run/netns` layout is composed in exactly one place, shared with the
        // module's own namespace-entry helper (`net::tap::in_netns`).
        crate::net::tap::netns_path(&self.0.netns)
    }

    /// The bridge interface name (`<prefix>-br-<segid>`), a stable documented accessor.
    #[must_use]
    pub fn bridge_name(&self) -> &str {
        &self.0.bridge
    }

    /// The gateway address the bridge holds: `10.201.<s>.1`, the host side of the segment.
    #[must_use]
    pub fn gateway(&self) -> Ipv4Addr {
        self.0.gateway
    }

    /// The member slots currently handed out (1-based), for assertions and diagnostics.
    #[must_use]
    pub fn active_slots(&self) -> std::collections::BTreeSet<u32> {
        self.0
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .copied()
            .collect()
    }

    /// Claims a member slot and creates `vmid`'s tap inside the segment namespace, enslaved to the
    /// bridge and carrying **no** address of its own.
    ///
    /// Returns the RAII [`SegmentMember`] whose `Drop` deletes the tap and returns the slot; it is
    /// released through the orchestrator's one ordered teardown helper (law L1), and it never
    /// touches the namespace — that dies with the last handle.
    ///
    /// # Errors
    /// - [`Error::Config`] if `vmid` already holds a slot in **this** segment: a member's tap name
    ///   is `<prefix>-tap-<vmid>` and every member's tap lives in the one shared namespace, so two
    ///   members with equal vmids would name a single interface — the live member's. Refused here,
    ///   **before** any host state is touched (an accepted input is honored or rejected at
    ///   construction), rather than surfacing later as the second create's `EBUSY`.
    /// - [`Error::Exhaustion`] when all [`crate::net::MAX_SEGMENT_SLOT`] slots are taken, or
    /// - [`Error::Network`] if the tap cannot be created or enslaved.
    pub(crate) fn claim_member(&self, vmid: u32) -> Result<SegmentMember> {
        let tap_name = crate::naming::tap_name(&self.0.prefix, vmid);
        let slot = {
            let mut slots = self.0.slots.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((held, _)) = slots.iter().find(|(_, held_vmid)| **held_vmid == vmid) {
                return Err(crate::error::Error::Config(format!(
                    "vmid {vmid} already holds slot {held} in segment {}: one tap ({tap_name}) per \
                     vmid per segment namespace, so a second member with this vmid would resolve \
                     to the live member's interface",
                    self.0.netns
                )));
            }
            let free = (1..=crate::net::MAX_SEGMENT_SLOT).find(|s| !slots.contains_key(s));
            let Some(slot) = free else {
                return Err(crate::error::Error::Exhaustion(format!(
                    "segment {} has no free member slot (limit {})",
                    self.0.netns,
                    crate::net::MAX_SEGMENT_SLOT
                )));
            };
            slots.insert(slot, vmid);
            slot
        };

        let membership = SegmentMembership {
            netns: self.0.netns.clone(),
            tap_name: tap_name.clone(),
            segid: self.segid(),
            slot,
        };

        if let Err(e) = self
            .0
            .netlink
            .setup_tap_on_bridge(&self.0.netns, &tap_name, &self.0.bridge)
        {
            // `SegmentMember` is never constructed on this path, so its `Drop` cannot reclaim
            // anything — the same discipline `NetNamespace::create` uses. The half-created tap is
            // reclaimed by `setup_tap_on_bridge` itself, which is the only party that knows
            // whether it created one: unlike a per-VM namespace, a segment namespace **pre-exists
            // and is shared**, so a delete-by-name here would remove a live sibling member's tap
            // whenever the failure is "that interface already exists". Only the slot is ours to
            // return.
            self.release_slot(slot);
            return Err(e);
        }

        Ok(SegmentMember {
            segment: self.clone(),
            membership,
        })
    }

    /// Returns `slot` to the free list.
    fn release_slot(&self, slot: u32) {
        self.0
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&slot);
    }

    /// Applies `impairment` to member `vmid`'s tap inside the segment namespace (design §17,
    /// Segment refinements).
    ///
    /// Idempotent by construction — it `replace`s the tap's root qdisc, so calling it twice, or
    /// changing an impairment in place, is one call and not an add-after-delete dance.
    ///
    /// Degrades traffic flowing **toward** `vmid`'s guest; see [`Impairment`] for why, and for what
    /// the subprocess transport costs. Blocks for the lifetime of one `tc` invocation.
    ///
    /// # Errors
    /// - [`Error::Config`] if `vmid` holds no slot in this segment — refused before any host state
    ///   is touched, rather than surfacing as `tc`'s "Cannot find device".
    /// - [`Error::CapabilityUnavailable`] if the iproute2 `tc` binary is absent (an absent
    ///   facility, §7.2), or [`Error::Io`] with the errno intact if it cannot be spawned.
    /// - [`Error::Subprocess`] carrying `tc`'s exit status and stderr if it refuses the request —
    ///   the shape a missing `sch_netem` module or an absent `CAP_NET_ADMIN` takes.
    /// - [`Error::Network`] if the segment namespace cannot be entered.
    pub fn impair_member(&self, vmid: u32, impairment: &Impairment) -> Result<()> {
        let tap = self.member_tap(vmid)?;
        let mut args = vec![
            "qdisc".to_string(),
            "replace".to_string(),
            "dev".to_string(),
            tap,
            "root".to_string(),
            "netem".to_string(),
        ];
        args.extend(impairment.netem_args());
        let out = self.run_tc(&args)?;
        if !out.status.success() {
            return Err(tc_failed("applying the impairment", &args, &out));
        }
        Ok(())
    }

    /// Removes any impairment from member `vmid`'s tap, restoring the unimpaired link.
    ///
    /// Idempotent: clearing a tap that carries no impairment succeeds. That is decided by
    /// **re-reading the tap's qdisc** when the delete fails — the postcondition, not iproute2's
    /// error text, which is not an interface this can depend on.
    ///
    /// # Errors
    /// The same set as [`NetSegment::impair_member`]; [`Error::Subprocess`] only when the delete
    /// failed *and* an impairment is still installed afterwards.
    pub fn clear_impairment(&self, vmid: u32) -> Result<()> {
        let tap = self.member_tap(vmid)?;
        let del = vec![
            "qdisc".to_string(),
            "delete".to_string(),
            "dev".to_string(),
            tap.clone(),
            "root".to_string(),
        ];
        let out = self.run_tc(&del)?;
        if out.status.success() {
            return Ok(());
        }
        // The postcondition is "no netem on this tap", and deleting a root qdisc that was never
        // there fails while satisfying it. Ask the kernel rather than parse the complaint.
        let show = vec![
            "qdisc".to_string(),
            "show".to_string(),
            "dev".to_string(),
            tap,
        ];
        let listed = self.run_tc(&show)?;
        if listed.status.success() && !String::from_utf8_lossy(&listed.stdout).contains("netem") {
            return Ok(());
        }
        Err(tc_failed("clearing the impairment", &del, &out))
    }

    /// The tap name of the member holding `vmid`'s slot — the accepted-input check both impairment
    /// verbs share, so a non-member is refused at the API boundary, not by `tc`.
    fn member_tap(&self, vmid: u32) -> Result<String> {
        let held = {
            let slots = self.0.slots.lock().unwrap_or_else(|e| e.into_inner());
            slots.values().any(|held| *held == vmid)
        };
        if !held {
            return Err(Error::Config(format!(
                "vmid {vmid} is not a member of segment {}: impairment names a member, and its \
                 tap is created only when the member claims its slot",
                self.0.netns
            )));
        }
        Ok(crate::naming::tap_name(&self.0.prefix, vmid))
    }

    /// Runs `tc <args…>` inside the segment namespace.
    ///
    /// Entered through the module's one `setns` helper (a dedicated thread, joined before this
    /// returns), so the child inherits the namespace with no `nsenter` dependency of its own. The
    /// subprocess is unbounded for the same reason this module's `nft` application is: `tc` is a
    /// local utility that performs one netlink transaction and exits — it blocks on no network I/O
    /// and no guest.
    fn run_tc(&self, args: &[String]) -> Result<std::process::Output> {
        let owned: Vec<String> = args.to_vec();
        let spawned = crate::net::tap::in_netns(&self.0.netns, move || {
            std::process::Command::new(TC_BINARY).args(&owned).output()
        })?;
        spawned.map_err(classify_tc_spawn_error)
    }

    /// Dials a TCP listener inside a member guest **from the host** (FR-V3's privileged shape).
    ///
    /// A socket's network namespace is fixed at `socket()` time, so the socket is created on a
    /// dedicated thread that has `setns`'d into the segment namespace — the §6.4 proxy's pattern,
    /// minus its re-entry step: this thread exists only for this dial and terminates immediately
    /// afterwards, so there is no later socket that could be trapped in the wrong namespace (the
    /// proxy re-enters because its thread goes on to originate upstream connections). The connected
    /// socket is handed back to the caller's runtime, where it keeps its segment binding.
    ///
    /// Bounded and typed, never a hang: `timeout` bounds the connect.
    ///
    /// # Errors
    /// [`Error::Timeout`] naming the address when the connect does not complete within `timeout`,
    /// [`Error::Io`] (errno intact) when the connect is refused or the namespace cannot be entered,
    /// and [`Error::Network`] if the dialing thread itself fails.
    pub async fn dial_tcp(
        &self,
        addr: SocketAddrV4,
        timeout: Duration,
    ) -> Result<tokio::net::TcpStream> {
        let netns_path = self.netns_path();
        let (tx, rx) = tokio::sync::oneshot::channel::<Result<std::net::TcpStream>>();

        // A DEDICATED thread, never `spawn_blocking`: `setns` moves the calling thread, and a
        // pooled runtime worker would keep the segment namespace for every later blocking task.
        std::thread::spawn(move || {
            let result = (|| -> Result<std::net::TcpStream> {
                use std::os::fd::AsRawFd;
                let ns = std::fs::File::open(&netns_path).map_err(|e| {
                    Error::Io(std::io::Error::new(
                        e.kind(),
                        format!("open segment netns {}: {e}", netns_path.display()),
                    ))
                })?;
                crate::net_sys::setns_net(ns.as_raw_fd()).map_err(|e| {
                    Error::Io(std::io::Error::new(
                        e.kind(),
                        format!("setns into segment netns {}: {e}", netns_path.display()),
                    ))
                })?;
                let sock =
                    std::net::TcpStream::connect_timeout(&std::net::SocketAddr::V4(addr), timeout)
                        .map_err(|e| match e.kind() {
                            std::io::ErrorKind::TimedOut => {
                                Error::Timeout(format!("segment dial_tcp to {addr} timed out"))
                            }
                            _ => Error::Io(std::io::Error::new(
                                e.kind(),
                                format!("segment dial_tcp to {addr}: {e}"),
                            )),
                        })?;
                sock.set_nonblocking(true)?;
                Ok(sock)
            })();
            // The receiver is dropped only if the caller was cancelled; nothing to report.
            #[expect(
                clippy::let_underscore_must_use,
                reason = "the receiver is dropped only when the caller was cancelled, and rx.await already maps that to a typed error"
            )]
            let _ = tx.send(result);
        });

        let std_stream = rx.await.map_err(|_| {
            Error::Network(format!(
                "segment dial_tcp worker thread died before answering (addr {addr})"
            ))
        })??;
        Ok(tokio::net::TcpStream::from_std(std_stream)?)
    }
}

/// One VM's membership in a segment: the RAII guard that owns the member's **slot** and **tap**.
///
/// Held by the orchestrator alongside the VM and released through the one ordered teardown helper
/// (law L1) after the VMM process group is reaped. It deliberately does **not** delete the segment
/// namespace — that dies with the last [`NetSegment`] handle, of which this guard holds one, which
/// is what makes "never delete a netns under a live VMM" structural.
#[derive(Debug)]
pub struct SegmentMember {
    segment: NetSegment,
    membership: SegmentMembership,
}

impl SegmentMember {
    /// The membership descriptor handed to the backends via
    /// [`PerVmResources`](crate::vmm::PerVmResources).
    #[must_use]
    pub fn membership(&self) -> &SegmentMembership {
        &self.membership
    }

    /// The segment this VM is a member of.
    #[must_use]
    pub fn segment(&self) -> &NetSegment {
        &self.segment
    }
}

impl Drop for SegmentMember {
    fn drop(&mut self) {
        // Delete the member's tap FIRST: it is persistent in the shared segment namespace, which
        // outlives this member, so a left-behind tap would collide when its vmid is reused.
        if let Err(e) = self
            .segment
            .0
            .netlink
            .delete_link(&self.membership.netns, &self.membership.tap_name)
        {
            tracing::warn!(
                "SegmentMember drop: failed to delete tap {} in {}: {}",
                self.membership.tap_name,
                self.membership.netns,
                e
            );
        }
        self.segment.release_slot(self.membership.slot);
    }
}

/// Test-only seam doubles, shared with the orchestrator's and config's unit tests so every
/// segment-touching gate drives the same recording fake (there is no second copy).
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::net::tap::Netlink;

    /// A recording `Netlink` fake: the segment's create/claim/release calls, in order.
    ///
    /// It also keeps a **live-link set** per namespace. That is not decoration: without it a tap
    /// that already exists is unrepresentable, and "the cleanup deleted a live sibling's tap" —
    /// the L1 defect this fake now guards — is invisible to a pure call recorder. The set models
    /// the two kernel behaviors that matter: creating an interface whose name is taken fails
    /// (`EBUSY`), and deleting one that is absent fails (`ENODEV`).
    pub(crate) struct RecordingNetlink {
        pub(crate) calls: Arc<Mutex<Vec<String>>>,
        /// `(netns, link)` pairs currently present, as the kernel would hold them.
        pub(crate) links: Arc<Mutex<std::collections::BTreeSet<(String, String)>>>,
        pub(crate) fail_bridge: bool,
        pub(crate) fail_enslave: bool,
    }

    impl RecordingNetlink {
        pub(crate) fn new() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                links: Arc::new(Mutex::new(std::collections::BTreeSet::new())),
                fail_bridge: false,
                fail_enslave: false,
            }
        }
    }

    impl Netlink for RecordingNetlink {
        fn add_netns(&self, name: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("add_netns({name})"));
            Ok(())
        }
        fn setup_tap(&self, netns: &str, tap_name: &str, _vmid: u32) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("setup_tap({netns}, {tap_name})"));
            Ok(())
        }
        fn create_bridge(
            &self,
            netns: &str,
            bridge: &str,
            gateway: Ipv4Addr,
            prefix_len: u8,
        ) -> Result<()> {
            self.calls.lock().unwrap().push(format!(
                "create_bridge({netns}, {bridge}, {gateway}/{prefix_len})"
            ));
            if self.fail_bridge {
                return Err(Error::Network("injected create_bridge failure".into()));
            }
            self.links
                .lock()
                .unwrap()
                .insert((netns.to_string(), bridge.to_string()));
            Ok(())
        }
        fn setup_tap_on_bridge(&self, netns: &str, tap_name: &str, bridge: &str) -> Result<()> {
            self.calls.lock().unwrap().push(format!(
                "setup_tap_on_bridge({netns}, {tap_name}, {bridge})"
            ));
            let key = (netns.to_string(), tap_name.to_string());
            // The kernel's `EBUSY`, as a live member produces it: an interface of that name is
            // already there and its VMM holds it open, so the create fails. Nothing is created,
            // so — per the trait's cleanup contract — nothing is removed either.
            if self
                .links
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&key)
            {
                return Err(Error::Network(format!(
                    "tap create fail: Device or resource busy (os error 16) [{tap_name} in \
                     {netns}]"
                )));
            }
            self.links
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key);
            if self.fail_enslave {
                // The creator reclaims exactly what it created (`RtNetlink` does the same).
                self.delete_link(netns, tap_name)?;
                return Err(Error::Network("injected enslave failure".into()));
            }
            Ok(())
        }
        fn delete_link(&self, netns: &str, link: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("delete_link({netns}, {link})"));
            if !self
                .links
                .lock()
                .unwrap()
                .remove(&(netns.to_string(), link.to_string()))
            {
                return Err(Error::Network(format!(
                    "link {link} del err: no such device in {netns}"
                )));
            }
            Ok(())
        }
        fn delete_netns(&self, name: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("delete_netns({name})"));
            // Removing a namespace reaps every link inside it, as the kernel does.
            self.links
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|(ns, _)| ns != name);
            Ok(())
        }
        fn setup_tproxy_routing(&self, netns: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("setup_tproxy_routing({netns})"));
            Ok(())
        }
    }

    /// A hermetic `HostEnv` whose segid allocator is seeded from a **fixed** clock, so two of them
    /// start their id search at the same place. The production seed is the real clock precisely so
    /// that two processes do *not* both pick segid 1; a test that needs the ids to line up asks
    /// for it explicitly here rather than relying on an ordering the product deliberately
    /// randomizes.
    pub(crate) fn seeded_env() -> crate::env::HostEnv {
        crate::env::HostEnv {
            segids: crate::orchestrator::SegmentIdAllocator::new().with_seed_clock(Arc::new(
                crate::orchestrator::FakeClock {
                    time: std::time::UNIX_EPOCH + Duration::new(3, 271_828_182),
                },
            )),
            ..crate::env::HostEnv::for_unit_tests()
        }
    }

    /// A hermetic segment over a recording fake — no privileges, no kernel.
    pub(crate) fn fake_segment(
        prefix: &str,
    ) -> (NetSegment, crate::env::HostEnv, Arc<Mutex<Vec<String>>>) {
        let env = crate::env::HostEnv::for_unit_tests();
        fake_segment_in(prefix, &env)
    }

    /// The same, over a caller-supplied `HostEnv` (so a test can share one segid allocator).
    pub(crate) fn fake_segment_in(
        prefix: &str,
        env: &crate::env::HostEnv,
    ) -> (NetSegment, crate::env::HostEnv, Arc<Mutex<Vec<String>>>) {
        let netlink = RecordingNetlink::new();
        let calls = netlink.calls.clone();
        let seg = NetSegment::create_with_netlink(prefix, env, Box::new(netlink))
            .expect("hermetic segment creates");
        (seg, env.clone(), calls)
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{RecordingNetlink, fake_segment};
    use super::*;

    // The names and addresses a segment publishes are the ONE naming/IP law, not local formats.
    // Buggy impl guarded: a segment that composed its own `format!("{prefix}-seg-{id}")` (or put
    // the gateway on the member octet) diverges from `naming`/`segment_ip_math` here.
    #[test]
    fn segment_names_and_gateway_come_from_the_shared_laws() {
        let (seg, _env, _calls) = fake_segment("vmcell");
        let segid = seg.segid();
        assert_eq!(
            seg.netns_name(),
            crate::naming::segment_netns_name("vmcell", segid)
        );
        assert_eq!(
            seg.bridge_name(),
            crate::naming::segment_bridge_name("vmcell", segid)
        );
        assert_eq!(
            seg.netns_path(),
            std::path::Path::new("/var/run/netns").join(seg.netns_name())
        );
        let (gw, _, _) = crate::net::segment_ip_math(segid, 1).unwrap();
        assert_eq!(seg.gateway(), gw);
        assert_eq!(seg.prefix(), "vmcell");
    }

    // The prefix goes through the SAME validator `VmConfig::build()` uses — one law. Buggy impl
    // guarded: a `NetSegment::new` that skipped validation would happily create a
    // `has-dash-seg-1` namespace whose sweep filter no longer parses.
    #[test]
    fn segment_rejects_an_invalid_prefix_through_the_one_validator() {
        let env = crate::env::HostEnv::for_unit_tests();
        for bad in ["", "has-dash", "toolongprefix", "has space"] {
            let err = NetSegment::create_with_netlink(bad, &env, Box::new(RecordingNetlink::new()))
                .expect_err("an invalid prefix must be refused");
            assert!(
                matches!(err, Error::Config(_)),
                "prefix {bad:?} must be refused as a Config error, got {err:?}"
            );
        }
        // Positive control: the same call with a valid prefix succeeds.
        assert!(
            NetSegment::create_with_netlink("acme", &env, Box::new(RecordingNetlink::new()))
                .is_ok()
        );
    }

    // Slots: claim/free/exhaustion, and the address each slot maps to. Buggy impl guarded: a
    // free-list that never returned a released slot exhausts after 253 members even when they are
    // sequential, and a slot that started at 0 would alias the gateway.
    #[test]
    fn slots_are_claimed_freed_and_exhaust_at_the_documented_limit() {
        let (seg, _env, _calls) = fake_segment("vmcell");

        let a = seg.claim_member(1).expect("first member");
        let b = seg.claim_member(2).expect("second member");
        assert_eq!(
            a.membership().slot,
            1,
            "slots are 1-based (the gateway is .1)"
        );
        assert_eq!(b.membership().slot, 2);
        assert_eq!(seg.active_slots(), [1, 2].into_iter().collect());

        // Each member's address comes from the shared math.
        let (gw, ip, _) = a.membership().addresses().unwrap();
        assert_eq!(gw, seg.gateway());
        assert_eq!(ip, crate::net::segment_ip_math(seg.segid(), 1).unwrap().1);

        // A released slot is reusable — this is what keeps a long-lived segment from exhausting.
        drop(a);
        assert_eq!(seg.active_slots(), [2].into_iter().collect());
        let c = seg.claim_member(3).expect("slot 1 is reusable");
        assert_eq!(c.membership().slot, 1);
        drop((b, c));

        // Exhaustion at exactly MAX_SEGMENT_SLOT, typed.
        let mut held = Vec::new();
        for vmid in 1..=crate::net::MAX_SEGMENT_SLOT {
            held.push(seg.claim_member(vmid).expect("slot within the limit"));
        }
        let err = seg
            .claim_member(9999)
            .expect_err("the 254th member must be refused");
        assert!(
            matches!(err, Error::Exhaustion(_)),
            "expected a typed Exhaustion, got {err:?}"
        );
    }

    // The member tap is created on the bridge and deleted on teardown — but the NAMESPACE is
    // never touched by a member. Buggy impl guarded: a member `Drop` that deleted the segment
    // netns (the "tear down what you set up" reflex) would kill every sibling VM's datapath; the
    // absence assertion below reddens on it. Fake-blind axis: the fake records the calls but
    // never touches the kernel — the live `segment.rs` legs cover the real bridge/enslave.
    #[test]
    fn member_teardown_releases_its_tap_and_slot_but_never_the_namespace() {
        let (seg, _env, calls) = fake_segment("vmcell");
        let netns = seg.netns_name().to_string();
        let member = seg.claim_member(7).expect("member");
        let tap = member.membership().tap_name.clone();
        assert_eq!(tap, crate::naming::tap_name("vmcell", 7));

        drop(member);

        let c = calls.lock().unwrap().clone();
        let enslave = format!("setup_tap_on_bridge({netns}, {tap}, {})", seg.bridge_name());
        let del = format!("delete_link({netns}, {tap})");
        let pos_enslave = c.iter().position(|s| *s == enslave).expect("tap enslaved");
        let pos_del = c.iter().position(|s| *s == del).expect("tap deleted");
        assert!(
            pos_enslave < pos_del,
            "tap must be created before deleted: {c:?}"
        );
        assert!(
            !c.iter().any(|s| s.starts_with("delete_netns")),
            "a member must NEVER delete the segment namespace: {c:?}"
        );
        // A member's tap gets no address of its own — `setup_tap` (which assigns the /30) must
        // not appear at all on the segment path.
        assert!(
            !c.iter().any(|s| s.starts_with("setup_tap(")),
            "a member tap must go through setup_tap_on_bridge (no address), not setup_tap: {c:?}"
        );
    }

    // The namespace dies with the LAST handle, and the segid is released with it. Buggy impl
    // guarded: a `NetSegment` that deleted the namespace on every clone's drop reddens on the
    // first assertion; one that never released the segid reddens on the reallocation.
    #[test]
    fn namespace_dies_with_the_last_handle_and_frees_the_segid() {
        // A fixed seed clock: the segid search start is clock-seeded (so concurrent processes do
        // not all pick segid 1), which would otherwise make "the next segment takes the released
        // id" a coin flip rather than an assertion.
        let env = testing::seeded_env();
        let netlink = RecordingNetlink::new();
        let calls = netlink.calls.clone();
        let seg = NetSegment::create_with_netlink("vmcell", &env, Box::new(netlink)).unwrap();
        let segid = seg.segid();
        let netns = seg.netns_name().to_string();

        let clone_a = seg.clone();
        let clone_b = seg.clone();
        assert_eq!(clone_a, clone_b, "two handles to one segment are equal");
        drop(seg);
        drop(clone_a);
        assert!(
            !calls
                .lock()
                .unwrap()
                .iter()
                .any(|s| s == &format!("delete_netns({netns})")),
            "the namespace must survive while any handle lives"
        );

        drop(clone_b);
        assert!(
            calls
                .lock()
                .unwrap()
                .iter()
                .any(|s| s == &format!("delete_netns({netns})")),
            "the last handle must delete the namespace"
        );

        // The segid is free again, so the next segment can take it.
        let next =
            NetSegment::create_with_netlink("vmcell", &env, Box::new(RecordingNetlink::new()))
                .unwrap();
        assert_eq!(next.segid(), segid, "a dropped segment must release its id");
    }

    // Two distinct segments are never equal, even when their handles wrap equal ids from
    // independent allocators (the `Arc::ptr_eq` identity semantics `NetConfig`'s derived `Eq`
    // inherits). Buggy impl guarded: an `Eq` derived over the id/name fields would call these two
    // equal, so a config carrying segment A would compare equal to one carrying segment B.
    #[test]
    fn distinct_segments_with_equal_ids_are_not_equal() {
        // Two independent allocators on the SAME seed clock, so they hand out the same first id —
        // the situation this test exists for. (With the production `RealClock` seed the two ids
        // are merely usually different, which would make the assertion vacuous half the time.)
        let (a, _env_a, _ca) = testing::fake_segment_in("vmcell", &testing::seeded_env());
        let (b, _env_b, _cb) = testing::fake_segment_in("vmcell", &testing::seeded_env());
        assert_eq!(
            a.segid(),
            b.segid(),
            "independent allocators hand out the same first id"
        );
        assert_ne!(a, b, "distinct segments must never compare equal");
        assert_eq!(a, a.clone());
    }

    // A failed enslave must leave neither a half-created tap nor a consumed slot. Buggy impl
    // guarded: leaving the tap behind makes the NEXT claim of that vmid fail with EEXIST;
    // forgetting `release_slot` erodes the segment's address space one failed claim at a time.
    // The tap is reclaimed by `setup_tap_on_bridge` — the only party that knows it created one —
    // so the assertion is on the RESULTING STATE (no tap in the namespace), not on who called
    // what.
    #[test]
    fn failed_member_enslave_releases_the_slot_and_the_tap() {
        let env = crate::env::HostEnv::for_unit_tests();
        let netlink = RecordingNetlink {
            fail_enslave: true,
            ..RecordingNetlink::new()
        };
        let calls = netlink.calls.clone();
        let links = netlink.links.clone();
        let seg = NetSegment::create_with_netlink("vmcell", &env, Box::new(netlink))
            .expect("the segment itself creates");

        let err = seg
            .claim_member(7)
            .expect_err("the injected enslave failure must propagate");
        assert!(matches!(err, Error::Network(_)), "got {err:?}");

        assert!(
            seg.active_slots().is_empty(),
            "a failed claim must return its slot to the free list"
        );
        let tap = crate::naming::tap_name("vmcell", 7);
        // Snapshot rather than assert under the lock: a message that formats the guard would
        // poison the fake's mutex on failure and turn the next fake call into a second panic.
        let live = links.lock().unwrap().clone();
        assert!(
            !live.contains(&(seg.netns_name().to_string(), tap.clone())),
            "a failed claim must leave no half-created tap behind: {live:?}"
        );
        let c = calls.lock().unwrap().clone();
        assert!(
            !c.iter().any(|s| s.starts_with("delete_netns")),
            "a failed claim must NOT take down the segment namespace: {c:?}"
        );
    }

    // A vmid that already holds a slot in THIS segment is refused before any host state is
    // touched, and the live sibling's tap survives untouched.
    //
    // Buggy impl guarded — this is the shipped v30-delta-8 code, reproduced live: `claim_member`
    // accepted the duplicate vmid, its tap create failed `EBUSY` (member A's tap owns that name in
    // the SHARED namespace), and the failure path then deleted the interface *by name* — severing
    // a still-running sibling's datapath, silently. Two things make the fake able to see it where
    // a pure call-recorder could not: it holds a live-link set (so a pre-existing tap exists at
    // all), and it fails a create whose name is taken exactly as the kernel does.
    #[test]
    fn a_duplicate_vmid_is_refused_and_the_live_siblings_tap_survives() {
        let env = crate::env::HostEnv::for_unit_tests();
        let netlink = RecordingNetlink::new();
        let calls = netlink.calls.clone();
        let links = netlink.links.clone();
        let seg = NetSegment::create_with_netlink("vmcell", &env, Box::new(netlink))
            .expect("the segment creates");
        let netns = seg.netns_name().to_string();
        let tap = crate::naming::tap_name("vmcell", 7);

        // Snapshot rather than assert under the lock (see the sibling test above).
        let live = || links.lock().unwrap().clone();

        let a = seg.claim_member(7).expect("member A joins");
        assert!(
            live().contains(&(netns.clone(), tap.clone())),
            "member A's tap must exist before the second claim (a survival check that never \
             observed the artifact proves nothing): {:?}",
            live()
        );
        let calls_before = calls.lock().unwrap().len();

        let err = seg
            .claim_member(7)
            .expect_err("a second member with a vmid the segment already holds must be refused");
        assert!(
            matches!(err, Error::Config(_)),
            "a duplicate vmid is an invalid accepted input, refused at construction: {err:?}"
        );

        // The refusal touched NO host state at all…
        let recorded = calls.lock().unwrap().clone();
        assert_eq!(
            recorded.len(),
            calls_before,
            "the refusal must precede every netlink call: {recorded:?}"
        );
        // …so the live sibling still has its tap, and its slot.
        assert!(
            live().contains(&(netns.clone(), tap.clone())),
            "the live sibling's tap must survive a refused duplicate claim: {:?}",
            live()
        );
        assert_eq!(
            seg.active_slots(),
            [a.membership().slot].into_iter().collect(),
            "the refused claim must not consume or release a slot"
        );

        // Positive control: a DIFFERENT vmid still joins, through the same call.
        let b = seg.claim_member(8).expect("a distinct vmid still joins");
        assert!(
            live().contains(&(netns.clone(), crate::naming::tap_name("vmcell", 8))),
            "the allowed path reaches the same target: {:?}",
            live()
        );
        // …and once the holder leaves, its vmid is claimable again (the refusal is about live
        // membership, not a permanent ban).
        drop(a);
        let a2 = seg.claim_member(7).expect("a departed vmid is reusable");
        drop((a2, b));
    }

    // A failed bridge creation must not leak the namespace it already created — `Self` is never
    // constructed on that path, so `Drop` cannot reclaim it. Buggy impl guarded: returning the
    // error without the cleanup leaves `vmcell-seg-<id>` behind forever (and the sweep only
    // reclaims it on the *next* start-up).
    #[test]
    fn failed_bridge_creation_cleans_up_the_namespace() {
        let env = crate::env::HostEnv::for_unit_tests();
        let netlink = RecordingNetlink {
            fail_bridge: true,
            ..RecordingNetlink::new()
        };
        let calls = netlink.calls.clone();
        let err = NetSegment::create_with_netlink("vmcell", &env, Box::new(netlink))
            .expect_err("the injected bridge failure must propagate");
        assert!(matches!(err, Error::Network(_)), "got {err:?}");

        let c = calls.lock().unwrap().clone();
        let pos_add = c
            .iter()
            .position(|s| s.starts_with("add_netns"))
            .expect("add_netns");
        let pos_del = c
            .iter()
            .position(|s| s.starts_with("delete_netns"))
            .expect("the namespace must be cleaned up after a bridge failure");
        assert!(pos_add < pos_del, "{c:?}");
    }
    // ---------------------------------------------------------------------------------------
    // Link impairment (design §17, Segment refinements)
    // ---------------------------------------------------------------------------------------

    /// The one netem composer emits exactly the words `tc` means, for every shape the builder can
    /// produce.
    ///
    /// Buggy impls guarded: rendering durations in milliseconds (a 500 µs delay becomes `0ms`,
    /// which `tc` accepts and the kernel ignores); emitting a `jitter` keyword (`tc` refuses it);
    /// emitting the loss percentage without its `%`.
    #[test]
    fn netem_args_are_composed_in_one_place() {
        let delay_only = Impairment::builder()
            .delay(Duration::from_millis(50))
            .build()
            .expect("a delay-only impairment is legal");
        assert_eq!(delay_only.netem_args(), ["delay", "50000us"]);

        let loss_only = Impairment::builder()
            .loss_percent(100)
            .build()
            .expect("a loss-only impairment is legal");
        assert_eq!(loss_only.netem_args(), ["loss", "100%"]);

        let both = Impairment::builder()
            .delay(Duration::from_millis(20))
            .jitter(Duration::from_millis(5))
            .loss_percent(3)
            .build()
            .expect("delay + jitter + loss is legal");
        assert_eq!(
            both.netem_args(),
            ["delay", "20000us", "5000us", "loss", "3%"],
            "jitter is delay's positional second argument, and loss follows"
        );

        // Sub-millisecond resolution survives: the unit is microseconds precisely so it can.
        let fine = Impairment::builder()
            .delay(Duration::from_micros(500))
            .build()
            .expect("a sub-millisecond delay is legal");
        assert_eq!(fine.netem_args(), ["delay", "500us"]);

        // The accessors report what was built — an impairment is a value, not just an argv.
        assert_eq!(both.delay(), Some(Duration::from_millis(20)));
        assert_eq!(both.jitter(), Some(Duration::from_millis(5)));
        assert_eq!(both.loss_percent(), Some(3));
        assert_eq!(loss_only.delay(), None);
    }

    /// Every argv the composer can emit is accepted by the **installed** iproute2 parser — the one
    /// thing a golden-string test cannot prove.
    ///
    /// Privilege-free and kernel-free by construction: iproute2 parses the qdisc options *before*
    /// it resolves the device, so aiming at a device that does not exist reaches the parser and
    /// nothing else. A well-formed argv dies at `Cannot find device`; a malformed one dies in the
    /// parser with `What is "…"?` and the netem usage block — and the malformed leg is the
    /// positive control proving the discriminator can fire at all.
    ///
    /// Buggy impl guarded: the `jitter` keyword, or a bare number where `tc` wants a unit-suffixed
    /// TIME, is invisible to `netem_args_are_composed_in_one_place` and reddens here.
    #[test]
    fn netem_args_are_accepted_by_the_installed_tc_parser() {
        // A device that must not exist: the probe is only harmless because nothing can be
        // modified through it. Checked, not assumed.
        let absent_dev = "vmcellprobe0";
        assert!(
            !std::path::Path::new("/sys/class/net")
                .join(absent_dev)
                .exists(),
            "gate misconfigured: the parser probe's target device {absent_dev} exists on this \
             host, so the probe could reach a real interface"
        );

        let run = |extra: &[String]| -> std::process::Output {
            let mut args = vec![
                "qdisc".to_string(),
                "replace".to_string(),
                "dev".to_string(),
                absent_dev.to_string(),
                "root".to_string(),
                "netem".to_string(),
            ];
            args.extend_from_slice(extra);
            match std::process::Command::new(TC_BINARY).args(&args).output() {
                Ok(out) => out,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => panic!(
                    "gate misconfigured: the iproute2 `{TC_BINARY}` binary is required to validate \
                     the netem argv composer against a real parser (install iproute2)"
                ),
                Err(e) => panic!("spawning `{TC_BINARY}` failed: {e}"),
            }
        };

        for impairment in [
            Impairment::builder().delay(Duration::from_millis(50)),
            Impairment::builder().loss_percent(100),
            Impairment::builder().delay(Duration::from_micros(500)),
            Impairment::builder()
                .delay(Duration::from_millis(20))
                .jitter(Duration::from_millis(5))
                .loss_percent(3),
            Impairment::builder()
                .delay(MAX_IMPAIRMENT_DELAY)
                .loss_percent(0),
        ] {
            let impairment = impairment.build().expect("every probe shape is legal");
            let out = run(&impairment.netem_args());
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                !stderr.contains("Usage:") && !stderr.contains("What is"),
                "the installed tc parser rejected the composed argv for {impairment:?}: {stderr}"
            );
            assert!(
                stderr.contains("Cannot find device"),
                "the probe must reach device resolution (and stop there) for {impairment:?}: \
                 {stderr}"
            );
        }

        // Positive control: the discriminator fires on an argv the parser really does refuse.
        let bogus = run(&["jitter".to_string(), "5ms".to_string()]);
        let bogus_stderr = String::from_utf8_lossy(&bogus.stderr);
        assert!(
            bogus_stderr.contains("Usage:") && bogus_stderr.contains("What is"),
            "the parser-error discriminator never fires, so the legs above are vacuous: \
             {bogus_stderr}"
        );
    }

    /// Every nonsense impairment is refused at construction, so an `Impairment` that exists is one
    /// `tc` will accept.
    #[test]
    fn impairment_rejects_nonsense_at_construction() {
        let cases: Vec<(ImpairmentBuilder, &str)> = vec![
            (Impairment::builder(), "at least one of delay or loss"),
            (
                Impairment::builder().delay(Duration::ZERO),
                "must be non-zero",
            ),
            (
                Impairment::builder()
                    .delay(Duration::from_millis(1))
                    .jitter(Duration::ZERO),
                "must be non-zero",
            ),
            (
                Impairment::builder().delay(MAX_IMPAIRMENT_DELAY + Duration::from_micros(1)),
                "exceeds the",
            ),
            (
                Impairment::builder()
                    .delay(Duration::from_millis(1))
                    .jitter(MAX_IMPAIRMENT_DELAY + Duration::from_micros(1)),
                "exceeds the",
            ),
            (
                Impairment::builder().jitter(Duration::from_millis(5)),
                "needs a delay",
            ),
            (Impairment::builder().loss_percent(101), "exceeds 100%"),
        ];
        for (builder, needle) in cases {
            let err = builder
                .clone()
                .build()
                .expect_err(&format!("{builder:?} must be refused"));
            match err {
                Error::Config(msg) => assert!(
                    msg.contains(needle),
                    "{builder:?} must be refused naming {needle:?}: {msg}"
                ),
                other => panic!("{builder:?} must be refused as a Config error, got {other:?}"),
            }
        }

        // The boundaries themselves are legal — the refusals above are not off by one.
        assert!(
            Impairment::builder()
                .delay(MAX_IMPAIRMENT_DELAY)
                .build()
                .is_ok()
        );
        assert!(Impairment::builder().loss_percent(100).build().is_ok());
        assert!(Impairment::builder().loss_percent(0).build().is_ok());
    }

    /// Impairment names a **member**, and a vmid that holds no slot is refused at the API boundary
    /// — before any host state is touched, and before `tc` is spawned at all.
    ///
    /// Buggy impl guarded: composing `naming::tap_name(prefix, vmid)` without consulting the slot
    /// map, which reaches `tc` and returns "Cannot find device" — indistinguishable, to a caller,
    /// from a member whose tap really did vanish.
    #[test]
    fn impairment_refuses_a_vmid_that_is_not_a_member() {
        let (seg, _env, calls) = fake_segment("vmcell");
        let member = seg.claim_member(7).expect("a first member claims a slot");
        let before = calls.lock().unwrap().len();

        let imp = Impairment::builder()
            .loss_percent(100)
            .build()
            .expect("legal impairment");
        for verb in ["impair", "clear"] {
            let err = if verb == "impair" {
                seg.impair_member(9, &imp).expect_err("vmid 9 is no member")
            } else {
                seg.clear_impairment(9).expect_err("vmid 9 is no member")
            };
            match err {
                Error::Config(msg) => assert!(
                    msg.contains("vmid 9") && msg.contains(seg.netns_name()),
                    "{verb} must name the vmid and the segment: {msg}"
                ),
                other => panic!("{verb} on a non-member must be a Config error: {other:?}"),
            }
        }
        assert_eq!(
            calls.lock().unwrap().len(),
            before,
            "a refused impairment must touch no host state"
        );
        // The member's own vmid resolves to the one naming law's tap — the positive control for
        // the refusals above.
        assert_eq!(
            seg.member_tap(7).expect("the member resolves"),
            crate::naming::tap_name("vmcell", 7)
        );
        drop(member);
        assert!(
            seg.member_tap(7).is_err(),
            "a released slot stops being impairable"
        );
    }

    /// §7.2 capability honesty: an absent `tc` is an absent **facility**
    /// ([`Error::CapabilityUnavailable`]); one that exists but cannot be spawned is a **broken**
    /// one, reported with its errno intact.
    ///
    /// Buggy impl guarded: collapsing both into `Error::Subprocess`, which tells an operator to
    /// debug a permission problem they do not have.
    #[test]
    fn an_absent_tc_is_a_capability_and_a_broken_one_is_an_errno() {
        match classify_tc_spawn_error(std::io::Error::from_raw_os_error(libc::ENOENT)) {
            Error::CapabilityUnavailable { op, needed } => {
                assert!(op.contains("impairment"), "{op}");
                assert!(
                    needed.contains(TC_BINARY) && needed.contains("iproute2"),
                    "{needed}"
                );
            }
            other => panic!("an absent tc must be a capability, got {other:?}"),
        }
        match classify_tc_spawn_error(std::io::Error::from_raw_os_error(libc::EACCES)) {
            Error::Io(e) => assert_eq!(
                e.raw_os_error(),
                Some(libc::EACCES),
                "a broken tc keeps its errno"
            ),
            other => panic!("a broken tc must keep its errno, got {other:?}"),
        }
    }
}
