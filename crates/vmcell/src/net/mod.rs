//! Network management and namespaces.
//!
//! This module provides functionality for setting up network interfaces,
//! network namespaces, and userspace networking for the virtual machines.

#![forbid(unsafe_code)]

/// TAP interface and network namespace management.
pub mod tap;

/// VM-to-VM segments: one netns per segment holding one bridge, with member taps enslaved to it
/// (§6.5, VM-to-VM segments).
pub mod segment;

#[cfg(feature = "net-unprivileged")]
/// unprivileged userspace networking with smoltcp.
pub mod smoltcp;

/// Per-VM network byte counters: the netns-scoped usage type (§7.1, What is read and enforced).
pub mod usage;

pub use segment::{
    Impairment, ImpairmentBuilder, MAX_IMPAIRMENT_DELAY, NetSegment, NetSegmentRef, SegmentMember,
    SegmentMembership,
};
pub use tap::{NetNamespace, cleanup_orphan_netns};
pub use usage::{NetUsage, NetUsageTarget};

#[cfg(feature = "net-unprivileged")]
pub use smoltcp::backend::SmoltcpProcess;

use crate::error::{Error, Result};
use std::net::Ipv4Addr;

/// The number of **third octets** the `10.200.0.0/16` and `10.201.0.0/16` maps hand out: the range
/// `1..=254`, which excludes `.0` and `.255` so no `/30` or `/24` lands on a third octet an
/// operator's tooling reads as a network or broadcast boundary.
///
/// Deliberately its own constant rather than a reuse of [`MAX_VMID`] or [`MAX_SEGMENT_ID`], which
/// happen to equal it today: this is the *size of the codomain*, those are *domain ceilings*, and
/// one constant for both would let a widened ceiling silently start wrapping two ids onto one
/// address. The two `const _: () = assert!(…)` blocks below are what keep the relation between them
/// a **compile error** instead of a comment.
const THIRD_OCTET_SPACE: u32 = 254;

/// The highest VMID the host addressing law admits — the `≈254`-VM-per-`/16` ceiling design §17
/// (Networking) records, named once here instead of spelled inline at each of its homes.
///
/// **Moving it is a coordinated change, not an edit here.** The ceiling has five homes, and
/// `the_vmid_ceiling_is_one_law_with_four_other_homes` (this module's tests) is their executable
/// roster: raising this constant alone reddens it at every home that did not move with it.
///
/// 1. **This map.** [`ip_math`] and [`mac_math`] refuse anything above it. The map stays a
///    bijection only while `MAX_VMID <= THIRD_OCTET_SPACE` — asserted below as a `const`, so
///    widening past 254 is a *compile* error until the map grows a second dimension (each third
///    octet holds 64 disjoint `/30`s — `10.200.<octet>.{0,4,8,…,252}/30` — of which this map uses
///    exactly one, so the headroom is real and unclaimed).
/// 2. **`orchestrator::VmidAllocator::reserve`** and `allocate_vmid`, which carry their own
///    `1..=254`.
/// 3. **The interface-name budget.** `<prefix>-tap-<vmid>` must fit `IFNAMSIZ - 1`; at
///    [`crate::naming::MAX_RESOURCE_PREFIX_LEN`] that admits at most **four** decimal digits, so a
///    ceiling above 9999 forces the prefix budget down or the tap-name scheme to change.
/// 4. **The guest CID space** (`3..=254`, `vmm::CidAllocator`). Every VM allocates one
///    unconditionally, so **252 is the binding ceiling on concurrent VMs per host today** — below
///    this one. Widening the address map alone raises the concurrent-VM count by exactly zero.
/// 5. **`net::smoltcp`'s reserved host MAC**, which must stay outside the image of
///    [`mac_math`] over `1..=MAX_VMID` (`host_nat_mac_never_collides_with_guest_mac`).
pub const MAX_VMID: u32 = 254;

/// The bijection precondition for [`ip_math`], as a compile error rather than a comment: the map
/// `vmid ↦ (vmid % THIRD_OCTET_SPACE) + 1` is injective exactly while the domain is no larger than
/// the codomain. Above it, two vmids share one `/30` — two guests with one address, which is a
/// silent data-plane defect rather than a loud refusal.
const _: () = assert!(
    MAX_VMID <= THIRD_OCTET_SPACE,
    "MAX_VMID exceeds the third-octet space: ip_math would wrap two vmids onto one /30. Widening \
     the ceiling means giving the map a second dimension (the 64 /30s inside each third octet), \
     not raising this constant."
);

/// Centralized IP math for VM network. Returns (host_ip, guest_ip, guest_cidr).
///
/// The third octet is `(vmid % 254) + 1` (§9.3); the pair is the `.1`/`.2` of the `/30` based at
/// `10.200.<octet>.0`. [`MAX_VMID`] documents the ceiling this imposes and what moving it costs.
///
/// # Errors
/// Returns an error if the VMID is out of range (`1..=`[`MAX_VMID`]) — never a silently wrapped,
/// colliding address.
pub fn ip_math(vmid: u32) -> Result<(Ipv4Addr, Ipv4Addr, String)> {
    if vmid == 0 || vmid > MAX_VMID {
        return Err(Error::Network(format!("VMID {vmid} out of range")));
    }
    // `THIRD_OCTET_SPACE` is 254, so the result is `1..=254` and the cast cannot truncate.
    let octet = ((vmid % THIRD_OCTET_SPACE) + 1) as u8;
    Ok((
        Ipv4Addr::new(10, 200, octet, 1),
        Ipv4Addr::new(10, 200, octet, 2),
        format!("10.200.{octet}.2/30"),
    ))
}

/// The highest segment id the addressing math can carry.
pub const MAX_SEGMENT_ID: u32 = 254;

/// [`segment_ip_math`]'s half of the same precondition [`MAX_VMID`]'s `const` assert states for
/// [`ip_math`]: a segid above the third-octet space wraps two segments onto one `/24`.
const _: () = assert!(
    MAX_SEGMENT_ID <= THIRD_OCTET_SPACE,
    "MAX_SEGMENT_ID exceeds the third-octet space: segment_ip_math would wrap two segments onto \
     one /24, silently bridging two segments that must not see each other."
);

/// The highest member **slot** a segment can hand out: gateway `.1` plus slots `.2`..=`.254`.
pub const MAX_SEGMENT_SLOT: u32 = 253;

/// Centralized IP math for a **segment** member (§6.5, VM-to-VM segments). Returns
/// (gateway, member_ip, member_cidr) on `10.201.<s>.0/24`, where `s = (segid % 254) + 1`, the
/// gateway (bridge) is `.1`, and member slot `k` (1-based) is `.(k + 1)`.
///
/// The sibling of [`ip_math`], deliberately on a **different /16**: the per-VM `/30`s consume the
/// whole `10.200.<octet>` third-octet space for `vmid ∈ 1..=254`, so the two schemes cannot
/// collide for any (vmid, segid, slot) triple.
///
/// # Errors
/// Returns an error if `segid` is outside `1..=`[`MAX_SEGMENT_ID`] or `slot` is outside
/// `1..=`[`MAX_SEGMENT_SLOT`] — never a silently wrapped, colliding address.
pub fn segment_ip_math(segid: u32, slot: u32) -> Result<(Ipv4Addr, Ipv4Addr, String)> {
    if segid == 0 || segid > MAX_SEGMENT_ID {
        return Err(Error::Network(format!("segment id {segid} out of range")));
    }
    if slot == 0 || slot > MAX_SEGMENT_SLOT {
        return Err(Error::Network(format!(
            "segment slot {slot} out of range (1..={MAX_SEGMENT_SLOT})"
        )));
    }
    // The octet space, not the id ceiling: they are equal today, and the `const` assert above is
    // what keeps that equality from being an accident.
    let octet = ((segid % THIRD_OCTET_SPACE) + 1) as u8;
    // `slot <= 253` ⇒ `slot + 1 <= 254`, so the cast cannot truncate.
    let host = (slot + 1) as u8;
    Ok((
        Ipv4Addr::new(10, 201, octet, 1),
        Ipv4Addr::new(10, 201, octet, host),
        format!("10.201.{octet}.{host}/24"),
    ))
}

/// Centralized MAC address math for VM network.
///
/// The whole 32-bit vmid is embedded in the low four bytes under the locally-administered,
/// unicast `02:00:` prefix, so the map is injective for **any** vmid — unlike [`ip_math`], it
/// imposes no ceiling of its own. It refuses the same range anyway, so one out-of-range vmid
/// cannot acquire a MAC without an address.
///
/// # Errors
/// Returns an error if the VMID is out of range (`1..=`[`MAX_VMID`]).
pub fn mac_math(vmid: u32) -> Result<String> {
    if vmid == 0 || vmid > MAX_VMID {
        return Err(Error::Network(format!("VMID {vmid} out of range")));
    }
    Ok(format!(
        "02:00:{:02x}:{:02x}:{:02x}:{:02x}",
        (vmid >> 24) & 0xff,
        (vmid >> 16) & 0xff,
        (vmid >> 8) & 0xff,
        vmid & 0xff
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole supported vmid range, mapped through [`ip_math`] and [`mac_math`], is a
    /// **bijection** onto addresses that collide with nothing — proved by exhaustion over the
    /// domain rather than asserted at three sample points.
    ///
    /// Exhaustive rather than randomized on purpose: the domain is `1..=MAX_VMID`, small enough to
    /// enumerate, and a proptest over the same space would be strictly weaker (it samples) and
    /// slower. Widening the ceiling keeps this test honest by construction — it iterates
    /// `MAX_VMID`, so it grows with the law instead of pinning a stale 254.
    ///
    /// Buggy impls guarded: a map that drops the `+ 1` (vmid 254 → third octet 0, the network
    /// address) reddens on the reserved-octet leg; one that widens the ceiling without widening
    /// the codomain (`vmid % 254` with `MAX_VMID = 500`) reddens on the injectivity leg — and does
    /// not compile, because of `MAX_VMID`'s `const` assert; one that moves the per-VM map onto
    /// `10.201` reddens on the segment-disjointness leg.
    #[test]
    fn vmid_address_map_is_a_bijection_over_the_whole_supported_range() {
        use std::collections::HashSet;

        let mut hosts = HashSet::new();
        let mut guests = HashSet::new();
        let mut macs = HashSet::new();

        for vmid in 1..=MAX_VMID {
            let (host, guest, cidr) = ip_math(vmid).expect("every vmid in range must map");

            // Both addresses live in the per-VM /16 and nowhere else — in particular never in the
            // segment /16 (`10.201.0.0/16`), whose disjointness is the whole reason the two
            // schemes can share a host.
            for addr in [host, guest] {
                let o = addr.octets();
                assert_eq!(
                    (o[0], o[1]),
                    (10, 200),
                    "vmid {vmid} escaped the per-VM /16 with {addr}"
                );
                // A third octet of 0 or 255 is a network/broadcast boundary an operator's tooling
                // reads specially; the map must never emit one.
                assert!(
                    (1..=254).contains(&o[2]),
                    "vmid {vmid} landed on reserved third octet {} ({addr})",
                    o[2]
                );
            }

            // The /30 shape: host `.1`, guest `.2`, and the CIDR the guest is handed agrees with
            // the address it is handed.
            assert_eq!(host.octets()[3], 1, "host side of vmid {vmid}'s /30");
            assert_eq!(guest.octets()[3], 2, "guest side of vmid {vmid}'s /30");
            assert_eq!(
                host.octets()[2],
                guest.octets()[2],
                "vmid {vmid} split its /30"
            );
            assert_eq!(cidr, format!("{guest}/30"), "vmid {vmid} CIDR vs address");

            // Injectivity — the bijection. Both sides, because a map that collided only on the
            // host side would still wedge the gateway.
            assert!(hosts.insert(host), "vmid {vmid} reused host address {host}");
            assert!(
                guests.insert(guest),
                "vmid {vmid} reused guest address {guest}"
            );

            let mac = mac_math(vmid).expect("every vmid in range must map to a MAC");
            let bytes: Vec<u8> = mac
                .split(':')
                .map(|b| u8::from_str_radix(b, 16).expect("mac_math emits hex octets"))
                .collect();
            assert_eq!(bytes.len(), 6, "vmid {vmid} MAC {mac} is not six octets");
            // Locally administered (bit 1 set) and unicast (bit 0 clear): a multicast guest MAC is
            // accepted by no bridge.
            assert_eq!(
                bytes[0] & 0b11,
                0b10,
                "vmid {vmid} MAC {mac} is not LAA unicast"
            );
            assert!(macs.insert(mac.clone()), "vmid {vmid} reused MAC {mac}");
        }

        // Surjectivity onto the codomain the ceiling claims: `MAX_VMID` distinct /30s, one per
        // usable third octet. Together with injectivity above, that is the bijection.
        assert_eq!(hosts.len(), MAX_VMID as usize);
        assert_eq!(guests.len(), MAX_VMID as usize);
        assert_eq!(macs.len(), MAX_VMID as usize);

        // The ceiling moves; it never vanishes. Both boundaries stay loud refusals.
        for out_of_range in [0, MAX_VMID + 1, u32::MAX] {
            assert!(
                ip_math(out_of_range).is_err(),
                "vmid {out_of_range} must be refused, never wrapped"
            );
            assert!(
                mac_math(out_of_range).is_err(),
                "vmid {out_of_range} must be refused a MAC too"
            );
        }
    }

    /// The executable roster of the ≈254 ceiling's **other** homes (design §17, Networking).
    ///
    /// [`MAX_VMID`] names the ceiling once, but four more sites carry it and none of them can
    /// import it (two are in other modules with their own `1..=254` literals; one is an ABI
    /// budget; one is a different id space entirely). Nothing could see them drift apart, so this
    /// test is what makes raising `MAX_VMID` alone go red at each home that did not move with it —
    /// the "one law, one predicate" mechanism where the drift is not a compile error.
    ///
    /// It also records the finding that widening the address map is **not** what raises the
    /// concurrent-VM count: the guest CID space is the lower ceiling.
    ///
    /// Buggy impl guarded: raising `MAX_VMID` to 255 reddens the allocator leg (which still
    /// refuses 255) and the CID leg; raising it to 10000 reddens the interface-name leg.
    #[test]
    fn the_vmid_ceiling_is_one_law_with_four_other_homes() {
        // Home 2: the VMID allocator's own `1..=254`. It must accept exactly what the address map
        // accepts — an id the allocator hands out but the map refuses is a VM that cannot be
        // addressed, and vice versa is an address no VM can ever hold.
        let vmids = crate::orchestrator::VmidAllocator::new();
        assert!(
            vmids.reserve(MAX_VMID).is_ok(),
            "the allocator must hand out the highest vmid the address map admits"
        );
        assert!(
            vmids.reserve(MAX_VMID + 1).is_err(),
            "the allocator's ceiling did not move with net::MAX_VMID"
        );

        // Home 3: the IFNAMSIZ budget on `<prefix>-tap-<vmid>`, measured at the longest legal
        // prefix and the highest vmid — against the real ABI constant, not a copy of it.
        let widest = "a".repeat(crate::naming::MAX_RESOURCE_PREFIX_LEN);
        assert!(
            crate::naming::validate_resource_prefix(&widest).is_ok(),
            "the widest legal prefix must validate"
        );
        let tap = crate::naming::tap_name(&widest, MAX_VMID);
        assert!(
            tap.len() < libc::IFNAMSIZ,
            "the tap name for the highest vmid ({tap}, {} bytes) no longer fits IFNAMSIZ ({}): a \
             ceiling with more decimal digits costs prefix budget",
            tap.len(),
            libc::IFNAMSIZ
        );

        // Home 4: the guest CID space, `3..=254`. Every VM allocates one unconditionally, so this
        // — not the address map — is the binding ceiling on concurrent VMs per host.
        let cids = crate::vmm::CidAllocator::new();
        let mut handed = 0u32;
        while cids.allocate().is_ok() {
            handed += 1;
            assert!(handed <= MAX_VMID, "the CID space outgrew its own ceiling");
        }
        assert_eq!(handed, 252, "the guest CID space is `3..=254`");
        assert!(
            handed < MAX_VMID,
            "the CID space is no longer the binding concurrency ceiling — the §17 finding that \
             widening the /16 map raises the concurrent-VM count by zero has changed, and the \
             design register needs re-reading before this is relaxed"
        );

        // Home 5 is `net::smoltcp`'s reserved host MAC, whose own gate
        // (`host_nat_mac_never_collides_with_guest_mac`) iterates `1..=MAX_VMID`. Not re-asserted
        // here: one law, one home — this roster names it, it does not copy it.
    }

    #[test]
    fn test_ip_math() {
        assert!(ip_math(0).is_err());
        assert!(ip_math(255).is_err());
        let (host, guest, cidr) = ip_math(1).unwrap();
        assert_eq!(host, Ipv4Addr::new(10, 200, 2, 1));
        assert_eq!(guest, Ipv4Addr::new(10, 200, 2, 2));
        assert_eq!(cidr, "10.200.2.2/30");
        let (host, _, _) = ip_math(254).unwrap();
        assert_eq!(host, Ipv4Addr::new(10, 200, 1, 1));
    }

    // v30 §6.5 KVM-free gate: range, injectivity, and disjointness from `ip_math`.
    // Buggy impl guarded: a `segment_ip_math` that reused `10.200` (or that let slot 0 /
    // slot 254 through, aliasing the gateway or overflowing the octet) reddens on the
    // disjointness and range legs below.
    #[test]
    fn segment_ip_math_range_injectivity_and_disjointness() {
        // Range: both coordinates are rejected at their boundaries, never wrapped.
        assert!(segment_ip_math(0, 1).is_err(), "segid 0");
        assert!(segment_ip_math(255, 1).is_err(), "segid 255");
        assert!(segment_ip_math(1, 0).is_err(), "slot 0 aliases the gateway");
        assert!(
            segment_ip_math(1, 254).is_err(),
            "slot 254 overflows the /24"
        );

        // Exact values: segid 1 → third octet 2, gateway .1, slot 1 → .2.
        let (gw, member, cidr) = segment_ip_math(1, 1).unwrap();
        assert_eq!(gw, Ipv4Addr::new(10, 201, 2, 1));
        assert_eq!(member, Ipv4Addr::new(10, 201, 2, 2));
        assert_eq!(cidr, "10.201.2.2/24");
        // The last legal slot lands on .254, and segid 254 wraps to third octet 1.
        assert_eq!(
            segment_ip_math(1, MAX_SEGMENT_SLOT).unwrap().1,
            Ipv4Addr::new(10, 201, 2, 254)
        );
        assert_eq!(
            segment_ip_math(254, 1).unwrap().0,
            Ipv4Addr::new(10, 201, 1, 1)
        );

        // Injectivity across the whole (segid, slot) space, and disjointness from every
        // per-VM /30 address the other scheme can emit.
        let mut seen = std::collections::HashSet::new();
        for segid in 1..=MAX_SEGMENT_ID {
            for slot in 1..=MAX_SEGMENT_SLOT {
                let (gw, member, _) = segment_ip_math(segid, slot).unwrap();
                assert_ne!(gw, member, "a member must never take the gateway address");
                assert!(
                    seen.insert(member),
                    "segment_ip_math({segid}, {slot}) collided with an earlier member"
                );
            }
        }
        for vmid in 1..=254u32 {
            let (host, guest, _) = ip_math(vmid).unwrap();
            assert!(
                !seen.contains(&host) && !seen.contains(&guest),
                "the per-VM /30 for vmid {vmid} overlaps the segment /24 space"
            );
        }
    }
}
