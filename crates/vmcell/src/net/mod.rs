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
/// Deliberately its own constant rather than a reuse of [`MAX_VMID`] or [`MAX_SEGMENT_ID`]: this is
/// one *dimension of the codomain*, those are *domain ceilings*, and one constant for all three
/// would let a widened ceiling silently start wrapping two ids onto one address. The three
/// `const _: () = assert!(…)` blocks below are what keep the relations between them a **compile
/// error** instead of a comment.
const THIRD_OCTET_SPACE: u32 = 254;

/// The map's **second dimension**: the number of disjoint `/30`s that fit inside one
/// `10.200.<octet>.0/24` — `256 / 4` — of which [`ip_math`] assigns exactly one per vmid.
///
/// Until the H2 widening this dimension was unused: every vmid took the `.0/30` of its own third
/// octet, so the `/16` carried at most `THIRD_OCTET_SPACE` VMs and the other 63 `/30`s in each
/// `/24` sat unclaimed. That is the `≈254`-VM-per-`/16` ceiling design §17 (Networking) records.
/// Claiming it multiplies the address space by 64 while leaving the `sub == 0` row — every vmid in
/// `1..=THIRD_OCTET_SPACE` — byte-for-byte where it already was.
const SUBNETS_PER_THIRD_OCTET: u32 = 64;

/// The highest VMID the host addressing law admits, named once here instead of spelled inline at
/// each of its homes.
///
/// **Moving it is a coordinated change, not an edit here.** The ceiling has six homes, and
/// `the_vmid_ceiling_is_one_law_with_five_other_homes` (this module's tests) is their executable
/// roster: raising this constant alone reddens it at every home that did not move with it. Five of
/// the six now read this constant (so their drift is a *compile* error); the sixth mirrors it
/// because it must compile without the `host-common` feature, and its mirror carries an equality
/// assert.
///
/// 1. **This map.** [`ip_math`] and [`mac_math`] refuse anything above it. The map stays a
///    bijection only while `MAX_VMID <= THIRD_OCTET_SPACE * SUBNETS_PER_THIRD_OCTET` — asserted
///    below as a `const`.
/// 2. **`orchestrator::VmidAllocator::allocate`** and `reserve`, which bound the id space they
///    search and accept.
/// 3. **The interface-name budget.** `<prefix>-tap-<vmid>` must fit `IFNAMSIZ - 1`; at
///    [`crate::naming::MAX_RESOURCE_PREFIX_LEN`] that admits at most **four** decimal digits, so
///    this ceiling cannot exceed 9999 without buying the digit out of the prefix budget or
///    changing the tap-name scheme. It is *at* that bound — `const`-asserted below — so the
///    interface-name budget, not the address space, is what stops the next widening.
/// 4. **The guest CID space** ([`crate::vmm::MIN_GUEST_CID`]`..=`[`crate::vmm::MAX_GUEST_CID`]).
///    Every VM allocates a guest CID unconditionally in `MicroVm::start`, so a CID space narrower
///    than this one is the *binding* ceiling on concurrent VMs per host — which is exactly what it
///    was (`3..=254`: 252 VMs, below the map's own 254, so widening the map alone would have raised
///    the concurrent-VM count by zero). [`crate::vmm::MAX_GUEST_CID`] is now **derived** from this
///    constant, so the two move together by construction.
/// 5. **`net::smoltcp`'s reserved host MAC**, which must stay outside the image of
///    [`mac_math`] over `1..=MAX_VMID` (`host_nat_mac_never_collides_with_guest_mac`).
/// 6. **`config::VmConfigBuilder::build`**, the boundary-1 window on a caller-pinned
///    `cfg.vmid`. An explicit vmid the map can address but the builder refuses is a ceiling that
///    disagrees with this one.
pub const MAX_VMID: u32 = 9999;

/// The bijection precondition for [`ip_math`], as a compile error rather than a comment: the map
/// `vmid ↦ ((vmid - 1) / THIRD_OCTET_SPACE, (vmid % THIRD_OCTET_SPACE) + 1)` is injective exactly
/// while the domain is no larger than the product of the two dimensions. Above it, two vmids share
/// one `/30` — two guests with one address, which is a silent data-plane defect rather than a loud
/// refusal.
const _: () = assert!(
    MAX_VMID <= THIRD_OCTET_SPACE * SUBNETS_PER_THIRD_OCTET,
    "MAX_VMID exceeds the (third octet × /30-within-/24) address space: ip_math would wrap two \
     vmids onto one /30. There is no third dimension inside 10.200.0.0/16 — widening past this \
     means taking another /16, not raising this constant."
);

/// Home 3 of [`MAX_VMID`]'s roster as a compile error: `<prefix>-tap-<vmid>` must fit
/// `IFNAMSIZ - 1`, and at [`crate::naming::MAX_RESOURCE_PREFIX_LEN`] that leaves room for exactly
/// four decimal digits. `crate::naming` cannot import this constant (it compiles without
/// `host-common`, which gates this module), so the budget itself is asserted in
/// `naming::interface_names_fit_ifnamsiz` against the real `libc::IFNAMSIZ`; what is asserted here
/// is the *digit count* that budget was measured at.
const _: () = assert!(
    MAX_VMID < 10_000,
    "MAX_VMID needs a fifth decimal digit, which `<prefix>-tap-<vmid>` has no room for at \
     naming::MAX_RESOURCE_PREFIX_LEN. Widening past this costs prefix budget or a new tap-name \
     scheme — see naming::interface_names_fit_ifnamsiz, which measures the real IFNAMSIZ."
);

/// Centralized IP math for VM network. Returns (host_ip, guest_ip, guest_cidr).
///
/// The map is two-dimensional (§9.3). The third octet is `(vmid % 254) + 1`; the fourth picks one
/// of the 64 `/30`s inside that `/24` — `sub = (vmid - 1) / 254`, based at `4 * sub` — and the pair
/// is that `/30`'s `.1` (host) and `.2` (guest).
///
/// The second dimension is a **strict superset** of the one-dimensional map it replaced: for every
/// `vmid` in `1..=254`, `sub` is 0, the base is `.0`, and the pair is `.1`/`.2` exactly as before
/// (`the_widened_map_agrees_with_the_one_dimensional_map_it_replaced`).
///
/// [`MAX_VMID`] documents the ceiling this imposes and what moving it costs.
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
    // The `const` assert above bounds `sub` by `SUBNETS_PER_THIRD_OCTET - 1 = 63`, so `base` is at
    // most 252 and neither of the two casts below can truncate — nor can either address land on
    // the `/24`'s `.0` network or `.255` broadcast.
    let sub = (vmid - 1) / THIRD_OCTET_SPACE;
    let base = 4 * sub;
    let host = (base + 1) as u8;
    let guest = (base + 2) as u8;
    Ok((
        Ipv4Addr::new(10, 200, octet, host),
        Ipv4Addr::new(10, 200, octet, guest),
        format!("10.200.{octet}.{guest}/30"),
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
/// whole `10.200.0.0/16` — every third octet, and (since the H2 widening) up to all 64 `/30`s
/// inside each of them — so the two schemes cannot collide for any (vmid, segid, slot) triple.
/// That disjointness is a property of the `/16`, not of either ceiling, which is why widening
/// [`MAX_VMID`] does not touch it.
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
    /// Buggy impls guarded, each constructed and watched go red: a map that drops the `+ 1`
    /// (vmid 254 → third octet 0, the network address) reddens on the reserved-octet leg; one that
    /// moves the per-VM map onto `10.201` reddens on the segment-disjointness leg; a ceiling that
    /// *vanishes* instead of moving (dropping `vmid > MAX_VMID`) reddens on the refusal leg; and —
    /// the defect this widening could most easily have shipped — a raised `MAX_VMID` whose map
    /// forgot the second dimension (`base = 0` unconditionally, which still satisfies every
    /// `const` assert, so no compiler sees it) puts vmid 1 and vmid 255 on the same
    /// `10.200.2.0/30` and reddens on the injectivity and subnet legs. Widening past the codomain
    /// itself (`MAX_VMID > THIRD_OCTET_SPACE * SUBNETS_PER_THIRD_OCTET`) never reaches this test at
    /// all: it is a compile error.
    #[test]
    fn vmid_address_map_is_a_bijection_over_the_whole_supported_range() {
        use std::collections::HashSet;

        let mut hosts = HashSet::new();
        let mut guests = HashSet::new();
        let mut macs = HashSet::new();
        // The `/30`s themselves: `(third octet, base of the /30)`. Two vmids sharing a `/30` but
        // (impossibly) not an address would still put two guests on one broadcast domain, so the
        // subnet is asserted unique in its own right rather than inferred from the addresses.
        let mut subnets = HashSet::new();

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

            // The /30 shape: the pair is the `.1`/`.2` of a four-address block whose base is a
            // multiple of four, both sides in the same block, and the CIDR the guest is handed
            // agrees with the address it is handed. Asserted as `base + 1` / `base + 2` rather
            // than the literal `.1`/`.2` the one-dimensional map emitted, because the second
            // dimension is exactly what moves the base off zero.
            let base = u32::from(guest.octets()[3]) & !3;
            assert_eq!(
                u32::from(host.octets()[3]),
                base + 1,
                "host side of vmid {vmid}'s /30 ({host})"
            );
            assert_eq!(
                u32::from(guest.octets()[3]),
                base + 2,
                "guest side of vmid {vmid}'s /30 ({guest})"
            );
            assert_eq!(
                host.octets()[2],
                guest.octets()[2],
                "vmid {vmid} split its /30"
            );
            assert_eq!(cidr, format!("{guest}/30"), "vmid {vmid} CIDR vs address");
            // Neither end may be the block's own network (`base`) or broadcast (`base + 3`); the
            // `.1`/`.2` assertions above already imply it, and this states the reason.
            assert!(
                base + 3 <= 255,
                "vmid {vmid}'s /30 at base {base} overruns the /24"
            );

            // Injectivity — the bijection. All three of host address, guest address and the /30
            // itself, because a map that collided only on the host side would still wedge the
            // gateway, and one that put two VMs in one /30 without sharing an address would still
            // merge two broadcast domains.
            assert!(hosts.insert(host), "vmid {vmid} reused host address {host}");
            assert!(
                guests.insert(guest),
                "vmid {vmid} reused guest address {guest}"
            );
            assert!(
                subnets.insert((guest.octets()[2], base)),
                "vmid {vmid} reused the /30 10.200.{}.{base}/30",
                guest.octets()[2]
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

        // Surjectivity onto the codomain the ceiling claims: `MAX_VMID` distinct /30s. Together
        // with injectivity above, that is the bijection.
        assert_eq!(hosts.len(), MAX_VMID as usize);
        assert_eq!(guests.len(), MAX_VMID as usize);
        assert_eq!(macs.len(), MAX_VMID as usize);
        assert_eq!(subnets.len(), MAX_VMID as usize);

        // Disjointness from the segment `/16` over the WHOLE widened range, not just the range the
        // one-dimensional map could reach. `segment_ip_math_range_injectivity_and_disjointness`
        // checks the same property from the other side; this leg is what makes a widened
        // `MAX_VMID` re-prove it instead of inheriting a stale 254-wide claim.
        for segid in 1..=MAX_SEGMENT_ID {
            for slot in 1..=MAX_SEGMENT_SLOT {
                let (gw, member, _) = segment_ip_math(segid, slot).expect("segment maps");
                for addr in [gw, member] {
                    assert!(
                        !hosts.contains(&addr) && !guests.contains(&addr),
                        "segment ({segid}, {slot}) address {addr} collides with a per-VM /30"
                    );
                }
            }
        }

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

    /// The widened, two-dimensional map **agrees byte-for-byte** with the one-dimensional map it
    /// replaced, over that map's entire domain (`1..=254`).
    ///
    /// This is what makes the widening a strict superset rather than a renumbering: design §9.3's
    /// own statement of the third-octet map, every pinned golden in the tree
    /// (`net::tap`'s vmid-1/vmid-254 render goldens and its `10.200.43.1` / `10.200.10.1` nftables
    /// fixtures, `orchestrator`'s "vmid 5 → 10.200.6.2"), and every already-running host's
    /// addressing all stay true across the change. A widening that shifted even one of the first
    /// 254 addresses would be a fleet-wide renumber wearing a ceiling raise's clothes.
    ///
    /// The old map is spelled out here **deliberately as a second copy** — the one place in the
    /// tree where that is right, because the property under test *is* equality with a formula that
    /// no longer exists in production. Everywhere else, a second copy is the defect.
    ///
    /// Buggy impl guarded: any `base` that is non-zero for `sub == 0` (say `base = 4 * sub + 4`)
    /// moves all 254 and reddens on the first vmid.
    #[test]
    fn the_widened_map_agrees_with_the_one_dimensional_map_it_replaced() {
        for vmid in 1..=THIRD_OCTET_SPACE {
            // The pre-widening formula, verbatim.
            let octet = ((vmid % 254) + 1) as u8;
            let (host, guest, cidr) = ip_math(vmid).expect("the old domain must still map");
            assert_eq!(
                host,
                Ipv4Addr::new(10, 200, octet, 1),
                "vmid {vmid} host address moved"
            );
            assert_eq!(
                guest,
                Ipv4Addr::new(10, 200, octet, 2),
                "vmid {vmid} guest address moved"
            );
            assert_eq!(
                cidr,
                format!("10.200.{octet}.2/30"),
                "vmid {vmid} CIDR moved"
            );
        }

        // …and the first vmid *past* the old domain is where the second dimension starts: the same
        // third octet as vmid 1, one /30 further in. Without this leg the test above is satisfied
        // by a map that never widened at all.
        assert_eq!(
            ip_math(THIRD_OCTET_SPACE + 1)
                .expect("the widened domain maps")
                .1,
            Ipv4Addr::new(10, 200, 2, 6),
            "vmid 255 must take the second /30 of 10.200.2.0/24, beside vmid 1's"
        );
    }

    /// The executable roster of the vmid ceiling's **other** homes (design §17, Networking).
    ///
    /// [`MAX_VMID`] names the ceiling once, but five more sites carry it. Five of the six now read
    /// this constant directly, so their drift is a compile error; home 3 mirrors it (it must
    /// compile without `host-common`) and carries its own equality assert. This test is what makes
    /// raising `MAX_VMID` alone go red at each home that did not move with it — the "one law, one
    /// predicate" mechanism where the drift is not a compile error — and
    /// `scripts/ban-inline-vmid-ceiling.sh` is its complement, catching a *new* site that spells
    /// the ceiling inline instead of importing it.
    ///
    /// It also records the discharge of the §17 finding it used to record: the guest CID space was
    /// the lower ceiling (252 < 254), so widening the `/16` map alone would have raised the
    /// concurrent-VM count by exactly zero. [`crate::vmm::MAX_GUEST_CID`] is now derived from
    /// [`MAX_VMID`], and this test's home-4 leg is what proves the derivation holds end to end
    /// rather than in the constant alone.
    ///
    /// Buggy impls guarded: reverting any one home to its `254` literal reddens that home's leg
    /// (each was reverted in turn and watched go red); raising `MAX_VMID` to 10000 reddens the
    /// interface-name leg — and fails to compile, because of the four-digit `const` assert.
    #[test]
    fn the_vmid_ceiling_is_one_law_with_five_other_homes() {
        // Home 2: the VMID allocator's accepted window. It must accept exactly what the address map
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

        // Home 4: the guest CID space. Every VM allocates one unconditionally in `MicroVm::start`,
        // so a CID space narrower than the vmid space is the binding ceiling on concurrent VMs per
        // host — which it was, at 252. Drained rather than read off the constant: the constant
        // being right and the allocator handing out that many are two different claims, and it was
        // the allocator's own `3..=254` literal that bound the host.
        let cids = crate::vmm::CidAllocator::new();
        let mut handed = 0u32;
        while cids.allocate().is_ok() {
            handed += 1;
            assert!(
                handed <= MAX_VMID,
                "the CID space outgrew the vmid space it is sized from"
            );
        }
        assert_eq!(
            handed, MAX_VMID,
            "the guest CID space must hold one CID per addressable vmid, or it — not the address \
             map — is the ceiling on concurrent VMs per host (design §17, Networking)"
        );

        // Home 5 is `net::smoltcp`'s reserved host MAC, whose own gate
        // (`host_nat_mac_never_collides_with_guest_mac`) iterates `1..=MAX_VMID`. Not re-asserted
        // here: one law, one home — this roster names it, it does not copy it.

        // Home 6: `VmConfigBuilder::build`'s boundary-1 window on a caller-pinned `cfg.vmid`. It
        // refuses loudly rather than wrapping, so a stale copy here is not a data-plane defect —
        // it is a second, narrower ceiling on one input path, which is exactly the disagreement
        // this roster exists to make visible.
        let build_with_vmid = |vmid: u32| {
            crate::config::VmConfig::builder(
                std::path::PathBuf::from("/vmlinux"),
                crate::config::RootfsSource::Erofs {
                    image: std::path::PathBuf::from("/rootfs.erofs"),
                },
            )
            .vmid(vmid)
            .build()
        };
        assert!(
            build_with_vmid(MAX_VMID).is_ok(),
            "the config boundary refuses a vmid the address map and the allocator both admit"
        );
        assert!(
            build_with_vmid(MAX_VMID + 1).is_err(),
            "the config boundary's ceiling did not move with net::MAX_VMID"
        );
    }

    #[test]
    fn test_ip_math() {
        assert!(ip_math(0).is_err());
        assert!(ip_math(MAX_VMID + 1).is_err());
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
        for vmid in 1..=MAX_VMID {
            let (host, guest, _) = ip_math(vmid).unwrap();
            assert!(
                !seen.contains(&host) && !seen.contains(&guest),
                "the per-VM /30 for vmid {vmid} overlaps the segment /24 space"
            );
        }
    }
}
