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

pub use segment::{NetSegment, NetSegmentRef, SegmentMember, SegmentMembership};
pub use tap::{NetNamespace, cleanup_orphan_netns};

#[cfg(feature = "net-unprivileged")]
pub use smoltcp::backend::SmoltcpProcess;

use crate::error::{Error, Result};
use std::net::Ipv4Addr;

/// Centralized IP math for VM network. Returns (host_ip, guest_ip, guest_cidr).
///
/// # Errors
/// Returns an error if the VMID is out of range.
pub fn ip_math(vmid: u32) -> Result<(Ipv4Addr, Ipv4Addr, String)> {
    if vmid == 0 || vmid > 254 {
        return Err(Error::Network(format!("VMID {vmid} out of range")));
    }
    let octet = ((vmid % 254) + 1) as u8;
    Ok((
        Ipv4Addr::new(10, 200, octet, 1),
        Ipv4Addr::new(10, 200, octet, 2),
        format!("10.200.{octet}.2/30"),
    ))
}

/// The highest segment id (and the highest vmid) the addressing math can carry.
pub const MAX_SEGMENT_ID: u32 = 254;

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
    let octet = ((segid % MAX_SEGMENT_ID) + 1) as u8;
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
/// # Errors
/// Returns an error if the VMID is out of range.
pub fn mac_math(vmid: u32) -> Result<String> {
    if vmid == 0 || vmid > 254 {
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
