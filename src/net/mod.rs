//! Network management and namespaces.
//!
//! This module provides functionality for setting up network interfaces,
//! network namespaces, and userspace networking for the virtual machines.

#![forbid(unsafe_code)]

/// TAP interface and network namespace management.
pub mod tap;

#[cfg(feature = "net-unprivileged")]
/// rootless userspace networking with smoltcp.
pub mod smoltcp;

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
        return Err(Error::Network(format!("VMID {} out of range", vmid)));
    }
    let octet = ((vmid % 254) + 1) as u8;
    Ok((
        Ipv4Addr::new(10, 200, octet, 1),
        Ipv4Addr::new(10, 200, octet, 2),
        format!("10.200.{}.2/30", octet),
    ))
}

/// Centralized MAC address math for VM network.
///
/// # Errors
/// Returns an error if the VMID is out of range.
pub fn mac_math(vmid: u32) -> Result<String> {
    if vmid == 0 || vmid > 254 {
        return Err(Error::Network(format!("VMID {} out of range", vmid)));
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
}
