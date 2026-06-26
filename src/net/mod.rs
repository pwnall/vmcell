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

pub use tap::NetNamespace;

#[cfg(feature = "net-unprivileged")]
pub use smoltcp::backend::SmoltcpProcess;
