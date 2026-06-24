//! Network management and namespaces.
//!
//! This module provides functionality for setting up network interfaces,
//! network namespaces, and userspace networking for the virtual machines.

/// TAP interface and network namespace management.
pub mod tap;

#[cfg(feature = "experiment-smoltcp")]
/// rootless userspace networking with smoltcp.
pub mod smoltcp;

pub use tap::NetNamespace;

#[cfg(feature = "experiment-smoltcp")]
pub use smoltcp::backend::SmoltcpProcess;
