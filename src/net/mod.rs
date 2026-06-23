/// TAP interface and network namespace management.
pub mod tap;

#[cfg(feature = "experiment-smoltcp")]
/// rootless userspace networking with smoltcp.
pub mod smoltcp;

pub use tap::NetNamespace;

#[cfg(feature = "experiment-smoltcp")]
pub use smoltcp::backend::SmoltcpProcess;
