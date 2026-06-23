pub mod tap;

#[cfg(feature = "experiment-smoltcp")]
pub mod smoltcp;

pub use tap::NetNamespace;

#[cfg(feature = "experiment-smoltcp")]
pub use smoltcp::backend::SmoltcpProcess;
