//! `imp-testing` is a framework for fast, snapshot-based microvm testing.
#![deny(missing_docs)]
#![deny(clippy::missing_errors_doc)]
/// Agent protocol and client implementation.
pub mod agent;
/// Error and Result types.
pub mod error;

#[cfg(feature = "host-common")]
/// Artifact building stages and pipeline.
pub mod artifact;
#[cfg(feature = "host-common")]
/// VM configuration models.
pub mod config;
#[cfg(feature = "host-common")]
/// virtio-fs daemon implementation.
pub mod fs;
#[cfg(feature = "host-common")]
/// Resource usage metrics collection.
pub mod metrics;
#[cfg(feature = "host-common")]
/// Networking models and implementations (tap, smoltcp).
pub mod net;
#[cfg(feature = "host-common")]
/// VM orchestration and management.
pub mod orchestrator;
#[cfg(feature = "host-common")]
/// Egress proxy implementation.
pub mod proxy;
#[cfg(feature = "host-common")]
/// VMM interface and backend implementations.
pub mod vmm;

#[cfg(feature = "host-common")]
pub use config::{NetConfig, ResourceLimits, Share, VmConfig};
pub use error::{Error, Result};
#[cfg(feature = "host-common")]
pub use orchestrator::TestVm;
