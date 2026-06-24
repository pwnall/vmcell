//! `imp-testing` is a framework for fast, snapshot-based microvm testing.
//!
//! This crate provides tools to configure, launch, and interact with microVMs.
//! It includes abstractions for networking, virtual machine monitors (like Cloud Hypervisor),
//! and an agent protocol for executing commands inside the guest.

#![deny(missing_docs)]
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    unsafe_op_in_unsafe_fn,
    rustdoc::broken_intra_doc_links
)]
#![allow(async_fn_in_trait)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::dbg_macro
    )
)]
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

pub use agent::{AgentClient, ExecOutcome, ExecRequest};
#[cfg(feature = "host-common")]
pub use config::{NetConfig, ResourceLimits, Share, VmConfig};
pub use error::{Error, Result};
#[cfg(feature = "host-common")]
pub use metrics::ResourceUsage;
#[cfg(feature = "host-common")]
pub use net::tap::NetNamespace;
#[cfg(feature = "host-common")]
pub use orchestrator::TestVm;
#[cfg(feature = "host-common")]
pub use proxy::EgressProxy;
#[cfg(feature = "host-common")]
pub use vmm::{CloudHypervisor, VmInstance, Vmm};
