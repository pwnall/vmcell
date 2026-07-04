//! `vmcell` is a framework for fast, snapshot-based microvm testing.
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

/// Artifact building stages and pipeline.
#[cfg(feature = "host-common")]
pub mod artifact;

/// VM configuration models.
#[cfg(feature = "host-common")]
pub mod config;

/// CPU-frequency pinning for benchmark noise-floor discipline.
#[cfg(feature = "host-common")]
pub mod cpufreq;

/// virtio-fs daemon implementation.
#[cfg(feature = "host-common")]
pub mod fs;

/// Resource usage metrics collection.
#[cfg(feature = "host-common")]
pub mod metrics;

/// Networking models and implementations (tap, smoltcp).
#[cfg(feature = "host-common")]
pub mod net;
/// Privileged-networking syscall helpers (kept out of `net`, which forbids unsafe).
#[cfg(feature = "net-privileged")]
mod net_sys;
/// VM orchestration and management.
#[cfg(feature = "host-common")]
pub mod orchestrator;

/// Copy-on-write cloning of zygote suspend images (§9.4).
#[cfg(feature = "host-common")]
mod reflink;

/// Egress proxy implementation.
#[cfg(feature = "host-common")]
pub mod proxy;

/// Zygote suspend/resume fan-out: mint many identical VMs from one suspend image.
#[cfg(feature = "host-common")]
pub mod zygote;

/// VMM interface and backend implementations.
#[cfg(feature = "host-common")]
pub mod vmm;

#[cfg(feature = "host-common")]
pub use agent::AgentClient;
pub use agent::{ExecOutcome, ExecRequest};
#[cfg(feature = "host-common")]
pub use config::{
    ConsoleMode, KernelVerbosity, NetConfig, ResourceLimits, Share, Timeouts, VmConfig,
};
pub use error::{Error, Result};
#[cfg(feature = "host-common")]
pub use metrics::ResourceUsage;
#[cfg(feature = "host-common")]
pub use net::tap::NetNamespace;
#[cfg(feature = "host-common")]
pub use orchestrator::MicroVm;
#[cfg(feature = "host-common")]
pub use proxy::EgressProxy;
#[cfg(feature = "host-common")]
pub use reflink::CowSupport;
#[cfg(feature = "firecracker")]
pub use vmm::Firecracker;
#[cfg(feature = "qemu")]
pub use vmm::Qemu;
#[cfg(feature = "host-common")]
pub use vmm::{CloudHypervisor, VmInstance, Vmm};
#[cfg(feature = "host-common")]
pub use zygote::Zygote;
