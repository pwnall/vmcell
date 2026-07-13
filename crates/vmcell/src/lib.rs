//! `vmcell` is a framework for fast, snapshot-based microvm testing.
//!
//! This crate provides tools to configure, launch, and interact with microVMs.
//! It includes abstractions for networking, virtual machine monitors (like Cloud Hypervisor),
//! and an agent protocol for executing commands inside the guest.

#![deny(missing_docs)]
#![deny(unreachable_pub)] // pub-in-private-module API-surface honesty
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::multiple_unsafe_ops_per_block, // one obligation per SAFETY comment
    unsafe_op_in_unsafe_fn,
    rustdoc::broken_intra_doc_links
)]
// The host `Vmm`/`Stage`/… traits deliberately use `async fn` in traits; the desugaring caveats are
// understood and accepted. Scoped to `host-common` (where those traits live) so the expectation is
// fulfilled exactly when they compile — a bare crate-level `#[expect]` would go unfulfilled in the
// no-host-feature powerset configs where none is present, and a bare `#[allow]` now trips B11.
#![cfg_attr(
    feature = "host-common",
    expect(
        async_fn_in_trait,
        reason = "host traits intentionally use async-fn-in-trait; caveats accepted (host-common only)"
    )
)]
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
        clippy::dbg_macro,
        clippy::allow_attributes,               // B11: prefer #[expect] over #[allow] in prod code
        clippy::allow_attributes_without_reason  // B11: every suppression states why
    )
)]
/// Agent protocol and client implementation.
pub mod agent;
/// Error and Result types.
pub mod error;
/// The one place that composes swept per-VM host resource names from a configurable prefix (§13, Cross-cutting invariants).
pub mod naming;

/// Artifact building stages and pipeline.
#[cfg(feature = "host-common")]
pub mod artifact;

/// VM configuration models.
#[cfg(feature = "host-common")]
pub mod config;

/// The process-wide seam bundle (`HostEnv`), threaded by reference to every VM-spawning entry point
/// (§9.3, The public API surface, design §18, Delta register: changes from the validated v27 build, deltas 1–2).
#[cfg(feature = "host-common")]
pub mod env;

/// CPU-frequency pinning for benchmark noise-floor discipline.
#[cfg(feature = "host-common")]
pub mod cpufreq;

/// virtio-fs daemon implementation.
#[cfg(feature = "host-common")]
pub mod fs;

/// The one-probe host-capability descriptor (`HostCapabilities`), §7.2 (The fail-loud capability contract and HostCapabilities) / design §18 (Delta register: changes from the validated v27 build) delta 8.
#[cfg(feature = "host-common")]
pub mod hostcaps;

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

/// Copy-on-write cloning of zygote suspend images (§8.4, The zygote fan-out and the OverlayStore seam).
#[cfg(feature = "host-common")]
mod reflink;

/// The `OverlayStore` seam: how a snapshot dir is copy-on-write cloned (§8.4, The zygote fan-out and the OverlayStore seam).
#[cfg(feature = "host-common")]
pub mod overlay;

/// Egress proxy implementation.
#[cfg(feature = "host-common")]
pub mod proxy;

/// Zygote suspend/resume fan-out: mint many identical VMs from one suspend image.
#[cfg(feature = "host-common")]
pub mod zygote;

/// Fork/branch lineage handles over the zygote fan-out (§8.5, Lineage: fork and branch).
#[cfg(feature = "host-common")]
pub mod lineage;

/// VMM interface and backend implementations.
#[cfg(feature = "host-common")]
pub mod vmm;

#[cfg(feature = "host-common")]
pub use agent::AgentClient;
pub use agent::{ExecOutcome, ExecRequest};
#[cfg(feature = "host-common")]
pub use config::{
    BlockDevice, ConsoleMode, DiskIoLimit, KernelVerbosity, NetConfig, ResourceLimits, Share,
    Timeouts, VmConfig,
};
#[cfg(feature = "host-common")]
pub use env::HostEnv;
pub use error::{Error, Result};
#[cfg(feature = "host-common")]
pub use hostcaps::HostCapabilities;
#[cfg(feature = "host-common")]
pub use lineage::{Lineage, LineageAllocator, LineageId};
#[cfg(feature = "host-common")]
pub use metrics::ResourceUsage;
#[cfg(feature = "host-common")]
pub use net::tap::NetNamespace;
#[cfg(feature = "host-common")]
pub use orchestrator::MicroVm;
#[cfg(feature = "host-common")]
pub use overlay::{OverlayStore, ReflinkOverlayStore};
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
