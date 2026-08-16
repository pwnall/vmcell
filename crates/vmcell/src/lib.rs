//! `vmcell` is a framework for fast, snapshot-based microvm testing.
//!
//! This crate provides tools to configure, launch, and interact with microVMs.
//! It includes abstractions for networking, virtual machine monitors (like Cloud Hypervisor),
//! and a steward protocol for executing commands inside the guest.
//!
//! # Consuming `vmcell` as a git dependency
//!
//! Out-of-repo consumers stand on one **named contract surface** (design §10.4, The downstream
//! toolkit contract): the pins schema + overlay ([`artifact::ResolvePinsStage`],
//! [`artifact::resolve_pins`], [`artifact::pins_overlay_path`]), the stage model
//! ([`artifact::Stage`], [`artifact::Pipeline`], [`artifact::CacheKey`]), the kernel build entry
//! points and their resolved-config sidecar, [`artifact::rootfs::pack_erofs_with_injection`] and the
//! rootfs-construction contract, the `VMCELL_*` environment contract, and the
//! `vmcell-artifact-validator` battery. A breaking change to any of it is a deliberate entry in the
//! comment-changelog at the top of this crate's `Cargo.toml`, gated by `cargo semver-checks` over
//! both contract crates and by the out-of-tree `examples/downstream-kernel/` consumer workspace.
//!
//! Two things bite consumers that the compiler cannot catch, both covered in the repository README's
//! "Consuming vmcell as a dependency" section:
//!
//! - **The vendored `vhost` patch does not travel with a git dep.** Cargo honors `[patch.crates-io]`
//!   only from the *consuming* workspace root, so a QEMU + [`config::NetConfig::Unprivileged`]
//!   consumer silently loses the carried `SET_VRING_ENABLE` fix and gets a cryptic vhost-handshake
//!   boot failure. Replicate the stanza, and run `scripts/check-vendored-vhost.sh` (path-independent,
//!   the same predicate this repo's CI runs) in your own CI.
//! - **The artifact bootstrap cannot build downstream.** Build artifacts with a vmcell checkout, or
//!   build kernels through the toolkit with `VMCELL_PINS`, then point `VMCELL_KERNEL` /
//!   `VMCELL_ROOTFS` at the outputs. The harness getters fail loud naming that route rather than
//!   attempting the workspace bootstrap against your checkout.

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
/// Error and Result types.
pub mod error;
/// The one place that composes swept per-VM host resource names from a configurable prefix (§13, Cross-cutting invariants).
pub mod naming;
/// Steward protocol and client implementation.
pub mod steward;

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
pub use steward::StewardClient;
/// The raw vsock dial's stream handle (§3.2, The host side: StewardClient and SessionMux), re-exported beside
/// [`StewardClient`] because `MicroVm::dial_vsock` returns it.
#[cfg(feature = "host-common")]
pub use steward::VsockDial;
pub use steward::{ExecOutcome, ExecRequest};
// The root re-export set is what `use vmcell::{…}` gives a consumer, and it must be *callable*:
// every type a caller cannot avoid naming to build a `VmConfig` is here, not only the leaf
// value types. `RootfsSource` is a required `VmConfig::builder` argument, `Egress` is carried by
// the `NetConfig::Privileged`/`Unprivileged` variants, and `UsbHostDevice` is the
// `with_usb_host_device` argument — a consumer holding only the leaf re-exports could not call the
// builder at all and had to reach into `vmcell::config` for the missing halves (docs/78 §9.4,
// `crate-root-reexport-roster-inconsistent`; this also retires the recorded `UsbHostDevice`
// residual). `root_reexport_tests` below is the gate: it builds a full config importing from the
// crate root only, so a re-export dropped from this list stops compiling.
#[cfg(feature = "host-common")]
pub use config::{
    BlockDevice, ConsoleMode, DiskIoLimit, Egress, KernelVerbosity, NetConfig, ResourceLimits,
    RootfsSource, Share, Timeouts, UsbHostDevice, VmConfig,
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
// `Firecracker` / `Qemu` now live in the `vmcell-firecracker` / `vmcell-qemu` crates; `vmcell`
// re-exports only the primary Cloud Hypervisor backend and the shared traits.
#[cfg(feature = "host-common")]
pub use vmm::{CloudHypervisor, VmInstance, Vmm};
#[cfg(feature = "host-common")]
pub use zygote::Zygote;

#[cfg(all(test, feature = "host-common"))]
mod root_reexport_tests {
    // GATE (docs/78 §9.4 `crate-root-reexport-roster-inconsistent`). Every path below names a type
    // through the crate ROOT — exactly what an out-of-repo consumer writes after
    // `use vmcell::{…}` — and never through `crate::config::…`. A re-export dropped from the
    // roster above therefore stops this module COMPILING, which is the failure mode: the defect
    // this guards (`RootfsSource`/`Egress`/`UsbHostDevice` reachable only via `vmcell::config`)
    // is invisible to any test that imports from the private-facing module path. Red-on-inverse:
    // remove `RootfsSource` from the root `pub use config::{…}` and `cargo test -p vmcell` fails
    // to build here.
    use crate::{Egress, NetConfig, RootfsSource, UsbHostDevice, VmConfig};

    #[test]
    fn a_full_vm_config_builds_from_the_root_reexports_alone() {
        let cfg = VmConfig::builder(
            "/nonexistent/vmlinux",
            RootfsSource::Erofs {
                image: "/nonexistent/rootfs.erofs".into(),
            },
        )
        .net(NetConfig::Unprivileged {
            egress: Egress::Blocked,
            host_services_port: None,
        })
        .with_usb_host_device(UsbHostDevice::new(0x1d6b, 0x0002))
        .build()
        .expect("a config naming only root-re-exported types must build");

        // Not a compile-only test: assert the values actually landed, so the builder chain cannot
        // be reduced to a type-check that silently drops what it was handed.
        assert!(matches!(cfg.rootfs, RootfsSource::Erofs { .. }));
        assert!(matches!(
            cfg.net,
            NetConfig::Unprivileged {
                egress: Egress::Blocked,
                host_services_port: None
            }
        ));
        assert_eq!(
            cfg.usb_host_devices,
            vec![UsbHostDevice::new(0x1d6b, 0x0002)]
        );
    }
}
