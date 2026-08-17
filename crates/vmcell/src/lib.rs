//! `vmcell` is a framework for fast, snapshot-based microvm testing.
//!
//! This crate provides tools to configure, launch, and interact with microVMs.
//! It includes abstractions for networking, virtual machine monitors (like Cloud Hypervisor),
//! and a steward protocol for executing commands inside the guest.
//!
//! # Worked examples
//!
//! Every example here is a **doctest**, compiled by `just test-doc` (which `just ci` invokes) and
//! therefore unable to describe an API this crate no longer has. Each is `no_run`: they boot real
//! guests, so they need a KVM host, a `cloud-hypervisor` binary and built artifacts
//! (`vmcell build`) — the gate compiles them and does not run them.
//!
//! The rest live on the items they document, under the same gate: a
//! [`Pipeline`](artifact::Pipeline) assembly and the one inject-and-pack tail in [`artifact`], a
//! `DaemonClient` round trip in `vmcell-daemon-client`, and the two-directional conformance battery
//! in `vmcell-artifact-validator`.
//!
//! ## Boot a cell, run a command in it, tear it down
//!
//! ```no_run
//! use vmcell::artifact::{ch_binary_path, kernel_path, rootfs_path};
//! use vmcell::{CloudHypervisor, ExecRequest, HostEnv, MicroVm, RootfsSource, VmConfig};
//!
//! # #[tokio::main]
//! # async fn main() -> vmcell::Result<()> {
//! // ONE seam bundle per process, threaded by reference into every VM-spawning entry point
//! // (§9.3). A composition root builds `shared()` once; a test builds `HostEnv::hermetic()`.
//! let env = HostEnv::shared()?;
//! // `$VMCELL_CH_BIN`, else `cloud-hypervisor` on `PATH` — the one resolver, never a second copy.
//! let vmm = CloudHypervisor::new(ch_binary_path());
//! // `kernel_path()` / `rootfs_path()` honor `$VMCELL_KERNEL` / `$VMCELL_ROOTFS`; the kernel must
//! // be an absolute path, which `build()` enforces rather than resolving against the VMM child's
//! // working directory.
//! let cfg = VmConfig::builder(kernel_path(), RootfsSource::Erofs { image: rootfs_path() })
//!     .vcpus(2)
//!     .mem_mib(512)
//!     .build()?;
//!
//! let mut vm = MicroVm::start(&vmm, cfg, &env).await?;
//! // `steward()` connects on first use; its argument is the per-call connect budget, not a seam.
//! let out = vm
//!     .steward(None)
//!     .await?
//!     .exec(ExecRequest::new(vec!["/bin/echo".into(), "hello".into()]))
//!     .await?;
//! assert_eq!(out.code, 0);
//! assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello");
//! // The graceful path. `Drop` is the panic path, and both run the one ordered teardown helper.
//! vm.shutdown().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Pay the boot cost once: suspend a zygote, fan out clones
//!
//! Booting to steward-ready is the dominant per-VM cost, so a pool pays it once: [`Zygote`] freezes
//! one warm cell and each clone restores from its own copy-on-write copy of that image.
//!
//! ```no_run
//! use vmcell::artifact::{ch_binary_path, kernel_path, rootfs_path};
//! use vmcell::{CloudHypervisor, ExecRequest, HostEnv, MicroVm, RootfsSource, VmConfig, Zygote};
//!
//! # #[tokio::main]
//! # async fn main() -> vmcell::Result<()> {
//! let env = HostEnv::shared()?;
//! let vmm = CloudHypervisor::new(ch_binary_path());
//! // Snapshot eligibility is a property of the CONFIG: a cell carrying a vhost-user device (a
//! // virtio-fs share, the unprivileged NAT, the external vsock daemon) is refused with a typed
//! // `Unsupported` rather than half-snapshotted (§8.1). The default `NetConfig::None` carries none.
//! let cfg = VmConfig::builder(kernel_path(), RootfsSource::Erofs { image: rootfs_path() })
//!     .snapshotting(true)
//!     .build()?;
//!
//! let mut warm = MicroVm::start(&vmm, cfg.clone(), &env).await?;
//! warm.steward(None).await?; // the boot cost, paid once
//! // Create-only: a destination that already holds anything is refused, never written into.
//! let master = std::env::temp_dir().join("vmcell-doc-zygote-master");
//! let zygote = Zygote::suspend(&mut warm, cfg, &master).await?;
//! warm.shutdown().await?;
//!
//! // Each clone restores from its OWN copy-on-write copy of the master (so the master is never
//! // mutated) and draws a FRESH vmid, hence its own IP/MAC/vsock (§8.2). Concurrent fan-out needs a
//! // backend that rotates host paths on restore; on one that does not — Firecracker — `spawn_clones`
//! // refuses `count > 1` with a typed error instead of letting the clones collide on one socket.
//! for mut clone in zygote.spawn_clones(&vmm, 4, &env).await? {
//!     // The first `steward()` call on a restored VM performs the mandatory resync (clock, entropy,
//!     // network identity) before it hands the client back.
//!     let out = clone
//!         .steward(None)
//!         .await?
//!         .exec(ExecRequest::new(vec!["/bin/true".into()]))
//!         .await?;
//!     assert_eq!(out.code, 0);
//!     clone.shutdown().await?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Consuming `vmcell` as a git dependency
//!
//! Out-of-repo consumers stand on one **named contract surface** (design §10.4, The downstream
//! toolkit contract): the pins schema + overlay ([`artifact::ResolvePinsStage`],
//! [`artifact::resolve_pins`], [`artifact::pins_overlay_path`]), the stage model
//! ([`artifact::Stage`], [`artifact::Pipeline`], [`artifact::CacheKey`]), the kernel build entry
//! points and their resolved-config sidecar, [`artifact::rootfs::pack_rootfs_with_injection`] — with
//! [`artifact::rootfs::pack_erofs_with_injection`] as its erofs-only door — and the
//! rootfs-construction contract, the `VMCELL_*` environment contract, and the
//! `vmcell-artifact-validator` battery.
//!
//! A change to any of it is a deliberate entry in the comment-changelog at the top of this crate's
//! `Cargo.toml`. Three gates hold three different halves of that promise, and none of them covers
//! another's:
//!
//! - `cargo semver-checks`, over both contract crates, gates the version **number** against the
//!   signatures that actually moved. It is silent by construction on an addition, and on any
//!   behavior change behind an unchanged signature — which is exactly why the ledger is written by
//!   hand and not derived.
//! - `tests/contract_ledger.rs` gates the **ledger itself**: that its `# X → Y:` entries form an
//!   unbroken chain ending at the version the crate publishes. Nothing gated that before, and the
//!   ledger had a two-version hole at its most breaking release (docs/90 C2).
//! - the out-of-tree `examples/downstream-kernel/` consumer workspace gates the **guidance**, by
//!   compiling against it — breaking its CI job is the intended failure mode of contract drift.
//!
//! What no gate can supply is the entry's prose. Write it for the consumer who is migrating.
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
/// The repository README, pulled in **only** when rustdoc is collecting doctests, so its Rust
/// examples are compiled by `just test-doc` exactly like the ones above.
///
/// `#[cfg(doctest)]` is the whole trick: that cfg is set only by rustdoc's test pass, so this item
/// is absent from `cargo build`, from `cargo doc`, and from the rustdoc JSON `cargo semver-checks`
/// reads — the README's setup instructions never become this crate's API documentation, and the item
/// itself is not public API. What it buys is that the README's worked example cannot rot: an
/// example on the front door that nothing compiles is the defect this closes (docs/90 D11), and
/// README examples are exactly where that rot is least visible.
#[cfg(doctest)]
#[doc = include_str!("../../../README.md")]
pub struct ReadmeExamplesAreDoctested;

/// Error and Result types.
pub mod error;
/// The feature vocabulary and the one intersection site (§7.4, invariant F6).
pub mod feature;
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
