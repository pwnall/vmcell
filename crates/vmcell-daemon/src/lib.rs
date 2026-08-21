//! The vmcell control-plane daemon library (design §11, The control-plane daemon (`vmcelld`)).
//!
//! An **owning** daemon: it holds the `MicroVm` handles for the VMs it starts (through the
//! [`launcher::VmHandle`] seam), so their VMM processes and netns/tap/cgroup/scratch stay alive while
//! held and are released **on `Drop`** in order (§13, Cross-cutting invariants; the invariant is preserved). A
//! hard-killed daemon leaks resources; the next boot's **start-up orphan sweep**
//! (`vmcell::orchestrator::sweep_orphans`, wired in `vmcelld`) reclaims them. It also manages a flat
//! [`artifact_store::ArtifactStore`] (create/list/delete; no update) whose names are a restricted set
//! mapping directly to files ([`name`]), and serves a bearer-authenticated HTTP REST API ([`server`])
//! described by a served OpenAPI document ([`openapi`]).
//!
//! The `server` feature (default) pulls the axum/vmcell host stack. A client links this crate with
//! `default-features = false` to get only the wire [`dto`] types and the [`name`] predicate — the
//! schema is single-sourced without the client pulling the server (design §11.1, What it adds, and where it sits).
#![deny(missing_docs, unsafe_op_in_unsafe_fn, rustdoc::broken_intra_doc_links)]
#![deny(unreachable_pub)] // pub-in-private-module API-surface honesty
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::multiple_unsafe_ops_per_block // one obligation per SAFETY comment
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
        clippy::dbg_macro,
        clippy::print_stdout,
        clippy::print_stderr,
        // AGENTS.md "Fail loud": no bare `let _ =` on a `Result`. `let_underscore_must_use` is the
        // narrowest instrument rustc/clippy has for that rule — and it is deliberately BROADER on
        // one axis, firing on any `#[must_use]` expression (a detached `JoinHandle`, a discarded
        // `Instant`), which is the same defect one step out: the compiler said this matters and the
        // code said nothing back. Scoped `not(test)` like every lint in this block: the rule's
        // stated harms (a swallowed teardown failure, a lost write, a wedged session) are
        // production harms, and forcing a reason onto a test's `try_init()` would manufacture the
        // hollow suppressions AGENTS.md rule 2 calls theater. `crates/vmcell/tests/lint_roster.rs`
        // is the gate that this line exists in EVERY crate root, so a new crate cannot opt out by
        // being new.
        clippy::let_underscore_must_use,
        clippy::allow_attributes,               // B11: prefer #[expect] over #[allow] in prod code
        clippy::allow_attributes_without_reason  // B11: every suppression states why
    )
)]

// Always compiled — the wire schema + the name predicate, shared with the client.
pub mod dto;
pub mod name;

#[cfg(feature = "server")]
pub mod artifact_store;
#[cfg(feature = "server")]
pub mod auth;
#[cfg(feature = "server")]
pub mod bridge;
#[cfg(feature = "server")]
pub mod error;
#[cfg(feature = "server")]
pub mod launcher;
#[cfg(feature = "server")]
pub mod openapi;
#[cfg(feature = "server")]
pub mod registry;
#[cfg(feature = "server")]
pub mod scratch;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "server")]
pub mod sweep;
#[cfg(feature = "server")]
pub mod uds;

/// Re-export the resource-naming helpers so the daemon binary (`vmcelld`) can validate its
/// `--resource-prefix` without a direct `vmcell` dependency (design).
#[cfg(feature = "server")]
pub use vmcell::naming;

#[cfg(feature = "server")]
pub use error::{DaemonError, DaemonResult};
#[cfg(feature = "server")]
pub use server::{AppState, build_router, serve};
