//! The steward binary: a thin wrapper around [`vmcell_steward::run`].
//!
//! Everything this file used to carry — mounts, vsock serving, exec, sessions, power-off policy —
//! now lives in the library (design §3.5, v33 delta 5), so the same code runs whether the kernel
//! started the steward as PID 1 or somebody else's init started it as a service. All that is left
//! here is what a `daemon-bin`-style wrapper is for: select the placement, install the subscriber,
//! call `run`.
//!
//! **The placement is derived from `getpid()`, not from a flag.** A kernel-started steward is
//! pid 1; a systemd- or `mini-init`-started one is not. That is unforgeable and needs no argument,
//! which matters because this binary is also a legal `init=` target and its argv is the kernel's.
//!
//! `main.rs` staying thin is a *gated* property, not an intention: `vmcell_steward`'s
//! `main_is_thin_gate` scans this file's text and reddens on any item beyond `main` — the
//! split-drift hazard §3.5 names, which no per-crate dependency gate can see because cargo has no
//! per-target dependency graph.
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
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::dbg_macro,
        // B10: production guest/network-derived values narrow with `try_from`, never `as` (wire
        // crate). Test vectors may still build byte patterns with `as` — the repo's lenient-in-tests
        // idiom (clippy.toml allow-*-in-tests, AGENTS.md; see docs/implementation-notes.md).
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap,
        clippy::allow_attributes,               // B11: prefer #[expect] over #[allow] in prod code
        clippy::allow_attributes_without_reason  // B11: every suppression states why
    )
)]

fn main() -> Result<(), Box<dyn std::error::Error>> {
    vmcell_steward::run(vmcell_steward::StewardOptions::new(
        vmcell_steward::GuestPlacement::from_getpid(),
    ))
}
