//! Privileged capability launcher (and nextest target-runner): raises the three capabilities the
//! privileged suite needs (`cap_net_admin,cap_sys_admin,cap_dac_override`), confines the exec target
//! under the trusted cargo `target/` dir derived from its OWN location, then `execvp`s it.
//!
//! The target is any binary confined under `target/`: a nextest test binary (the original use), **or**
//! another workspace binary such as **`vmcelld`** launched by an integration test or `just daemon`
//! (§11.2, Privilege and blessing). Launching `vmcelld` this way confers the three caps via the
//! **ambient** set without blessing `vmcelld` itself, so the daemon — which changes constantly —
//! rebuilds with no `setcap` churn, exactly the reason this runner was introduced for the
//! ever-changing test binaries (§15.5, The capability test runner).
//!
//! The blessing precondition and the pure privilege-transition plan live in `vmcell-privilege`, so
//! this crate and the daemon (`vmcelld`) share one copy of the security-critical cap logic
//! (§11.2, Privilege and blessing).
//! What stays here is the exec-target **confinement** — the boundary that makes launching an arbitrary
//! `target/` binary safe — plus the thin `main` that wires the shared pieces and performs the `execvp`.
//!
//! No crate-level `forbid(unsafe_code)`: the privilege transition (in `vmcell-privilege`) uses raw
//! capability/syscall FFI. `print_stdout`/`print_stderr` are intentionally NOT denied — a
//! target-runner's operator diagnostics go to stderr by contract.
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
        clippy::allow_attributes,               // B11: prefer #[expect] over #[allow] in prod code
        clippy::allow_attributes_without_reason  // B11: every suppression states why
    )
)]

use std::env;
use std::ffi::{OsStr, OsString};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path};
use std::process::Command;
use vmcell_privilege::{
    PRIVILEGED_CAPS, apply_privilege_transition, current_supplementary_groups,
    ensure_blessed_or_explain, lookup_group_gid, plan_privilege_transition, probe_supported_caps,
};

/// Terminate the wrapper with a non-zero status so the target runner records a failure.
///
/// This binary is a nextest target-runner: on any setup error it must exit non-zero. At every call
/// site there is no owned host state to unwind — the privilege transition has either not happened
/// yet or is being aborted — so `process::exit` (banned elsewhere for skipping Drop) is the correct
/// terminator. Centralized here behind one `#[expect]` so the ban stays live in the rest of the file.
fn exit_failure() -> ! {
    #[expect(
        clippy::disallowed_methods,
        reason = "nextest target-runner setup-error terminator; no owned host state to unwind at any call site"
    )]
    std::process::exit(1)
}

/// Verifies that `candidate` is safely confined under `target_root`.
///
/// Rejects any `..` (parent-dir) component and requires `candidate` to be a real path-component
/// descendant of `target_root`. A bare "has a component named `target`" check is not confinement:
/// it accepts unrelated paths like `/home/target/evil` and — because `..` resolves away — escapes
/// such as `…/target/../../usr/bin/sh`. Component-wise `starts_with` also rejects a sibling-prefix
/// like `…/target-evil/…`.
fn confine_under(candidate: &Path, target_root: &Path) -> Result<(), String> {
    if candidate
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(format!(
            "refusing target {}: contains a `..` component",
            candidate.display()
        ));
    }
    if candidate.starts_with(target_root) {
        Ok(())
    } else {
        Err(format!(
            "refusing target {}: not a descendant of the cargo target dir {}",
            candidate.display(),
            target_root.display()
        ))
    }
}

/// Derives the **trusted** confinement root from the runner's OWN (canonicalized) executable path —
/// never from the untrusted exec argument.
///
/// The blessed runner is installed to a stable path *outside* `target/`, namely
/// `<workspace>/.vmcell-bin/<profile>/vmcell-test-runner` (justfile / §15.5, The capability test runner, churn-fix #1). The
/// trusted workspace root is therefore the parent of the `.vmcell-bin` ancestor, and every
/// legitimate exec target (a test binary nextest hands us, or `vmcelld`; always under `<workspace>/target/…`)
/// must descend from `<workspace>/target`. Anchoring on the runner's own location is the security
/// boundary; anchoring on the *argument* (the pre-fix v15 behavior) was inert. A dev fallback also
/// accepts a runner still run in place from under `target/` itself.
fn trusted_target_root(exe: &Path) -> Result<std::path::PathBuf, String> {
    for anc in exe.ancestors() {
        if anc.file_name() == Some(OsStr::new(".vmcell-bin")) {
            let workspace = anc.parent().ok_or_else(|| {
                format!(
                    "runner path {} has a .vmcell-bin ancestor with no workspace root above it",
                    exe.display()
                )
            })?;
            return Ok(workspace.join("target"));
        }
    }
    for anc in exe.ancestors() {
        if anc.file_name() == Some(OsStr::new("target")) {
            return Ok(anc.to_path_buf());
        }
    }
    Err(format!(
        "cannot derive a trusted target root from the runner path {}: expected a \
         `.vmcell-bin/` (blessed, stable-path) or `target/` (in-place dev) ancestor",
        exe.display()
    ))
}

/// Confirms the exec target resolves to a binary inside the **trusted** cargo `target` directory
/// derived from the runner's own location ([`trusted_target_root`]).
///
/// `..` is rejected on the raw input first (canonicalization strips `..`), then the path is
/// canonicalized (resolving symlinks; a non-existent path fails closed), and the resolved path is
/// confirmed to descend from the trusted root. Returns the **canonicalized** path on success so the
/// caller execs exactly the file that was verified (M-HOST-2) — never the raw argument.
fn confine_target_under(target: &str, trusted_root: &Path) -> Result<std::path::PathBuf, String> {
    let raw = Path::new(target);
    if raw.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(format!(
            "refusing target {target}: contains a `..` component"
        ));
    }
    let resolved = raw
        .canonicalize()
        .map_err(|e| format!("cannot resolve target {target}: {e}"))?;
    confine_under(&resolved, trusted_root)?;
    Ok(resolved)
}

fn main() {
    // No tracing-subscriber here. This binary runs in the privileged window and must stay
    // dependency-thin, and it has to report failures that occur BEFORE the privilege drop. Fatal
    // errors go straight to stderr. Use `args_os()` (L-HOST-4: `env::args()` panics on non-UTF-8
    // argv) and refuse a non-UTF-8 target path with a typed error.
    let args: Vec<OsString> = env::args_os().collect();
    let Some((_runner, rest)) = args.split_first() else {
        eprintln!("vmcell-test-runner: usage: vmcell-test-runner <target-binary> [args...]");
        exit_failure();
    };
    let Some((target_os, forwarded)) = rest.split_first() else {
        eprintln!("vmcell-test-runner: usage: vmcell-test-runner <target-binary> [args...]");
        exit_failure();
    };

    // The blessing precondition (shared with the daemon): all three privileged caps must be in this
    // process's own EFFECTIVE set. Nothing else substitutes — a root process whose effective set was
    // narrowed (default container root, a `CapabilityBoundingSet=` that omits one of the three) is
    // REFUSED, because the caps this runner exists to hand its exec target would not be there (M5
    // deleted the euid-0 short-circuit that used to accept exactly that). Same remediation
    // machinery for both callers, one message per refusal shape (§11.2, Privilege and blessing).
    let need = PRIVILEGED_CAPS;
    if let Err(e) = ensure_blessed_or_explain(&need) {
        eprintln!("{e}");
        exit_failure();
    }

    // Confine the (untrusted) exec argument under a TRUSTED root derived from the runner's OWN
    // location — never from the argument itself (PRIV-1).
    let exe = match std::env::current_exe().and_then(|p| p.canonicalize()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("vmcell-test-runner: cannot resolve own executable path: {e}");
            exit_failure();
        }
    };
    let trusted_root = match trusted_target_root(&exe) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("vmcell-test-runner: {e}");
            exit_failure();
        }
    };
    let target = match target_os.to_str() {
        Some(s) => s,
        None => {
            eprintln!("vmcell-test-runner: refusing non-UTF-8 target path: {target_os:?}");
            exit_failure();
        }
    };
    let resolved_target = match confine_target_under(target, &trusted_root) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("vmcell-test-runner: {e}");
            exit_failure();
        }
    };

    // Compute the privilege transition as PURE data (unit-tested in `vmcell-privilege` against its
    // buggy inverses), then apply it. For the setuid-root form the uid drop is part of the plan and
    // `apply_privilege_transition` performs it BEFORE raising ambient — the security-critical
    // ordering. The kvm group and the supported-cap universe are captured here while still
    // privileged so getgroups/getgrnam/probe are unrestricted.
    let euid = rustix::process::geteuid();
    let uid = rustix::process::getuid();
    let gid = rustix::process::getgid();
    let kvm_gid = lookup_group_gid("kvm");
    let held_groups = current_supplementary_groups();
    let supported = probe_supported_caps();
    let plan = plan_privilege_transition(
        &need,
        &supported,
        euid.as_raw(),
        uid.as_raw(),
        gid.as_raw(),
        kvm_gid,
        &held_groups,
    );
    if let Err(e) = apply_privilege_transition(&plan) {
        eprintln!("vmcell-test-runner: {e}");
        exit_failure();
    }

    // M-HOST-2: exec the CANONICALIZED, verified path returned by `confine_target_under` — not the
    // raw argument (a bare filename triggers a PATH lookup; a symlink could be re-pointed TOCTOU).
    let err = Command::new(&resolved_target).args(forwarded).exec();
    eprintln!(
        "vmcell-test-runner: failed to exec {}: {err}",
        resolved_target.display()
    );
    exit_failure();
}

#[cfg(test)]
mod tests {
    use super::*;

    // Guards M-RUN-2: confinement must be a real path-descendant check, not a bare "has a component
    // named target". The buggy impl accepted any path with a `target` component.
    #[test]
    fn confine_under_requires_real_descendant() {
        let root = Path::new("/home/u/proj/target");
        assert!(confine_under(Path::new("/home/u/proj/target/debug/it"), root).is_ok());
        assert!(confine_under(Path::new("/home/target/evil"), root).is_err());
        assert!(confine_under(Path::new("/home/u/proj/target-evil/x"), root).is_err());
    }

    #[test]
    fn confine_under_rejects_parent_dir_components() {
        let root = Path::new("/tmp/x/target");
        assert!(confine_under(Path::new("/tmp/x/target/../../usr/bin/sh"), root).is_err());
    }

    // `..` is rejected before any filesystem resolution, so even a non-existent escape path fails
    // closed. The raw-input `..` rejection happens first, before canonicalization.
    #[test]
    fn confine_target_under_rejects_dotdot() {
        let trusted = Path::new("/tmp/x/target");
        assert!(confine_target_under("/tmp/x/target/../../usr/bin/sh", trusted).is_err());
        assert!(confine_target_under("relative/../escape", trusted).is_err());
    }

    // Derives the trusted root from the runner's OWN location (PRIV-1).
    #[test]
    fn trusted_target_root_derives_from_runner_location() {
        assert_eq!(
            trusted_target_root(Path::new(
                "/home/dev/proj/.vmcell-bin/debug/vmcell-test-runner"
            ))
            .expect("blessed path"),
            Path::new("/home/dev/proj/target")
        );
        assert_eq!(
            trusted_target_root(Path::new("/home/dev/proj/target/debug/vmcell-test-runner"))
                .expect("in-place path"),
            Path::new("/home/dev/proj/target")
        );
        assert!(trusted_target_root(Path::new("/usr/local/bin/vmcell-test-runner")).is_err());
    }

    // PRIV-1 inverse — the load-bearing security test. Confinement must anchor on the TRUSTED root
    // derived from the runner's own location, NOT on any `target/`-named ancestor of the untrusted
    // argument. Uses tempdirs so canonicalize() resolves real paths.
    #[test]
    fn confine_target_under_rejects_attacker_target_accepts_trusted_descendant() {
        let tmp = std::env::temp_dir()
            .canonicalize()
            .expect("canonical temp_dir");
        let ws = tmp.join("vmcell-priv1-ws");
        let runner = ws.join(".vmcell-bin/debug/vmcell-test-runner");
        std::fs::create_dir_all(runner.parent().expect("runner dir")).expect("mkdir runner");
        std::fs::write(&runner, b"#!/bin/true").expect("write runner");
        let trusted_root = trusted_target_root(&runner).expect("derive trusted root");
        assert_eq!(trusted_root, ws.join("target"));

        let good = ws.join("target/debug/deps/itest-bin");
        std::fs::create_dir_all(good.parent().expect("good dir")).expect("mkdir good");
        std::fs::write(&good, b"#!/bin/true").expect("write good");
        assert!(
            confine_target_under(good.to_str().expect("utf8"), &trusted_root).is_ok(),
            "a test binary under the trusted target/ must be accepted"
        );

        let attacker = tmp.join("vmcell-priv1-attacker/target/debug/evil");
        std::fs::create_dir_all(attacker.parent().expect("attacker dir")).expect("mkdir attacker");
        std::fs::write(&attacker, b"#!/bin/true").expect("write attacker");
        assert!(
            confine_target_under(attacker.to_str().expect("utf8"), &trusted_root).is_err(),
            "an attacker-controlled `target/`-named ancestor must be REJECTED (PRIV-1)"
        );

        let _ = std::fs::remove_dir_all(ws);
        let _ = std::fs::remove_dir_all(tmp.join("vmcell-priv1-attacker"));
    }

    // §11.2 (Privilege and blessing): the runner is used as a cap-conferring launcher for `vmcelld`, not only test binaries.
    // The confinement must accept `target/<profile>/vmcelld` under the trusted root (so an integration
    // test can `vmcell-test-runner target/debug/vmcelld …`), while still rejecting a `vmcelld` outside
    // it. RED if a change ever special-cased "test binaries" (e.g. a `deps/` or name filter) and locked
    // `vmcelld` out.
    #[test]
    fn confine_target_under_accepts_vmcelld_under_target() {
        let tmp = std::env::temp_dir()
            .canonicalize()
            .expect("canonical temp_dir");
        let ws = tmp.join("vmcell-d2-ws");
        let runner = ws.join(".vmcell-bin/debug/vmcell-test-runner");
        std::fs::create_dir_all(runner.parent().expect("runner dir")).expect("mkdir runner");
        std::fs::write(&runner, b"#!/bin/true").expect("write runner");
        let trusted_root = trusted_target_root(&runner).expect("derive trusted root");

        // `vmcelld` lands directly under `target/<profile>/`, not under `deps/` — assert it is admitted.
        for profile in ["debug", "release"] {
            let vmcelld = ws.join(format!("target/{profile}/vmcelld"));
            std::fs::create_dir_all(vmcelld.parent().expect("dir")).expect("mkdir");
            std::fs::write(&vmcelld, b"#!/bin/true").expect("write vmcelld");
            assert!(
                confine_target_under(vmcelld.to_str().expect("utf8"), &trusted_root).is_ok(),
                "the runner must accept target/{profile}/vmcelld so it can launch the daemon (§11.2, Privilege and blessing)"
            );
        }

        // A `vmcelld` OUTSIDE the trusted target/ is still rejected (the boundary is the location,
        // not the name).
        let rogue = tmp.join("vmcell-d2-rogue/target/debug/vmcelld");
        std::fs::create_dir_all(rogue.parent().expect("dir")).expect("mkdir");
        std::fs::write(&rogue, b"#!/bin/true").expect("write rogue");
        assert!(
            confine_target_under(rogue.to_str().expect("utf8"), &trusted_root).is_err(),
            "a vmcelld outside the trusted target/ must still be rejected"
        );

        let _ = std::fs::remove_dir_all(ws);
        let _ = std::fs::remove_dir_all(tmp.join("vmcell-d2-rogue"));
    }
}

/// The blessing precondition's gate, at **this** call site rather than only inside the predicate
/// (AGENTS.md: a gate binds the call sites) — the runner's half of the twin in `vmcelld`, whose
/// module doc carries the full rationale for the per-crate copy and for the two halves.
#[cfg(test)]
mod blessing_precondition_gate {
    use vmcell_privilege::{BlessingRefusal, Cap, CapSet, PRIVILEGED_CAPS, blessing_verdict};

    const SOURCE: &str = include_str!("main.rs");

    /// The line the comment under test sits above — the cap list the precondition is checked
    /// against, which is the first statement of that precondition here (the call is the next line;
    /// [`PRECONDITION`] pins that adjacency, so the comment cannot drift off what it describes).
    const CALL_SITE: &str = "let need = PRIVILEGED_CAPS;";

    /// The two statements the comment above `CALL_SITE` describes, verbatim: the runner binds the
    /// cap list (it needs it again for the transition plan) and then checks it.
    const PRECONDITION: &str =
        "let need = PRIVILEGED_CAPS;\n    if let Err(e) = ensure_blessed_or_explain(&need) {";

    /// The `//` comment block immediately above `anchor`, with the markers stripped.
    ///
    /// Panics if the anchor is missing or carries no comment — an extraction that silently returned
    /// nothing would make every assertion below vacuous.
    fn comment_block_before(source: &str, anchor: &str) -> String {
        let before = source
            .split_once(anchor)
            .unwrap_or_else(|| panic!("`{anchor}` must exist in this file"))
            .0;
        let mut block: Vec<&str> = Vec::new();
        for line in before.lines().rev() {
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix("//") {
                block.push(rest);
                continue;
            }
            // The anchor is mid-line, so the split's last "line" is the call's own indentation;
            // blank lines may also sit between a comment and its statement. Neither ends the block
            // before it has started — anything else does.
            if block.is_empty() && trimmed.is_empty() {
                continue;
            }
            break;
        }
        assert!(!block.is_empty(), "`{anchor}` must carry a comment block");
        block.reverse();
        block.join(" ")
    }

    /// Whether `comment` offers something *other than* holding the caps as a way to satisfy the
    /// precondition. The stale spellings, listed rather than guessed: this is what "the three
    /// privileged caps must be in the EFFECTIVE set, **or euid 0**" reads as once the short-circuit
    /// is gone.
    fn claims_an_exemption(comment: &str) -> bool {
        let lower = comment.to_lowercase();
        [
            "or euid",
            "or if euid",
            "or uid",
            "or be running as",
            "or running as",
        ]
        .iter()
        .any(|stale| lower.contains(stale))
    }

    // THE PROSE HALF. RED on the inverse: restore ", or euid 0." to the comment above the call.
    #[test]
    fn the_call_sites_comment_claims_no_euid_exemption() {
        assert!(
            SOURCE.contains(PRECONDITION),
            "the commented statement must still be the precondition itself — expected:\n\
             {PRECONDITION}"
        );
        let comment = comment_block_before(SOURCE, CALL_SITE);
        assert!(
            !claims_an_exemption(&comment),
            "the precondition admits no alternative to holding the caps (M5, law P1); this comment \
             still offers one:\n{comment}"
        );
        // Non-vacuity for the extraction AND the predicate: the block must actually be the one that
        // describes the precondition, so a comment that says nothing cannot pass by saying nothing.
        assert!(
            comment.contains("EFFECTIVE"),
            "the comment must name the set that decides — the effective one:\n{comment}"
        );
        // The predicate's own control: it flags the historical sentence and accepts the shipped one.
        assert!(claims_an_exemption(
            "the three privileged caps must be in the EFFECTIVE set, or euid 0."
        ));
    }

    // THE BEHAVIORAL HALF, so the prose above is pinned to what this runner's precondition actually
    // answers rather than to itself. RED on the inverse: put `if euid == 0 { return Ok(()) }` back
    // into `blessing_verdict` and the narrowed-root leg returns `Ok`.
    #[test]
    fn a_narrowed_root_cannot_run_the_privileged_suite() {
        let mut narrowed = CapSet::empty();
        narrowed.add(Cap::NET_ADMIN);
        assert!(
            matches!(
                blessing_verdict(0, &narrowed, &PRIVILEGED_CAPS),
                Err(BlessingRefusal::NarrowedRoot(_))
            ),
            "euid 0 with a narrowed effective set must refuse: the caps this runner hands its exec \
             target are not there to hand"
        );
        // Positive control: a root process that genuinely holds the caps still runs, so the refusal
        // above is about the narrowing and not about the uid.
        let mut full = CapSet::empty();
        for c in PRIVILEGED_CAPS {
            full.add(c);
        }
        assert_eq!(blessing_verdict(0, &full, &PRIVILEGED_CAPS), Ok(()));
    }
}
