//! Privileged nextest target-runner: raises the three capabilities the privileged suite needs
//! (`cap_net_admin,cap_sys_admin,cap_dac_override`), confines the exec target under the trusted
//! cargo `target/` dir derived from its OWN location, then `execvp`s the test binary.
//!
//! No crate-level `forbid(unsafe_code)`: the privilege transition uses raw capability/syscall FFI,
//! audited via `undocumented_unsafe_blocks` + `unsafe_op_in_unsafe_fn`. `print_stdout`/`print_stderr`
//! are intentionally NOT denied — a target-runner's operator diagnostics go to stderr by contract.
#![deny(missing_docs, unsafe_op_in_unsafe_fn, rustdoc::broken_intra_doc_links)]
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
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
        clippy::dbg_macro
    )
)]

use capctl::{Cap, CapSet, CapState};
use std::env;
use std::ffi::{OsStr, OsString};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path};
use std::process::Command;

/// Terminate the wrapper with a non-zero status so the target runner records a failure.
///
/// This binary is a nextest target-runner: on any setup error it must exit non-zero. At every
/// call site there is no owned host state to unwind — the privilege transition has either not
/// happened yet or is being aborted — so `process::exit` (banned elsewhere for skipping Drop) is
/// the correct terminator. Centralized here behind one `allow` so the ban stays live in the rest
/// of the file.
fn exit_failure() -> ! {
    #[allow(clippy::disallowed_methods)]
    std::process::exit(1)
}

/// Builds the operator-facing remediation message shown when the runner lacks
/// its capabilities.
///
/// The precondition (`ensure_blessed_or_explain`) checks the **effective** set,
/// so the printed `setcap` must grant `+ep` (effective + permitted). A bare `+p`
/// would set only the permitted set and the runner would still fail the check.
///
/// The message reports the **actual** `missing` set the precondition computed
/// (each `Cap` renders as `CAP_…`), so a missing `CAP_DAC_OVERRIDE` — omitted by
/// the pre-fix hardcoded prose — is named rather than silently dropped (PRIV-6).
fn blessing_remediation(uid: u32, exe: &Path, missing: &[Cap]) -> String {
    let missing_list = missing
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "error: vmcell-test-runner is missing {missing_list} in its effective set (uid={uid}, no file caps).\n\
         It was almost certainly rebuilt. Restore its privileges (one-time, until next rebuild):\n\n\
         sudo setcap cap_net_admin,cap_sys_admin,cap_dac_override+ep {}\n\n\
         Then re-run the privileged suite. See §12.8.",
        shell_single_quote(exe)
    )
}

/// Shell-single-quotes a path so a copy-pasted `setcap` command survives a
/// workspace path containing spaces or shell metacharacters (N-HOST-3). An
/// unquoted path with a space would be split by the shell into separate
/// arguments; single quotes disable all expansion, and an embedded single quote is
/// escaped with the standard `'\''` idiom.
fn shell_single_quote(p: &Path) -> String {
    format!("'{}'", p.display().to_string().replace('\'', r"'\''"))
}

/// Computes which of `need` are absent from the `effective` capability set.
///
/// Kept PURE (no `CapState::get_current`) so the check is unit-testable against its
/// buggy inverse (M-HOST-3): the privileged window needs the caps in the EFFECTIVE
/// set (file-cap `+ep` form), and a cap that is only *permitted* would fail at first
/// use, so the precondition must test `effective`, never `permitted`. A test that
/// puts a cap in permitted-only reddens if this ever consulted the permitted set.
fn compute_missing(effective: &CapSet, need: &[Cap]) -> Vec<Cap> {
    need.iter()
        .copied()
        .filter(|&c| !effective.has(c))
        .collect()
}

fn ensure_blessed_or_explain(need: &[Cap]) -> Result<(), String> {
    let caps = CapState::get_current().map_err(|e| e.to_string())?;

    // Check if euid is 0 (setuid root fallback).
    let euid = rustix::process::geteuid();
    if euid.as_raw() == 0 {
        return Ok(());
    }

    // The privileged window needs these caps in the EFFECTIVE set (file-caps +ep form).
    let missing = compute_missing(&caps.effective, need);

    if missing.is_empty() {
        Ok(())
    } else {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        Err(blessing_remediation(
            rustix::process::getuid().as_raw(),
            &exe,
            &missing,
        ))
    }
}

/// Verifies that `candidate` is safely confined under `target_root`.
///
/// Rejects any `..` (parent-dir) component and requires `candidate` to be a
/// real path-component descendant of `target_root`. A bare "has a component
/// named `target`" check is not confinement: it accepts unrelated paths like
/// `/home/target/evil` and — because `..` resolves away — escapes such as
/// `…/target/../../usr/bin/sh`. Component-wise `starts_with` also rejects a
/// sibling-prefix like `…/target-evil/…`.
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

/// Derives the **trusted** confinement root from the runner's OWN (canonicalized)
/// executable path — never from the untrusted exec argument.
///
/// The blessed runner is installed to a stable path *outside* `target/`, namely
/// `<workspace>/.vmcell-bin/<profile>/vmcell-test-runner` (justfile / §12.8
/// churn-fix #1). The trusted workspace root is therefore the parent of the
/// `.vmcell-bin` ancestor, and every legitimate exec target (the test binary
/// nextest hands us, always under `<workspace>/target/…`) must descend from
/// `<workspace>/target`. Anchoring on the runner's own location is the security
/// boundary; anchoring on the *argument* (the pre-fix v15 behavior) was inert —
/// a caller-supplied `target_root` is by construction an ancestor of the argument,
/// so the containment check always passed (`/home/attacker/target/debug/evil`
/// slipped through). A dev fallback also accepts a runner still run in place from
/// under `target/` itself (unblessed, so it would fail the effective-set check
/// first — but we fail closed regardless of that ordering).
fn trusted_target_root(exe: &Path) -> Result<std::path::PathBuf, String> {
    // Preferred: the blessed runner under <workspace>/.vmcell-bin/<profile>/… →
    // the trusted target dir is <workspace>/target.
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
    // Dev fallback: a runner still executed in place from <workspace>/target/… →
    // its own nearest `target/` ancestor IS the trusted cargo target dir.
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

/// Confirms the exec target resolves to a binary inside the **trusted** cargo
/// `target` directory derived from the runner's own location ([`trusted_target_root`]).
///
/// `..` is rejected on the raw input first (canonicalization strips `..`, so a later
/// check could not distinguish an escape attempt), then the path is canonicalized
/// (resolving symlinks; a non-existent path fails closed), and the resolved path is
/// confirmed to descend from the trusted root — NOT from any `target/`-named ancestor
/// of the argument itself, which is what made the pre-fix v15 check a no-op.
///
/// Returns the **canonicalized** path on success so the caller execs exactly the
/// file that was verified (M-HOST-2) — never the raw argument, whose bare filename
/// would trigger a `PATH` lookup and whose symlink could be re-pointed between the
/// check and the exec.
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

/// Looks up the numeric gid for a group name, or `None` if it does not exist.
fn lookup_group_gid(name: &str) -> Option<libc::gid_t> {
    let cname = std::ffi::CString::new(name).ok()?;
    // SAFETY: `getgrnam` receives a valid NUL-terminated C string and returns
    // either NULL or a pointer to a `group`. We read `gr_gid` once and copy it
    // out; the pointer is not retained. Single-threaded pre-exec context.
    unsafe {
        let grp = libc::getgrnam(cname.as_ptr());
        if grp.is_null() {
            None
        } else {
            Some((*grp).gr_gid)
        }
    }
}

/// Returns the process's current supplementary group ids.
fn current_supplementary_groups() -> Vec<libc::gid_t> {
    // SAFETY: the first `getgroups` (size 0, null ptr) only queries the count;
    // the second fills an exactly-sized buffer. Standard `getgroups(2)` usage.
    unsafe {
        let n = libc::getgroups(0, std::ptr::null_mut());
        if n <= 0 {
            return Vec::new();
        }
        let mut buf: Vec<libc::gid_t> = vec![0; n as usize];
        let got = libc::getgroups(n, buf.as_mut_ptr());
        if got < 0 {
            return Vec::new();
        }
        buf.truncate(got as usize);
        buf
    }
}

/// Builds the supplementary-group list to install before dropping uid.
///
/// Always includes the primary `gid`; additionally preserves `kvm_gid` when the
/// process currently holds it, so the exec'd test keeps `/dev/kvm` access by
/// group membership (it is `root:kvm 0660`) instead of relying solely on the
/// incidental `CAP_DAC_OVERRIDE` we carry. Never duplicates the primary gid and
/// never invents a membership the invoker did not have.
fn merge_preserved_groups(
    gid: libc::gid_t,
    kvm_gid: Option<libc::gid_t>,
    held: &[libc::gid_t],
) -> Vec<libc::gid_t> {
    let mut groups = vec![gid];
    if let Some(kvm) = kvm_gid {
        if kvm != gid && held.contains(&kvm) {
            groups.push(kvm);
        }
    }
    groups
}

/// The invoking user's identity to drop to BEFORE raising ambient (setuid-root form).
#[derive(Debug, Clone, PartialEq, Eq)]
struct UidDrop {
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
    uid: libc::uid_t,
}

/// A PURE description of the privilege transition, computed off the live process so
/// every step is unit-testable against its buggy inverse (§12.8 churn-fix #3). Only
/// the thin [`apply_privilege_transition`] performs syscalls.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PrivilegePlan {
    /// Drop to this uid/gid/groups BEFORE raising ambient — `Some` only for the
    /// setuid-root form. `None` for the file-cap form, which never changed uid.
    uid_drop: Option<UidDrop>,
    /// Caps to add to the inheritable set so the ambient set can hold them.
    inheritable_add: Vec<Cap>,
    /// Caps to drop from the bounding set: everything `supported` except `need`.
    bounding_drop: Vec<Cap>,
    /// Caps to raise in the ambient set so they survive `exec` into the test.
    ambient_raise: Vec<Cap>,
    /// Final permitted/effective trim target — exactly `need`.
    final_caps: Vec<Cap>,
}

/// Computes the [`PrivilegePlan`] from in-memory inputs — no process mutation.
///
/// `need` are the caps to deliver to the exec'd test; `supported` is the universe of
/// caps to consider for the bounding-set shrink (the live `Cap::probe_supported()`
/// set, passed in so this function stays pure). The uid drop is emitted ONLY for the
/// setuid-root form (`euid == 0 && uid != 0`); the file-cap form (`euid != 0`) never
/// changed uid, so it carries no uid drop. The `kvm` group is preserved across the
/// drop iff currently held, never invented or duplicated.
fn plan_privilege_transition(
    need: &[Cap],
    supported: &[Cap],
    euid: u32,
    uid: libc::uid_t,
    gid: libc::gid_t,
    kvm_gid: Option<libc::gid_t>,
    held_groups: &[libc::gid_t],
) -> PrivilegePlan {
    let uid_drop = if euid == 0 && uid != 0 {
        Some(UidDrop {
            gid,
            groups: merge_preserved_groups(gid, kvm_gid, held_groups),
            uid,
        })
    } else {
        None
    };
    PrivilegePlan {
        uid_drop,
        inheritable_add: need.to_vec(),
        bounding_drop: supported
            .iter()
            .copied()
            .filter(|c| !need.contains(c))
            .collect(),
        ambient_raise: need.to_vec(),
        final_caps: need.to_vec(),
    }
}

/// Executes a [`PrivilegePlan`] against the live process — the thin syscall edge,
/// integration-only.
///
/// The ORDER is security-critical: the uid drop (setuid-root form) MUST happen
/// BEFORE the ambient raise, so a root process never reaches `exec` holding ambient
/// caps. The pure plan separates the two; this applies them in that fixed order.
///
/// # Errors
/// Returns a diagnostic string on any failed syscall; the caller exits non-zero.
fn apply_privilege_transition(plan: &PrivilegePlan) -> Result<(), String> {
    // 1. Setuid-root form: drop to the invoking user BEFORE raising ambient.
    //    PR_SET_KEEPCAPS preserves the permitted set across the uid change.
    if let Some(drop) = &plan.uid_drop {
        capctl::prctl::set_keepcaps(true).map_err(|e| format!("failed to set keepcaps: {e}"))?;
        // SAFETY: single-threaded pre-exec context; we return (and the caller exits)
        // on any failure and spawn no threads. `groups` is non-empty and `setgroups`
        // reads exactly `groups.len()` gids from a valid pointer.
        unsafe {
            if libc::setresgid(drop.gid, drop.gid, drop.gid) != 0 {
                return Err("setresgid failed".to_string());
            }
            if libc::setgroups(drop.groups.len(), drop.groups.as_ptr()) != 0 {
                return Err("setgroups failed".to_string());
            }
            if libc::setresuid(drop.uid, drop.uid, drop.uid) != 0 {
                return Err("setresuid failed".to_string());
            }
        }
    }

    // 2. Add the needed caps to the inheritable set so ambient can hold them.
    let mut caps =
        CapState::get_current().map_err(|e| format!("failed to get current capabilities: {e}"))?;
    for &c in &plan.inheritable_add {
        caps.inheritable.add(c);
    }
    caps.set_current()
        .map_err(|e| format!("failed to set inheritable capabilities: {e}"))?;

    // 3. Shrink the bounding set. PR_CAPBSET_DROP needs CAP_SETPCAP in EFFECTIVE;
    //    raise it from permitted first if we hold it (setuid-root form). Best-effort
    //    — but surface, never swallow, a failed drop.
    if let Ok(mut st) = CapState::get_current() {
        if st.permitted.has(Cap::SETPCAP) && !st.effective.has(Cap::SETPCAP) {
            st.effective.add(Cap::SETPCAP);
            let _ = st.set_current();
        }
    }
    let mut bounding_drop_failures = 0usize;
    for &c in &plan.bounding_drop {
        if capctl::bounding::drop(c).is_err() {
            bounding_drop_failures += 1;
        }
    }
    if bounding_drop_failures > 0 {
        eprintln!(
            "vmcell-test-runner: warning: could not drop {bounding_drop_failures} bounding-set \
             capabilities (PR_CAPBSET_DROP needs CAP_SETPCAP in the effective set); the bounding \
             set is wider than intended"
        );
    }

    // 4. Raise ambient last, after the bounding set is shrunk and uid is dropped.
    for &c in &plan.ambient_raise {
        capctl::ambient::raise(c)
            .map_err(|e| format!("failed to raise ambient capability {c:?}: {e}"))?;
    }

    // 5. Trim permitted/effective down to exactly the caps we need.
    let mut final_caps = CapState::get_current()
        .map_err(|e| format!("failed to read capabilities before trim: {e}"))?;
    final_caps.permitted.clear();
    final_caps.effective.clear();
    for &c in &plan.final_caps {
        final_caps.permitted.add(c);
        final_caps.effective.add(c);
    }
    final_caps
        .set_current()
        .map_err(|e| format!("failed to trim capabilities: {e}"))?;
    Ok(())
}

fn main() {
    // No tracing-subscriber here. This binary runs in the privileged window and
    // must stay dependency-thin (no host async/log stack), and it has to report
    // failures that occur BEFORE the privilege drop — a subscriber initialized
    // after the drop could not show them. Fatal errors go straight to stderr.
    // L-HOST-4: `env::args()` panics on non-UTF-8 argv (a legal condition on Linux)
    // in this privileged binary. Use `args_os()` and refuse a non-UTF-8 target path
    // with a typed error instead of an unhelpful panic. Passthrough args (`args[2..]`)
    // are kept as `OsString` and never require UTF-8.
    let args: Vec<OsString> = env::args_os().collect();
    // argv[0] is the runner, argv[1] the test binary, argv[2..] its forwarded args. Split via
    // `split_first` (non-panicking) so the exec path carries no `indexing_slicing`, which is denied
    // crate-wide — a target-runner must fail closed, never panic-index on a malformed argv.
    let Some((_runner, rest)) = args.split_first() else {
        eprintln!("vmcell-test-runner: usage: vmcell-test-runner <test-binary> [args...]");
        exit_failure();
    };
    let Some((target_os, forwarded)) = rest.split_first() else {
        eprintln!("vmcell-test-runner: usage: vmcell-test-runner <test-binary> [args...]");
        exit_failure();
    };

    // DAC_OVERRIDE is required by the privileged tap path: `netns_rs::NetNs::new`
    // creates the bind-mount target under `/var/run/netns`, which is `root:root`,
    // and SYS_ADMIN alone does not bypass the file-permission check.
    let need = [Cap::NET_ADMIN, Cap::SYS_ADMIN, Cap::DAC_OVERRIDE];
    if let Err(e) = ensure_blessed_or_explain(&need) {
        eprintln!("{e}");
        exit_failure();
    }

    // Confine the (untrusted) exec argument under a TRUSTED root derived from the
    // runner's OWN location — never from the argument itself (PRIV-1). The blessed
    // runner lives at <workspace>/.vmcell-bin/<profile>/vmcell-test-runner, so the
    // trusted cargo target dir is <workspace>/target; any exec target outside it
    // (e.g. /home/attacker/target/debug/evil) is rejected before the cap injection.
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

    // Compute the privilege transition as PURE data (unit-tested against its buggy
    // inverses), then apply it. For the setuid-root form the uid drop is part of the
    // plan and `apply_privilege_transition` performs it BEFORE raising ambient — the
    // security-critical ordering. The kvm group and the supported-cap universe are
    // captured here while still privileged so getgroups/getgrnam/probe are unrestricted.
    let euid = rustix::process::geteuid();
    let uid = rustix::process::getuid();
    let gid = rustix::process::getgid();
    let kvm_gid = lookup_group_gid("kvm");
    let held_groups = current_supplementary_groups();
    let supported: Vec<Cap> = Cap::probe_supported().into_iter().collect();
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

    // M-HOST-2: exec the CANONICALIZED, verified path returned by
    // `confine_target_under` — not the raw argument. Execing the raw `target` would
    // re-open a possibly-different file: a bare filename triggers a `PATH` lookup,
    // and a symlink could be re-pointed between the check and the exec (TOCTOU).
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

    // Buggy impl this guards: the remediation printed `cap_..+p`, but the
    // precondition checks the EFFECTIVE set, so a user who ran the printed `+p`
    // command would set permitted-only and STILL fail the check. It must grant
    // `+ep` (effective + permitted).
    #[test]
    fn remediation_message_grants_effective_and_permitted() {
        let missing = [Cap::NET_ADMIN, Cap::SYS_ADMIN, Cap::DAC_OVERRIDE];
        let msg = blessing_remediation(
            1000,
            Path::new("/x/target/debug/vmcell-test-runner"),
            &missing,
        );
        assert!(
            msg.contains("cap_net_admin,cap_sys_admin,cap_dac_override+ep"),
            "remediation must grant the three caps with +ep: {msg}"
        );
        // The permitted-only spellings must not appear.
        assert!(!msg.contains("+p "), "must not print a bare +p flag: {msg}");
        assert!(
            !msg.contains("+p\n"),
            "must not print a bare +p flag: {msg}"
        );
    }

    // Guards PRIV-6: the remediation must print the ACTUAL computed `missing` vec,
    // not a hardcoded "CAP_NET_ADMIN/CAP_SYS_ADMIN" string that omits
    // CAP_DAC_OVERRIDE and discards the vec. The buggy inverse (ignoring `missing`)
    // would fail to name DAC_OVERRIDE when only it is missing.
    #[test]
    fn remediation_lists_actual_missing_caps_including_dac_override() {
        // Only DAC_OVERRIDE missing → it MUST be named.
        let msg = blessing_remediation(
            1000,
            Path::new("/x/target/debug/vmcell-test-runner"),
            &[Cap::DAC_OVERRIDE],
        );
        assert!(
            msg.contains("CAP_DAC_OVERRIDE"),
            "must name the actually-missing CAP_DAC_OVERRIDE: {msg}"
        );
        // A hardcoded net/sys string would wrongly name caps that are NOT missing.
        assert!(
            !msg.contains("CAP_NET_ADMIN") && !msg.contains("CAP_SYS_ADMIN"),
            "must not name caps that are present (only DAC_OVERRIDE missing): {msg}"
        );
    }

    // Guards M-RUN-2: confinement must be a real path-descendant check, not a
    // bare "has a component named target". The buggy impl accepted any path with
    // a `target` component (so `/home/target/evil`), giving essentially no
    // confinement before the three-ambient-cap exec.
    #[test]
    fn confine_under_requires_real_descendant() {
        let root = Path::new("/home/u/proj/target");
        assert!(confine_under(Path::new("/home/u/proj/target/debug/it"), root).is_ok());
        // Unrelated path that merely contains a `target` component → rejected.
        assert!(confine_under(Path::new("/home/target/evil"), root).is_err());
        // Sibling-prefix: a string `starts_with` would accept it; path-component
        // confinement must not.
        assert!(confine_under(Path::new("/home/u/proj/target-evil/x"), root).is_err());
    }

    #[test]
    fn confine_under_rejects_parent_dir_components() {
        let root = Path::new("/tmp/x/target");
        assert!(confine_under(Path::new("/tmp/x/target/../../usr/bin/sh"), root).is_err());
    }

    // `..` is rejected before any filesystem resolution, so even a non-existent
    // escape path fails closed (the old impl had no `..` rejection at all). The
    // raw-input `..` rejection happens first, before canonicalization, regardless
    // of the trusted root.
    #[test]
    fn confine_target_under_rejects_dotdot() {
        let trusted = Path::new("/tmp/x/target");
        assert!(confine_target_under("/tmp/x/target/../../usr/bin/sh", trusted).is_err());
        assert!(confine_target_under("relative/../escape", trusted).is_err());
    }

    // Derives the trusted root from the runner's OWN location (PRIV-1): the blessed
    // runner under `<workspace>/.vmcell-bin/<profile>/…` yields `<workspace>/target`;
    // a runner run in place from `<workspace>/target/…` yields that `target/`; a path
    // with neither anchor is an error (fail closed).
    #[test]
    fn trusted_target_root_derives_from_runner_location() {
        // Blessed stable-path install → trusted root is the sibling workspace target/.
        assert_eq!(
            trusted_target_root(Path::new(
                "/home/dev/proj/.vmcell-bin/debug/vmcell-test-runner"
            ))
            .expect("blessed path"),
            Path::new("/home/dev/proj/target")
        );
        // In-place dev runner still under target/ → its own target/ is trusted.
        assert_eq!(
            trusted_target_root(Path::new("/home/dev/proj/target/debug/vmcell-test-runner"))
                .expect("in-place path"),
            Path::new("/home/dev/proj/target")
        );
        // Neither `.vmcell-bin` nor `target` above the runner → fail closed.
        assert!(trusted_target_root(Path::new("/usr/local/bin/vmcell-test-runner")).is_err());
    }

    // PRIV-1 inverse — the load-bearing security test. Confinement must anchor on the
    // TRUSTED root derived from the runner's own location, NOT on any `target/`-named
    // ancestor of the untrusted argument. The pre-fix no-op ACCEPTED an attacker
    // binary under an unrelated `/…/attacker/target/…`; this test reddens on that
    // inverse. Uses tempdirs so canonicalize() resolves real paths.
    #[test]
    fn confine_target_under_rejects_attacker_target_accepts_trusted_descendant() {
        let tmp = std::env::temp_dir()
            .canonicalize()
            .expect("canonical temp_dir");
        // The trusted workspace, derived from the (blessed) runner's own location.
        let ws = tmp.join("vmcell-priv1-ws");
        let runner = ws.join(".vmcell-bin/debug/vmcell-test-runner");
        std::fs::create_dir_all(runner.parent().expect("runner dir")).expect("mkdir runner");
        std::fs::write(&runner, b"#!/bin/true").expect("write runner");
        let trusted_root = trusted_target_root(&runner).expect("derive trusted root");
        assert_eq!(trusted_root, ws.join("target"));

        // A real test binary UNDER the trusted target/ is accepted.
        let good = ws.join("target/debug/deps/itest-bin");
        std::fs::create_dir_all(good.parent().expect("good dir")).expect("mkdir good");
        std::fs::write(&good, b"#!/bin/true").expect("write good");
        assert!(
            confine_target_under(good.to_str().expect("utf8"), &trusted_root).is_ok(),
            "a test binary under the trusted target/ must be accepted"
        );

        // An attacker binary under an UNRELATED `target/`-named dir is REJECTED —
        // the no-op inverse accepted exactly this.
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

    // ---- pure privilege-transition plan: each guards a documented buggy inverse ----

    #[test]
    fn plan_adds_all_needed_to_inheritable_and_ambient() {
        let need = [Cap::NET_ADMIN, Cap::SYS_ADMIN, Cap::DAC_OVERRIDE];
        let supported = [
            Cap::NET_ADMIN,
            Cap::SYS_ADMIN,
            Cap::DAC_OVERRIDE,
            Cap::CHOWN,
        ];
        let plan = plan_privilege_transition(&need, &supported, 1000, 1000, 1000, None, &[]);
        // Inverse: a forgotten inheritable-add or ambient-raise drops a need cap → red.
        for c in need {
            assert!(
                plan.inheritable_add.contains(&c),
                "inheritable missing {c:?}"
            );
            assert!(plan.ambient_raise.contains(&c), "ambient missing {c:?}");
        }
    }

    #[test]
    fn plan_bounding_drop_excludes_needed_includes_others() {
        let need = [Cap::NET_ADMIN, Cap::SYS_ADMIN, Cap::DAC_OVERRIDE];
        let supported = [
            Cap::NET_ADMIN,
            Cap::SYS_ADMIN,
            Cap::DAC_OVERRIDE,
            Cap::CHOWN,
            Cap::SETUID,
        ];
        let plan = plan_privilege_transition(&need, &supported, 1000, 1000, 1000, None, &[]);
        // Inverse: a bounding set left wide (a needed cap droppable) → red.
        for c in need {
            assert!(
                !plan.bounding_drop.contains(&c),
                "must not drop needed {c:?}"
            );
        }
        // Every non-needed supported cap MUST be in the drop set.
        assert!(plan.bounding_drop.contains(&Cap::CHOWN));
        assert!(plan.bounding_drop.contains(&Cap::SETUID));
    }

    #[test]
    fn plan_final_caps_are_exactly_need() {
        let need = [Cap::NET_ADMIN, Cap::SYS_ADMIN];
        let supported = [Cap::NET_ADMIN, Cap::SYS_ADMIN, Cap::CHOWN];
        let plan = plan_privilege_transition(&need, &supported, 1000, 1000, 1000, None, &[]);
        // Trimmed to exactly need — no more (CHOWN must not leak), no less.
        assert_eq!(plan.final_caps.len(), need.len());
        for c in need {
            assert!(plan.final_caps.contains(&c));
        }
        assert!(!plan.final_caps.contains(&Cap::CHOWN));
    }

    #[test]
    fn plan_setuid_form_drops_uid_before_ambient_file_cap_form_does_not() {
        let need = [Cap::NET_ADMIN];
        let supported = [Cap::NET_ADMIN];
        // setuid-root form (euid 0, uid != 0): the uid drop is present, so
        // apply_privilege_transition runs it BEFORE the ambient raise. Inverse — a
        // refactor that drops the uid_drop (or applies ambient first) — fails here.
        let setuid = plan_privilege_transition(&need, &supported, 0, 1000, 1000, None, &[]);
        let drop = setuid
            .uid_drop
            .expect("setuid-root form must drop uid before ambient");
        assert_eq!(drop.uid, 1000);
        assert_eq!(drop.gid, 1000);
        // file-cap form (euid != 0): never changed uid → no uid drop.
        let filecap = plan_privilege_transition(&need, &supported, 1000, 1000, 1000, None, &[]);
        assert!(
            filecap.uid_drop.is_none(),
            "file-cap form must not drop uid"
        );
        // invoked as real root (euid 0, uid 0): nothing to drop to.
        let asroot = plan_privilege_transition(&need, &supported, 0, 0, 0, None, &[]);
        assert!(asroot.uid_drop.is_none());
    }

    #[test]
    fn plan_preserves_kvm_gid_in_setuid_form_only_when_held() {
        let need = [Cap::NET_ADMIN];
        let supported = [Cap::NET_ADMIN];
        // setuid form, kvm (108) held → preserved in the drop's group list.
        let held =
            plan_privilege_transition(&need, &supported, 0, 1000, 1000, Some(108), &[108, 4]);
        let groups = held.uid_drop.expect("setuid form").groups;
        assert!(groups.contains(&1000));
        assert!(
            groups.contains(&108),
            "kvm gid must survive the setgroups drop when held"
        );
        // setuid form, kvm NOT held → not invented.
        let unheld = plan_privilege_transition(&need, &supported, 0, 1000, 1000, Some(108), &[4]);
        assert_eq!(unheld.uid_drop.expect("setuid form").groups, vec![1000]);
    }

    // Guards the kvm-gid preservation: the primary gid is always present, the kvm
    // group is preserved iff currently held, never duplicated, never invented.
    // The buggy `setgroups(1, [gid])` drops kvm unconditionally → first case red.
    #[test]
    fn merge_preserved_groups_keeps_kvm_only_when_held() {
        // kvm (108) held → preserved alongside the primary gid.
        let g = merge_preserved_groups(1000, Some(108), &[108, 4, 27]);
        assert!(g.contains(&1000));
        assert!(
            g.contains(&108),
            "kvm gid must survive the setgroups drop: {g:?}"
        );

        // kvm not held → not added (don't invent membership).
        assert_eq!(
            merge_preserved_groups(1000, Some(108), &[4, 27]),
            vec![1000]
        );

        // kvm == primary → no duplicate.
        assert_eq!(merge_preserved_groups(108, Some(108), &[108]), vec![108]);

        // no kvm group on the host → just the primary gid.
        assert_eq!(merge_preserved_groups(1000, None, &[4]), vec![1000]);
    }

    // M-HOST-3: `compute_missing` returns exactly the needed caps ABSENT from the
    // given set. `ensure_blessed_or_explain` passes the EFFECTIVE set, so a cap
    // present only in permitted (absent from effective) MUST be reported missing —
    // the privileged window fails at first use on a permitted-only cap. This pure
    // seam is what the pre-fix code lacked: swapping effective→permitted at the call
    // site now has a test that reddens (a permitted-only cap would wrongly pass).
    #[test]
    fn compute_missing_reports_caps_absent_from_the_given_set() {
        let mut effective = CapSet::empty();
        effective.add(Cap::NET_ADMIN); // present in effective
        // SYS_ADMIN is NOT in `effective` (imagine it sits in permitted-only).
        let missing = compute_missing(&effective, &[Cap::NET_ADMIN, Cap::SYS_ADMIN]);
        assert_eq!(
            missing,
            vec![Cap::SYS_ADMIN],
            "only the absent cap is missing"
        );

        // An empty effective set → every needed cap is missing (the permitted-only
        // case that must NOT be reported as satisfied).
        let empty = CapSet::empty();
        assert_eq!(
            compute_missing(&empty, &[Cap::NET_ADMIN]),
            vec![Cap::NET_ADMIN],
            "a cap absent from effective (e.g. permitted-only) must be reported missing"
        );

        // All present → nothing missing (inverse of the above).
        let mut all = CapSet::empty();
        all.add(Cap::NET_ADMIN);
        all.add(Cap::SYS_ADMIN);
        assert!(
            compute_missing(&all, &[Cap::NET_ADMIN, Cap::SYS_ADMIN]).is_empty(),
            "no caps missing when all needed are effective"
        );
    }

    // N-HOST-3: the printed `setcap` command must shell-quote the exe path so a
    // workspace path with spaces stays a single copy-pasteable argument (an unquoted
    // path would be split by the shell). Goes RED if the single-quoting is dropped.
    #[test]
    fn remediation_shell_quotes_exe_path_with_spaces() {
        let msg = blessing_remediation(
            1000,
            Path::new("/home/a b/proj/target/debug/vmcell-test-runner"),
            &[Cap::NET_ADMIN],
        );
        assert!(
            msg.contains("+ep '/home/a b/proj/target/debug/vmcell-test-runner'"),
            "exe path with spaces must be single-quoted for copy-paste: {msg}"
        );
    }
}
