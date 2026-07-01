use capctl::{Cap, CapState};
use std::env;
use std::ffi::OsStr;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path};
use std::process::{Command, exit};

/// Builds the operator-facing remediation message shown when the runner lacks
/// its capabilities.
///
/// The precondition (`ensure_blessed_or_explain`) checks the **effective** set,
/// so the printed `setcap` must grant `+ep` (effective + permitted). A bare `+p`
/// would set only the permitted set and the runner would still fail the check.
fn blessing_remediation(uid: u32, exe: &Path) -> String {
    format!(
        "error: vmcell-test-runner is missing CAP_NET_ADMIN/CAP_SYS_ADMIN (uid={uid}, no file caps).\n\
         It was almost certainly rebuilt. Restore its privileges (one-time, until next rebuild):\n\n\
         sudo setcap cap_net_admin,cap_sys_admin,cap_dac_override+ep {}\n\n\
         Then re-run the privileged suite. See §12.8.",
        exe.display()
    )
}

fn ensure_blessed_or_explain(need: &[Cap]) -> Result<(), String> {
    let caps = CapState::get_current().map_err(|e| e.to_string())?;

    // Check if euid is 0 (setuid root fallback).
    let euid = rustix::process::geteuid();
    if euid.as_raw() == 0 {
        return Ok(());
    }

    // The privileged window needs these caps in the EFFECTIVE set (file-caps +ep form).
    let mut missing = Vec::new();
    for &c in need {
        if !caps.effective.has(c) {
            missing.push(c);
        }
    }

    if missing.is_empty() {
        Ok(())
    } else {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        Err(blessing_remediation(
            rustix::process::getuid().as_raw(),
            &exe,
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

/// Confirms the exec target resolves to a binary inside ITS OWN cargo `target`
/// directory.
///
/// v15 (§12.8 churn-fix #1): the confinement root is derived from the **exec
/// target** (the test binary, which nextest always hands us from under `target/`)
/// rather than from the runner's own `/proc/self/exe`. The runner now lives at a
/// stable path *outside* `target/` (so cargo's churn never re-strips its caps), and
/// anchoring on its own path would find no `target/` ancestor and refuse every
/// test. Anchoring on the target is also a *stronger* defense-in-depth.
///
/// Defense-in-depth for the privileged window: `..` is rejected on the raw input
/// first (canonicalization strips `..`, so a later check could not distinguish an
/// escape attempt), then the path is canonicalized (resolving symlinks; a
/// non-existent path fails closed), its nearest `target/` ancestor is located, and
/// the resolved path is confirmed to descend from it.
fn confine_under_target_dir_of(target: &str) -> Result<(), String> {
    let raw = Path::new(target);
    if raw.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(format!(
            "refusing target {target}: contains a `..` component"
        ));
    }
    let resolved = raw
        .canonicalize()
        .map_err(|e| format!("cannot resolve target {target}: {e}"))?;
    let target_root = resolved
        .ancestors()
        .find(|a| a.file_name() == Some(OsStr::new("target")))
        .ok_or_else(|| {
            format!(
                "could not locate a cargo `target` directory above the test binary at {}",
                resolved.display()
            )
        })?;
    confine_under(&resolved, target_root)
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
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("vmcell-test-runner: usage: vmcell-test-runner <test-binary> [args...]");
        exit(1);
    }

    // DAC_OVERRIDE is required by the privileged tap path: `netns_rs::NetNs::new`
    // creates the bind-mount target under `/var/run/netns`, which is `root:root`,
    // and SYS_ADMIN alone does not bypass the file-permission check.
    let need = [Cap::NET_ADMIN, Cap::SYS_ADMIN, Cap::DAC_OVERRIDE];
    if let Err(e) = ensure_blessed_or_explain(&need) {
        eprintln!("{e}");
        exit(1);
    }

    let target = &args[1];
    if let Err(e) = confine_under_target_dir_of(target) {
        eprintln!("vmcell-test-runner: {e}");
        exit(1);
    }

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
        exit(1);
    }

    let err = Command::new(target).args(&args[2..]).exec();
    eprintln!("vmcell-test-runner: failed to exec {target}: {err}");
    exit(1);
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
        let msg = blessing_remediation(1000, Path::new("/x/target/debug/vmcell-test-runner"));
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
    // confinement root is now derived from the exec target's own path (v15), but the
    // raw-input `..` rejection still happens first, before canonicalization.
    #[test]
    fn confine_under_target_dir_of_rejects_dotdot() {
        assert!(confine_under_target_dir_of("/tmp/x/target/../../usr/bin/sh").is_err());
        assert!(confine_under_target_dir_of("relative/../escape").is_err());
    }

    // The exec target must live under ITS OWN `target/` ancestor (v15 §12.8): a real
    // test binary under `<cargo target>/<profile>/deps/...` is accepted; a resolved
    // path with no `target/` ancestor is refused. Uses a tempdir so canonicalize()
    // succeeds on a real path. The buggy inverse — anchoring on the runner's own
    // `/proc/self/exe` (which has no `target/` ancestor once installed to a stable
    // path) — would refuse the first case.
    #[test]
    fn confine_under_target_dir_of_accepts_real_target_descendant() {
        let tmp = std::env::temp_dir();
        let base = tmp.join("vmcell-conf-test/target/debug/deps");
        std::fs::create_dir_all(&base).expect("mkdir");
        let bin = base.join("itest-bin");
        std::fs::write(&bin, b"#!/bin/true").expect("write bin");
        assert!(
            confine_under_target_dir_of(bin.to_str().expect("utf8")).is_ok(),
            "a test binary under a real `target/` tree must be accepted"
        );
        // A real path with no `target/` ancestor is refused.
        let no_target = tmp.join("vmcell-conf-test-notarget/bin");
        std::fs::create_dir_all(no_target.parent().expect("parent")).expect("mkdir");
        std::fs::write(&no_target, b"x").expect("write");
        assert!(
            confine_under_target_dir_of(no_target.to_str().expect("utf8")).is_err(),
            "a binary with no `target/` ancestor must be refused"
        );
        let _ = std::fs::remove_dir_all(tmp.join("vmcell-conf-test"));
        let _ = std::fs::remove_dir_all(tmp.join("vmcell-conf-test-notarget"));
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
}
