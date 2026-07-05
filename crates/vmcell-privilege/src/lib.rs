//! Shared privileged-window capability/blessing predicates for vmcell.
//!
//! Two callers link this crate and must agree, byte-for-byte, on the security-critical logic
//! (AGENTS.md "one law, one predicate"): the transient **`vmcell-test-runner`** (raise ambient →
//! drop uid → `execvp` the test) and the long-lived **`vmcell-daemon`/`vmcelld`** (check the
//! precondition, then *retain* the caps for the life of the server — no uid drop, no exec). Both
//! share the blessing precondition ([`ensure_blessed_or_explain`]) and its remediation message; only
//! the runner uses the uid-drop transition ([`plan_privilege_transition`]/
//! [`apply_privilege_transition`]). Keeping the predicates here means a fix or a test reddens for both
//! callers, never one silently diverging from a copied second implementation (design v21 §D2).
//!
//! No crate-level `forbid(unsafe_code)`: the transition uses raw capability/syscall FFI, audited via
//! `undocumented_unsafe_blocks` + `unsafe_op_in_unsafe_fn`.
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

use capctl::{CapSet, CapState};
use std::path::Path;

// Re-export the capability type so callers (the runner, the daemon) name caps and probe the
// supported set without a direct `capctl` dependency — one crate owns the privileged vocabulary.
pub use capctl::Cap;

/// Probes the kernel's supported-capability set (the universe for the bounding-set shrink).
///
/// Kept here (not inlined at the call site) so [`plan_privilege_transition`] stays pure and its
/// one impure input — the live supported set — has a single named source.
#[must_use]
pub fn probe_supported_caps() -> Vec<Cap> {
    Cap::probe_supported().into_iter().collect()
}

/// The three capabilities the vmcell privileged operating mode needs
/// (`cap_net_admin,cap_sys_admin,cap_dac_override`, design v20 §6.4/§12.8):
///
/// - `CAP_NET_ADMIN` — netns / tap / rtnetlink / nft bring-up.
/// - `CAP_SYS_ADMIN` — mount + cgroup + assorted VMM operations.
/// - `CAP_DAC_OVERRIDE` — the `netns_rs` bind-mount target under `/var/run/netns`
///   is `root:root`, and `SYS_ADMIN` alone does not bypass the file-permission check.
///
/// Both the runner (delivers these to the exec'd test) and the daemon (retains them)
/// build their `need` set from this one constant, so the two never drift.
pub const PRIVILEGED_CAPS: [Cap; 3] = [Cap::NET_ADMIN, Cap::SYS_ADMIN, Cap::DAC_OVERRIDE];

/// Builds the operator-facing remediation message shown when a blessed binary lacks
/// its capabilities.
///
/// The precondition ([`ensure_blessed_or_explain`]) checks the **effective** set, so
/// the printed `setcap` must grant `+ep` (effective + permitted). A bare `+p` would
/// set only the permitted set and the binary would still fail the check.
///
/// The message reports the **actual** `missing` set the precondition computed (each
/// `Cap` renders as `CAP_…`), so a missing `CAP_DAC_OVERRIDE` — omitted by the pre-fix
/// hardcoded prose — is named rather than silently dropped (PRIV-6).
#[must_use]
pub fn blessing_remediation(uid: u32, exe: &Path, missing: &[Cap]) -> String {
    let missing_list = missing
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "error: this vmcell binary is missing {missing_list} in its effective set (uid={uid}, no file caps).\n\
         It was almost certainly rebuilt. Restore its privileges (one-time, until next rebuild):\n\n\
         sudo setcap cap_net_admin,cap_sys_admin,cap_dac_override+ep {}\n\n\
         Then re-run. See design v20 §12.8 / v21 §D2.",
        shell_single_quote(exe)
    )
}

/// Shell-single-quotes a path so a copy-pasted `setcap` command survives a workspace
/// path containing spaces or shell metacharacters (N-HOST-3). An unquoted path with a
/// space would be split by the shell into separate arguments; single quotes disable all
/// expansion, and an embedded single quote is escaped with the standard `'\''` idiom.
#[must_use]
pub fn shell_single_quote(p: &Path) -> String {
    format!("'{}'", p.display().to_string().replace('\'', r"'\''"))
}

/// Computes which of `need` are absent from the `effective` capability set.
///
/// Kept PURE (no `CapState::get_current`) so the check is unit-testable against its
/// buggy inverse (M-HOST-3): the privileged window needs the caps in the EFFECTIVE set
/// (file-cap `+ep` form), and a cap that is only *permitted* would fail at first use, so
/// the precondition must test `effective`, never `permitted`. A test that puts a cap in
/// permitted-only reddens if this ever consulted the permitted set.
#[must_use]
pub fn compute_missing(effective: &CapSet, need: &[Cap]) -> Vec<Cap> {
    need.iter()
        .copied()
        .filter(|&c| !effective.has(c))
        .collect()
}

/// The blessing precondition shared by the runner and the daemon: the process must hold
/// every cap in `need` in its **effective** set, or be running as `euid == 0`.
///
/// Does **not** mutate the process — it only reads the current cap state and (on failure)
/// resolves `current_exe()` to build the remediation. The daemon calls this once at
/// start-up and, on `Ok`, keeps its caps; the runner calls it before the transition.
///
/// # Errors
/// Returns the operator-facing remediation string (from [`blessing_remediation`]) when a
/// needed cap is absent from the effective set, or a diagnostic if the cap state / own
/// executable path cannot be read.
pub fn ensure_blessed_or_explain(need: &[Cap]) -> Result<(), String> {
    let caps = CapState::get_current().map_err(|e| e.to_string())?;

    // euid 0 (setuid-root / real-root form) already carries full authority.
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

/// Looks up the numeric gid for a group name, or `None` if it does not exist.
#[must_use]
pub fn lookup_group_gid(name: &str) -> Option<libc::gid_t> {
    let cname = std::ffi::CString::new(name).ok()?;
    // SAFETY: `getgrnam` receives a valid NUL-terminated C string (from `CString`) and returns
    // either NULL or a pointer to a `group` owned by the C library; the pointer is not retained.
    let grp = unsafe { libc::getgrnam(cname.as_ptr()) };
    if grp.is_null() {
        None
    } else {
        // SAFETY: `grp` is non-null (checked above) and points to a valid `group` from `getgrnam`;
        // we read `gr_gid` once and copy it out without retaining the pointer. Single-threaded.
        Some(unsafe { (*grp).gr_gid })
    }
}

/// Returns the process's current supplementary group ids.
#[must_use]
pub fn current_supplementary_groups() -> Vec<libc::gid_t> {
    // SAFETY: `getgroups(0, NULL)` only queries the current supplementary-group count and writes
    // nothing — the standard `getgroups(2)` size-probe.
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n <= 0 {
        return Vec::new();
    }
    let mut buf: Vec<libc::gid_t> = vec![0; n as usize];
    // SAFETY: `buf` holds exactly `n` elements (the count queried above), so `getgroups` fills at
    // most `n` gids into a buffer it fully owns for the duration of the call.
    let got = unsafe { libc::getgroups(n, buf.as_mut_ptr()) };
    if got < 0 {
        return Vec::new();
    }
    buf.truncate(got as usize);
    buf
}

/// Builds the supplementary-group list to install before dropping uid.
///
/// Always includes the primary `gid`; additionally preserves `kvm_gid` when the process
/// currently holds it, so the exec'd test keeps `/dev/kvm` access by group membership (it
/// is `root:kvm 0660`) instead of relying solely on the incidental `CAP_DAC_OVERRIDE` we
/// carry. Never duplicates the primary gid and never invents a membership the invoker did
/// not have.
#[must_use]
pub fn merge_preserved_groups(
    gid: libc::gid_t,
    kvm_gid: Option<libc::gid_t>,
    held: &[libc::gid_t],
) -> Vec<libc::gid_t> {
    let mut groups = vec![gid];
    if let Some(kvm) = kvm_gid
        && kvm != gid
        && held.contains(&kvm)
    {
        groups.push(kvm);
    }
    groups
}

/// The invoking user's identity to drop to BEFORE raising ambient (setuid-root form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UidDrop {
    /// Primary gid to install (`setresgid`).
    pub gid: libc::gid_t,
    /// Supplementary groups to install (`setgroups`) — primary gid plus preserved `kvm`.
    pub groups: Vec<libc::gid_t>,
    /// uid to drop to (`setresuid`).
    pub uid: libc::uid_t,
}

/// A PURE description of the privilege transition, computed off the live process so every
/// step is unit-testable against its buggy inverse (design v20 §12.8 churn-fix #3). Only
/// the thin [`apply_privilege_transition`] performs syscalls.
///
/// The daemon does **not** use this — it retains its caps unchanged. Only the transient
/// runner form (drop uid, raise ambient, exec) applies a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegePlan {
    /// Drop to this uid/gid/groups BEFORE raising ambient — `Some` only for the
    /// setuid-root form. `None` for the file-cap form, which never changed uid.
    pub uid_drop: Option<UidDrop>,
    /// Caps to add to the inheritable set so the ambient set can hold them.
    pub inheritable_add: Vec<Cap>,
    /// Caps to drop from the bounding set: everything `supported` except `need`.
    pub bounding_drop: Vec<Cap>,
    /// Caps to raise in the ambient set so they survive `exec` into the test.
    pub ambient_raise: Vec<Cap>,
    /// Final permitted/effective trim target — exactly `need`.
    pub final_caps: Vec<Cap>,
}

/// Computes the [`PrivilegePlan`] from in-memory inputs — no process mutation.
///
/// `need` are the caps to deliver to the exec'd test; `supported` is the universe of caps
/// to consider for the bounding-set shrink (the live `Cap::probe_supported()` set, passed
/// in so this function stays pure). The uid drop is emitted ONLY for the setuid-root form
/// (`euid == 0 && uid != 0`); the file-cap form (`euid != 0`) never changed uid, so it
/// carries no uid drop. The `kvm` group is preserved across the drop iff currently held,
/// never invented or duplicated.
#[must_use]
pub fn plan_privilege_transition(
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
/// The ORDER is security-critical: the uid drop (setuid-root form) MUST happen BEFORE the
/// ambient raise, so a root process never reaches `exec` holding ambient caps. The pure
/// plan separates the two; this applies them in that fixed order.
///
/// # Errors
/// Returns a diagnostic string on any failed syscall; the caller exits non-zero.
pub fn apply_privilege_transition(plan: &PrivilegePlan) -> Result<(), String> {
    // 1. Setuid-root form: drop to the invoking user BEFORE raising ambient.
    //    PR_SET_KEEPCAPS preserves the permitted set across the uid change.
    if let Some(drop) = &plan.uid_drop {
        capctl::prctl::set_keepcaps(true).map_err(|e| format!("failed to set keepcaps: {e}"))?;
        // SAFETY: single-threaded pre-exec context; we return (and the caller exits) on any failure
        // and spawn no threads. Drops the real/effective/saved gid to the invoking user's gid.
        if unsafe { libc::setresgid(drop.gid, drop.gid, drop.gid) } != 0 {
            return Err("setresgid failed".to_string());
        }
        // SAFETY: `groups` is non-empty and `setgroups` reads exactly `groups.len()` gids from the
        // valid pointer `drop.groups.as_ptr()`; still single-threaded pre-exec.
        if unsafe { libc::setgroups(drop.groups.len(), drop.groups.as_ptr()) } != 0 {
            return Err("setgroups failed".to_string());
        }
        // SAFETY: performed AFTER the gid drop + setgroups (the order is load-bearing — uid must go
        // last, while the gid/group changes still have privilege); single-threaded pre-exec context.
        if unsafe { libc::setresuid(drop.uid, drop.uid, drop.uid) } != 0 {
            return Err("setresuid failed".to_string());
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

    // 3. Shrink the bounding set. PR_CAPBSET_DROP needs CAP_SETPCAP in EFFECTIVE; raise it
    //    from permitted first if we hold it (setuid-root form). Best-effort — but surface,
    //    never swallow, a failed drop.
    if let Ok(mut st) = CapState::get_current()
        && st.permitted.has(Cap::SETPCAP)
        && !st.effective.has(Cap::SETPCAP)
    {
        st.effective.add(Cap::SETPCAP);
        let _ = st.set_current();
    }
    let mut bounding_drop_failures = 0usize;
    for &c in &plan.bounding_drop {
        if capctl::bounding::drop(c).is_err() {
            bounding_drop_failures += 1;
        }
    }
    if bounding_drop_failures > 0 {
        eprintln!(
            "vmcell-privilege: warning: could not drop {bounding_drop_failures} bounding-set \
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

#[cfg(test)]
mod tests {
    use super::*;

    // Buggy impl this guards: the remediation printed `cap_..+p`, but the precondition
    // checks the EFFECTIVE set, so a user who ran the printed `+p` command would set
    // permitted-only and STILL fail the check. It must grant `+ep` (effective + permitted).
    #[test]
    fn remediation_message_grants_effective_and_permitted() {
        let missing = [Cap::NET_ADMIN, Cap::SYS_ADMIN, Cap::DAC_OVERRIDE];
        let msg = blessing_remediation(1000, Path::new("/x/target/debug/vmcelld"), &missing);
        assert!(
            msg.contains("cap_net_admin,cap_sys_admin,cap_dac_override+ep"),
            "remediation must grant the three caps with +ep: {msg}"
        );
        assert!(!msg.contains("+p "), "must not print a bare +p flag: {msg}");
        assert!(
            !msg.contains("+p\n"),
            "must not print a bare +p flag: {msg}"
        );
    }

    // Guards PRIV-6: the remediation must print the ACTUAL computed `missing` vec, not a
    // hardcoded "CAP_NET_ADMIN/CAP_SYS_ADMIN" string that omits CAP_DAC_OVERRIDE.
    #[test]
    fn remediation_lists_actual_missing_caps_including_dac_override() {
        let msg = blessing_remediation(
            1000,
            Path::new("/x/target/debug/vmcelld"),
            &[Cap::DAC_OVERRIDE],
        );
        assert!(
            msg.contains("CAP_DAC_OVERRIDE"),
            "must name the actually-missing CAP_DAC_OVERRIDE: {msg}"
        );
        assert!(
            !msg.contains("CAP_NET_ADMIN") && !msg.contains("CAP_SYS_ADMIN"),
            "must not name caps that are present (only DAC_OVERRIDE missing): {msg}"
        );
    }

    // N-HOST-3: the printed `setcap` command must shell-quote the exe path so a workspace
    // path with spaces stays a single copy-pasteable argument.
    #[test]
    fn remediation_shell_quotes_exe_path_with_spaces() {
        let msg = blessing_remediation(
            1000,
            Path::new("/home/a b/proj/target/debug/vmcelld"),
            &[Cap::NET_ADMIN],
        );
        assert!(
            msg.contains("+ep '/home/a b/proj/target/debug/vmcelld'"),
            "exe path with spaces must be single-quoted for copy-paste: {msg}"
        );
    }

    // M-HOST-3: `compute_missing` returns exactly the needed caps ABSENT from the given
    // set. `ensure_blessed_or_explain` passes the EFFECTIVE set, so a cap present only in
    // permitted MUST be reported missing — the privileged window fails at first use on a
    // permitted-only cap. Swapping effective→permitted at the call site now reddens here.
    #[test]
    fn compute_missing_reports_caps_absent_from_the_given_set() {
        let mut effective = CapSet::empty();
        effective.add(Cap::NET_ADMIN);
        let missing = compute_missing(&effective, &[Cap::NET_ADMIN, Cap::SYS_ADMIN]);
        assert_eq!(
            missing,
            vec![Cap::SYS_ADMIN],
            "only the absent cap is missing"
        );

        let empty = CapSet::empty();
        assert_eq!(
            compute_missing(&empty, &[Cap::NET_ADMIN]),
            vec![Cap::NET_ADMIN],
            "a cap absent from effective (e.g. permitted-only) must be reported missing"
        );

        let mut all = CapSet::empty();
        all.add(Cap::NET_ADMIN);
        all.add(Cap::SYS_ADMIN);
        assert!(
            compute_missing(&all, &[Cap::NET_ADMIN, Cap::SYS_ADMIN]).is_empty(),
            "no caps missing when all needed are effective"
        );
    }

    #[test]
    fn privileged_caps_are_the_three_expected() {
        assert_eq!(
            PRIVILEGED_CAPS,
            [Cap::NET_ADMIN, Cap::SYS_ADMIN, Cap::DAC_OVERRIDE]
        );
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
        for c in need {
            assert!(
                !plan.bounding_drop.contains(&c),
                "must not drop needed {c:?}"
            );
        }
        assert!(plan.bounding_drop.contains(&Cap::CHOWN));
        assert!(plan.bounding_drop.contains(&Cap::SETUID));
    }

    #[test]
    fn plan_final_caps_are_exactly_need() {
        let need = [Cap::NET_ADMIN, Cap::SYS_ADMIN];
        let supported = [Cap::NET_ADMIN, Cap::SYS_ADMIN, Cap::CHOWN];
        let plan = plan_privilege_transition(&need, &supported, 1000, 1000, 1000, None, &[]);
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
        let setuid = plan_privilege_transition(&need, &supported, 0, 1000, 1000, None, &[]);
        let drop = setuid
            .uid_drop
            .expect("setuid-root form must drop uid before ambient");
        assert_eq!(drop.uid, 1000);
        assert_eq!(drop.gid, 1000);
        let filecap = plan_privilege_transition(&need, &supported, 1000, 1000, 1000, None, &[]);
        assert!(
            filecap.uid_drop.is_none(),
            "file-cap form must not drop uid"
        );
        let asroot = plan_privilege_transition(&need, &supported, 0, 0, 0, None, &[]);
        assert!(asroot.uid_drop.is_none());
    }

    #[test]
    fn plan_preserves_kvm_gid_in_setuid_form_only_when_held() {
        let need = [Cap::NET_ADMIN];
        let supported = [Cap::NET_ADMIN];
        let held =
            plan_privilege_transition(&need, &supported, 0, 1000, 1000, Some(108), &[108, 4]);
        let groups = held.uid_drop.expect("setuid form").groups;
        assert!(groups.contains(&1000));
        assert!(
            groups.contains(&108),
            "kvm gid must survive the setgroups drop when held"
        );
        let unheld = plan_privilege_transition(&need, &supported, 0, 1000, 1000, Some(108), &[4]);
        assert_eq!(unheld.uid_drop.expect("setuid form").groups, vec![1000]);
    }

    #[test]
    fn merge_preserved_groups_keeps_kvm_only_when_held() {
        let g = merge_preserved_groups(1000, Some(108), &[108, 4, 27]);
        assert!(g.contains(&1000));
        assert!(
            g.contains(&108),
            "kvm gid must survive the setgroups drop: {g:?}"
        );

        assert_eq!(
            merge_preserved_groups(1000, Some(108), &[4, 27]),
            vec![1000]
        );
        assert_eq!(merge_preserved_groups(108, Some(108), &[108]), vec![108]);
        assert_eq!(merge_preserved_groups(1000, None, &[4]), vec![1000]);
    }
}
