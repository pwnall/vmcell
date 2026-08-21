//! Shared privileged-window capability/blessing predicates for vmcell.
//!
//! Two callers link this crate and must agree, byte-for-byte, on the security-critical logic
//! (AGENTS.md "one law, one predicate"): the transient **`vmcell-test-runner`** (raise ambient →
//! drop uid → `execvp` the test) and the long-lived **`vmcell-daemon`/`vmcelld`** (check the
//! precondition, then *retain* the caps for the life of the server — no uid drop, no exec). Both
//! share the blessing precondition ([`ensure_blessed_or_explain`]) and its remediation message; only
//! the runner uses the uid-drop transition ([`plan_privilege_transition`]/
//! [`apply_privilege_transition`]). Keeping the predicates here means a fix or a test reddens for both
//! callers, never one silently diverging from a copied second implementation (design §11.2, Privilege and blessing).
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
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::dbg_macro,
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

use capctl::CapState;
use std::path::Path;

// Re-export the capability type so callers (the runner, the daemon) name caps and probe the
// supported set without a direct `capctl` dependency — one crate owns the privileged vocabulary.
pub use capctl::{Cap, CapSet};

/// Probes the kernel's supported-capability set (the universe for the bounding-set shrink).
///
/// Kept here (not inlined at the call site) so [`plan_privilege_transition`] stays pure and its
/// one impure input — the live supported set — has a single named source.
#[must_use]
pub fn probe_supported_caps() -> Vec<Cap> {
    Cap::probe_supported().into_iter().collect()
}

/// The three capabilities the vmcell privileged operating mode needs
/// (`cap_net_admin,cap_sys_admin,cap_dac_override`, design §6.1, The two operating modes / §13, Cross-cutting invariants):
///
/// - `CAP_NET_ADMIN` — netns / tap / rtnetlink / nft bring-up.
/// - `CAP_SYS_ADMIN` — mount + cgroup + assorted VMM operations.
/// - `CAP_DAC_OVERRIDE` — the `netns_rs` bind-mount target under `/var/run/netns`
///   is `root:root`, and `SYS_ADMIN` alone does not bypass the file-permission check.
///
/// Both the runner (delivers these to the exec'd test) and the daemon (retains them)
/// build their `need` set from this one constant, so the two never drift.
pub const PRIVILEGED_CAPS: [Cap; 3] = [Cap::NET_ADMIN, Cap::SYS_ADMIN, Cap::DAC_OVERRIDE];

/// The capability set `just bless` puts on the **runner file**: [`PRIVILEGED_CAPS`] plus
/// `CAP_SETPCAP`, which is **transient** — held only across the privilege transition and gone
/// before the test runs.
///
/// `CAP_SETPCAP` is deliberately *not* in [`PRIVILEGED_CAPS`], because that constant is the set the
/// runner **delivers** (inheritable → ambient → the exec'd test) and the daemon **retains**. The two
/// sets answer different questions, and conflating them would be a real widening: `SETPCAP` in
/// `need` would ride the ambient set into every test and every VMM, *and* — since the bounding drop
/// is `supported − need` — would keep itself in the bounding set forever, which is the opposite of
/// the point.
///
/// Its one use is `PR_CAPBSET_DROP`, which the kernel gates on `CAP_SETPCAP` in the **effective**
/// set. Without it, the shared bounding-shrink edge is a warned no-op and the bounding set stays as
/// wide as the kernel supports, so a child that later execs a file-cap'd or setuid binary could
/// gain capabilities the jail was supposed to have made unreachable. With it, the bounding set is
/// shrunk to exactly [`PRIVILEGED_CAPS`] before `exec`.
///
/// It grants no authority the runner does not already have: `CAP_SETPCAP` cannot add a capability
/// to a set the process does not already hold, and the runner already carries `CAP_SYS_ADMIN`
/// (≈ root). It is dropped twice over by the transition — out of the bounding set by step 3 (it is
/// in `supported` but not in `need`) and out of permitted/effective by step 5's trim to exactly
/// `need` — so nothing downstream of the runner ever sees it.
pub const BLESSED_FILE_CAPS: [Cap; 4] = [
    Cap::NET_ADMIN,
    Cap::SYS_ADMIN,
    Cap::DAC_OVERRIDE,
    Cap::SETPCAP,
];

/// Renders `caps` as the argument `setcap(8)` takes: `cap_a,cap_b+ep`, lowercase.
///
/// The ONE composer of that string (AGENTS.md "one law, one predicate"). Every other rendering is
/// a hand-maintained copy that cannot import this constant — the `bless` recipe, the preflight
/// probe's `NEEDED_CAPS` array, the README's operator and downstream blocks, the design doc's
/// downstream-consumer route — and that is exactly how a blessing silently grants the wrong set:
/// the design's copy kept naming the three delivered caps after [`BLESSED_FILE_CAPS`] grew the
/// transient `CAP_SETPCAP`, so a consumer following it got a warned-no-op bounding-set shrink. The
/// drift gate (`every_setcap_copy_in_the_tree_matches_this_constant`) therefore walks the whole
/// tree, not a hand-listed pair of files. `+ep` is load-bearing: the precondition
/// ([`ensure_blessed_or_explain`]) checks the **effective** set, and a bare `+p` leaves the caps
/// permitted-but-not-raised, which fails at first use.
#[must_use]
pub fn setcap_arg(caps: &[Cap]) -> String {
    let names: Vec<String> = caps
        .iter()
        .map(|c| c.to_string().to_ascii_lowercase())
        .collect();
    format!("{}+ep", names.join(","))
}

/// Why the blessing precondition refused, and therefore which remediation the operator needs.
///
/// Both arms **refuse** — the verdict never depends on the euid ([`blessing_verdict`]); they differ
/// only in what fixes it, and that difference is why the euid is read at all. Telling a
/// narrowed-root process to run `setcap` is advice that cannot work: a file capability is masked by
/// the process's own bounding set, so the grant has to happen where that set is configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlessingRefusal {
    /// A process running at a non-zero euid that lacks the file caps — almost always a rebuilt
    /// binary, fixed by re-running `just bless` (or the `setcap …+ep` it prints).
    Unblessed(Vec<Cap>),
    /// A process at `euid == 0` whose own effective set is narrowed: default container root (which
    /// holds neither `CAP_NET_ADMIN` nor `CAP_SYS_ADMIN`), or a unit with `User=root` and a
    /// `CapabilityBoundingSet=` that omits one of the three. This used to be accepted as blessed
    /// (M5), which is the "started clean, then failed every privileged create" degradation law P1
    /// forbids.
    NarrowedRoot(Vec<Cap>),
}

impl BlessingRefusal {
    /// The caps absent from the effective set, whichever arm refused.
    #[must_use]
    pub fn missing(&self) -> &[Cap] {
        match self {
            Self::Unblessed(m) | Self::NarrowedRoot(m) => m,
        }
    }
}

/// The blessing precondition's verdict, computed from in-memory inputs — PURE, so the
/// euid-0-with-a-narrowed-set shape is unit-testable on any host, at any privilege level
/// (`a_narrowed_root_is_refused_and_a_full_one_is_not`; law P1's start-up gate).
///
/// The **effective** set decides, unconditionally: `euid == 0` was a short-circuit that returned
/// `Ok` for any root process, however narrow its capability set (M5). A genuine full-authority root
/// process still passes here — it holds the caps in its effective set — so nothing that legitimately
/// worked stops working; only the degraded shapes now refuse. The euid keys the *refusal*, never the
/// pass: it selects which [`BlessingRefusal`] (and therefore which remediation) the operator gets.
///
/// # Errors
/// The [`BlessingRefusal`] naming the caps absent from `effective`, tagged with the shape that is
/// missing them.
pub fn blessing_verdict(
    euid: u32,
    effective: &CapSet,
    need: &[Cap],
) -> Result<(), BlessingRefusal> {
    let missing = compute_missing(effective, need);
    if missing.is_empty() {
        return Ok(());
    }
    Err(if euid == 0 {
        BlessingRefusal::NarrowedRoot(missing)
    } else {
        BlessingRefusal::Unblessed(missing)
    })
}

/// Builds the operator-facing remediation message for a [`BlessingRefusal`].
///
/// The precondition ([`ensure_blessed_or_explain`]) checks the **effective** set, so
/// the printed `setcap` must grant `+ep` (effective + permitted). A bare `+p` would
/// set only the permitted set and the binary would still fail the check.
///
/// The message reports the **actual** missing set the precondition computed (each
/// `Cap` renders as `CAP_…`), so a missing `CAP_DAC_OVERRIDE` — omitted by the pre-fix
/// hardcoded prose — is named rather than silently dropped (PRIV-6). A
/// [`BlessingRefusal::NarrowedRoot`] deliberately does **not** print the `setcap` line: the
/// capability is absent from the process's own bounding set, where a file cap cannot reach it.
#[must_use]
pub fn blessing_remediation(uid: u32, exe: &Path, refusal: &BlessingRefusal) -> String {
    let missing_list = refusal
        .missing()
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let head = format!(
        "error: this vmcell binary is missing {missing_list} in its effective set (uid={uid})."
    );
    let tail = "See design §13 (Cross-cutting invariants) / §11.2 (Privilege and blessing).";
    match refusal {
        BlessingRefusal::Unblessed(_) => format!(
            "{head}\n\
             It carries no file caps, so it was almost certainly rebuilt. Restore its privileges \
             (one-time, until next rebuild):\n\n\
             sudo setcap {} {}\n\n\
             Then re-run. {tail}",
            // The printed command grants the FILE set, not just the missing subset: `setcap`
            // REPLACES a file's capability set rather than adding to it, so echoing back only what
            // is missing would strip whatever else the file still held — including the transient
            // `CAP_SETPCAP` that makes the bounding-set shrink work.
            setcap_arg(&BLESSED_FILE_CAPS),
            shell_single_quote(exe)
        ),
        BlessingRefusal::NarrowedRoot(_) => format!(
            "{head}\n\
             Running as root is not enough, and refusing to start is deliberate (law P1): this \
             process's own set is narrowed — default container root and a unit whose \
             CapabilityBoundingSet= omits one of the three both look like this. A file capability \
             is masked by the bounding set, so blessing the binary {} cannot help; grant the \
             capabilities where this process is configured (the container runtime's --cap-add, or \
             the unit's AmbientCapabilities=), then re-run. {tail}",
            shell_single_quote(exe)
        ),
    }
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
/// every cap in `need` in its **effective** set. No euid is exempt.
///
/// The thin live edge over [`blessing_verdict`] — it reads the process (cap state, euid) and, on a
/// refusal, resolves `current_exe()` to build the remediation; the decision itself is pure, which is
/// what lets law P1's start-up gate present a euid-0 process with a narrowed set without needing one.
/// Does **not** mutate the process. The daemon calls this once at start-up and, on `Ok`, keeps its
/// caps; the runner calls it before the transition.
///
/// # Errors
/// Returns the operator-facing remediation string (from [`blessing_remediation`]) when a
/// needed cap is absent from the effective set, or a diagnostic if the cap state / own
/// executable path cannot be read.
pub fn ensure_blessed_or_explain(need: &[Cap]) -> Result<(), String> {
    let caps = CapState::get_current().map_err(|e| e.to_string())?;

    // The privileged window needs these caps in the EFFECTIVE set (file-caps +ep form) — and the
    // euid is not a substitute for holding them. It reaches exactly one place, the verdict, where it
    // picks the remediation; the pre-fix `if euid == 0 { return Ok(()) }` here was M5, and it passed
    // every default-container root straight into a daemon that fails at first privileged use.
    let euid = rustix::process::geteuid().as_raw();
    match blessing_verdict(euid, &caps.effective, need) {
        Ok(()) => Ok(()),
        Err(refusal) => {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            Err(blessing_remediation(
                rustix::process::getuid().as_raw(),
                &exe,
                &refusal,
            ))
        }
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

/// The operator-facing warning for a partially-failed bounding-set shrink, or `None` when every
/// drop succeeded — PURE, so the wording and the count are unit-testable without `CAP_SETPCAP`
/// (design §12.4, Layer 3 — the setup broker (network surface never holds caps); implementation-notes (j)).
///
/// A wider-than-intended bounding set is a hardening regression the operator must see, and both
/// privileged edges ([`apply_privilege_transition`] and [`apply_broker_parent_drop`]) hit the same
/// `CAP_SETPCAP`-absent limitation, so the message lives here ONCE (AGENTS.md "one law, one
/// predicate") instead of being counted at one site and silently discarded at the other.
#[must_use]
fn bounding_drop_warning(failures: usize) -> Option<String> {
    if failures == 0 {
        return None;
    }
    Some(format!(
        "vmcell-privilege: warning: could not drop {failures} bounding-set \
         capabilities (PR_CAPBSET_DROP needs CAP_SETPCAP in the effective set); the bounding \
         set is wider than intended"
    ))
}

/// Attempts every cap in `caps` and emits [`bounding_drop_warning`] ONCE if any drop failed.
///
/// `drop_one` returns `true` on a successful drop and `warn` receives the single summary line;
/// both are injected so the counting AND the emission are unit-testable on a host that holds (or
/// lacks) `CAP_SETPCAP` — a test that only passes because this box happens to lack the cap would
/// prove nothing. Every cap is attempted regardless of earlier failures: the shrink is
/// best-effort, and stopping at the first failure would leave droppable caps in the bounding set.
fn shrink_bounding_set(
    caps: &[Cap],
    mut drop_one: impl FnMut(Cap) -> bool,
    warn: impl FnOnce(&str),
) {
    let mut failures = 0usize;
    for &c in caps {
        if !drop_one(c) {
            failures += 1;
        }
    }
    if let Some(msg) = bounding_drop_warning(failures) {
        warn(&msg);
    }
}

/// The live edge shared by both drop paths: raise `CAP_SETPCAP` into effective (from permitted, if
/// held — `PR_CAPBSET_DROP` requires it there), then shrink the bounding set and warn on failure.
///
/// The warning goes straight to stderr rather than through a logger: both callers run on a
/// pre-`main` / pre-runtime cap-drop path where the caller may not have wired one up.
fn shrink_bounding_set_live(caps: &[Cap]) {
    if let Ok(mut st) = CapState::get_current()
        && st.permitted.has(Cap::SETPCAP)
        && !st.effective.has(Cap::SETPCAP)
    {
        st.effective.add(Cap::SETPCAP);
        // Deliberately unchecked: raising SETPCAP is an optimization of the best-effort shrink, and
        // a failure here is already reported by the drop-failure warning below (it is exactly the
        // no-SETPCAP case) — surfacing it twice would be noise on a path that must not abort.
        #[expect(
            clippy::let_underscore_must_use,
            reason = "raising SETPCAP is an optimization of a best-effort shrink; its failure IS the no-SETPCAP case the drop-failure warning below reports"
        )]
        let _ = st.set_current();
    }
    shrink_bounding_set(
        caps,
        |c| capctl::bounding::drop(c).is_ok(),
        |msg| {
            // The #[expect] wraps a block, not the macro directly — an attribute on a bare
            // macro-call statement is silently ignored by rustc (unused_attributes), which would
            // leave print_stderr firing.
            #[expect(
                clippy::print_stderr,
                reason = "best-effort cap-drop-failure warning on the privilege boundary; must reach the operator without depending on a logger"
            )]
            {
                eprintln!("{msg}");
            }
        },
    );
}

/// A PURE description of the privilege transition, computed off the live process so every
/// step is unit-testable against its buggy inverse (design §13, Cross-cutting invariants, churn-fix #3). Only
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

/// One step of a [`PrivilegePlan`], in the order [`PrivilegePlan::steps`] emits them.
///
/// A struct has no sequence, so [`PrivilegePlan`]'s fields are **order-blind**: the
/// security-critical ordering (uid drop BEFORE the ambient raise) used to live only in the
/// statement order of [`apply_privilege_transition`], where no test could observe it and design
/// §15.5's promised "pure transition test that asserts the uid change happens before the ambient
/// raise" had nothing to assert against. Emitting the transition as an ordered step list makes the
/// order **data**: [`PrivilegePlan::steps`] is the ONE place it is written (AGENTS.md "one law, one
/// predicate"), [`apply_privilege_transition`] executes exactly that sequence, and both facts are
/// gated by unit tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivilegeStep {
    /// Drop gid → supplementary groups → uid to the invoking user (setuid-root form only), with
    /// `PR_SET_KEEPCAPS` so the permitted set survives the uid change.
    DropUid(UidDrop),
    /// Add these caps to the inheritable set so the ambient set can hold them.
    AddInheritable(Vec<Cap>),
    /// Drop these caps from the bounding set — best-effort, warned on failure.
    ShrinkBounding(Vec<Cap>),
    /// Raise these caps into the ambient set so they survive `execve` into the test.
    RaiseAmbient(Vec<Cap>),
    /// Trim permitted/effective down to exactly these caps.
    TrimCaps(Vec<Cap>),
}

impl PrivilegePlan {
    /// The transition as an ordered step list — **the one place the order is written**.
    ///
    /// The ORDER is security-critical: the uid drop (setuid-root form) MUST come BEFORE the
    /// ambient raise, so a root process never reaches `exec` holding ambient caps. The bounding
    /// shrink precedes the raise so ambient caps are raised into an already-narrowed set. The
    /// file-cap form never changed uid, so it emits no [`PrivilegeStep::DropUid`].
    #[must_use]
    pub fn steps(&self) -> Vec<PrivilegeStep> {
        let mut steps = Vec::with_capacity(5);
        // 1. Setuid-root form: drop to the invoking user BEFORE raising ambient.
        if let Some(drop) = &self.uid_drop {
            steps.push(PrivilegeStep::DropUid(drop.clone()));
        }
        // 2. Add the needed caps to the inheritable set so ambient can hold them.
        steps.push(PrivilegeStep::AddInheritable(self.inheritable_add.clone()));
        // 3. Shrink the bounding set (before the raise, so ambient lands inside the narrowed set).
        steps.push(PrivilegeStep::ShrinkBounding(self.bounding_drop.clone()));
        // 4. Raise ambient, after the bounding set is shrunk and uid is dropped.
        steps.push(PrivilegeStep::RaiseAmbient(self.ambient_raise.clone()));
        // 5. Trim permitted/effective down to exactly the caps we need.
        steps.push(PrivilegeStep::TrimCaps(self.final_caps.clone()));
        steps
    }
}

/// Runs a plan's [`PrivilegeStep`]s through `run`, in [`PrivilegePlan::steps`] order, stopping at
/// the first failure.
///
/// The executor is INJECTED for the same reason [`shrink_bounding_set`]'s dropper is: the order
/// the live edge actually applies is then observable to a unit test on any host, without
/// privileges and without syscalls. [`apply_privilege_transition`] passes the real syscall runner;
/// `apply_executes_the_planned_steps_in_order` passes a recorder. Stopping at the first error is
/// load-bearing — continuing past a failed uid drop would raise ambient caps while still root,
/// which is exactly the hazard the ordering exists to prevent.
fn execute_privilege_steps(
    plan: &PrivilegePlan,
    mut run: impl FnMut(&PrivilegeStep) -> Result<(), String>,
) -> Result<(), String> {
    for step in plan.steps() {
        run(&step)?;
    }
    Ok(())
}

/// Performs ONE [`PrivilegeStep`] against the live process — the only syscall site of each edge,
/// pinned there by `the_uid_drop_and_ambient_raise_syscalls_live_only_in_the_step_dispatch`.
fn apply_privilege_step(step: &PrivilegeStep) -> Result<(), String> {
    match step {
        PrivilegeStep::DropUid(drop) => {
            // PR_SET_KEEPCAPS preserves the permitted set across the uid change.
            capctl::prctl::set_keepcaps(true)
                .map_err(|e| format!("failed to set keepcaps: {e}"))?;
            // SAFETY: single-threaded pre-exec context; we return (and the caller exits) on any
            // failure and spawn no threads. Drops the real/effective/saved gid to the invoking
            // user's gid.
            if unsafe { libc::setresgid(drop.gid, drop.gid, drop.gid) } != 0 {
                return Err("setresgid failed".to_string());
            }
            // SAFETY: `groups` is non-empty and `setgroups` reads exactly `groups.len()` gids from
            // the valid pointer `drop.groups.as_ptr()`; still single-threaded pre-exec.
            if unsafe { libc::setgroups(drop.groups.len(), drop.groups.as_ptr()) } != 0 {
                return Err("setgroups failed".to_string());
            }
            // SAFETY: performed AFTER the gid drop + setgroups (the order is load-bearing — uid
            // must go last, while the gid/group changes still have privilege); single-threaded
            // pre-exec context.
            if unsafe { libc::setresuid(drop.uid, drop.uid, drop.uid) } != 0 {
                return Err("setresuid failed".to_string());
            }
            Ok(())
        }
        PrivilegeStep::AddInheritable(caps) => {
            let mut state = CapState::get_current()
                .map_err(|e| format!("failed to get current capabilities: {e}"))?;
            for &c in caps {
                state.inheritable.add(c);
            }
            state
                .set_current()
                .map_err(|e| format!("failed to set inheritable capabilities: {e}"))
        }
        // Both forms can shrink: the setuid-root form has always held CAP_SETPCAP, and the
        // file-cap form gets it from `BLESSED_FILE_CAPS` (`just bless` grants it). `bounding_drop`
        // is `supported − need`, so CAP_SETPCAP is in the drop list and drops ITSELF here — which
        // does not disarm the remaining drops: `PR_CAPBSET_DROP` is gated on CAP_SETPCAP in the
        // EFFECTIVE set, and leaving the bounding set does not remove it from effective.
        // Best-effort — but surface, never swallow, a failed drop (a host that still has no
        // CAP_SETPCAP keeps the old warned-no-op behavior rather than failing to run); the one
        // shared edge does both.
        PrivilegeStep::ShrinkBounding(caps) => {
            shrink_bounding_set_live(caps);
            Ok(())
        }
        PrivilegeStep::RaiseAmbient(caps) => {
            for &c in caps {
                capctl::ambient::raise(c)
                    .map_err(|e| format!("failed to raise ambient capability {c:?}: {e}"))?;
            }
            Ok(())
        }
        PrivilegeStep::TrimCaps(caps) => {
            let mut state = CapState::get_current()
                .map_err(|e| format!("failed to read capabilities before trim: {e}"))?;
            state.permitted.clear();
            state.effective.clear();
            for &c in caps {
                state.permitted.add(c);
                state.effective.add(c);
            }
            state
                .set_current()
                .map_err(|e| format!("failed to trim capabilities: {e}"))
        }
    }
}

/// Executes a [`PrivilegePlan`] against the live process — the thin syscall edge,
/// integration-only.
///
/// The ORDER is security-critical: the uid drop (setuid-root form) MUST happen BEFORE the
/// ambient raise, so a root process never reaches `exec` holding ambient caps. That order is not
/// this function's statement order — it is [`PrivilegePlan::steps`]'s output, which this walks in
/// sequence through the private `apply_privilege_step`, so the ordering is asserted by a pure unit test
/// rather than being invisible source layout (design §15.5).
///
/// # Errors
/// Returns a diagnostic string on any failed syscall; the caller exits non-zero. The first failing
/// step aborts the transition — no later step runs.
pub fn apply_privilege_transition(plan: &PrivilegePlan) -> Result<(), String> {
    execute_privilege_steps(plan, apply_privilege_step)
}

/// A PURE description of the **setup-broker parent's** capability drop (design §12.4,
/// Layer 3 — the setup broker (network surface never holds caps)): after `vmcelld` forks the privileged broker child, the parent — which serves the
/// network-facing HTTP API — drops **every** capability so a bug in the request parser can no
/// longer reach the caps. Unlike [`PrivilegePlan`] (which *keeps* `need`), this keeps
/// **nothing**: `final_caps` is empty. The uid is intentionally NOT dropped — the parent stays
/// the same uid so it can `connect()` the VMM's sockets and `pidfd_send_signal` it (a
/// cross-uid signal would need `CAP_KILL`, §12.4, Layer 3 — the setup broker (network surface never holds caps)).
///
/// Only the thin [`apply_broker_parent_drop`] performs syscalls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerParentDropPlan {
    /// Caps to drop from the bounding set: **everything** the kernel supports (the parent
    /// needs none, and an empty bounding set means no future `exec` can regain one).
    pub bounding_drop: Vec<Cap>,
    /// Clear the ambient capability set (so no cap survives into any child the parent execs).
    pub clear_ambient: bool,
    /// Set `PR_SET_NO_NEW_PRIVS` — the parent can never gain privilege via a setuid binary.
    pub no_new_privs: bool,
    /// The final permitted/effective/inheritable target — **empty** (the parent keeps no cap).
    pub final_caps: Vec<Cap>,
}

/// Computes the [`BrokerParentDropPlan`] from the live supported-cap set — no process mutation.
///
/// Pure so the "keeps nothing" contract is unit-testable against its buggy inverse (a plan that
/// accidentally retained a cap, e.g. copied [`PRIVILEGED_CAPS`] into `final_caps`, would leave
/// the HTTP surface holding privilege — the exact thing the broker split removes).
#[must_use]
pub fn plan_broker_parent_drop(supported: &[Cap]) -> BrokerParentDropPlan {
    BrokerParentDropPlan {
        bounding_drop: supported.to_vec(),
        clear_ambient: true,
        no_new_privs: true,
        final_caps: Vec::new(),
    }
}

/// Executes a [`BrokerParentDropPlan`] against the live process — the thin syscall edge,
/// integration-only (the parent after the broker fork).
///
/// Order: clear ambient → shrink bounding (needs `CAP_SETPCAP` in effective, raised from
/// permitted first if held) → set `no_new_privs` → clear permitted/effective/inheritable to
/// exactly `final_caps` (empty). The uid is left unchanged (§12.4, Layer 3 — the setup broker (network surface never holds caps)).
///
/// # Errors
/// Returns a diagnostic string on any failed syscall; the caller exits non-zero (a parent that
/// could not fully drop its caps must not go on to serve the API).
pub fn apply_broker_parent_drop(plan: &BrokerParentDropPlan) -> Result<(), String> {
    // 1. Clear the ambient set.
    if plan.clear_ambient {
        capctl::ambient::clear().map_err(|e| format!("failed to clear ambient caps: {e}"))?;
    }

    // 2. Shrink the bounding set through the SAME edge the runner uses. Best-effort: the broker
    //    parent inherits the runner's file-cap limitation (no CAP_SETPCAP), so some drops fail and
    //    the shrink is a *warned* no-op — the permitted/effective clear below is the load-bearing
    //    removal and the wide bounding set is inert under `no_new_privs` (implementation-notes (j)).
    //    Discarding those failures silently is the defect this shared edge fixes
    //    (`broker-parent-bounding-drop-failure-is-silent`).
    shrink_bounding_set_live(&plan.bounding_drop);

    // 3. no_new_privs: no setuid exec can regain a capability after this.
    if plan.no_new_privs {
        capctl::prctl::set_no_new_privs()
            .map_err(|e| format!("failed to set no_new_privs: {e}"))?;
    }

    // 4. Trim permitted/effective/inheritable to exactly final_caps (empty for the parent).
    let mut caps =
        CapState::get_current().map_err(|e| format!("failed to read capabilities: {e}"))?;
    caps.permitted.clear();
    caps.effective.clear();
    caps.inheritable.clear();
    for &c in &plan.final_caps {
        caps.permitted.add(c);
        caps.effective.add(c);
    }
    caps.set_current()
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
        let missing = vec![Cap::NET_ADMIN, Cap::SYS_ADMIN, Cap::DAC_OVERRIDE];
        let msg = blessing_remediation(
            1000,
            Path::new("/x/target/debug/vmcelld"),
            &BlessingRefusal::Unblessed(missing),
        );
        // Recomputed through the one composer, never a test-local literal: this test used to spell
        // the cap list out by hand, which made it a fourth copy — and it went red (correctly) the
        // moment the blessed set grew `cap_setpcap`. The property it guards is the `+ep` flag, not
        // the roster; the roster is pinned by `setcap_arg_renders_the_blessed_set_verbatim`.
        assert!(
            msg.contains(&setcap_arg(&BLESSED_FILE_CAPS)),
            "remediation must grant the blessed file set with +ep: {msg}"
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
            &BlessingRefusal::Unblessed(vec![Cap::DAC_OVERRIDE]),
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
            &BlessingRefusal::Unblessed(vec![Cap::NET_ADMIN]),
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

    // ---- law P1's start-up precondition: a degraded process must REFUSE to start ----

    // GATE for law P1 ("a long-lived cap-holder retains and refuses to start degraded", design §13),
    // which had no start-up precondition test at all — so M5 shipped: `ensure_blessed_or_explain`
    // returned `Ok` for ANY euid-0 process, however narrow its effective set, while its own rustdoc
    // twelve lines above stated the effective-set rule. Default container root holds neither
    // `CAP_NET_ADMIN` nor `CAP_SYS_ADMIN`, and `User=root` with a narrowed `CapabilityBoundingSet=`
    // is the documented production unit, so both came up "blessed" and then failed every privileged
    // create at first use.
    //
    // The verdict is PURE, so this presents the euid-0-with-a-narrowed-set shape on any host: the
    // test's answer never depends on the caps of whoever runs it (a box that happens to be root, or
    // a blessed runner, cannot make it vacuously green).
    //
    // RED on the inverse: put `if euid == 0 { return Ok(()) }` back at the top of `blessing_verdict`
    // (or around its call in `ensure_blessed_or_explain`, which the scan below catches) and the
    // narrowed-root legs return `Ok`.
    #[test]
    fn a_narrowed_root_is_refused_and_a_full_one_is_not() {
        let mut narrowed = CapSet::empty();
        narrowed.add(Cap::NET_ADMIN);

        assert_eq!(
            blessing_verdict(0, &narrowed, &PRIVILEGED_CAPS),
            Err(BlessingRefusal::NarrowedRoot(vec![
                Cap::SYS_ADMIN,
                Cap::DAC_OVERRIDE
            ])),
            "euid 0 with a narrowed effective set must REFUSE, naming what is absent"
        );

        // Positive control: genuine full-authority root still starts. Dropping the short-circuit
        // costs it nothing — it holds the caps in its effective set, which is what is checked.
        let mut full = CapSet::empty();
        for c in PRIVILEGED_CAPS {
            full.add(c);
        }
        assert_eq!(
            blessing_verdict(0, &full, &PRIVILEGED_CAPS),
            Ok(()),
            "a root process that actually holds the caps must still pass"
        );
        assert_eq!(
            blessing_verdict(1000, &full, &PRIVILEGED_CAPS),
            Ok(()),
            "the blessed file-cap form must still pass"
        );

        // The discriminating half: the refusal IDENTITY is what the euid selects, because the two
        // shapes need different fixes. An arm that collapsed them would hand a containerized root a
        // `setcap` command that cannot work.
        assert_eq!(
            blessing_verdict(1000, &narrowed, &PRIVILEGED_CAPS),
            Err(BlessingRefusal::Unblessed(vec![
                Cap::SYS_ADMIN,
                Cap::DAC_OVERRIDE
            ])),
            "a non-root process missing the caps is the rebuilt-binary shape"
        );

        // No euid is a pass — not 0, and not any of the mapped-root shapes a user namespace hands a
        // container.
        for euid in [0, 1, 65_534, 1000] {
            assert!(
                blessing_verdict(euid, &narrowed, &PRIVILEGED_CAPS).is_err(),
                "euid {euid} must not excuse a missing capability"
            );
        }
    }

    // The two refusals must remediate differently, or the split is decoration: `setcap` on the
    // binary cannot restore a capability the process's bounding set does not carry, so printing it
    // to a narrowed root is advice that fails silently.
    //
    // RED on the inverse: render one message for both arms (the narrowed-root leg then prints the
    // blessing command and this fails).
    #[test]
    fn the_narrowed_root_remediation_does_not_print_the_blessing_command() {
        let exe = Path::new("/usr/bin/vmcelld");
        let narrowed =
            blessing_remediation(0, exe, &BlessingRefusal::NarrowedRoot(vec![Cap::SYS_ADMIN]));
        assert!(
            !narrowed.contains(&setcap_arg(&BLESSED_FILE_CAPS)),
            "a narrowed root must not be told to bless the binary: {narrowed}"
        );
        assert!(
            narrowed.contains("CAP_SYS_ADMIN") && narrowed.contains("bounding set"),
            "it must name the absent cap and why the file-cap fix cannot reach it: {narrowed}"
        );

        // Positive control: the rebuilt-binary arm still prints the one blessing command.
        let unblessed =
            blessing_remediation(1000, exe, &BlessingRefusal::Unblessed(vec![Cap::SYS_ADMIN]));
        assert!(
            unblessed.contains(&setcap_arg(&BLESSED_FILE_CAPS)),
            "the file-cap arm must still print the blessing command: {unblessed}"
        );
    }

    // GATE, the direction the pure verdict test structurally cannot see: that the LIVE precondition
    // both callers run delegates to that verdict, and never re-branches on the euid beside it. The
    // precondition is impure (its answer on this box depends on this box's caps), so its window is
    // scanned instead — the same shape as the two syscall-site scans above.
    //
    // The euid read may reach exactly TWO places in that body: the binding, and the one argument it
    // is passed as. The pre-fix `if euid.as_raw() == 0 { return Ok(()); }` was a third — a
    // re-added short-circuit is therefore red here even if it reuses the existing binding rather
    // than reading the euid again.
    #[test]
    fn the_live_precondition_delegates_its_verdict_and_never_branches_on_euid() {
        const SOURCE: &str = include_str!("lib.rs");
        let prod = SOURCE
            .split_once("#[cfg(test)]")
            .expect("the test module is gated in this file")
            .0;
        assert_eq!(
            prod.matches("geteuid").count(),
            1,
            "the live euid must be read in exactly one place (the precondition); a second read is a \
             second policy"
        );

        let body = prod
            .split_once("pub fn ensure_blessed_or_explain(")
            .expect("the precondition is defined in this file")
            .1
            .split_once("pub fn lookup_group_gid(")
            .expect("the precondition is defined before the group lookup")
            .0;
        // Comments stripped first, so the prose explaining WHY the euid is not a pass is not
        // counted as a use of it.
        let code: String = body
            .lines()
            .map(|l| l.split_once("//").map_or(l, |(before, _)| before))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            code.contains("blessing_verdict("),
            "the live precondition must delegate to the pure verdict, not re-implement it"
        );
        assert_eq!(
            code.replace("geteuid", "").matches("euid").count(),
            2,
            "the euid may only be bound and handed to the verdict; a third use is a branch on it \
             (the M5 short-circuit): {code}"
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

    // ---- design §15.5's promised ordering gate: uid drop BEFORE the ambient raise ----

    // GATE for design §15.5's "a `setuid`-fallback path … verified by a pure transition test that
    // asserts the uid change happens **before** the ambient raise" — which did not exist, because
    // `PrivilegePlan` is a struct and a struct has no sequence: the ordering lived only in
    // `apply_privilege_transition`'s statement order, invisible to every test. `PrivilegePlan::steps()`
    // now IS the order, so it can be asserted.
    //
    // The order is not stylistic. Raising ambient first would give a root process ambient caps that
    // survive `execve`, and the uid drop that follows would NOT remove them — the exec'd test would
    // run at the dev uid holding caps the runner meant to have narrowed.
    //
    // RED on the inverse: swap the `DropUid` and `RaiseAmbient` pushes in `steps()`; both the index
    // comparison and the exact-sequence assert fail.
    #[test]
    fn the_setuid_plan_drops_uid_before_raising_ambient() {
        let need = [Cap::NET_ADMIN, Cap::SYS_ADMIN];
        let supported = [Cap::NET_ADMIN, Cap::SYS_ADMIN, Cap::CHOWN];
        // euid 0 + uid 1000 = the setuid-root form, the only one that carries a uid drop.
        let plan = plan_privilege_transition(&need, &supported, 0, 1000, 1000, Some(108), &[108]);
        let steps = plan.steps();

        let drop_at = steps
            .iter()
            .position(|s| matches!(s, PrivilegeStep::DropUid(_)))
            .expect("the setuid-root form must carry a uid drop");
        let raise_at = steps
            .iter()
            .position(|s| matches!(s, PrivilegeStep::RaiseAmbient(_)))
            .expect("every form raises ambient");
        assert!(
            drop_at < raise_at,
            "the uid drop must precede the ambient raise (a root process must never reach exec \
             holding ambient caps); got {steps:?}"
        );

        // The whole sequence, pinned: a reorder anywhere reddens, not just this one pair.
        assert_eq!(
            steps,
            vec![
                PrivilegeStep::DropUid(UidDrop {
                    gid: 1000,
                    groups: vec![1000, 108],
                    uid: 1000,
                }),
                PrivilegeStep::AddInheritable(need.to_vec()),
                PrivilegeStep::ShrinkBounding(vec![Cap::CHOWN]),
                PrivilegeStep::RaiseAmbient(need.to_vec()),
                PrivilegeStep::TrimCaps(need.to_vec()),
            ],
            "the transition sequence is security-critical and pinned here"
        );
    }

    // The file-cap form (the one this repo actually provisions) never changed uid, so it must emit
    // NO uid-drop step — and the remaining four keep the same relative order.
    #[test]
    fn the_file_cap_plan_emits_no_uid_drop_step() {
        let need = [Cap::NET_ADMIN];
        let supported = [Cap::NET_ADMIN, Cap::CHOWN];
        let steps =
            plan_privilege_transition(&need, &supported, 1000, 1000, 1000, None, &[]).steps();
        assert!(
            !steps.iter().any(|s| matches!(s, PrivilegeStep::DropUid(_))),
            "the file-cap form must not drop uid: {steps:?}"
        );
        assert_eq!(
            steps,
            vec![
                PrivilegeStep::AddInheritable(need.to_vec()),
                PrivilegeStep::ShrinkBounding(vec![Cap::CHOWN]),
                PrivilegeStep::RaiseAmbient(need.to_vec()),
                PrivilegeStep::TrimCaps(need.to_vec()),
            ]
        );
    }

    // The plan's order is only worth asserting if the live edge executes THAT order. The executor is
    // injected (the `shrink_bounding_set` shape), so this runs on any host, unprivileged, with no
    // syscalls — and covers the abort-on-failure half the syscall edge structurally hides.
    //
    // RED on the inverse: swap the `DropUid`/`RaiseAmbient` pushes in `steps()` (the recorded order
    // no longer starts with the uid drop), or replace `run(&step)?` with a discarded
    // `let _ = run(&step);` (the failed-step assertion sees all five steps run).
    #[test]
    fn apply_executes_the_planned_steps_in_order() {
        let plan = plan_privilege_transition(
            &[Cap::NET_ADMIN],
            &[Cap::NET_ADMIN, Cap::CHOWN],
            0,
            1000,
            1000,
            None,
            &[],
        );

        let mut seen = Vec::new();
        execute_privilege_steps(&plan, |s| {
            seen.push(s.clone());
            Ok(())
        })
        .expect("an all-Ok executor must complete the transition");
        assert_eq!(
            seen,
            plan.steps(),
            "the live edge must execute exactly the planned sequence, in order"
        );
        assert!(
            matches!(seen.first(), Some(PrivilegeStep::DropUid(_))),
            "the setuid-root form must execute the uid drop FIRST: {seen:?}"
        );

        // A failed step aborts the rest. Continuing past a failed uid drop would raise ambient caps
        // while still root — the exact hazard the ordering exists to prevent.
        let mut seen = Vec::new();
        let err = execute_privilege_steps(&plan, |s| {
            seen.push(s.clone());
            if matches!(s, PrivilegeStep::DropUid(_)) {
                Err("setresuid failed".to_string())
            } else {
                Ok(())
            }
        })
        .expect_err("a failed uid drop must abort the transition");
        assert_eq!(err, "setresuid failed", "the step's error must propagate");
        assert_eq!(
            seen.len(),
            1,
            "nothing may run after a failed uid drop — least of all the ambient raise: {seen:?}"
        );
    }

    // GATE, the direction the injected-executor test structurally cannot see: it proves the ORDER
    // the step list is walked in, not that the real syscalls still live inside the step dispatch. A
    // re-inlined uid drop or ambient raise in `apply_privilege_transition` would restore the
    // order-blind statement-order arrangement while leaving every test above green. Same shape (and
    // same rationale) as `the_raw_bounding_drop_call_exists_only_in_the_shared_warned_edge`.
    //
    // RED on the inverse: paste either syscall back into `apply_privilege_transition` and the count
    // for that needle goes to 2.
    #[test]
    fn the_uid_drop_and_ambient_raise_syscalls_live_only_in_the_step_dispatch() {
        const SOURCE: &str = include_str!("lib.rs");
        // Production half only — the first `#[cfg(test)]` in the file is this module's attribute,
        // and the needles are quoted verbatim in the prose below.
        let prod = SOURCE
            .split_once("#[cfg(test)]")
            .expect("the test module is gated in this file")
            .0;
        // The dispatch's exact window: from its own `fn` line to the public edge defined directly
        // after it. Bounding the window (rather than taking the whole tail) is what makes the
        // "inside the dispatch" half non-vacuous.
        let dispatch = prod
            .split_once("fn apply_privilege_step(")
            .expect("the step dispatch is defined in this file")
            .1
            .split_once("pub fn apply_privilege_transition(")
            .expect("the dispatch is defined immediately before the public edge")
            .0;
        for needle in ["libc::setresuid(", "capctl::ambient::raise("] {
            assert_eq!(
                prod.matches(needle).count(),
                1,
                "`{needle}` must have exactly one call site (in `apply_privilege_step`); a second \
                 copy puts the security-critical ordering back into invisible statement order"
            );
            assert!(
                dispatch.contains(needle),
                "the one `{needle}` call site must be inside the step dispatch, so \
                 `PrivilegePlan::steps()` stays the only place the order is written"
            );
        }
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

    // ---- the shared bounding-set shrink: the failure must be WARNED, never swallowed ----

    // Guards `broker-parent-bounding-drop-failure-is-silent`. Buggy impl this guards: the broker
    // parent's shrink was `let _ = capctl::bounding::drop(c);` — every failure discarded, so the
    // wider-than-intended bounding set §12.4 / implementation-notes (j) promise to WARN about was
    // invisible. Both the dropper and the emitter are injected, so this reddens on any host: a box
    // that happens to hold CAP_SETPCAP cannot make it vacuously green.
    #[test]
    fn bounding_shrink_warns_once_with_the_failure_count() {
        let caps = [
            Cap::NET_ADMIN,
            Cap::SYS_ADMIN,
            Cap::DAC_OVERRIDE,
            Cap::CHOWN,
        ];
        let mut attempted = Vec::new();
        let mut warnings = Vec::new();
        shrink_bounding_set(
            &caps,
            |c| {
                attempted.push(c);
                // The no-CAP_SETPCAP shape: two of the four drops are refused by the kernel.
                !matches!(c, Cap::SYS_ADMIN | Cap::CHOWN)
            },
            |msg| warnings.push(msg.to_string()),
        );

        assert_eq!(
            attempted, caps,
            "every cap must be attempted; stopping at the first failure leaves droppable caps in \
             the bounding set"
        );
        assert_eq!(
            warnings.len(),
            1,
            "the failed shrink must warn exactly once, not per cap and not never: {warnings:?}"
        );
        let msg = &warnings[0];
        assert!(
            msg.contains("could not drop 2 bounding-set"),
            "the warning must carry the FAILURE count (2 of 4), not the attempt count: {msg}"
        );
        assert!(
            msg.contains("CAP_SETPCAP") && msg.contains("wider than intended"),
            "the warning must name the cause and the consequence: {msg}"
        );
    }

    // The inverse: a fully successful shrink is silent, so the warning stays a real signal rather
    // than noise every privileged start-up prints.
    #[test]
    fn bounding_shrink_is_silent_when_every_drop_succeeds() {
        let mut warnings: Vec<String> = Vec::new();
        shrink_bounding_set(
            &[Cap::NET_ADMIN, Cap::CHOWN],
            |_| true,
            |msg| warnings.push(msg.to_string()),
        );
        assert!(
            warnings.is_empty(),
            "a fully successful shrink must not warn: {warnings:?}"
        );
        assert_eq!(bounding_drop_warning(0), None, "zero failures = no warning");
    }

    // GATE, the direction the injected-closure tests above structurally cannot see: they prove the
    // shared edge warns, not that both live paths GO THROUGH it. `apply_broker_parent_drop` and
    // `apply_privilege_transition` are syscall edges (integration-only, and unobservable without
    // CAP_SETPCAP), so this scans this file's own source the way `artifact::mod.rs` scans its
    // dispatch: the raw bounding-drop call may appear exactly ONCE, inside `shrink_bounding_set_live`.
    // Red-on-inverse: re-inline the pre-fix `let _ = capctl::bounding::drop(c);` loop at either
    // caller and the count goes to 2.
    #[test]
    fn the_raw_bounding_drop_call_exists_only_in_the_shared_warned_edge() {
        const SOURCE: &str = include_str!("lib.rs");
        // Only the production half is scanned — the first `#[cfg(test)]` in the file is this
        // module's own attribute, and the prose below quotes the pre-fix call verbatim.
        let prod = SOURCE
            .split_once("#[cfg(test)]")
            .expect("the test module is gated in this file")
            .0;
        let needle = "capctl::bounding::drop(";
        assert_eq!(
            prod.matches(needle).count(),
            1,
            "the bounding-set drop must have exactly one call site ({needle} in \
             shrink_bounding_set_live); a second copy is a silently-discarded failure waiting to \
             happen (broker-parent-bounding-drop-failure-is-silent)"
        );
        let live = prod
            .split_once("fn shrink_bounding_set_live(")
            .expect("the shared live edge is defined in this file")
            .1;
        assert!(
            live.contains(needle),
            "the one call site must be inside the shared warned edge"
        );
    }

    // The two privileged edges (runner transition, broker-parent drop) share ONE message, so the
    // wording cannot drift between them (AGENTS.md "one law, one predicate").
    #[test]
    fn bounding_drop_warning_names_count_cause_and_consequence() {
        let msg = bounding_drop_warning(38).expect("a non-zero failure count must warn");
        assert!(
            msg.starts_with("vmcell-privilege: warning: could not drop 38 bounding-set"),
            "warning must be prefixed and count-carrying: {msg}"
        );
        assert!(msg.contains("PR_CAPBSET_DROP needs CAP_SETPCAP"), "{msg}");
    }

    // Guards §12.4, Layer 3 — the setup broker (network surface never holds caps): the broker parent keeps NOTHING. `final_caps` must be empty (the whole
    // point of the split is that the HTTP-serving process holds no capability); it drops the
    // ENTIRE supported set from the bounding set; and it sets no_new_privs + clears ambient.
    // The buggy inverse (retaining a cap in `final_caps` — e.g. copying PRIVILEGED_CAPS the way
    // the runner/daemon plan does) leaves the network surface privileged and reddens here.
    #[test]
    fn broker_parent_drop_keeps_no_caps_and_shrinks_everything() {
        let supported = [
            Cap::NET_ADMIN,
            Cap::SYS_ADMIN,
            Cap::DAC_OVERRIDE,
            Cap::CHOWN,
            Cap::SETPCAP,
        ];
        let plan = plan_broker_parent_drop(&supported);
        assert!(
            plan.final_caps.is_empty(),
            "the broker parent must retain NO capability, got {:?}",
            plan.final_caps
        );
        assert!(plan.no_new_privs, "the parent must set no_new_privs");
        assert!(plan.clear_ambient, "the parent must clear the ambient set");
        // Every supported cap — including the three privileged ones — is dropped from bounding.
        for c in supported {
            assert!(
                plan.bounding_drop.contains(&c),
                "bounding-set drop must include {c:?} (nothing is spared)"
            );
        }
        for c in PRIVILEGED_CAPS {
            assert!(
                !plan.final_caps.contains(&c),
                "the parent must NOT keep the privileged cap {c:?}"
            );
        }
    }

    // ---- docs/78 follow-up: CAP_SETPCAP, the transient bounding-shrink capability ----

    // The whole point of a SEPARATE constant: `CAP_SETPCAP` must be on the runner FILE and must
    // NOT be in the delivered set. Conflating them would ride SETPCAP into every test and VMM over
    // the ambient set AND — because `bounding_drop` is `supported − need` — pin it in the bounding
    // set permanently, which is the exact opposite of why it is granted.
    //
    // RED on the inverse: add `Cap::SETPCAP` to `PRIVILEGED_CAPS` and the delivered-set assertions
    // below fail; drop it from `BLESSED_FILE_CAPS` and the file-set assertion fails.
    #[test]
    fn setpcap_is_a_transient_file_cap_never_delivered_to_the_test() {
        assert!(
            !PRIVILEGED_CAPS.contains(&Cap::SETPCAP),
            "CAP_SETPCAP must NOT be in the delivered/retained set"
        );
        assert!(
            BLESSED_FILE_CAPS.contains(&Cap::SETPCAP),
            "the blessed FILE set must carry the transient CAP_SETPCAP"
        );
        for c in PRIVILEGED_CAPS {
            assert!(
                BLESSED_FILE_CAPS.contains(&c),
                "the blessed file set must be a superset of the delivered set (missing {c:?})"
            );
        }
        assert_eq!(
            BLESSED_FILE_CAPS.len(),
            PRIVILEGED_CAPS.len() + 1,
            "the blessed file set adds exactly one cap (the transient SETPCAP)"
        );

        // And the plan must actually shed it, twice over: out of the bounding set (it is in
        // `supported` but not in `need`) and out of the final permitted/effective trim.
        let supported = [
            Cap::NET_ADMIN,
            Cap::SYS_ADMIN,
            Cap::DAC_OVERRIDE,
            Cap::SETPCAP,
            Cap::SYS_PTRACE,
        ];
        let plan = plan_privilege_transition(
            &PRIVILEGED_CAPS,
            &supported,
            1000,
            1000,
            1000,
            None,
            &[1000],
        );
        assert!(
            plan.bounding_drop.contains(&Cap::SETPCAP),
            "SETPCAP must be dropped from the bounding set, not preserved by being `need`"
        );
        for set in [&plan.ambient_raise, &plan.final_caps, &plan.inheritable_add] {
            assert!(
                !set.contains(&Cap::SETPCAP),
                "SETPCAP must never be delivered to the exec'd test: {set:?}"
            );
        }
        // Positive control: the caps that ARE delivered still are.
        for c in PRIVILEGED_CAPS {
            assert!(plan.ambient_raise.contains(&c) && plan.final_caps.contains(&c));
        }
    }

    // `setcap_arg` is the ONE composer of the `setcap(8)` argument. Pin its exact rendering: the
    // string is copy-pasted by operators out of `blessing_remediation` and executed verbatim, so a
    // silent change in spelling or flag is a blessing that grants the wrong set.
    //
    // RED on the inverse: render `+p` instead of `+ep` (the permitted-only blessing the precondition
    // rejects), or upper-case the names (`setcap` refuses `CAP_NET_ADMIN`).
    #[test]
    fn setcap_arg_renders_the_blessed_set_verbatim() {
        assert_eq!(
            setcap_arg(&BLESSED_FILE_CAPS),
            "cap_net_admin,cap_sys_admin,cap_dac_override,cap_setpcap+ep"
        );
        assert_eq!(
            setcap_arg(&PRIVILEGED_CAPS),
            "cap_net_admin,cap_sys_admin,cap_dac_override+ep"
        );
        // The remediation an operator copy-pastes grants the FILE set, never the missing subset —
        // `setcap` REPLACES a file's set, so echoing a subset would silently strip the rest.
        let msg = blessing_remediation(
            1000,
            Path::new("/x/runner"),
            &BlessingRefusal::Unblessed(vec![Cap::NET_ADMIN]),
        );
        assert!(
            msg.contains(&format!(
                "sudo setcap {} '/x/runner'",
                setcap_arg(&BLESSED_FILE_CAPS)
            )),
            "remediation must print the whole blessed set: {msg}"
        );
    }

    /// Every copy-pasteable capability argument in `text`, in source order.
    ///
    /// A *copy* is an occurrence of the literal `setcap` followed by a space whose next
    /// whitespace-delimited token — skipping a `\` line-continuation, then stripped of Markdown
    /// backticks and shell quotes — begins with the `cap_` prefix. The `sudo` is deliberately NOT
    /// part of the match: a copy written without it (a root shell, a Dockerfile, an ansible task)
    /// is still a copy, and the earlier scan that keyed on the literal `sudo ` would have walked
    /// straight past one. The `cap_` prefix is what separates a command from prose: a backticked
    /// mention never matches (no trailing space), and prose like "the setcap failed" matches the
    /// literal but yields a token that is not a capability list.
    ///
    /// Known shape limit, stated rather than glossed: the capability list must BE the argument. A
    /// copy that hides it behind a flag (`setcap -v …`) is not matched — that form verifies rather
    /// than grants, and widening the match to "any `cap_` token later on the line" would flag
    /// ordinary prose that names one cap.
    fn setcap_copies(text: &str) -> Vec<&str> {
        text.match_indices("setcap ")
            .filter_map(|(at, m)| text.get(at + m.len()..))
            .filter_map(|tail| tail.split_whitespace().find(|t| *t != "\\"))
            .map(|tok| tok.trim_matches(['`', '"', '\'']))
            .filter(|tok| tok.starts_with("cap_"))
            .collect()
    }

    /// Collects every tree file that could carry a hand-written copy — Markdown, shell, Rust,
    /// TOML, YAML, and the `justfile` — rooted at `dir`, with paths relative to `root`.
    ///
    /// Prunes `target/` at any depth (build output — the example workspace's built kernel tree
    /// alone is gigabytes and ships selftests that legitimately grant `cap_sys_boot`), `.git/`, and
    /// `docs/historical/`. Historical designs are frozen snapshots: they name the two- and
    /// three-cap sets vmcell used to bless with, and rewriting them would falsify the record.
    fn collect_scannable(dir: &Path, root: &Path, out: &mut Vec<std::path::PathBuf>) {
        let entries = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("scan: read_dir {}: {e}", dir.display()));
        for entry in entries {
            let entry =
                entry.unwrap_or_else(|e| panic!("scan: entry under {}: {e}", dir.display()));
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let ty = entry
                .file_type()
                .unwrap_or_else(|e| panic!("scan: file_type {}: {e}", path.display()));
            if ty.is_dir() {
                if name == "target"
                    || name == ".git"
                    || path == root.join("docs").join("historical")
                {
                    continue;
                }
                collect_scannable(&path, root, out);
            } else if ty.is_file() {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if name == "justfile"
                    || matches!(
                        ext,
                        "md" | "sh" | "bash" | "rs" | "toml" | "yml" | "yaml" | "just"
                    )
                {
                    out.push(path);
                }
            }
        }
    }

    /// The repo-relative path of the **current** design document: the one non-historical
    /// `docs/*.md` whose first non-empty line is the design's title.
    ///
    /// Discovered at run time, never hardcoded. The design is reissued under a new file name every
    /// campaign (v31 was `docs/79-…`, v32 is `docs/82-…`), and its §10.4 downstream route carries a
    /// blessing copy the roster below must cover; a pinned filename would therefore turn every
    /// reissue into a build break — which is exactly what happened, and is the hazard this function
    /// removes. Sub-directories are not descended, so the frozen copies in `docs/historical/` — old
    /// two- and three-cap grants that are the record, not drift — are out of scope by construction,
    /// the same way [`collect_scannable`] prunes them.
    ///
    /// Panics unless **exactly one** document claims the title: a text-scanning gate that resolves
    /// to nothing passes vacuously, which is what makes this class of gate theater. Same
    /// reissue-proof shape as `vmcell::vmm::jail`'s deny-list gate, which finds the same document
    /// by its §12.3 section heading.
    fn current_design_doc(root: &Path) -> String {
        /// The design's title line, up to its version number. Stable across every revision since
        /// v28; matched on the FIRST non-empty line, so a review or notes document that *quotes*
        /// the title further down does not masquerade as the design.
        const TITLE_PREFIX: &str = "# vmcell — Design Document (v";

        let docs = root.join("docs");
        let entries = std::fs::read_dir(&docs)
            .unwrap_or_else(|e| panic!("design scan: read_dir {}: {e}", docs.display()));
        let mut found = Vec::new();
        for entry in entries {
            let entry = entry.unwrap_or_else(|e| panic!("design scan: docs entry: {e}"));
            let path = entry.path();
            if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("md") {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("design scan: read {}: {e}", path.display()));
            if text
                .lines()
                .find(|l| !l.trim().is_empty())
                .is_some_and(|l| l.starts_with(TITLE_PREFIX))
            {
                found.push(
                    path.strip_prefix(root)
                        .expect("a docs/ path is under the repo root")
                        .display()
                        .to_string(),
                );
            }
        }
        found.sort();
        assert_eq!(
            found.len(),
            1,
            "expected exactly one current design document under {} (a file whose first line \
             starts with {TITLE_PREFIX:?}), found {found:?} — with none, the roster below would \
             pass vacuously over a design whose blessing copy nobody checked; with two, one of \
             them belongs in docs/historical/",
            docs.display()
        );
        found.into_iter().next().expect("exactly one, asserted")
    }

    // The cap list also lives in files that cannot import this constant: the `bless` recipe (which
    // grants it), the preflight probe (which verifies it), THREE copy-pasteable command lines in
    // the README, and ONE in the current design doc's downstream-consumer route (which is the only
    // blessing instruction a git-dep consumer following the design ever sees, since `just bless`
    // belongs to the vmcell checkout). That is the duplication "one law, one predicate" warns
    // about, and it has bitten twice — two copies drifted on strictness (`*ep*` substring vs the
    // `=ep`/`+ep` field), and the design's copy sat on the three-cap delivered set for a whole
    // release after `CAP_SETPCAP` joined the file set, precisely because the first version of this
    // gate read a hand-listed pair of files and claimed to read "every copy".
    //
    // So it now reads every copy that names its capability list as the `setcap` argument (the one
    // shape `setcap_copies` documents, `sudo` or not): a walk of the tree — minus `target/`,
    // `.git/`, and the frozen `docs/historical/`, whose old two- and three-cap grants are the
    // record, not drift — over every file type that can carry one. The roster below pins
    // WHICH files carry a copy and HOW MANY each carries, so the scan can neither pass vacuously
    // (an empty find is not the expected roster) nor let a new, uncovered copy appear in a new doc.
    // Reading at runtime rather than through `include_str!` is what makes coverage automatic; a
    // file that moves away reddens on the roster instead of the compile, which is the trade.
    //
    // The design document's row is DISCOVERED, not pinned (`current_design_doc`): pinning its
    // filename here made every design reissue a build break, since the design is renumbered each
    // campaign. Discovery is not a weakening — `current_design_doc` demands exactly one current
    // design and panics on none, so deleting the document, or the section carrying the copy, still
    // reddens.
    //
    // RED on the inverse: drop `cap_setpcap` from the justfile's grant, from the preflight's
    // NEEDED_CAPS, from any of the README's three command lines, or from the design's §10.4 route,
    // and this fails naming the file and the copy index. Delete the `sudo` from any of them and it
    // still holds (the scan does not key on it); add a copy to a new doc and the roster reddens.
    #[test]
    fn every_setcap_copy_in_the_tree_matches_this_constant() {
        const PREFLIGHT: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../scripts/review-preflight-priv.sh"
        ));
        /// Every **fixed-name** file carrying a copy-pasteable blessing command, and how many each
        /// carries: the `bless` recipe (1) and the README's downstream-consumer step 5 plus the two
        /// lines `just bless` runs (3). The design document carries one more (§10.4's
        /// downstream-consumer route) and is deliberately NOT listed here: it is renamed on every
        /// reissue, so it is discovered at run time by [`current_design_doc`] and spliced in below.
        /// Asserted as an exact roster, so a scan that silently matched nothing — how every
        /// text-scanning gate fails vacuously — reddens instead of passing over an empty set. If a
        /// copy is legitimately added, removed, or moved, update this roster; never delete the scan.
        const EXPECTED_FIXED: &[(&str, usize)] = &[("README.md", 3), ("justfile", 1)];
        /// How many blessing copies the current design document carries: §10.4's downstream route.
        const DESIGN_COPIES: usize = 1;
        /// The roster's total, stated once more on its own so the count is impossible to satisfy
        /// by deleting roster rows.
        const TOTAL_COPIES: usize = 5;

        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .canonicalize()
            .expect("repo root must resolve");
        let mut files = Vec::new();
        collect_scannable(&root, &root, &mut files);
        assert!(
            files.len() > 50,
            "the tree walk found only {} scannable files — it is not scanning the tree",
            files.len()
        );

        let arg = setcap_arg(&BLESSED_FILE_CAPS);
        let mut found: Vec<(String, usize)> = Vec::new();
        for path in &files {
            let text = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("scan: read {}: {e}", path.display()));
            let copies = setcap_copies(&text);
            if copies.is_empty() {
                continue;
            }
            let rel = path
                .strip_prefix(&root)
                .expect("scanned path is under the repo root")
                .display()
                .to_string();
            for (i, got) in copies.iter().enumerate() {
                assert_eq!(
                    *got,
                    arg,
                    "{rel}: blessing copy #{} must grant exactly `{arg}`",
                    i + 1
                );
            }
            found.push((rel, copies.len()));
        }
        found.sort();
        let mut expected: Vec<(String, usize)> = EXPECTED_FIXED
            .iter()
            .map(|&(p, n)| (p.replace('/', std::path::MAIN_SEPARATOR_STR), n))
            .collect();
        expected.push((current_design_doc(&root), DESIGN_COPIES));
        expected.sort();
        assert_eq!(
            found, expected,
            "the tree's blessing-copy roster changed; cover the new copy and update EXPECTED_FIXED \
             (the design document's row is discovered, not listed)"
        );
        assert_eq!(
            found.iter().map(|(_, n)| n).sum::<usize>(),
            TOTAL_COPIES,
            "expected {TOTAL_COPIES} blessing copies in the tree, found {found:?}"
        );

        // The preflight names the caps as a bash array it matches getcap output against; assert
        // every cap in the blessed set appears there, and that the array is not wider than the set.
        let needed = PREFLIGHT
            .lines()
            .find_map(|l| l.trim().strip_prefix("NEEDED_CAPS=("))
            .and_then(|l| l.split(')').next())
            .expect("preflight must declare NEEDED_CAPS=(…)");
        let listed: Vec<&str> = needed.split_whitespace().collect();
        for c in BLESSED_FILE_CAPS {
            let name = c.to_string().to_ascii_lowercase();
            assert!(
                listed.contains(&name.as_str()),
                "preflight NEEDED_CAPS must include {name}, got {listed:?}"
            );
        }
        assert_eq!(
            listed.len(),
            BLESSED_FILE_CAPS.len(),
            "preflight NEEDED_CAPS must be exactly the blessed set, got {listed:?}"
        );
    }
}
