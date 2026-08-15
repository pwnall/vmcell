//! Jailer-equivalent: pre-exec hardening applied to the VMM child (design §12.3, Layer 2 — the jailer-equivalent (JailSpec + apply_jail),
//! invariant §13, Cross-cutting invariants).
//!
//! Firecracker's `jailer` is a privileged pre-exec wrapper (cgroup + netns + chroot +
//! uid-drop, then `execve`), and Firecracker itself installs `PR_SET_NO_NEW_PRIVS` +
//! seccomp **after** exec. vmcell already owns the netns + cgroup setup (§6.1, The two operating modes); this module
//! adds the rest — the hardening applied to the forked VMM child in the existing
//! `build_vmm_cmd` `pre_exec` window (where the netns `setns` already happens), plus the
//! `no_new_privs` + optional seccomp the VMM would otherwise do for itself (belt-and-braces,
//! since we cannot audit every backend's self-hardening).
//!
//! The split mirrors `plan_privilege_transition`/`apply_privilege_transition` (§11.2, Privilege and blessing): a
//! pure [`JailSpec`](crate::vmm::jail::JailSpec) compiled from the serializable
//! [`JailConfig`](crate::config::JailConfig), and one thin, **async-signal-safe**
//! [`apply_jail`](crate::vmm::jail::apply_jail) edge — the only impure part, and the one that runs
//! post-`fork`/pre-`execve`, so it must call only async-signal-safe syscalls on
//! already-allocated inputs (no allocation, no non-reentrant libc), exactly like the
//! `enter_netns` closure in `build_vmm_cmd`. The compiled seccomp filter is built here
//! (allocating, pre-`fork`) so the apply edge only *loads* it.
//!
//! One law, two callers: `apply_jail` is invoked from the in-process spawn (`build_vmm_cmd`)
//! and from the setup broker's `SpawnVmm` (§12.4, Layer 3 — the setup broker (network surface never holds caps)), never a second copy.

use crate::config::JailConfig;
use crate::error::{Error, Result};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};
use std::collections::BTreeMap;
use std::sync::Arc;

/// The coarse, default-allow seccomp **deny-list** (design §12.3, Layer 2 — the jailer-equivalent (JailSpec + apply_jail)): syscalls a booting VMM
/// never needs and an escape would want. A default-allow deny-list cannot break the VMM
/// unless it legitimately needs one of these *dangerous* syscalls (it does not), which is
/// why it is far safer to ship than a default-deny allow-list. Each `→ EPERM`.
///
/// Named `(syscall, number)` pairs (numbers from `libc::SYS_*`, arch-correct) so the unit
/// test can assert membership without decompiling the BPF program. The number is `i64` (what
/// seccompiler keys on); `libc::SYS_*` is `c_long`, which **is** `i64` on the 64-bit targets
/// vmcell supports (x86-64 / aarch64), so no conversion is needed.
pub const DENIED_SYSCALLS: &[(&str, i64)] = &[
    ("mount", libc::SYS_mount),
    ("umount2", libc::SYS_umount2),
    ("pivot_root", libc::SYS_pivot_root),
    ("kexec_load", libc::SYS_kexec_load),
    ("kexec_file_load", libc::SYS_kexec_file_load),
    ("init_module", libc::SYS_init_module),
    ("finit_module", libc::SYS_finit_module),
    ("delete_module", libc::SYS_delete_module),
    ("ptrace", libc::SYS_ptrace),
    // Both halves of the attach-to-another-process primitive. `process_vm_readv` was missing
    // (docs/78 M15) while the design roster has carried it since v28; on the crosvm
    // `Enforcing` path this list is the ONLY confinement (`--disable-sandbox`), so the read
    // half was the one exfiltration primitive left open there.
    ("process_vm_readv", libc::SYS_process_vm_readv),
    ("process_vm_writev", libc::SYS_process_vm_writev),
    ("bpf", libc::SYS_bpf),
    ("perf_event_open", libc::SYS_perf_event_open),
    ("add_key", libc::SYS_add_key),
    ("keyctl", libc::SYS_keyctl),
    ("request_key", libc::SYS_request_key),
    ("setns", libc::SYS_setns),
    ("unshare", libc::SYS_unshare),
    // Part of the §12.3 roster since design v31, which folded in what had been a recorded
    // deviation (docs/78 M15): they are dangerous-and-never-needed by a booting VMM in exactly
    // the sense the other entries are — `reboot` reboots/halts the HOST (a guest reboot is a
    // VMM-internal transition, not this syscall), and `swapon`/`swapoff` reconfigure host swap.
    // This const and the §12.3 table match name-for-name in both directions, and
    // `deny_list_is_exactly_the_documented_set_and_compiles` proves it by PARSING that table out
    // of the current design document at run time — not by comparing this const to a second
    // hand-transcribed list, which would prove only that the transcription was copied correctly.
    // Do not drop them to "match the doc" — the doc already carries them.
    ("reboot", libc::SYS_reboot),
    ("swapon", libc::SYS_swapon),
    ("swapoff", libc::SYS_swapoff),
];

/// Builds the coarse VMM deny-list BPF program with seccompiler (design §12.5, The licensing constraint on seccomp crates — the
/// rust-vmm library CH/FC use, `Apache-2.0 OR BSD-3-Clause`, no C linkage). Default action
/// is **Allow** (a mismatch, i.e. any syscall not in [`DENIED_SYSCALLS`], is permitted); a
/// match returns `EPERM`. Built pre-`fork` (allocation is fine here); the async-signal-safe
/// [`apply_jail`] only loads the result.
///
/// # Errors
/// Returns [`Error::Config`] if the host architecture is unsupported by seccompiler or the
/// filter fails to compile.
pub fn build_vmm_deny_filter() -> Result<BpfProgram> {
    let target_arch = std::env::consts::ARCH.try_into().map_err(|_| {
        Error::Config(format!(
            "seccomp deny-list: unsupported target arch {}",
            std::env::consts::ARCH
        ))
    })?;
    // An empty rule vector for a syscall means "match unconditionally" → the match action.
    let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = DENIED_SYSCALLS
        .iter()
        .map(|&(_, nr)| (nr, Vec::new()))
        .collect();
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow, // mismatch: everything else is allowed
        // match: a denied syscall returns EPERM (unsigned_abs avoids a sign-loss cast).
        SeccompAction::Errno(libc::EPERM.unsigned_abs()),
        target_arch,
    )
    .map_err(|e| Error::Config(format!("seccomp deny-list compile: {e}")))?;
    filter
        .try_into()
        .map_err(|e| Error::Config(format!("seccomp deny-list to BPF: {e}")))
}

/// Runtime jail specification: the hardening flags/limits from [`JailConfig`] plus the
/// optional pre-compiled seccomp filter. Applied by [`apply_jail`] in the forked child.
#[derive(Clone, Default)]
pub struct JailSpec {
    /// `prctl(PR_SET_NO_NEW_PRIVS, 1)`.
    pub no_new_privs: bool,
    /// `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)`.
    pub clear_ambient_caps: bool,
    /// `prctl(PR_SET_DUMPABLE, 0)`.
    pub non_dumpable: bool,
    /// `RLIMIT_CORE` value, or `None` to leave it inherited.
    pub rlimit_core: Option<u64>,
    /// `RLIMIT_FSIZE` value, or `None` to leave it inherited.
    pub rlimit_fsize: Option<u64>,
    /// `RLIMIT_NOFILE` value, or `None` to leave it inherited.
    pub rlimit_nofile: Option<u64>,
    /// A pre-compiled seccomp deny-list to load last (loading itself sets `no_new_privs`);
    /// `None` when [`JailConfig::seccomp_deny_list`] is off.
    pub seccomp: Option<Arc<BpfProgram>>,
}

impl std::fmt::Debug for JailSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `BpfProgram` is a large Vec<sock_filter>; render only whether a filter is present.
        f.debug_struct("JailSpec")
            .field("no_new_privs", &self.no_new_privs)
            .field("clear_ambient_caps", &self.clear_ambient_caps)
            .field("non_dumpable", &self.non_dumpable)
            .field("rlimit_core", &self.rlimit_core)
            .field("rlimit_fsize", &self.rlimit_fsize)
            .field("rlimit_nofile", &self.rlimit_nofile)
            .field("seccomp", &self.seccomp.is_some())
            .finish()
    }
}

impl JailSpec {
    /// Returns `true` if this spec would apply no hardening at all (every flag off, no
    /// rlimits, no filter).
    ///
    /// Descriptive only — it gates nothing, and has **no production caller** in the workspace.
    /// `build_vmm_cmd` installs its `pre_exec` closure unconditionally (docs/78 M9): that closure
    /// also resets SIGINT/SIGTERM to `SIG_DFL` and joins the netns, and both must happen even for
    /// a no-op jail, so "the jail is a no-op" is not a reason to skip it. The predicate exists for
    /// the tests that assert [`JailConfig::hardened`] hardens and [`JailConfig::disabled`] does
    /// not.
    #[must_use]
    pub fn is_noop(&self) -> bool {
        !self.no_new_privs
            && !self.clear_ambient_caps
            && !self.non_dumpable
            && self.rlimit_core.is_none()
            && self.rlimit_fsize.is_none()
            && self.rlimit_nofile.is_none()
            && self.seccomp.is_none()
    }
}

/// Compiles a [`JailConfig`] into a runtime [`JailSpec`], building the seccomp deny-list
/// (pre-`fork`) when [`JailConfig::seccomp_deny_list`] is set.
///
/// # Errors
/// Returns [`Error::Config`] if the seccomp deny-list fails to compile ([`build_vmm_deny_filter`]).
pub fn jail_spec_from_config(cfg: &JailConfig) -> Result<JailSpec> {
    let seccomp = if cfg.seccomp_deny_list {
        Some(Arc::new(build_vmm_deny_filter()?))
    } else {
        None
    };
    Ok(JailSpec {
        no_new_privs: cfg.no_new_privs,
        clear_ambient_caps: cfg.clear_ambient_caps,
        non_dumpable: cfg.non_dumpable,
        rlimit_core: cfg.rlimit_core,
        rlimit_fsize: cfg.rlimit_fsize,
        rlimit_nofile: cfg.rlimit_nofile,
        seccomp,
    })
}

/// Sets one `RLIMIT_*` to `value` (both soft and hard) via `setrlimit(2)`.
///
/// Async-signal-safe: `setrlimit` on a stack `rlimit` struct, no allocation. Called only
/// from [`apply_jail`]'s pre-exec window.
fn set_rlimit(resource: libc::__rlimit_resource_t, value: u64) -> std::io::Result<()> {
    let lim = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: `setrlimit(2)` with a valid resource id and a pointer to a fully-initialized,
    // stack-owned `rlimit`; async-signal-safe, no allocation.
    if unsafe { libc::setrlimit(resource, &lim) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Flattens a [`seccompiler::Error`] to a bare errno, the only shape [`apply_jail`] may return
/// from the forked child (docs/78 `apply-jail-error-path-allocates-post-fork`): rendering the
/// error — `format!`, `io::Error::other`, `io::Error::new` — heap-allocates, and a child that
/// grabs the allocator lock its parent held at `fork` deadlocks, so `create()` would HANG
/// instead of failing. The two variants that carry an errno pass it through; the rest (an empty
/// filter, a TSYNC pid, a backend compile bug) collapse to `EINVAL` — enough for the caller,
/// which aborts the child either way, so the VMM never runs under partial hardening.
///
/// Async-signal-safe: a pure match, no allocation.
fn seccomp_apply_errno(e: &seccompiler::Error) -> i32 {
    match e {
        seccompiler::Error::Prctl(io) | seccompiler::Error::Seccomp(io) => {
            io.raw_os_error().unwrap_or(libc::EINVAL)
        }
        _ => libc::EINVAL,
    }
}

/// Applies `spec` to the calling thread in the forked child, **pre-exec** — the only impure,
/// async-signal-safe edge (design §12.3, Layer 2 — the jailer-equivalent (JailSpec + apply_jail) / §13, Cross-cutting invariants).
///
/// Order is load-bearing: rlimits → non-dumpable → clear-ambient → no-new-privs → seccomp.
/// `seccomp(SECCOMP_SET_MODE_FILTER)` requires `no_new_privs` first (seccompiler's
/// `apply_filter` sets it too, so the ordering is honored either way). Runs **after** the
/// caller's `setns` (which still needs the caps the child holds pre-exec).
///
/// # Errors
/// Returns the first failed syscall's [`std::io::Error`]; the caller (`pre_exec`) aborts the
/// child, so the VMM never starts under partial hardening. Every error is a bare errno
/// (`last_os_error`/`from_raw_os_error`, which store the code inline) — the error path is as
/// allocation-free as the success path, because both run post-`fork`.
pub fn apply_jail(spec: &JailSpec) -> std::io::Result<()> {
    if let Some(v) = spec.rlimit_core {
        set_rlimit(libc::RLIMIT_CORE, v)?;
    }
    if let Some(v) = spec.rlimit_fsize {
        set_rlimit(libc::RLIMIT_FSIZE, v)?;
    }
    if let Some(v) = spec.rlimit_nofile {
        set_rlimit(libc::RLIMIT_NOFILE, v)?;
    }
    if spec.non_dumpable {
        // SAFETY: `prctl(PR_SET_DUMPABLE, 0)` takes no pointer args; async-signal-safe.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    if spec.clear_ambient_caps {
        // SAFETY: `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, …)` clears the ambient
        // capability set; no pointer args; async-signal-safe.
        if unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    if spec.no_new_privs {
        // SAFETY: `prctl(PR_SET_NO_NEW_PRIVS, 1)` takes no pointer args; async-signal-safe.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    if let Some(bpf) = &spec.seccomp {
        // seccompiler::apply_filter builds a stack `sock_fprog` from the already-allocated
        // BpfProgram and issues prctl(NO_NEW_PRIVS)+seccomp(SET_MODE_FILTER) — no allocation,
        // async-signal-safe. Loaded last so the deny-list is active at execve. The failure is
        // flattened to a bare errno by `seccomp_apply_errno` (never rendered — rendering
        // allocates, see its doc); `from_raw_os_error` stores the code inline.
        seccompiler::apply_filter(bpf)
            .map_err(|e| std::io::Error::from_raw_os_error(seccomp_apply_errno(&e)))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    // ---- the §12.3 roster gate ------------------------------------------------------------
    //
    // The design's §12.3 table and [`DENIED_SYSCALLS`] are two copies of one roster, and the
    // doc's own text says the table "is checked against it, in both directions". The previous
    // version of this gate compared the const to a THIRD copy — a 21-name literal transcribed
    // into the test body — so it proved `const == transcription` and would have stayed green if
    // §12.3 changed. It also could not see the drift it was written for: the const had silently
    // dropped `process_vm_readv` while the design carried it (docs/78 M15).
    //
    // So the expected set is now PARSED OUT OF THE DESIGN at run time. The document is found by
    // its **§12.3 heading**, never by filename: the design is reissued under a new number every
    // campaign (v31 lives in `docs/79-…`, its successor will not), and a hardcoded path would
    // either break on the rename or, worse, keep reading the frozen copy in `docs/historical/`.
    // Directories are not descended, so `docs/historical/` — whose older tables are the record,
    // not drift — is skipped by construction. Same reissue-proof shape as
    // `vmcell-privilege`'s `every_setcap_copy_in_the_tree_matches_this_constant`.
    //
    // Every failure to FIND the table is an error, never an empty expected set: a text-scanning
    // gate that matches nothing passes vacuously, which is the failure mode that makes this
    // class of gate theater.

    /// The design section that carries the deny-list roster.
    const DESIGN_SECTION: &str = "12.3";

    /// The smallest roster this gate accepts as "a real table" — a second non-vacuity guard
    /// behind the parser's own empty-table error, in case a future table is parsed down to one
    /// stray token.
    const MIN_ROSTER: usize = 15;

    /// Heading level of `line` (`###` → 3), or `None` when it is not a heading.
    fn heading_level(line: &str) -> Option<usize> {
        let hashes = line.trim_start().chars().take_while(|&c| c == '#').count();
        (hashes > 0).then_some(hashes)
    }

    /// True when `line` opens the design section named by `section` (`### 12.3 Layer 2 …`).
    /// Matches on the section NUMBER only — the heading's prose is free to change — and
    /// requires a boundary after it so `12.30` is not mistaken for `12.3`.
    fn is_section_heading(line: &str, section: &str) -> bool {
        if heading_level(line).is_none() {
            return false;
        }
        let rest = line.trim_start().trim_start_matches('#').trim_start();
        rest.strip_prefix(section)
            .is_some_and(|tail| !tail.starts_with(|c: char| c.is_ascii_digit() || c == '.'))
    }

    /// The body of section `section` in `markdown` — the lines after its heading, up to the next
    /// heading at the same or a shallower level. Headings *inside* fenced code blocks are
    /// ignored (a `# comment` line in a fence is not a section break).
    fn section_body<'a>(markdown: &'a str, section: &str) -> Option<Vec<&'a str>> {
        let mut lines = markdown.lines();
        let level = lines.find_map(|l| {
            if is_section_heading(l, section) {
                heading_level(l)
            } else {
                None
            }
        })?;
        let mut body = Vec::new();
        let mut in_fence = false;
        for line in lines {
            if line.trim_start().starts_with("```") {
                in_fence = !in_fence;
            } else if !in_fence && heading_level(line).is_some_and(|l| l <= level) {
                break;
            }
            body.push(line);
        }
        Some(body)
    }

    /// The syscall roster in section `section` of `markdown`.
    ///
    /// The roster is the section's single ```` ```text ```` fenced block: comma-separated
    /// syscall names per line, each line optionally ending in a `#` comment. Every departure
    /// from that shape — no such section, no ```` ```text ```` block, more than one, an empty
    /// table, a token that is not a syscall identifier — is an `Err`, so the comparison below
    /// can never silently run against an empty expected set.
    fn design_roster(
        markdown: &str,
        section: &str,
    ) -> std::result::Result<BTreeSet<String>, String> {
        let body = section_body(markdown, section)
            .ok_or_else(|| format!("no §{section} heading in this document"))?;
        let mut blocks: Vec<Vec<&str>> = Vec::new();
        let mut current: Option<Vec<&str>> = None;
        for line in body {
            let trimmed = line.trim_start();
            if let Some(info) = trimmed.strip_prefix("```") {
                match current.take() {
                    Some(block) => blocks.push(block),
                    None => {
                        if info.trim() == "text" {
                            current = Some(Vec::new());
                        }
                    }
                }
            } else if let Some(block) = current.as_mut() {
                block.push(line);
            }
        }
        if blocks.len() != 1 {
            return Err(format!(
                "§{section} must carry exactly one ```text roster block; found {}",
                blocks.len()
            ));
        }
        let mut names = BTreeSet::new();
        for line in blocks.into_iter().flatten() {
            let code = line.split('#').next().unwrap_or("");
            for token in code.split(',') {
                let name = token.trim();
                if name.is_empty() {
                    continue;
                }
                if !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                {
                    return Err(format!(
                        "§{section} roster entry {name:?} is not a syscall name — the table's \
                         shape changed and this parser no longer reads it"
                    ));
                }
                names.insert(name.to_string());
            }
        }
        if names.is_empty() {
            return Err(format!("§{section}'s roster block parsed to zero syscalls"));
        }
        Ok(names)
    }

    /// Every non-historical `docs/*.md` that carries a §12.3 roster, as `(file name, roster)`.
    ///
    /// Reading the directory at run time (rather than `include_str!`) is what makes the gate
    /// survive the design's reissue: the successor document is picked up by its heading the
    /// moment it lands. Sub-directories are not descended, so `docs/historical/` is out of
    /// scope. Panics — never returns an empty roster — if the design cannot be found or parsed.
    fn design_rosters() -> Vec<(String, BTreeSet<String>)> {
        let docs = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("docs");
        let entries =
            std::fs::read_dir(&docs).unwrap_or_else(|e| panic!("read_dir {}: {e}", docs.display()));
        let mut out = Vec::new();
        let mut errors = Vec::new();
        for entry in entries {
            let entry = entry.unwrap_or_else(|e| panic!("docs entry: {e}"));
            let path = entry.path();
            if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("md") {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            if !text.lines().any(|l| is_section_heading(l, DESIGN_SECTION)) {
                continue;
            }
            match design_roster(&text, DESIGN_SECTION) {
                Ok(roster) => out.push((name, roster)),
                Err(e) => errors.push(format!("{name}: {e}")),
            }
        }
        assert!(
            errors.is_empty(),
            "a document carries a §{DESIGN_SECTION} heading but its roster could not be read — \
             fix the parser or the table, never let this gate fall back to an empty set: \
             {errors:?}"
        );
        assert!(
            !out.is_empty(),
            "no document under {} carries a §{DESIGN_SECTION} roster — the design was renamed or \
             moved and this gate is reading nothing (it must not pass vacuously)",
            docs.display()
        );
        out
    }

    // Guards §13 (Cross-cutting invariants) / §12.3 (Layer 2 — the jailer-equivalent (JailSpec +
    // apply_jail)): the shipped deny-list is EXACTLY the roster the current design documents, and
    // compiles to a non-empty BPF program. Guarded in both directions — dropping a syscall (e.g.
    // `kexec_file_load`, the file-based kexec variant that stays reachable if only `kexec_load` is
    // blocked) OR adding an undocumented one reddens here, and so does deleting a name from the
    // design's table without deleting it from the const. The behavioral "mount → EPERM" proof is
    // the KVM-free stand-in integration test (tests/jail_hardening.rs).
    #[test]
    fn deny_list_is_exactly_the_documented_set_and_compiles() {
        let actual: BTreeSet<String> = DENIED_SYSCALLS
            .iter()
            .map(|&(n, _)| n.to_string())
            .collect();
        for (doc, expected) in design_rosters() {
            assert!(
                expected.len() >= MIN_ROSTER,
                "{doc}: §{DESIGN_SECTION}'s roster parsed to only {} entries ({expected:?}) — \
                 that is not the table, and a short expected set would let the const drift",
                expected.len()
            );
            assert_eq!(
                actual, expected,
                "the VMM deny-list must exactly match {doc} §{DESIGN_SECTION} (Layer 2 — the \
                 jailer-equivalent), guarded both directions: add a syscall to BOTH, never drop \
                 one from the const to \"match the doc\""
            );
        }
        let bpf = build_vmm_deny_filter().expect("deny-list must compile on this arch");
        assert!(
            !bpf.is_empty(),
            "a non-empty deny-list must compile to a non-empty BPF program"
        );
    }

    // The parser's own red-on-inverse (AGENTS.md rule 2): every way the design can stop carrying
    // a readable roster must be an `Err`, because an `Ok(empty)` would make the gate above pass
    // over nothing at all. Also pins the shape it DOES accept, so the positive path is not
    // accidental.
    #[test]
    fn the_roster_parser_errors_rather_than_reading_an_empty_table() {
        const GOOD: &str = "## 12 Security\n\
             ### 12.3 Layer 2\n\
             prose\n\
             ```rust\n\
             pub struct JailSpec { /* ### 12.4 is not a heading in here */ }\n\
             ```\n\
             ```text\n\
             mount, umount2   # filesystem-namespace escape\n\
             ptrace\n\
             ```\n\
             ### 12.4 Layer 3\n\
             ```text\n\
             not_the_roster\n\
             ```\n";
        assert_eq!(
            design_roster(GOOD, "12.3").expect("the documented shape must parse"),
            ["mount", "umount2", "ptrace"]
                .into_iter()
                .map(String::from)
                .collect::<BTreeSet<String>>(),
            "the roster is this section's own ```text block: fenced `###` lines are not section \
             breaks, and the NEXT section's block must not leak in"
        );

        for (case, markdown) in [
            ("missing section", "## 12 Security\n### 12.4 Layer 3\n"),
            (
                "section number is a prefix of another",
                "### 12.30 Layer 2\n```text\nmount\n```\n",
            ),
            (
                "no ```text block",
                "### 12.3 Layer 2\n```rust\nmount\n```\n",
            ),
            (
                "two ```text blocks",
                "### 12.3 L2\n```text\nmount\n```\n```text\nptrace\n```\n",
            ),
            ("empty table", "### 12.3 Layer 2\n```text\n\n```\n"),
            (
                "prose where the roster should be",
                "### 12.3 Layer 2\n```text\nThe list is default-allow.\n```\n",
            ),
        ] {
            assert!(
                design_roster(markdown, "12.3").is_err(),
                "{case}: the parser must ERROR rather than hand the gate an empty or bogus roster"
            );
        }
    }

    // Guards §13 (Cross-cutting invariants): `jail_spec_from_config` maps every flag through, and only builds a
    // filter when the deny-list is requested. Inverse: a mapping that dropped `non_dumpable`
    // or built a filter unconditionally reddens.
    #[test]
    fn jail_spec_from_config_maps_flags_and_gates_the_filter() {
        let hardened = jail_spec_from_config(&JailConfig::hardened()).expect("hardened spec");
        assert!(hardened.no_new_privs);
        assert!(
            !hardened.clear_ambient_caps,
            "clear_ambient_caps is opt-in (default off): the VMM needs its inherited CAP_NET_ADMIN \
             for privileged tap ops on restore (§17, Open gaps and future capabilities; validated on a KVM host)"
        );
        assert!(hardened.non_dumpable);
        assert_eq!(hardened.rlimit_core, Some(0));
        assert!(
            hardened.seccomp.is_none(),
            "the deny-list is opt-in; the hardened default must NOT carry a filter (§12.3, Layer 2 — the jailer-equivalent)"
        );
        assert!(!hardened.is_noop());

        let mut with_filter = JailConfig::hardened();
        with_filter.seccomp_deny_list = true;
        let spec = jail_spec_from_config(&with_filter).expect("filter spec");
        assert!(
            spec.seccomp.is_some(),
            "seccomp_deny_list=true must compile and attach a filter"
        );

        let noop = jail_spec_from_config(&JailConfig::disabled()).expect("disabled spec");
        assert!(noop.is_noop(), "the disabled jail must be a no-op");
    }

    // Guards the post-`fork` no-allocation contract of `apply_jail`'s ERROR path (docs/78
    // `apply-jail-error-path-allocates-post-fork`, §12.3 Layer 2). `raw_os_error()` is `Some`
    // exactly for an OS-repr `io::Error` — the only variant that carries no heap payload — so
    // the inverse (`io::Error::other(format!(…))`, `io::Error::new(…, msg)`, or any rendered
    // error) yields `None` and reddens both legs here. The seccomp arm is driven through the
    // real `apply_jail` with an EMPTY filter: seccompiler rejects it BEFORE issuing any syscall
    // (no `prctl`/`seccomp` side effect on the test process), so the leg is in-process,
    // root-free and KVM-free.
    #[test]
    fn apply_jail_errors_are_bare_errnos_never_allocated_messages() {
        // Both errno-carrying variants pass their code through unchanged…
        assert_eq!(
            seccomp_apply_errno(&seccompiler::Error::Prctl(
                std::io::Error::from_raw_os_error(libc::EACCES)
            )),
            libc::EACCES
        );
        assert_eq!(
            seccomp_apply_errno(&seccompiler::Error::Seccomp(
                std::io::Error::from_raw_os_error(libc::ENOSYS)
            )),
            libc::ENOSYS
        );
        // …and the errno-less variants collapse to EINVAL rather than being rendered.
        assert_eq!(
            seccomp_apply_errno(&seccompiler::Error::EmptyFilter),
            libc::EINVAL
        );
        assert_eq!(
            seccomp_apply_errno(&seccompiler::Error::ThreadSync(4242)),
            libc::EINVAL
        );

        let empty = JailSpec {
            seccomp: Some(Arc::new(Vec::new())),
            ..JailSpec::default()
        };
        let err = apply_jail(&empty).expect_err("an empty filter must fail the seccomp arm");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EINVAL),
            "apply_jail must return a bare errno post-fork; a rendered/boxed error allocates \
             and can deadlock the forked child against the parent's allocator lock"
        );
    }
}
