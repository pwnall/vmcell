//! Jailer-equivalent: pre-exec hardening applied to the VMM child (design §20.4,
//! invariant §12.22).
//!
//! Firecracker's `jailer` is a privileged pre-exec wrapper (cgroup + netns + chroot +
//! uid-drop, then `execve`), and Firecracker itself installs `PR_SET_NO_NEW_PRIVS` +
//! seccomp **after** exec. vmcell already owns the netns + cgroup setup (§6.4); this module
//! adds the rest — the hardening applied to the forked VMM child in the existing
//! `build_vmm_cmd` `pre_exec` window (where the netns `setns` already happens), plus the
//! `no_new_privs` + optional seccomp the VMM would otherwise do for itself (belt-and-braces,
//! since we cannot audit every backend's self-hardening).
//!
//! The split mirrors `plan_privilege_transition`/`apply_privilege_transition` (§18.2): a
//! pure [`JailSpec`](crate::vmm::jail::JailSpec) compiled from the serializable
//! [`JailConfig`](crate::config::JailConfig), and one thin, **async-signal-safe**
//! [`apply_jail`](crate::vmm::jail::apply_jail) edge — the only impure part, and the one that runs
//! post-`fork`/pre-`execve`, so it must call only async-signal-safe syscalls on
//! already-allocated inputs (no allocation, no non-reentrant libc), exactly like the
//! `enter_netns` closure in `build_vmm_cmd`. The compiled seccomp filter is built here
//! (allocating, pre-`fork`) so the apply edge only *loads* it.
//!
//! One law, two callers: `apply_jail` is invoked from the in-process spawn (`build_vmm_cmd`)
//! and from the setup broker's `SpawnVmm` (§20.5), never a second copy.

use crate::config::JailConfig;
use crate::error::{Error, Result};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};
use std::collections::BTreeMap;
use std::sync::Arc;

/// The coarse, default-allow seccomp **deny-list** (design §20.4): syscalls a booting VMM
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
    ("process_vm_writev", libc::SYS_process_vm_writev),
    ("bpf", libc::SYS_bpf),
    ("perf_event_open", libc::SYS_perf_event_open),
    ("add_key", libc::SYS_add_key),
    ("keyctl", libc::SYS_keyctl),
    ("request_key", libc::SYS_request_key),
    ("setns", libc::SYS_setns),
    ("unshare", libc::SYS_unshare),
    ("reboot", libc::SYS_reboot),
    ("swapon", libc::SYS_swapon),
    ("swapoff", libc::SYS_swapoff),
];

/// Builds the coarse VMM deny-list BPF program with seccompiler (design §20.6 — the
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
    /// rlimits, no filter) — so `build_vmm_cmd` can skip installing a no-op `pre_exec`.
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

/// Applies `spec` to the calling thread in the forked child, **pre-exec** — the only impure,
/// async-signal-safe edge (design §20.4 / §12.22).
///
/// Order is load-bearing: rlimits → non-dumpable → clear-ambient → no-new-privs → seccomp.
/// `seccomp(SECCOMP_SET_MODE_FILTER)` requires `no_new_privs` first (seccompiler's
/// `apply_filter` sets it too, so the ordering is honored either way). Runs **after** the
/// caller's `setns` (which still needs the caps the child holds pre-exec).
///
/// # Errors
/// Returns the first failed syscall's [`std::io::Error`]; the caller (`pre_exec`) aborts the
/// child, so the VMM never starts under partial hardening.
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
        // async-signal-safe. Loaded last so the deny-list is active at execve.
        seccompiler::apply_filter(bpf)
            .map_err(|e| std::io::Error::other(format!("seccomp apply: {e}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Guards §12.22 / §20.4: the shipped deny-list is EXACTLY the documented set, and compiles
    // to a non-empty BPF program. Pinned as an exact membership so the filter cannot silently
    // drift from design §20.4 in either direction — dropping a syscall (e.g. `kexec_file_load`,
    // the file-based kexec variant that stays reachable if only `kexec_load` is blocked) OR
    // adding an undocumented one reddens here. The behavioral "mount → EPERM" proof is the
    // KVM-free stand-in integration test (tests/jail_hardening.rs).
    #[test]
    fn deny_list_is_exactly_the_documented_set_and_compiles() {
        use std::collections::BTreeSet;
        let expected: BTreeSet<&str> = [
            "mount",
            "umount2",
            "pivot_root",
            "kexec_load",
            "kexec_file_load",
            "init_module",
            "finit_module",
            "delete_module",
            "ptrace",
            "process_vm_writev",
            "bpf",
            "perf_event_open",
            "add_key",
            "keyctl",
            "request_key",
            "setns",
            "unshare",
            "reboot",
            "swapon",
            "swapoff",
        ]
        .into_iter()
        .collect();
        let actual: BTreeSet<&str> = DENIED_SYSCALLS.iter().map(|&(n, _)| n).collect();
        assert_eq!(
            actual, expected,
            "the VMM deny-list must exactly match design §20.4 (guarded both directions)"
        );
        let bpf = build_vmm_deny_filter().expect("deny-list must compile on this arch");
        assert!(
            !bpf.is_empty(),
            "a non-empty deny-list must compile to a non-empty BPF program"
        );
    }

    // Guards §12.22: `jail_spec_from_config` maps every flag through, and only builds a
    // filter when the deny-list is requested. Inverse: a mapping that dropped `non_dumpable`
    // or built a filter unconditionally reddens.
    #[test]
    fn jail_spec_from_config_maps_flags_and_gates_the_filter() {
        let hardened = jail_spec_from_config(&JailConfig::hardened()).expect("hardened spec");
        assert!(hardened.no_new_privs);
        assert!(
            !hardened.clear_ambient_caps,
            "clear_ambient_caps is opt-in (default off): the VMM needs its inherited CAP_NET_ADMIN \
             for privileged tap ops on restore (§20.9, validated on a KVM host)"
        );
        assert!(hardened.non_dumpable);
        assert_eq!(hardened.rlimit_core, Some(0));
        assert!(
            hardened.seccomp.is_none(),
            "the deny-list is opt-in; the hardened default must NOT carry a filter (§20.4)"
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
}
