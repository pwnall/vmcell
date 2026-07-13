//! The one-probe host-capability descriptor (`HostCapabilities`), design §7.2 rule 1 / §18 delta 8.
//!
//! An earlier stance — "unprivileged delegation degrades gracefully" — invited **silent no-ops**: a
//! caller asks for a 256 MiB cap, the controller isn't delegated, the write fails, and the VM runs
//! *unlimited* while the call returns `Ok`. The rule is reversed: a missing capability fails loud
//! unless the op is explicitly best-effort (law F1). To make "what does this host support?" have
//! **one** answer and **one** probe, [`HostCapabilities`] records — probed once at start-up (by mode
//! selection, the daemon's `main`, and the test harness) — the effective capability set, KVM-group
//! access, `/var/run/netns` reachability, which cgroup controllers the current scope delegates, and
//! whether the scope is a non-threaded `domain` leaf. Per-op checks read the descriptor instead of
//! re-probing (this consolidates the previously scattered per-op checks — §18 delta 8).

use std::collections::BTreeSet;

/// `CAP_NET_ADMIN` — the capability the privileged tap/netns datapath needs (§6.1). Bit index in the
/// `/proc/self/status` `CapEff` mask.
const CAP_NET_ADMIN: u32 = 12;
/// `CAP_SYS_ADMIN` — the capability `virtiofsd` needs to enter its mount namespace for a data share
/// (§4.5).
const CAP_SYS_ADMIN: u32 = 21;

/// A single-probe snapshot of what the host actually offers, the one source of truth per-op checks
/// read instead of re-probing (design §7.2 rule 1, §18 delta 8).
///
/// Build one at start-up with [`HostCapabilities::probe`]; tests construct a fake-host descriptor
/// directly (every field is `pub`) and assert that it drives the mode-selection and fail-loud
/// decisions the accessor methods encode.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct HostCapabilities {
    /// Effective `CAP_NET_ADMIN` — required for the privileged tap + netns network path (§6.1).
    pub cap_net_admin: bool,
    /// Effective `CAP_SYS_ADMIN` — required for `virtiofsd`'s mount namespace, so virtio-fs data
    /// shares can mount (§4.5).
    pub cap_sys_admin: bool,
    /// `/dev/kvm` is present and openable read-write — the hard precondition for booting any VM.
    pub kvm_accessible: bool,
    /// The `/var/run/netns` bind-mount directory is reachable — the privileged datapath keeps its
    /// per-VM namespaces there (§6.1).
    pub netns_reachable: bool,
    /// The cgroup-v2 controllers the current scope delegates into its subtree (§7.3). A *requested*
    /// limit needing an absent controller must fail loud (§7.2 rule 2), never run unlimited.
    pub delegated_controllers: BTreeSet<String>,
    /// The current cgroup scope is a non-threaded `domain` leaf. A threaded scope rejects
    /// `cgroup.procs` regardless of `CAP_SYS_ADMIN`, so no per-VM slice can hold the VMM (§7.3).
    pub domain_leaf: bool,
}

impl HostCapabilities {
    /// Probes the host **once**, reading `/proc/self/status`, `/dev/kvm`, `/var/run/netns`, and the
    /// current cgroup scope's `cgroup.subtree_control` / `cgroup.type`. Every field is a best-effort
    /// read that resolves to the conservative value (`false` / empty) when the source is unreadable,
    /// so an unknown host is treated as *un*-provisioned rather than optimistically capable.
    #[must_use]
    pub fn probe() -> Self {
        Self {
            cap_net_admin: has_effective_cap(CAP_NET_ADMIN),
            cap_sys_admin: has_effective_cap(CAP_SYS_ADMIN),
            kvm_accessible: kvm_accessible(),
            netns_reachable: netns_reachable(),
            delegated_controllers: probe_delegated_controllers(),
            domain_leaf: probe_domain_leaf(),
        }
    }

    /// Whether the **privileged** (tap + netns) networking datapath is available (§6.1): effective
    /// `CAP_NET_ADMIN` **and** a reachable netns directory. Mode selection falls back to the
    /// unprivileged smoltcp NAT when this is `false` — the decision that keeps the box usable
    /// without root.
    #[must_use]
    pub fn privileged_net_available(&self) -> bool {
        self.cap_net_admin && self.netns_reachable
    }

    /// Whether a *requested* limit for `controller` (`"memory"`/`"cpu"`/`"io"`/`"pids"`) can be
    /// enforced: the scope is a non-threaded `domain` leaf **and** delegates that controller (§7.3).
    /// A requested limit on a host where this is `false` must fail loud with
    /// [`Error::CapabilityUnavailable`](crate::error::Error::CapabilityUnavailable) (§7.2 rule 2),
    /// never silently run unlimited.
    #[must_use]
    pub fn controller_enforceable(&self, controller: &str) -> bool {
        self.domain_leaf && self.delegated_controllers.contains(controller)
    }

    /// Whether a *requested* **memory** limit can be enforced (the binding cap for guest RAM, §7.3).
    #[must_use]
    pub fn memory_limit_enforceable(&self) -> bool {
        self.controller_enforceable("memory")
    }

    /// Whether virtio-fs data shares can mount (`virtiofsd` needs `CAP_SYS_ADMIN` for its mount
    /// namespace, §4.5).
    #[must_use]
    pub fn virtio_fs_shares_available(&self) -> bool {
        self.cap_sys_admin
    }

    /// Whether a VM can boot at all on this host (`/dev/kvm` present and openable).
    #[must_use]
    pub fn can_boot_vm(&self) -> bool {
        self.kvm_accessible
    }
}

/// Probes the process's **effective** capability set for capability `bit` via `/proc/self/status`
/// `CapEff:` — the §12.8-consistent gate: the capability runner grants caps ambiently without a
/// full-root uid, so a `geteuid()==0` gate checks the wrong thing.
fn has_effective_cap(bit: u32) -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    for line in status.lines() {
        if let Some(hex) = line.strip_prefix("CapEff:")
            && let Ok(bits) = u64::from_str_radix(hex.trim(), 16)
        {
            return bits & (1u64 << bit) != 0;
        }
    }
    false
}

/// Whether `/dev/kvm` is present and openable read-write. Existence alone is insufficient (it can
/// exist but be inaccessible), so this opens it.
fn kvm_accessible() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
}

/// Whether the `/var/run/netns` bind-mount directory is reachable (the privileged datapath keeps
/// per-VM network namespaces there). `iproute2` creates it on demand, so its *parent* being a
/// writable directory is the reachability signal.
fn netns_reachable() -> bool {
    // `/var/run` is conventionally a symlink to `/run`; either being a directory means the netns dir
    // is creatable there.
    std::path::Path::new("/run").is_dir() || std::path::Path::new("/var/run").is_dir()
}

/// The cgroup-v2 controllers delegated into the current scope's subtree, read from the current
/// scope's `cgroup.subtree_control` (via the canonical `/proc/self/cgroup` base parser).
fn probe_delegated_controllers() -> BTreeSet<String> {
    let base = current_cgroup_base();
    let path = match &base {
        Some(b) => format!("/sys/fs/cgroup/{b}/cgroup.subtree_control"),
        None => "/sys/fs/cgroup/cgroup.subtree_control".to_string(),
    };
    std::fs::read_to_string(path)
        .map(|s| s.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default()
}

/// Whether the current cgroup scope is a non-threaded `domain` leaf (a threaded scope rejects
/// `cgroup.procs`). Reads the scope's `cgroup.type`; absent/unreadable is treated as `domain` (the
/// unified-hierarchy default) so a host that simply does not expose the file is not falsely degraded.
fn probe_domain_leaf() -> bool {
    let base = current_cgroup_base();
    let path = match &base {
        Some(b) => format!("/sys/fs/cgroup/{b}/cgroup.type"),
        None => "/sys/fs/cgroup/cgroup.type".to_string(),
    };
    match std::fs::read_to_string(path) {
        Ok(t) => t.trim() == "domain",
        // No `cgroup.type` (e.g. the root, or a v1/hybrid host) → assume the default `domain`.
        Err(_) => true,
    }
}

/// The current cgroup base path (relative to the v2 root), via the crate's one canonical
/// `/proc/self/cgroup` parser so this descriptor and the metrics sibling-placement agree (F2).
fn current_cgroup_base() -> Option<String> {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    crate::metrics::cgroup_base_from_proc(&cgroup)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controllers(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    // Delta 8 gate (§18): a probe on a **fake-host** descriptor drives the mode-selection and
    // fail-loud decisions — the single source of truth per-op checks read. RED on the inverse (a
    // decision that ignores a field: e.g. reporting a memory limit enforceable on an undelegated or
    // threaded scope, which is the silent-unlimited no-op §7.2 exists to prevent).
    #[test]
    fn descriptor_drives_mode_selection_and_fail_loud() {
        let full = HostCapabilities {
            cap_net_admin: true,
            cap_sys_admin: true,
            kvm_accessible: true,
            netns_reachable: true,
            delegated_controllers: controllers(&["memory", "cpu", "io", "pids"]),
            domain_leaf: true,
        };
        assert!(
            full.privileged_net_available(),
            "full host runs the privileged datapath"
        );
        assert!(
            full.memory_limit_enforceable(),
            "delegated memory + domain leaf → enforceable"
        );
        assert!(
            full.controller_enforceable("io"),
            "delegated io → enforceable"
        );
        assert!(full.virtio_fs_shares_available());
        assert!(full.can_boot_vm());

        // No CAP_NET_ADMIN → mode selection must NOT pick the privileged path (falls to smoltcp NAT).
        let no_net_admin = HostCapabilities {
            cap_net_admin: false,
            ..full.clone()
        };
        assert!(
            !no_net_admin.privileged_net_available(),
            "no CAP_NET_ADMIN → unprivileged NAT, not the privileged tap path"
        );

        // Undelegated memory → a requested memory limit is UNENFORCEABLE and must fail loud, never
        // silently run the guest unlimited (§7.2 rule 2).
        let no_mem = HostCapabilities {
            delegated_controllers: controllers(&["cpu", "pids"]),
            ..full.clone()
        };
        assert!(
            !no_mem.memory_limit_enforceable(),
            "undelegated memory controller → fail loud, not silent unlimited"
        );
        assert!(
            no_mem.controller_enforceable("cpu"),
            "cpu is still delegated"
        );

        // A threaded (non-`domain`) scope rejects `cgroup.procs` regardless of delegated controllers.
        let threaded = HostCapabilities {
            domain_leaf: false,
            ..full.clone()
        };
        assert!(
            !threaded.memory_limit_enforceable(),
            "a threaded scope cannot enforce any limit even with memory delegated"
        );

        // No KVM → the box cannot boot a VM at all.
        let no_kvm = HostCapabilities {
            kvm_accessible: false,
            ..full
        };
        assert!(!no_kvm.can_boot_vm(), "no /dev/kvm → static-only");
    }
}
