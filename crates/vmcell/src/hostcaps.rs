//! The one-probe host-capability descriptor (`HostCapabilities`), design §7.2 (The fail-loud capability contract and HostCapabilities) rule 1 / §18 (Delta register: changes from the validated v27 build) delta 8.
//!
//! An earlier stance — "unprivileged delegation degrades gracefully" — invited **silent no-ops**: a
//! caller asks for a 256 MiB cap, the controller isn't delegated, the write fails, and the VM runs
//! *unlimited* while the call returns `Ok`. The rule is reversed: a missing capability fails loud
//! unless the op is explicitly best-effort (law F1). To make "what does this host support?" have
//! **one** answer and **one** probe, [`HostCapabilities`] records the effective capability set,
//! KVM-group access, `/var/run/netns` reachability, which cgroup controllers the current scope
//! delegates, and whether the scope is a non-threaded `domain` leaf. As built (§18 delta 8, Delta
//! register: changes from the validated v27 build), the descriptor is **probed once at start-up and
//! logged** as a visible boot-time capability signal; per-op enforcement keeps its own authoritative
//! fail-loud per-write check (`metrics::try_apply_limit_at` / `classify_limit_write_err`), so the
//! descriptor is the queryable single source, not a replacement for that per-write typed error (see
//! docs/implementation-notes.md, Delta 8).
//!
//! The as-built production consumers are exactly three (`hostcaps-consumer-roster-overstated`; the
//! §7.2 sentence "mode selection, the daemon's main, and the test harness" overstates them — there
//! is no mode-selection and no test-harness caller):
//!
//! 1. [`crate::net::segment::NetSegment::new`] — the fail-loud
//!    [`HostCapabilities::privileged_net_available`] gate for vm-to-vm segments (§6.5).
//! 2. `vmcell_daemon::launcher::MicroVmLauncher::new` — the boot-time capability log (§11.2).
//! 3. `vmcell-bench`'s `bench-vm` net-egress leg — the privileged-variant self-skip (M-BIN-1).

use std::collections::BTreeSet;

/// `CAP_NET_ADMIN` — the capability the privileged tap/netns datapath needs (§6.1, The two operating modes). Bit index in the
/// `/proc/self/status` `CapEff` mask.
const CAP_NET_ADMIN: u32 = 12;
/// `CAP_SYS_ADMIN` — the capability `virtiofsd` needs to enter its mount namespace for a data share
/// (§4.5, Shared directories (virtio-fs)).
const CAP_SYS_ADMIN: u32 = 21;

/// A single-probe snapshot of what the host actually offers, probed once at start-up and logged as a
/// boot-time capability signal (design §7.2 rule 1, The fail-loud capability contract and HostCapabilities; §18 delta 8, Delta register: changes from the validated v27 build). Per-op enforcement keeps its own authoritative fail-loud per-write check; this descriptor is the queryable single source, not a replacement for it.
///
/// Build one at start-up with [`HostCapabilities::probe`]; tests construct a fake-host descriptor
/// directly (every field is `pub`) and assert that it drives the mode-selection and fail-loud
/// decisions the accessor methods encode.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct HostCapabilities {
    /// Effective `CAP_NET_ADMIN` — required for the privileged tap + netns network path (§6.1, The two operating modes).
    pub cap_net_admin: bool,
    /// Effective `CAP_SYS_ADMIN` — required for `virtiofsd`'s mount namespace, so virtio-fs data
    /// shares can mount (§4.5, Shared directories (virtio-fs)).
    pub cap_sys_admin: bool,
    /// `/dev/kvm` is present and openable read-write — the hard precondition for booting any VM.
    pub kvm_accessible: bool,
    /// The `/var/run/netns` bind-mount directory is reachable — the privileged datapath keeps its
    /// per-VM namespaces there (§6.1, The two operating modes).
    pub netns_reachable: bool,
    /// The cgroup-v2 controllers the current scope delegates into its subtree (§7.3, cgroup delegation mechanics). A *requested*
    /// limit needing an absent controller must fail loud (§7.2 rule 2, The fail-loud capability contract and HostCapabilities), never run unlimited.
    pub delegated_controllers: BTreeSet<String>,
    /// The current cgroup scope is a non-threaded `domain` leaf. A threaded scope rejects
    /// `cgroup.procs` regardless of `CAP_SYS_ADMIN`, so no per-VM slice can hold the VMM (§7.3, cgroup delegation mechanics).
    pub domain_leaf: bool,
}

impl HostCapabilities {
    /// Probes the host **once**, reading `/proc/self/status`, `/dev/kvm`, `/var/run/netns`, and the
    /// current cgroup scope's `cgroup.subtree_control` / `cgroup.type`. Every field is a best-effort
    /// read that resolves to the conservative value (`false` / empty) when the source is unreadable,
    /// so an unknown host is treated as *un*-provisioned rather than optimistically capable.
    #[must_use]
    pub fn probe() -> Self {
        let cgroups = CgroupSysfs::system();
        Self {
            cap_net_admin: has_effective_cap(CAP_NET_ADMIN),
            cap_sys_admin: has_effective_cap(CAP_SYS_ADMIN),
            kvm_accessible: kvm_accessible(),
            netns_reachable: netns_reachable(),
            delegated_controllers: cgroups.delegated_controllers(),
            domain_leaf: cgroups.domain_leaf(),
        }
    }

    /// Whether the **privileged** (tap + netns) networking datapath is available (§6.1, The two operating modes): effective
    /// `CAP_NET_ADMIN` **and** effective `CAP_SYS_ADMIN` **and** a reachable netns directory. Mode
    /// selection falls back to the unprivileged smoltcp NAT when this is `false` — the decision that
    /// keeps the box usable without root.
    ///
    /// `CAP_SYS_ADMIN` is a conjunct because *creating* and *entering* a network namespace is
    /// gated on it, not on `CAP_NET_ADMIN`: `unshare(CLONE_NEWNET)`, the `/var/run/netns` bind
    /// mount, and `setns(CLONE_NEWNET)` all require it. Without it a `CAP_NET_ADMIN`-only host got
    /// an untyped `Error::Network` out of `netns_rs` instead of the typed
    /// [`Error::CapabilityUnavailable`](crate::error::Error::CapabilityUnavailable) this predicate
    /// exists to produce (`privileged-net-available-omits-sys-admin`). `CAP_DAC_OVERRIDE` — the
    /// third member of `vmcell_privilege::PRIVILEGED_CAPS` — is not probed here: this descriptor
    /// carries only the two capability fields, and the two shipped privileged entry points check
    /// all three through `ensure_blessed_or_explain`.
    #[must_use]
    pub fn privileged_net_available(&self) -> bool {
        self.cap_net_admin && self.cap_sys_admin && self.netns_reachable
    }

    /// Whether a *requested* limit for `controller` (`"memory"`/`"cpu"`/`"io"`/`"pids"`) can be
    /// enforced: the scope is a non-threaded `domain` leaf **and** delegates that controller (§7.3, cgroup delegation mechanics).
    /// A requested limit on a host where this is `false` must fail loud with
    /// [`Error::CapabilityUnavailable`](crate::error::Error::CapabilityUnavailable) (§7.2 rule 2, The fail-loud capability contract and HostCapabilities),
    /// never silently run unlimited.
    #[must_use]
    pub fn controller_enforceable(&self, controller: &str) -> bool {
        self.domain_leaf && self.delegated_controllers.contains(controller)
    }

    /// Whether a *requested* **memory** limit can be enforced (the binding cap for guest RAM, §7.3, cgroup delegation mechanics).
    #[must_use]
    pub fn memory_limit_enforceable(&self) -> bool {
        self.controller_enforceable("memory")
    }

    /// Whether virtio-fs data shares can mount (`virtiofsd` needs `CAP_SYS_ADMIN` for its mount
    /// namespace, §4.5, Shared directories (virtio-fs)).
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
/// `CapEff:` — the §13-consistent gate (Cross-cutting invariants): the capability runner grants caps ambiently without a
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
/// per-VM network namespaces there). `iproute2` creates it on demand, so its *parent* (`/run`, or
/// `/var/run` when that is not a symlink to `/run`) **existing as a directory** is the conservative
/// reachability signal — this does not probe writability (a `W_OK` check would false-negatively
/// under-report on unprivileged-but-blessed hosts whose privileged datapath still sets up the netns).
fn netns_reachable() -> bool {
    // `/var/run` is conventionally a symlink to `/run`; either being a directory is the reachability
    // signal (existence, not a writability probe — see the doc-comment).
    std::path::Path::new("/run").is_dir() || std::path::Path::new("/var/run").is_dir()
}

/// The cgroup-v2 sysfs tree the cgroup half of the probe reads, with an **injectable root** so
/// `delegated_controllers` / `domain_leaf` are unit-testable against a synthetic tree
/// (`hostcaps-probe-body-untested`). This is the crate's existing seam idiom —
/// [`crate::cpufreq::SysfsCpuFreq::with_root`] — not a second one; the cgroup read needs a second
/// coordinate (the scope base under the root), so [`CgroupSysfs::with_root`] carries it explicitly
/// rather than growing a builder.
///
/// The other half of the probe (`CapEff` / `/dev/kvm` / netns) has no seam and does not need one:
/// it is live-covered by `tests/segment.rs`, whose `require_privileged_net` guard parses `CapEff`
/// **independently** and must agree with `NetSegment::new`'s `privileged_net_available()` gate —
/// a disagreement either way (skip-then-run, or run-then-refuse) reddens the suite.
#[derive(Debug, Clone)]
struct CgroupSysfs {
    root: std::path::PathBuf,
    /// The current scope's path relative to `root`, `None` when `/proc/self/cgroup` has no usable
    /// unified entry (the reads then fall back to the root's own control files).
    base: Option<String>,
}

impl CgroupSysfs {
    /// The live tree: the real `/sys/fs/cgroup` at the scope the canonical `/proc/self/cgroup`
    /// parser reports.
    fn system() -> Self {
        Self {
            root: std::path::PathBuf::from("/sys/fs/cgroup"),
            base: current_cgroup_base(),
        }
    }

    /// A tree rooted at `root` with scope `base`, for testing the reads against a synthetic sysfs
    /// tree. `#[cfg(test)]` so the seam constructor ships in no build but the test one (the
    /// `AgentClient::from_stream_for_tests` precedent) — production has exactly one tree,
    /// [`CgroupSysfs::system`].
    #[cfg(test)]
    fn with_root(root: impl Into<std::path::PathBuf>, base: Option<String>) -> Self {
        Self {
            root: root.into(),
            base,
        }
    }

    /// The path of control file `file` in the current scope.
    fn scope_file(&self, file: &str) -> std::path::PathBuf {
        match &self.base {
            Some(b) => self.root.join(b).join(file),
            None => self.root.join(file),
        }
    }

    /// The cgroup-v2 controllers delegated into this scope's subtree, read from the scope's
    /// `cgroup.subtree_control`. Whole tokens only: the `+memory` *write* form is not the effective
    /// form, so a tree holding it reports no `memory` delegation (matching the whole-token
    /// `metrics::controller_listed` law the per-write check enforces). An absent/unreadable file is
    /// the conservative empty set.
    fn delegated_controllers(&self) -> BTreeSet<String> {
        std::fs::read_to_string(self.scope_file("cgroup.subtree_control"))
            .map(|s| s.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default()
    }

    /// Whether this scope is a non-threaded `domain` leaf (a threaded scope rejects
    /// `cgroup.procs`). Reads the scope's `cgroup.type`; absent/unreadable is treated as `domain`
    /// (the unified-hierarchy default) so a host that simply does not expose the file is not
    /// falsely degraded.
    fn domain_leaf(&self) -> bool {
        match std::fs::read_to_string(self.scope_file("cgroup.type")) {
            Ok(t) => t.trim() == "domain",
            // No `cgroup.type` (e.g. the root, or a v1/hybrid host) → assume the default `domain`.
            Err(_) => true,
        }
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

    // Delta 8 gate (§18, Delta register: changes from the validated v27 build): a probe on a **fake-host** descriptor drives the mode-selection and
    // fail-loud decisions — the single source of truth per-op checks read. RED on the inverse (a
    // decision that ignores a field: e.g. reporting a memory limit enforceable on an undelegated or
    // threaded scope, which is the silent-unlimited no-op §7.2 (The fail-loud capability contract and HostCapabilities) exists to prevent).
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

        // `privileged-net-available-omits-sys-admin`: creating and entering a netns is gated on
        // CAP_SYS_ADMIN, so a NET_ADMIN-only host must be refused **here**, with the typed
        // `CapabilityUnavailable`, rather than failing later as an untyped `Error::Network` from
        // inside `netns_rs`. RED on the inverse (`cap_net_admin && netns_reachable`), which reports
        // the privileged datapath available on a host that cannot create a namespace at all.
        let no_sys_admin = HostCapabilities {
            cap_sys_admin: false,
            ..full.clone()
        };
        assert!(
            !no_sys_admin.privileged_net_available(),
            "no CAP_SYS_ADMIN → no netns creation/entry, so the privileged datapath is unavailable"
        );
        // …and the netns directory stays a conjunct of its own (neither cap substitutes for it).
        let no_netns_dir = HostCapabilities {
            netns_reachable: false,
            ..full.clone()
        };
        assert!(
            !no_netns_dir.privileged_net_available(),
            "no /var/run/netns → the privileged datapath has nowhere to keep its namespaces"
        );

        // Undelegated memory → a requested memory limit is UNENFORCEABLE and must fail loud, never
        // silently run the guest unlimited (§7.2 rule 2, The fail-loud capability contract and HostCapabilities).
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

    /// Writes `contents` to `dir/name`, creating the parent scope directory.
    fn seed(dir: &std::path::Path, name: &str, contents: &str) {
        if let Some(parent) = dir.join(name).parent() {
            std::fs::create_dir_all(parent).expect("create synthetic scope dir");
        }
        std::fs::write(dir.join(name), contents).expect("seed synthetic control file");
    }

    // `hostcaps-probe-body-untested` (docs/78 §7): the cgroup half of the probe body — the half the
    // segment suite's live coverage does NOT reach — read against a synthetic sysfs tree through
    // the injected root. Covers the present arm (including the scope base join, so a probe that
    // ignored `base` and read the tree root would go red) and the absent-facility arm.
    #[test]
    fn cgroup_probe_reads_scope_control_files_under_injected_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        // The scope's OWN files (delegated: cpu+memory, non-threaded) …
        seed(
            dir.path(),
            "user.slice/scope/cgroup.subtree_control",
            "cpu memory\n",
        );
        seed(dir.path(), "user.slice/scope/cgroup.type", "domain\n");
        // … and decoy root files that must NOT be read when a base is set.
        seed(dir.path(), "cgroup.subtree_control", "io pids");
        seed(dir.path(), "cgroup.type", "threaded");

        let probe = CgroupSysfs::with_root(dir.path(), Some("user.slice/scope".to_string()));
        assert_eq!(
            probe.delegated_controllers(),
            controllers(&["cpu", "memory"]),
            "the SCOPE's subtree_control is the delegation source, not the tree root's"
        );
        assert!(
            probe.domain_leaf(),
            "a `domain` scope is a usable non-threaded leaf"
        );

        // Absent facility: a scope with no control files at all (a v1/hybrid host, or a root that
        // exposes neither) delegates nothing and keeps the `domain` default rather than being
        // falsely degraded to "threaded".
        let bare = CgroupSysfs::with_root(dir.path(), Some("no/such/scope".to_string()));
        assert!(
            bare.delegated_controllers().is_empty(),
            "an unreadable subtree_control is the conservative empty set"
        );
        assert!(
            bare.domain_leaf(),
            "an absent cgroup.type is the unified-hierarchy `domain` default"
        );

        // No base (`/proc/self/cgroup` had no usable unified entry) reads the tree root's files —
        // the fallback the `None` arm exists for.
        let rooted = CgroupSysfs::with_root(dir.path(), None);
        assert_eq!(rooted.delegated_controllers(), controllers(&["io", "pids"]));
        assert!(
            !rooted.domain_leaf(),
            "a `threaded` scope cannot hold the VMM's cgroup.procs write"
        );
    }

    // The malformed/edge content arms of the same two reads. Each goes red on the sloppy
    // implementation it names.
    #[test]
    fn cgroup_probe_rejects_malformed_control_file_contents() {
        let dir = tempfile::tempdir().expect("tempdir");

        // `+memory` is the WRITE form, not the effective delegation. Reporting it as a delegated
        // `memory` controller is the silent-unlimited no-op §7.2 exists to prevent, so the
        // whole-token set must not contain `memory` (red on a `contains("memory")` impl).
        seed(dir.path(), "cgroup.subtree_control", "+memory");
        let probe = CgroupSysfs::with_root(dir.path(), None);
        assert!(
            !probe.delegated_controllers().contains("memory"),
            "the `+memory` write form is not an effective delegation"
        );
        assert_eq!(probe.delegated_controllers(), controllers(&["+memory"]));

        // An empty file is empty delegation, not a parse that yields an empty-string controller.
        seed(dir.path(), "cgroup.subtree_control", "\n  \n");
        assert!(probe.delegated_controllers().is_empty());

        // `cgroup.type` is compared on the TRIMMED whole value: `domain threaded` and
        // `domain invalid` are not the plain `domain` leaf (red on a `starts_with`/`contains` impl),
        // while the real kernel's trailing newline still reads as `domain` (red on an untrimmed
        // equality).
        for (contents, expected) in [
            ("domain\n", true),
            ("domain", true),
            ("  domain \n", true),
            ("threaded\n", false),
            ("domain threaded\n", false),
            ("domain invalid\n", false),
            ("", false),
        ] {
            seed(dir.path(), "cgroup.type", contents);
            assert_eq!(
                probe.domain_leaf(),
                expected,
                "cgroup.type {contents:?} → domain_leaf {expected}"
            );
        }
    }
}
