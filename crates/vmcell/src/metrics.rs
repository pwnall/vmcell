//! Resource usage tracking and metrics collection.

#![forbid(unsafe_code)]

use crate::error::Result;

/// Resource usage statistics for a VM instance.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResourceUsage {
    /// Peak memory usage in MiB.
    pub mem_peak_mib: u64,
    /// Current memory usage in MiB.
    pub mem_current_mib: u64,
    /// CPU usage in microseconds.
    pub cpu_usec: u64,
    /// Bytes read from disk/block devices.
    pub io_read_bytes: u64,
    /// Bytes written to disk/block devices.
    pub io_write_bytes: u64,
    /// Whether the `memory` controller is delegated into this cgroup — the honest
    /// proxy for "the hard memory cap took effect", **not** a guarantee that every
    /// requested limit (cpu/pids/io) is enforced (M-HOST-5). Renamed from the former
    /// `limits_enforced` (design §18, Delta register: changes from the validated v27
    /// build, delta 3): the old name over-claimed a
    /// whole-`ResourceLimits` guarantee, but a read that holds only the cgroup *name*
    /// cannot know which controllers were requested, so it reports the **one** — the
    /// memory controller — whose silent absence lets the memory cap not fire; a caller
    /// needing per-controller enforcement must consult the individual control files.
    ///
    /// `true` only when the `memory` controller is delegated into this cgroup
    /// (`cgroup.controllers` lists it), meaning the limit writes took effect.
    /// `false` when no controller is delegated — reads then fall back to bare
    /// sysfs values and the caller must not assume enforcement (§7.2, The fail-loud
    /// capability contract and HostCapabilities, rule 3).
    /// A `ResourceUsage::default()` (no cgroup attached) is honestly `false`.
    ///
    /// Network byte counters are intentionally absent: cgroup v2 has no network
    /// accounting and the read path holds only the cgroup name, not the VM's
    /// netns/interface handle, so an always-zero `net_*` field would be a lie
    /// (§7.1, What is read and enforced / rubric B8). See the "Net counters omitted
    /// from `ResourceUsage`"
    /// deviation in `docs/implementation-notes.md`.
    pub mem_limit_enforced: bool,
    /// Whether the memory counters (`mem_current_mib`, `mem_peak_mib`) were read
    /// and parsed successfully (§7.1, What is read and enforced, rule 3: an unread
    /// counter is the same lie as a missing one). `false` when
    /// `memory.current`/`memory.peak` are absent or fail
    /// to parse, so the caller can tell a real `0` from an unreadable counter. A
    /// `ResourceUsage::default()` is honestly `false`.
    pub mem_read_ok: bool,
    /// Whether the CPU counter (`cpu_usec`) was read and parsed successfully.
    /// `false` when `cpu.stat` is absent or lacks a parseable `usage_usec` line,
    /// distinguishing a real `0` from an unreadable counter (§7.1, What is read and
    /// enforced, rule 3). A `ResourceUsage::default()` is honestly `false`.
    pub cpu_read_ok: bool,
    /// Whether the I/O byte counters (`io_read_bytes`, `io_write_bytes`) were read
    /// successfully. `false` when `io.stat` is absent, distinguishing a real `0`
    /// from an unreadable counter (§7.1, What is read and enforced, rule 3). A
    /// `ResourceUsage::default()` is honestly `false`.
    pub io_read_ok: bool,
}

/// Interface for managing cgroups.
pub trait CgroupFs: Send + Sync + std::fmt::Debug {
    /// Creates a cgroup slice with the given limits.
    ///
    /// # Errors
    /// Returns an error if the slice cannot be created or limits applied.
    fn create_slice(&self, name: &str, limits: &crate::config::ResourceLimits) -> Result<()>;
    /// Deletes a cgroup slice.
    ///
    /// # Errors
    /// Returns an error if the slice cannot be deleted.
    fn delete_slice(&self, name: &str) -> Result<()>;
    /// Reads resource usage statistics from a given cgroup.
    ///
    /// # Errors
    /// Returns an error if reading the stats fails.
    fn read_stats(&self, name: &str) -> Result<ResourceUsage>;
    /// Adds a task (process ID) to the cgroup.
    ///
    /// # Errors
    /// Returns an error if adding the task fails.
    fn add_task(&self, name: &str, pid: u32) -> Result<()>;
}

/// Parses `/proc/self/cgroup` contents into the base (unified, v2) cgroup path the
/// per-VM slice is created *under*, stripping the supervisor's own `/supervisor`
/// leaf so the VM slice becomes a **sibling** of the supervisor, not a child
/// (§13, Cross-cutting invariants, "no internal processes"). Returns `None` when
/// there is no `0::` unified
/// entry or the resulting base is empty.
///
/// This is the single home for the derivation (AGENTS.md: "cgroup logic lives in
/// `metrics.rs`"), consumed by the orchestrator and mirrored in the tests
/// (M-ORCH-4/H-HOST-3). It parses **line-by-line** so a hybrid v1/v2 hierarchy —
/// where the `0::` line is not the whole file — cannot fold trailing lines into
/// the path, and it strips `/supervisor` **exactly once** (`strip_suffix`, not the
/// repeat-stripping `trim_end_matches`).
#[must_use]
pub fn cgroup_base_from_proc(contents: &str) -> Option<String> {
    let path = contents
        .lines()
        .find_map(|line| line.strip_prefix("0::"))?
        .trim_start_matches('/');
    let base = path.strip_suffix("/supervisor").unwrap_or(path);
    if base.is_empty() {
        None
    } else {
        Some(base.to_string())
    }
}

/// Computes the cgroup-v2 `cpu.max` `(quota, period)` pair for a CPU cap expressed
/// as a percentage of one core. The period is fixed at 100000us and the quota is the
/// matching slice of that period (e.g. 50% -> `(50000, 100000)`, 200% -> `(200000, 100000)`).
fn cpu_quota_period(cpu_max_pct: u32) -> (i64, u64) {
    let period = 100_000_u64;
    let quota = u64::from(cpu_max_pct) * period / 100;
    (quota as i64, period)
}

/// Converts a memory cap in MiB to the byte value written to `memory.max`
/// (`memory_hard_limit`). MiB is `<< 20`, not the SI `1_000_000`.
fn mem_hard_limit_bytes(mem_max_mib: u32) -> i64 {
    i64::from(mem_max_mib) << 20
}

/// Renders the exact `io.max` control-file contents for the given limits, or `None`
/// when no rate rule is set (so the caller skips the write). Format:
/// `<device> rbps=.. wbps=.. riops=.. wiops=..\n`, emitting only the present fields
/// in that fixed order.
fn render_io_max(io: &crate::config::IoMax) -> Option<String> {
    let mut rules = Vec::new();
    if let Some(rbps) = io.rbps {
        rules.push(format!("rbps={rbps}"));
    }
    if let Some(wbps) = io.wbps {
        rules.push(format!("wbps={wbps}"));
    }
    if let Some(riops) = io.riops {
        rules.push(format!("riops={riops}"));
    }
    if let Some(wiops) = io.wiops {
        rules.push(format!("wiops={wiops}"));
    }
    if rules.is_empty() {
        None
    } else {
        Some(format!("{} {}\n", io.device, rules.join(" ")))
    }
}

/// Renders the exact `pids.max` control-file contents (a bare decimal count).
fn render_pids_max(pids_max: u32) -> String {
    pids_max.to_string()
}

/// Returns whether `controller` appears as a whole space-separated token in a
/// cgroup-v2 controller listing (`cgroup.controllers` or `cgroup.subtree_control`).
/// A whole-token match — never a substring — so `memory` does not match `memoryx`.
fn controller_listed(listing: &str, controller: &str) -> bool {
    listing.split_whitespace().any(|c| c == controller)
}

/// Classifies a failed limit-write into a typed error, distinguishing a rejected
/// limit *value* from a missing host capability. `EINVAL` means the kernel refused
/// the value itself (e.g. a `cpu.max` quota below the kernel's µs floor, or a
/// malformed `io.max` device) — a caller bug that must surface as
/// [`crate::error::Error::Cgroup`] so its remediation is "fix the limit", not
/// "enable delegation". Every other errno (`EACCES`/`EPERM`/`EROFS`, or anything
/// unexpected) is treated as the §7.2 (The fail-loud capability contract and
/// HostCapabilities) capability/permission failure and stays
/// [`crate::error::Error::CapabilityUnavailable`]. Kept pure so the errno split is
/// unit-testable without provoking a real `EINVAL` from the filesystem (M-HOST-4).
fn classify_limit_write_err(
    file: &str,
    path: &str,
    controller: &str,
    value: &str,
    e: &std::io::Error,
) -> crate::error::Error {
    use crate::error::Error;
    if e.raw_os_error() == Some(libc::EINVAL) {
        Error::Cgroup(format!(
            "invalid limit value {value:?} for {path} ('{controller}' controller): {e}"
        ))
    } else {
        Error::CapabilityUnavailable {
            op: format!("cgroup {file} limit"),
            needed: format!("writable {path} for the '{controller}' controller ({e})"),
        }
    }
}

/// Applies a single *requested functional* cgroup limit under `cgroup_root`, failing
/// loud per the §7.2 (The fail-loud capability contract and HostCapabilities): confirm
/// `controller` is delegated on the
/// parent's `subtree_control` (enabling it there first if absent), then write `value`.
/// A requested limit that cannot be enforced — because the controller is not
/// delegated, or the control file rejects the write — returns
/// [`crate::error::Error::CapabilityUnavailable`] rather than logging a warning and
/// skipping it (which would hand back a VM running unbounded). This is *not*
/// best-effort; only the explicitly-listed §7.2 (The fail-loud capability contract and
/// HostCapabilities) benchmark knobs (cpufreq/KSM) may
/// degrade with a `warn!`.
///
/// `cgroup_root` is injected (default `/sys/fs/cgroup`) so the write path is
/// unit-testable against a temp directory. The delegation read-back runs for
/// parent-less slice names too (CFG-2): a top-level `vmcell-vm-{vmid}` slice's
/// controllers are delegated by the cgroup *root*'s `subtree_control`, so an empty
/// parent maps to `{cgroup_root}/cgroup.subtree_control` rather than skipping the check
/// and relying solely on the final write-failure backstop.
///
/// # Errors
/// Returns [`crate::error::Error::CapabilityUnavailable`] when the controller is not
/// delegated to the parent's `subtree_control`, or when the limit write fails for a
/// capability/permission reason (`EACCES`/`EPERM`/`EROFS`). A write the kernel
/// rejects for a bad limit *value* (`EINVAL`) returns
/// [`crate::error::Error::Cgroup`] instead (M-HOST-4).
fn try_apply_limit_at(
    cgroup_root: &str,
    name: &str,
    controller: &str,
    file: &str,
    value: &str,
) -> Result<()> {
    use crate::error::Error;
    if let Some(parent) = std::path::Path::new(name).parent() {
        let parent = parent.to_string_lossy();
        // CFG-2: an empty parent (a parent-less `vmcell-vm-{vmid}` fallback name) is
        // delegated by the cgroup root's own `subtree_control`; check it rather than
        // skip the read-back and lean solely on the write-failure backstop below.
        let subtree = if parent.is_empty() {
            format!("{cgroup_root}/cgroup.subtree_control")
        } else {
            format!("{cgroup_root}/{parent}/cgroup.subtree_control")
        };
        // Enable the controller on the parent's subtree_control only if it is not
        // already delegated. A constrained/non-delegated layout silently ignores the
        // `+controller` write, so we never trust the write — we read the effective set
        // back and require a whole-token match.
        let already_delegated = std::fs::read_to_string(&subtree)
            .map(|s| controller_listed(&s, controller))
            .unwrap_or(false);
        if !already_delegated {
            let _ = std::fs::write(&subtree, format!("+{controller}"));
        }
        let delegated = std::fs::read_to_string(&subtree)
            .map(|s| controller_listed(&s, controller))
            .unwrap_or(false);
        if !delegated {
            return Err(Error::CapabilityUnavailable {
                op: format!("cgroup {file} limit"),
                needed: format!("'{controller}' controller delegated to {subtree}"),
            });
        }
    }
    let path = format!("{cgroup_root}/{name}/{file}");
    std::fs::write(&path, value)
        .map_err(|e| classify_limit_write_err(file, &path, controller, value, &e))
}

/// Sums the `rbytes`/`wbytes` counters across every device line of a cgroup-v2
/// `io.stat` file, returning `(read_bytes, write_bytes)`. A device with no counters
/// (or an empty file) contributes nothing.
fn parse_io_stat_bytes(contents: &str) -> (u64, u64) {
    let mut read_bytes = 0u64;
    let mut write_bytes = 0u64;
    for line in contents.lines() {
        for field in line.split_whitespace() {
            if let Some(v) = field
                .strip_prefix("rbytes=")
                .and_then(|s| s.parse::<u64>().ok())
            {
                read_bytes = read_bytes.saturating_add(v);
            } else if let Some(v) = field
                .strip_prefix("wbytes=")
                .and_then(|s| s.parse::<u64>().ok())
            {
                write_bytes = write_bytes.saturating_add(v);
            }
        }
    }
    (read_bytes, write_bytes)
}

/// Extracts the `usage_usec` value from a cgroup-v2 `cpu.stat` file, if present.
fn parse_cpu_usage_usec(contents: &str) -> Option<u64> {
    contents.lines().find_map(|line| {
        line.strip_prefix("usage_usec ")
            .and_then(|s| s.trim().parse::<u64>().ok())
    })
}

/// Reads a [`ResourceUsage`] snapshot from a cgroup-v2 directory at `base_path`,
/// surfacing per-metric availability so the caller can tell a real `0` from an
/// unreadable counter (§7.1, What is read and enforced, rule 3: "an unread counter is the same lie as a missing
/// one"). Reads are best-effort: an absent or unparseable control file leaves the
/// corresponding value at `0` and its `*_read_ok` flag `false`. Factored out of
/// [`DefaultCgroupFs::read_stats`] so the availability contract is unit-testable
/// against a temp cgroup-like directory without writing to `/sys`.
fn read_stats_at(base_path: &str) -> ResourceUsage {
    let mut usage = ResourceUsage::default();

    // Memory: read directly from sysfs and unconditionally (METRICS-FS-3). The
    // previous implementation gated this on cgroups-rs reporting a Mem subsystem,
    // which silently returned 0 in the very constrained/delegated case it claimed
    // to handle. Only a genuinely absent control file now falls through to 0, and
    // `mem_read_ok` then stays `false` so the caller never mistakes it for a real 0.
    let mut mem_current_ok = false;
    if let Ok(s) = std::fs::read_to_string(format!("{base_path}/memory.current"))
        && let Ok(val) = s.trim().parse::<u64>()
    {
        usage.mem_current_mib = val / 1024 / 1024;
        mem_current_ok = true;
    }
    let mut mem_peak_ok = false;
    if let Ok(s) = std::fs::read_to_string(format!("{base_path}/memory.peak"))
        && let Ok(val) = s.trim().parse::<u64>()
    {
        usage.mem_peak_mib = val / 1024 / 1024;
        mem_peak_ok = true;
    }
    // Both memory counters must read for the memory metrics to be trustworthy.
    usage.mem_read_ok = mem_current_ok && mem_peak_ok;

    // I/O byte counters: sum rbytes/wbytes over every device line of io.stat
    // (METRICS-FS-1). These fields were previously never populated. `io_read_ok`
    // is `false` when `io.stat` is absent (an empty/counter-less file is a valid 0).
    if let Ok(s) = std::fs::read_to_string(format!("{base_path}/io.stat")) {
        let (read_bytes, write_bytes) = parse_io_stat_bytes(&s);
        usage.io_read_bytes = read_bytes;
        usage.io_write_bytes = write_bytes;
        usage.io_read_ok = true;
    }

    // CPU usage in microseconds: the `usage_usec` line of cpu.stat. `cpu_read_ok`
    // is `false` when the file is absent or has no parseable `usage_usec` line.
    if let Ok(s) = std::fs::read_to_string(format!("{base_path}/cpu.stat"))
        && let Some(val) = parse_cpu_usage_usec(&s)
    {
        usage.cpu_usec = val;
        usage.cpu_read_ok = true;
    }

    // mem_limit_enforced (§7.1, What is read and enforced, rule 3): the memory controller is delegated into this
    // cgroup iff it is listed in `cgroup.controllers`. When it is absent the limit
    // writes were rejected and the values above are bare sysfs fallbacks, so the
    // caller must not assume enforcement. Honestly `false` if the file is missing.
    let controllers_path = format!("{base_path}/cgroup.controllers");
    usage.mem_limit_enforced = std::fs::read_to_string(controllers_path)
        .map(|s| controller_listed(&s, "memory"))
        .unwrap_or(false);

    usage
}

/// Creates the per-VM cgroup directory under `cgroup_root` and applies every
/// requested functional limit. The limit-application block is deliberately **not**
/// gated on the `metrics` feature (CFG-1): it writes cgroup sysfs directly via
/// `std::fs` and pulls in no `metrics`-only dependency, so gating it silently dropped
/// every requested limit — returning `Ok(())` on an unbounded VM — in a
/// `--no-default-features --features cloud-hypervisor` build whose `create_slice`
/// caller (`orchestrator::setup_env`) is *not* gated on `metrics`. `cgroup_root` is
/// injected (default `/sys/fs/cgroup`) so the real write path is unit-testable against
/// a temp directory without touching the host cgroup tree.
///
/// # Errors
/// Returns [`crate::error::Error::Cgroup`] if the directory cannot be created, or
/// [`crate::error::Error::CapabilityUnavailable`] if a requested limit's controller is
/// not delegated or its control-file write fails.
fn create_slice_at(
    cgroup_root: &str,
    name: &str,
    limits: &crate::config::ResourceLimits,
) -> Result<()> {
    // Create the per-VM cgroup directly with `mkdir`. The previous implementation used
    // `cgroups-rs` `CgroupBuilder`, whose V2 path manipulates the parent's
    // `subtree_control` and leaves the new cgroup in a state that rejects
    // `cgroup.procs` writes (EOPNOTSUPP) under common systemd cgroup layouts; a plain
    // directory + direct limit writes is robust across layouts. (The cgroup must still
    // live in a non-threaded `domain` subtree — a threaded scope rejects `cgroup.procs`
    // regardless; see implementation-notes.)
    std::fs::create_dir_all(format!("{cgroup_root}/{name}"))
        .map_err(|e| crate::error::Error::Cgroup(format!("create cgroup {name}: {e}")))?;

    if let Some(mem) = limits.mem_max_mib {
        try_apply_limit_at(
            cgroup_root,
            name,
            "memory",
            "memory.max",
            &mem_hard_limit_bytes(mem).to_string(),
        )?;
        // E1: make the cap a HARD bound, not a throttle. Guest RAM can be
        // shmem/memfd-backed; under `memory.max` pressure cgroup v2 reclaims shmem to
        // swap instead of OOM-killing, so the cap never fires and the guest overruns
        // it. `memory.swap.max=0` removes the swap escape hatch (shmem stays charged,
        // the cap hard-kills) and `memory.oom.group=1` makes the kill take the whole VM
        // cgroup atomically. Both are part of the requested functional limit, so they
        // fail loud too.
        try_apply_limit_at(cgroup_root, name, "memory", "memory.swap.max", "0")?;
        try_apply_limit_at(cgroup_root, name, "memory", "memory.oom.group", "1")?;
    }
    if let Some(cpu) = limits.cpu_max_pct {
        let (quota, period) = cpu_quota_period(cpu);
        try_apply_limit_at(
            cgroup_root,
            name,
            "cpu",
            "cpu.max",
            &format!("{quota} {period}"),
        )?;
    }
    if let Some(pids) = limits.pids_max {
        try_apply_limit_at(
            cgroup_root,
            name,
            "pids",
            "pids.max",
            &render_pids_max(pids),
        )?;
    }
    if let Some(io) = &limits.io_max
        && let Some(io_str) = render_io_max(io)
    {
        try_apply_limit_at(cgroup_root, name, "io", "io.max", io_str.trim_end())?;
    }
    Ok(())
}

/// The default CgroupFs implementation.
#[derive(Debug, Default, Clone)]
pub struct DefaultCgroupFs;

impl CgroupFs for DefaultCgroupFs {
    fn create_slice(&self, name: &str, limits: &crate::config::ResourceLimits) -> Result<()> {
        create_slice_at("/sys/fs/cgroup", name, limits)
    }

    fn delete_slice(&self, name: &str) -> Result<()> {
        // Contracts self-guard (L-HOST-1): an empty name is a caller bug, not an
        // in-band "no-op" sentinel — fail loud instead of a silent `Ok`.
        if name.is_empty() {
            return Err(crate::error::Error::Cgroup(
                "cgroup name cannot be empty".to_string(),
            ));
        }
        // Best-effort rmdir of the (now-empty) per-VM cgroup. The owning VMM
        // process group is reaped before this runs, so the cgroup has no
        // remaining members. A failure (e.g. members still present) is a leak, so
        // surface it as a `warn!` rather than swallowing it invisibly (L-HOST-2);
        // deletion itself stays best-effort.
        if let Err(e) = std::fs::remove_dir(format!("/sys/fs/cgroup/{name}")) {
            tracing::warn!("failed to remove cgroup {}: {}", name, e);
        }
        Ok(())
    }

    fn read_stats(&self, name: &str) -> Result<ResourceUsage> {
        Ok(read_stats_at(&format!("/sys/fs/cgroup/{name}")))
    }

    fn add_task(&self, name: &str, pid: u32) -> Result<()> {
        // Contracts self-guard (L-HOST-1): reject an empty name instead of silently
        // succeeding on a caller bug (there is no valid empty-named cgroup).
        if name.is_empty() {
            return Err(crate::error::Error::Cgroup(
                "cgroup name cannot be empty".to_string(),
            ));
        }
        let procs_path = format!("/sys/fs/cgroup/{name}/cgroup.procs");
        // Write PID directly to bypass `Cgroup::add_task` limitations for nested unprivileged cgroups
        std::fs::write(&procs_path, pid.to_string()).map_err(|e| {
            crate::error::Error::Cgroup(format!(
                "Failed to add process {pid} to cgroup {name}: {e}"
            ))
        })?;
        tracing::info!("Added process {} to cgroup {}", pid, name);
        Ok(())
    }
}

/// A fake CgroupFs implementation for unit testing.
//
// METRICS-FS-4 note: this is a test-only fake. Its `.lock().unwrap()` calls keep
// `unwrap` deliberately — the mutex is exercised single-threaded within a test, so a
// poisoned guard would itself be a test bug we want to surface loudly. Production
// mutex callers (e.g. `fs::in_process`) recover from poison via `into_inner()`.
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct FakeCgroupFs {
    state: std::sync::Arc<std::sync::Mutex<FakeCgroupState>>,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct FakeCgroupState {
    pub slices: std::collections::HashMap<String, crate::config::ResourceLimits>,
    pub tasks: std::collections::HashMap<String, Vec<u32>>,
    /// Cgroup controllers modelled as delegated to the slice. A requested limit
    /// whose controller is absent here must fail loud (§7.2, The fail-loud capability
    /// contract and HostCapabilities), mirroring the real
    /// `DefaultCgroupFs` `subtree_control` check.
    pub delegated: std::collections::HashSet<String>,
}

#[cfg(test)]
impl Default for FakeCgroupFs {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl FakeCgroupFs {
    /// Creates a new fake cgroup filesystem with every controller delegated, so a
    /// well-configured host is the default and limit application succeeds.
    #[must_use]
    pub fn new() -> Self {
        let delegated = ["memory", "cpu", "pids", "io"]
            .iter()
            .map(|c| (*c).to_string())
            .collect();
        Self {
            state: std::sync::Arc::new(std::sync::Mutex::new(FakeCgroupState {
                delegated,
                ..FakeCgroupState::default()
            })),
        }
    }

    /// Models a controller that is **not** delegated into the slice, so a requested
    /// limit needing it must fail loud with
    /// [`crate::error::Error::CapabilityUnavailable`] instead of a silent `Ok`
    /// (§7.2, The fail-loud capability contract and HostCapabilities). Drives the
    /// fail-loud unit test.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn undelegate(&self, controller: &str) {
        self.state.lock().unwrap().delegated.remove(controller);
    }

    /// Checks if a slice exists.
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn has_slice(&self, name: &str) -> bool {
        self.state.lock().unwrap().slices.contains_key(name)
    }

    /// Gets limits for a slice.
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn get_limits(&self, name: &str) -> Option<crate::config::ResourceLimits> {
        self.state.lock().unwrap().slices.get(name).cloned()
    }

    /// Checks if a task is added.
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn has_task(&self, name: &str, pid: u32) -> bool {
        self.state
            .lock()
            .unwrap()
            .tasks
            .get(name)
            .map(|t| t.contains(&pid))
            .unwrap_or(false)
    }
}

#[cfg(test)]
impl CgroupFs for FakeCgroupFs {
    fn create_slice(&self, name: &str, limits: &crate::config::ResourceLimits) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        // Model the §7.2 (The fail-loud capability contract and HostCapabilities)
        // fail-loud contract: a requested limit whose controller is
        // not delegated cannot be enforced, so return CapabilityUnavailable and do
        // NOT record the slice as created (a silent `Ok` here is the exact bug).
        for (requested, controller, file) in [
            (limits.mem_max_mib.is_some(), "memory", "memory.max"),
            (limits.cpu_max_pct.is_some(), "cpu", "cpu.max"),
            (limits.pids_max.is_some(), "pids", "pids.max"),
            (limits.io_max.is_some(), "io", "io.max"),
        ] {
            if requested && !state.delegated.contains(controller) {
                return Err(crate::error::Error::CapabilityUnavailable {
                    op: format!("cgroup {file} limit"),
                    needed: format!("'{controller}' controller delegated to {name}"),
                });
            }
        }
        state.slices.insert(name.to_string(), limits.clone());
        Ok(())
    }

    fn delete_slice(&self, name: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.slices.remove(name);
        state.tasks.remove(name);
        Ok(())
    }

    fn read_stats(&self, _name: &str) -> Result<ResourceUsage> {
        // The fake models a delegated host with readable counters, so enforcement is
        // honestly reported true and every per-metric availability flag is true.
        Ok(ResourceUsage {
            mem_peak_mib: 42,
            mem_current_mib: 21,
            cpu_usec: 1000,
            io_read_bytes: 0,
            io_write_bytes: 0,
            mem_limit_enforced: true,
            mem_read_ok: true,
            cpu_read_ok: true,
            io_read_ok: true,
        })
    }

    fn add_task(&self, name: &str, pid: u32) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.tasks.entry(name.to_string()).or_default().push(pid);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResourceLimits;

    // M-ORCH-4/H-HOST-3: a hybrid v1/v2 `/proc/self/cgroup` where the `0::` line
    // is not last must yield only that line's path — the old `split("0::").nth(1)`
    // over the whole string folded the trailing lines into the base name.
    #[test]
    fn cgroup_base_parses_line_by_line_on_hybrid_hierarchy() {
        let hybrid = "12:pids:/system.slice\n0::/parent/supervisor\n5:cpu:/other";
        assert_eq!(cgroup_base_from_proc(hybrid).as_deref(), Some("parent"));
    }

    // M-ORCH-4: `/supervisor` is stripped EXACTLY once. The old `trim_end_matches`
    // stripped repeated suffixes, so `a/supervisor/supervisor` collapsed to `a`.
    #[test]
    fn cgroup_base_strips_supervisor_leaf_once() {
        assert_eq!(
            cgroup_base_from_proc("0::/a/supervisor/supervisor").as_deref(),
            Some("a/supervisor")
        );
        assert_eq!(
            cgroup_base_from_proc("0::/a/supervisor").as_deref(),
            Some("a")
        );
    }

    // An empty base or a missing unified entry yields `None` (the orchestrator then
    // falls back to a top-level `vmcell-vm-<vmid>` slice).
    #[test]
    fn cgroup_base_none_on_empty_or_missing() {
        assert_eq!(cgroup_base_from_proc("0::/"), None);
        assert_eq!(
            cgroup_base_from_proc("0::/supervisor").as_deref(),
            Some("supervisor")
        );
        assert_eq!(cgroup_base_from_proc("2:cpu:/only/v1/lines"), None);
        assert_eq!(cgroup_base_from_proc(""), None);
    }

    #[test]
    fn test_fake_cgroup_fs() {
        let fs = FakeCgroupFs::new();
        let name = "vmcell-vm-1";
        let limits = ResourceLimits {
            mem_max_mib: Some(128),
            cpu_max_pct: Some(50),
            pids_max: None,
            io_max: None,
        };

        fs.create_slice(name, &limits).unwrap();
        assert!(fs.has_slice(name));

        let stored_limits = fs.get_limits(name).unwrap();
        assert_eq!(stored_limits.mem_max_mib, Some(128));
        assert_eq!(stored_limits.cpu_max_pct, Some(50));

        fs.add_task(name, 1234).unwrap();
        assert!(fs.has_task(name, 1234));

        fs.delete_slice(name).unwrap();
        assert!(!fs.has_slice(name));
        assert!(!fs.has_task(name, 1234));
    }

    // METRICS-FS-1: guards against the regression where io.stat is never read (fields
    // permanently 0) and against summing only the first device or swapping read/write.
    #[test]
    fn test_parse_io_stat_sums_all_devices() {
        let sample = "8:0 rbytes=100 wbytes=200 rios=1 wios=2 dbytes=0 dios=0\n\
                      259:0 rbytes=50 wbytes=25 rios=3 wios=4 dbytes=0 dios=0\n";
        let (read_bytes, write_bytes) = parse_io_stat_bytes(sample);
        // An impl that read only the first line would yield (100, 200); a read/write
        // swap would yield (225, 150). Both are red against these exact totals.
        assert_eq!(read_bytes, 150);
        assert_eq!(write_bytes, 225);
    }

    #[test]
    fn test_parse_io_stat_empty_is_zero() {
        assert_eq!(parse_io_stat_bytes(""), (0, 0));
        assert_eq!(parse_io_stat_bytes("8:0 rios=1 wios=2\n"), (0, 0));
    }

    // Guards against parsing the wrong key (e.g. `user_usec`) for cpu_usec.
    #[test]
    fn test_parse_cpu_usage_usec_picks_usage_line() {
        let sample = "usage_usec 123456\nuser_usec 100000\nsystem_usec 23456\n";
        assert_eq!(parse_cpu_usage_usec(sample), Some(123_456));
        assert_eq!(parse_cpu_usage_usec("user_usec 5\n"), None);
        assert_eq!(parse_cpu_usage_usec(""), None);
    }

    // METRICS-FS-2: exact control-file rendering. Each assertion goes red on an
    // inverted formula or a mis-rendered rule string.
    #[test]
    fn test_cpu_quota_period_exact() {
        // Inverting the ratio (period * 100 / pct) would give (200_000, 100_000) for 50%.
        assert_eq!(cpu_quota_period(50), (50_000, 100_000));
        assert_eq!(cpu_quota_period(100), (100_000, 100_000));
        assert_eq!(cpu_quota_period(200), (200_000, 100_000));
    }

    #[test]
    fn test_mem_hard_limit_bytes_exact() {
        // Using SI MB (1_000_000) or the wrong shift would fail these.
        assert_eq!(mem_hard_limit_bytes(128), 128 * 1024 * 1024);
        assert_eq!(mem_hard_limit_bytes(1), 1_048_576);
    }

    #[test]
    fn test_render_io_max_exact() {
        let io = crate::config::IoMax {
            device: "8:0".to_string(),
            rbps: Some(1000),
            wbps: Some(2000),
            riops: None,
            wiops: Some(50),
        };
        // Exact bytes the kernel sees, in fixed order, omitting the unset riops field,
        // with a trailing newline.
        assert_eq!(
            render_io_max(&io).as_deref(),
            Some("8:0 rbps=1000 wbps=2000 wiops=50\n")
        );

        let empty = crate::config::IoMax {
            device: "8:0".to_string(),
            rbps: None,
            wbps: None,
            riops: None,
            wiops: None,
        };
        // No rules => no write at all (None), not an empty/malformed line.
        assert_eq!(render_io_max(&empty), None);
    }

    #[test]
    fn test_render_pids_max_exact() {
        assert_eq!(render_pids_max(64), "64");
    }

    // Whole-token controller matching. A `listing.contains(controller)` impl (the
    // likely bug) would match `memory` inside `memoryx` and go red on that case.
    #[test]
    fn test_controller_listed_whole_token() {
        assert!(controller_listed("cpu io memory pids", "memory"));
        assert!(controller_listed("memory", "memory"));
        assert!(!controller_listed("cpuset cpu io pids", "memory"));
        assert!(!controller_listed("memoryx hugetlb", "memory"));
        assert!(!controller_listed("", "memory"));
    }

    // H-FAILLOUD-1 (§7.2, The fail-loud capability contract and HostCapabilities,
    // rule 2): a *requested* limit whose controller is not
    // delegated must fail loud with a matchable CapabilityUnavailable and must NOT
    // be recorded as created. Goes red on the old `Ok(())`-unconditional create_slice.
    #[test]
    fn test_create_slice_fails_loud_when_memory_controller_undelegated() {
        let fs = FakeCgroupFs::new();
        fs.undelegate("memory");
        let limits = ResourceLimits {
            mem_max_mib: Some(128),
            cpu_max_pct: None,
            pids_max: None,
            io_max: None,
        };
        let err = fs
            .create_slice("vmcell-vm-1", &limits)
            .expect_err("requested memory.max on an undelegated controller must fail loud");
        assert!(
            matches!(err, crate::error::Error::CapabilityUnavailable { .. }),
            "expected CapabilityUnavailable, got {err:?}"
        );
        // A limit that could not be enforced must leave no slice behind.
        assert!(
            !fs.has_slice("vmcell-vm-1"),
            "no slice may be recorded when its requested limit could not be enforced"
        );
    }

    // The inverse: with the controller delegated (the default), the same request
    // succeeds — proving the failure above is the undelegation, not a blanket reject.
    #[test]
    fn test_create_slice_ok_when_controller_delegated() {
        let fs = FakeCgroupFs::new();
        let limits = ResourceLimits {
            mem_max_mib: Some(128),
            cpu_max_pct: None,
            pids_max: None,
            io_max: None,
        };
        fs.create_slice("vmcell-vm-1", &limits).unwrap();
        assert!(fs.has_slice("vmcell-vm-1"));
    }

    // §7.1 (What is read and enforced) rule 3: when no control files exist, every per-metric availability flag
    // must be `false` so a caller can distinguish an unreadable counter from a real 0
    // ("an unread counter is the same lie as a missing one"). Goes red on an impl that
    // hardcodes the flags true or never sets them off the always-zero values.
    #[test]
    fn test_read_stats_availability_false_when_files_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir.path().join("empty-cgroup");
        std::fs::create_dir_all(&base).expect("create empty cgroup dir");
        // No memory.current/peak, cpu.stat, io.stat, or cgroup.controllers exist.
        let usage = read_stats_at(&base.to_string_lossy());
        assert!(
            !usage.mem_read_ok,
            "mem_read_ok must be false when memory.current/peak are absent"
        );
        assert!(
            !usage.cpu_read_ok,
            "cpu_read_ok must be false when cpu.stat is absent"
        );
        assert!(
            !usage.io_read_ok,
            "io_read_ok must be false when io.stat is absent"
        );
        assert!(!usage.mem_limit_enforced);
        // The values themselves must be the honest 0, paired with the false flags.
        assert_eq!(usage.mem_current_mib, 0);
        assert_eq!(usage.cpu_usec, 0);
        assert_eq!(usage.io_read_bytes, 0);
    }

    // The inverse: with the control files present and parseable, each flag flips to
    // true alongside the parsed value. Proves the false above is the absent file, not
    // a flag wired permanently off.
    #[test]
    fn test_read_stats_availability_true_when_files_present() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir.path().join("full-cgroup");
        std::fs::create_dir_all(&base).expect("create cgroup dir");
        let write = |name: &str, contents: &str| {
            std::fs::write(base.join(name), contents).expect("write control file");
        };
        // 4 MiB current, 8 MiB peak.
        write("memory.current", &(4u64 * 1024 * 1024).to_string());
        write("memory.peak", &(8u64 * 1024 * 1024).to_string());
        write("cpu.stat", "usage_usec 123456\nuser_usec 1\n");
        write("io.stat", "8:0 rbytes=100 wbytes=200\n");
        write("cgroup.controllers", "cpu io memory pids");

        let usage = read_stats_at(&base.to_string_lossy());
        assert!(usage.mem_read_ok);
        assert!(usage.cpu_read_ok);
        assert!(usage.io_read_ok);
        assert_eq!(usage.mem_current_mib, 4);
        assert_eq!(usage.mem_peak_mib, 8);
        assert_eq!(usage.cpu_usec, 123_456);
        assert_eq!(usage.io_read_bytes, 100);
        assert_eq!(usage.io_write_bytes, 200);
        assert!(usage.mem_limit_enforced);
    }

    // A half-readable memory controller (current present, peak missing) is not
    // trustworthy: mem_read_ok must require BOTH counters, guarding against an impl
    // that flips the flag on the first successful read.
    #[test]
    fn test_read_stats_mem_read_ok_requires_both_counters() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir.path().join("partial-cgroup");
        std::fs::create_dir_all(&base).expect("create cgroup dir");
        std::fs::write(
            base.join("memory.current"),
            (4u64 * 1024 * 1024).to_string(),
        )
        .expect("write memory.current");
        // memory.peak intentionally absent.
        let usage = read_stats_at(&base.to_string_lossy());
        assert!(
            !usage.mem_read_ok,
            "mem_read_ok must be false when memory.peak is missing"
        );
    }

    // A requested limit fails loud for the specific undelegated controller (cpu),
    // not just memory — guards against a memory-only check.
    #[test]
    fn test_create_slice_fails_loud_for_undelegated_cpu() {
        let fs = FakeCgroupFs::new();
        fs.undelegate("cpu");
        let limits = ResourceLimits {
            mem_max_mib: None,
            cpu_max_pct: Some(50),
            pids_max: None,
            io_max: None,
        };
        let err = fs
            .create_slice("vmcell-vm-1", &limits)
            .expect_err("requested cpu.max on an undelegated controller must fail loud");
        assert!(matches!(
            err,
            crate::error::Error::CapabilityUnavailable { .. }
        ));
    }

    // CFG-1: the limit-application block must run REGARDLESS of the `metrics` feature
    // and actually write the cgroup control files. This exercises the REAL
    // `DefaultCgroupFs` write path (`create_slice_at`) against a tempdir root — not the
    // `FakeCgroupFs`, which over-promised relative to the old non-`metrics` impl and so
    // never caught the silent-drop bug — so it reddens if the block is re-gated behind
    // `metrics` (the control files would be absent) or a render formula is inverted.
    #[test]
    fn test_create_slice_at_writes_real_limit_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_string_lossy().into_owned();
        // Model a delegated host: the cgroup root's subtree_control lists every
        // controller so the fail-loud delegation check passes and the limits apply.
        std::fs::write(
            dir.path().join("cgroup.subtree_control"),
            "cpu io memory pids",
        )
        .expect("seed delegated subtree_control");

        let limits = ResourceLimits {
            mem_max_mib: Some(256),
            cpu_max_pct: Some(50),
            pids_max: Some(64),
            io_max: Some(crate::config::IoMax {
                device: "8:0".to_string(),
                rbps: Some(1000),
                wbps: Some(2000),
                riops: None,
                wiops: None,
            }),
        };

        create_slice_at(&root, "vmcell-vm-1", &limits)
            .expect("create_slice_at must apply the requested limits on a delegated host");

        let read = |f: &str| {
            std::fs::read_to_string(dir.path().join("vmcell-vm-1").join(f))
                .unwrap_or_else(|e| panic!("{f} must be written by the ungated limit block: {e}"))
        };
        // The exact bytes the kernel would see; each reddens on a re-gated/removed
        // block (file absent) or an inverted render formula.
        assert_eq!(read("memory.max"), (256u64 << 20).to_string());
        assert_eq!(read("memory.swap.max"), "0");
        assert_eq!(read("memory.oom.group"), "1");
        assert_eq!(read("cpu.max"), "50000 100000");
        assert_eq!(read("pids.max"), "64");
        assert_eq!(read("io.max"), "8:0 rbps=1000 wbps=2000");
    }

    // CFG-2: a parent-less slice name must still have its controller delegation
    // verified — against the cgroup ROOT's `subtree_control`. The old impl skipped the
    // read-back for parent-less names, so in a tempdir (where the final control-file
    // write always succeeds) it returned `Ok` even with the controller undelegated.
    // This goes red on that inverse: with the root `subtree_control` NOT listing
    // `memory`, applying a memory limit to the top-level `vmcell-vm-1` must fail loud
    // and leave no control file behind.
    #[test]
    fn test_try_apply_limit_at_verifies_root_delegation_for_parentless_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_string_lossy().into_owned();
        std::fs::create_dir_all(dir.path().join("vmcell-vm-1")).expect("mkdir slice");
        // Root delegates cpu/pids but NOT memory.
        std::fs::write(dir.path().join("cgroup.subtree_control"), "cpu pids")
            .expect("seed root subtree_control without memory");

        let err = try_apply_limit_at(&root, "vmcell-vm-1", "memory", "memory.max", "1")
            .expect_err("undelegated memory on a parent-less name must fail loud (CFG-2)");
        assert!(
            matches!(err, crate::error::Error::CapabilityUnavailable { .. }),
            "expected CapabilityUnavailable, got {err:?}"
        );
        assert!(
            !dir.path().join("vmcell-vm-1/memory.max").exists(),
            "no control file may be written when the controller is not delegated"
        );

        // Inverse: once the root delegates memory, the same call succeeds and writes —
        // proving the failure above is the missing delegation, not a blanket reject.
        std::fs::write(dir.path().join("cgroup.subtree_control"), "cpu memory pids")
            .expect("re-seed root subtree_control with memory");
        try_apply_limit_at(&root, "vmcell-vm-1", "memory", "memory.max", "42")
            .expect("delegated memory must apply");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("vmcell-vm-1/memory.max")).unwrap(),
            "42"
        );
    }

    // M-HOST-4 part B: a limit write rejected for a bad VALUE (EINVAL — e.g. a
    // `cpu.max` quota below the kernel floor) is a caller bug that must map to
    // `Error::Cgroup`, while a permission/read-only failure keeps the §7.2 (The
    // fail-loud capability contract and HostCapabilities)
    // `CapabilityUnavailable` remediation. Goes RED on the old "every write error →
    // CapabilityUnavailable" mapping (EINVAL would then match CapabilityUnavailable).
    #[test]
    fn classify_limit_write_err_splits_einval_from_permission() {
        use crate::error::Error;
        let einval = std::io::Error::from_raw_os_error(libc::EINVAL);
        assert!(
            matches!(
                classify_limit_write_err("cpu.max", "/p/cpu.max", "cpu", "0 100000", &einval),
                Error::Cgroup(_)
            ),
            "EINVAL (bad limit value) must be Error::Cgroup, not CapabilityUnavailable"
        );
        // The capability/permission errnos must remain CapabilityUnavailable so the
        // "enable delegation" remediation still fires.
        for errno in [libc::EACCES, libc::EPERM, libc::EROFS] {
            let e = std::io::Error::from_raw_os_error(errno);
            assert!(
                matches!(
                    classify_limit_write_err("cpu.max", "/p/cpu.max", "cpu", "0 100000", &e),
                    Error::CapabilityUnavailable { .. }
                ),
                "errno {errno} must remain CapabilityUnavailable"
            );
        }
    }

    // M-HOST-5: `mem_limit_enforced` reports specifically whether the MEMORY controller
    // is delegated (the knob whose silent absence lets the hard memory cap not fire),
    // not "any requested controller is enforced". A cgroup delegating cpu+pids but
    // NOT memory must therefore report `false`; adding memory flips it `true`. Goes
    // RED on an impl that checks "any controller present", a substring, or the
    // first-requested controller instead of the fixed `memory` token.
    #[test]
    fn test_read_stats_limits_enforced_tracks_memory_controller_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir.path().join("cg");
        std::fs::create_dir_all(&base).expect("mkdir");
        // cpu and pids delegated, memory NOT.
        std::fs::write(base.join("cgroup.controllers"), "cpu pids").expect("controllers");
        assert!(
            !read_stats_at(&base.to_string_lossy()).mem_limit_enforced,
            "memory not delegated ⇒ mem_limit_enforced must be false even if cpu/pids are"
        );
        // Now delegate memory too — the flag flips, proving the check is memory-specific.
        std::fs::write(base.join("cgroup.controllers"), "cpu memory pids").expect("controllers");
        assert!(
            read_stats_at(&base.to_string_lossy()).mem_limit_enforced,
            "memory delegated ⇒ mem_limit_enforced true"
        );
    }

    // L-HOST-1: an empty cgroup name is a caller bug, not a silent success. The real
    // `DefaultCgroupFs` must self-guard in both delete_slice and add_task and return
    // a typed error BEFORE touching `/sys`. Goes RED on the old
    // `if !name.is_empty() { … } Ok(())` silent-Ok.
    #[test]
    fn default_cgroup_fs_rejects_empty_name() {
        let fs = DefaultCgroupFs;
        assert!(
            matches!(fs.delete_slice(""), Err(crate::error::Error::Cgroup(_))),
            "delete_slice with an empty name must error"
        );
        assert!(
            matches!(fs.add_task("", 1234), Err(crate::error::Error::Cgroup(_))),
            "add_task with an empty name must error"
        );
    }
}
