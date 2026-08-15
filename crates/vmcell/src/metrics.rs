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

/// The **full** cgroup slice name the orchestrator creates for `vmid`: the
/// [`crate::naming::cgroup_slice_name`] leaf, placed as a sibling of this process's own cgroup
/// (§13 sibling placement) when `/proc/self/cgroup` yields a base, and bare otherwise.
///
/// One law (AGENTS.md "one law, one predicate"): the leaf, the base, and the `{base}/{leaf}` join
/// live here and nowhere else. The join used to be inline in `setup_env` — harmless while it had a
/// single caller, but the unit-test delegation gate in `orchestrator`'s tests must name the exact
/// slice a start would have created in order to assert that nothing by that name appears under
/// /sys/fs/cgroup, and a test-local `format!` would put a second copy of the law inside the very
/// test whose job is to catch drift in it.
///
/// **Public, and re-exported as [`crate::naming::vm_slice_name`]** beside the sibling name
/// composers, because `pub(crate)` is what forced the copies this rule exists to prevent: an
/// out-of-crate reader of `memory.events` (the artifact validator) could not reach the law, so it
/// hand-formatted a `vmcell-vm-<vmid>` literal and silently read a path that does not exist for any
/// VM configured with a non-default [`crate::naming::DEFAULT_RESOURCE_PREFIX`]. Take the prefix from
/// the same `VmConfig::resource_prefix` the VM was started with; never assume the default.
#[must_use]
pub fn vm_slice_name(prefix: &str, vmid: u32) -> String {
    let leaf = crate::naming::cgroup_slice_name(prefix, vmid);
    match std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|contents| cgroup_base_from_proc(&contents))
    {
        Some(base) => format!("{base}/{leaf}"),
        None => leaf,
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
/// "enable delegation". `ENOENT`/`EOPNOTSUPP` mean the control file is *absent* or
/// the facility is unsupported (e.g. `memory.swap.max` on a kernel without swap
/// accounting / `swapaccount=0`) — also [`crate::error::Error::Cgroup`], because the
/// controller is delegated and an "enable delegation" remediation would be wrong.
/// Every other errno (`EACCES`/`EPERM`/`EROFS`, or anything unexpected) is the §7.2
/// (The fail-loud capability contract and HostCapabilities) capability/permission
/// failure and stays [`crate::error::Error::CapabilityUnavailable`]. Kept pure so the
/// errno split is unit-testable without provoking a real errno from the filesystem
/// (M-HOST-4).
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
    } else if matches!(
        e.raw_os_error(),
        Some(libc::ENOENT) | Some(libc::EOPNOTSUPP)
    ) {
        // An ABSENT facility, not a delegation/permission fault: the control file does
        // not exist (e.g. `memory.swap.max` on a kernel without swap accounting /
        // `swapaccount=0`) or the kernel reports the operation unsupported. On such a
        // host the controller IS delegated, so a `CapabilityUnavailable` "enable
        // delegation" remediation would send the operator chasing the wrong fix. Surface
        // it as `Error::Cgroup` ("fix the host"), matching the EINVAL treatment above.
        Error::Cgroup(format!(
            "control file {path} absent/unsupported for the '{controller}' controller \
             (no swap accounting or facility not compiled in): {e}"
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

/// Best-effort reclaim of the per-VM cgroup leaf directory at `path`, used by the
/// `create_slice_at` error path so a mid-sequence limit failure leaves **no**
/// partially-configured cgroup behind (`failed-create-slice-leaves-partial-cgroup-dir`).
///
/// On real cgroupfs a slice's control files are kernfs attributes, not directory
/// entries, so the plain `rmdir` below already reclaims a slice carrying `memory.max`
/// and friends. A plain-filesystem cgroup tree (the injected `cgroup_root` the unit
/// tests use) holds them as regular files and answers `ENOTEMPTY` instead, so that one
/// errno falls back to sweeping the depth-1 *files* and retrying. The fallback never
/// recurses: a real slice that grew a **child** cgroup must keep its child and surface
/// the failure, never be silently flattened (and on cgroupfs the sweep's `remove_file`
/// is refused by kernfs anyway, so the caller warns rather than damaging anything).
fn remove_cgroup_leaf(path: &str) -> std::io::Result<()> {
    match std::fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::ENOTEMPTY) => {
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    std::fs::remove_file(entry.path())?;
                }
            }
            std::fs::remove_dir(path)
        }
        Err(e) => Err(e),
    }
}

/// Applies every *requested functional* limit in `limits` to the (already created) slice
/// `name` under `cgroup_root`, in the fixed memory → cpu → pids → io order. Split out of
/// [`create_slice_at`] so the error path has a single place to reclaim the leaf directory
/// it created (`failed-create-slice-leaves-partial-cgroup-dir`); every arm keeps the
/// fail-loud §7.2 (The fail-loud capability contract and HostCapabilities) contract.
fn apply_requested_limits(
    cgroup_root: &str,
    name: &str,
    limits: &crate::config::ResourceLimits,
) -> Result<()> {
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
/// A failed limit leaves **no residue**
/// (`failed-create-slice-leaves-partial-cgroup-dir`): the caller sees `Err` and drops
/// the slice name on the floor, so a leaf this call created and then half-configured
/// (say `memory.max` applied, `cpu.max` refused) would linger forever — the effect class
/// `FakeCgroupFs` is structurally blind to (AGENTS rule 4: the fakes never touch the
/// filesystem). Only a leaf *we* created is reclaimed; a pre-existing slice may already
/// hold a live VMM's members and is left alone.
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
    let slice_path = format!("{cgroup_root}/{name}");
    // Whether the leaf existed BEFORE this call decides whether the error path may
    // reclaim it: only a leaf we created is ours to remove.
    let preexisting = std::path::Path::new(&slice_path).is_dir();
    std::fs::create_dir_all(&slice_path)
        .map_err(|e| crate::error::Error::Cgroup(format!("create cgroup {name}: {e}")))?;

    let applied = apply_requested_limits(cgroup_root, name, limits);
    if applied.is_err() && !preexisting {
        // Best-effort, like `delete_slice`: a failure to reclaim is a leak, so it is a
        // visible `warn!` rather than a swallowed discard (L-HOST-2), and it never
        // masks the limit error the caller must see.
        if let Err(e) = remove_cgroup_leaf(&slice_path) {
            tracing::warn!(
                "failed to remove partially-configured cgroup {}: {}",
                name,
                e
            );
        }
    }
    applied
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

/// An in-process [`CgroupFs`] fake for unit testing.
///
/// **Test-only.** Compiled only under `cfg(test)` or the `test-support` feature, which is
/// never in `default` and which the backend crates take as a **dev**-dependency — so it
/// cannot reach a shipped binary. It was `#[cfg(test)]`-only, which made it invisible
/// outside this crate and left `vmcell-firecracker`, `vmcell-qemu`, `vmcell-crosvm` and
/// `vmcell-artifact-validator` each carrying a hand-rolled `TestCgroupFs` copy (docs/81
/// §9); the feature is what lets them share this one.
///
/// **It is still structurally blind to the filesystem** (AGENTS rule 4). It models slices,
/// tasks and controller delegation in a `HashMap` and touches no cgroup sysfs, so no test
/// driven by it is evidence about on-disk residue — `create_slice_at`'s
/// no-residue-on-failure law is proven against a real temp directory instead. Exposing it
/// downstream widens who can use the fake; it does not widen what the fake can see.
//
// METRICS-FS-4 note: this is a test-only fake. Its `.lock().unwrap()` calls keep
// `unwrap` deliberately — the mutex is exercised single-threaded within a test, so a
// poisoned guard would itself be a test bug we want to surface loudly. Production
// mutex callers (e.g. `fs::in_process`) recover from poison via `into_inner()`.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone)]
pub struct FakeCgroupFs {
    state: std::sync::Arc<std::sync::Mutex<FakeCgroupState>>,
}

#[cfg(any(test, feature = "test-support"))]
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

#[cfg(any(test, feature = "test-support"))]
impl Default for FakeCgroupFs {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test-support"))]
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

    /// The one locked accessor every method below goes through.
    ///
    /// A poisoned mutex here means a previous test panicked while holding it, which is itself a
    /// test bug worth surfacing loudly — so this deliberately panics rather than recovering the
    /// way production mutex callers do (`fs::in_process` uses `into_inner()`). Routing every
    /// method through this one helper means the class carries ONE suppression instead of a dozen
    /// (AGENTS.md "route repeated legitimate sites through one helper"), which matters now that
    /// the `test-support` feature compiles this fixture outside `cfg(test)`, where
    /// `clippy::unwrap_used` is denied.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[expect(
        clippy::unwrap_used,
        reason = "test fixture: a poisoned mutex means an earlier test panicked mid-fixture, \
                  which must surface loudly rather than be papered over"
    )]
    fn state(&self) -> std::sync::MutexGuard<'_, FakeCgroupState> {
        self.state.lock().unwrap()
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
        self.state().delegated.remove(controller);
    }

    /// Checks if a slice exists.
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn has_slice(&self, name: &str) -> bool {
        self.state().slices.contains_key(name)
    }

    /// Gets limits for a slice.
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn get_limits(&self, name: &str) -> Option<crate::config::ResourceLimits> {
        self.state().slices.get(name).cloned()
    }

    /// Checks if a task is added.
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn has_task(&self, name: &str, pid: u32) -> bool {
        self.state()
            .tasks
            .get(name)
            .map(|t| t.contains(&pid))
            .unwrap_or(false)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl CgroupFs for FakeCgroupFs {
    fn create_slice(&self, name: &str, limits: &crate::config::ResourceLimits) -> Result<()> {
        let mut state = self.state();
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
        let mut state = self.state();
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
        let mut state = self.state();
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

    // d3: `vm_slice_name` composes from the prefix it is GIVEN. It was `pub(crate)`, so every
    // out-of-crate reader of a VM's cgroup files had to re-type the composition — and the artifact
    // validator's copy hard-coded `vmcell-vm-<vmid>`, silently reading a path that exists for no VM
    // started with a non-default `resource_prefix` (`memory.events oom_kill` then reads as zero
    // rather than as an error). The prefix here is deliberately NOT the default, so a hard-coded
    // `vmcell-` prefix cannot pass this test.
    #[test]
    fn vm_slice_name_composes_from_the_given_prefix() {
        let vmid = 7;
        for prefix in ["acme", "z9"] {
            assert_ne!(
                prefix,
                crate::naming::DEFAULT_RESOURCE_PREFIX,
                "this gate is vacuous if it runs on the default prefix"
            );
            let name = vm_slice_name(prefix, vmid);
            let leaf = name
                .rsplit('/')
                .next()
                .expect("rsplit always yields at least one element");
            // Positive identity through the one composer, never a test-local `format!`.
            assert_eq!(
                leaf,
                crate::naming::cgroup_slice_name(prefix, vmid),
                "the slice leaf must be composed from the CONFIGURED prefix, not a literal"
            );
            assert!(
                !leaf.starts_with(crate::naming::DEFAULT_RESOURCE_PREFIX),
                "a hard-coded default-prefix leaf ({leaf:?}) survived a non-default prefix"
            );
        }

        // The sibling-placement half stays pinned too: with a base, the name is `{base}/{leaf}`;
        // without one it is the bare leaf. A slice that lost its base would be created at the
        // cgroup root instead of beside this process.
        let name = vm_slice_name("acme", vmid);
        let leaf = crate::naming::cgroup_slice_name("acme", vmid);
        match std::fs::read_to_string("/proc/self/cgroup")
            .ok()
            .as_deref()
            .and_then(cgroup_base_from_proc)
        {
            Some(base) => assert_eq!(
                name,
                format!("{base}/{leaf}"),
                "with a /proc/self/cgroup base the slice must be placed as its sibling"
            ),
            None => assert_eq!(
                name, leaf,
                "with no base the slice name is the bare leaf, not an empty-rooted path"
            ),
        }
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
    fn test_create_slice_at_creates_a_nested_sibling_slice() {
        // The name the orchestrator really passes is NESTED — `{base}/{prefix}-vm-{vmid}`, the §13
        // sibling placement — not the bare leaf the sibling test below uses. Until now the only
        // thing exercising that shape was every fake-VMM unit test writing into the developer's own
        // delegated session cgroup: incidental coverage that was invisible on any host without
        // delegation, and that is exactly why those 21 tests needed delegation in the first place.
        // Now that they run on an in-process seam (`HostEnv::for_unit_tests`), the nested mkdir is
        // pinned here instead — KVM-free, delegation-free, against a tempdir root (AGENTS rule 4:
        // name what the fakes cannot see, and cover it).
        //
        // RED on `create_dir` in place of `create_dir_all` (ENOENT on the missing parents), and RED
        // if the CFG-2 delegation check stops reading the LEAF'S PARENT's `subtree_control` — the
        // seeded file below is on the parent, not the root.
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_string_lossy().into_owned();
        let parent = "system.slice/hosted-compute-agent.service";
        let name = format!("{parent}/vmcell-vm-7");

        // No limits requested: the bare nested mkdir must succeed with no delegation modelled at all.
        create_slice_at(&root, &name, &ResourceLimits::default())
            .expect("a nested slice name must be created in full");
        assert!(
            dir.path().join(&name).is_dir(),
            "create_slice_at must create every missing ancestor of a nested slice name"
        );

        // …and a requested limit consults the leaf's PARENT, not the root.
        std::fs::create_dir_all(dir.path().join(parent)).expect("parent dir");
        std::fs::write(
            dir.path().join(parent).join("cgroup.subtree_control"),
            "cpu io memory pids",
        )
        .expect("seed the parent's delegated subtree_control");
        let limits = ResourceLimits {
            mem_max_mib: Some(256),
            ..ResourceLimits::default()
        };
        create_slice_at(&root, &name, &limits)
            .expect("a delegated PARENT must let the limit apply on a nested name");
        assert_eq!(
            std::fs::read_to_string(dir.path().join(&name).join("memory.max"))
                .expect("memory.max must be written"),
            (256u64 << 20).to_string()
        );
    }

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

    // `failed-create-slice-leaves-partial-cgroup-dir` (docs/78 §6): a mid-sequence limit
    // failure must leave NO cgroup leaf behind. This runs against a REAL (temp-dir) cgroup
    // tree on purpose — `FakeCgroupFs` never touches the filesystem, so the residue is an
    // effect class it is structurally blind to (AGENTS rule 4). Residue shape: assert the
    // artifact exists on the success control first, then that it is gone after the failure.
    // Goes RED without the error-path reclaim (the half-configured `vmcell-vm-2` directory,
    // carrying `memory.max`, survives).
    #[test]
    fn test_create_slice_at_leaves_no_partial_cgroup_dir_on_limit_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_string_lossy().into_owned();
        let limits = ResourceLimits {
            mem_max_mib: Some(256),
            cpu_max_pct: Some(50),
            pids_max: None,
            io_max: None,
        };

        // Positive control: on a fully delegated host the slice IS created and configured,
        // so the absence asserted below is the cleanup — not a create that never ran.
        std::fs::write(
            dir.path().join("cgroup.subtree_control"),
            "cpu io memory pids",
        )
        .expect("seed delegated subtree_control");
        create_slice_at(&root, "vmcell-vm-ok", &limits)
            .expect("a delegated host applies both limits");
        assert!(
            dir.path().join("vmcell-vm-ok/memory.max").exists(),
            "the control leg must exist before the residue assertion means anything"
        );
        assert!(dir.path().join("vmcell-vm-ok").is_dir());

        // The failing run: `memory` IS delegated (its three writes land in the leaf) but
        // `cpu` is NOT, so the sequence fails half-applied — the partially-configured
        // directory this finding is about.
        std::fs::write(dir.path().join("cgroup.subtree_control"), "memory pids")
            .expect("re-seed subtree_control without cpu");
        let err = create_slice_at(&root, "vmcell-vm-2", &limits)
            .expect_err("an undelegated cpu controller must fail loud");
        assert!(
            matches!(err, crate::error::Error::CapabilityUnavailable { .. }),
            "expected CapabilityUnavailable, got {err:?}"
        );
        assert!(
            !dir.path().join("vmcell-vm-2").exists(),
            "a mid-sequence limit failure must leave no partially-configured cgroup leaf"
        );

        // A slice we did NOT create is never reclaimed — it may already hold a live VMM's
        // members. (`try_apply_limit_at` clobbered subtree_control with `+cpu`; re-seed.)
        std::fs::write(dir.path().join("cgroup.subtree_control"), "memory pids")
            .expect("re-seed subtree_control without cpu");
        let pre = dir.path().join("vmcell-vm-3");
        std::fs::create_dir_all(&pre).expect("pre-create a foreign slice");
        create_slice_at(&root, "vmcell-vm-3", &limits)
            .expect_err("an undelegated cpu controller must fail loud");
        assert!(
            pre.is_dir(),
            "a pre-existing slice must survive a failed create — it is not ours to remove"
        );
    }

    // The reclaim is deliberately NON-recursive: a leaf that grew a child cgroup keeps its
    // child and surfaces the failure instead of being flattened. Goes RED on a
    // `remove_dir_all` implementation (the child would vanish and the call would succeed).
    #[test]
    fn test_remove_cgroup_leaf_sweeps_control_files_but_never_recurses() {
        let dir = tempfile::tempdir().expect("tempdir");
        let leaf = dir.path().join("vmcell-vm-1");
        std::fs::create_dir_all(leaf.join("child")).expect("mkdir child cgroup");
        std::fs::write(leaf.join("memory.max"), "1").expect("write control file");

        remove_cgroup_leaf(&leaf.to_string_lossy())
            .expect_err("a leaf holding a child cgroup must not be reclaimed");
        assert!(
            leaf.join("child").is_dir(),
            "the child cgroup must survive — the sweep never recurses"
        );

        // Inverse: with the child gone, the same call reclaims the leaf AND the control
        // files a plain filesystem holds as real directory entries.
        std::fs::remove_dir(leaf.join("child")).expect("rmdir child");
        std::fs::write(leaf.join("cpu.max"), "50000 100000").expect("write control file");
        remove_cgroup_leaf(&leaf.to_string_lossy()).expect("a control-file-only leaf is reclaimed");
        assert!(!leaf.exists(), "the leaf and its control files are gone");
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

    // M-HOST-4 part C: an ABSENT control file (ENOENT — e.g. `memory.swap.max` on a
    // kernel without swap accounting / `swapaccount=0`) or an unsupported facility
    // (EOPNOTSUPP) is NOT a delegation/permission fault. It must map to `Error::Cgroup`
    // ("fix the host"), never `CapabilityUnavailable` ("enable delegation") — the
    // controller is delegated on such a host, so the delegation remediation is wrong.
    // Goes RED on the pre-fix classifier, where ENOENT falls into the else arm and
    // returns CapabilityUnavailable.
    #[test]
    fn classify_limit_write_err_treats_absent_facility_as_unsupported() {
        use crate::error::Error;
        for errno in [libc::ENOENT, libc::EOPNOTSUPP] {
            let e = std::io::Error::from_raw_os_error(errno);
            let classified = classify_limit_write_err(
                "memory.swap.max",
                "/p/memory.swap.max",
                "memory",
                "0",
                &e,
            );
            assert!(
                matches!(classified, Error::Cgroup(_)),
                "errno {errno} (absent facility) must be Error::Cgroup, got {classified:?}"
            );
            assert!(
                !matches!(classified, Error::CapabilityUnavailable { .. }),
                "errno {errno} must NOT be CapabilityUnavailable (wrong 'enable delegation' remediation)"
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
