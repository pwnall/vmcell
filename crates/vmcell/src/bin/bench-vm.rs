use clap::Parser;
use std::path::{Path, PathBuf};

use std::time::Instant;

use vmcell::agent::protocol::ExecRequest;
use vmcell::config::{RestoreMode, RootfsSource, VmConfig};
use vmcell::orchestrator::{MicroVm, VmidAllocator};
use vmcell::vmm::{CidAllocator, VmInstance, Vmm};

#[derive(Parser, Debug)]
#[command(author, version, about = "Macro-benchmarking harness for vmcell VMs")]
struct Args {
    #[arg(long, default_value = "cloud-hypervisor")]
    backend: String,

    /// Benchmark mode. `latency` preserves the original cold/warm boot bench.
    /// Others answer the design's open §13 questions.
    #[arg(long, default_value = "latency")]
    mode: String,

    /// Iteration count. If unset, defaults to 200 for `vsock-rtt`, else 10.
    #[arg(long)]
    iterations: Option<usize>,

    #[arg(long, default_value_t = 3)]
    warmup: usize,

    /// Number of concurrently-resident guests for `footprint`.
    #[arg(long, default_value_t = 4)]
    count: usize,

    /// Guest RAM in MiB (floor 64). Used by every mode's VM config.
    #[arg(long, default_value_t = 256)]
    mem_mib: u32,

    /// Directory (must be on a real FS, NOT tmpfs) for the `latency` warm-restore,
    /// `suspend-size`, and `phase-budget` snapshots — a RAM-backed tmpfs would
    /// mis-measure suspend size and make warm-restore latency systematically
    /// optimistic (RAM-backed reads; design §13.1 snap-dir caveat).
    #[arg(long, default_value = "./target/vmcell-bench-snap")]
    snap_dir: String,

    /// Memory-restore strategy for the warm-restore path (CH `prefault`):
    /// `default` (VMM default), `eager` (`prefault=on`), or `lazy`
    /// (`prefault=off`, userfaultfd demand-paging). Drives the §13.3
    /// eager-vs-lazy benchmark; harmless for non-restore modes.
    #[arg(long, default_value = "default", value_parser = parse_restore_mode)]
    restore_mode: RestoreMode,

    /// Mark guest memory KSM-mergeable (CH `mergeable=on`, implies `shared=off`)
    /// so the `footprint` mode can measure KSM dedup (§13.5). Off by default.
    #[arg(long, default_value_t = false)]
    ksm_mergeable: bool,

    /// Kernel-version label to benchmark — selects `vmlinux-<label>` from
    /// `VMCELL_ARTIFACTS_DIR` (built by `vmcell build-kernels`). Omit to use the
    /// default `vmlinux`. This is the kernel-version benchmark dimension.
    #[arg(long)]
    kernel: Option<String>,

    /// Timeouts profile: `default` (balanced), `low-latency` (min time-to-output),
    /// or `throughput` (min whole-lifecycle incl. teardown). Selects the
    /// `Timeouts` preset applied to every VM in the run.
    #[arg(long, default_value = "default")]
    profile: String,

    /// Guest kernel console verbosity: `balanced` (default, `loglevel=6`),
    /// `quiet` (3), `verbose` (7), or `debug` (8). Drives the serial-logging
    /// VM-exit cost dimension.
    #[arg(long, default_value = "balanced")]
    kernel_verbosity: String,
}

/// Maps the `--profile` flag to a [`Timeouts`] preset (unknown → `default`).
fn timeouts_for(profile: &str) -> vmcell::config::Timeouts {
    match profile {
        "low-latency" => vmcell::config::Timeouts::low_latency(),
        "throughput" => vmcell::config::Timeouts::throughput(),
        _ => vmcell::config::Timeouts::default(),
    }
}

/// Maps the `--kernel-verbosity` flag to a [`KernelVerbosity`] (unknown → `Balanced`).
fn verbosity_for(s: &str) -> vmcell::config::KernelVerbosity {
    use vmcell::config::KernelVerbosity as K;
    match s {
        "quiet" => K::Quiet,
        "verbose" => K::Verbose,
        "debug" => K::Debug,
        _ => K::Balanced,
    }
}

/// Parses the `--restore-mode` flag into a [`RestoreMode`], rejecting any value
/// other than `default`, `eager`, or `lazy`.
fn parse_restore_mode(s: &str) -> Result<RestoreMode, String> {
    match s {
        "default" => Ok(RestoreMode::Default),
        "eager" => Ok(RestoreMode::Eager),
        "lazy" => Ok(RestoreMode::Lazy),
        other => Err(format!(
            "invalid restore mode '{other}' (expected: default, eager, lazy)"
        )),
    }
}

impl Args {
    /// Effective iteration count, applying the per-mode default when unset.
    fn iters(&self) -> usize {
        self.iterations
            .unwrap_or(if self.mode == "vsock-rtt" { 200 } else { 10 })
    }
}

fn report(name: &str, latencies: &mut [u128]) {
    if latencies.is_empty() {
        println!("{}: No successful runs", name);
        return;
    }
    latencies.sort_unstable();
    let count = latencies.len() as f64;
    let p50 = latencies[(count * 0.5).floor() as usize];
    let p95 = latencies[(count * 0.95).floor() as usize];
    let p99 = latencies[(count * 0.99).floor() as usize];
    let max = latencies
        .last()
        .expect("latencies should not be empty at this point");

    println!(
        "{}: count={} p50={}ms p95={}ms p99={}ms max={}ms",
        name,
        latencies.len(),
        p50,
        p95,
        p99,
        max
    );
}

async fn run_bench<V: Vmm>(
    vmm: &V,
    name: &str,
    args: &Args,
    allocator: VmidAllocator,
    is_restore: bool,
) {
    println!("Starting benchmark: {}", name);
    let mut latencies = Vec::new();

    let artifacts_dir = vmcell::artifact::artifacts_dir();
    let kernel_path = artifacts_dir.join(kernel_filename(args.kernel.as_deref()));
    let rootfs_path = artifacts_dir.join("rootfs.erofs");

    // Fail fast (and KVM-independently) when the artifacts are absent: attempting a boot would
    // instead hang on the agent-connect timeout (and the restore baseline boots regardless of
    // `--iterations`). Report zero successful runs and return before booting anything.
    if !kernel_path.exists() || !rootfs_path.exists() {
        println!(
            "{name}: No successful runs (missing artifacts in {})",
            artifacts_dir.display()
        );
        return;
    }

    let cfg = VmConfig::builder(kernel_path, RootfsSource::Erofs { image: rootfs_path })
        .vcpus(1)
        .mem_mib(args.mem_mib)
        .network_disabled()
        .restore_mode(args.restore_mode)
        .timeouts(timeouts_for(&args.profile))
        .kernel_verbosity(verbosity_for(&args.kernel_verbosity))
        .build()
        .expect("valid VM configuration benchmark invariant");
    let cid_allocator = std::sync::Arc::new(CidAllocator::new());

    // CLI-5: honor `--snap-dir` for the warm-restore snapshot instead of `temp_dir()`
    // (commonly tmpfs / RAM-backed), which makes warm-restore latency systematically
    // optimistic (§13.1 snap-dir caveat). `--snap-dir` defaults to a real-FS path
    // (`./target/vmcell-bench-snap`), matching the suspend-size / phase-budget modes.
    let snap_dir = PathBuf::from(&args.snap_dir).join(format!(
        "latency-{}-{}",
        args.backend,
        std::process::id()
    ));
    // Best-effort pre-clean of a stale snapshot dir left by a prior aborted run; a
    // missing dir (the common case) is not an error worth surfacing.
    let _ = std::fs::remove_dir_all(&snap_dir);

    if is_restore {
        println!("Creating baseline snapshot for restore benchmark...");
        let mut base_vm = match MicroVm::start(
            vmm,
            cfg.clone(),
            cid_allocator.clone(),
            allocator.clone(),
            Box::new(vmcell::metrics::DefaultCgroupFs),
        )
        .await
        {
            Ok(vm) => vm,
            Err(e) => {
                println!("Failed to start base VM for snapshotting: {}", e);
                return;
            }
        };
        if let Err(e) = base_vm.agent(None, &vmcell::orchestrator::RealClock).await {
            println!("Failed to connect to base VM agent: {}", e);
            // Best-effort graceful teardown of the base VM; `MicroVm::Drop` is the
            // real, guaranteed teardown, so a shutdown error is not actionable here.
            let _ = base_vm.shutdown().await;
            return;
        }
        // CLI-3: a real I/O failure creating the snapshot dir must degrade gracefully
        // (report zero runs and return), mirroring `run_suspend_size`, not panic the
        // whole harness via `.expect()`.
        if let Err(e) = std::fs::create_dir_all(&snap_dir) {
            println!(
                "{name}: cannot create snapshot dir {}: {e}",
                snap_dir.display()
            );
            // Best-effort teardown of the booted base VM before bailing; `Drop` still
            // guarantees the real teardown.
            let _ = base_vm.shutdown().await;
            return;
        }
        if let Err(e) = base_vm.instance_mut().snapshot(&snap_dir).await {
            println!("Failed to take snapshot of base VM: {}", e);
            // Best-effort cleanup on the snapshot-failure path: shut the base VM down
            // (Drop is the real teardown) and drop the partial snapshot dir. Neither
            // error is actionable and must not mask the reported failure above.
            let _ = base_vm.shutdown().await;
            let _ = std::fs::remove_dir_all(&snap_dir);
            return;
        }
        // Best-effort graceful shutdown of the base VM now that the snapshot is taken;
        // `MicroVm::Drop` guarantees the real teardown regardless.
        let _ = base_vm.shutdown().await;
    }

    // Tracks whether every cold-boot iteration managed to drop the page cache.
    // If any write fails (we lack CAP_SYS_ADMIN / root), the cold numbers are
    // actually warm-cache and we say so on the label instead of mislabeling them.
    let mut page_cache_dropped = true;

    for i in 0..(args.iters() + args.warmup) {
        if !is_restore {
            // A "cold boot" is only cold if the page cache is cold. Drop it
            // directly via /proc/sys/vm/drop_caches — no interactive sudo, so it
            // works under the privileged test-runner / root without a tty prompt.
            // O_TRUNC on a procfs sysctl is rejected, so open write-only (no
            // create/truncate) and write_all; only flag warm if that fails.
            if !drop_page_cache() {
                page_cache_dropped = false;
            }
        }

        let start = Instant::now();
        let vm_res = if is_restore {
            MicroVm::restore(
                vmm,
                &snap_dir,
                cfg.clone(),
                cid_allocator.clone(),
                allocator.clone(),
                Box::new(vmcell::metrics::DefaultCgroupFs),
            )
            .await
        } else {
            MicroVm::start(
                vmm,
                cfg.clone(),
                cid_allocator.clone(),
                allocator.clone(),
                Box::new(vmcell::metrics::DefaultCgroupFs),
            )
            .await
        };

        match vm_res {
            Ok(mut vm) => {
                if let Ok(_agent) = vm.agent(None, &vmcell::orchestrator::RealClock).await {
                    let elapsed = start.elapsed().as_millis();
                    if i >= args.warmup {
                        latencies.push(elapsed);
                    }
                }
                // Best-effort per-iteration teardown; `Drop` is the guaranteed path,
                // and a shutdown error must not corrupt the latency sample above.
                let _ = vm.shutdown().await;
            }
            Err(e) => {
                println!("Run failed (expected if artifacts/KVM are missing): {}", e);
                break;
            }
        }
    }

    if is_restore {
        // Best-effort cleanup of the baseline snapshot dir after the run; a removal
        // failure is not worth aborting the (already-collected) report for.
        let _ = std::fs::remove_dir_all(&snap_dir);
    }

    report(
        &bench_label(name, is_restore, page_cache_dropped),
        &mut latencies,
    );
}

/// Returns the report label, annotating a cold-boot benchmark whose page cache
/// could not be dropped — those latencies are warm-cache (systematically
/// optimistic), not cold, so they must not be reported as plain "cold".
fn bench_label(base: &str, is_restore: bool, page_cache_dropped: bool) -> String {
    if !is_restore && !page_cache_dropped {
        format!("{base} (WARM-CACHE: drop_caches unavailable — run as root for cold numbers)")
    } else {
        base.to_string()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Fail loud and early on a misinvocation, before any side effects (CPU-freq
    // pinning, booting). An unknown/feature-disabled `--backend`, an unknown
    // `--mode`, or an out-of-floor `--mem-mib` must exit non-zero — not print a
    // notice and silently succeed (M-CLI-1), and not panic at a `.build()`
    // `.expect()` site with a misleading "benchmark invariant" message (P22).
    validate_backend(&args.backend)?;
    validate_mode(&args.mode)?;
    validate_vm_params(&args)?;

    println!("Running benchmarks with backend: {}", args.backend);
    println!(
        "kernel: {} (label={})",
        kernel_filename(args.kernel.as_deref()),
        args.kernel.as_deref().unwrap_or("default")
    );

    // Pin CPU frequency for the whole run (design §13.2 noise floor): every online
    // CPU is set to the `performance` governor with turbo disabled, and the prior
    // settings are restored when this guard drops — including on panic. Held until
    // `main` returns. Degrades to a logged no-op without CAP_DAC_OVERRIDE, so run
    // through `vmcell-test-runner` (or as root) to actually pin.
    let _freq_pin =
        match vmcell::cpufreq::CpuFreqPin::engage(vmcell::cpufreq::SysfsCpuFreq::system()) {
            Ok(pin) if pin.is_pinned() => {
                println!(
                    "cpufreq: pinned {} CPU(s) to `performance` + turbo off (restored on exit)",
                    pin.pinned_cpus()
                );
                Some(pin)
            }
            Ok(pin) => {
                println!(
                    "cpufreq: NOT pinned (need CAP_DAC_OVERRIDE via vmcell-test-runner) — \
                 latency numbers carry CPU-scaling noise"
                );
                Some(pin)
            }
            Err(e) => {
                println!("cpufreq: pin unavailable: {e}");
                None
            }
        };

    let allocator = VmidAllocator::new();

    match args.backend.as_str() {
        #[cfg(feature = "cloud-hypervisor")]
        "cloud-hypervisor" => {
            let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new("cloud-hypervisor");
            println!("Capabilities: {:?}", vmm.capabilities());
            run_mode(&vmm, "cloud-hypervisor", &args, allocator.clone()).await?;
        }
        #[cfg(feature = "firecracker")]
        "firecracker" => {
            let vmm = vmcell::vmm::firecracker::Firecracker::new("firecracker");
            println!("Capabilities: {:?}", vmm.capabilities());
            run_mode(&vmm, "firecracker", &args, allocator.clone()).await?;
        }
        #[cfg(feature = "qemu")]
        "qemu" => {
            let vmm = vmcell::vmm::qemu::Qemu::new("qemu-system-x86_64");
            println!("Capabilities: {:?}", vmm.capabilities());
            run_mode(&vmm, "qemu", &args, allocator.clone()).await?;
        }
        // Unreachable after `validate_backend`, but fail loud rather than
        // silently succeed if the two ever drift.
        _ => anyhow::bail!(
            "unsupported or feature-disabled --backend '{}'",
            args.backend
        ),
    }

    Ok(())
}

/// The benchmark backends compiled into this binary, honoring the per-backend
/// feature gates. The set is the single source of truth shared with the
/// `--backend` dispatch in `main` so a feature-disabled backend reads as
/// unsupported rather than silently succeeding.
fn supported_backends() -> Vec<&'static str> {
    // `cloud-hypervisor` is a `required-features` of this binary, so the array
    // always has at least one element. cfg attributes gate the array elements
    // so a feature-disabled backend reads as unsupported.
    [
        #[cfg(feature = "cloud-hypervisor")]
        "cloud-hypervisor",
        #[cfg(feature = "firecracker")]
        "firecracker",
        #[cfg(feature = "qemu")]
        "qemu",
    ]
    .to_vec()
}

/// Validates `--backend` against [`supported_backends`].
///
/// # Errors
/// Returns an error when the backend is unknown or its feature was not enabled
/// at build time, so a CI/script typo or a feature-gated build exits non-zero
/// instead of printing a notice and returning `Ok`.
fn validate_backend(backend: &str) -> anyhow::Result<()> {
    let supported = supported_backends();
    if supported.contains(&backend) {
        Ok(())
    } else {
        anyhow::bail!(
            "unsupported or feature-disabled --backend '{backend}' (compiled-in: {})",
            supported.join(", ")
        )
    }
}

/// The benchmark modes this harness understands. Kept in one place so the
/// `--mode` validator and its error message cannot drift from the dispatcher in
/// [`run_mode`].
const VALID_MODES: &[&str] = &[
    "latency",
    "footprint",
    "suspend-size",
    "phase-budget",
    "vsock-rtt",
];

/// Validates `--mode` against [`VALID_MODES`].
///
/// # Errors
/// Returns an error for an unknown mode so a typo exits non-zero instead of
/// printing "Unknown mode" and returning `Ok`.
fn validate_mode(mode: &str) -> anyhow::Result<()> {
    if VALID_MODES.contains(&mode) {
        Ok(())
    } else {
        anyhow::bail!(
            "unknown --mode '{mode}' (valid: {})",
            VALID_MODES.join(", ")
        )
    }
}

/// Validates the VM parameters shared by every benchmark mode by running them
/// through [`VmConfig`]'s own builder, surfacing its typed validation error
/// (chiefly a `--mem-mib` below the documented 64 MiB floor) instead of
/// panicking later at the `.build().expect(...)` sites.
///
/// # Errors
/// Propagates any [`VmConfig`] build error — currently a `mem_mib` below the
/// floor — as a clear, non-panicking error.
fn validate_vm_params(args: &Args) -> anyhow::Result<()> {
    VmConfig::builder(
        PathBuf::from("vmlinux"),
        RootfsSource::Erofs {
            image: PathBuf::from("rootfs.erofs"),
        },
    )
    .vcpus(1)
    .mem_mib(args.mem_mib)
    .network_disabled()
    .restore_mode(args.restore_mode)
    .ksm_mergeable(args.ksm_mergeable)
    .build()
    .map_err(|e| anyhow::anyhow!("invalid benchmark VM parameters: {e}"))?;
    Ok(())
}

/// Dispatches to the requested benchmark mode. `latency` preserves the original
/// cold/warm behaviour exactly (the dry-test path); the rest answer §13.
///
/// # Errors
/// Returns an error for an unknown `--mode` so a typo exits non-zero rather than
/// printing a notice and returning `Ok`. `--mode` is normally pre-validated by
/// [`validate_mode`] in `main`; the trailing arm re-checks defensively so the
/// two cannot silently drift.
async fn run_mode<V: Vmm>(
    vmm: &V,
    backend: &str,
    args: &Args,
    allocator: VmidAllocator,
) -> anyhow::Result<()> {
    match args.mode.as_str() {
        "latency" => {
            run_bench(vmm, "Cold Boot", args, allocator.clone(), false).await;
            if vmm.capabilities().snapshot_restore {
                run_bench(vmm, "Warm Restore", args, allocator.clone(), true).await;
            } else {
                // CLI-4 / §13.2 visible-skip: a no-snapshot backend (e.g. FC/QEMU in
                // the unprivileged+vsock tier, §3.3) can't run Warm Restore. Print the
                // reason rather than silently dropping the benchmark, matching the
                // suspend-size / phase-budget modes.
                println!("Warm Restore: backend {backend} has no snapshot support; skipping");
            }
        }
        "footprint" => run_footprint(vmm, backend, args, allocator).await,
        "suspend-size" => run_suspend_size(vmm, backend, args, allocator).await,
        "phase-budget" => run_phase_budget(vmm, backend, args, allocator).await,
        "vsock-rtt" => run_vsock_rtt(vmm, backend, args, allocator).await,
        other => anyhow::bail!(
            "unknown --mode '{other}' (valid: {})",
            VALID_MODES.join(", ")
        ),
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// Shared helpers for the §13 benchmark modes.
// ----------------------------------------------------------------------------

/// The kernel artifact filename for an optional version label (`vmlinux` or
/// `vmlinux-<sanitized-label>`). `.`→`-` matches the build-side filename
/// sanitization in `KernelStage::suffix` (the pipeline's cache sidecar uses
/// `with_extension`, which mangles dotted names).
fn kernel_filename(label: Option<&str>) -> String {
    match label {
        Some(l) => format!("vmlinux-{}", l.replace('.', "-")),
        None => "vmlinux".to_string(),
    }
}

/// Resolves the (dir, kernel, rootfs) artifact paths from `VMCELL_ARTIFACTS_DIR`,
/// selecting `vmlinux-<label>` when a kernel-version label is given.
fn artifact_paths(kernel_label: Option<&str>) -> (String, PathBuf, PathBuf) {
    let dir = vmcell::artifact::artifacts_dir()
        .to_string_lossy()
        .into_owned();
    let kernel = PathBuf::from(&dir).join(kernel_filename(kernel_label));
    let rootfs = PathBuf::from(&dir).join("rootfs.erofs");
    (dir, kernel, rootfs)
}

/// Builds the standard network-disabled erofs VM config used by every mode,
/// applying the run's `--profile` timeouts and `--kernel-verbosity`.
fn build_cfg(
    kernel: PathBuf,
    rootfs: PathBuf,
    mem_mib: u32,
    restore_mode: RestoreMode,
    ksm_mergeable: bool,
    timeouts: vmcell::config::Timeouts,
    verbosity: vmcell::config::KernelVerbosity,
) -> VmConfig {
    VmConfig::builder(kernel, RootfsSource::Erofs { image: rootfs })
        .vcpus(1)
        .mem_mib(mem_mib)
        .network_disabled()
        .restore_mode(restore_mode)
        .ksm_mergeable(ksm_mergeable)
        .timeouts(timeouts)
        .kernel_verbosity(verbosity)
        .build()
        .expect("valid VM configuration benchmark invariant")
}

/// Drops the host page cache. Returns true only if the open AND write both
/// succeed. Opens write-only (no `O_CREAT`/`O_TRUNC`): `O_TRUNC` on a procfs
/// sysctl is rejected even with `CAP_DAC_OVERRIDE`, which silently broke the
/// original `std::fs::write` cold path (it always reported a warm cache).
fn drop_page_cache() -> bool {
    use std::io::Write;
    match std::fs::OpenOptions::new()
        .write(true)
        .open("/proc/sys/vm/drop_caches")
    {
        Ok(mut f) => f.write_all(b"3\n").is_ok(),
        Err(_) => false,
    }
}

/// p50/p95/p99/max of a sample set (indices clamped to the last element).
fn pcts(latencies: &mut [u128]) -> Option<(u128, u128, u128, u128)> {
    if latencies.is_empty() {
        return None;
    }
    latencies.sort_unstable();
    let last = latencies.len() - 1;
    let idx = |q: f64| ((latencies.len() as f64 * q).floor() as usize).min(last);
    Some((
        latencies[idx(0.5)],
        latencies[idx(0.95)],
        latencies[idx(0.99)],
        latencies[last],
    ))
}

/// Reads a `/sys/kernel/mm/ksm/<field>` counter (0 if unavailable).
fn read_ksm(field: &str) -> u64 {
    std::fs::read_to_string(format!("/sys/kernel/mm/ksm/{field}"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Writes a `/sys/kernel/mm/ksm/<field>` (best-effort; the `root:root` sysfs file
/// needs `CAP_DAC_OVERRIDE`, which the test runner grants). Returns success.
fn write_ksm(field: &str, value: &str) -> bool {
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .write(true)
        .open(format!("/sys/kernel/mm/ksm/{field}"))
        .and_then(|mut f| f.write_all(value.as_bytes()))
        .is_ok()
}

/// Parses a `Key:  <value> kB`-style line (matches both `/proc/meminfo` and
/// `/proc/<pid>/status`). Returns the value in kB.
fn parse_kv_kb(text: &str, key: &str) -> Option<u64> {
    for line in text.lines() {
        let mut it = line.split_whitespace();
        if let Some(k) = it.next() {
            if k.trim_end_matches(':') == key {
                if let Some(v) = it.next() {
                    if let Ok(n) = v.parse::<u64>() {
                        return Some(n);
                    }
                }
            }
        }
    }
    None
}

/// Reads one `/proc/<pid>/status` field in kB.
fn read_proc_status_kb(pid: u32, key: &str) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    parse_kv_kb(&s, key)
}

/// Finds the host VMM process for a VM by its unique per-VM tmp dir.
///
/// CH/FC do not put the vsock socket path verbatim on the command line, but the
/// `--api-socket` argument lives in the *same* unique `vmcell-vm-<pid>-<vmid>` dir,
/// which is `vsock_path`'s parent. Match that parent **with a trailing `/`** so
/// vmid 5 does not match vmid 50/51 (`vmcell-vm-…-5` is a substring of `…-50`).
fn find_host_pid(vsock: &Path) -> Option<u32> {
    let parent = vsock
        .parent()
        .unwrap_or(vsock)
        .to_string_lossy()
        .to_string();
    let needle = format!("{parent}/");
    let full = vsock.to_string_lossy().to_string();
    let me = std::process::id();
    for e in std::fs::read_dir("/proc").ok()?.flatten() {
        let pid: u32 = match e.file_name().to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if pid == me {
            continue;
        }
        if let Ok(bytes) = std::fs::read(e.path().join("cmdline")) {
            // cmdline is NUL-separated; the path token stays intact in the lossy
            // string, and the trailing `/` keeps the match on a boundary.
            let s = String::from_utf8_lossy(&bytes);
            if s.contains(&full) || s.contains(&needle) {
                return Some(pid);
            }
        }
    }
    None
}

/// Recursively lists `(path, size)` for every regular file under `dir`.
fn walk_files(dir: &Path) -> Vec<(PathBuf, u64)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                let p = e.path();
                if let Ok(md) = e.metadata() {
                    if md.is_dir() {
                        stack.push(p);
                    } else if md.is_file() {
                        out.push((p, md.len()));
                    }
                }
            }
        }
    }
    out
}

/// Picks a working zero-cost exec probe command, preferring `/bin/true`.
async fn pick_exec_cmd<V: Vmm>(vm: &mut MicroVm<V>) -> Vec<String> {
    let candidates = [
        vec!["/bin/true".to_string()],
        vec!["/usr/bin/true".to_string()],
        vec!["true".to_string()],
    ];
    for c in candidates {
        if let Ok(agent) = vm.agent(None, &vmcell::orchestrator::RealClock).await {
            if let Ok(o) = agent.exec(ExecRequest::new(c.clone())).await {
                if o.code == 0 {
                    return c;
                }
            }
        }
    }
    vec!["cat".to_string(), "/proc/uptime".to_string()]
}

fn mean_u64(v: &[u64]) -> u64 {
    if v.is_empty() {
        0
    } else {
        v.iter().sum::<u64>() / v.len() as u64
    }
}

// ----------------------------------------------------------------------------
// §13.3 — footprint: per-guest RAM, shared erofs page cache, KSM dedup.
// ----------------------------------------------------------------------------
async fn run_footprint<V: Vmm>(vmm: &V, backend: &str, args: &Args, allocator: VmidAllocator) {
    let (dir, kernel, rootfs) = artifact_paths(args.kernel.as_deref());
    if !kernel.exists() || !rootfs.exists() {
        println!("footprint: No successful runs (missing artifacts in {dir})");
        return;
    }
    let count = args.count.max(1);
    let cfg = build_cfg(
        kernel,
        rootfs,
        args.mem_mib,
        args.restore_mode,
        args.ksm_mergeable,
        timeouts_for(&args.profile),
        verbosity_for(&args.kernel_verbosity),
    );
    let cid = std::sync::Arc::new(CidAllocator::new());

    let ksm_shared_before = read_ksm("pages_shared");
    let ksm_sharing_before = read_ksm("pages_sharing");

    // Boot guests one-by-one, holding them all alive in a Vec (so all N coexist),
    // and snapshot the *total* host RssAnon after each addition — this yields a
    // real marginal slope (step N minus step N-1) within a single invocation.
    let mut vms: Vec<MicroVm<V>> = Vec::new();
    let mut step_anon: Vec<u64> = Vec::new();
    let mut step_shmem: Vec<u64> = Vec::new();
    for i in 0..count {
        let mut vm = match MicroVm::start(
            vmm,
            cfg.clone(),
            cid.clone(),
            allocator.clone(),
            Box::new(vmcell::metrics::DefaultCgroupFs),
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                println!("footprint: boot {i} failed: {e}");
                break;
            }
        };
        if let Err(e) = vm.agent(None, &vmcell::orchestrator::RealClock).await {
            println!("footprint: agent connect {i} failed: {e}");
            // Best-effort teardown of the just-booted guest before bailing; `Drop`
            // guarantees the real teardown, so a shutdown error is not actionable.
            let _ = vm.shutdown().await;
            break;
        }
        vms.push(vm);
        // Sum host RssAnon and RssShmem across all alive VMs. CH backs guest RAM
        // with a shared memfd, so guest RAM is accounted as RssShmem, not RssAnon
        // (RssAnon is then just VMM overhead) — both slopes are reported.
        let mut anon = 0u64;
        let mut shmem = 0u64;
        for v in &vms {
            if let Some(pid) = find_host_pid(v.instance().vsock_path()) {
                anon += read_proc_status_kb(pid, "RssAnon").unwrap_or(0);
                shmem += read_proc_status_kb(pid, "RssShmem").unwrap_or(0);
            }
        }
        step_anon.push(anon / 1024);
        step_shmem.push(shmem / 1024);
    }

    let n = vms.len();
    if n == 0 {
        println!("footprint: No successful runs");
        return;
    }

    // Give KSM a window to scan & dedup the now-resident guest pages. With the
    // mergeable lever on, accelerate the scanner (CAP_DAC_OVERRIDE via the runner)
    // so dedup converges in a bounded window, then restore the prior KSM settings.
    let ksm_saved = if args.ksm_mergeable {
        let saved = (
            read_ksm("pages_to_scan"),
            read_ksm("sleep_millis"),
            read_ksm("run"),
        );
        // `run`/`pages_to_scan` are the essential knobs; `sleep_millis` is absent
        // on some kernels (7.x), so bump it opportunistically without requiring it.
        let accel = write_ksm("run", "1") && write_ksm("pages_to_scan", "20000");
        let _ = write_ksm("sleep_millis", "5");
        if !accel {
            println!(
                "footprint: WARN could not accelerate KSM (need CAP_DAC_OVERRIDE via the runner); dedup may be partial"
            );
        }
        Some(saved)
    } else {
        None
    };
    let window_secs = if args.ksm_mergeable { 25 } else { 8 };
    tokio::time::sleep(std::time::Duration::from_secs(window_secs)).await;
    let ksm_shared_after = read_ksm("pages_shared");
    let ksm_sharing_after = read_ksm("pages_sharing");
    if let Some((scan, sleep, run)) = ksm_saved {
        // Best-effort restore of the KSM scanner settings bumped above.
        let _ = write_ksm("pages_to_scan", &scan.to_string());
        let _ = write_ksm("sleep_millis", &sleep.to_string());
        let _ = write_ksm("run", &run.to_string());
    }

    let mut tot_anon = 0u64;
    let mut tot_file = 0u64;
    let mut tot_shmem = 0u64;
    let mut guest_total = 0u64;
    let mut guest_avail = Vec::new();
    let mut pid1_rss = Vec::new();
    for v in vms.iter_mut() {
        let vsock = v.instance().vsock_path().to_path_buf();
        if let Some(pid) = find_host_pid(&vsock) {
            tot_anon += read_proc_status_kb(pid, "RssAnon").unwrap_or(0);
            tot_file += read_proc_status_kb(pid, "RssFile").unwrap_or(0);
            tot_shmem += read_proc_status_kb(pid, "RssShmem").unwrap_or(0);
        }
        if let Ok(agent) = v.agent(None, &vmcell::orchestrator::RealClock).await {
            if let Ok(o) = agent
                .exec(ExecRequest::new(vec!["cat".into(), "/proc/meminfo".into()]))
                .await
            {
                let s = String::from_utf8_lossy(&o.stdout);
                if let Some(t) = parse_kv_kb(&s, "MemTotal") {
                    guest_total = t;
                }
                if let Some(a) = parse_kv_kb(&s, "MemAvailable") {
                    guest_avail.push(a);
                }
            }
            if let Ok(o) = agent
                .exec(ExecRequest::new(vec![
                    "cat".into(),
                    "/proc/1/status".into(),
                ]))
                .await
            {
                let s = String::from_utf8_lossy(&o.stdout);
                if let Some(r) = parse_kv_kb(&s, "VmRSS") {
                    pid1_rss.push(r);
                }
            }
        }
    }

    let marginal_of = |steps: &[u64]| -> Vec<u64> {
        let mut m = Vec::new();
        for i in 0..steps.len() {
            m.push(if i == 0 {
                steps[0]
            } else {
                steps[i].saturating_sub(steps[i - 1])
            });
        }
        m
    };
    let marginals = marginal_of(&step_anon);
    let marg_mean = mean_u64(&marginals);
    let marginals_shmem = marginal_of(&step_shmem);
    let marg_mean_shmem = mean_u64(&marginals_shmem);

    println!(
        "=== FOOTPRINT (backend={backend} N={n} mem_mib={}) ===",
        args.mem_mib
    );
    println!(
        "host RssAnon total = {} MiB  (per-guest mean = {} MiB)  [VMM overhead; guest RAM is shmem on CH]",
        tot_anon / 1024,
        (tot_anon / 1024) / n as u64
    );
    println!(
        "host RssFile total = {} MiB  (per-guest mean = {} MiB)  [shared-erofs page cache]",
        tot_file / 1024,
        (tot_file / 1024) / n as u64
    );
    println!(
        "host RssShmem total = {} MiB  (per-guest mean = {} MiB)  [CH guest-RAM memfd; the real density figure]",
        tot_shmem / 1024,
        (tot_shmem / 1024) / n as u64
    );
    println!("per-step total host RssAnon  (MiB) 1..N = {step_anon:?}");
    println!("per-step total host RssShmem (MiB) 1..N = {step_shmem:?}");
    println!(
        "marginal host RssAnon  per added guest (MiB): mean={marg_mean}  series={marginals:?}  [VMM overhead only]"
    );
    println!(
        "marginal host RssShmem per added guest (MiB): mean={marg_mean_shmem}  series={marginals_shmem:?}  [guest-RAM touched; step N - step N-1]"
    );
    let sharing_delta = ksm_sharing_after.saturating_sub(ksm_sharing_before);
    println!(
        "KSM pages_sharing: before={ksm_sharing_before} after={ksm_sharing_after} delta={sharing_delta} (~{} MiB dedup'd @4KiB)",
        sharing_delta * 4 / 1024
    );
    println!("KSM pages_shared:  before={ksm_shared_before} after={ksm_shared_after}");
    println!(
        "guest MemTotal = {} MiB  MemAvailable mean = {} MiB",
        guest_total / 1024,
        mean_u64(&guest_avail) / 1024
    );
    println!("guest pid1 (agent) RSS mean = {} KiB", mean_u64(&pid1_rss));

    // Best-effort teardown of every resident guest; `Drop` is the guaranteed path,
    // so a shutdown error on any one VM must not abort cleanup of the rest.
    for v in vms {
        let _ = v.shutdown().await;
    }
}

// ----------------------------------------------------------------------------
// §13.6 — suspend-size: snapshot bytes + memory-file share, vs guest RAM.
// ----------------------------------------------------------------------------
async fn run_suspend_size<V: Vmm>(vmm: &V, backend: &str, args: &Args, allocator: VmidAllocator) {
    let (dir, kernel, rootfs) = artifact_paths(args.kernel.as_deref());
    if !kernel.exists() || !rootfs.exists() {
        println!("suspend-size: No successful runs (missing artifacts in {dir})");
        return;
    }
    if !vmm.capabilities().snapshot_restore {
        println!("suspend-size: backend {backend} has no snapshot support; skipping");
        return;
    }
    let cfg = build_cfg(
        kernel,
        rootfs,
        args.mem_mib,
        args.restore_mode,
        false,
        timeouts_for(&args.profile),
        verbosity_for(&args.kernel_verbosity),
    );
    let cid = std::sync::Arc::new(CidAllocator::new());
    let snap_dir = PathBuf::from(&args.snap_dir).join(format!(
        "suspend-{backend}-{}-{}",
        args.mem_mib,
        std::process::id()
    ));
    // Best-effort pre-clean of a stale snapshot dir from a prior aborted run.
    let _ = std::fs::remove_dir_all(&snap_dir);
    if let Err(e) = std::fs::create_dir_all(&snap_dir) {
        println!(
            "suspend-size: cannot create snap dir {}: {e}",
            snap_dir.display()
        );
        return;
    }

    let mut vm = match MicroVm::start(
        vmm,
        cfg,
        cid,
        allocator,
        Box::new(vmcell::metrics::DefaultCgroupFs),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            println!("suspend-size: boot failed: {e}");
            // Best-effort removal of the (empty) snapshot dir before bailing.
            let _ = std::fs::remove_dir_all(&snap_dir);
            return;
        }
    };
    if let Err(e) = vm.agent(None, &vmcell::orchestrator::RealClock).await {
        println!("suspend-size: agent connect failed: {e}");
        // Best-effort teardown + snapshot-dir cleanup; `Drop` guarantees the real
        // teardown and neither error is actionable, so we don't surface them.
        let _ = vm.shutdown().await;
        let _ = std::fs::remove_dir_all(&snap_dir);
        return;
    }
    if let Err(e) = vm.instance_mut().snapshot(&snap_dir).await {
        println!("suspend-size: snapshot failed: {e}");
        // Best-effort teardown + partial-snapshot cleanup on the failure path.
        let _ = vm.shutdown().await;
        let _ = std::fs::remove_dir_all(&snap_dir);
        return;
    }
    // Best-effort graceful shutdown before we measure the on-disk snapshot; `Drop`
    // guarantees teardown regardless of this result.
    let _ = vm.shutdown().await;

    let files = walk_files(&snap_dir);
    let total: u64 = files.iter().map(|(_, s)| *s).sum();
    let (mem_path, mem_size) = files
        .iter()
        .max_by_key(|(_, s)| *s)
        .cloned()
        .unwrap_or((snap_dir.clone(), 0));
    let share = if total > 0 {
        (mem_size as f64) * 100.0 / (total as f64)
    } else {
        0.0
    };
    let fname = |p: &Path| -> String {
        p.file_name()
            .map(|n| n.to_string_lossy().into())
            .unwrap_or_default()
    };

    println!(
        "=== SUSPEND-SIZE (backend={backend} mem_mib={}) ===",
        args.mem_mib
    );
    println!(
        "total snapshot bytes = {total} ({:.1} MiB)",
        total as f64 / 1048576.0
    );
    println!(
        "memory file = {} : {mem_size} bytes ({:.1} MiB)",
        fname(&mem_path),
        mem_size as f64 / 1048576.0
    );
    println!("memory-file share of total = {share:.1}%");
    println!("all files:");
    for (p, s) in &files {
        println!("  {s:>12}  {}", fname(p));
    }

    // Best-effort cleanup of the measured snapshot dir now that it's been reported.
    let _ = std::fs::remove_dir_all(&snap_dir);
}

// ----------------------------------------------------------------------------
// §13.4 — phase-budget: per-phase distribution + share, restore and cold.
// ----------------------------------------------------------------------------
async fn build_baseline_snapshot<V: Vmm>(
    vmm: &V,
    cfg: &VmConfig,
    cid: std::sync::Arc<CidAllocator>,
    allocator: VmidAllocator,
    snap_dir: &Path,
) -> Result<(), String> {
    let mut base = MicroVm::start(
        vmm,
        cfg.clone(),
        cid,
        allocator,
        Box::new(vmcell::metrics::DefaultCgroupFs),
    )
    .await
    .map_err(|e| e.to_string())?;
    base.agent(None, &vmcell::orchestrator::RealClock)
        .await
        .map_err(|e| e.to_string())?;
    base.instance_mut()
        .snapshot(snap_dir)
        .await
        .map_err(|e| e.to_string())?;
    // Best-effort graceful shutdown of the baseline VM once its snapshot is written;
    // `Drop` guarantees teardown, so a shutdown error must not fail the (successful)
    // snapshot build we return `Ok` for.
    let _ = base.shutdown().await;
    Ok(())
}

fn report_phase(name: &str, v: &mut [u128], total_mean_us: u128) {
    let n = v.len() as u128;
    let mean = v.iter().sum::<u128>().checked_div(n).unwrap_or(0);
    let (p50, p95, _p99, max) = pcts(v).unwrap_or((0, 0, 0, 0));
    let share = if total_mean_us > 0 {
        (mean as f64) * 100.0 / (total_mean_us as f64)
    } else {
        0.0
    };
    println!("  {name}: p50={p50}µs p95={p95}µs max={max}µs  share={share:.1}%");
}

async fn phase_budget_path<V: Vmm>(
    vmm: &V,
    backend: &str,
    args: &Args,
    cfg: &VmConfig,
    cid: std::sync::Arc<CidAllocator>,
    allocator: VmidAllocator,
    snap_dir: Option<PathBuf>,
) {
    let label = if snap_dir.is_some() {
        "RESTORE"
    } else {
        "COLD"
    };
    let iters = args.iters();
    let mut p_create = Vec::new();
    let mut p_connect = Vec::new();
    let mut p_exec = Vec::new();
    let mut p_teardown = Vec::new();
    let mut cmd: Option<Vec<String>> = None;

    for i in 0..(iters + args.warmup) {
        if snap_dir.is_none() {
            // Best-effort cold-cache drop for the cold-boot budget. Unlike `run_bench`
            // (which labels the warm case), the phase-budget cold path is opt-in and
            // relative, so a failed drop just yields warm-cache create timing — not a
            // wrong result — and needs no CAP_SYS_ADMIN gate here.
            let _ = drop_page_cache();
        }
        let t0 = Instant::now();
        let vm_res = match &snap_dir {
            Some(d) => {
                MicroVm::restore(
                    vmm,
                    d,
                    cfg.clone(),
                    cid.clone(),
                    allocator.clone(),
                    Box::new(vmcell::metrics::DefaultCgroupFs),
                )
                .await
            }
            None => {
                MicroVm::start(
                    vmm,
                    cfg.clone(),
                    cid.clone(),
                    allocator.clone(),
                    Box::new(vmcell::metrics::DefaultCgroupFs),
                )
                .await
            }
        };
        let t_create = t0.elapsed();
        let mut vm = match vm_res {
            Ok(v) => v,
            Err(e) => {
                println!("phase-budget {label}: iter {i} create failed: {e}");
                break;
            }
        };

        let t1 = Instant::now();
        let connect_ok = vm
            .agent(None, &vmcell::orchestrator::RealClock)
            .await
            .is_ok();
        let t_connect = t1.elapsed();
        if !connect_ok {
            println!("phase-budget {label}: iter {i} connect failed");
            // Best-effort teardown before bailing; `Drop` guarantees teardown.
            let _ = vm.shutdown().await;
            break;
        }

        if cmd.is_none() {
            cmd = Some(pick_exec_cmd(&mut vm).await);
        }
        let argv = cmd
            .clone()
            .unwrap_or_else(|| vec!["cat".into(), "/proc/uptime".into()]);

        let t2 = Instant::now();
        if let Ok(agent) = vm.agent(None, &vmcell::orchestrator::RealClock).await {
            // The exec *result* is intentionally unused: this phase measures the
            // exec-round-trip latency (t2..t_exec), not the command's exit/output.
            let _ = agent.exec(ExecRequest::new(argv)).await;
        }
        let t_exec = t2.elapsed();

        let t3 = Instant::now();
        // Teardown is deliberately on the budget (§13.4): we time it, and `Drop`
        // still guarantees the real teardown if `shutdown` errors.
        let _ = vm.shutdown().await;
        let t_teardown = t3.elapsed();

        if i >= args.warmup {
            p_create.push(t_create.as_micros());
            p_connect.push(t_connect.as_micros());
            p_exec.push(t_exec.as_micros());
            p_teardown.push(t_teardown.as_micros());
        }
    }

    if p_create.is_empty() {
        println!("phase-budget {label} ({backend}): No successful runs");
        return;
    }

    let sum = |v: &[u128]| -> u128 { v.iter().sum() };
    let runs = p_create.len() as u128;
    let total_mean = (sum(&p_create) + sum(&p_connect) + sum(&p_exec) + sum(&p_teardown)) / runs;
    println!(
        "=== PHASE-BUDGET {label} (backend={backend} n={}) ===",
        p_create.len()
    );
    report_phase("create  ", &mut p_create, total_mean);
    report_phase("connect ", &mut p_connect, total_mean);
    report_phase("exec    ", &mut p_exec, total_mean);
    report_phase("teardown", &mut p_teardown, total_mean);
    println!("  TOTAL (sum of phase means) ~= {total_mean} µs");
}

async fn run_phase_budget<V: Vmm>(vmm: &V, backend: &str, args: &Args, allocator: VmidAllocator) {
    let (dir, kernel, rootfs) = artifact_paths(args.kernel.as_deref());
    if !kernel.exists() || !rootfs.exists() {
        println!("phase-budget: No successful runs (missing artifacts in {dir})");
        return;
    }
    let cfg = build_cfg(
        kernel,
        rootfs,
        args.mem_mib,
        args.restore_mode,
        false,
        timeouts_for(&args.profile),
        verbosity_for(&args.kernel_verbosity),
    );
    let cid = std::sync::Arc::new(CidAllocator::new());

    // Cold-boot path (opt-in budget).
    phase_budget_path(
        vmm,
        backend,
        args,
        &cfg,
        cid.clone(),
        allocator.clone(),
        None,
    )
    .await;

    // Restore path (the hot path) — build the baseline snapshot once.
    if vmm.capabilities().snapshot_restore {
        let snap_dir =
            PathBuf::from(&args.snap_dir).join(format!("phase-{backend}-{}", std::process::id()));
        // Best-effort pre-clean of a stale snapshot dir from a prior aborted run.
        let _ = std::fs::remove_dir_all(&snap_dir);
        if let Err(e) = std::fs::create_dir_all(&snap_dir) {
            println!("phase-budget: cannot create snap dir: {e}");
            return;
        }
        match build_baseline_snapshot(vmm, &cfg, cid.clone(), allocator.clone(), &snap_dir).await {
            Ok(()) => {
                phase_budget_path(
                    vmm,
                    backend,
                    args,
                    &cfg,
                    cid.clone(),
                    allocator.clone(),
                    Some(snap_dir.clone()),
                )
                .await;
            }
            Err(e) => println!("phase-budget: baseline snapshot failed: {e}"),
        }
        // Best-effort cleanup of the baseline snapshot dir after the restore budget.
        let _ = std::fs::remove_dir_all(&snap_dir);
    } else {
        println!("phase-budget: backend {backend} has no restore; cold path only");
    }
}

// ----------------------------------------------------------------------------
// §13.5 — vsock-rtt: control-plane exec round-trip latency floor.
// ----------------------------------------------------------------------------
async fn run_vsock_rtt<V: Vmm>(vmm: &V, backend: &str, args: &Args, allocator: VmidAllocator) {
    let (dir, kernel, rootfs) = artifact_paths(args.kernel.as_deref());
    if !kernel.exists() || !rootfs.exists() {
        println!("vsock-rtt: No successful runs (missing artifacts in {dir})");
        return;
    }
    let cfg = build_cfg(
        kernel,
        rootfs,
        args.mem_mib,
        args.restore_mode,
        false,
        timeouts_for(&args.profile),
        verbosity_for(&args.kernel_verbosity),
    );
    let cid = std::sync::Arc::new(CidAllocator::new());
    let iters = args.iters();

    let mut vm = match MicroVm::start(
        vmm,
        cfg,
        cid,
        allocator,
        Box::new(vmcell::metrics::DefaultCgroupFs),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            println!("vsock-rtt: boot failed: {e}");
            return;
        }
    };
    if let Err(e) = vm.agent(None, &vmcell::orchestrator::RealClock).await {
        println!("vsock-rtt: agent connect failed: {e}");
        // Best-effort teardown before bailing; `Drop` guarantees teardown.
        let _ = vm.shutdown().await;
        return;
    }
    let argv = pick_exec_cmd(&mut vm).await;

    for _ in 0..args.warmup {
        if let Ok(agent) = vm.agent(None, &vmcell::orchestrator::RealClock).await {
            // Warmup iteration: the exec result is discarded on purpose (it primes
            // caches / the vsock path and is not part of the measured sample).
            let _ = agent.exec(ExecRequest::new(argv.clone())).await;
        }
    }

    let mut rtts = Vec::with_capacity(iters);
    for _ in 0..iters {
        let agent = match vm.agent(None, &vmcell::orchestrator::RealClock).await {
            Ok(a) => a,
            Err(_) => break,
        };
        let t = Instant::now();
        let r = agent.exec(ExecRequest::new(argv.clone())).await;
        let dt = t.elapsed().as_micros();
        if r.is_ok() {
            rtts.push(dt);
        }
    }
    // Best-effort teardown after the run; `Drop` guarantees the real teardown, so a
    // shutdown error must not corrupt the collected RTT report below.
    let _ = vm.shutdown().await;

    println!(
        "=== VSOCK-RTT (backend={backend} n={} cmd={argv:?}) ===",
        rtts.len()
    );
    if let Some((p50, p95, p99, max)) = pcts(&mut rtts) {
        println!("  per-round-trip exec latency: p50={p50}µs p95={p95}µs p99={p99}µs max={max}µs");
    } else {
        println!("  No successful runs");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Buggy impl this guards: cold-boot latencies were reported under a plain
    // "Cold Boot" label even when the page cache was never dropped (warm cache),
    // so warm numbers masqueraded as cold. The label must flag the warm case.
    #[test]
    fn cold_label_flags_warm_cache_when_drop_unavailable() {
        assert!(bench_label("Cold Boot", false, false).contains("WARM-CACHE"));
        assert_eq!(bench_label("Cold Boot", false, true), "Cold Boot");
        // Restore is not page-cache sensitive in the same way; never flagged.
        assert_eq!(bench_label("Warm Restore", true, false), "Warm Restore");
    }

    // M-CLI-1: the `_` backend arm printed "Unsupported backend or feature not
    // enabled" then let `main` return `Ok(())`, so a typo or a feature-disabled
    // build exited 0. RED on the inverse (a validator that returns `Ok` for
    // anything): the unknown-backend assert below fails.
    #[test]
    fn validate_backend_rejects_unknown_backend() {
        assert!(validate_backend("totally-not-a-vmm").is_err());
        assert!(validate_backend("").is_err());
        // bench-vm's `required-features` always include `cloud-hypervisor`, so
        // the default backend must be accepted whenever this binary compiles.
        assert!(validate_backend("cloud-hypervisor").is_ok());
        // Every compiled-in backend round-trips through the validator.
        for b in supported_backends() {
            assert!(validate_backend(b).is_ok(), "backend {b} should be valid");
        }
    }

    // M-CLI-1: the `other =>` mode arm printed "Unknown mode" then returned, so
    // `run_mode` (and `main`) still reported success. RED on the inverse: an
    // accept-all validator fails the `is_err` asserts.
    #[test]
    fn validate_mode_rejects_unknown_mode() {
        assert!(validate_mode("latencyy").is_err());
        assert!(validate_mode("").is_err());
        for m in VALID_MODES {
            assert!(validate_mode(m).is_ok(), "mode {m} should be valid");
        }
    }

    // P22: bench-vm `.expect()`ed on the config builder, panicking with a
    // misleading "benchmark invariant" message for a `--mem-mib` below the 64
    // MiB floor. The validator must instead surface config's typed error.
    // RED on the inverse (no floor check, i.e. `.expect()`/accept-all): the
    // below-floor case panics or returns `Ok`, failing `unwrap_err`/the assert.
    #[test]
    fn validate_vm_params_rejects_mem_below_floor() {
        let bad = <Args as clap::Parser>::parse_from(["bench-vm", "--mem-mib", "32"]);
        let err = validate_vm_params(&bad).unwrap_err();
        assert!(
            err.to_string().contains("mem_mib must be >= 64"),
            "error should surface config's typed floor message, got: {err}"
        );
        // The documented floor itself is accepted.
        let ok = <Args as clap::Parser>::parse_from(["bench-vm", "--mem-mib", "64"]);
        assert!(validate_vm_params(&ok).is_ok());
    }
}
