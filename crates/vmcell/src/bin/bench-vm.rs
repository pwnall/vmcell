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
    /// `Timeouts` preset applied to every VM in the run. An unknown value is
    /// rejected at parse time (no silent default — H-BIN-1).
    #[arg(long, default_value = "default", value_parser = parse_profile)]
    profile: String,

    /// Guest kernel console verbosity: `balanced` (default, `loglevel=6`),
    /// `quiet` (3), `verbose` (7), or `debug` (8). Drives the serial-logging
    /// VM-exit cost dimension. An unknown value is rejected at parse time.
    #[arg(long, default_value = "balanced", value_parser = parse_verbosity)]
    kernel_verbosity: vmcell::config::KernelVerbosity,

    /// Guest console mode: `uart` (default, 8250 `ttyS0` — early-boot + panic
    /// capture, per-byte VM-exits) or `virtio-console` (`hvc0` — batched, ~no exit
    /// tax, but loses early boot / pre-virtio panics; not supported on Firecracker).
    /// An unknown value is rejected at parse time.
    #[arg(long, default_value = "uart", value_parser = parse_console)]
    console: vmcell::config::ConsoleMode,
}

/// Validates the `--profile` flag, rejecting any value other than `default`,
/// `low-latency`, or `throughput` (H-BIN-1). Returns the validated name unchanged so
/// the run header can echo it; [`timeouts_for`] maps it to the preset.
fn parse_profile(s: &str) -> Result<String, String> {
    match s {
        "default" | "low-latency" | "throughput" => Ok(s.to_string()),
        other => Err(format!(
            "invalid profile '{other}' (expected: default, low-latency, throughput)"
        )),
    }
}

/// Maps the (already-validated by [`parse_profile`]) `--profile` name to a
/// [`Timeouts`](vmcell::config::Timeouts) preset.
fn timeouts_for(profile: &str) -> vmcell::config::Timeouts {
    match profile {
        "low-latency" => vmcell::config::Timeouts::low_latency(),
        "throughput" => vmcell::config::Timeouts::throughput(),
        // Only `"default"` reaches here for a validated flag; the catch-all keeps
        // the mapping total (the CLI value_parser is the actual gate).
        _ => vmcell::config::Timeouts::default(),
    }
}

/// Parses the `--kernel-verbosity` flag into a
/// [`KernelVerbosity`](vmcell::config::KernelVerbosity), rejecting unknown values
/// (H-BIN-1) instead of silently defaulting to `Balanced`.
fn parse_verbosity(s: &str) -> Result<vmcell::config::KernelVerbosity, String> {
    use vmcell::config::KernelVerbosity as K;
    match s {
        "quiet" => Ok(K::Quiet),
        "balanced" => Ok(K::Balanced),
        "verbose" => Ok(K::Verbose),
        "debug" => Ok(K::Debug),
        other => Err(format!(
            "invalid kernel-verbosity '{other}' (expected: quiet, balanced, verbose, debug)"
        )),
    }
}

/// Parses the `--console` flag into a [`ConsoleMode`](vmcell::config::ConsoleMode),
/// rejecting unknown values (H-BIN-1) instead of silently defaulting to `Uart`.
fn parse_console(s: &str) -> Result<vmcell::config::ConsoleMode, String> {
    use vmcell::config::ConsoleMode as C;
    match s {
        "uart" => Ok(C::Uart),
        "virtio-console" => Ok(C::VirtioConsole),
        other => Err(format!(
            "invalid console '{other}' (expected: uart, virtio-console)"
        )),
    }
}

/// The run-header line echoing the resolved `--profile`/`--kernel-verbosity`/
/// `--console` knobs (H-BIN-1), so a run's actual configuration is visible rather
/// than silently defaulted.
fn resolved_knobs_line(args: &Args) -> String {
    format!(
        "profile: {}  kernel-verbosity: {:?}  console: {:?}",
        args.profile, args.kernel_verbosity, args.console
    )
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

/// Formats the trailing `dropped=/warmup_failed=` accounting for a report line so a
/// silently-shrunk sample count is visible (H-BIN-2). Empty when nothing was dropped.
fn accounting_suffix(dropped: usize, warmup_failed: usize) -> String {
    if dropped == 0 && warmup_failed == 0 {
        String::new()
    } else {
        format!(" dropped={dropped} warmup_failed={warmup_failed}")
    }
}

/// Reports p50/p95/p99/max for a sample set, collapsed onto the single [`pcts`]
/// helper (L-BIN-7) instead of a duplicate hand-rolled `floor` index that lacked the
/// nearest-rank clamp (H-BIN-1-revisited). `dropped`/`warmup_failed` surface any
/// iterations discarded during collection.
fn report(name: &str, latencies: &mut [u128], dropped: usize, warmup_failed: usize) {
    let acct = accounting_suffix(dropped, warmup_failed);
    match pcts(latencies) {
        Some((p50, p95, p99, max)) => println!(
            "{name}: count={}{acct} p50={p50}ms p95={p95}ms p99={p99}ms max={max}ms",
            latencies.len()
        ),
        None => println!("{name}: No successful runs{acct}"),
    }
}

async fn run_bench<V: Vmm>(
    vmm: &V,
    name: &str,
    args: &Args,
    allocator: VmidAllocator,
    is_restore: bool,
) -> anyhow::Result<()> {
    println!("Starting benchmark: {name}");
    let mut latencies = Vec::new();

    // L-BIN-7: resolve artifact paths and build the VM config through the SAME
    // helpers every other mode uses, instead of a hand-rolled duplicate that could
    // drift (it lacked `ksm_mergeable`, and re-derived the config knobs).
    let (dir, kernel_path, rootfs_path) = artifact_paths(args.kernel.as_deref());

    // Fail LOUD (M-BIN-1) rather than exit-0 when the artifacts are absent: the
    // harness measured nothing, so automation must not read it as success. Still
    // KVM-independent — we check before booting, which would otherwise hang on the
    // agent-connect timeout.
    if !kernel_path.exists() || !rootfs_path.exists() {
        println!("{name}: No successful runs (missing artifacts in {dir})");
        anyhow::bail!("{name}: missing artifacts in {dir}");
    }

    let cfg = build_cfg(args, kernel_path, rootfs_path, false);
    let cid_allocator = std::sync::Arc::new(CidAllocator::new());

    // CLI-5 / N-BIN-5: honor `--snap-dir` for the warm-restore snapshot, resolved on
    // the workspace root (not the process CWD) so it lands on the same real FS as the
    // artifacts, instead of `temp_dir()` (commonly tmpfs / RAM-backed), which makes
    // warm-restore latency systematically optimistic (§13.1 snap-dir caveat).
    let snap_dir = resolve_snap_dir(&args.snap_dir).join(format!(
        "latency-{}-{}",
        args.backend,
        std::process::id()
    ));
    if is_restore && is_tmpfs(&snap_dir) {
        println!(
            "warning: snap-dir {} is on tmpfs; warm-restore latency will be optimistic (§13.1)",
            snap_dir.display()
        );
    }
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
            // M-BIN-1: a baseline-snapshot failure is an attempted-and-failed run, not
            // a skip — fail loud so it can't masquerade as success.
            Err(e) => anyhow::bail!("{name}: failed to start base VM for snapshotting: {e}"),
        };
        if let Err(e) = base_vm.agent(None, &vmcell::orchestrator::RealClock).await {
            // Best-effort graceful teardown of the base VM; `MicroVm::Drop` is the
            // real, guaranteed teardown, so a shutdown error is not actionable here.
            let _ = base_vm.shutdown().await;
            anyhow::bail!("{name}: failed to connect to base VM agent: {e}");
        }
        if let Err(e) = std::fs::create_dir_all(&snap_dir) {
            // Best-effort teardown of the booted base VM before bailing.
            let _ = base_vm.shutdown().await;
            anyhow::bail!(
                "{name}: cannot create snapshot dir {}: {e}",
                snap_dir.display()
            );
        }
        if let Err(e) = base_vm.snapshot(&snap_dir).await {
            // Best-effort cleanup on the snapshot-failure path: shut the base VM down
            // (Drop is the real teardown) and drop the partial snapshot dir.
            let _ = base_vm.shutdown().await;
            let _ = std::fs::remove_dir_all(&snap_dir);
            anyhow::bail!("{name}: failed to take snapshot of base VM: {e}");
        }
        // Best-effort graceful shutdown of the base VM now that the snapshot is taken;
        // `MicroVm::Drop` guarantees the real teardown regardless.
        let _ = base_vm.shutdown().await;
    }

    // Tracks whether every cold-boot iteration managed to drop the page cache.
    // M-BIN-8: under the file-cap runner (euid != 0) the `drop_caches` write is
    // silently ineffective (the procfs sysctl permission is euid-based), so
    // `drop_page_cache` verifies via a `Cached`-drop check rather than trusting the
    // write. If any iteration could not actually drop the cache, the cold numbers are
    // warm-cache and the label says so instead of mislabeling them.
    let mut page_cache_dropped = true;
    // H-BIN-2: post-warmup agent-connect failures shrink the sample set — count and
    // print them (with the iteration + error) instead of letting the count silently
    // drop. Warmup failures are tracked separately since they never count as samples.
    let mut dropped = 0usize;
    let mut warmup_failed = 0usize;

    for i in 0..(args.iters() + args.warmup) {
        if !is_restore && !drop_page_cache() {
            page_cache_dropped = false;
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
                match vm.agent(None, &vmcell::orchestrator::RealClock).await {
                    Ok(_agent) => {
                        let elapsed = start.elapsed().as_millis();
                        if i >= args.warmup {
                            latencies.push(elapsed);
                        }
                    }
                    Err(e) => {
                        // H-BIN-2: a silent `if let Ok(_agent)` hid agent-connect
                        // failures; surface each and account for the discarded sample.
                        println!("{name}: iteration {i} agent-connect failed: {e}");
                        if i >= args.warmup {
                            dropped += 1;
                        } else {
                            warmup_failed += 1;
                        }
                    }
                }
                // Best-effort per-iteration teardown; `Drop` is the guaranteed path,
                // and a shutdown error must not corrupt the latency sample above.
                let _ = vm.shutdown().await;
            }
            Err(e) => {
                println!("{name}: iteration {i} create/restore failed: {e}");
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
        dropped,
        warmup_failed,
    );

    // M-BIN-1: attempted the run but collected zero post-warmup samples → fail loud so
    // automation sees a non-zero exit instead of a silent "No successful runs".
    if latencies.is_empty() {
        anyhow::bail!("{name}: no successful post-warmup samples");
    }
    Ok(())
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
    // H-BIN-1: echo the resolved profile/verbosity/console so a run's actual knobs
    // are visible (and provably not silently defaulted from a rejected typo).
    println!("{}", resolved_knobs_line(&args));

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
/// floor — as a clear, non-panicking error, and rejects `--count 0` (N-BIN-2),
/// which the `footprint` mode would otherwise silently clamp to 1.
fn validate_vm_params(args: &Args) -> anyhow::Result<()> {
    // N-BIN-2: reject `--count 0` loudly rather than silently clamping to 1 — a run
    // that measures zero guests is a misinvocation, not a request for one guest.
    if args.count == 0 {
        anyhow::bail!("--count must be >= 1 (0 guests measures nothing)");
    }
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
            run_bench(vmm, "Cold Boot", args, allocator.clone(), false).await?;
            if vmm.capabilities().snapshot_restore {
                run_bench(vmm, "Warm Restore", args, allocator.clone(), true).await?;
            } else {
                // CLI-4 / §13.2 visible-skip: a no-snapshot backend (e.g. FC/QEMU in
                // the unprivileged+vsock tier, §3.3) can't run Warm Restore. Print the
                // reason rather than silently dropping the benchmark; a genuine
                // capability skip is success (Ok), not a failure (M-BIN-1).
                println!("Warm Restore: backend {backend} has no snapshot support; skipping");
            }
            Ok(())
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

/// The workspace root, so `--snap-dir` anchors independent of the process CWD
/// (N-BIN-5). Mirrors the library's `workspace_root` ascent (the `vmcell-protocol`
/// marker); the library's is `pub(crate)` so it cannot be reused here — see the
/// integrator note to expose it publicly and collapse this duplicate.
fn workspace_root() -> PathBuf {
    let start = std::env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    for dir in start.ancestors() {
        if dir.join("crates/vmcell-protocol/Cargo.toml").is_file() {
            return dir.to_path_buf();
        }
    }
    start
}

/// Resolves `--snap-dir` to an absolute, CWD-independent path anchored on the
/// workspace root (N-BIN-5): artifacts anchor there too (§11), so an out-of-root
/// invocation must not measure a *different* filesystem for the warm-restore snapshot
/// than for the artifacts. An absolute `--snap-dir` is honored verbatim.
fn resolve_snap_dir(raw: &str) -> PathBuf {
    let p = PathBuf::from(raw);
    if p.is_absolute() {
        p
    } else {
        workspace_root().join(p)
    }
}

/// The filesystem type backing `path`, per the longest mount-point prefix in a
/// `/proc/self/mountinfo` dump. Factored out (pure) so the tmpfs check is testable
/// without a real mount table (N-BIN-5).
fn path_fstype(mountinfo: &str, path: &Path) -> Option<String> {
    let mut best_len = 0usize;
    let mut best: Option<String> = None;
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Optional fields precede a `-` separator; mount point is field 4, fstype is
        // the first field after the separator.
        let Some(sep) = fields.iter().position(|f| *f == "-") else {
            continue;
        };
        let (Some(mp), Some(fstype)) = (fields.get(4), fields.get(sep + 1)) else {
            continue;
        };
        let mp = PathBuf::from(mp);
        if path.starts_with(&mp) {
            let len = mp.as_os_str().len();
            // `>=` so a longer (more specific) mount wins ties against the root `/`.
            if len >= best_len {
                best_len = len;
                best = Some((*fstype).to_string());
            }
        }
    }
    best
}

/// Best-effort check whether `path` lives on a tmpfs mount (RAM-backed), which makes
/// warm-restore latency systematically optimistic (§13.1). Consults
/// `/proc/self/mountinfo`; a non-Linux/unreadable table degrades to `false`.
fn is_tmpfs(path: &Path) -> bool {
    let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    match std::fs::read_to_string("/proc/self/mountinfo") {
        Ok(mi) => path_fstype(&mi, &canon).as_deref() == Some("tmpfs"),
        Err(_) => false,
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
/// applying the run's `--mem-mib`, `--restore-mode`, `--profile` timeouts,
/// `--kernel-verbosity`, and `--console` from `args`. `ksm_mergeable` stays an
/// explicit argument because only `footprint` opts into it (§13.5); every other
/// mode passes `false`.
fn build_cfg(args: &Args, kernel: PathBuf, rootfs: PathBuf, ksm_mergeable: bool) -> VmConfig {
    VmConfig::builder(kernel, RootfsSource::Erofs { image: rootfs })
        .vcpus(1)
        .mem_mib(args.mem_mib)
        .network_disabled()
        .restore_mode(args.restore_mode)
        .ksm_mergeable(ksm_mergeable)
        .timeouts(timeouts_for(&args.profile))
        .kernel_verbosity(args.kernel_verbosity)
        .console_mode(args.console)
        .build()
        .expect("valid VM configuration benchmark invariant")
}

/// Reads a `/proc/meminfo` field in kB (`None` if unreadable/absent).
fn read_meminfo_kb(key: &str) -> Option<u64> {
    let s = std::fs::read_to_string("/proc/meminfo").ok()?;
    parse_kv_kb(&s, key)
}

/// Decides whether a `drop_caches` attempt actually took effect (M-BIN-8). A write
/// that "succeeds" but leaves `Cached` untouched is a warm cache — the permission was
/// silently ignored under the file-cap runner (euid != 0) — so only a real decrease in
/// `Cached` (or no cache to begin with) counts as cold.
fn cache_drop_effective(
    wrote: bool,
    cached_before: Option<u64>,
    cached_after: Option<u64>,
) -> bool {
    if !wrote {
        return false;
    }
    match (cached_before, cached_after) {
        // There was page cache to drop: require it to have actually shrunk.
        (Some(before), Some(after)) if before > 0 => after < before,
        // No prior cache (already cold) or meminfo unreadable → trust the write.
        _ => true,
    }
}

/// Drops the host page cache and verifies it took effect. Opens write-only (no
/// `O_CREAT`/`O_TRUNC`): `O_TRUNC` on a procfs sysctl is rejected even with
/// `CAP_DAC_OVERRIDE`, which silently broke the original `std::fs::write` cold path.
/// Returns true only if the write succeeds AND `Cached` actually dropped — a
/// successful-but-ineffective write (euid != 0 under the file-cap runner) is still a
/// warm cache and is flagged as such (M-BIN-8), rather than trusting write success.
fn drop_page_cache() -> bool {
    use std::io::Write;
    let before = read_meminfo_kb("Cached");
    let wrote = match std::fs::OpenOptions::new()
        .write(true)
        .open("/proc/sys/vm/drop_caches")
    {
        Ok(mut f) => f.write_all(b"3\n").is_ok(),
        Err(_) => false,
    };
    cache_drop_effective(wrote, before, read_meminfo_kb("Cached"))
}

/// p50/p95/p99/max of a sample set via the **nearest-rank** method: index
/// `ceil(q*n) - 1`, clamped to `[0, n-1]` (H-BIN-1-revisited). The old `floor(q*n)`
/// was one rank too high whenever `q*n` is integral — at N=20, `floor(20*0.95)=19`
/// returned the sample MAXIMUM as p95, so p95 and max were always identical.
fn pcts(latencies: &mut [u128]) -> Option<(u128, u128, u128, u128)> {
    if latencies.is_empty() {
        return None;
    }
    latencies.sort_unstable();
    let n = latencies.len();
    let last = n - 1;
    let idx = |q: f64| ((n as f64 * q).ceil() as usize).saturating_sub(1).min(last);
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
        if let Some(k) = it.next()
            && k.trim_end_matches(':') == key
            && let Some(v) = it.next()
            && let Ok(n) = v.parse::<u64>()
        {
            return Some(n);
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
///
/// M-BIN-7: several processes can share that per-VM dir on the command line — on
/// QEMU the `vhost-device-vsock` daemon is spawned (with a *lower* pid) before the
/// VMM and carries the same socket dir, so a plain first-match measures the wrong
/// process. Prefer the process whose cmdline also names the VMM binary (`vmm_hint`,
/// e.g. `cloud-hypervisor` / `qemu` / `firecracker`); only fall back to a dir-only
/// match (e.g. the vsock daemon) when no candidate names the VMM.
fn find_host_pid(vsock: &Path, vmm_hint: &str) -> Option<u32> {
    let parent = vsock
        .parent()
        .unwrap_or(vsock)
        .to_string_lossy()
        .to_string();
    let needle = format!("{parent}/");
    let full = vsock.to_string_lossy().to_string();
    let me = std::process::id();
    let mut fallback = None;
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
                if s.contains(vmm_hint) {
                    // The actual VMM process — the one whose guest RAM we want.
                    return Some(pid);
                }
                // A dir-sharing helper (e.g. the vsock daemon); use only if nothing
                // better turns up.
                fallback.get_or_insert(pid);
            }
        }
    }
    fallback
}

/// The `(anon, shmem)` report annotations for a backend's guest-RAM memory model
/// (M-BIN-7): CH backs guest RAM with a shared memfd (accounted as `RssShmem`), while
/// Firecracker uses private anonymous guest RAM (accounted as `RssAnon`), so the
/// hard-coded CH-only labels would invert the reading on FC.
fn footprint_mem_notes(backend: &str) -> (&'static str, &'static str) {
    match backend {
        "cloud-hypervisor" => (
            "VMM overhead; guest RAM is shmem on CH",
            "CH guest-RAM memfd; the real density figure",
        ),
        "firecracker" => (
            "VMM overhead + private-anon guest RAM on Firecracker (the real density figure)",
            "shared shmem (minimal on FC; guest RAM is the anon line above)",
        ),
        _ => (
            "RssAnon: VMM overhead / anon guest RAM (backend-dependent)",
            "RssShmem: shared guest RAM, if the backend uses a memfd (backend-dependent)",
        ),
    }
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
        if let Ok(agent) = vm.agent(None, &vmcell::orchestrator::RealClock).await
            && let Ok(o) = agent.exec(ExecRequest::new(c.clone())).await
            && o.code == 0
        {
            return c;
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
async fn run_footprint<V: Vmm>(
    vmm: &V,
    backend: &str,
    args: &Args,
    allocator: VmidAllocator,
) -> anyhow::Result<()> {
    let (dir, kernel, rootfs) = artifact_paths(args.kernel.as_deref());
    if !kernel.exists() || !rootfs.exists() {
        println!("footprint: No successful runs (missing artifacts in {dir})");
        anyhow::bail!("footprint: missing artifacts in {dir}");
    }
    // N-BIN-2: `--count 0` is rejected loudly in `validate_vm_params`, so `count` is
    // >= 1 here (no silent `.max(1)` clamp).
    let count = args.count;
    let cfg = build_cfg(args, kernel, rootfs, args.ksm_mergeable);
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
            if let Some(pid) = find_host_pid(v.instance().vsock_path(), backend) {
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
        anyhow::bail!("footprint: no guests booted");
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
    // M-BIN-7: count how many per-VM host pids actually resolved, so an unresolved
    // process (collapsed to 0 by `unwrap_or(0)`) is visible instead of silently
    // deflating the reported totals.
    let mut resolved = 0usize;
    for v in vms.iter_mut() {
        let vsock = v.instance().vsock_path().to_path_buf();
        if let Some(pid) = find_host_pid(&vsock, backend) {
            resolved += 1;
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

    let (anon_note, shmem_note) = footprint_mem_notes(backend);
    println!(
        "=== FOOTPRINT (backend={backend} N={n} mem_mib={}) ===",
        args.mem_mib
    );
    // M-BIN-7: surface incomplete host-pid attribution instead of silently reporting
    // deflated totals as if every VM resolved.
    if resolved < n {
        println!(
            "footprint: warning — resolved {resolved}/{n} host pids; per-VM memory attribution is incomplete"
        );
    }
    println!(
        "host RssAnon total = {} MiB  (per-guest mean = {} MiB)  [{anon_note}]",
        tot_anon / 1024,
        (tot_anon / 1024) / n as u64
    );
    println!(
        "host RssFile total = {} MiB  (per-guest mean = {} MiB)  [shared-erofs page cache]",
        tot_file / 1024,
        (tot_file / 1024) / n as u64
    );
    println!(
        "host RssShmem total = {} MiB  (per-guest mean = {} MiB)  [{shmem_note}]",
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
    if args.ksm_mergeable {
        // N-BIN-2: restoring `run`/`pages_to_scan` re-disables the scanner but does
        // NOT un-merge pages already deduped during this run, so the host KSM state is
        // not byte-for-byte what it was before. Say so rather than imply a full reset.
        println!(
            "KSM note: the scanner knobs were restored, but pages merged during this run stay merged (host KSM state is not fully reset)"
        );
    }
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
    Ok(())
}

// ----------------------------------------------------------------------------
// §13.6 — suspend-size: snapshot bytes + memory-file share, vs guest RAM.
// ----------------------------------------------------------------------------
async fn run_suspend_size<V: Vmm>(
    vmm: &V,
    backend: &str,
    args: &Args,
    allocator: VmidAllocator,
) -> anyhow::Result<()> {
    let (dir, kernel, rootfs) = artifact_paths(args.kernel.as_deref());
    if !kernel.exists() || !rootfs.exists() {
        println!("suspend-size: No successful runs (missing artifacts in {dir})");
        anyhow::bail!("suspend-size: missing artifacts in {dir}");
    }
    if !vmm.capabilities().snapshot_restore {
        // Genuine capability skip → success (M-BIN-1), not a failure.
        println!("suspend-size: backend {backend} has no snapshot support; skipping");
        return Ok(());
    }
    let cfg = build_cfg(args, kernel, rootfs, false);
    let cid = std::sync::Arc::new(CidAllocator::new());
    let snap_dir = resolve_snap_dir(&args.snap_dir).join(format!(
        "suspend-{backend}-{}-{}",
        args.mem_mib,
        std::process::id()
    ));
    // Best-effort pre-clean of a stale snapshot dir from a prior aborted run.
    let _ = std::fs::remove_dir_all(&snap_dir);
    if let Err(e) = std::fs::create_dir_all(&snap_dir) {
        anyhow::bail!(
            "suspend-size: cannot create snap dir {}: {e}",
            snap_dir.display()
        );
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
            // Best-effort removal of the (empty) snapshot dir before bailing.
            let _ = std::fs::remove_dir_all(&snap_dir);
            anyhow::bail!("suspend-size: boot failed: {e}");
        }
    };
    if let Err(e) = vm.agent(None, &vmcell::orchestrator::RealClock).await {
        // Best-effort teardown + snapshot-dir cleanup; `Drop` guarantees the real
        // teardown and neither cleanup error is actionable.
        let _ = vm.shutdown().await;
        let _ = std::fs::remove_dir_all(&snap_dir);
        anyhow::bail!("suspend-size: agent connect failed: {e}");
    }
    if let Err(e) = vm.snapshot(&snap_dir).await {
        // Best-effort teardown + partial-snapshot cleanup on the failure path.
        let _ = vm.shutdown().await;
        let _ = std::fs::remove_dir_all(&snap_dir);
        anyhow::bail!("suspend-size: snapshot failed: {e}");
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
    Ok(())
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
    base.snapshot(snap_dir).await.map_err(|e| e.to_string())?;
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
) -> anyhow::Result<()> {
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
        anyhow::bail!("phase-budget {label} ({backend}): no successful post-warmup samples");
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
    Ok(())
}

async fn run_phase_budget<V: Vmm>(
    vmm: &V,
    backend: &str,
    args: &Args,
    allocator: VmidAllocator,
) -> anyhow::Result<()> {
    let (dir, kernel, rootfs) = artifact_paths(args.kernel.as_deref());
    if !kernel.exists() || !rootfs.exists() {
        println!("phase-budget: No successful runs (missing artifacts in {dir})");
        anyhow::bail!("phase-budget: missing artifacts in {dir}");
    }
    let cfg = build_cfg(args, kernel, rootfs, false);
    let cid = std::sync::Arc::new(CidAllocator::new());

    // Cold-boot path (opt-in budget). A zero-sample cold path is an attempted-and-
    // failed run → propagate (M-BIN-1).
    phase_budget_path(
        vmm,
        backend,
        args,
        &cfg,
        cid.clone(),
        allocator.clone(),
        None,
    )
    .await?;

    // Restore path (the hot path) — build the baseline snapshot once.
    if vmm.capabilities().snapshot_restore {
        let snap_dir = resolve_snap_dir(&args.snap_dir)
            .join(format!("phase-{backend}-{}", std::process::id()));
        // Best-effort pre-clean of a stale snapshot dir from a prior aborted run.
        let _ = std::fs::remove_dir_all(&snap_dir);
        if let Err(e) = std::fs::create_dir_all(&snap_dir) {
            anyhow::bail!("phase-budget: cannot create snap dir: {e}");
        }
        let baseline =
            build_baseline_snapshot(vmm, &cfg, cid.clone(), allocator.clone(), &snap_dir).await;
        let restore_res = match baseline {
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
                .await
            }
            Err(e) => Err(anyhow::anyhow!(
                "phase-budget: baseline snapshot failed: {e}"
            )),
        };
        // Best-effort cleanup of the baseline snapshot dir after the restore budget,
        // regardless of whether the restore path succeeded.
        let _ = std::fs::remove_dir_all(&snap_dir);
        restore_res?;
    } else {
        // Genuine capability skip → success; the cold path already ran.
        println!("phase-budget: backend {backend} has no restore; cold path only");
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// §13.5 — vsock-rtt: control-plane exec round-trip latency floor.
// ----------------------------------------------------------------------------
async fn run_vsock_rtt<V: Vmm>(
    vmm: &V,
    backend: &str,
    args: &Args,
    allocator: VmidAllocator,
) -> anyhow::Result<()> {
    let (dir, kernel, rootfs) = artifact_paths(args.kernel.as_deref());
    if !kernel.exists() || !rootfs.exists() {
        println!("vsock-rtt: No successful runs (missing artifacts in {dir})");
        anyhow::bail!("vsock-rtt: missing artifacts in {dir}");
    }
    let cfg = build_cfg(args, kernel, rootfs, false);
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
        Err(e) => anyhow::bail!("vsock-rtt: boot failed: {e}"),
    };
    if let Err(e) = vm.agent(None, &vmcell::orchestrator::RealClock).await {
        // Best-effort teardown before bailing; `Drop` guarantees teardown.
        let _ = vm.shutdown().await;
        anyhow::bail!("vsock-rtt: agent connect failed: {e}");
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
    // H-BIN-2: count exec failures that shrink the sample set instead of the silent
    // `if r.is_ok()` drop, and surface the error rather than a bare `break`.
    let mut dropped = 0usize;
    for i in 0..iters {
        let agent = match vm.agent(None, &vmcell::orchestrator::RealClock).await {
            Ok(a) => a,
            Err(e) => {
                println!("vsock-rtt: iteration {i} agent-connect failed: {e}");
                break;
            }
        };
        let t = Instant::now();
        let r = agent.exec(ExecRequest::new(argv.clone())).await;
        let dt = t.elapsed().as_micros();
        match r {
            Ok(_) => rtts.push(dt),
            Err(e) => {
                println!("vsock-rtt: iteration {i} exec failed: {e}");
                dropped += 1;
            }
        }
    }
    // Best-effort teardown after the run; `Drop` guarantees the real teardown, so a
    // shutdown error must not corrupt the collected RTT report below.
    let _ = vm.shutdown().await;

    let acct = accounting_suffix(dropped, 0);
    println!(
        "=== VSOCK-RTT (backend={backend} n={}{acct} cmd={argv:?}) ===",
        rtts.len()
    );
    match pcts(&mut rtts) {
        Some((p50, p95, p99, max)) => {
            println!(
                "  per-round-trip exec latency: p50={p50}µs p95={p95}µs p99={p99}µs max={max}µs"
            );
            Ok(())
        }
        None => {
            println!("  No successful runs");
            // M-BIN-1: attempted but zero samples → fail loud.
            anyhow::bail!("vsock-rtt: no successful exec round-trips");
        }
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

    // N-BIN-2: `--count 0` was silently clamped to 1 by `args.count.max(1)`. RED on
    // the inverse (silent clamp / no check): the count-0 case returns `Ok`.
    #[test]
    fn validate_vm_params_rejects_zero_count() {
        let bad = <Args as clap::Parser>::parse_from(["bench-vm", "--count", "0"]);
        assert!(validate_vm_params(&bad).is_err());
        let ok = <Args as clap::Parser>::parse_from(["bench-vm", "--count", "1"]);
        assert!(validate_vm_params(&ok).is_ok());
    }

    // H-BIN-1-revisited: `report`/`pcts` used `floor(q*n)`, one rank too high when
    // `q*n` is integral — at N=20 it returned index 19 (the MAX) for p95. Nearest-rank
    // `ceil(q*n)-1` gives p50=10, p95=19, p99=20. RED on the old `floor` impl (which
    // yields p50=11, p95=20).
    #[test]
    fn percentile_nearest_rank_correctness() {
        let mut v: Vec<u128> = (1..=20).collect();
        let (p50, p95, p99, max) = pcts(&mut v).expect("non-empty sample set");
        assert_eq!(p50, 10, "p50 nearest-rank");
        assert_eq!(p95, 19, "p95 nearest-rank (NOT the max)");
        assert_eq!(p99, 20, "p99 nearest-rank");
        assert_eq!(max, 20, "max is the last element");
        // Degenerate sizes stay in-bounds.
        assert_eq!(pcts(&mut [7u128]), Some((7, 7, 7, 7)));
        assert_eq!(pcts(&mut []), None);
    }

    // H-BIN-2: dropped/warmup-failed iterations silently shrank the reported count.
    // RED on the inverse (a suffix that is always empty): the `dropped=5` assert fails.
    #[test]
    fn accounting_suffix_surfaces_drops() {
        assert_eq!(accounting_suffix(0, 0), "");
        let s = accounting_suffix(5, 2);
        assert!(s.contains("dropped=5"), "got {s}");
        assert!(s.contains("warmup_failed=2"), "got {s}");
    }

    // M-BIN-8: the cold label trusted the `drop_caches` write's success alone, so a
    // silently-ineffective write (euid != 0) mislabeled a warm cache as cold. RED on
    // the inverse (`fn(...) -> wrote`): the (wrote, unchanged-Cached) case returns true.
    #[test]
    fn cache_drop_effective_flags_ineffective_write() {
        // Write failed → not effective (warm).
        assert!(!cache_drop_effective(false, Some(100), Some(10)));
        // Write "succeeded" but Cached did not drop → ineffective (warm).
        assert!(!cache_drop_effective(true, Some(100), Some(100)));
        // Write succeeded and Cached dropped → effective (cold).
        assert!(cache_drop_effective(true, Some(100), Some(10)));
        // No prior cache (already cold) → trivially effective.
        assert!(cache_drop_effective(true, Some(0), Some(0)));
    }

    // M-BIN-7: the footprint host-RAM annotations were hard-coded CH memfd/shmem
    // terms, which invert on Firecracker (private anon guest RAM). RED on the inverse
    // (always the CH strings): the FC anon assertion and the CH != FC assertion fail.
    #[test]
    fn footprint_notes_are_backend_specific() {
        let (_a_ch, s_ch) = footprint_mem_notes("cloud-hypervisor");
        assert!(s_ch.contains("memfd"), "CH shmem note should mention memfd");
        let (a_fc, s_fc) = footprint_mem_notes("firecracker");
        assert!(
            a_fc.to_lowercase().contains("anon"),
            "FC anon note should mention anon, got: {a_fc}"
        );
        assert_ne!(s_ch, s_fc, "CH and FC shmem notes must differ");
    }

    // H-BIN-1: `--profile`/`--kernel-verbosity`/`--console` silently defaulted on an
    // unknown value (the `_ => default` arms). RED on the inverse (accept-all
    // parser): the typo `is_err` asserts fail. Note the underscore spelling
    // `low_latency` (vs the hyphenated flag) is a real, rejected typo.
    #[test]
    fn cli_enum_parsers_reject_typos() {
        assert!(parse_profile("low_latency").is_err()); // underscore typo
        assert!(parse_profile("throughputt").is_err());
        assert!(parse_profile("low-latency").is_ok());
        assert!(parse_profile("default").is_ok());
        assert!(parse_profile("throughput").is_ok());

        assert!(parse_console("virtio_console_typo").is_err());
        assert!(parse_console("virtio-console").is_ok());
        assert!(parse_console("uart").is_ok());

        assert!(parse_verbosity("balancedd").is_err());
        assert!(parse_verbosity("quiet").is_ok());
        assert!(parse_verbosity("debug").is_ok());
    }

    // H-BIN-1: the run header now echoes the resolved knobs. RED on the inverse (no
    // echo / hard-coded defaults): the resolved values would be absent from the line.
    #[test]
    fn header_echoes_resolved_knobs() {
        let a = <Args as clap::Parser>::parse_from([
            "bench-vm",
            "--profile",
            "low-latency",
            "--console",
            "virtio-console",
        ]);
        let line = resolved_knobs_line(&a);
        assert!(line.contains("profile: low-latency"), "{line}");
        assert!(line.contains("VirtioConsole"), "{line}");
    }

    // N-BIN-5: the tmpfs check must match the LONGEST mount-point prefix, not the
    // first (`/` matches every absolute path). RED on the inverse (first-match): the
    // nested `/home/x/target/snap` path resolves to the root `ext4` instead of tmpfs.
    #[test]
    fn path_fstype_uses_longest_mount_prefix() {
        let mi = "\
1 0 8:1 / / rw shared:1 - ext4 /dev/sda1 rw
2 0 0:22 / /dev/shm rw shared:2 - tmpfs tmpfs rw
3 0 0:23 / /home/x/target rw shared:3 - tmpfs tmpfs rw
";
        assert_eq!(
            path_fstype(mi, Path::new("/dev/shm/snap")).as_deref(),
            Some("tmpfs")
        );
        assert_eq!(
            path_fstype(mi, Path::new("/var/data")).as_deref(),
            Some("ext4")
        );
        assert_eq!(
            path_fstype(mi, Path::new("/home/x/target/vmcell-bench-snap")).as_deref(),
            Some("tmpfs")
        );
    }
}
