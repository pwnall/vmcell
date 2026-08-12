//! `bench-vm`: the cross-backend macro-benchmark harness (design §16, Performance). The composition
//! root that wires all four backends — Cloud Hypervisor, Firecracker, QEMU, crosvm — behind one
//! `--backend` flag, so a lever is measured the same way everywhere.
//!
//! `print_stdout`/`print_stderr` are intentionally NOT denied here — emitting the measured tables
//! and the per-run report on stdout/stderr is the whole point of a benchmark harness.
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

use clap::Parser;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use std::time::Instant;

use vmcell::HostEnv;
use vmcell::agent::protocol::ExecRequest;
use vmcell::agent::session::SessionSpecBuilder;
use vmcell::config::{Egress, NetConfig, RestoreMode, RootfsSource, VmConfig};
use vmcell::orchestrator::{MicroVm, VmidAllocator};
use vmcell::vmm::{VmInstance, Vmm};

#[derive(Parser, Debug)]
#[command(author, version, about = "Macro-benchmarking harness for vmcell VMs")]
struct Args {
    #[arg(long, default_value = "cloud-hypervisor")]
    backend: String,

    /// Benchmark mode. `latency` preserves the original cold/warm boot bench.
    /// Others answer the design's open §16 (Performance) questions.
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
    /// optimistic (RAM-backed reads; design §16, Performance, snap-dir caveat).
    #[arg(long, default_value = "./target/vmcell-bench-snap")]
    snap_dir: String,

    /// Memory-restore strategy for the warm-restore path (CH `prefault`):
    /// `default` (VMM default), `eager` (`prefault=on`), or `lazy`
    /// (`prefault=off`, userfaultfd demand-paging). Drives the §16 (Performance)
    /// eager-vs-lazy benchmark; harmless for non-restore modes.
    #[arg(long, default_value = "default", value_parser = parse_restore_mode)]
    restore_mode: RestoreMode,

    /// Mark guest memory KSM-mergeable (CH `mergeable=on`, implies `shared=off`)
    /// so the `footprint` mode can measure KSM dedup (§16, Performance). Off by default.
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

    /// `net-egress` variant: `plain` (unprivileged smoltcp NAT + `Egress::Open` to a
    /// host responder — the datapath cost), `tls` (unprivileged smoltcp + `Egress::Filtered`
    /// MITM proxy, HTTPS-through-proxy — the per-connection cert-mint + guest↔proxy TLS
    /// handshake cost), or `privileged` (tap + netns + nft + `Egress::Filtered` — the
    /// privileged networked-start cost + the same MITM egress). `tls`/`privileged` need the
    /// `proxy` feature; `privileged` needs CAP_NET_ADMIN (self-skips otherwise). Ignored by
    /// other modes. An unknown value is rejected at parse time.
    #[arg(long, default_value = "plain", value_parser = parse_net_mode)]
    net_mode: String,
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

/// Validates `--net-mode` (the `net-egress` variant selector), rejecting unknown values
/// at parse time (H-BIN-1) instead of silently defaulting.
fn parse_net_mode(s: &str) -> Result<String, String> {
    match s {
        "plain" | "tls" | "privileged" => Ok(s.to_string()),
        other => Err(format!(
            "invalid net-mode '{other}' (expected: plain, tls, privileged)"
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

    let cfg = build_cfg(args, kernel_path, rootfs_path, false, is_restore);
    let mut env = HostEnv::hermetic();
    env.vmids = allocator.clone();

    // CLI-5 / N-BIN-5: honor `--snap-dir` for the warm-restore snapshot, resolved on
    // the workspace root (not the process CWD) so it lands on the same real FS as the
    // artifacts, instead of `temp_dir()` (commonly tmpfs / RAM-backed), which makes
    // warm-restore latency systematically optimistic (§16, Performance, snap-dir caveat).
    let snap_dir = resolve_snap_dir(&args.snap_dir).join(format!(
        "latency-{}-{}",
        args.backend,
        std::process::id()
    ));
    if is_restore && is_tmpfs(&snap_dir) {
        println!(
            "warning: snap-dir {} is on tmpfs; warm-restore latency will be optimistic (§16, Performance)",
            snap_dir.display()
        );
    }
    // Best-effort pre-clean of a stale snapshot dir left by a prior aborted run; a
    // missing dir (the common case) is not an error worth surfacing.
    let _ = std::fs::remove_dir_all(&snap_dir);

    if is_restore {
        println!("Creating baseline snapshot for restore benchmark...");
        let mut base_vm = match MicroVm::start(vmm, cfg.clone(), &env).await {
            Ok(vm) => vm,
            // M-BIN-1: a baseline-snapshot failure is an attempted-and-failed run, not
            // a skip — fail loud so it can't masquerade as success.
            Err(e) => anyhow::bail!("{name}: failed to start base VM for snapshotting: {e}"),
        };
        if let Err(e) = base_vm.agent(None).await {
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
            MicroVm::restore(vmm, &snap_dir, cfg.clone(), &env).await
        } else {
            MicroVm::start(vmm, cfg.clone(), &env).await
        };

        match vm_res {
            Ok(mut vm) => {
                match vm.agent(None).await {
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

    // Pin CPU frequency for the whole run (design §16, Performance, noise floor): every online
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

    // `daemon-api` drives an already-spawned `vmcelld` over HTTP — it needs no local `Vmm`,
    // so branch here (after the freq-pin engages, so the daemon's VM boots are freq-pinned)
    // before the per-backend VMM construction. It ignores `--backend` (the daemon is CH).
    if args.mode == "daemon-api" {
        return run_daemon_api(&args).await;
    }

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
            let vmm = vmcell_firecracker::Firecracker::new("firecracker");
            println!("Capabilities: {:?}", vmm.capabilities());
            run_mode(&vmm, "firecracker", &args, allocator.clone()).await?;
        }
        #[cfg(feature = "qemu")]
        "qemu" => {
            let vmm = vmcell_qemu::Qemu::new("qemu-system-x86_64");
            println!("Capabilities: {:?}", vmm.capabilities());
            run_mode(&vmm, "qemu", &args, allocator.clone()).await?;
        }
        #[cfg(feature = "crosvm")]
        "crosvm" => {
            let vmm = vmcell_crosvm::Crosvm::new("crosvm");
            println!("Capabilities: {:?}", vmm.capabilities());
            run_mode(&vmm, "crosvm", &args, allocator.clone()).await?;
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
        #[cfg(feature = "crosvm")]
        "crosvm",
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
    "net-egress",
    "zygote",
    "session",
    "daemon-api",
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
/// cold/warm behaviour exactly (the dry-test path); the rest answer §16 (Performance).
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
                // CLI-4 / §16 (Performance) visible-skip: a backend that does not advertise
                // `snapshot_restore` can't run Warm Restore (all three shipped backends now do,
                // §2.5, The capability matrix — this guards a re-gated or hypothetical backend).
                // Print the reason rather than silently dropping the benchmark; a genuine
                // capability skip is success (Ok), not a failure (M-BIN-1).
                println!("Warm Restore: backend {backend} has no snapshot support; skipping");
            }
            Ok(())
        }
        "footprint" => run_footprint(vmm, backend, args, allocator).await,
        "suspend-size" => run_suspend_size(vmm, backend, args, allocator).await,
        "phase-budget" => run_phase_budget(vmm, backend, args, allocator).await,
        "vsock-rtt" => run_vsock_rtt(vmm, backend, args, allocator).await,
        "net-egress" => run_net_egress(vmm, backend, args, allocator).await,
        "zygote" => run_zygote(vmm, backend, args, allocator).await,
        "session" => run_session(vmm, backend, args, allocator).await,
        other => anyhow::bail!(
            "unknown --mode '{other}' (valid: {})",
            VALID_MODES.join(", ")
        ),
    }
}

// ----------------------------------------------------------------------------
// Shared helpers for the §16 (Performance) benchmark modes.
// ----------------------------------------------------------------------------

/// The kernel artifact filename for an optional version label (`vmlinux` or
/// `vmlinux-<sanitized-label>`) — `vmcell`'s shared
/// [`kernel_filename`](vmcell::artifact::kernel::kernel_filename) law, so this harness resolves
/// exactly the names the producers write rather than re-encoding the `.`→`-` sanitization.
fn kernel_filename(label: Option<&str>) -> String {
    vmcell::artifact::kernel::kernel_filename(label)
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
/// workspace root (N-BIN-5): artifacts anchor there too (§10, The artifact build pipeline), so an out-of-root
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
/// warm-restore latency systematically optimistic (§16, Performance). Consults
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
/// explicit argument because only `footprint` opts into it (§16, Performance); every other
/// mode passes `false`.
fn build_cfg(
    args: &Args,
    kernel: PathBuf,
    rootfs: PathBuf,
    ksm_mergeable: bool,
    snapshotting: bool,
) -> VmConfig {
    VmConfig::builder(kernel, RootfsSource::Erofs { image: rootfs })
        .vcpus(1)
        .mem_mib(args.mem_mib)
        .network_disabled()
        // Snapshot-taking modes (warm-restore, suspend-size, phase-budget) mark the VM
        // snapshot-eligible, which for QEMU selects the in-kernel vhost-vsock transport
        // (§2.4); a no-op for CH/FC. Non-snapshot modes leave the default (QEMU's
        // external vhost-device-vsock), so a plain cold-boot benchmark needs no
        // `/dev/vhost-vsock` access. `network_disabled` (NetConfig::None) is
        // snapshot-compatible — it carries no vhost-user device.
        .snapshotting(snapshotting)
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
    // `.get()` rather than `[]`: the clamp above already proves every index in-bounds, so this is
    // the same values with no panic path to argue about — and no suppression to outlive its proof.
    Some((
        *latencies.get(idx(0.5))?,
        *latencies.get(idx(0.95))?,
        *latencies.get(idx(0.99))?,
        *latencies.get(last)?,
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
        // Probed 2026-07-17 (docs/benchmark-results.md): crosvm backs guest RAM with a memfd
        // accounted as `RssShmem` (the CH model — ~57 MiB/guest is the real density figure), with a
        // very light ~1 MiB/guest `RssAnon` VMM overhead (at the CH floor, far below QEMU's ~21).
        "crosvm" => (
            "VMM overhead; guest RAM is a shmem/memfd on crosvm (~1 MiB/guest — at the CH floor)",
            "crosvm guest-RAM memfd; the real density figure",
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
        if let Ok(agent) = vm.agent(None).await
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
// §16 (Performance) — footprint: per-guest RAM, shared erofs page cache, KSM dedup.
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
    let cfg = build_cfg(args, kernel, rootfs, args.ksm_mergeable, false);
    let mut env = HostEnv::hermetic();
    env.vmids = allocator.clone();

    let ksm_shared_before = read_ksm("pages_shared");
    let ksm_sharing_before = read_ksm("pages_sharing");

    // Boot guests one-by-one, holding them all alive in a Vec (so all N coexist),
    // and snapshot the *total* host RssAnon after each addition — this yields a
    // real marginal slope (step N minus step N-1) within a single invocation.
    let mut vms: Vec<MicroVm<V>> = Vec::new();
    let mut step_anon: Vec<u64> = Vec::new();
    let mut step_shmem: Vec<u64> = Vec::new();
    for i in 0..count {
        let mut vm = match MicroVm::start(vmm, cfg.clone(), &env).await {
            Ok(v) => v,
            Err(e) => {
                println!("footprint: boot {i} failed: {e}");
                break;
            }
        };
        if let Err(e) = vm.agent(None).await {
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
        if let Ok(agent) = v.agent(None).await {
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

    // Marginal cost of each additional resident guest: step N minus step N-1, with the first step
    // its own marginal. Carrying `prev` (seeded 0, so the first subtraction is a no-op) keeps this
    // index-free — the arithmetic that would panic on an empty/short slice cannot be written.
    let marginal_of = |steps: &[u64]| -> Vec<u64> {
        let mut prev = 0u64;
        steps
            .iter()
            .map(|&s| {
                let marginal = s.saturating_sub(prev);
                prev = s;
                marginal
            })
            .collect()
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
// §16 (Performance) — suspend-size: snapshot bytes + memory-file share, vs guest RAM.
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
    let cfg = build_cfg(args, kernel, rootfs, false, true);
    let mut env = HostEnv::hermetic();
    env.vmids = allocator;
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

    let mut vm = match MicroVm::start(vmm, cfg, &env).await {
        Ok(v) => v,
        Err(e) => {
            // Best-effort removal of the (empty) snapshot dir before bailing.
            let _ = std::fs::remove_dir_all(&snap_dir);
            anyhow::bail!("suspend-size: boot failed: {e}");
        }
    };
    if let Err(e) = vm.agent(None).await {
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
// §16 (Performance) — phase-budget: per-phase distribution + share, restore and cold.
// ----------------------------------------------------------------------------
async fn build_baseline_snapshot<V: Vmm>(
    vmm: &V,
    cfg: &VmConfig,
    env: &HostEnv,
    snap_dir: &Path,
) -> Result<(), String> {
    let mut base = MicroVm::start(vmm, cfg.clone(), env)
        .await
        .map_err(|e| e.to_string())?;
    base.agent(None).await.map_err(|e| e.to_string())?;
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
    env: &HostEnv,
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
            Some(d) => MicroVm::restore(vmm, d, cfg.clone(), env).await,
            None => MicroVm::start(vmm, cfg.clone(), env).await,
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
        let connect_ok = vm.agent(None).await.is_ok();
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
        if let Ok(agent) = vm.agent(None).await {
            // The exec *result* is intentionally unused: this phase measures the
            // exec-round-trip latency (t2..t_exec), not the command's exit/output.
            let _ = agent.exec(ExecRequest::new(argv)).await;
        }
        let t_exec = t2.elapsed();

        let t3 = Instant::now();
        // Teardown is deliberately on the budget (§16, Performance): we time it, and `Drop`
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
    let cfg = build_cfg(args, kernel, rootfs, false, true);
    let mut env = HostEnv::hermetic();
    env.vmids = allocator;

    // Cold-boot path (opt-in budget). A zero-sample cold path is an attempted-and-
    // failed run → propagate (M-BIN-1).
    phase_budget_path(vmm, backend, args, &cfg, &env, None).await?;

    // Restore path (the hot path) — build the baseline snapshot once.
    if vmm.capabilities().snapshot_restore {
        let snap_dir = resolve_snap_dir(&args.snap_dir)
            .join(format!("phase-{backend}-{}", std::process::id()));
        // Best-effort pre-clean of a stale snapshot dir from a prior aborted run.
        let _ = std::fs::remove_dir_all(&snap_dir);
        if let Err(e) = std::fs::create_dir_all(&snap_dir) {
            anyhow::bail!("phase-budget: cannot create snap dir: {e}");
        }
        let baseline = build_baseline_snapshot(vmm, &cfg, &env, &snap_dir).await;
        let restore_res = match baseline {
            Ok(()) => {
                phase_budget_path(vmm, backend, args, &cfg, &env, Some(snap_dir.clone())).await
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
// §16 (Performance) — vsock-rtt: control-plane exec round-trip latency floor.
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
    let cfg = build_cfg(args, kernel, rootfs, false, false);
    let mut env = HostEnv::hermetic();
    env.vmids = allocator;
    let iters = args.iters();

    let mut vm = match MicroVm::start(vmm, cfg, &env).await {
        Ok(v) => v,
        Err(e) => anyhow::bail!("vsock-rtt: boot failed: {e}"),
    };
    if let Err(e) = vm.agent(None).await {
        // Best-effort teardown before bailing; `Drop` guarantees teardown.
        let _ = vm.shutdown().await;
        anyhow::bail!("vsock-rtt: agent connect failed: {e}");
    }
    let argv = pick_exec_cmd(&mut vm).await;

    for _ in 0..args.warmup {
        if let Ok(agent) = vm.agent(None).await {
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
        let agent = match vm.agent(None).await {
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

// ----------------------------------------------------------------------------
// net-egress: boot-with-networking latency + in-guest egress round-trip (§13, the
// L-invariant data plane). Fills the coverage gap where every other mode uses
// `network_disabled()` and never exercises the smoltcp NAT.
// ----------------------------------------------------------------------------

/// A minimal host-side HTTP/1.1 responder for the `net-egress` benchmark: binds
/// `127.0.0.1:0`, answers every connection with a fixed 200 body, and is reaped on
/// `Drop` (ownership owns cleanup — it survives a panic mid-run). The guest reaches
/// it through the smoltcp NAT at `http://<gateway_ip>:<port>/`. In-process `std::net`
/// (no `python3 -m http.server` dependency, unlike the integration tests).
struct HostResponder {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl HostResponder {
    fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        // Non-blocking accept + a poll loop so `Drop` can stop the thread promptly
        // without a self-connect wakeup hack.
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let handle = std::thread::spawn(move || {
            const BODY: &[u8] = b"vmcell-egress-ok\n";
            while !stop_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut conn, _)) => {
                        // Drain one request chunk (a GET fits in 1 KiB) before replying,
                        // so curl doesn't take an RST on unread data; then a fixed 200.
                        let mut buf = [0u8; 1024];
                        let _ = conn.set_read_timeout(Some(std::time::Duration::from_millis(500)));
                        let _ = conn.read(&mut buf);
                        let head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            BODY.len()
                        );
                        let _ = conn.write_all(head.as_bytes());
                        let _ = conn.write_all(BODY);
                        let _ = conn.flush();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    // A real accept error (fd exhaustion, etc.) ends the responder; the
                    // bench's per-request checks then surface it as dropped samples.
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            port,
            stop,
            handle: Some(handle),
        })
    }
}

impl Drop for HostResponder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// The in-guest egress client: `curl -s --max-time 5 <url>`. `curl` is on the guest
/// PATH (rootfs `--include=curl` + the guest-tools multicall).
fn egress_curl(url: &str) -> Vec<String> {
    vec![
        "curl".to_string(),
        "-s".to_string(),
        "--max-time".to_string(),
        "5".to_string(),
        url.to_string(),
    ]
}

/// §16 (Performance) — net-egress dispatcher: `--net-mode plain` (unprivileged smoltcp
/// NAT datapath), `tls` (unprivileged smoltcp + MITM proxy), or `privileged` (tap +
/// netns + nft + MITM proxy). Each self-skips where its facility is absent.
async fn run_net_egress<V: Vmm>(
    vmm: &V,
    backend: &str,
    args: &Args,
    allocator: VmidAllocator,
) -> anyhow::Result<()> {
    match args.net_mode.as_str() {
        "plain" => run_net_egress_plain(vmm, backend, args, allocator).await,
        "tls" => run_net_egress_filtered(vmm, backend, args, allocator, false).await,
        "privileged" => run_net_egress_filtered(vmm, backend, args, allocator, true).await,
        // Pre-validated by `parse_net_mode`; fail loud rather than silently succeed if the
        // two ever drift.
        other => anyhow::bail!("net-egress: unknown --net-mode '{other}'"),
    }
}

/// §16 (Performance) — net-egress `plain`: (A) VM start latency WITH the smoltcp NAT on
/// the boot path, and (B) the in-guest egress round-trip through the NAT to a host
/// endpoint (asserting a real egress byte, not a proxy signal — §15/AGENTS.md).
async fn run_net_egress_plain<V: Vmm>(
    vmm: &V,
    backend: &str,
    args: &Args,
    allocator: VmidAllocator,
) -> anyhow::Result<()> {
    // Self-skip: the unprivileged smoltcp NAT needs the vhost-user-net device (CH +
    // QEMU; Firecracker has none). A capability skip is success (Ok), not a failure
    // (M-BIN-1).
    if !vmm.capabilities().unprivileged_vhost_user_net {
        println!("net-egress: backend {backend} has no unprivileged vhost-user-net; skipping");
        return Ok(());
    }
    let (dir, kernel, rootfs) = artifact_paths(args.kernel.as_deref());
    if !kernel.exists() || !rootfs.exists() {
        println!("net-egress: No successful runs (missing artifacts in {dir})");
        anyhow::bail!("net-egress: missing artifacts in {dir}");
    }

    // Host endpoint the guest NATs to, owned in a Drop guard (reaped even on panic).
    let responder = HostResponder::start()
        .map_err(|e| anyhow::anyhow!("net-egress: failed to start host responder: {e}"))?;
    let host_port = responder.port;

    // Networked config (NOT `network_disabled()`); same tunable knobs as `build_cfg`.
    let cfg = VmConfig::builder(kernel, RootfsSource::Erofs { image: rootfs })
        .vcpus(1)
        .mem_mib(args.mem_mib)
        .net(NetConfig::Unprivileged {
            egress: Egress::Open,
            host_services_port: Some(host_port),
        })
        .restore_mode(args.restore_mode)
        .timeouts(timeouts_for(&args.profile))
        .kernel_verbosity(args.kernel_verbosity)
        .console_mode(args.console)
        .build()
        .map_err(|e| anyhow::anyhow!("net-egress: invalid config: {e}"))?;

    let mut env = HostEnv::hermetic();
    env.vmids = allocator;
    let iters = args.iters();

    // The smoltcp vhost-user-net daemon intermittently fails to bind its UDS (~10% of
    // boots the daemon thread errors and the socket never appears within the readiness
    // ceiling — a latent smoltcp bring-up flake this volume probe surfaced; the existing
    // egress tests boot a single VM and never hit it. See docs/benchmark-results.md).
    // Retry a transient boot failure on a FRESH VM (fresh smoltcp) a bounded number of
    // times, counting the retries so they are visible, not hidden (mirrors the QEMU vsock
    // re-spawn recovery). An agent-connect failure is separate `dropped` accounting.
    const NET_BOOT_RETRIES: usize = 5;

    // --- Phase A: start latency WITH the smoltcp NAT set up on the boot path ---
    let mut starts = Vec::new();
    let mut start_dropped = 0usize;
    let mut boot_retries = 0usize;
    for i in 0..(iters + args.warmup) {
        let mut attempt = 0usize;
        loop {
            let t = Instant::now();
            match MicroVm::start(vmm, cfg.clone(), &env).await {
                Ok(mut vm) => {
                    match vm.agent(None).await {
                        Ok(_) => {
                            let dt = t.elapsed().as_millis();
                            if i >= args.warmup {
                                starts.push(dt);
                            }
                        }
                        Err(e) => {
                            println!("net-egress: net-start iter {i} agent-connect failed: {e}");
                            if i >= args.warmup {
                                start_dropped += 1;
                            }
                        }
                    }
                    let _ = vm.shutdown().await;
                    break;
                }
                Err(e) => {
                    attempt += 1;
                    if attempt > NET_BOOT_RETRIES {
                        anyhow::bail!(
                            "net-egress: net-start iter {i} start failed after {attempt} attempts: {e}"
                        );
                    }
                    boot_retries += 1;
                    println!(
                        "net-egress: net-start iter {i} transient boot failure (attempt {attempt}, retrying): {e}"
                    );
                }
            }
        }
    }
    if boot_retries > 0 {
        println!(
            "net-egress: NET-START recovered {boot_retries} transient smoltcp-bringup boot failure(s) via retry"
        );
    }
    report(
        "NET-START (boot with smoltcp NAT)",
        &mut starts,
        start_dropped,
        0,
    );

    // --- Phase B: steady egress round-trip (one warm VM, N in-guest curls) ---
    // Same bounded retry over the smoltcp bring-up flake as Phase A.
    let mut vm = {
        let mut attempt = 0usize;
        loop {
            match MicroVm::start(vmm, cfg.clone(), &env).await {
                Ok(v) => break v,
                Err(e) => {
                    attempt += 1;
                    if attempt > NET_BOOT_RETRIES {
                        anyhow::bail!(
                            "net-egress: egress VM boot failed after {attempt} attempts: {e}"
                        );
                    }
                    println!(
                        "net-egress: egress VM transient boot failure (attempt {attempt}, retrying): {e}"
                    );
                }
            }
        }
    };
    if let Err(e) = vm.agent(None).await {
        let _ = vm.shutdown().await;
        anyhow::bail!("net-egress: egress VM agent connect failed: {e}");
    }
    let (gateway_ip, _guest_ip, _cidr) = vmcell::net::ip_math(vm.vmid())
        .map_err(|e| anyhow::anyhow!("net-egress: ip_math({}): {e}", vm.vmid()))?;
    let url = format!("http://{gateway_ip}:{host_port}/");

    // Warm-up: the guest configures eth0 from the kernel `ip=` line (IP-PNP) after
    // boot, so the first curl races the interface/NAT coming up. Retry until the first
    // success (bounded) before measuring the steady RTT — and require a real egress
    // byte (`code==0 && !stdout.is_empty()`), a data-plane assertion.
    let mut warmed = false;
    for _ in 0..40 {
        if let Ok(agent) = vm.agent(None).await
            && let Ok(o) = agent.exec(ExecRequest::new(egress_curl(&url))).await
            && o.code == 0
            && !o.stdout.is_empty()
        {
            warmed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    if !warmed {
        let _ = vm.shutdown().await;
        anyhow::bail!("net-egress: no successful egress request within the warm-up budget");
    }

    let mut rtts = Vec::with_capacity(iters);
    let mut dropped = 0usize;
    for i in 0..iters {
        let agent = match vm.agent(None).await {
            Ok(a) => a,
            Err(e) => {
                println!("net-egress: egress iter {i} agent-connect failed: {e}");
                break;
            }
        };
        let t = Instant::now();
        let r = agent.exec(ExecRequest::new(egress_curl(&url))).await;
        let dt = t.elapsed().as_micros();
        match r {
            Ok(o) if o.code == 0 && !o.stdout.is_empty() => rtts.push(dt),
            Ok(o) => {
                println!(
                    "net-egress: egress iter {i} curl code={} stdout={}B (no egress byte)",
                    o.code,
                    o.stdout.len()
                );
                dropped += 1;
            }
            Err(e) => {
                println!("net-egress: egress iter {i} exec failed: {e}");
                dropped += 1;
            }
        }
    }
    let _ = vm.shutdown().await;
    // `responder` stays alive until here; its Drop reaps the host thread.

    let acct = accounting_suffix(dropped, 0);
    println!(
        "=== NET-EGRESS (backend={backend} n={}{acct} url={url}) ===",
        rtts.len()
    );
    match pcts(&mut rtts) {
        Some((p50, p95, p99, max)) => {
            println!(
                "  in-guest curl round-trip (guest→NAT→host→guest): p50={p50}µs p95={p95}µs p99={p99}µs max={max}µs"
            );
            Ok(())
        }
        None => {
            println!("  No successful egress round-trips");
            anyhow::bail!("net-egress: no egress samples");
        }
    }
}

/// Builds a `Filtered` proxy config whose MITM test-double answers any `*.probe.local`
/// host with a fixed body. The guest↔proxy TLS handshake + per-connection cert mint happen
/// at `CONNECT`, *before* the double is matched, so they are exercised with NO real upstream
/// origin (hudsucker's upstream leg pins webpki roots and can't reach a self-signed local
/// origin — so the upstream handshake is deliberately out of scope; §16). The proxy
/// self-generates its CA (baked into the rootfs trust store, so the guest verifies).
fn mitm_proxy_config() -> vmcell::config::ProxyConfig {
    // `ProxyConfig` is `#[non_exhaustive]`, so build via `default()` + field-set (the exact
    // pattern the `egress_proxy` test uses; clippy does not fire `field_reassign_with_default`
    // for a `#[non_exhaustive]` struct from another crate).
    let mut cfg = vmcell::config::ProxyConfig::default();
    cfg.doubles = std::sync::Arc::new(std::sync::RwLock::new(vec![
        vmcell::proxy::doubles::TestDouble {
            matcher: Box::new(|req| {
                req.method() != hyper::Method::CONNECT
                    && req
                        .uri()
                        .host()
                        .is_some_and(|h| h.ends_with(".probe.local"))
            }),
            responder: Box::new(|_req| {
                hyper::Response::builder()
                    .status(200)
                    .body(hudsucker::Body::from("vmcell-mitm-ok\n"))
                    .expect("static MITM response builds")
            }),
        },
    ]));
    cfg
}

// ----------------------------------------------------------------------------
// net-egress `tls` / `privileged`: the MITM egress proxy (per-connection cert mint +
// guest↔proxy TLS handshake) over either the unprivileged smoltcp NAT (`tls`) or the
// privileged tap + netns + nft path (`privileged`). Covers the two egress surfaces the
// `plain` NAT datapath probe leaves unmeasured (docs/benchmark-results.md coverage caveat).
// ----------------------------------------------------------------------------

/// §16 (Performance) — net-egress `tls`/`privileged`: (A) start latency WITH the filtered
/// egress set up (smoltcp+proxy, or netns+tap+nft+proxy), and (B) the in-guest
/// HTTPS-through-MITM-proxy round-trip (fresh unique host per iter → fresh cert mint),
/// asserting a real MITM'd body byte. `privileged=true` uses `NetConfig::Privileged` (tap)
/// and self-skips without CAP_NET_ADMIN; `false` uses unprivileged smoltcp and self-skips
/// without the vhost-user-net device.
async fn run_net_egress_filtered<V: Vmm>(
    vmm: &V,
    backend: &str,
    args: &Args,
    allocator: VmidAllocator,
    privileged: bool,
) -> anyhow::Result<()> {
    let label = if privileged { "privileged" } else { "tls" };
    let sweep_prefix = vmcell::naming::netns_sweep_prefix(vmcell::naming::DEFAULT_RESOURCE_PREFIX);

    // Self-skip per variant (a capability skip is success, M-BIN-1).
    if privileged {
        if !vmcell::HostCapabilities::probe().privileged_net_available() {
            println!("net-egress[{label}]: no CAP_NET_ADMIN / netns dir; skipping");
            return Ok(());
        }
        // Reap orphan `vmcell-net-*` netns from prior aborted/hard-killed runs before we start.
        let _ = vmcell::net::cleanup_orphan_netns(&sweep_prefix);
    } else if !vmm.capabilities().unprivileged_vhost_user_net {
        println!(
            "net-egress[{label}]: backend {backend} has no unprivileged vhost-user-net; skipping"
        );
        return Ok(());
    }

    let (dir, kernel, rootfs) = artifact_paths(args.kernel.as_deref());
    if !kernel.exists() || !rootfs.exists() {
        println!("net-egress[{label}]: No successful runs (missing artifacts in {dir})");
        anyhow::bail!("net-egress[{label}]: missing artifacts in {dir}");
    }

    let egress = Egress::Filtered(mitm_proxy_config());
    let net = if privileged {
        NetConfig::Privileged { egress }
    } else {
        NetConfig::Unprivileged {
            egress,
            host_services_port: None,
        }
    };
    let cfg = VmConfig::builder(kernel, RootfsSource::Erofs { image: rootfs })
        .vcpus(1)
        .mem_mib(args.mem_mib)
        .net(net)
        .restore_mode(args.restore_mode)
        .timeouts(timeouts_for(&args.profile))
        .kernel_verbosity(args.kernel_verbosity)
        .console_mode(args.console)
        .build()
        .map_err(|e| anyhow::anyhow!("net-egress[{label}]: invalid config: {e}"))?;

    let mut env = HostEnv::hermetic();
    env.vmids = allocator;
    let iters = args.iters();
    // Bounded retry over transient net bring-up (the smoltcp flake for `tls`; a
    // netns/tap/nft hiccup for `privileged`), same recovery pattern as `plain`.
    const NET_BOOT_RETRIES: usize = 5;

    // --- Phase A: start latency WITH the filtered-egress net setup on the boot path ---
    let mut starts = Vec::new();
    let mut start_dropped = 0usize;
    let mut boot_retries = 0usize;
    for i in 0..(iters + args.warmup) {
        let mut attempt = 0usize;
        loop {
            let t = Instant::now();
            match MicroVm::start(vmm, cfg.clone(), &env).await {
                Ok(mut vm) => {
                    match vm.agent(None).await {
                        Ok(_) => {
                            let dt = t.elapsed().as_millis();
                            if i >= args.warmup {
                                starts.push(dt);
                            }
                        }
                        Err(e) => {
                            println!(
                                "net-egress[{label}]: net-start iter {i} agent-connect failed: {e}"
                            );
                            if i >= args.warmup {
                                start_dropped += 1;
                            }
                        }
                    }
                    let _ = vm.shutdown().await;
                    break;
                }
                Err(e) => {
                    attempt += 1;
                    if attempt > NET_BOOT_RETRIES {
                        anyhow::bail!(
                            "net-egress[{label}]: net-start iter {i} start failed after {attempt} attempts: {e}"
                        );
                    }
                    boot_retries += 1;
                    println!(
                        "net-egress[{label}]: net-start iter {i} transient boot failure (attempt {attempt}, retrying): {e}"
                    );
                }
            }
        }
    }
    if boot_retries > 0 {
        println!(
            "net-egress[{label}]: NET-START recovered {boot_retries} transient boot failure(s) via retry"
        );
    }
    let start_label = if privileged {
        "NET-START (boot with tap+netns+nft+proxy)"
    } else {
        "NET-START (boot with smoltcp NAT + MITM proxy)"
    };
    report(start_label, &mut starts, start_dropped, 0);

    // --- Phase B: steady MITM egress round-trip (one warm VM, N HTTPS-through-proxy curls) ---
    let mut vm = {
        let mut attempt = 0usize;
        loop {
            match MicroVm::start(vmm, cfg.clone(), &env).await {
                Ok(v) => break v,
                Err(e) => {
                    attempt += 1;
                    if attempt > NET_BOOT_RETRIES {
                        anyhow::bail!(
                            "net-egress[{label}]: egress VM boot failed after {attempt} attempts: {e}"
                        );
                    }
                    println!(
                        "net-egress[{label}]: egress VM transient boot failure (attempt {attempt}, retrying): {e}"
                    );
                }
            }
        }
    };
    if let Err(e) = vm.agent(None).await {
        let _ = vm.shutdown().await;
        anyhow::bail!("net-egress[{label}]: egress VM agent connect failed: {e}");
    }
    let (gateway_ip, _guest_ip, _cidr) = vmcell::net::ip_math(vm.vmid())
        .map_err(|e| anyhow::anyhow!("net-egress[{label}]: ip_math({}): {e}", vm.vmid()))?;
    let proxy_port = match vm.proxy() {
        Some(p) => p.port,
        None => {
            let _ = vm.shutdown().await;
            anyhow::bail!("net-egress[{label}]: filtered egress did not start a proxy");
        }
    };
    let proxy_url = format!("http://{gateway_ip}:{proxy_port}");
    // A fresh unique `*.probe.local` host per request → cache miss → fresh per-connection
    // cert mint each time (the moka authority cache is keyed by host). `--resolve …:1.2.3.4`
    // is a black-hole placeholder never contacted (the double answers post-handshake).
    let mitm_curl = |host: &str| -> (Vec<String>, Vec<(String, String)>) {
        (
            vec![
                "curl".to_string(),
                "-4".to_string(),
                "-k".to_string(),
                "-s".to_string(),
                "--max-time".to_string(),
                "5".to_string(),
                "--resolve".to_string(),
                format!("{host}:443:1.2.3.4"),
                format!("https://{host}/"),
            ],
            vec![
                ("http_proxy".to_string(), proxy_url.clone()),
                ("https_proxy".to_string(), proxy_url.clone()),
            ],
        )
    };

    // Warm-up: bring eth0 / NAT / proxy up + prime the CA; retry until the first successful
    // MITM'd byte before measuring the steady round-trip (data-plane assertion).
    let mut warmed = false;
    for w in 0..40 {
        let (argv, cenv) = mitm_curl(&format!("warm{w}.probe.local"));
        if let Ok(agent) = vm.agent(None).await
            && let Ok(o) = agent.exec(ExecRequest::new(argv).with_env(cenv)).await
            && o.code == 0
            && o.stdout.starts_with(b"vmcell-mitm-ok")
        {
            warmed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    if !warmed {
        let _ = vm.shutdown().await;
        if privileged {
            let _ = vmcell::net::cleanup_orphan_netns(&sweep_prefix);
        }
        anyhow::bail!("net-egress[{label}]: no successful MITM egress within the warm-up budget");
    }

    let mut rtts = Vec::with_capacity(iters);
    let mut dropped = 0usize;
    for i in 0..iters {
        let (argv, cenv) = mitm_curl(&format!("h{i}.probe.local"));
        let agent = match vm.agent(None).await {
            Ok(a) => a,
            Err(e) => {
                println!("net-egress[{label}]: egress iter {i} agent-connect failed: {e}");
                break;
            }
        };
        let t = Instant::now();
        let r = agent.exec(ExecRequest::new(argv).with_env(cenv)).await;
        let dt = t.elapsed().as_micros();
        match r {
            Ok(o) if o.code == 0 && o.stdout.starts_with(b"vmcell-mitm-ok") => rtts.push(dt),
            Ok(o) => {
                println!(
                    "net-egress[{label}]: egress iter {i} MITM curl code={} stdout={}B (no MITM byte)",
                    o.code,
                    o.stdout.len()
                );
                dropped += 1;
            }
            Err(e) => {
                println!("net-egress[{label}]: egress iter {i} exec failed: {e}");
                dropped += 1;
            }
        }
    }
    let _ = vm.shutdown().await;
    // Belt-and-suspenders netns sweep for any panic residue (privileged only; a clean
    // `shutdown()` already removes this VM's netns).
    if privileged {
        let _ = vmcell::net::cleanup_orphan_netns(&sweep_prefix);
    }

    let acct = accounting_suffix(dropped, 0);
    let tag = if privileged {
        "NET-EGRESS-PRIV (MITM via tap+nft+proxy)"
    } else {
        "NET-EGRESS-TLS (MITM via smoltcp+proxy)"
    };
    println!("=== {tag} (backend={backend} n={}{acct}) ===", rtts.len());
    match pcts(&mut rtts) {
        Some((p50, p95, p99, max)) => {
            println!(
                "  in-guest HTTPS-through-MITM-proxy round-trip (cert mint + TLS handshake): p50={p50}µs p95={p95}µs p99={p99}µs max={max}µs"
            );
            Ok(())
        }
        None => {
            println!("  No successful MITM egress round-trips");
            anyhow::bail!("net-egress[{label}]: no MITM egress samples");
        }
    }
}

// ----------------------------------------------------------------------------
// zygote: CoW-clone fan-out latency. Snapshot a base once, then time restoring +
// resuming N CoW clones concurrently (the zygote/lineage fan-out the library-direct
// single-VM restore metric structurally cannot reach).
// ----------------------------------------------------------------------------

/// §16 (Performance) — zygote fan-out: snapshot a base VM once, then time
/// `Zygote::spawn_clones` to `--count` resumed CoW clones (plus the time to reach
/// agent-ready across all of them). `restore_rotates_host_paths` gates concurrent
/// fan-out (CH + QEMU); Firecracker degrades to the single-clone control.
async fn run_zygote<V: Vmm>(
    vmm: &V,
    backend: &str,
    args: &Args,
    allocator: VmidAllocator,
) -> anyhow::Result<()> {
    let caps = vmm.capabilities();
    if !caps.snapshot_restore {
        println!("zygote: backend {backend} has no snapshot support; skipping");
        return Ok(());
    }
    // FC rotates no host paths → only a single clone is representable (`spawn_clones`
    // would return `Unsupported` for n>1); CH/QEMU fan out to `--count`. Announce the
    // clamp loudly rather than silently measuring a different n (N-BIN-2 spirit).
    let requested = args.count;
    let clone_count = if caps.restore_rotates_host_paths {
        requested
    } else {
        if requested > 1 {
            println!(
                "zygote: backend {backend} does not rotate host paths; measuring the \
                 single-clone control (n=1), not {requested}"
            );
        }
        1
    };

    let (dir, kernel, rootfs) = artifact_paths(args.kernel.as_deref());
    if !kernel.exists() || !rootfs.exists() {
        println!("zygote: No successful runs (missing artifacts in {dir})");
        anyhow::bail!("zygote: missing artifacts in {dir}");
    }
    // snapshotting=true: QEMU needs the in-kernel vhost-vsock transport to restore.
    let cfg = build_cfg(args, kernel, rootfs, false, true);
    let mut env = HostEnv::hermetic();
    env.vmids = allocator;

    // --- Snapshot the base ONCE into the master zygote image ---
    let master =
        resolve_snap_dir(&args.snap_dir).join(format!("zygote-{backend}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&master);
    std::fs::create_dir_all(&master).map_err(|e| {
        anyhow::anyhow!("zygote: cannot create master dir {}: {e}", master.display())
    })?;

    let mut base = match MicroVm::start(vmm, cfg.clone(), &env).await {
        Ok(v) => v,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&master);
            anyhow::bail!("zygote: base VM start failed: {e}");
        }
    };
    if let Err(e) = base.agent(None).await {
        let _ = base.shutdown().await;
        let _ = std::fs::remove_dir_all(&master);
        anyhow::bail!("zygote: base VM agent connect failed: {e}");
    }
    let zygote = match vmcell::Zygote::suspend(&mut base, cfg.clone(), &master).await {
        Ok(z) => z,
        Err(e) => {
            let _ = base.shutdown().await;
            let _ = std::fs::remove_dir_all(&master);
            anyhow::bail!("zygote: suspend failed: {e}");
        }
    };
    let _ = base.shutdown().await;
    let cow = zygote.probe_cow_support();
    println!(
        "zygote master ready (fan-out={clone_count}); CoW support: {cow:?} \
         (reflink needs $TMPDIR + master on one reflink-capable fs; else a full copy)"
    );

    // --- Timed fan-out: N clones restored + resumed concurrently per iteration ---
    let mut fanout = Vec::new(); // wall-clock to `clone_count` live+resumed clones
    let mut ready = Vec::new(); // + time to agent-ready across all clones
    let mut dropped = 0usize;
    for i in 0..(args.iters() + args.warmup) {
        let t_fan = Instant::now();
        let mut clones = match zygote.spawn_clones(vmm, clone_count, &env).await {
            Ok(c) => c,
            Err(e) => {
                println!("zygote: iteration {i} fan-out failed: {e}");
                dropped += 1;
                continue;
            }
        };
        let fan_ms = t_fan.elapsed().as_millis();

        // Time to agent-ready across all clones (concurrent; the first agent() runs the
        // post-restore resync). Disjoint `&mut` borrows via `iter_mut`, so this is sound.
        let t_ready = Instant::now();
        let ready_res =
            futures::future::try_join_all(clones.iter_mut().map(|c| c.agent(None))).await;
        let ready_ms = t_ready.elapsed().as_millis();

        match ready_res {
            Ok(_) => {
                if i >= args.warmup {
                    fanout.push(fan_ms);
                    ready.push(ready_ms);
                }
            }
            Err(e) => {
                println!("zygote: iteration {i} clone agent-ready failed: {e}");
                dropped += 1;
            }
        }
        for c in clones {
            let _ = c.shutdown().await;
        }
    }
    let _ = std::fs::remove_dir_all(&master);

    let acct = accounting_suffix(dropped, 0);
    println!(
        "=== ZYGOTE (backend={backend} fan-out={clone_count} n={}{acct} cow={cow:?}) ===",
        fanout.len()
    );
    let per_clone = |p: u128| p / clone_count.max(1) as u128;
    match pcts(&mut fanout) {
        Some((p50, p95, p99, max)) => {
            println!(
                "  fan-out to {clone_count} resumed clones: p50={p50}ms p95={p95}ms p99={p99}ms max={max}ms  (per-clone p50≈{}ms)",
                per_clone(p50)
            );
        }
        None => {
            println!("  No successful fan-outs");
            anyhow::bail!("zygote: no successful fan-outs");
        }
    }
    if let Some((p50, p95, p99, max)) = pcts(&mut ready) {
        println!(
            "  + time to agent-ready across all clones: p50={p50}ms p95={p95}ms p99={p99}ms max={max}ms"
        );
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// session: the interactive-session layer (`SessionMux`) the one-shot AgentClient
// path (measured by vsock-rtt) never exercises — the SECOND vsock handshake +
// per-session open/spawn. (There is no resume-by-id API: "session persistence" =
// long-lived sessions, not reattach-across-reconnect, so the connect handshake is
// the closest analogue to a resume.)
// ----------------------------------------------------------------------------

/// §16 (Performance) — session: (A) `connect_sessions` latency (the mux's own second
/// vsock connection + `Ready` handshake, separate from the cached `agent()` client),
/// and (B) per-session `open`→guest-spawn→`exit` on one persistent mux. Both assert a
/// real `code==0` exit before counting (data-plane liveness, not a connect-only signal).
/// Works on all four backends (sessions ride the same vsock; no capability gate).
async fn run_session<V: Vmm>(
    vmm: &V,
    backend: &str,
    args: &Args,
    allocator: VmidAllocator,
) -> anyhow::Result<()> {
    let (dir, kernel, rootfs) = artifact_paths(args.kernel.as_deref());
    if !kernel.exists() || !rootfs.exists() {
        println!("session: No successful runs (missing artifacts in {dir})");
        anyhow::bail!("session: missing artifacts in {dir}");
    }
    let cfg = build_cfg(args, kernel, rootfs, false, false);
    let mut env = HostEnv::hermetic();
    env.vmids = allocator;
    let iters = args.iters();

    let mut vm = match MicroVm::start(vmm, cfg, &env).await {
        Ok(v) => v,
        Err(e) => anyhow::bail!("session: boot failed: {e}"),
    };
    if let Err(e) = vm.agent(None).await {
        let _ = vm.shutdown().await;
        anyhow::bail!("session: agent connect failed: {e}");
    }
    let argv = pick_exec_cmd(&mut vm).await;

    // --- Metric A: session-connect latency (the 2nd vsock handshake) ---
    // Each `connect_sessions` dials a fresh mux connection + `Ready` handshake, distinct
    // from the cached one-shot `agent()` client vsock-rtt reuses. Prove liveness (run one
    // command to `code==0`) before counting the sample, then drop the mux.
    let mut connect_rtts = Vec::with_capacity(iters);
    let mut conn_dropped = 0usize;
    for _ in 0..args.warmup {
        if let Ok(mux) = vm.connect_sessions(None).await
            && let Ok(mut s) = mux.open_spec(SessionSpecBuilder::new(argv.clone())).await
        {
            let _ = s.wait().await;
        }
    }
    for i in 0..iters {
        let t = Instant::now();
        let mux = match vm.connect_sessions(None).await {
            Ok(m) => m,
            Err(e) => {
                println!("session: connect iter {i} failed: {e}");
                conn_dropped += 1;
                continue;
            }
        };
        let dt = t.elapsed().as_micros();
        let live = match mux.open_spec(SessionSpecBuilder::new(argv.clone())).await {
            Ok(mut s) => s.wait().await.code == 0,
            Err(_) => false,
        };
        drop(mux);
        if live {
            connect_rtts.push(dt);
        } else {
            conn_dropped += 1;
        }
    }

    // --- Metric B: session-open latency on ONE persistent mux (open→spawn→exit) ---
    // `open` has no ack round-trip (it fires OpenSession and returns), so the real cost is
    // open→guest-spawn→Exit: time to `wait()`'s terminal exit, not `open()` alone.
    let mux = match vm.connect_sessions(None).await {
        Ok(m) => m,
        Err(e) => {
            let _ = vm.shutdown().await;
            anyhow::bail!("session: mux connect failed: {e}");
        }
    };
    for _ in 0..args.warmup {
        if let Ok(mut s) = mux.open_spec(SessionSpecBuilder::new(argv.clone())).await {
            let _ = s.wait().await;
        }
    }
    let mut open_rtts = Vec::with_capacity(iters);
    let mut open_dropped = 0usize;
    for i in 0..iters {
        let t = Instant::now();
        let outcome = match mux.open_spec(SessionSpecBuilder::new(argv.clone())).await {
            Ok(mut s) => s.wait().await,
            Err(e) => {
                println!("session: open iter {i} failed: {e}");
                open_dropped += 1;
                continue;
            }
        };
        let dt = t.elapsed().as_micros();
        if outcome.code == 0 {
            open_rtts.push(dt);
        } else {
            open_dropped += 1;
        }
    }
    drop(mux);
    let _ = vm.shutdown().await;

    println!("=== SESSION (backend={backend} cmd={argv:?}) ===");
    let acct_c = accounting_suffix(conn_dropped, 0);
    match pcts(&mut connect_rtts) {
        Some((p50, p95, p99, max)) => println!(
            "  session-connect (2nd vsock handshake) n={}{acct_c}: p50={p50}µs p95={p95}µs p99={p99}µs max={max}µs",
            connect_rtts.len()
        ),
        None => {
            println!("  session-connect: No successful runs{acct_c}");
            anyhow::bail!("session: no successful mux connects");
        }
    }
    let acct_o = accounting_suffix(open_dropped, 0);
    match pcts(&mut open_rtts) {
        Some((p50, p95, p99, max)) => {
            println!(
                "  session-open (open→spawn→exit) n={}{acct_o}: p50={p50}µs p95={p95}µs p99={p99}µs max={max}µs",
                open_rtts.len()
            );
            Ok(())
        }
        None => {
            println!("  session-open: No successful runs{acct_o}");
            anyhow::bail!("session: no successful session opens");
        }
    }
}

// ----------------------------------------------------------------------------
// daemon-api: the `vmcelld` HTTP + broker-bridge overhead over the raw VMM op. Spawns its
// own `vmcelld` child (bench-vm runs under the blessed runner, so the daemon inherits the
// caps via the ambient set), drives create/restore/exec/list/destroy over HTTP, and reports
// through the shared `pcts` — replacing the former `scripts/perf-daemon.sh` (curl + a python
// percentile reimplementation + curl-`%{time_total}` timing + python JSON id-parsing).
// ----------------------------------------------------------------------------

/// Owns the spawned `vmcelld` child and tears it down on drop: SIGTERM (so the daemon's
/// signal handler runs `engine.shutdown_all()`, reaping every CH VM + the broker) → bounded
/// wait → SIGKILL backstop → reap. Mirrors the `vmcelld` integration harness; a bare kill
/// would orphan the live CH VMs.
struct DaemonChild(std::process::Child);

impl Drop for DaemonChild {
    fn drop(&mut self) {
        // If the child was already reaped (e.g. the health-poll's `try_wait` collected it
        // after an early daemon exit), its pid is freed and `Child::id()` is stale — do NOT
        // signal it (that pid may have been recycled). This mirrors std's own `Child::kill`,
        // which no-ops once the status is cached.
        if matches!(self.0.try_wait(), Ok(Some(_))) {
            return;
        }
        // SAFETY: `kill(2)` with a pid this process spawned and has NOT yet reaped (the guard
        // above), plus a valid signal constant. It transfers no pointers and touches no memory.
        unsafe {
            libc::kill(self.0.id() as libc::pid_t, libc::SIGTERM);
        }
        for _ in 0..50 {
            if matches!(self.0.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One timed HTTP request: `Instant` around send + a full body drain (the `curl
/// %{time_total}` equivalent). Returns (elapsed µs, parsed JSON body — `Null` for an empty
/// 204). A non-2xx status is a hard error (`error_for_status`), so a broken op fails loud.
async fn daemon_timed(req: reqwest::RequestBuilder) -> anyhow::Result<(u128, serde_json::Value)> {
    let t = Instant::now();
    let resp = req.send().await?.error_for_status()?;
    let body = resp.text().await?;
    let us = t.elapsed().as_micros();
    let v = if body.trim().is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(&body)?
    };
    Ok((us, v))
}

/// `POST /v1/vms` with `body`, returning (elapsed µs, the created `vm.id`). Parses via
/// `serde_json::Value` because the typed DTOs live in `vmcell-daemon`, which cannot be a
/// dependency of `vmcell` (the `vmcell-daemon → vmcell` back-edge makes it a cyclic package).
async fn daemon_create(
    http: &reqwest::Client,
    base: &str,
    body: &serde_json::Value,
) -> anyhow::Result<(u128, String)> {
    let (us, v) = daemon_timed(
        http.post(format!("{base}/v1/vms"))
            .header("content-type", "application/json")
            .body(body.to_string()),
    )
    .await?;
    // `.get()` rather than `v["vm"]["id"]`: serde_json's Index panics on a non-object, and a daemon
    // that answered with an error body is exactly the case this must report, not crash on.
    let id = v
        .get("vm")
        .and_then(|vm| vm.get("id"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("daemon-api: create response carried no vm.id"))?
        .to_string();
    Ok((us, id))
}

/// `DELETE /v1/vms/{id}`, returning the elapsed µs.
async fn daemon_destroy(http: &reqwest::Client, base: &str, id: &str) -> anyhow::Result<u128> {
    let (us, _) = daemon_timed(http.delete(format!("{base}/v1/vms/{id}"))).await?;
    Ok(us)
}

/// Reports a daemon op's µs samples as ms (one decimal) through the shared nearest-rank
/// `pcts` — the ONE percentile law (no second copy, unlike the retired python `pctl`).
fn report_daemon_op(name: &str, samples: &mut [u128]) {
    match pcts(samples) {
        Some((p50, p95, p99, max)) => {
            let ms = |us: u128| us as f64 / 1000.0;
            println!(
                "  {name:8}: count={} p50={:.1}ms p95={:.1}ms p99={:.1}ms max={:.1}ms",
                samples.len(),
                ms(p50),
                ms(p95),
                ms(p99),
                ms(max)
            );
        }
        None => println!("  {name:8}: No successful samples"),
    }
}

/// §16 (Performance) — daemon-api: create/restore/exec/list/destroy latency through the
/// `vmcelld` HTTP + broker bridge. `list` (no VMM work) is the pure bridge floor; `restore`
/// exercises `restore_cow`. Spawns its own `vmcelld` (inheriting the runner's ambient caps),
/// times each op with `Instant`, and reports via `pcts`.
async fn run_daemon_api(args: &Args) -> anyhow::Result<()> {
    // The daemon binary sits next to this one (same cargo profile dir: target/<profile>/).
    let exe =
        std::env::current_exe().map_err(|e| anyhow::anyhow!("daemon-api: current_exe: {e}"))?;
    let vmcelld = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("daemon-api: current_exe has no parent dir"))?
        .join("vmcelld");
    if !vmcelld.exists() {
        anyhow::bail!(
            "daemon-api: vmcelld not built at {} (cargo build --locked --release -p vmcelld)",
            vmcelld.display()
        );
    }

    let (adir, kernel, rootfs) = artifact_paths(args.kernel.as_deref());
    if !kernel.exists() || !rootfs.exists() {
        println!("daemon-api: No successful runs (missing artifacts in {adir})");
        anyhow::bail!("daemon-api: missing artifacts in {adir}");
    }

    // Private ephemeral artifact store: symlink the two prebuilt artifacts in (the store
    // reads through symlinks — no copy). Dropped (cleaned) at function end.
    let store = tempfile::tempdir().map_err(|e| anyhow::anyhow!("daemon-api: tempdir: {e}"))?;
    for name in ["vmlinux", "rootfs.erofs"] {
        std::os::unix::fs::symlink(PathBuf::from(&adir).join(name), store.path().join(name))
            .map_err(|e| anyhow::anyhow!("daemon-api: symlink {name}: {e}"))?;
    }

    // Free ephemeral port so a stale/parallel daemon does not collide.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|e| anyhow::anyhow!("daemon-api: bind ephemeral port: {e}"))?;
        l.local_addr()
            .map_err(|e| anyhow::anyhow!("daemon-api: local_addr: {e}"))?
            .port()
    };
    let base = format!("http://127.0.0.1:{port}");
    let iters = args.iters();
    let warmup = args.warmup;
    let total = iters + warmup;

    println!(
        "=== DAEMON-API (vmcelld HTTP + broker bridge; port={port} n={iters} warmup={warmup}) ==="
    );

    // Launch vmcelld directly — bench-vm runs under the blessed runner, so the daemon inherits
    // the three caps via the ambient set (the integration-harness path). Real broker split
    // (no --no-setup-broker) so the bridge is what we measure.
    let log = store.path().join("vmcelld.log");
    let logf = std::fs::File::create(&log)
        .map_err(|e| anyhow::anyhow!("daemon-api: create daemon log: {e}"))?;
    let logf2 = logf
        .try_clone()
        .map_err(|e| anyhow::anyhow!("daemon-api: dup daemon log fd: {e}"))?;
    let child = std::process::Command::new(&vmcelld)
        .arg("--artifacts-dir")
        .arg(store.path())
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--allow-unauthenticated")
        .arg("--resource-prefix")
        .arg("vmcd")
        .stdout(logf)
        .stderr(logf2)
        .spawn()
        .map_err(|e| anyhow::anyhow!("daemon-api: spawn vmcelld: {e}"))?;
    // Owns teardown from here (SIGTERM → wait → SIGKILL), even on an early `?`.
    let mut daemon = DaemonChild(child);

    let http = reqwest::Client::new();

    // Readiness: poll /healthz (20 s budget, matching the integration harness).
    let mut healthy = false;
    for _ in 0..80 {
        if let Ok(r) = http.get(format!("{base}/healthz")).send().await
            && r.status().is_success()
        {
            healthy = true;
            break;
        }
        if matches!(daemon.0.try_wait(), Ok(Some(_))) {
            anyhow::bail!(
                "daemon-api: vmcelld exited before healthz (log: {})",
                log.display()
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    if !healthy {
        anyhow::bail!(
            "daemon-api: vmcelld not healthy in 20s (log: {})",
            log.display()
        );
    }

    let create_body = serde_json::json!({ "kernel": "vmlinux", "rootfs": "rootfs.erofs" });
    let exec_body = serde_json::json!({ "argv": ["/bin/true"] });

    // --- Lifecycle loop: create -> destroy, timing each (warmup excluded) ---
    let mut create_us = Vec::with_capacity(iters);
    let mut destroy_us = Vec::with_capacity(iters);
    for i in 0..total {
        let (cms, id) = daemon_create(&http, &base, &create_body).await?;
        let dms = daemon_destroy(&http, &base, &id).await?;
        if i >= warmup {
            create_us.push(cms);
            destroy_us.push(dms);
        }
    }

    // --- Steady-op loop: one VM, N list + N exec (isolates the per-op bridge cost) ---
    let (_, sid) = daemon_create(&http, &base, &create_body).await?;
    for _ in 0..warmup {
        let _ = daemon_timed(http.get(format!("{base}/v1/vms"))).await?;
        let _ = daemon_timed(
            http.post(format!("{base}/v1/vms/{sid}/exec"))
                .header("content-type", "application/json")
                .body(exec_body.to_string()),
        )
        .await?;
    }
    let mut list_us = Vec::with_capacity(iters);
    let mut exec_us = Vec::with_capacity(iters);
    for _ in 0..iters {
        let (lms, _) = daemon_timed(http.get(format!("{base}/v1/vms"))).await?;
        list_us.push(lms);
        let (ems, _) = daemon_timed(
            http.post(format!("{base}/v1/vms/{sid}/exec"))
                .header("content-type", "application/json")
                .body(exec_body.to_string()),
        )
        .await?;
        exec_us.push(ems);
    }
    daemon_destroy(&http, &base, &sid).await?;

    // --- Restore loop: snapshot one source VM once, then time N `restore_cow` restores ---
    let (_, src_id) = daemon_create(
        &http,
        &base,
        &serde_json::json!({ "kernel": "vmlinux", "rootfs": "rootfs.erofs", "snapshotting": true }),
    )
    .await?;
    daemon_timed(
        http.post(format!("{base}/v1/vms/{src_id}/snapshot"))
            .header("content-type", "application/json")
            .body(serde_json::json!({ "artifact_prefix": "snap0" }).to_string()),
    )
    .await?;
    let restore_body = serde_json::json!({
        "kernel": "vmlinux", "rootfs": "rootfs.erofs", "snapshotting": true, "restore_from": "snap0"
    });
    let mut restore_us = Vec::with_capacity(iters);
    for i in 0..total {
        let (rms, rid) = daemon_create(&http, &base, &restore_body).await?;
        daemon_destroy(&http, &base, &rid).await?;
        if i >= warmup {
            restore_us.push(rms);
        }
    }
    daemon_destroy(&http, &base, &src_id).await?;

    report_daemon_op("create", &mut create_us);
    report_daemon_op("restore", &mut restore_us);
    report_daemon_op("exec", &mut exec_us);
    report_daemon_op("list", &mut list_us);
    report_daemon_op("destroy", &mut destroy_us);
    println!("=== DAEMON-API done ===");

    // Explicit graceful teardown (rather than waiting for the drop) so a hiccup surfaces here;
    // `store` cleanup follows on its own drop.
    drop(daemon);
    Ok(())
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
