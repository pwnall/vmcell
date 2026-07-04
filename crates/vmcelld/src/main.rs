//! `vmcelld` — the blessed vmcell control-plane daemon binary (design v21 §D2/§D6).
//!
//! Blessed exactly like `vmcell-test-runner` (file-caps installed by `just bless`), but it **retains**
//! the three privileged caps for the life of the server instead of dropping-and-exec'ing: it runs the
//! shared blessing precondition ([`vmcell_privilege::ensure_blessed_or_explain`]) and, on success,
//! keeps its caps and serves. If a cap is missing it prints the same `setcap …+ep` remediation and
//! exits non-zero — **refuse to start if privileges are missing**.
//!
//! `print_stdout`/`print_stderr` are NOT denied — a daemon binary logs startup/fatal diagnostics.
#![deny(missing_docs, unsafe_op_in_unsafe_fn, rustdoc::broken_intra_doc_links)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::todo,
        clippy::unimplemented
    )
)]

use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use vmcell_daemon::artifact_store::ArtifactStore;
use vmcell_daemon::auth::{AuthPolicy, load_api_key_file};
use vmcell_daemon::launcher::MicroVmLauncher;
use vmcell_daemon::registry::Registry;
use vmcell_daemon::server::{AppState, serve};
use vmcell_daemon::sweep::startup_sweep;
use vmcell_privilege::PRIVILEGED_CAPS;

/// The vmcell control-plane daemon.
#[derive(Parser)]
#[command(name = "vmcelld", version, about, long_about = None)]
struct Cli {
    /// Directory the artifact store lives in (kernels/rootfs/snapshots referenced by name).
    #[arg(long)]
    artifacts_dir: PathBuf,

    /// TCP address to bind, e.g. `127.0.0.1:8787` (loopback by default — the setup broker / UDS bind
    /// are forward work, v21 §D12).
    #[arg(long, default_value = "127.0.0.1:8787")]
    bind: String,

    /// Path to the bearer API-key file (owner-only perms required). Refuse to start without it,
    /// unless `--allow-unauthenticated`.
    #[arg(long)]
    api_key_file: Option<PathBuf>,

    /// Disable authentication — ONLY for a loopback dev bind; logged loudly at every request.
    #[arg(long)]
    allow_unauthenticated: bool,

    /// Per-upload artifact size cap in bytes.
    #[arg(long, default_value_t = 4 * 1024 * 1024 * 1024)]
    max_artifact_bytes: u64,

    /// The `cloud-hypervisor` binary path (else `$VMCELL_CH_BIN`, else `cloud-hypervisor`).
    #[arg(long)]
    ch_bin: Option<String>,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    if let Err(code) = run() {
        // allow(disallowed_methods): top-level terminator. Either the config/blessing check failed
        // before any owned resource exists, or the server future returned after `shutdown_all`/`Drop`
        // already tore the owned VMs down; a non-zero shell status is the required contract.
        #[allow(clippy::disallowed_methods)]
        std::process::exit(code);
    }
}

/// The fallible body. Returns the desired non-zero exit code on failure.
fn run() -> Result<(), i32> {
    let cli = Cli::parse();

    // Blessing precondition (shared with the test-runner): the three privileged caps must be in the
    // EFFECTIVE set, or euid 0. On success we RETAIN them (no uid drop, no exec) — v21 §D2.
    if let Err(remediation) = vmcell_privilege::ensure_blessed_or_explain(&PRIVILEGED_CAPS) {
        eprintln!("{remediation}");
        return Err(1);
    }

    // Auth policy: an owner-only key file, or the explicit dev bypass. A control plane with no auth
    // is never an accident (v21 §D6) — refuse to start otherwise.
    let auth = match (&cli.api_key_file, cli.allow_unauthenticated) {
        (Some(path), _) => match load_api_key_file(path) {
            Ok(key) => AuthPolicy::Key(key),
            Err(e) => {
                eprintln!("vmcelld: {e}");
                return Err(1);
            }
        },
        (None, true) => {
            tracing::warn!(
                "vmcelld: starting with --allow-unauthenticated; the API is UNPROTECTED. Use only \
                 on a loopback dev bind."
            );
            AuthPolicy::Unauthenticated
        }
        (None, false) => {
            eprintln!(
                "vmcelld: refusing to start without authentication. Pass --api-key-file <path> \
                 (owner-only perms) or, for a loopback dev bind only, --allow-unauthenticated."
            );
            return Err(1);
        }
    };

    let ch_bin = cli
        .ch_bin
        .clone()
        .or_else(|| std::env::var("VMCELL_CH_BIN").ok())
        .unwrap_or_else(|| "cloud-hypervisor".to_string());

    let artifacts = match ArtifactStore::open(&cli.artifacts_dir, cli.max_artifact_bytes) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("vmcelld: {e}");
            return Err(1);
        }
    };

    // Start-up orphan sweep (v21 §D4): reclaim netns/cgroup/scratch a previously hard-killed daemon
    // leaked, BEFORE we own any VM. We hold the caps (blessed above) that netns delete needs.
    let report = startup_sweep();
    if !report.netns.is_empty()
        || !report.cgroup_slices.is_empty()
        || !report.scratch_dirs.is_empty()
    {
        tracing::info!(
            netns = report.netns.len(),
            cgroup_slices = report.cgroup_slices.len(),
            scratch_dirs = report.scratch_dirs.len(),
            "vmcelld: reclaimed leaked resources from a prior daemon"
        );
    }

    let launcher = MicroVmLauncher::new(ch_bin);
    let registry = Arc::new(Registry::new(Box::new(launcher), artifacts, id_seed()));
    let state = AppState {
        registry: registry.clone(),
        auth,
        max_artifact_bytes: usize::try_from(cli.max_artifact_bytes).unwrap_or(usize::MAX),
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("vmcelld: cannot build async runtime: {e}");
            return Err(1);
        }
    };
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&cli.bind).await.map_err(|e| {
            eprintln!("vmcelld: cannot bind {}: {e}", cli.bind);
            1
        })?;
        tracing::info!(bind = %cli.bind, artifacts = %cli.artifacts_dir.display(), "vmcelld serving");
        // Serve until a shutdown signal, then gracefully tear down every owned VM (the ordered
        // `MicroVm::shutdown` path). A hard kill skips this and relies on the next boot's sweep.
        tokio::select! {
            r = serve(state, listener) => r.map_err(|e| { eprintln!("vmcelld: server error: {e}"); 1 }),
            _ = shutdown_signal() => {
                tracing::info!("vmcelld: shutdown signal received; tearing down owned VMs");
                registry.shutdown_all().await;
                Ok(())
            }
        }
    })
}

/// Resolves when the process receives SIGINT (Ctrl-C) or SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
}

/// A per-process seed for the opaque VM ids (start time mixed with pid), so ids are not a bare
/// guessable counter across daemon restarts.
fn id_seed() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    nanos ^ (u64::from(std::process::id()) << 32)
}
