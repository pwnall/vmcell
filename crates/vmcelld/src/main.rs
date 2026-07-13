//! `vmcelld` — the blessed vmcell control-plane daemon binary (design §11.2 (Privilege and blessing) / §12.4 (Layer 3 — the setup broker (network surface never holds caps))).
//!
//! **Privilege-separated by default (the §12.4 (Layer 3 — the setup broker (network surface never holds caps)) setup-broker cutover).** `vmcelld` runs the shared
//! blessing precondition ([`vmcell_privilege::ensure_blessed_or_explain`]) and then **forks**: the
//! **broker child** keeps the three privileged caps and owns the VM [`Registry`] (netns/tap/nft/cgroup
//! and the jailed VMM spawn all need caps), while the **parent drops ALL caps**
//! ([`vmcell_privilege::apply_broker_parent_drop`]) and serves the network-facing HTTP API,
//! forwarding every VM op to the broker over the framed [`vmcell_daemon::bridge`] RPC. So a bug in
//! the HTTP request parser can never reach the caps, and the cap-holder never parses attacker input
//! (§12.4, Layer 3 — the setup broker (network surface never holds caps)). `--no-setup-broker` falls back to the single-process retain-caps model (§11.2, Privilege and blessing).
//!
//! A daemon logs through `tracing`, never `print`/`eprintln` (full-family, v3) — so
//! `print_stdout`/`print_stderr` are denied. The subscriber is installed as the very first line of
//! `main`, so every startup and fatal diagnostic (blessing, auth, bind, fork, cap-drop) goes through
//! `tracing::{error,warn,info}!` onto the same stderr, keeping the whole daemon one
//! consistently-formatted stream instead of interleaving raw `eprintln` with structured events.
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
        clippy::print_stdout,                   // v3: a daemon logs via tracing, never stdout
        clippy::print_stderr,                   // v3: a daemon logs via tracing, never stderr
        clippy::dbg_macro,
        clippy::allow_attributes,               // B11: prefer #[expect] over #[allow] in prod code
        clippy::allow_attributes_without_reason  // B11: every suppression states why
    )
)]

use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use vmcell_broker::ForkSide;
use vmcell_daemon::artifact_store::ArtifactStore;
use vmcell_daemon::auth::{AuthPolicy, load_api_key_file};
use vmcell_daemon::bridge::{BrokerClientEngine, VmEngine, serve_engine};
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

    /// TCP address to bind, e.g. `127.0.0.1:8787` (loopback by default; the cap-dropped HTTP parent
    /// binds it — the broker child never touches the network).
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

    /// Prefix for this daemon's swept host-resource names (netns/tap/cgroup/scratch). Both the VMs it
    /// creates and its start-up orphan sweep use this one value, so two daemons with distinct prefixes
    /// never sweep each other's resources. `[A-Za-z0-9]`, ≤ 6 chars (v21).
    #[arg(long, default_value = "vmcell")]
    resource_prefix: String,

    /// Fall back to the single-process retain-caps model (§11.2, Privilege and blessing): no broker fork, the caps stay in
    /// the HTTP-serving process. The setup-broker split (§12.4, Layer 3 — the setup broker (network surface never holds caps)) is the default.
    #[arg(long)]
    no_setup_broker: bool,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    if let Err(code) = run() {
        // expect(disallowed_methods): top-level terminator. Either the config/blessing check failed
        // before any owned resource exists, or the server future returned after graceful teardown.
        #[expect(
            clippy::disallowed_methods,
            reason = "top-level terminator; owned VMs already torn down or none exist yet"
        )]
        std::process::exit(code);
    }
}

/// The fallible body. Returns the desired non-zero exit code on failure.
fn run() -> Result<(), i32> {
    let cli = Cli::parse();

    // Blessing precondition (shared with the test-runner): the three privileged caps must be in the
    // EFFECTIVE set, or euid 0. Checked BEFORE the fork so both the broker child (which keeps them)
    // and the parent (which drops them) start from a known-blessed state.
    if let Err(remediation) = vmcell_privilege::ensure_blessed_or_explain(&PRIVILEGED_CAPS) {
        tracing::error!("{remediation}");
        return Err(1);
    }

    // Reject a malformed resource prefix up front (it becomes part of netns/interface/cgroup/dir
    // names). One value drives both VM naming and the sweep, so they can never disagree (v21).
    if let Err(e) = vmcell_daemon::naming::validate_resource_prefix(&cli.resource_prefix) {
        tracing::error!("vmcelld: {e}");
        return Err(1);
    }

    let ch_bin = cli
        .ch_bin
        .clone()
        .or_else(|| std::env::var("VMCELL_CH_BIN").ok())
        .unwrap_or_else(|| "cloud-hypervisor".to_string());

    if cli.no_setup_broker {
        // Single-process retain-caps fallback (§11.2, Privilege and blessing): the HTTP surface keeps the caps.
        return run_single_process(&cli, ch_bin);
    }

    // The setup-broker split (§12.4, Layer 3 — the setup broker (network surface never holds caps)): fork BEFORE any thread/runtime exists (fork-with-threads is
    // unsafe). The child keeps the caps and owns the registry; the parent drops all caps and serves.
    match vmcell_broker::fork_privileged_child() {
        Ok(ForkSide::Child { sock }) => run_broker_child(&cli, ch_bin, sock),
        Ok(ForkSide::Parent { sock, child }) => run_http_parent(&cli, sock, child),
        Err(e) => {
            tracing::error!("vmcelld: cannot fork the setup broker: {e}");
            Err(1)
        }
    }
}

/// The **broker child**: keeps the three caps, owns the VM [`Registry`], runs the start-up orphan
/// sweep, and serves the [`vmcell_daemon::bridge`] RPC over `sock`. Never returns — it `_exit`s so a
/// forked child does not run the parent's at-exit handlers.
fn run_broker_child(cli: &Cli, ch_bin: String, sock: std::os::unix::net::UnixStream) -> ! {
    let code = run_broker_child_inner(cli, ch_bin, sock);
    // SAFETY: `_exit` is async-signal-safe and skips at-exit handlers — the forked child must not run
    // the parent's teardown. The registry (and its VMs) already dropped inside `block_on` above.
    unsafe { libc::_exit(code) }
}

fn run_broker_child_inner(cli: &Cli, ch_bin: String, sock: std::os::unix::net::UnixStream) -> i32 {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!("vmcelld broker: cannot build async runtime: {e}");
            return 1;
        }
    };
    runtime.block_on(async move {
        // Start-up orphan sweep (§11.4, The VM registry and the start-up sweep): reclaim leaks (matching `--resource-prefix`) a previously
        // hard-killed daemon left, BEFORE we own any VM. The broker holds the caps netns delete needs.
        let report = startup_sweep(&cli.resource_prefix);
        if !report.netns.is_empty()
            || !report.cgroup_slices.is_empty()
            || !report.scratch_dirs.is_empty()
        {
            tracing::info!(
                netns = report.netns.len(),
                cgroup_slices = report.cgroup_slices.len(),
                scratch_dirs = report.scratch_dirs.len(),
                "vmcelld broker: reclaimed leaked resources from a prior daemon"
            );
        }

        let artifacts = match ArtifactStore::open(&cli.artifacts_dir, cli.max_artifact_bytes) {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("vmcelld broker: {e}");
                return 1;
            }
        };
        let launcher = match MicroVmLauncher::new(ch_bin, &cli.resource_prefix) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("vmcelld: {e}");
                return 1;
            }
        };
        let registry: Arc<dyn VmEngine> =
            Arc::new(Registry::new(Box::new(launcher), artifacts, id_seed()));

        if let Err(e) = sock.set_nonblocking(true) {
            tracing::error!("vmcelld broker: cannot set the control socket nonblocking: {e}");
            return 1;
        }
        let sock = match tokio::net::UnixStream::from_std(sock) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("vmcelld broker: cannot adopt the control socket: {e}");
                return 1;
            }
        };
        tracing::info!("vmcelld broker: serving (holds caps; owns the registry)");
        // Serves until the parent sends `ShutdownAll` (VMs torn down, then returns) or closes the
        // channel (then dropping `registry` at end of scope runs each VM's ordered teardown).
        serve_engine(registry, sock).await;
        0
    })
}

/// The **HTTP parent**: drops ALL capabilities (§12.4, Layer 3 — the setup broker (network surface never holds caps)), then serves the axum API and the local
/// artifact store, forwarding VM ops to the broker over `sock`.
fn run_http_parent(
    cli: &Cli,
    sock: std::os::unix::net::UnixStream,
    child: vmcell_broker::BrokerChild,
) -> Result<(), i32> {
    // Drop EVERY capability before binding the network socket — the HTTP surface holds none (§12.4, Layer 3 — the setup broker (network surface never holds caps)).
    let plan = vmcell_privilege::plan_broker_parent_drop(&vmcell_privilege::probe_supported_caps());
    if let Err(e) = vmcell_privilege::apply_broker_parent_drop(&plan) {
        tracing::error!("vmcelld: the HTTP parent could not drop its capabilities: {e}");
        return Err(1);
    }

    // Auth policy: an owner-only key file, or the explicit dev bypass (§11.6, Authentication — a bearer API key).
    let auth = auth_policy(cli)?;
    let artifacts = match ArtifactStore::open(&cli.artifacts_dir, cli.max_artifact_bytes) {
        Ok(a) => Arc::new(a),
        Err(e) => {
            tracing::error!("vmcelld: {e}");
            return Err(1);
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!("vmcelld: cannot build async runtime: {e}");
            return Err(1);
        }
    };
    let bind = cli.bind.clone();
    let max = usize::try_from(cli.max_artifact_bytes).unwrap_or(usize::MAX);
    // Hold the child handle so it is reaped (its `Drop` kills+reaps) after the runtime returns.
    let _child = child;
    runtime.block_on(async move {
        if let Err(e) = sock.set_nonblocking(true) {
            tracing::error!("vmcelld: cannot set the broker socket nonblocking: {e}");
            return Err(1);
        }
        let sock = match tokio::net::UnixStream::from_std(sock) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("vmcelld: cannot adopt the broker socket: {e}");
                return Err(1);
            }
        };
        let engine: Arc<dyn VmEngine> = BrokerClientEngine::new(sock);
        let state = AppState {
            engine: engine.clone(),
            artifacts,
            auth,
            max_artifact_bytes: max,
        };
        let listener = tokio::net::TcpListener::bind(&bind).await.map_err(|e| {
            tracing::error!("vmcelld: cannot bind {bind}: {e}");
            1
        })?;
        tracing::info!(bind = %bind, "vmcelld serving (HTTP parent; no capabilities)");
        let serve_result = tokio::select! {
            r = serve(state, listener) => r.map_err(|e| { tracing::error!("vmcelld: server error: {e}"); 1 }),
            _ = shutdown_signal() => {
                tracing::info!("vmcelld: shutdown signal received; asking the broker to tear down VMs");
                Ok(())
            }
        };
        // Always ask the broker to gracefully tear down its VMs before we let its handle reap it.
        engine.shutdown_all().await;
        serve_result
    })
}

/// The single-process retain-caps fallback (§11.2, Privilege and blessing): the HTTP surface keeps the three caps and owns
/// the registry directly — no broker, no privilege separation. Selected with `--no-setup-broker`.
fn run_single_process(cli: &Cli, ch_bin: String) -> Result<(), i32> {
    tracing::warn!(
        "vmcelld: --no-setup-broker; the HTTP surface RETAINS the three caps (no privilege \
         separation). Prefer the default setup-broker split (§12.4, Layer 3 — the setup broker)."
    );
    let auth = auth_policy(cli)?;
    let artifacts = match ArtifactStore::open(&cli.artifacts_dir, cli.max_artifact_bytes) {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("vmcelld: {e}");
            return Err(1);
        }
    };

    let report = startup_sweep(&cli.resource_prefix);
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

    let launcher = match MicroVmLauncher::new(ch_bin, &cli.resource_prefix) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("vmcelld: {e}");
            return Err(1);
        }
    };
    let registry: Arc<dyn VmEngine> =
        Arc::new(Registry::new(Box::new(launcher), artifacts, id_seed()));
    let parent_artifacts = match ArtifactStore::open(&cli.artifacts_dir, cli.max_artifact_bytes) {
        Ok(a) => Arc::new(a),
        Err(e) => {
            tracing::error!("vmcelld: {e}");
            return Err(1);
        }
    };
    let state = AppState {
        engine: registry.clone(),
        artifacts: parent_artifacts,
        auth,
        max_artifact_bytes: usize::try_from(cli.max_artifact_bytes).unwrap_or(usize::MAX),
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!("vmcelld: cannot build async runtime: {e}");
            return Err(1);
        }
    };
    let bind = cli.bind.clone();
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&bind).await.map_err(|e| {
            tracing::error!("vmcelld: cannot bind {bind}: {e}");
            1
        })?;
        tracing::info!(bind = %bind, "vmcelld serving (single-process, retains caps)");
        tokio::select! {
            r = serve(state, listener) => r.map_err(|e| { tracing::error!("vmcelld: server error: {e}"); 1 }),
            _ = shutdown_signal() => {
                tracing::info!("vmcelld: shutdown signal received; tearing down owned VMs");
                registry.shutdown_all().await;
                Ok(())
            }
        }
    })
}

/// Resolves the bearer-auth policy from the CLI: an owner-only key file, or the explicit dev bypass.
/// A control plane with no auth is never an accident (§11.6, Authentication — a bearer API key) — refuse to start otherwise.
fn auth_policy(cli: &Cli) -> Result<AuthPolicy, i32> {
    match (&cli.api_key_file, cli.allow_unauthenticated) {
        (Some(path), _) => match load_api_key_file(path) {
            Ok(key) => Ok(AuthPolicy::Key(key)),
            Err(e) => {
                tracing::error!("vmcelld: {e}");
                Err(1)
            }
        },
        (None, true) => {
            tracing::warn!(
                "vmcelld: starting with --allow-unauthenticated; the API is UNPROTECTED. Use only \
                 on a loopback dev bind."
            );
            Ok(AuthPolicy::Unauthenticated)
        }
        (None, false) => {
            tracing::error!(
                "vmcelld: refusing to start without authentication. Pass --api-key-file <path> \
                 (owner-only perms) or, for a loopback dev bind only, --allow-unauthenticated."
            );
            Err(1)
        }
    }
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
