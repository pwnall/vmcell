//! `vmcelld-ctl` — a CLI over [`vmcell_daemon_client`] (design §11.7, The client library and CLI).
//!
//! Argument marshaling + output formatting only; every operation is a `DaemonClient` call. `run`/
//! `exec` relay the guest's captured stdout/stderr and propagate its exit code, exactly as `vmcell
//! run` does (design §11, The control-plane daemon (vmcelld)).
//!
//! `print_stdout`/`print_stderr` are NOT denied — a CLI writes results to stdout/stderr.
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
        // AGENTS.md "Fail loud": no bare `let _ =` on a `Result`. `let_underscore_must_use` is the
        // narrowest instrument rustc/clippy has for that rule — and it is deliberately BROADER on
        // one axis, firing on any `#[must_use]` expression (a detached `JoinHandle`, a discarded
        // `Instant`), which is the same defect one step out: the compiler said this matters and the
        // code said nothing back. Scoped `not(test)` like every lint in this block: the rule's
        // stated harms (a swallowed teardown failure, a lost write, a wedged session) are
        // production harms, and forcing a reason onto a test's `try_init()` would manufacture the
        // hollow suppressions AGENTS.md rule 2 calls theater. `crates/vmcell/tests/lint_roster.rs`
        // is the gate that this line exists in EVERY crate root, so a new crate cannot opt out by
        // being new.
        clippy::let_underscore_must_use,
        clippy::allow_attributes,               // B11: prefer #[expect] over #[allow] in prod code
        clippy::allow_attributes_without_reason  // B11: every suppression states why
    )
)]

use clap::{Parser, Subcommand};
use std::io::Write as _;
use std::path::PathBuf;
use url::Url;
use vmcell_daemon_client::dto::{ExecRequestDto, VmId};
use vmcell_daemon_client::{ClientError, DaemonClient};

/// Control a vmcell daemon (`vmcelld`).
#[derive(Parser)]
#[command(name = "vmcelld-ctl", version, about, long_about = None)]
struct Cli {
    /// The daemon base URL.
    #[arg(long, env = "VMCELLD_URL", default_value = "http://127.0.0.1:8787")]
    daemon_url: Url,

    /// Path to a file holding the bearer API key (trailing newline trimmed).
    #[arg(long, env = "VMCELLD_API_KEY_FILE")]
    api_key_file: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Artifact store operations.
    Artifact {
        #[command(subcommand)]
        op: ArtifactOp,
    },
    /// Report the artifact store's usage against its quota (JSON).
    Store,
    /// Create a VM and keep it (boot to steward-ready).
    Create {
        /// Kernel artifact name.
        #[arg(long)]
        kernel: String,
        /// Rootfs artifact name.
        #[arg(long)]
        rootfs: String,
    },
    /// Create a VM, run a command, tear it down, and propagate its exit code.
    Run {
        /// Kernel artifact name.
        #[arg(long)]
        kernel: String,
        /// Rootfs artifact name.
        #[arg(long)]
        rootfs: String,
        /// The command (and args) to run in the guest.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        cmd: Vec<String>,
    },
    /// List live VMs.
    Ls,
    /// Get one VM.
    Get {
        /// The VM id.
        id: String,
    },
    /// Run a command in an existing VM and propagate its exit code.
    Exec {
        /// The VM id.
        id: String,
        /// The command (and args) to run.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        cmd: Vec<String>,
    },
    /// Sample a VM's resource usage (JSON).
    Stats {
        /// The VM id.
        id: String,
    },
    /// Pause a VM's vCPUs (it keeps every host resource, and still pins its artifacts).
    Pause {
        /// The VM id.
        id: String,
    },
    /// Resume a paused VM's vCPUs.
    Resume {
        /// The VM id.
        id: String,
    },
    /// Write a warm snapshot of a VM into the artifact store.
    Snapshot {
        /// The VM id.
        id: String,
        /// The artifact-store subdirectory prefix to write under.
        prefix: String,
    },
    /// Destroy a VM.
    Rm {
        /// The VM id.
        id: String,
    },
}

#[derive(Subcommand)]
enum ArtifactOp {
    /// Upload a local file as a named artifact.
    Put {
        /// The artifact name (a safe single component).
        name: String,
        /// The local file to upload.
        path: PathBuf,
    },
    /// List artifacts (JSON).
    Ls,
    /// Delete an artifact.
    Rm {
        /// The artifact name.
        name: String,
    },
}

fn main() {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("vmcelld-ctl: cannot build runtime: {e}");
            // expect(disallowed_methods): the runtime failed to build — no owned state to unwind.
            #[expect(
                clippy::disallowed_methods,
                reason = "runtime failed to build — no owned state to unwind"
            )]
            std::process::exit(1);
        }
    };
    let code = rt.block_on(async_main());
    // expect(disallowed_methods): the async body returned and its Drops ran; the CLI must exit with
    // the guest's own code (run/exec) or 0/1 — a non-zero shell status is the contract (design §11,
    // The control-plane daemon (vmcelld)).
    #[expect(
        clippy::disallowed_methods,
        reason = "async body returned and its Drops ran; relay the guest's exit code as the shell status"
    )]
    std::process::exit(code);
}

async fn async_main() -> i32 {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("vmcelld-ctl: {e}");
            1
        }
    }
}

/// Runs the selected command, returning the process exit code (the guest's own code for run/exec).
async fn run(cli: Cli) -> Result<i32, Box<dyn std::error::Error>> {
    let api_key = match &cli.api_key_file {
        Some(path) => std::fs::read_to_string(path)?.trim().to_string(),
        None => String::new(),
    };
    let client = DaemonClient::new(cli.daemon_url, api_key)?;

    match cli.command {
        Command::Artifact { op } => {
            match op {
                ArtifactOp::Put { name, path } => {
                    let info = client.upload_artifact(&name, path).await?;
                    print_json(&info)?;
                }
                ArtifactOp::Ls => {
                    let list = client.list_artifacts().await?;
                    print_json(&list)?;
                }
                ArtifactOp::Rm { name } => {
                    client.delete_artifact(&name).await?;
                    println!("deleted artifact {name}");
                }
            }
            Ok(0)
        }
        Command::Store => {
            print_json(&client.store_usage().await?)?;
            Ok(0)
        }
        Command::Create { kernel, rootfs } => {
            let info = client.create(&kernel, &rootfs).await?;
            print_json(&info)?;
            Ok(0)
        }
        Command::Run {
            kernel,
            rootfs,
            cmd,
        } => {
            let outcome = client.run(&kernel, &rootfs, cmd).await?;
            relay_and_code(&outcome)
        }
        Command::Ls => {
            print_json(&client.ls().await?)?;
            Ok(0)
        }
        Command::Get { id } => {
            print_json(&client.get(&VmId(id)).await?)?;
            Ok(0)
        }
        Command::Exec { id, cmd } => {
            let outcome = client.exec(&VmId(id), ExecRequestDto::new(cmd)).await?;
            relay_and_code(&outcome)
        }
        Command::Stats { id } => {
            print_json(&client.stats(&VmId(id)).await?)?;
            Ok(0)
        }
        Command::Pause { id } => {
            print_json(&client.pause(&VmId(id)).await?)?;
            Ok(0)
        }
        Command::Resume { id } => {
            print_json(&client.resume(&VmId(id)).await?)?;
            Ok(0)
        }
        Command::Snapshot { id, prefix } => {
            print_json(&client.snapshot(&VmId(id), &prefix).await?)?;
            Ok(0)
        }
        Command::Rm { id } => {
            client.destroy(&VmId(id.clone())).await?;
            println!("destroyed vm {id}");
            Ok(0)
        }
    }
}

/// Relays a captured exec outcome to stdout/stderr and returns the guest's exit code (design §11,
/// The control-plane daemon (vmcelld)).
fn relay_and_code(
    outcome: &vmcell_daemon_client::dto::ExecOutcomeDto,
) -> Result<i32, Box<dyn std::error::Error>> {
    let stdout = outcome
        .stdout()
        .map_err(|e| format!("bad stdout base64: {e}"))?;
    let stderr = outcome
        .stderr()
        .map_err(|e| format!("bad stderr base64: {e}"))?;
    // Best-effort relay; a broken pipe must not mask the guest's exit code, which is what this
    // function contracts to return. Two statements, two reasons, because there is no third site to
    // route through a helper — the class has exactly these members in this crate.
    #[expect(
        clippy::let_underscore_must_use,
        reason = "EPIPE on the consumer side must not mask the guest's exit code returned below"
    )]
    let _ = std::io::stdout().write_all(&stdout);
    #[expect(
        clippy::let_underscore_must_use,
        reason = "same: a closed stderr consumer must not turn a completed guest command into an error"
    )]
    let _ = std::io::stderr().write_all(&stderr);
    Ok(outcome.code)
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<(), ClientError> {
    match serde_json::to_string_pretty(value) {
        Ok(s) => {
            println!("{s}");
            Ok(())
        }
        Err(e) => Err(ClientError::Decode(e.to_string())),
    }
}
