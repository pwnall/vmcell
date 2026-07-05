//! `vmcell` command-line entry point: the composition root that wires the `vmcell` library and the
//! in-VM `vmcell-rootfs-builder` / `vmcell-kernel-builder` stages into runnable subcommands
//! (`build`, `create`, …).
//!
//! `print_stdout`/`print_stderr` are intentionally NOT denied here — a CLI's whole job is to write
//! results and diagnostics to stdout/stderr.
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

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Which kernel builder produces the `vmlinux` for `build` (design §8.5).
#[derive(Copy, Clone, PartialEq, Eq, Debug, clap::ValueEnum)]
enum KernelSource {
    /// Download + SHA-verify a digest-pinned prebuilt `vmlinux` (the fast, no-toolchain
    /// bootstrap seed; the pinned Kata kernel is validated to boot §8.5).
    Prebuilt,
    /// Compile from the pinned source with `make` on the HOST (the guaranteed fallback seed).
    HostMake,
    /// Compile from the pinned source INSIDE a builder micro-VM (`vmcell-kernel-builder`).
    InVm,
}

/// Which rootfs builder produces the erofs for `build` (design §5.4).
#[derive(Copy, Clone, PartialEq, Eq, Debug, clap::ValueEnum)]
enum RootfsSourceKind {
    /// Pull + unpack a digest-pinned OCI base image on the HOST (the bootstrap source).
    Oci,
    /// Full-apt `mmdebstrap` INSIDE a builder micro-VM (`vmcell-rootfs-builder`).
    Mmdebstrap,
}

#[derive(Subcommand)]
enum Commands {
    /// Build the kernel + rootfs + agent + tools artifacts into the artifacts dir.
    Build {
        /// Which kernel builder to use for the `vmlinux` seed (§8.5).
        #[arg(long, value_enum, default_value_t = KernelSource::Prebuilt)]
        kernel_source: KernelSource,
        /// Which rootfs builder to use for the erofs (§5.4).
        #[arg(long, value_enum, default_value_t = RootfsSourceKind::Oci)]
        rootfs_source: RootfsSourceKind,
        /// Debian release suite for the `mmdebstrap` rootfs source (ignored for `oci`).
        #[arg(long, default_value = "trixie")]
        release: String,
    },
    /// Build every kernel in the pins `kernels` registry to `vmlinux-<label>`.
    BuildKernels {
        /// Compile each kernel inside a builder micro-VM (`vmcell-kernel-builder`) instead of
        /// on the host — the in-VM path needs a seed kernel already present (§8.5).
        #[arg(long)]
        in_vm: bool,
    },
    /// Convert any digest-pinned OCI image into an erofs rootfs (build-time; v15 §8.2).
    /// The base MUST be pinned by digest (`IMAGE@sha256:...`), never a tag.
    Oci2Erofs {
        /// The digest-pinned base image, e.g. `debian:trixie-slim@sha256:<hex>`.
        image: String,
        /// Output path for the packed erofs rootfs image.
        #[arg(short, long)]
        output: PathBuf,
        /// Inject this prebuilt static-musl guest agent instead of the default glibc agent
        /// (required for a libc6-less base). Without it, a libc6-less base fails loud.
        #[arg(long)]
        agent_musl: Option<PathBuf>,
    },
    /// Write a digest-pinned fetch-and-verify manifest of the built artifacts (kernel,
    /// rootfs, proxy CA, pins.json) for reproducibility (v15 §11).
    Bundle {
        /// Output path for the manifest JSON (default `<artifacts_dir>/manifest.json`).
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Re-hash every artifact in a manifest and fail loud on any digest mismatch (v15 §11).
    VerifyBundle {
        /// Manifest JSON to verify (default `<artifacts_dir>/manifest.json`).
        #[arg(short, long)]
        manifest: Option<PathBuf>,
    },
    /// Create a fresh micro-VM, run a command in it over vsock, then tear it down,
    /// exiting with the guest command's exit code (v15 §10.2).
    Run {
        /// Path to the `vmlinux` direct-boot kernel image.
        #[arg(long)]
        kernel: PathBuf,
        /// Path to the erofs root filesystem image.
        #[arg(long)]
        rootfs: PathBuf,
        /// vCPU count (default 2).
        #[arg(long, default_value_t = 2)]
        vcpus: u8,
        /// Guest RAM in MiB (default 512).
        #[arg(long, default_value_t = 512)]
        mem_mib: u32,
        /// Extra read-only virtio-blk device image (repeatable); enumerated in the
        /// guest as `/dev/vdb`, `/dev/vdc`, … after the root disk (§19.1).
        #[arg(long = "disk")]
        disk: Vec<PathBuf>,
        /// Extra read-write virtio-blk device image (repeatable).
        #[arg(long = "disk-rw")]
        disk_rw: Vec<PathBuf>,
        /// Append-only extra kernel command-line argument (repeatable); cannot
        /// override a reserved boot token vmcell owns (§19.2.1).
        #[arg(long = "append")]
        append: Vec<String>,
        /// Command (and args) to run in the guest. Defaults to `/bin/true`.
        ///
        /// `allow_hyphen_values` lets the guest argv carry its own flags without a
        /// `--` separator, e.g. `vmcell run --kernel k --rootfs r /bin/sh -c 'echo hi'`
        /// — otherwise clap intercepts the leading-hyphen `-c` as an unknown option.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// Create + boot a fresh micro-VM and confirm its agent is ready, then tear it
    /// down (a boot smoke test; v15 §10.2).
    Create {
        /// Path to the `vmlinux` direct-boot kernel image.
        #[arg(long)]
        kernel: PathBuf,
        /// Path to the erofs root filesystem image.
        #[arg(long)]
        rootfs: PathBuf,
        /// vCPU count (default 2).
        #[arg(long, default_value_t = 2)]
        vcpus: u8,
        /// Guest RAM in MiB (default 512).
        #[arg(long, default_value_t = 512)]
        mem_mib: u32,
        /// Extra read-only virtio-blk device image (repeatable); enumerated in the
        /// guest as `/dev/vdb`, `/dev/vdc`, … after the root disk (§19.1).
        #[arg(long = "disk")]
        disk: Vec<PathBuf>,
        /// Extra read-write virtio-blk device image (repeatable).
        #[arg(long = "disk-rw")]
        disk_rw: Vec<PathBuf>,
        /// Append-only extra kernel command-line argument (repeatable); cannot
        /// override a reserved boot token vmcell owns (§19.2.1).
        #[arg(long = "append")]
        append: Vec<String>,
    },
    /// Boot a micro-VM and write a warm snapshot into a directory, then tear it
    /// down (snapshot-eligible config only; v15 §10.2).
    Snapshot {
        /// Path to the `vmlinux` direct-boot kernel image.
        #[arg(long)]
        kernel: PathBuf,
        /// Path to the erofs root filesystem image.
        #[arg(long)]
        rootfs: PathBuf,
        /// Output directory for the snapshot artifacts.
        #[arg(long)]
        out: PathBuf,
        /// vCPU count (default 2).
        #[arg(long, default_value_t = 2)]
        vcpus: u8,
        /// Guest RAM in MiB (default 512).
        #[arg(long, default_value_t = 512)]
        mem_mib: u32,
    },
    /// Boot a micro-VM, sample its resource usage, print it as JSON, then tear it
    /// down (v15 §10.2).
    Stats {
        /// Path to the `vmlinux` direct-boot kernel image.
        #[arg(long)]
        kernel: PathBuf,
        /// Path to the erofs root filesystem image.
        #[arg(long)]
        rootfs: PathBuf,
        /// vCPU count (default 2).
        #[arg(long, default_value_t = 2)]
        vcpus: u8,
        /// Guest RAM in MiB (default 512).
        #[arg(long, default_value_t = 512)]
        mem_mib: u32,
    },
    /// Deferred to the `vmcelld` daemon (§18): a standalone exec needs a cross-process
    /// VM registry, which collides with the ordered-Drop-owns-cleanup invariant.
    Exec,
    /// Deferred to the `vmcelld` daemon (§18): listing VMs needs a cross-process registry.
    Ls,
    /// Deferred to the `vmcelld` daemon (§18): removing a VM by id needs a cross-process registry.
    Rm,
    /// Deferred to the `vmcelld` daemon (§18): destroying a VM by id needs a cross-process
    /// registry. Within one process the owning handle's drop/`shutdown` already destroys it.
    Destroy,
}

fn main() {
    // Surface the error's `Display` (the thiserror `#[error("…")]` message) on a
    // non-zero exit, not its `Debug` struct-dump. Returning `vmcell::Result<()>`
    // from `main` prints errors via `Termination`/`{:?}`, so an
    // `Error::Unsupported { vmm, feature }` would read as a raw struct instead of
    // the human-readable "Unsupported feature in …: …" line (L-BIN-4).
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("valid async runtime config")
        .block_on(async_main());
    if let Err(e) = result {
        eprintln!("vmcell: {e}");
        // expect(disallowed_methods): top-level bin exit AFTER the runtime future returned and its
        // Drops ran — nothing left to unwind; a non-zero shell status is the required contract.
        #[expect(
            clippy::disallowed_methods,
            reason = "top-level exit after the runtime future's Drops ran; nothing left to unwind"
        )]
        std::process::exit(1);
    }
}

async fn async_main() -> vmcell::Result<()> {
    let cli = Cli::parse();
    dispatch(&cli.command).await
}

/// Builds the typed error returned by a subcommand that is deferred to the `vmcelld`
/// daemon (§18) because it needs a cross-process VM registry.
///
/// These subcommands must fail loud — a typed, matchable error that drives a
/// non-zero exit — rather than printing fake success. Printing "Removing VM..." and
/// returning `Ok(())` while doing nothing is the "skip == pass" failure in CLI form:
/// it impersonates a completed operation.
fn deferred_to_daemon(subcommand: &str) -> vmcell::Error {
    vmcell::Error::Unsupported {
        vmm: "vmcell".to_string(),
        feature: format!(
            "subcommand `{subcommand}` needs a cross-process VM registry; deferred to the vmcelld daemon (§18)"
        ),
    }
}

/// Builds the kernel [`Stage`](vmcell::artifact::Stage) selected by `source` — a `vmcell`
/// bootstrap producer (prebuilt download or host-`make`) or the in-VM `vmcell-kernel-builder`.
/// This is the composition-root wiring that keeps the dependency graph acyclic (§10.1): only
/// `vmcell-cli` names the builder crates.
fn kernel_stage(
    source: KernelSource,
    label: Option<String>,
    fragments: Option<Vec<String>>,
    cid_alloc: std::sync::Arc<vmcell::vmm::CidAllocator>,
) -> Box<dyn vmcell::artifact::Stage> {
    let http_client = std::sync::Arc::new(vmcell::artifact::kernel::ReqwestClient);
    match source {
        KernelSource::Prebuilt => {
            Box::new(vmcell::artifact::kernel::PrebuiltKernelStage { http_client })
        }
        KernelSource::HostMake => Box::new(vmcell::artifact::kernel::KernelStage {
            http_client,
            label,
            fragments,
        }),
        KernelSource::InVm => Box::new(vmcell_kernel_builder::InVmKernelStage {
            http_client,
            label,
            fragments,
            cid_alloc,
        }),
    }
}

/// Builds the rootfs [`Stage`](vmcell::artifact::Stage) selected by `source` — the `vmcell`
/// OCI bootstrap producer or the in-VM `vmcell-rootfs-builder` mmdebstrap source (§5.4).
fn rootfs_stage(
    source: RootfsSourceKind,
    release: String,
    cid_alloc: std::sync::Arc<vmcell::vmm::CidAllocator>,
) -> Box<dyn vmcell::artifact::Stage> {
    match source {
        RootfsSourceKind::Oci => Box::new(vmcell::artifact::rootfs::RootfsStage {
            image_override: None,
            agent_musl: None,
        }),
        RootfsSourceKind::Mmdebstrap => {
            Box::new(vmcell_rootfs_builder::MmdebstrapRootfsStage { release, cid_alloc })
        }
    }
}

async fn dispatch(command: &Commands) -> vmcell::Result<()> {
    match command {
        Commands::Build {
            kernel_source,
            rootfs_source,
            release,
        } => {
            println!("Building artifacts...");
            // One CID allocator shared by any in-VM builder stage this pipeline runs.
            let cid_alloc = std::sync::Arc::new(vmcell::vmm::CidAllocator::new());
            let pipeline = vmcell::artifact::Pipeline::new(vmcell::artifact::artifacts_dir())
                .add_stage(Box::new(vmcell::artifact::ResolvePinsStage {
                    pins_file: pins_path(),
                }))
                .add_stage(kernel_stage(*kernel_source, None, None, cid_alloc.clone()))
                .add_stage(Box::new(vmcell::artifact::guest_agent::GuestAgentStage {}))
                .add_stage(Box::new(vmcell::artifact::guest_tools::GuestToolsStage {}))
                .add_stage(rootfs_stage(*rootfs_source, release.clone(), cid_alloc));
            pipeline.build(&vmcell::artifact::Cache::default()).await?;
            println!("Artifacts built successfully.");
            Ok(())
        }
        Commands::Oci2Erofs {
            image,
            output,
            agent_musl,
        } => oci2erofs(image, output, agent_musl.as_deref()).await,
        Commands::Bundle { out } => {
            let dir = vmcell::artifact::artifacts_dir();
            let mut candidates: Vec<(String, PathBuf)> = vec![
                ("kernel".to_string(), dir.join("vmlinux")),
                ("rootfs".to_string(), dir.join("rootfs.erofs")),
                ("ca".to_string(), dir.join("ca.pem")),
                ("pins".to_string(), pins_path()),
            ];
            // Cover every labelled kernel built by `build-kernels` (`vmlinux-<label>`),
            // not just the default `vmlinux` — otherwise the manifest silently omits
            // the cross-kernel sweep's artifacts (N-BIN-4).
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for e in rd.flatten() {
                    let fname = e.file_name();
                    let name = fname.to_string_lossy();
                    if let Some(label) = kernel_label_from_filename(&name) {
                        candidates.push((format!("kernel-{label}"), e.path()));
                    }
                }
            }
            let present: Vec<(&str, &std::path::Path)> = candidates
                .iter()
                .filter(|(_, p)| p.exists())
                .map(|(n, p)| (n.as_str(), p.as_path()))
                .collect();
            if present.is_empty() {
                return Err(vmcell::Error::Artifact(
                    "no artifacts found to bundle; run `vmcell build` first".to_string(),
                ));
            }
            // Surface what was left out — a silently-omitted artifact would make the manifest
            // read as "covered everything" when it didn't.
            let skipped: Vec<&str> = candidates
                .iter()
                .filter(|(_, p)| !p.exists())
                .map(|(n, _)| n.as_str())
                .collect();
            if !skipped.is_empty() {
                println!(
                    "vmcell: bundle skipping absent artifacts: {}",
                    skipped.join(", ")
                );
            }
            let manifest = vmcell::artifact::bundle::ArtifactManifest::build(&present)?;
            let out_path = out.clone().unwrap_or_else(|| dir.join("manifest.json"));
            manifest.write_to(&out_path)?;
            println!(
                "vmcell: wrote artifact manifest ({} entries) to {}",
                present.len(),
                out_path.display()
            );
            Ok(())
        }
        Commands::VerifyBundle { manifest } => {
            let mp = manifest
                .clone()
                .unwrap_or_else(|| vmcell::artifact::artifacts_dir().join("manifest.json"));
            vmcell::artifact::bundle::ArtifactManifest::verify_file(&mp)?;
            println!("vmcell: artifact manifest {} verified OK", mp.display());
            Ok(())
        }
        Commands::BuildKernels { in_vm } => {
            // Build each kernel in the `kernels` registry to its own `vmlinux-<label>`
            // (the kernel-version dimension), so multiple versions coexist for the
            // cross-kernel benchmark sweep. Each labelled stage has its own cache sidecar
            // and build dir. `--in-vm` compiles inside a builder micro-VM instead.
            let cid_alloc = std::sync::Arc::new(vmcell::vmm::CidAllocator::new());
            let pins_file = pins_path();
            let content = std::fs::read_to_string(&pins_file).map_err(vmcell::Error::Io)?;
            let json: serde_json::Value = serde_json::from_str(&content)
                .map_err(|e| vmcell::Error::Artifact(format!("pins.json parse: {e}")))?;
            let labels: Vec<String> = json
                .get("kernels")
                .and_then(|k| k.as_object())
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();
            if labels.is_empty() {
                return Err(vmcell::Error::Artifact(
                    "no `kernels` registry in pins.json".to_string(),
                ));
            }
            println!("Building kernels: {}", labels.join(", "));
            let mut pipeline = vmcell::artifact::Pipeline::new(vmcell::artifact::artifacts_dir())
                .add_stage(Box::new(vmcell::artifact::ResolvePinsStage {
                    pins_file: pins_file.clone(),
                }));
            let ksrc = if *in_vm {
                KernelSource::InVm
            } else {
                KernelSource::HostMake
            };
            for label in &labels {
                println!("  - kernel {label} -> vmlinux-{label}");
                pipeline = pipeline.add_stage(kernel_stage(
                    ksrc,
                    Some(label.clone()),
                    None,
                    cid_alloc.clone(),
                ));
            }
            pipeline.build(&vmcell::artifact::Cache::default()).await?;
            println!("Kernels built: {}", labels.join(", "));
            Ok(())
        }
        Commands::Run {
            kernel,
            rootfs,
            vcpus,
            mem_mib,
            disk,
            disk_rw,
            append,
            cmd,
        } => {
            let disks = extra_disks_from(disk, disk_rw);
            let mut vm = ephemeral_vm(kernel, rootfs, *vcpus, *mem_mib, &disks, append).await?;
            let argv = if cmd.is_empty() {
                vec!["/bin/true".to_string()]
            } else {
                cmd.clone()
            };
            let agent = vm.agent(None, &vmcell::orchestrator::RealClock).await?;
            let outcome = agent.exec(vmcell::ExecRequest::new(argv)).await?;
            use std::io::Write as _;
            // Best-effort relay of the guest command's captured output. A broken pipe
            // (the consumer closed stdout/stderr) must not abort the run or mask the
            // guest's real exit code, which we propagate below via `process::exit`.
            let _ = std::io::stdout().write_all(&outcome.stdout);
            let _ = std::io::stderr().write_all(&outcome.stderr);
            vm.shutdown().await?;
            // The CLI propagates the guest command's exit code (§10.2). Teardown has
            // already run (shutdown consumed `vm`), so process::exit leaks nothing.
            // expect(disallowed_methods): ordered teardown already completed above; exiting with
            // the guest's own code is the documented CLI contract.
            #[expect(
                clippy::disallowed_methods,
                reason = "ordered teardown already ran (shutdown consumed vm); relay the guest's exit code"
            )]
            std::process::exit(outcome.code);
        }
        Commands::Create {
            kernel,
            rootfs,
            vcpus,
            mem_mib,
            disk,
            disk_rw,
            append,
        } => {
            let disks = extra_disks_from(disk, disk_rw);
            let mut vm = ephemeral_vm(kernel, rootfs, *vcpus, *mem_mib, &disks, append).await?;
            let vmid = vm.vmid();
            // Confirm the guest agent handshakes — i.e. the VM actually booted —
            // before teardown. A failure here is a real error, not a fake success.
            vm.agent(None, &vmcell::orchestrator::RealClock).await?;
            println!("vmcell: VM booted and agent ready (vmid {vmid})");
            vm.shutdown().await?;
            Ok(())
        }
        Commands::Snapshot {
            kernel,
            rootfs,
            out,
            vcpus,
            mem_mib,
        } => {
            let mut vm = ephemeral_vm(kernel, rootfs, *vcpus, *mem_mib, &[], &[]).await?;
            // Bring the agent up so the snapshot captures an agent-ready VM.
            vm.agent(None, &vmcell::orchestrator::RealClock).await?;
            std::fs::create_dir_all(out).map_err(vmcell::Error::Io)?;
            vm.snapshot(out).await?;
            println!("vmcell: snapshot written to {}", out.display());
            vm.shutdown().await?;
            Ok(())
        }
        Commands::Stats {
            kernel,
            rootfs,
            vcpus,
            mem_mib,
        } => {
            let mut vm = ephemeral_vm(kernel, rootfs, *vcpus, *mem_mib, &[], &[]).await?;
            vm.agent(None, &vmcell::orchestrator::RealClock).await?;
            let usage = vm.usage().await?;
            println!("{}", format_usage_json(&usage));
            vm.shutdown().await?;
            Ok(())
        }
        Commands::Exec => Err(deferred_to_daemon("exec")),
        Commands::Ls => Err(deferred_to_daemon("ls")),
        Commands::Rm => Err(deferred_to_daemon("rm")),
        Commands::Destroy => Err(deferred_to_daemon("destroy")),
    }
}

/// Resolves the `cloud-hypervisor` binary path: `$VMCELL_CH_BIN`, else `cloud-hypervisor`
/// on `PATH`.
fn ch_bin() -> String {
    std::env::var("VMCELL_CH_BIN").unwrap_or_else(|_| "cloud-hypervisor".to_string())
}

/// Resolves the committed `pins.json` at the workspace root, independent of the
/// process CWD (L-BIN-10). Artifacts anchor on the workspace root (design §11), so a
/// bare `PathBuf::from("pins.json")` would read pins from a *different* location than
/// the artifacts when the tool is run from `crates/vmcell/`. Mirrors the library's
/// `workspace_root` ascent (the `vmcell-protocol` marker); falls back to a
/// CWD-relative `pins.json` for an installed binary run outside the tree.
///
/// The library's `workspace_root` is `pub(crate)`, so it cannot be reused here — see
/// the integrator note to expose it publicly and collapse this duplicate.
fn pins_path() -> PathBuf {
    let start = std::env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    for dir in start.ancestors() {
        if dir.join("crates/vmcell-protocol/Cargo.toml").is_file() {
            return dir.join("pins.json");
        }
    }
    PathBuf::from("pins.json")
}

/// Extracts the version label of a labelled kernel artifact filename
/// (`vmlinux-<label>` → `Some("<label>")`), used by `bundle` to cover every
/// `vmlinux-*` built by `build-kernels`, not just the default `vmlinux` (N-BIN-4).
/// The bare `vmlinux` (no `-`) and an empty label return `None`.
fn kernel_label_from_filename(name: &str) -> Option<&str> {
    match name.strip_prefix("vmlinux-") {
        Some(label) if !label.is_empty() => Some(label),
        _ => None,
    }
}

/// Validates an OCI digest string (`sha256:<64 lowercase/upper hex>`), rejecting an
/// empty, short/long, or non-hex digest that the bare `starts_with("sha256:")` check
/// would accept (N-BIN-3).
///
/// # Errors
/// Returns [`vmcell::Error::Artifact`] when the algorithm prefix is not `sha256:` or
/// the hex body is not exactly 64 hex digits.
fn validate_oci_digest(digest: &str) -> vmcell::Result<()> {
    let hex = digest.strip_prefix("sha256:").ok_or_else(|| {
        vmcell::Error::Artifact(format!(
            "oci2erofs requires a `sha256:` digest, got `{digest}`"
        ))
    })?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(vmcell::Error::Artifact(format!(
            "oci2erofs requires a valid sha256 hex digest (64 hex chars), got {} char(s) in `{digest}`",
            hex.len()
        )));
    }
    Ok(())
}

/// Builds the extra virtio-blk device list from the CLI's `--disk` (read-only) and
/// `--disk-rw` (read-write) path lists, read-only disks first (§19.1). The guest
/// enumerates them `/dev/vdb`, `/dev/vdc`, … in this order after the root disk.
fn extra_disks_from(read_only: &[PathBuf], read_write: &[PathBuf]) -> Vec<vmcell::BlockDevice> {
    read_only
        .iter()
        .map(vmcell::BlockDevice::read_only)
        .chain(read_write.iter().map(vmcell::BlockDevice::read_write))
        .collect()
}

/// Creates and boots an ephemeral micro-VM from an erofs rootfs, owned by the
/// returned handle (its `Drop`/`shutdown` performs the ordered teardown).
///
/// The VM does not outlive the calling process — a persistent, cross-invocation VM
/// needs the `vmcelld` daemon's registry (§18), which collides with the
/// ordered-Drop-owns-cleanup invariant. So each VM-lifecycle CLI verb owns its VM's
/// full lifecycle: create → operate → teardown.
async fn ephemeral_vm(
    kernel: &std::path::Path,
    rootfs: &std::path::Path,
    vcpus: u8,
    mem_mib: u32,
    extra_disks: &[vmcell::BlockDevice],
    extra_kernel_args: &[String],
) -> vmcell::Result<vmcell::MicroVm<vmcell::CloudHypervisor>> {
    let mut builder = vmcell::config::VmConfig::builder(
        kernel.to_path_buf(),
        vmcell::config::RootfsSource::Erofs {
            image: rootfs.to_path_buf(),
        },
    )
    .vcpus(vcpus)
    .mem_mib(mem_mib);
    for disk in extra_disks {
        builder = builder.with_extra_disk(disk.clone());
    }
    for arg in extra_kernel_args {
        builder = builder.with_kernel_arg(arg.clone());
    }
    let cfg = builder.build()?;
    let vmm = vmcell::CloudHypervisor::new(ch_bin());
    let cid_alloc = std::sync::Arc::new(vmcell::vmm::CidAllocator::new());
    let vmid_alloc = vmcell::orchestrator::VmidAllocator::new();
    vmcell::MicroVm::start(
        &vmm,
        cfg,
        cid_alloc,
        vmid_alloc,
        Box::new(vmcell::metrics::DefaultCgroupFs),
    )
    .await
}

/// Renders [`vmcell::ResourceUsage`] as a single-line JSON object. Hand-formatted
/// (the type does not derive `Serialize`); the net counters are intentionally absent
/// (cgroup v2 has no network accounting — see the impl-notes deviation).
fn format_usage_json(u: &vmcell::ResourceUsage) -> String {
    format!(
        "{{\"mem_peak_mib\":{},\"mem_current_mib\":{},\"cpu_usec\":{},\
         \"io_read_bytes\":{},\"io_write_bytes\":{},\"limits_enforced\":{},\
         \"mem_read_ok\":{},\"cpu_read_ok\":{},\"io_read_ok\":{}}}",
        u.mem_peak_mib,
        u.mem_current_mib,
        u.cpu_usec,
        u.io_read_bytes,
        u.io_write_bytes,
        u.limits_enforced,
        u.mem_read_ok,
        u.cpu_read_ok,
        u.io_read_ok,
    )
}

/// Runs the full rootfs pipeline against an arbitrary digest-pinned OCI base image and
/// writes the resulting erofs to `output` (v15 §8.2).
///
/// The image MUST be digest-pinned (`IMAGE@sha256:DIGEST`): a tag is a §11.2 provenance hard
/// stop and is rejected up front. A base lacking libc6 fails loud during packing unless
/// `agent_musl` supplies a static-musl agent (which needs no glibc). The pipeline is the SAME
/// inject+pack tail as `vmcell build` — verify-every-blob → whiteouts → inject agent/CA/tools
/// → erofs — only the base image (and the agent) are parameterized, so the runtime stays
/// erofs-only.
async fn oci2erofs(
    image_ref: &str,
    output: &std::path::Path,
    agent_musl: Option<&std::path::Path>,
) -> vmcell::Result<()> {
    // Reject a tag: require `IMAGE@sha256:DIGEST`. The digest is whatever follows the last `@`.
    let (image, digest) = image_ref.rsplit_once('@').ok_or_else(|| {
        vmcell::Error::Artifact(format!(
            "oci2erofs requires a digest-pinned image `IMAGE@sha256:DIGEST`, got `{image_ref}` \
             (a tag is a provenance hard stop, §11.2)"
        ))
    })?;
    // Full digest validation (N-BIN-3): the bare `starts_with("sha256:")` check accepts
    // `sha256:` followed by anything (empty, wrong length, non-hex).
    validate_oci_digest(digest)?;

    // Build into a per-invocation staging dir, NOT the canonical `artifacts_dir` root
    // (M-BIN-6): the rootfs stage writes `<target_dir>/rootfs.erofs`, so building at
    // `artifacts_dir` would clobber the canonical `rootfs.erofs` that every test/bench
    // boots. The staging dir is a *distinct sibling* under `artifacts_dir` (same real
    // disk — not the system temp dir, which is often a size-limited tmpfs), so a large
    // rootfs has room. Copy only the final image out to `--output`. Trade-off: the
    // staging dir has no cache history, so the agent/tools/rootfs stages rebuild.
    let stage_dir =
        vmcell::artifact::artifacts_dir().join(format!("oci2erofs-stage-{}", std::process::id()));
    // Best-effort pre-clean of a stale staging dir from a prior aborted run.
    let _ = std::fs::remove_dir_all(&stage_dir);
    let mut pipeline = vmcell::artifact::Pipeline::new(stage_dir.clone()).add_stage(Box::new(
        vmcell::artifact::ResolvePinsStage {
            pins_file: pins_path(),
        },
    ));
    // The default glibc agent is built by the pipeline; `--agent-musl` supplies its own
    // prebuilt binary, so the build stage is skipped and the rootfs stage injects it instead.
    if agent_musl.is_none() {
        pipeline = pipeline.add_stage(Box::new(vmcell::artifact::guest_agent::GuestAgentStage {}));
    }
    pipeline = pipeline
        .add_stage(Box::new(vmcell::artifact::guest_tools::GuestToolsStage {}))
        .add_stage(Box::new(vmcell::artifact::rootfs::RootfsStage {
            image_override: Some((image.to_string(), digest.to_string())),
            agent_musl: agent_musl.map(std::path::Path::to_path_buf),
        }));

    pipeline.build(&vmcell::artifact::Cache::default()).await?;

    // The rootfs stage writes `<stage_dir>/rootfs.erofs`; copy it to the requested
    // output, leaving the canonical `artifacts_dir/rootfs.erofs` untouched (M-BIN-6).
    let built = stage_dir.join("rootfs.erofs");
    let copy_res = std::fs::copy(&built, output).map_err(vmcell::Error::Io);
    // Best-effort cleanup of the staging dir regardless of the copy result; it is a
    // per-pid scratch dir under the system temp dir, so a leftover is not actionable.
    let _ = std::fs::remove_dir_all(&stage_dir);
    copy_res?;
    println!("vmcell: wrote erofs rootfs to {}", output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Buggy impl this guards: the daemon-deferred verbs (exec/ls/rm/destroy) printing
    // fake success and returning Ok(()), impersonating a completed operation. Each
    // must instead surface a typed, matchable error so the process exits non-zero.
    // (run/create/snapshot/stats are now implemented and own a real VM lifecycle, so
    // they are NOT in this set — they boot a VM and so are exercised by the KVM suite.)
    #[test]
    fn daemon_deferred_subcommands_fail_loud() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("test runtime");
        for command in [
            Commands::Exec,
            Commands::Ls,
            Commands::Rm,
            Commands::Destroy,
        ] {
            let err = rt
                .block_on(dispatch(&command))
                .expect_err("a daemon-deferred subcommand must return an error");
            assert!(
                matches!(err, vmcell::Error::Unsupported { .. }),
                "expected Error::Unsupported, got {err:?}"
            );
            // L-BIN-4: `main` now surfaces the error's `Display` (human-readable),
            // not its `Debug` struct-dump. Guard that the `Display` message is the
            // "…: …" sentence, not `Unsupported { vmm: …, feature: … }`. RED on the
            // inverse (a `main`/`Error` that emits the Debug form): the struct syntax
            // would appear and the human phrase would not.
            let shown = err.to_string();
            assert!(
                shown.contains("cross-process VM registry"),
                "Display should be the human-readable message, got: {shown}"
            );
            assert!(
                !shown.contains("Unsupported {"),
                "Display must not be the Debug struct-dump, got: {shown}"
            );
        }
    }

    // N-BIN-3: the old `digest.starts_with(\"sha256:\")` check accepted an empty,
    // short, or non-hex digest. RED on the inverse (prefix-only check): each bad
    // digest below would pass instead of erroring.
    #[test]
    fn validate_oci_digest_rejects_malformed() {
        assert!(
            validate_oci_digest("sha256:").is_err(),
            "empty hex must error"
        );
        assert!(
            validate_oci_digest("sha256:xyz").is_err(),
            "too-short must error"
        );
        assert!(
            validate_oci_digest(&format!("sha256:{}", "z".repeat(64))).is_err(),
            "non-hex must error"
        );
        assert!(
            validate_oci_digest("md5:abc").is_err(),
            "wrong algo must error"
        );
        // A well-formed 64-hex digest is accepted.
        assert!(validate_oci_digest(&format!("sha256:{}", "a".repeat(64))).is_ok());
    }

    // N-BIN-4: `bundle` must recognize `vmlinux-<label>` kernels but not the bare
    // `vmlinux` (already covered) or an empty label. RED on the inverse (matching
    // bare `vmlinux` or accepting an empty label).
    #[test]
    fn kernel_label_from_filename_matches_labelled_only() {
        assert_eq!(
            kernel_label_from_filename("vmlinux-6.12.94"),
            Some("6.12.94")
        );
        assert_eq!(kernel_label_from_filename("vmlinux-6.6"), Some("6.6"));
        assert_eq!(kernel_label_from_filename("vmlinux"), None);
        assert_eq!(kernel_label_from_filename("vmlinux-"), None);
        assert_eq!(kernel_label_from_filename("rootfs.erofs"), None);
    }
}
