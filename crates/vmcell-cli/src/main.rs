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

/// Which kernel builder produces the `vmlinux` for `build` (design §5.4, The guest-kernel contract and the bootstrap seed).
#[derive(Copy, Clone, PartialEq, Eq, Debug, clap::ValueEnum)]
enum KernelSource {
    /// Download + SHA-verify a digest-pinned prebuilt `vmlinux` (the fast, no-toolchain
    /// bootstrap seed; the pinned Kata kernel is validated to boot §5.4, The guest-kernel contract and the bootstrap seed).
    Prebuilt,
    /// Compile from the pinned source with `make` on the HOST (the guaranteed fallback seed).
    HostMake,
    /// Compile from the pinned source INSIDE a builder micro-VM (`vmcell-kernel-builder`).
    InVm,
}

/// Which rootfs builder produces the erofs for `build` (design §4.3, The rootfs-construction contract).
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
        /// Which kernel builder to use for the `vmlinux` seed (§5.4, The guest-kernel contract and the bootstrap seed).
        #[arg(long, value_enum, default_value_t = KernelSource::Prebuilt)]
        kernel_source: KernelSource,
        /// Which rootfs builder to use for the erofs (§4.3, The rootfs-construction contract).
        #[arg(long, value_enum, default_value_t = RootfsSourceKind::Oci)]
        rootfs_source: RootfsSourceKind,
        /// Debian release suite for the `mmdebstrap` rootfs source (ignored for `oci`).
        #[arg(long, default_value = "trixie")]
        release: String,
        /// Pins overlay layered over vmcell's committed baseline (§10.2). Overrides `$VMCELL_PINS`.
        #[arg(long)]
        pins: Option<PathBuf>,
    },
    /// Build every kernel in the pins `kernels` registry to `vmlinux-<label>`.
    BuildKernels {
        /// Which producer compiles each labelled kernel (§5.4, The guest-kernel contract and the bootstrap seed).
        /// `host-make` compiles on this host; `in-vm` compiles inside a builder micro-VM
        /// (`vmcell-kernel-builder`, which needs a bootstrap seed — prepended automatically).
        /// `prebuilt` compiles nothing and is therefore a typed error here (§5.6).
        #[arg(long, value_enum, default_value_t = KernelSource::HostMake)]
        kernel_source: KernelSource,
        /// Pins overlay layered over vmcell's committed baseline (§10.2); its `kernels` entries are
        /// built too. Overrides `$VMCELL_PINS`.
        #[arg(long)]
        pins: Option<PathBuf>,
    },
    /// Convert any digest-pinned OCI image into an erofs rootfs (build-time; v15 §4.2, Rootfs sources and the one packer).
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
        /// Compose a downstream file into the image at pack time (repeatable, §4.2 FR-V4):
        /// `dest=/usr/local/bin/acme,src=./acme,mode=0755`. `dest` is absolute, `mode` is
        /// octal permission bits, and neither key may be omitted. A dest vmcell itself owns
        /// (the guest agent, the CA trust store, `/vmcell-tools`) or a duplicated dest is a
        /// hard error, never a silent overwrite. A `,` cannot appear in a path.
        #[arg(long = "inject", value_parser = parse_inject)]
        inject: Vec<vmcell::artifact::rootfs::ExtraFile>,
        /// Pins overlay layered over vmcell's committed baseline (§10.2). Overrides `$VMCELL_PINS`.
        #[arg(long)]
        pins: Option<PathBuf>,
    },
    /// Write a digest-pinned fetch-and-verify manifest of the built artifacts (kernel,
    /// rootfs, proxy CA, resolved_pins.json) for reproducibility (v15 §10, The artifact build pipeline).
    Bundle {
        /// Output path for the manifest JSON (default `<artifacts_dir>/manifest.json`).
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Re-hash every artifact in a manifest and fail loud on any digest mismatch (v15 §10, The artifact build pipeline).
    VerifyBundle {
        /// Manifest JSON to verify (default `<artifacts_dir>/manifest.json`).
        #[arg(short, long)]
        manifest: Option<PathBuf>,
    },
    /// Create a fresh micro-VM, run a command in it over vsock, then tear it down,
    /// exiting with the guest command's exit code (v15 §9.3, The public API surface).
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
        /// guest as `/dev/vdb`, `/dev/vdc`, … after the root disk (§4.6, Extra virtio-blk devices and disk-I/O throttling).
        #[arg(long = "disk")]
        disk: Vec<PathBuf>,
        /// Extra read-write virtio-blk device image (repeatable).
        #[arg(long = "disk-rw")]
        disk_rw: Vec<PathBuf>,
        /// Append-only extra kernel command-line argument (repeatable); cannot
        /// override a reserved boot token vmcell owns (§5.3, The kernel command line).
        #[arg(long = "append")]
        append: Vec<String>,
        /// Run the command in a PTY (controlling-terminal) interactive session so
        /// in-guest programs see a real terminal (`isatty` true, line editing);
        /// implies `--stdin`. Local raw-mode / `SIGWINCH` forwarding is best-effort
        /// (§17, Open gaps and future capabilities); a fixed 24×80 initial window is used.
        #[arg(long)]
        tty: bool,
        /// Stream this CLI's stdin into the guest command (an interactive pipe
        /// session, §3, The control plane: vsock, the host clients, and the guest agent) instead of the default one-shot `/dev/null`
        /// stdin.
        #[arg(long)]
        stdin: bool,
        /// Command (and args) to run in the guest. Defaults to `/bin/true`.
        ///
        /// `allow_hyphen_values` lets the guest argv carry its own flags without a
        /// `--` separator, e.g. `vmcell run --kernel k --rootfs r /bin/sh -c 'echo hi'`
        /// — otherwise clap intercepts the leading-hyphen `-c` as an unknown option.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// Create + boot a fresh micro-VM and confirm its agent is ready, then tear it
    /// down (a boot smoke test; v15 §9.3, The public API surface).
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
        /// guest as `/dev/vdb`, `/dev/vdc`, … after the root disk (§4.6, Extra virtio-blk devices and disk-I/O throttling).
        #[arg(long = "disk")]
        disk: Vec<PathBuf>,
        /// Extra read-write virtio-blk device image (repeatable).
        #[arg(long = "disk-rw")]
        disk_rw: Vec<PathBuf>,
        /// Append-only extra kernel command-line argument (repeatable); cannot
        /// override a reserved boot token vmcell owns (§5.3, The kernel command line).
        #[arg(long = "append")]
        append: Vec<String>,
    },
    /// Boot a micro-VM and write a warm snapshot into a directory, then tear it
    /// down (snapshot-eligible config only; v15 §9.3, The public API surface).
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
    /// down (v15 §9.3, The public API surface).
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
    /// Removed (design §11, The control-plane daemon (vmcelld)): a standalone exec needs a cross-process VM registry, which collides
    /// with the ordered-Drop-owns-cleanup invariant. Use `vmcelld-ctl exec` against a running daemon.
    Exec,
    /// Removed (design §11, The control-plane daemon (vmcelld)): listing VMs needs a cross-process registry. Use `vmcelld-ctl ls`.
    Ls,
    /// Removed (design §11, The control-plane daemon (vmcelld)): removing a VM by id needs a cross-process registry. Use `vmcelld-ctl rm`.
    Rm,
    /// Removed (design §11, The control-plane daemon (vmcelld)): destroying a VM by id needs a cross-process registry (within one
    /// process the owning handle's drop/`shutdown` already destroys it). Use `vmcelld-ctl rm`.
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

/// Builds the typed redirect error for a cross-process lifecycle verb that was **removed** from
/// the CLI (design §18 delta 11, Delta register: changes from the validated v27 build): `exec`/`ls`/`rm`/`destroy` genuinely belong to the daemon, which
/// **owns** VMs across process boundaries — a capability a single-shot CLI structurally cannot have
/// (§9, The Rust library (vmcell); §11, The control-plane daemon (vmcelld)). The message points the user at `vmcelld-ctl`, the daemon's control client.
///
/// These verbs must fail loud — a typed, matchable error that drives a non-zero exit — rather than
/// printing fake success. Printing "Removing VM..." and returning `Ok(())` while doing nothing is
/// the "skip == pass" failure in CLI form: it impersonates a completed operation.
fn moved_to_vmcelld_ctl(subcommand: &str) -> vmcell::Error {
    vmcell::Error::Unsupported {
        vmm: "vmcell".to_string(),
        feature: format!(
            "`vmcell {subcommand}` was removed: a cross-process VM registry belongs to the daemon — \
             run `vmcelld-ctl {subcommand}` against a running vmcelld instead (§11)"
        ),
    }
}

/// Builds the kernel [`Stage`](vmcell::artifact::Stage) selected by `source` — a `vmcell`
/// bootstrap producer (prebuilt download or host-`make`) or the in-VM `vmcell-kernel-builder`.
/// This is the composition-root wiring that keeps the dependency graph acyclic (§9.1, Workspace layout): only
/// `vmcell-cli` names the builder crates.
///
/// # Errors
/// Returns [`vmcell::Error::Artifact`] when a `label` or `fragments` are routed at the **prebuilt**
/// seed, which compiles nothing and can honor neither (§5.6, The downstream kernel toolkit). The
/// condition is the library's one `reject_labelled_prebuilt` predicate, not a local re-test.
fn kernel_stage(
    source: KernelSource,
    label: Option<String>,
    fragments: Option<Vec<String>>,
    cid_alloc: std::sync::Arc<vmcell::vmm::CidAllocator>,
) -> vmcell::Result<Box<dyn vmcell::artifact::Stage>> {
    let http_client = std::sync::Arc::new(vmcell::artifact::kernel::ReqwestClient);
    Ok(match source {
        KernelSource::Prebuilt => {
            // Pre-v30 this arm silently DROPPED label+fragments and handed back the default seed:
            // a labelled build that never happened, reported as success.
            vmcell::artifact::kernel::reject_labelled_prebuilt(
                label.as_deref(),
                fragments.as_deref(),
            )?;
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
    })
}

/// The producer name reported for a labelled build (§5.6, The downstream kernel toolkit).
///
/// Both compiling stages answer `name()` with the label, so neither the pipeline's stage log nor
/// the CLI's own line can say *how* a kernel was built without this mapping.
fn kernel_source_name(source: KernelSource) -> &'static str {
    match source {
        KernelSource::Prebuilt => "prebuilt",
        KernelSource::HostMake => "host-make",
        KernelSource::InVm => "in-vm",
    }
}

/// Whether `source` needs a **bootstrap seed kernel** staged ahead of it in the same pipeline
/// (§5.4, The guest-kernel contract and the bootstrap seed).
///
/// Only the in-VM producer does: it boots a builder micro-VM, which needs an already-working
/// `vmlinux` published under the `kernel` artifact key. `build-kernels` publishes only
/// `kernel-<label>` keys, so without a seed stage in front the in-VM path died on
/// "needs a seed `kernel` artifact" no matter what the operator had already built.
fn kernel_source_needs_seed(source: KernelSource) -> bool {
    matches!(source, KernelSource::InVm)
}

/// Builds the rootfs [`Stage`](vmcell::artifact::Stage) selected by `source` — the `vmcell`
/// OCI bootstrap producer or the in-VM `vmcell-rootfs-builder` mmdebstrap source (§4.3, The rootfs-construction contract).
fn rootfs_stage(
    source: RootfsSourceKind,
    release: String,
    cid_alloc: std::sync::Arc<vmcell::vmm::CidAllocator>,
) -> Box<dyn vmcell::artifact::Stage> {
    match source {
        // `vmcell build` produces vmcell's own canonical rootfs and takes no `--inject`; the
        // downstream extra-file surface is `oci2erofs` (§10.4's documented consumer
        // invocation), so both arms compose nothing.
        RootfsSourceKind::Oci => Box::new(vmcell::artifact::rootfs::RootfsStage {
            image_override: None,
            agent_musl: None,
            extra: Vec::new(),
        }),
        RootfsSourceKind::Mmdebstrap => Box::new(vmcell_rootfs_builder::MmdebstrapRootfsStage {
            release,
            cid_alloc,
            extra: Vec::new(),
        }),
    }
}

async fn dispatch(command: &Commands) -> vmcell::Result<()> {
    match command {
        Commands::Build {
            kernel_source,
            rootfs_source,
            release,
            pins,
        } => {
            println!("Building artifacts...");
            // One CID allocator shared by any in-VM builder stage this pipeline runs.
            let cid_alloc = std::sync::Arc::new(vmcell::vmm::CidAllocator::new());
            let pipeline = vmcell::artifact::Pipeline::new(vmcell::artifact::artifacts_dir())
                .add_stage(Box::new(vmcell::artifact::ResolvePinsStage {
                    overlay_file: pins_overlay(pins.as_deref()),
                }))
                .add_stage(kernel_stage(*kernel_source, None, None, cid_alloc.clone())?)
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
            inject,
            pins,
        } => {
            oci2erofs(
                image,
                output,
                agent_musl.as_deref(),
                inject,
                pins.as_deref(),
            )
            .await
        }
        Commands::Bundle { out } => {
            let dir = vmcell::artifact::artifacts_dir();
            let mut candidates: Vec<(String, PathBuf)> = vec![
                ("kernel".to_string(), dir.join("vmlinux")),
                ("rootfs".to_string(), dir.join("rootfs.erofs")),
                ("ca".to_string(), dir.join("ca.pem")),
                // The RESOLVED pins (baseline + any overlay), not the committed baseline: with an
                // overlay in play the repo file is not what the artifacts were built from, and the
                // baseline is embedded in the binary now anyway (§10.2). Absent until a pipeline
                // has run, which the skipped-artifact notice below reports.
                ("pins".to_string(), dir.join("resolved_pins.json")),
            ];
            // The default kernel's resolved-config sidecar (§5.6): present for a compiling
            // producer, absent for the prebuilt seed — which clears any config an earlier
            // compiling build of the same `vmlinux` path left behind (`clear_resolved_config`), so
            // this candidate is either THIS kernel's config or absent, never a stale one
            // describing different bytes. The skip notice below reports the absence honestly
            // rather than hiding it.
            candidates.push((
                "kernel-config".to_string(),
                vmcell::artifact::kernel::resolved_config_path(&dir.join("vmlinux")),
            ));
            // Cover every labelled kernel built by `build-kernels` (`vmlinux-<label>`),
            // not just the default `vmlinux` — otherwise the manifest silently omits
            // the cross-kernel sweep's artifacts (N-BIN-4) — and each one's resolved-config
            // sidecar alongside it, so the manifest pins what the kernel actually contains.
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for e in rd.flatten() {
                    let fname = e.file_name();
                    let name = fname.to_string_lossy();
                    // The library's one label law (the inverse of the producers' filename
                    // composer), so a producer that changed its sanitization could not silently
                    // drop its kernels from this manifest.
                    if let Some(label) = vmcell::artifact::kernel::kernel_label_from_filename(&name)
                    {
                        candidates.push((
                            format!("kernel-{label}-config"),
                            vmcell::artifact::kernel::resolved_config_path(&e.path()),
                        ));
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
        Commands::BuildKernels {
            kernel_source,
            pins,
        } => {
            // Build each kernel in the `kernels` registry to its own `vmlinux-<label>`
            // (the kernel-version dimension), so multiple versions coexist for the
            // cross-kernel benchmark sweep. Each labelled stage has its own cache sidecar
            // and build dir, and each carries the fragment set its registry entry declares.
            let cid_alloc = std::sync::Arc::new(vmcell::vmm::CidAllocator::new());
            let overlay_file = pins_overlay(pins.as_deref());
            // The roster comes from the library's merged resolution — the same one the stage
            // uses (§10.2), in the pinned sorted label order. A private re-parse here would be
            // overlay-blind, leaving a downstream-added `kernels.<label>` resolvable but
            // unbuildable by this very command, and would need its own fragment reader.
            let registry = vmcell::artifact::resolve_kernel_registry(overlay_file.as_deref())?;
            if registry.is_empty() {
                return Err(vmcell::Error::Artifact(
                    "no `kernels` registry in the resolved pins".to_string(),
                ));
            }
            let labels: Vec<&str> = registry.iter().map(|e| e.label.as_str()).collect();
            let producer = kernel_source_name(*kernel_source);
            println!("Building kernels ({producer}): {}", labels.join(", "));
            let mut pipeline = vmcell::artifact::Pipeline::new(vmcell::artifact::artifacts_dir())
                .add_stage(Box::new(vmcell::artifact::ResolvePinsStage {
                    overlay_file,
                }));
            // The in-VM producer boots a builder micro-VM, which needs a working `vmlinux`
            // published under the `kernel` artifact key — a key no labelled stage ever registers
            // (they register `kernel-<label>`). Stage the pinned prebuilt bootstrap seed ahead of
            // them (§5.4); it is content-addressed like any stage, so a warm artifacts dir hits
            // cache and nothing is re-downloaded.
            if kernel_source_needs_seed(*kernel_source) {
                println!("  - bootstrap seed (prebuilt) -> vmlinux (boots the builder VM)");
                pipeline = pipeline.add_stage(kernel_stage(
                    KernelSource::Prebuilt,
                    None,
                    None,
                    cid_alloc.clone(),
                )?);
            }
            for entry in &registry {
                let label = &entry.label;
                println!(
                    "  - kernel {label} -> vmlinux-{label} (producer: {producer}, fragments: {})",
                    if entry.fragments.is_empty() {
                        "none".to_string()
                    } else {
                        entry.fragments.join("+")
                    }
                );
                pipeline = pipeline.add_stage(kernel_stage(
                    *kernel_source,
                    Some(label.clone()),
                    Some(entry.fragments.clone()),
                    cid_alloc.clone(),
                )?);
            }
            pipeline.build(&vmcell::artifact::Cache::default()).await?;
            println!("Kernels built ({producer}): {}", labels.join(", "));
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
            tty,
            stdin,
            cmd,
        } => {
            let disks = extra_disks_from(disk, disk_rw);
            let mut vm = ephemeral_vm(kernel, rootfs, *vcpus, *mem_mib, &disks, append).await?;
            let argv = if cmd.is_empty() {
                vec!["/bin/true".to_string()]
            } else {
                cmd.clone()
            };
            // `--tty`/`--stdin` (§3, The control plane: vsock, the host clients, and the guest agent) route through an interactive session
            // that streams this CLI's stdin; the default path is the one-shot exec.
            let code = if *tty || *stdin {
                run_interactive_session(&vm, argv, *tty).await?
            } else {
                let agent = vm.agent(None).await?;
                let outcome = agent.exec(vmcell::ExecRequest::new(argv)).await?;
                use std::io::Write as _;
                // Best-effort relay of the guest command's captured output. A broken pipe
                // (the consumer closed stdout/stderr) must not abort the run or mask the
                // guest's real exit code, which we propagate below via `process::exit`.
                let _ = std::io::stdout().write_all(&outcome.stdout);
                let _ = std::io::stderr().write_all(&outcome.stderr);
                outcome.code
            };
            vm.shutdown().await?;
            // The CLI propagates the guest command's exit code (§9.3, The public API surface). Teardown has
            // already run (shutdown consumed `vm`), so process::exit leaks nothing.
            // expect(disallowed_methods): ordered teardown already completed above; exiting with
            // the guest's own code is the documented CLI contract.
            #[expect(
                clippy::disallowed_methods,
                reason = "ordered teardown already ran (shutdown consumed vm); relay the guest's exit code"
            )]
            std::process::exit(code);
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
            vm.agent(None).await?;
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
            vm.agent(None).await?;
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
            vm.agent(None).await?;
            let usage = vm.usage().await?;
            println!("{}", format_usage_json(&usage));
            vm.shutdown().await?;
            Ok(())
        }
        Commands::Exec => Err(moved_to_vmcelld_ctl("exec")),
        Commands::Ls => Err(moved_to_vmcelld_ctl("ls")),
        Commands::Rm => Err(moved_to_vmcelld_ctl("rm")),
        Commands::Destroy => Err(moved_to_vmcelld_ctl("rm")),
    }
}

/// Resolves the `cloud-hypervisor` binary path: `$VMCELL_CH_BIN`, else `cloud-hypervisor`
/// on `PATH`.
fn ch_bin() -> String {
    std::env::var("VMCELL_CH_BIN").unwrap_or_else(|_| "cloud-hypervisor".to_string())
}

/// Resolves the pins overlay for a pipeline-building subcommand: the `--pins` flag wins, else
/// `$VMCELL_PINS` (§10.2, The stage model and the five cache-key rules; §10.4's env contract), else
/// none — the committed baseline alone.
///
/// This retired the CLI's private `pins_path()` workspace-root ascent (L-BIN-10, a near-duplicate
/// of the library's `workspace_root`): the pins **baseline** is embedded in the library now, so the
/// CLI no longer hunts the filesystem for `pins.json` and there is nothing left to duplicate. Only
/// the overlay is a path, and it is caller-supplied rather than discovered.
///
/// Delegates to the library's [`pins_overlay_or_env`](vmcell::artifact::pins_overlay_or_env), the
/// one flag-beats-env law the toolkit build entry points use as well, so `$VMCELL_PINS` cannot
/// reach one and be ignored by the other.
fn pins_overlay(flag: Option<&std::path::Path>) -> Option<PathBuf> {
    vmcell::artifact::pins_overlay_or_env(flag)
}

/// Parses one `--inject dest=<abs path>,src=<path>,mode=<octal>` value into an
/// [`ExtraFile`](vmcell::artifact::rootfs::ExtraFile) (design §4.2, FR-V4).
///
/// Syntax only — this is the parser, not the policy. The reserved-dest and duplicate-dest
/// rejections (invariant F5) live at the one pack tail, so every rootfs source and every
/// non-CLI caller gets them; re-checking them here would be a second copy of the list.
///
/// Every accepted key is honored and every unaccepted one is refused by name: an unknown key,
/// a repeated key, a missing key, an empty value, or a fragment without `=` (which is what a
/// `,` inside a path looks like) is an error. Errors are `String` because clap's
/// `value_parser` renders them alongside the flag name.
fn parse_inject(spec: &str) -> std::result::Result<vmcell::artifact::rootfs::ExtraFile, String> {
    let mut dest: Option<&str> = None;
    let mut src: Option<&str> = None;
    let mut mode: Option<u32> = None;
    for field in spec.split(',') {
        let (key, value) = field.split_once('=').ok_or_else(|| {
            format!(
                "`{field}` is not a `key=value` field (a `,` in a path is not expressible; \
                 expected dest=<abs path>,src=<path>,mode=<octal>)"
            )
        })?;
        if value.is_empty() {
            return Err(format!("`{key}` has an empty value"));
        }
        let already = match key {
            "dest" => dest.replace(value).is_some(),
            "src" => src.replace(value).is_some(),
            "mode" => {
                let parsed = u32::from_str_radix(value, 8).map_err(|e| {
                    format!("`mode={value}` is not an octal permission set (e.g. 0755): {e}")
                })?;
                mode.replace(parsed).is_some()
            }
            other => {
                return Err(format!(
                    "unknown key `{other}` (expected `dest`, `src`, or `mode`)"
                ));
            }
        };
        if already {
            return Err(format!("`{key}` is given more than once"));
        }
    }
    Ok(vmcell::artifact::rootfs::ExtraFile::new(
        dest.ok_or("missing `dest=<absolute in-guest path>`")?,
        src.ok_or("missing `src=<host path>`")?,
        mode.ok_or("missing `mode=<octal permission set, e.g. 0755>`")?,
    ))
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

/// Runs `argv` in an interactive session (§3, The control plane: vsock, the host clients, and the guest agent), streaming this CLI's
/// stdin into the guest command and relaying its output, and returns the guest
/// exit code.
///
/// With `tty`, a controlling-terminal PTY session is used (fixed 24×80 initial
/// window; local raw-mode / `SIGWINCH` forwarding is best-effort forward work,
/// §17, Open gaps and future capabilities) — in-guest programs see a real terminal. Without it, a pipe session
/// carries separate stdout/stderr. The `select!` loop reads guest output and this
/// CLI's stdin concurrently; `recv()` and the stdin read are both cancellation-safe.
async fn run_interactive_session(
    vm: &vmcell::MicroVm<vmcell::CloudHypervisor>,
    argv: Vec<String>,
    tty: bool,
) -> vmcell::Result<i32> {
    use std::io::Write as _;
    use tokio::io::AsyncReadExt as _;
    use vmcell::agent::session::{SessionEvent, SessionSpecBuilder};

    let mux = vm.connect_sessions(None).await?;
    let mut builder = SessionSpecBuilder::new(argv);
    if tty {
        // A fixed classic default; dynamic sizing + resize forwarding is §17 (Open gaps and future capabilities).
        builder = builder.pty(24, 80);
    }
    let mut session = mux.open(builder.build()).await?;

    let mut stdin = tokio::io::stdin();
    let mut buf = [0u8; 4096];
    let mut stdin_open = true;
    loop {
        tokio::select! {
            event = session.recv() => match event {
                Some(SessionEvent::Stdout(data)) => {
                    let mut out = std::io::stdout();
                    let _ = out.write_all(&data);
                    let _ = out.flush();
                }
                Some(SessionEvent::Stderr(data)) => {
                    let mut err = std::io::stderr();
                    let _ = err.write_all(&data);
                    let _ = err.flush();
                }
                Some(SessionEvent::Exit(code)) => return Ok(code),
                // The connection dropped before an exit — surface the sentinel -1.
                None => return Ok(-1),
                // `SessionEvent` is non-exhaustive; ignore any future event kind.
                Some(_) => {}
            },
            read = stdin.read(&mut buf), if stdin_open => match read {
                // Local EOF (Ctrl-D / piped input exhausted): close the guest stdin.
                Ok(0) => {
                    let _ = session.close_stdin().await;
                    stdin_open = false;
                }
                Ok(n) => {
                    // `read` guarantees n <= buf.len(); `get(..n)` is the non-panicking form.
                    let _ = session.write_stdin(buf.get(..n).unwrap_or_default()).await;
                }
                // A local stdin read error: stop forwarding, keep relaying output.
                Err(_) => stdin_open = false,
            },
        }
    }
}

/// Builds the extra virtio-blk device list from the CLI's `--disk` (read-only) and
/// `--disk-rw` (read-write) path lists, read-only disks first (§4.6, Extra virtio-blk devices and disk-I/O throttling). The guest
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
/// needs the `vmcelld` daemon's registry (§11, The control-plane daemon (vmcelld)), which collides with the
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
    // One-shot CLI process booting one VM: in-process (hermetic) allocators suffice
    // (the design §18 delta-1 seam bundle, Delta register: changes from the validated v27 build; `shared()` is the daemon's home).
    let env = vmcell::HostEnv::hermetic();
    vmcell::MicroVm::start(&vmm, cfg, &env).await
}

/// Renders [`vmcell::ResourceUsage`] as a single-line JSON object. Hand-formatted
/// (the type does not derive `Serialize`); the net counters are intentionally absent
/// (cgroup v2 has no network accounting — see the impl-notes deviation).
fn format_usage_json(u: &vmcell::ResourceUsage) -> String {
    format!(
        "{{\"mem_peak_mib\":{},\"mem_current_mib\":{},\"cpu_usec\":{},\
         \"io_read_bytes\":{},\"io_write_bytes\":{},\"mem_limit_enforced\":{},\
         \"mem_read_ok\":{},\"cpu_read_ok\":{},\"io_read_ok\":{}}}",
        u.mem_peak_mib,
        u.mem_current_mib,
        u.cpu_usec,
        u.io_read_bytes,
        u.io_write_bytes,
        u.mem_limit_enforced,
        u.mem_read_ok,
        u.cpu_read_ok,
        u.io_read_ok,
    )
}

/// Runs the full rootfs pipeline against an arbitrary digest-pinned OCI base image and
/// writes the resulting erofs to `output` (v15 §4.2, Rootfs sources and the one packer).
///
/// The image MUST be digest-pinned (`IMAGE@sha256:DIGEST`): a tag is a §10.2 (The stage model and the five cache-key rules) provenance hard
/// stop and is rejected up front. A base lacking libc6 fails loud during packing unless
/// `agent_musl` supplies a static-musl agent (which needs no glibc). The pipeline is the SAME
/// inject+pack tail as `vmcell build` — verify-every-blob → whiteouts → inject agent/CA/tools
/// → erofs — only the base image (and the agent) are parameterized, so the runtime stays
/// erofs-only.
async fn oci2erofs(
    image_ref: &str,
    output: &std::path::Path,
    agent_musl: Option<&std::path::Path>,
    inject: &[vmcell::artifact::rootfs::ExtraFile],
    pins: Option<&std::path::Path>,
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
            overlay_file: pins_overlay(pins),
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
            // The `--inject` files; the pack tail validates them (absolute dest, explicit
            // mode, no vmcell-owned or duplicated dest — §4.2, invariant F5).
            extra: inject.to_vec(),
        }));

    pipeline.build(&vmcell::artifact::Cache::default()).await?;

    // The rootfs stage writes `<stage_dir>/rootfs.erofs`; copy it to the requested
    // output, leaving the canonical `artifacts_dir/rootfs.erofs` untouched (M-BIN-6).
    let built = stage_dir.join("rootfs.erofs");
    let copy_res = std::fs::copy(&built, output).map_err(vmcell::Error::Io);
    // Best-effort cleanup of the staging dir regardless of the copy result; it is a
    // per-pid scratch dir under the artifacts dir (a distinct sibling of the canonical
    // rootfs, M-BIN-6), so a leftover is not actionable.
    let _ = std::fs::remove_dir_all(&stage_dir);
    copy_res?;
    println!("vmcell: wrote erofs rootfs to {}", output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Delta 11 gate. Buggy impls this guards: (a) the removed cross-process verbs
    // (exec/ls/rm/destroy) printing fake success and returning Ok(()), impersonating a
    // completed operation; (b) a redirect that no longer points the user at `vmcelld-ctl`
    // (the daemon control client that owns those verbs). Each must surface a typed,
    // matchable error whose message names `vmcelld-ctl`, so the process exits non-zero.
    // (run/create/snapshot/stats are now implemented and own a real VM lifecycle, so
    // they are NOT in this set — they boot a VM and so are exercised by the KVM suite.)
    #[test]
    fn daemon_deferred_subcommands_fail_loud() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("test runtime");
        // Each removed verb must redirect to a subcommand `vmcelld-ctl` actually
        // exposes: the CLI `destroy` maps to the daemon client's teardown verb `rm`
        // (M3). A bare `contains("vmcelld-ctl")` stayed green even when the message
        // said `vmcelld-ctl destroy`, which `vmcelld-ctl` has no subcommand for; this
        // table asserts the exact verb so that regression reddens.
        for (command, ctl_verb) in [
            (Commands::Exec, "exec"),
            (Commands::Ls, "ls"),
            (Commands::Rm, "rm"),
            (Commands::Destroy, "rm"),
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
            // Delta 11: the removed verbs redirect the user at a `vmcelld-ctl` subcommand
            // that actually exists (the daemon's control client), where the real
            // exec/ls/rm live. RED on the inverse (a message naming `vmcelld-ctl destroy`,
            // which `vmcelld-ctl` has no subcommand for, or one that omits the ctl tool).
            assert!(
                shown.contains(&format!("vmcelld-ctl {ctl_verb}")),
                "the redirect must name `vmcelld-ctl {ctl_verb}`, got: {shown}"
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

    // §18 delta 6 gate: the `--inject` parser. Every accepted key is honored and everything
    // else is refused BY NAME — the accept-then-ignore class AGENTS.md bans. RED on the
    // inverse: a lenient parser (a `_ => {}` arm for unknown keys, a last-wins duplicate, a
    // decimal `mode`, or defaulted-away missing keys) turns each rejection below into an Ok
    // that silently packs the wrong file, at the wrong path, with the wrong permissions.
    #[test]
    fn parse_inject_honors_or_rejects_every_field() {
        // The positive control: a well-formed spec parses, mode is OCTAL, and the fields
        // land where they belong (a `mode=0755` read as decimal would be 755 == 0o1373).
        let f = parse_inject("dest=/usr/local/bin/acme,src=./build/acme,mode=0755")
            .expect("a well-formed spec must parse");
        assert_eq!(f.dest, "/usr/local/bin/acme");
        assert_eq!(f.src, std::path::PathBuf::from("./build/acme"));
        assert_eq!(f.mode, 0o755);
        // Key order is free.
        assert_eq!(
            parse_inject("mode=0644,src=./x,dest=/etc/x").expect("any key order"),
            vmcell::artifact::rootfs::ExtraFile::new("/etc/x", "./x", 0o644)
        );

        for (label, spec) in [
            ("unknown key", "dest=/a,src=./a,mode=0755,owner=root"),
            ("misspelled key", "destination=/a,src=./a,mode=0755"),
            ("missing dest", "src=./a,mode=0755"),
            ("missing src", "dest=/a,mode=0755"),
            ("missing mode", "dest=/a,src=./a"),
            ("repeated key", "dest=/a,src=./a,mode=0755,dest=/b"),
            ("empty value", "dest=,src=./a,mode=0755"),
            ("non-octal mode", "dest=/a,src=./a,mode=0o755"),
            ("out-of-range mode digit", "dest=/a,src=./a,mode=0778"),
            ("bare mode word", "dest=/a,src=./a,mode=rwx"),
            ("a `,` inside a path", "dest=/a,b,src=./a,mode=0755"),
            ("not key=value at all", "/usr/local/bin/acme"),
            ("empty spec", ""),
        ] {
            let err = parse_inject(spec)
                .map(|f| format!("{f:?}"))
                .expect_err(&format!("{label} must be rejected: `{spec}`"));
            assert!(!err.is_empty(), "{label} must explain itself");
        }
        // The refusal NAMES the offending key, so the user can fix it without guessing.
        assert!(
            parse_inject("dest=/a,src=./a,mode=0755,owner=root")
                .expect_err("unknown key")
                .contains("owner"),
            "an unknown key must be named in the error"
        );
    }

    // N-BIN-4 / §5.6: `bundle`'s directory walk must recognize the names the PRODUCERS write
    // (`vmlinux-<sanitized-label>`) and neither the bare `vmlinux` nor a kernel's sidecars. The
    // rule itself and its round-trip against the producers' filename composer live in
    // `vmcell::artifact::kernel` (one law); this pins that `bundle` reads through it — RED on the
    // inverse (a CLI-local re-implementation, which is what let the rule and the producers drift).
    #[test]
    fn bundle_reads_kernel_labels_through_the_library_law() {
        use vmcell::artifact::kernel::{kernel_filename, kernel_label_from_filename};
        // Composed by the producers' own filename law, not a test-local `format!`.
        assert_eq!(
            kernel_label_from_filename(&kernel_filename(Some("6.12.94"))),
            Some("6-12-94")
        );
        assert_eq!(
            kernel_label_from_filename(&kernel_filename(Some("ikconfig"))),
            Some("ikconfig")
        );
        assert_eq!(kernel_label_from_filename(&kernel_filename(None)), None);
        assert_eq!(kernel_label_from_filename("rootfs.erofs"), None);
        // A kernel's SIDECARS are not kernels: `bundle` used to record the cache sidecar as the
        // artifact `kernel-6-12-94.cache_key`, and the resolved config would have joined it.
        assert_eq!(
            kernel_label_from_filename("vmlinux-6-12-94.cache_key"),
            None
        );
        assert_eq!(kernel_label_from_filename("vmlinux-6-12-94.config"), None);
    }

    // §5.6 GATE (delta 3): a labelled or fragment-carrying build routed at the PREBUILT seed is a
    // typed refusal from the producer selector — reachable from the CLI now that `build-kernels`
    // takes `--kernel-source`. RED on the inverse (the pre-v30 arm that ignored both arguments and
    // handed back `PrebuiltKernelStage`): every case below returns Ok.
    #[test]
    fn kernel_stage_rejects_labelled_prebuilt() {
        let alloc = || std::sync::Arc::new(vmcell::vmm::CidAllocator::new());
        let labelled = kernel_stage(
            KernelSource::Prebuilt,
            Some("6.12.94".to_string()),
            None,
            alloc(),
        );
        match labelled {
            Err(vmcell::Error::Artifact(m)) => assert!(
                m.contains("6.12.94"),
                "the refusal must name the label, got: {m}"
            ),
            _ => panic!("prebuilt + label must be refused"),
        }
        assert!(
            kernel_stage(
                KernelSource::Prebuilt,
                None,
                Some(vec!["KASAN".to_string()]),
                alloc()
            )
            .is_err(),
            "prebuilt + fragments must be refused"
        );
        // Positive control: the seed request the prebuilt producer exists for still works, and
        // both compiling producers accept a labelled fragment build.
        assert!(kernel_stage(KernelSource::Prebuilt, None, None, alloc()).is_ok());
        assert!(
            kernel_stage(
                KernelSource::HostMake,
                Some("6.12.94".to_string()),
                Some(vec!["KASAN".to_string()]),
                alloc()
            )
            .is_ok()
        );
        assert!(
            kernel_stage(
                KernelSource::InVm,
                Some("6.12.94".to_string()),
                Some(vec!["KASAN".to_string()]),
                alloc()
            )
            .is_ok()
        );
    }

    // §5.4/§5.6 (delta 3): only the in-VM producer needs a bootstrap seed staged ahead of it —
    // it boots a builder VM off the `kernel` artifact key, which no labelled stage registers.
    // RED on the inverse (returning false for `InVm`, i.e. the pre-v30 pipeline):
    // `vmcell build-kernels --kernel-source in-vm` dies on "needs a seed `kernel` artifact".
    #[test]
    fn only_the_in_vm_producer_needs_a_seed() {
        assert!(kernel_source_needs_seed(KernelSource::InVm));
        assert!(!kernel_source_needs_seed(KernelSource::HostMake));
        assert!(!kernel_source_needs_seed(KernelSource::Prebuilt));
        // The producer names the CLI reports (§5.6: a labelled build says which producer ran).
        assert_eq!(kernel_source_name(KernelSource::InVm), "in-vm");
        assert_eq!(kernel_source_name(KernelSource::HostMake), "host-make");
        assert_eq!(kernel_source_name(KernelSource::Prebuilt), "prebuilt");
    }
}
