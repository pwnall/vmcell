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
// The ONE unknown-label refusal every registry selector shares (§10.5) — the library's composer,
// imported rather than re-spelled. This crate held three copies of it (the kernel, rootfs and
// handler selectors) and `vmcell::artifact::build_labelled_kernel` a fourth, with nothing but a
// cross-crate byte-equality test holding the two wordings together; see the composer's rustdoc.
use vmcell::artifact::registry::unknown_label_error;

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
    /// Build the kernel + rootfs + steward + tools artifacts into the artifacts dir.
    Build {
        /// Which kernel builder to use for the `vmlinux` seed (§5.4, The guest-kernel contract and the bootstrap seed).
        /// `prebuilt` downloads the seed and `host-make` compiles it here; `in-vm` needs a seed of
        /// its own to boot the builder VM and is therefore a typed error here (M3) — that producer's
        /// route is `build-kernels --all --kernel-source in-vm`, which stages the seed.
        #[arg(long, value_enum, default_value_t = KernelSource::Prebuilt)]
        kernel_source: KernelSource,
        /// Which rootfs builder to use for the erofs (§4.3, The rootfs-construction contract).
        #[arg(long, value_enum, default_value_t = RootfsSourceKind::Oci)]
        rootfs_source: RootfsSourceKind,
        /// Debian release suite for the `mmdebstrap` rootfs source (ignored for `oci`).
        #[arg(long, default_value = "trixie")]
        release: String,
        /// Which `rootfs` registry label to build (§10.5, v33 delta 6). Omitted builds `default`,
        /// which resolves to today's pinned base and lands at `rootfs.erofs`; a label lands at
        /// `rootfs-<label>.erofs`. Selection lives here, at the artifact layer, rather than on
        /// `VmConfig` — a cell consumes whatever path it is handed, exactly as before.
        #[arg(long)]
        rootfs_label: Option<String>,
        /// Which `handlers` registry label to inject at the guest tools path (§10.5). Omitted
        /// builds `default` — the workspace `vmcell-guest-tools` helper, exactly as before v33.
        /// A registered label is fetched and verified against its digest, and its own `applets`
        /// roster becomes the injected symlinks.
        #[arg(long)]
        handler_label: Option<String>,
        /// Pins overlay layered over vmcell's committed baseline (§10.2). Overrides `$VMCELL_PINS`.
        #[arg(long)]
        pins: Option<PathBuf>,
    },
    /// Build the named kernels from the pins `kernels` registry to `vmlinux-<label>`.
    BuildKernels {
        /// Which `kernels` registry labels to build, e.g. `6.12.94 usbhost` (§10.5, v33 delta 6).
        /// Selection is lazy: the verb builds exactly what it names, never the whole registry, so
        /// registering one more label in a shared pins file cannot tax every build that reads it.
        /// Pass `--all` for the pre-v33 roster; naming neither form is a typed error.
        labels: Vec<String>,
        /// Build every label in the merged `kernels` registry — the pre-v33 behavior, now explicit
        /// (§10.5). Mutually exclusive with the positional labels.
        #[arg(long)]
        all: bool,
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
        /// Inject this prebuilt static-musl steward instead of the default glibc steward
        /// (required for a libc6-less base). Without it, a libc6-less base fails loud.
        #[arg(long)]
        steward_musl: Option<PathBuf>,
        /// Compose a downstream file into the image at pack time (repeatable, §4.2 FR-V4):
        /// `dest=/usr/local/bin/acme,src=./acme,mode=0755`. `dest` is absolute, `mode` is
        /// octal permission bits, and neither key may be omitted. A dest vmcell itself owns
        /// (the steward, the CA trust store, `/vmcell-tools`) or a duplicated dest is a
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
        /// session, §3, The control plane: vsock, the host clients, and the steward) instead of the default one-shot `/dev/null`
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
    /// Create + boot a fresh micro-VM and confirm its steward is ready, then tear it
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

/// Refuses a seed-needing producer on `vmcell build`, naming the route that does work (M3, §5.4,
/// The guest-kernel contract and the bootstrap seed).
///
/// `build` publishes exactly one kernel, under the default `kernel` key, and cannot stage a seed
/// ahead of it the way `build-kernels` does: the unlabelled `InVmKernelStage` answers `name()` with
/// `"kernel"` and `out_path()` with `vmlinux` — the exact pair `PrebuiltKernelStage` uses — so the
/// seed and the in-VM stage would share the one `vmlinux.cache_key` sidecar and overwrite each
/// other's key on every run, making every `vmcell build` miss cache and re-run the up-to-2-hour
/// compile. That is why this is a refusal and not a copy of `build-kernels`' seed staging; the
/// obvious fix is the wrong one. Before M3 the flag was accepted and the pipeline then died on
/// "needs a seed `kernel` artifact" — remedial advice the operator could not act on from here.
///
/// The refusal lives at pipeline assembly rather than at clap-parse time: clap's own rejection is
/// an exit-2 usage error, not the matchable `vmcell::Error` every other CLI refusal is
/// (`moved_to_vmcelld_ctl`, `reject_labelled_prebuilt`), and encoding it in the type would mean a
/// second, `build`-only producer enum — a copy of §5.4's producer set whose clap "possible values"
/// line could not name the `build-kernels` route. It is the FIRST statement of [`build_stages`], so
/// nothing is printed, allocated, or downloaded before the flag is honored or rejected.
///
/// # Errors
/// Returns [`vmcell::Error::Unsupported`] when `source` needs a bootstrap seed (the one
/// [`kernel_source_needs_seed`] law), i.e. for the in-VM producer.
fn reject_seed_needing_source_for_build(source: KernelSource) -> vmcell::Result<()> {
    if !kernel_source_needs_seed(source) {
        return Ok(());
    }
    let producer = kernel_source_name(source);
    Err(vmcell::Error::Unsupported {
        vmm: "vmcell".to_string(),
        // The named route carries a SELECTOR (`--all`, or the labels): since v33 delta 6 a bare
        // `build-kernels` is itself a refusal, and remedial advice the operator cannot paste is the
        // exact defect this refusal replaced.
        feature: format!(
            "`vmcell build --kernel-source {producer}` cannot stage the bootstrap seed kernel the \
             {producer} producer boots from — run `vmcell build-kernels --all --kernel-source \
             {producer}` instead (or name the labels), which stages it (§5.4); `vmcell build` takes \
             `prebuilt` or `host-make`"
        ),
    })
}

/// Assembles the `vmcell build` pipeline's stages in run order: resolved pins, the selected kernel
/// producer, the steward and tools, and the selected rootfs producer (§5.4, The guest-kernel contract and the bootstrap seed; §4.3, The rootfs-construction contract).
///
/// Separate from [`dispatch`] so the wiring — including the refusal above — is assertable without
/// running a build that downloads and compiles for hours.
///
/// # Errors
/// As [`reject_seed_needing_source_for_build`] (a producer `build` cannot seed) and
/// [`kernel_stage`].
fn build_stages(
    kernel_source: KernelSource,
    rootfs_source: RootfsSourceKind,
    release: String,
    rootfs_label: Option<&str>,
    handler_label: Option<&str>,
    pins: Option<&std::path::Path>,
    cid_alloc: std::sync::Arc<vmcell::vmm::CidAllocator>,
) -> vmcell::Result<Vec<Box<dyn vmcell::artifact::Stage>>> {
    reject_seed_needing_source_for_build(kernel_source)?;
    // `--rootfs-label default` and no `--rootfs-label` are the SAME request, and the one law that
    // says so is `registry_label` (§10.5): the reserved default label contributes no suffix, so the
    // pins flatten to the un-suffixed `rootfs_image`/`rootfs_digest` keys and the image lands on
    // `rootfs.erofs`. Without this normalization the explicit spelling composed
    // `rootfs_default_image` — a pin key the flattener never emits — and the build died on
    // `Missing rootfs_default_image pin` while the identical implicit invocation worked.
    //
    // Normalized ONCE, here at the head, rather than at each of the three uses below: the entry
    // resolution, the image stage and the declaration stage must all be handed the same
    // `Option<&str>`, or the sidecar lands beside a differently-spelled image (the two filename
    // composers treat `Some("default")` and `None` as different files).
    let rootfs_label = rootfs_label.and_then(vmcell::artifact::registry::registry_label);
    let rootfs_entry = resolve_rootfs_entry(rootfs_label, pins)?;
    let handler = resolve_handler_entry(handler_label, pins)?;
    let mut stages: Vec<Box<dyn vmcell::artifact::Stage>> = vec![
        Box::new(vmcell::artifact::ResolvePinsStage {
            overlay_file: pins_overlay(pins),
        }),
        kernel_stage(kernel_source, None, None, cid_alloc.clone())?,
        Box::new(vmcell::artifact::steward::StewardStage {}),
        Box::new(vmcell::artifact::guest_tools::GuestToolsStage::labelled(
            handler_label,
            handler.as_ref().map(|e| e.source.clone()),
        )),
        rootfs_stage(
            rootfs_source,
            release,
            rootfs_label,
            handler
                .as_ref()
                .map(vmcell::artifact::handler::HandlerRegistryEntry::applet_roster),
            cid_alloc,
        ),
    ];
    // §7.4's declaration sidecar, emitted beside the image the OCI source just packed (§18 delta
    // 6c). Its own stage, because a declaration-only edit must re-emit the sidecar and leave the
    // image's cache key unmoved — see `RootfsFeaturesStage`'s rustdoc for the whole split.
    //
    // The OCI arm only, and that is the F1 reading rather than an omission: the `mmdebstrap` source
    // builds from a release suite and reads no registry entry at all (`--rootfs-label` is refused
    // against it), so it has no declaration to travel. Emitting the `default` entry's declaration
    // beside an image that entry never described would be a claim nobody made.
    if let (RootfsSourceKind::Oci, Some(entry)) = (rootfs_source, rootfs_entry.as_ref()) {
        // `rootfs_label` verbatim — the SAME `Option<&str>` `rootfs_stage` was handed above, so the
        // declaration lands beside the image it describes rather than beside a differently-spelled
        // one (the two filename composers treat `Some("default")` and `None` as different files).
        stages.push(Box::new(
            vmcell::artifact::rootfs::RootfsFeaturesStage::labelled(rootfs_label)
                .with_features(entry.features.clone()),
        ));
    }
    Ok(stages)
}

/// Resolves the `handlers` registry entry a `--handler-label` names, refusing an unknown one.
///
/// `None` (no flag) resolves the `default` entry when the registry has one — so the shipped
/// behavior is what the committed pins SAY rather than what this file hardcodes — and `None` again
/// when it does not, which is the pre-v33 workspace build.
///
/// # Errors
/// [`vmcell::Error::Artifact`] naming the unknown label and the registered ones.
fn resolve_handler_entry(
    label: Option<&str>,
    pins: Option<&std::path::Path>,
) -> vmcell::Result<Option<vmcell::artifact::handler::HandlerRegistryEntry>> {
    let overlay = vmcell::artifact::pins_overlay_or_env(pins);
    let registry = vmcell::artifact::resolve_handler_registry(overlay.as_deref())?;
    let wanted = label.unwrap_or(vmcell::artifact::registry::DEFAULT_LABEL);
    match registry.iter().find(|e| e.label == wanted) {
        Some(entry) => Ok(Some(entry.clone())),
        // An explicit label that is not registered is a refusal; an absent `default` is not — a
        // consumer's overlay may legitimately carry no `handlers` namespace at all, and the
        // workspace build is what that means.
        None if label.is_some() => Err(unknown_label_error(
            "handler",
            "handlers",
            wanted,
            &registry
                .iter()
                .map(|e| e.label.as_str())
                .collect::<Vec<_>>(),
        )),
        None => Ok(None),
    }
}

/// Selects the `kernels` registry entries a `build-kernels` invocation names — the lazy-selection
/// law (§10.5, v33 delta 6).
///
/// Before v33 the verb built **every** merged label unconditionally, so registering one more kernel
/// in a shared pins file taxed every build in every workspace that read that file — the asymmetry
/// §10.5 closes. Selection is now stated by the invocation: `build-kernels <label>…` builds exactly
/// what it names, `--all` builds the whole roster (the pre-v33 behavior, kept but no longer
/// implied). Naming neither is a refusal rather than a silent "everything", because the eager
/// reading is the expensive one — a wrong guess is an up-to-2-hour compile per label — and because
/// AGENTS' construction rule admits no third meaning for an input the operator did not give.
///
/// The order of the result is the **registry's** pinned byte-lexicographic order, not argv order,
/// so two invocations naming the same set build in the same order and a repeated label yields one
/// stage rather than two that fight over one `vmlinux-<label>.cache_key` sidecar.
///
/// This lives at the composition root, beside the assembly, rather than inside
/// [`build_kernels_stages`]: the assembly takes the slice it is handed, so its roster gates keep
/// asserting the seed law they say they assert, and selection gets its own gates instead of hiding
/// behind a green assembly test at an unchanged call site.
///
/// # Errors
/// [`vmcell::Error::Artifact`] when the invocation names neither form, names both, or names a label
/// the merged registry does not hold (naming the ones it does, via [`unknown_label_error`]).
fn select_kernel_labels(
    registry: &[vmcell::artifact::KernelRegistryEntry],
    labels: &[String],
    all: bool,
) -> vmcell::Result<Vec<vmcell::artifact::KernelRegistryEntry>> {
    let registered: Vec<&str> = registry.iter().map(|e| e.label.as_str()).collect();
    if all && !labels.is_empty() {
        return Err(vmcell::Error::Artifact(format!(
            "`vmcell build-kernels` names both the labels [{}] and `--all`: they mean different \
             builds, so pass the labels to build OR `--all` to build the whole `kernels` registry \
             [{}] — never both (§10.5)",
            labels.join(", "),
            registered.join(", ")
        )));
    }
    if all {
        return Ok(registry.to_vec());
    }
    let Some(example) = registered.first() else {
        // An empty registry is the caller's own error (it can say the namespace is missing), and
        // an example composed from nothing would be a fabricated label.
        return Err(vmcell::Error::Artifact(
            "`vmcell build-kernels` names no label and the resolved pins `kernels` registry is \
             empty — register one through a pins overlay (§10.2), then name it or pass `--all`"
                .to_string(),
        ));
    };
    if labels.is_empty() {
        return Err(vmcell::Error::Artifact(format!(
            "`vmcell build-kernels` names no label: pass one or more labels (e.g. `vmcell \
             build-kernels {example}`) or `--all` to build the whole `kernels` registry [{}]. \
             Selection is lazy as of v33 delta 6 (§10.5) — registering a label must not tax every \
             build that reads the pins, so this verb no longer defaults to everything",
            registered.join(", ")
        )));
    }
    for label in labels {
        if !registered.contains(&label.as_str()) {
            return Err(unknown_label_error("kernel", "kernels", label, &registered));
        }
    }
    Ok(registry
        .iter()
        .filter(|e| labels.iter().any(|l| l == &e.label))
        .cloned()
        .collect())
}

/// Assembles the kernel stages `vmcell build-kernels` runs, in run order: the bootstrap seed first
/// when the producer needs one, then one stage per **selected** registry entry (§5.4, The guest-kernel contract and the bootstrap seed; §5.6, The downstream kernel toolkit).
///
/// `registry` is what [`select_kernel_labels`] handed back, not the merged roster: selection is the
/// caller's, so this function's roster is exactly "seed, then what you asked for".
///
/// The in-VM producer boots a builder micro-VM, which needs a working `vmlinux` published under the
/// `kernel` artifact key — a key no labelled stage ever registers (they register `kernel-<label>`).
/// The pinned prebuilt seed is staged ahead of them (§5.4); it is content-addressed like any stage,
/// so a warm artifacts dir hits cache and nothing is re-downloaded. The caller prepends
/// [`ResolvePinsStage`](vmcell::artifact::ResolvePinsStage), which is not per-kernel.
///
/// # Errors
/// As [`kernel_stage`] — a labelled build routed at the prebuilt producer, which compiles nothing.
fn build_kernels_stages(
    kernel_source: KernelSource,
    registry: &[vmcell::artifact::KernelRegistryEntry],
    cid_alloc: std::sync::Arc<vmcell::vmm::CidAllocator>,
) -> vmcell::Result<Vec<Box<dyn vmcell::artifact::Stage>>> {
    let mut stages: Vec<Box<dyn vmcell::artifact::Stage>> = Vec::new();
    if kernel_source_needs_seed(kernel_source) {
        stages.push(kernel_stage(
            KernelSource::Prebuilt,
            None,
            None,
            cid_alloc.clone(),
        )?);
    }
    for entry in registry {
        stages.push(kernel_stage(
            kernel_source,
            Some(entry.label.clone()),
            Some(entry.fragments.clone()),
            cid_alloc.clone(),
        )?);
    }
    Ok(stages)
}

/// Every `(manifest name, path)` `vmcell bundle` considers in `dir`, present or not — the whole
/// candidate walk, as a pure function of the directory's contents.
///
/// Extracted from [`bundle_artifacts`] so the roster is assertable **directly**, against a fixture
/// tree, without hashing files or writing a manifest. It was inline, and that is why the sidecar
/// candidates below were missing for a whole delta: adding a line to a list buried inside `dispatch`
/// ships ungated, and the omission is invisible — the manifest simply covers less while still
/// reporting success.
///
/// The list is deliberately *candidates* rather than *hits*: the caller partitions them into present
/// and skipped, and prints the skipped ones, so an absent artifact is reported rather than silently
/// dropped.
///
/// Every name is composed through the library's own key laws, never spelled here: a manifest entry
/// under a name the producers do not register is a name no consumer can look up.
fn bundle_candidates(dir: &std::path::Path) -> Vec<(String, PathBuf)> {
    use vmcell::artifact::rootfs::{features_artifact_key, rootfs_artifact_key};
    use vmcell::feature::feature_manifest_path;

    let default_rootfs = dir.join("rootfs.erofs");
    let mut candidates: Vec<(String, PathBuf)> = vec![
        ("kernel".to_string(), dir.join("vmlinux")),
        (rootfs_artifact_key(None), default_rootfs.clone()),
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
    // The default rootfs's §7.4 feature-declaration sidecar (§18 delta 6c) — the rootfs's
    // counterpart of the kernel-config candidate above, and it closes the same N-BIN-4 hole for a
    // strictly worse consequence: a bundled rootfs that arrives WITHOUT its declaration reads to
    // `FeatureDeclaration::load_beside` exactly like an un-annotated artifact, so the consumer's
    // cell silently re-claims every capability the declaration existed to withdraw (today, that
    // vmcell's packer strips xattrs). A missing kernel config is a gap; a missing declaration is a
    // lie the consumer cannot detect.
    candidates.push((
        features_artifact_key(&rootfs_artifact_key(None)),
        feature_manifest_path(&default_rootfs),
    ));
    // Cover every labelled kernel built by `build-kernels` (`vmlinux-<label>`),
    // not just the default `vmlinux` — otherwise the manifest silently omits
    // the cross-kernel sweep's artifacts (N-BIN-4) — and each one's resolved-config
    // sidecar alongside it, so the manifest pins what the kernel actually contains.
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let fname = e.file_name();
            let name = fname.to_string_lossy();
            // The library's one label law (the inverse of the producers' filename
            // composer), so a producer that changed its sanitization could not silently
            // drop its kernels from this manifest.
            if let Some(label) = vmcell::artifact::kernel::kernel_label_from_filename(&name) {
                // The manifest names a labelled kernel by the library's artifact-key law
                // (and its sidecar by the derived config key) rather than re-spelling
                // `kernel-<label>` here — a manifest entry the producers do not register
                // under is a name no consumer can look up.
                let key = vmcell::artifact::kernel::kernel_artifact_key(Some(label));
                candidates.push((
                    vmcell::artifact::kernel::config_artifact_key(&key),
                    vmcell::artifact::kernel::resolved_config_path(&e.path()),
                ));
                candidates.push((key, e.path()));
            }
            // The same law, one kind over (§10.5, v33 delta 6): every labelled rootfs
            // built through `--rootfs-label` (`rootfs-<label>.erofs`). Without this the
            // registry would re-arm the exact N-BIN-4 defect the kernel walk above exists
            // to close — a registered artifact silently absent from the manifest.
            //
            // The walk keys on the IMAGE filename, so each labelled rootfs contributes its
            // declaration sidecar here rather than in a second pass: `rootfs_label_from_filename`
            // returns `None` for a `.features` file (it demands the `.erofs` suffix), which is the
            // property that keeps a sidecar from being bundled as a rootfs in its own right.
            if let Some(label) = vmcell::artifact::rootfs::rootfs_label_from_filename(&name) {
                let key = rootfs_artifact_key(Some(label));
                candidates.push((
                    features_artifact_key(&key),
                    feature_manifest_path(&e.path()),
                ));
                candidates.push((key, e.path()));
            }
        }
    }
    candidates
}

/// Writes the digest-pinned fetch-and-verify manifest of everything present in `dir`.
///
/// Separate from [`dispatch`] so the whole walk — and the F7 refusal at its head — is assertable
/// against a fixture directory without touching the process environment: the refusal is a *call
/// site* rule (it must run before the manifest is written), and a test that only drove the library
/// predicate would leave exactly the "green unit test beside an unchanged call site" gap AGENTS.md
/// names.
///
/// # Errors
/// [`vmcell::Error::Artifact`] when `dir` holds no artifacts at all, when its resolved pins name an
/// unpinned registration (§10.5, F7), or when an artifact cannot be hashed or the manifest written.
fn bundle_artifacts(dir: &std::path::Path, out: Option<&std::path::Path>) -> vmcell::Result<()> {
    let candidates = bundle_candidates(dir);
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
    // F7 (§10.5): an unpinned registration is REFUSED here, before a byte of manifest is written —
    // a manifest naming an artifact whose registration meant "whatever was at that path that day"
    // is a provenance claim vmcell cannot back, and writing it first and complaining afterwards
    // would leave that claim on disk. Read from the artifacts dir's own `resolved_pins.json`, so
    // `bundle` still needs no `--pins` (see `reject_unpinned_registrations`).
    vmcell::artifact::bundle::reject_unpinned_registrations(&dir.join("resolved_pins.json"))?;
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
    let out_path = out.map_or_else(|| dir.join("manifest.json"), std::path::Path::to_path_buf);
    manifest.write_to(&out_path)?;
    println!(
        "vmcell: wrote artifact manifest ({} entries) to {}",
        present.len(),
        out_path.display()
    );
    Ok(())
}

/// Resolves the `rootfs` registry entry a `--rootfs-label` names, refusing an unknown one and
/// naming the labels that ARE registered (§10.5).
///
/// A pre-flight rather than a `Missing rootfs_<label>_image pin` deep inside the stage: the pin
/// message cannot say which labels exist, and "the label you asked for is not registered" is the
/// only thing the operator needs to hear. Mirrors `build_labelled_kernel`'s own pre-flight and
/// [`resolve_handler_entry`]'s shape, one kind over.
///
/// It returns the **entry** rather than validating the label alone because v33 delta 6c gave the
/// entry a `features` declaration the build has to emit (§7.4): resolving the registry twice —
/// once to check the label, once to read what that label declares — is exactly how the two come to
/// disagree about which entry the build is for.
///
/// `None` (no flag) resolves the `default` entry when the registry has one, and `Ok(None)` when it
/// does not — a consumer overlay may legitimately carry no matching entry, and only an EXPLICIT
/// label is a refusal.
///
/// # Errors
/// [`vmcell::Error::Artifact`] naming the unknown label and the registered ones.
fn resolve_rootfs_entry(
    label: Option<&str>,
    pins: Option<&std::path::Path>,
) -> vmcell::Result<Option<vmcell::artifact::RootfsRegistryEntry>> {
    let overlay = vmcell::artifact::pins_overlay_or_env(pins);
    if let Some(entry) = vmcell::artifact::resolve_rootfs_entry(label, overlay.as_deref())? {
        return Ok(Some(entry));
    }
    match label {
        Some(label) => Err(unknown_label_error(
            "rootfs",
            "rootfs",
            label,
            &vmcell::artifact::resolve_rootfs_labels(overlay.as_deref())?
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        )),
        None => Ok(None),
    }
}

/// Builds the rootfs [`Stage`](vmcell::artifact::Stage) selected by `source` — the `vmcell`
/// OCI bootstrap producer or the in-VM `vmcell-rootfs-builder` mmdebstrap source (§4.3, The rootfs-construction contract).
fn rootfs_stage(
    source: RootfsSourceKind,
    release: String,
    rootfs_label: Option<&str>,
    applets: Option<Vec<String>>,
    cid_alloc: std::sync::Arc<vmcell::vmm::CidAllocator>,
) -> Box<dyn vmcell::artifact::Stage> {
    match source {
        // `vmcell build` produces vmcell's own canonical rootfs and takes no `--inject`; the
        // downstream extra-file surface is `oci2erofs` (§10.4's documented consumer
        // invocation), so both arms compose nothing.
        RootfsSourceKind::Oci => Box::new(
            vmcell::artifact::rootfs::RootfsStage::labelled(rootfs_label)
                .with_applets(applets.unwrap_or_default()),
        ),
        // The mmdebstrap source builds from a release suite, not from a registered digest, so it
        // has no label to honor. `dispatch` refuses the combination before this point rather than
        // dropping it here: an accepted-and-ignored `--rootfs-label` would build the default
        // userland and report success.
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
            rootfs_label,
            handler_label,
            pins,
        } => {
            // F1 on a flag pair: the mmdebstrap source builds from a release suite, not from a
            // registered digest, so it has no label to honor. Refuse rather than ignore.
            //
            // Keyed on the RAW flag, deliberately — `build_stages` normalizes the reserved
            // `default` label to `None`, but that normalization is about which pins keys a REGISTRY
            // request flattens to, and mmdebstrap reads no registry entry at all. Letting the
            // normalized form through would make `--rootfs-label default --rootfs-source
            // mmdebstrap` the one spelling that is silently ignored instead of refused.
            if rootfs_label.is_some() && matches!(rootfs_source, RootfsSourceKind::Mmdebstrap) {
                return Err(vmcell::Error::Artifact(
                    "--rootfs-label selects a `rootfs` registry entry (§10.5), which the \
                     `mmdebstrap` source does not read: it builds from --release. Use \
                     --rootfs-source oci, or drop --rootfs-label."
                        .into(),
                ));
            }
            // One CID allocator shared by any in-VM builder stage this pipeline runs.
            let cid_alloc = std::sync::Arc::new(vmcell::vmm::CidAllocator::new());
            // Assemble — and so honor or reject every flag — BEFORE announcing the build: a
            // refused `--kernel-source` (M3) must not first print "Building artifacts...".
            let stages = build_stages(
                *kernel_source,
                *rootfs_source,
                release.clone(),
                rootfs_label.as_deref(),
                handler_label.as_deref(),
                pins.as_deref(),
                cid_alloc,
            )?;
            println!("Building artifacts...");
            let mut pipeline = vmcell::artifact::Pipeline::new(vmcell::artifact::artifacts_dir());
            for stage in stages {
                pipeline = pipeline.add_stage(stage);
            }
            pipeline.build(&vmcell::artifact::Cache::default()).await?;
            println!("Artifacts built successfully.");
            Ok(())
        }
        Commands::Oci2Erofs {
            image,
            output,
            steward_musl,
            inject,
            pins,
        } => {
            oci2erofs(
                image,
                output,
                steward_musl.as_deref(),
                inject,
                pins.as_deref(),
            )
            .await
        }
        Commands::Bundle { out } => {
            bundle_artifacts(&vmcell::artifact::artifacts_dir(), out.as_deref())
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
            labels,
            all,
            kernel_source,
            pins,
        } => {
            // Build each SELECTED kernel to its own `vmlinux-<label>` (the kernel-version
            // dimension), so multiple versions coexist for the cross-kernel benchmark sweep.
            // Each labelled stage has its own cache sidecar and build dir, and each carries the
            // fragment set its registry entry declares.
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
            // Laziness (§10.5, v33 delta 6): the invocation says what it builds. The filter sits
            // between the merged resolution and the assembly — never inside `build_kernels_stages`,
            // whose job is the seed law over whatever slice it is handed.
            let selected = select_kernel_labels(&registry, labels, *all)?;
            let selected_labels: Vec<&str> = selected.iter().map(|e| e.label.as_str()).collect();
            let producer = kernel_source_name(*kernel_source);
            println!(
                "Building kernels ({producer}): {}",
                selected_labels.join(", ")
            );
            let mut pipeline = vmcell::artifact::Pipeline::new(vmcell::artifact::artifacts_dir())
                .add_stage(Box::new(vmcell::artifact::ResolvePinsStage {
                    overlay_file,
                }));
            // The seed-then-labels roster is `build_kernels_stages` (assertable without a build);
            // this loop is its log. The seed line is the same one predicate the assembly uses.
            if kernel_source_needs_seed(*kernel_source) {
                println!("  - bootstrap seed (prebuilt) -> vmlinux (boots the builder VM)");
            }
            for entry in &selected {
                let label = &entry.label;
                println!(
                    "  - kernel {label} -> vmlinux-{label} (producer: {producer}, fragments: {})",
                    if entry.fragments.is_empty() {
                        "none".to_string()
                    } else {
                        entry.fragments.join("+")
                    }
                );
            }
            for stage in build_kernels_stages(*kernel_source, &selected, cid_alloc)? {
                pipeline = pipeline.add_stage(stage);
            }
            pipeline.build(&vmcell::artifact::Cache::default()).await?;
            println!("Kernels built ({producer}): {}", selected_labels.join(", "));
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
            // `--tty`/`--stdin` (§3, The control plane: vsock, the host clients, and the steward) route through an interactive session
            // that streams this CLI's stdin; the default path is the one-shot exec.
            let code = if *tty || *stdin {
                run_interactive_session(&vm, argv, *tty).await?
            } else {
                let steward = vm.steward(None).await?;
                let outcome = steward.exec(vmcell::ExecRequest::new(argv)).await?;
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
            // Confirm the steward handshakes — i.e. the VM actually booted —
            // before teardown. A failure here is a real error, not a fake success.
            vm.steward(None).await?;
            println!("vmcell: VM booted and steward ready (vmid {vmid})");
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
            // Bring the steward up so the snapshot captures a steward-ready VM.
            vm.steward(None).await?;
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
            vm.steward(None).await?;
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
    // LOWERCASE ONLY, for the same reason `registry::reject_unpinned_digest` demands it one crate
    // over: `verify_blob_digest` renders the pulled bytes' hash lowercase and compares
    // case-SENSITIVELY, so an uppercase digest is accepted here and then can never match. The
    // operator would meet "digest mismatch" after a multi-megabyte pull instead of a spelling
    // complaint before it. This stays its OWN law rather than calling the registry predicate: that
    // one names a pins namespace and a registry label, and this is a flag the operator typed.
    if hex.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(vmcell::Error::Artifact(format!(
            "oci2erofs requires a LOWERCASE sha256 hex digest, got `{digest}` — the digest is \
             compared byte-for-byte against the pulled bytes' hash, which is rendered lowercase, \
             so an uppercase digest can never verify; use `sha256:{}`",
            hex.to_ascii_lowercase()
        )));
    }
    Ok(())
}

/// Runs `argv` in an interactive session (§3, The control plane: vsock, the host clients, and the steward), streaming this CLI's
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
    use vmcell::steward::session::{SessionEvent, SessionSpecBuilder};

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
/// `steward_musl` supplies a static-musl steward (which needs no glibc). The pipeline is the SAME
/// inject+pack tail as `vmcell build` — verify-every-blob → whiteouts → inject steward/CA/tools
/// → erofs — only the base image (and the steward) are parameterized, so the runtime stays
/// erofs-only.
async fn oci2erofs(
    image_ref: &str,
    output: &std::path::Path,
    steward_musl: Option<&std::path::Path>,
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
    // staging dir has no cache history, so the steward/tools/rootfs stages rebuild.
    let stage_dir =
        vmcell::artifact::artifacts_dir().join(format!("oci2erofs-stage-{}", std::process::id()));
    // Best-effort pre-clean of a stale staging dir from a prior aborted run.
    let _ = std::fs::remove_dir_all(&stage_dir);
    let mut pipeline = vmcell::artifact::Pipeline::new(stage_dir.clone()).add_stage(Box::new(
        vmcell::artifact::ResolvePinsStage {
            overlay_file: pins_overlay(pins),
        },
    ));
    // The default glibc steward is built by the pipeline; `--steward-musl` supplies its own
    // prebuilt binary, so the build stage is skipped and the rootfs stage injects it instead.
    if steward_musl.is_none() {
        pipeline = pipeline.add_stage(Box::new(vmcell::artifact::steward::StewardStage {}));
    }
    pipeline = pipeline
        .add_stage(Box::new(
            vmcell::artifact::guest_tools::GuestToolsStage::new(),
        ))
        .add_stage(Box::new(
            vmcell::artifact::rootfs::RootfsStage::new()
                .with_image_override(image.to_string(), digest.to_string())
                .with_steward_musl(steward_musl.map(std::path::Path::to_path_buf))
                // The `--inject` files; the pack tail validates them (absolute dest, explicit
                // mode, no vmcell-owned or duplicated dest — §4.2, invariant F5).
                .with_extra(inject.to_vec()),
        ));

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
        // UPPERCASE hex is hex, and was accepted here until v33 delta 6c. It could then never
        // verify, because `verify_blob_digest` compares against a lowercase rendering — so the
        // operator paid for the whole pull to be told "digest mismatch". Refuse at the flag, name
        // the case, and hand back the string to paste.
        let upper = format!("sha256:{}", "A".repeat(64));
        let err = validate_oci_digest(&upper).expect_err("an uppercase digest must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("LOWERCASE"),
            "the refusal must name the case, got: {msg}"
        );
        assert!(
            msg.contains(&"a".repeat(64)),
            "the refusal must hand back the lowercased digest to paste, got: {msg}"
        );
        // A well-formed 64-hex digest is accepted — the positive control, so the leg above is a
        // statement about case and not about length or prefix.
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

    // M3 GATE (§5.4, delta 3): `vmcell build --kernel-source in-vm` was accepted and could never be
    // honored — the in-VM stage reads its seed from the pipeline's ARTIFACT MAP, and `build` staged
    // no seed, so the run died on "needs a seed `kernel` artifact" no matter what the operator had
    // already built. `build` cannot stage one either (both stages are named `kernel` and write
    // `vmlinux`, so they would fight over the one `vmlinux.cache_key` sidecar and re-run the
    // up-to-2-hour compile every time), so the flag is a typed refusal naming the route that works.
    // RED on the inverse (the pre-M3 arm that wired `InVmKernelStage` with no seed): the assembly
    // returns Ok and the operator gets the unhonorable pipeline back.
    #[test]
    fn build_refuses_the_in_vm_kernel_source_and_names_the_route() {
        let alloc = || std::sync::Arc::new(vmcell::vmm::CidAllocator::new());
        let err = build_stages(
            KernelSource::InVm,
            RootfsSourceKind::Oci,
            "trixie".to_string(),
            None,
            None,
            None,
            alloc(),
        )
        // Render the roster so a regression reports WHAT it assembled instead of `Box<dyn Stage>`
        // (which is not `Debug`).
        .map(|s| {
            s.iter()
                .map(|st| st.name().to_string())
                .collect::<Vec<_>>()
                .join(",")
        })
        .expect_err("`vmcell build` + in-vm must be refused, not assembled");
        assert!(
            matches!(err, vmcell::Error::Unsupported { .. }),
            "expected Error::Unsupported, got {err:?}"
        );
        // The refusal must name the WORKING route verbatim, so the operator's next command is the
        // one that succeeds. RED on a message that only says "not supported" — and, since v33
        // delta 6, red on a route missing its SELECTOR: a bare `build-kernels` now refuses itself,
        // so advice without `--all` (or labels) is advice the operator cannot paste.
        let shown = err.to_string();
        assert!(
            shown.contains("build-kernels --all --kernel-source in-vm"),
            "the refusal must name the `build-kernels` route WITH a selector, got: {shown}"
        );
        // Positive control: every producer `build` CAN honor still assembles the whole pipeline, in
        // run order, for both rootfs sources — the refusal is scoped to the seed-needing producer,
        // not a blanket break of `vmcell build`.
        for source in [KernelSource::Prebuilt, KernelSource::HostMake] {
            for rootfs in [RootfsSourceKind::Oci, RootfsSourceKind::Mmdebstrap] {
                let stages = build_stages(
                    source,
                    rootfs,
                    "trixie".to_string(),
                    None,
                    None,
                    None,
                    alloc(),
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "{} + {rootfs:?} must assemble: {e}",
                        kernel_source_name(source)
                    )
                });
                let names: Vec<String> = stages.iter().map(|s| s.name().to_string()).collect();
                let mut expected = vec![
                    "resolve_pins".to_string(),
                    "kernel".to_string(),
                    "steward".to_string(),
                    "guest_tools".to_string(),
                    "rootfs".to_string(),
                ];
                // §7.4's declaration sidecar producer (§18 delta 6c) rides with the OCI source
                // ONLY: the mmdebstrap source builds from a release suite and reads no registry
                // entry, so there is no declaration for it to travel — emitting the `default`
                // entry's beside an image that entry never described would be a claim nobody made.
                // Composed through the key laws rather than spelled, so a rename cannot leave this
                // roster asserting a stage name that no longer exists.
                if matches!(rootfs, RootfsSourceKind::Oci) {
                    expected.push(vmcell::artifact::rootfs::features_artifact_key(
                        &vmcell::artifact::rootfs::rootfs_artifact_key(None),
                    ));
                }
                assert_eq!(
                    names,
                    expected,
                    "the `build` pipeline's stage roster ({} + {rootfs:?})",
                    kernel_source_name(source)
                );
            }
        }
    }

    // The `--rootfs-label` pre-flight survived becoming an ENTRY resolution (§18 delta 6c). It used
    // to validate the label alone; it now returns the entry, because 6c gave that entry a `features`
    // declaration the build has to emit — and resolving the registry twice, once to check the label
    // and once to read what it declares, is exactly how the two come to disagree about which entry
    // the build is for.
    //
    // RED on a `resolve_rootfs_entry` that answers `Ok(None)` for an EXPLICIT unknown label: the
    // assembly succeeds and the operator learns about it as a `Missing rootfs_<label>_image pin`
    // deep inside the stage, a message that cannot say which labels exist.
    #[test]
    fn build_refuses_an_unknown_rootfs_label_and_carries_a_known_ones_declaration() {
        let alloc = || std::sync::Arc::new(vmcell::vmm::CidAllocator::new());
        let assemble = |label: Option<&str>| {
            build_stages(
                KernelSource::Prebuilt,
                RootfsSourceKind::Oci,
                "trixie".to_string(),
                label,
                None,
                None,
                alloc(),
            )
        };
        let err = assemble(Some("no-such-userland"))
            .map(|s| {
                s.iter()
                    .map(|st| st.name().to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .expect_err("an unregistered `--rootfs-label` must be refused, not assembled");
        let shown = err.to_string();
        for named in [
            "no-such-userland",
            vmcell::artifact::registry::DEFAULT_LABEL,
        ] {
            assert!(
                shown.contains(named),
                "the refusal must name {named}: {shown}"
            );
        }

        // Positive control: the registered label assembles, AND its declaration reaches the
        // pipeline as its own stage — so the refusal is about the label, not about labels at all.
        let label = vmcell::artifact::registry::DEFAULT_LABEL;
        let stages = assemble(Some(label)).expect("the registered label must assemble");
        // The declaration stage carries the SAME label the image stage got — which, for the
        // reserved default, is the normalized `None` (§10.5, and
        // `build_treats_the_explicit_default_rootfs_label_as_the_omitted_one` is that law's own
        // gate). Composed through `registry_label` here rather than assumed, so the two stages are
        // asserted to agree whatever the label is.
        let image = vmcell::artifact::rootfs::rootfs_artifact_key(
            vmcell::artifact::registry::registry_label(label),
        );
        let names: Vec<&str> = stages.iter().map(|s| s.name()).collect();
        assert!(names.contains(&image.as_str()), "{names:?}");
        assert!(
            names.contains(&vmcell::artifact::rootfs::features_artifact_key(&image).as_str()),
            "the selected label's §7.4 declaration must travel with it: {names:?}"
        );
    }

    // §10.5's reserved default label, at the CLI's composition root: `--rootfs-label default` and no
    // `--rootfs-label` are the SAME request, so they must assemble the same pipeline.
    //
    // They did not. `rootfs_stage` built `RootfsStage::labelled(Some("default"))`, which composes
    // the filename `rootfs-default.erofs` and the pin key `rootfs_default_image` — a key the
    // flattener never emits, because `registry_label` normalizes the default to the un-suffixed
    // keys. So the explicit spelling of the default died on `Missing rootfs_default_image pin`
    // while the identical implicit invocation built fine. `registry_label` at the head of
    // `build_stages` is that one law applied once, and the third claim below is the one that names
    // the actual failure: the pin the normalized stage looks for is a key the pins really carry,
    // and the un-normalized one is not.
    //
    // RED on the inverse (drop the `registry_label` normalization): the roster claim fails first,
    // `left: ["…", "rootfs-default", "rootfs-default-features"]` against the omitted form's
    // `["…", "rootfs", "rootfs-features"]`.
    #[test]
    fn build_treats_the_explicit_default_rootfs_label_as_the_omitted_one() {
        use vmcell::artifact::registry::DEFAULT_LABEL;
        use vmcell::artifact::rootfs::{rootfs_artifact_key, rootfs_filename, rootfs_pin_key};

        let assemble = |label: Option<&str>| {
            build_stages(
                KernelSource::Prebuilt,
                RootfsSourceKind::Oci,
                "trixie".to_string(),
                label,
                None,
                None,
                std::sync::Arc::new(vmcell::vmm::CidAllocator::new()),
            )
            .unwrap_or_else(|e| panic!("`--rootfs-label {label:?}` must assemble: {e}"))
        };
        let roster = |stages: &[Box<dyn vmcell::artifact::Stage>]| -> Vec<String> {
            stages.iter().map(|s| s.name().to_string()).collect()
        };

        let omitted = assemble(None);
        let explicit = assemble(Some(DEFAULT_LABEL));
        assert_eq!(
            roster(&explicit),
            roster(&omitted),
            "`--rootfs-label {DEFAULT_LABEL}` must assemble the same pipeline as no label at all — \
             the reserved default contributes no suffix (§10.5)"
        );

        // And the same FILE: the roster is stage names, and the declaration sidecar lands beside
        // whatever the image stage writes, so the path is the claim that matters to disk.
        let dir = std::path::Path::new("/artifacts");
        let image = explicit
            .iter()
            .find(|s| s.name() == rootfs_artifact_key(None))
            .expect("the image stage must be named by the default artifact key");
        assert_eq!(
            image.out_path(dir),
            dir.join(rootfs_filename(None)),
            "the explicit default must still write `rootfs.erofs`, not `rootfs-default.erofs`"
        );

        // The failure itself: the pin key the normalized stage reads is one the flattener emits,
        // and the un-normalized one is a key that exists nowhere. Asserted against the REAL merged
        // pins, so this cannot pass against a fixture that invented either key.
        let pins = vmcell::artifact::resolve_pins(None).expect("the baseline pins resolve");
        assert!(
            pins.contains_key(&rootfs_pin_key(None, "image")),
            "the normalized stage reads `{}`, which the flattener must emit",
            rootfs_pin_key(None, "image")
        );
        assert!(
            !pins.contains_key(&rootfs_pin_key(Some(DEFAULT_LABEL), "image")),
            "`{}` is a key the flattener NEVER emits — composing it is exactly how \
             `--rootfs-label {DEFAULT_LABEL}` died on `Missing … pin`",
            rootfs_pin_key(Some(DEFAULT_LABEL), "image")
        );
    }

    // M3's other half, and delta 3's own gate: the in-VM producer's working route STILL works —
    // `build-kernels` stages the prebuilt seed (the `kernel` key the builder VM boots from) ahead
    // of the labelled stages, which is exactly what `build` structurally cannot do. RED on the
    // inverse (dropping the seed from the roster, i.e. the pre-v30 pipeline): the seed `kernel`
    // stage disappears and `build-kernels --kernel-source in-vm` dies on the missing artifact.
    #[test]
    fn build_kernels_still_stages_the_seed_for_in_vm() {
        let alloc = || std::sync::Arc::new(vmcell::vmm::CidAllocator::new());
        // The real registry, through the library's merged resolution — the same roster the command
        // builds, never a test-local list.
        let registry =
            vmcell::artifact::resolve_kernel_registry(None).expect("the baseline kernels registry");
        assert!(
            !registry.is_empty(),
            "the baseline registry must not be empty"
        );
        let labels: Vec<&str> = registry.iter().map(|e| e.label.as_str()).collect();
        let in_vm = build_kernels_stages(KernelSource::InVm, &registry, alloc())
            .expect("`build-kernels` + in-vm must assemble");
        let names: Vec<&str> = in_vm.iter().map(|s| s.name()).collect();
        // The seed is the unlabelled `kernel` stage FIRST; the labelled stages follow in registry
        // order (a seed staged after them would publish `kernel` too late for the builder VM).
        let mut expected = vec!["kernel"];
        expected.extend(labels.iter().copied());
        assert_eq!(names, expected, "seed-first roster for the in-VM producer");
        // Contrast: a producer that needs no seed gets exactly the labels, no seed stage.
        let host_make = build_kernels_stages(KernelSource::HostMake, &registry, alloc())
            .expect("`build-kernels` + host-make must assemble");
        assert_eq!(
            host_make.iter().map(|s| s.name()).collect::<Vec<_>>(),
            labels,
            "host-make needs no seed"
        );
    }

    /// The real merged registry, never a test-local list — the same roster the command selects
    /// from. `KernelRegistryEntry` is `#[non_exhaustive]`, so this crate could not fabricate one
    /// anyway, which is the right constraint: a selection gate over invented entries proves
    /// nothing about the entries `build-kernels` actually sees.
    fn baseline_registry() -> Vec<vmcell::artifact::KernelRegistryEntry> {
        let registry =
            vmcell::artifact::resolve_kernel_registry(None).expect("the baseline kernels registry");
        assert!(
            registry.len() >= 2,
            "the laziness gates need at least two registered labels to distinguish \
             `selected` from `everything`, got {registry:?}"
        );
        registry
    }

    // §10.5 LAZINESS GATE (v33 delta 6), the half the design calls "assert a build that selects
    // nothing does not build it": naming ONE label selects exactly that label, and every other
    // REGISTERED label stays unbuilt. The baseline registry carries three, so the distinction is
    // real data rather than a fixture.
    //
    // RED on the inverse — the pre-v33 eager reading, `Ok(registry.to_vec())` for every arm:
    // `selected` comes back with all three entries and the length assertion fails.
    #[test]
    fn build_kernels_selects_only_the_labels_it_names() {
        let registry = baseline_registry();
        let wanted = registry[0].label.clone();
        let selected = select_kernel_labels(&registry, std::slice::from_ref(&wanted), false)
            .expect("naming a registered label must select it");
        assert_eq!(
            selected
                .iter()
                .map(|e| e.label.as_str())
                .collect::<Vec<_>>(),
            vec![wanted.as_str()],
            "one named label selects exactly one entry"
        );
        // The unselected labels are REGISTERED and still unbuilt — the property that keeps a shared
        // pins file from taxing every workspace that reads it.
        for entry in registry.iter().skip(1) {
            assert!(
                !selected.iter().any(|s| s.label == entry.label),
                "`{}` is registered but was not named, so it must not be selected",
                entry.label
            );
        }
        // The fragment set travels with the selection: selecting by label must not drop what the
        // entry declares (a selected-but-fragment-less build is a labelled build that never
        // happened, the pre-v30 defect one layer up).
        assert_eq!(selected[0].fragments, registry[0].fragments);

        // `--all` is the pre-v33 roster, kept but now explicit — and in the registry's own pinned
        // order, which is what `build_kernels_stages` turns into stage order.
        let all =
            select_kernel_labels(&registry, &[], true).expect("`--all` must select the roster");
        assert_eq!(all, registry, "`--all` selects the whole roster, in order");

        // Two names select two entries in REGISTRY order, not argv order, and a repeated label is
        // one stage rather than two fighting over one `vmlinux-<label>.cache_key` sidecar.
        let reversed = vec![
            registry[1].label.clone(),
            registry[0].label.clone(),
            registry[0].label.clone(),
        ];
        let pair = select_kernel_labels(&registry, &reversed, false).expect("both are registered");
        assert_eq!(
            pair.iter().map(|e| e.label.as_str()).collect::<Vec<_>>(),
            vec![registry[0].label.as_str(), registry[1].label.as_str()],
            "selection is deduped and ordered by the registry, not by argv"
        );
    }

    // §10.5 (v33 delta 6): the CLI behavior change is a REFUSAL, not a new default. An invocation
    // that names neither form is refused naming BOTH forms, and one that names both is refused
    // too — vmcell picks neither for the operator (AGENTS: every accepted input is honored or
    // rejected at construction). Written explicitly rather than leaning on clap's
    // `conflicts_with`, whose rendering names neither the labels nor the registry.
    //
    // RED on the inverse (either arm falling through to `Ok(registry.to_vec())`, i.e. the eager
    // default): both `expect_err`s fail.
    #[test]
    fn build_kernels_refuses_an_invocation_that_states_no_selection() {
        let registry = baseline_registry();
        let neither = select_kernel_labels(&registry, &[], false)
            .expect_err("naming neither labels nor `--all` must be refused")
            .to_string();
        // BOTH forms, so the operator's next command is a runnable one either way.
        assert!(
            neither.contains("--all"),
            "the refusal must name `--all`, got: {neither}"
        );
        assert!(
            neither.contains(&format!("build-kernels {}", registry[0].label)),
            "the refusal must show the positional form with a REGISTERED label, got: {neither}"
        );
        for entry in &registry {
            assert!(
                neither.contains(entry.label.as_str()),
                "the refusal must list the registered label `{}`, got: {neither}",
                entry.label
            );
        }

        let both = select_kernel_labels(&registry, &[registry[0].label.clone()], true)
            .expect_err("naming labels AND `--all` must be refused")
            .to_string();
        assert!(
            both.contains("--all") && both.contains(registry[0].label.as_str()),
            "the both-forms refusal must name what was passed, got: {both}"
        );
    }

    // The unknown-label refusal is the one `unknown_label_error` shape every registry selector in
    // this file shares (§10.5) — it names the label asked for AND the labels that exist, so the
    // operator's next command is composable from the message alone.
    //
    // RED on the inverse (silently dropping an unknown label from the selection): the `expect_err`
    // fails — and that inverse is the pre-v30 "labelled build that never happened" defect, one
    // layer up.
    #[test]
    fn build_kernels_refuses_an_unknown_label_naming_the_registered_ones() {
        let registry = baseline_registry();
        let msg = select_kernel_labels(&registry, &["not-a-kernel".to_string()], false)
            .expect_err("an unregistered label must be refused")
            .to_string();
        assert!(
            msg.contains("not-a-kernel"),
            "the refusal must name the unknown label, got: {msg}"
        );
        for entry in &registry {
            assert!(
                msg.contains(entry.label.as_str()),
                "the refusal must name the registered label `{}`, got: {msg}",
                entry.label
            );
        }
        // The shared composer, with the RIGHT ARGUMENTS. Since §18 delta 6c the wording lives in
        // one `pub fn` (`vmcell::artifact::registry::unknown_label_error`), so this is no longer a
        // parity check between two `format!`s — it now pins what this selector HANDS that composer:
        // the operator's noun (`kernel`), the pins namespace it lives under (`kernels`, which is a
        // different string), and the full registered roster rather than the filtered selection.
        // RED on the inverse (swap the two strings, or pass `&[]` as the roster).
        assert_eq!(
            msg,
            unknown_label_error(
                "kernel",
                "kernels",
                "not-a-kernel",
                &registry
                    .iter()
                    .map(|e| e.label.as_str())
                    .collect::<Vec<_>>(),
            )
            .to_string(),
            "the kernel selector must route through the one unknown-label composer"
        );
        // Positive control: one registered label from the same registry still selects.
        assert!(
            select_kernel_labels(&registry, &[registry[0].label.clone()], false).is_ok(),
            "a registered label must still select"
        );
    }

    // The cross-crate half of the one-composer rule. `vmcell build-kernels <label>` and the
    // library's `build_labelled_kernel(label, …)` are the two documented routes to the same build
    // (§5.6/§10.4), so an unknown label must produce the SAME sentence from both — a consumer who
    // reads one message and gets the other has learned nothing about which route it came from.
    //
    // Until §18 delta 6c the two sides were two `format!`s and this was a WORDING check. They are
    // now one `pub fn` (`vmcell::artifact::registry::unknown_label_error`), so a reword is a single
    // edit that moves both — which is the fix, not a reason to delete the gate. What it pins now is
    // the half the shared composer cannot enforce: that both routes hand it the same ARGUMENTS.
    // Each side chooses its own `kind`, `namespace` and roster, and each side resolves the registry
    // separately — the library from `overlay_file`, the CLI from `pins_overlay_or_env` — so a
    // divergence in either is still invisible to the compiler and still lands two different
    // sentences on the operator.
    //
    // RED on the inverse (verified): change the library's `kind` argument from `"kernel"` to
    // `"kernels"` — the equality fails and prints both sentences.
    #[tokio::test]
    async fn the_unknown_kernel_label_refusal_matches_the_library_entry_point() {
        // The same overlay resolution both routes use, so an ambient `$VMCELL_PINS` cannot make the
        // two sides read different rosters and turn this into a message-shape coincidence.
        let overlay = vmcell::artifact::pins_overlay_or_env(None);
        let registry = vmcell::artifact::resolve_kernel_registry(overlay.as_deref())
            .expect("the kernels registry resolves");
        let from_cli = select_kernel_labels(&registry, &["not-a-kernel".to_string()], false)
            .expect_err("the CLI selector refuses an unregistered label")
            .to_string();
        // The target dir is deliberately unwritable: the registry pre-flight runs BEFORE any I/O,
        // which is the property that makes the two messages comparable at all.
        let from_library = vmcell::artifact::build_labelled_kernel(
            "not-a-kernel",
            std::path::Path::new("/nonexistent/vmcell-must-not-touch-this"),
            overlay.as_deref(),
        )
        .await
        .expect_err("the library entry point refuses it too")
        .to_string();
        assert_eq!(
            from_cli, from_library,
            "the CLI and the library must refuse an unknown kernel label identically"
        );
    }

    // The CLI's argument surface really parses the two forms — a gate on the predicate alone would
    // stay green if the positional/flag pair were never wired (the "green test beside an unchanged
    // call site" shape). RED on the inverse (dropping `labels` or `all` from the variant): this
    // does not compile, which is the strongest form of the gate.
    #[test]
    fn build_kernels_parses_both_selection_forms() {
        use clap::Parser;
        let named = Cli::try_parse_from(["vmcell", "build-kernels", "6.12.94", "usbhost"])
            .expect("positional labels must parse");
        match named.command {
            Commands::BuildKernels { labels, all, .. } => {
                assert_eq!(labels, vec!["6.12.94".to_string(), "usbhost".to_string()]);
                assert!(!all);
            }
            other => panic!(
                "expected BuildKernels, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
        let every =
            Cli::try_parse_from(["vmcell", "build-kernels", "--all"]).expect("`--all` must parse");
        match every.command {
            Commands::BuildKernels { labels, all, .. } => {
                assert!(labels.is_empty());
                assert!(all);
            }
            other => panic!(
                "expected BuildKernels, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
        // Neither form is a PARSE success and a typed refusal at construction — never clap's
        // exit-2 usage error, which no `vmcell::Error` consumer can match on.
        let bare = Cli::try_parse_from(["vmcell", "build-kernels"]).expect("a bare verb parses");
        match bare.command {
            Commands::BuildKernels { labels, all, .. } => {
                assert!(labels.is_empty() && !all);
            }
            other => panic!(
                "expected BuildKernels, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
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

    // §7.4 + N-BIN-4 (§18 delta 6c): `vmcell bundle`'s candidate roster carries every labelled
    // rootfs AND each one's feature-declaration sidecar.
    //
    // The sidecar half is the one with teeth. A bundled rootfs that arrives at a consumer WITHOUT
    // its `.features` file is indistinguishable, to `FeatureDeclaration::load_beside`, from an
    // artifact that never declared anything — so the consumer's cell silently re-claims every
    // capability the declaration existed to withdraw (today: that vmcell's packer strips xattrs).
    // A missing kernel is a build error; a missing declaration is a lie the consumer cannot detect,
    // which is why the declaration producer landing without this candidate was a hole rather than a
    // gap.
    //
    // Asserted on `bundle_candidates` — a pure function of the directory — rather than through a
    // written manifest: the roster was inline in the walk when the hole opened, and a list buried
    // inside `dispatch` is exactly what ships ungated.
    //
    // RED on the inverse, either half: drop the default `features_artifact_key` candidate (the
    // `rootfs-features` expectation fails), or drop the labelled one from the walk arm
    // (`rootfs-acme-features` fails). The last claim is the guard against the opposite error — a
    // sidecar mistaken FOR a rootfs, which would put a `.features` file in the manifest under an
    // image's name.
    #[test]
    fn bundle_carries_every_labelled_rootfs_and_its_declaration_sidecar() {
        use vmcell::artifact::rootfs::{
            features_artifact_key, rootfs_artifact_key, rootfs_filename,
        };
        use vmcell::feature::feature_manifest_path;

        let dir = tempfile::tempdir().expect("tempdir");
        // A dir as `vmcell build --rootfs-label acme` leaves it: two images, two declarations, and
        // a cache sidecar beside them (the near-miss that must not read as an artifact).
        for label in [None, Some("acme")] {
            let image = dir.path().join(rootfs_filename(label));
            std::fs::write(&image, b"erofs").expect("write image");
            std::fs::write(feature_manifest_path(&image), b"xattr_preserved = false\n")
                .expect("write declaration");
        }
        std::fs::write(dir.path().join("rootfs-acme.cache_key"), b"k").expect("write sidecar");

        let candidates = bundle_candidates(dir.path());
        let named = |name: &str| -> Option<PathBuf> {
            candidates
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, p)| p.clone())
        };
        // Both kinds of entry, both labels, each name composed through the library's own laws.
        for label in [None, Some("acme")] {
            let key = rootfs_artifact_key(label);
            let image = dir.path().join(rootfs_filename(label));
            assert_eq!(
                named(&key),
                Some(image.clone()),
                "the manifest must cover the rootfs `{key}`: {candidates:?}"
            );
            let sidecar_key = features_artifact_key(&key);
            assert_eq!(
                named(&sidecar_key),
                Some(feature_manifest_path(&image)),
                "the manifest must cover `{sidecar_key}` — a rootfs bundled without its §7.4 \
                 declaration reads to the consumer as one that never declared anything, and the \
                 cell re-claims what the declaration withdrew: {candidates:?}"
            );
        }
        // Every candidate is present on disk here, so the roster is non-vacuous rather than a list
        // of names that happen to be spelled right.
        for (name, path) in &candidates {
            if name.starts_with("rootfs") {
                assert!(
                    path.exists(),
                    "`{name}` points at {path:?}, which is not there"
                );
            }
        }
        // A `.features` sidecar is never itself bundled AS a rootfs, and neither is the
        // `.cache_key`: the walk keys on the `.erofs` filename law, whose inverse returns `None`
        // for both. The check runs over the whole roster rather than over one expected name, so a
        // future producer's sidecar cannot slip in either.
        for (name, path) in &candidates {
            let is_declaration = path.extension().is_some_and(|e| e == "features");
            assert_eq!(
                is_declaration,
                name.ends_with("-features"),
                "`{name}` -> {path:?}: a declaration sidecar belongs under a `-features` key and \
                 nothing else may claim one"
            );
            assert!(
                !path.to_string_lossy().ends_with(".cache_key"),
                "a stage's cache sidecar is not an artifact: `{name}` -> {path:?}"
            );
        }
    }

    // §10.5's F7, last clause, AT ITS CALL SITE: `vmcell bundle` refuses an artifacts dir whose
    // resolved pins name an unpinned registration, and refuses it BEFORE writing the manifest.
    //
    // Driven through `bundle_artifacts` rather than through the library predicate alone, because
    // the predicate being green beside a call site that never calls it is the exact shape AGENTS.md
    // names ("a gate binds the call sites, not just the extracted predicate"). The two placement
    // claims are what only this level can see: the refusal fires on a dir that has real artifacts
    // to bundle, and `manifest.json` does not exist afterwards.
    //
    // `bundle` deliberately gains NO `--pins` flag — a bundle of a previously-built dir judged
    // against today's overlay is the wrong fact — so the fixture states the provenance the only
    // honest way it can: the `resolved_pins.json` the pipeline published into that dir.
    //
    // RED on the inverse, two ways: (a) drop the `reject_unpinned_registrations` call from
    // `bundle_artifacts` — the refusal leg's `expect_err` fails; (b) move the call AFTER
    // `manifest.write_to` — the "no manifest was written" assertion fails while the error still
    // arrives, which is the half a message-only assertion would miss.
    #[test]
    fn bundle_refuses_an_artifacts_dir_whose_resolved_pins_are_unpinned() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A dir with real artifacts, so the refusal is about provenance and not about emptiness
        // (`bundle` has its own "no artifacts found" error, and a fixture that tripped it would
        // make this test pass for the wrong reason).
        std::fs::write(dir.path().join("vmlinux"), b"kernel-bytes").expect("write");
        std::fs::write(dir.path().join("rootfs.erofs"), b"erofs-bytes").expect("write");
        let pins = dir.path().join("resolved_pins.json");
        let manifest = dir.path().join("manifest.json");

        std::fs::write(
            &pins,
            r#"{"rootfs": {"acme": {"unpinned_path": "/tmp/dev.erofs"}}}"#,
        )
        .expect("write resolved pins");
        let err = bundle_artifacts(dir.path(), None)
            .expect_err("an unpinned registration must be refused by bundle");
        let msg = err.to_string();
        assert!(
            msg.contains("rootfs_acme_unpinned_path"),
            "the refusal must name the unpinned entry: {msg}"
        );
        assert!(
            !manifest.exists(),
            "the refusal must come BEFORE the manifest is written — a manifest on disk is a \
             durable provenance claim, and complaining afterwards leaves the claim behind"
        );

        // THE POSITIVE CONTROL: the same fixture with the unpinned pin removed bundles, and writes
        // the manifest. Without it the refusal leg would also pass against a `bundle` that refused
        // every artifacts dir it was handed.
        std::fs::write(
            &pins,
            format!(
                r#"{{"rootfs": {{"acme": {{"image": "i", "digest": "sha256:{}"}}}}}}"#,
                "a".repeat(64)
            ),
        )
        .expect("rewrite resolved pins");
        bundle_artifacts(dir.path(), None)
            .expect("a digest-pinned artifacts dir must still bundle");
        assert!(
            manifest.exists(),
            "the positive control must actually produce a manifest"
        );
    }
}
