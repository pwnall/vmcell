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

/// The Debian release suite the `mmdebstrap` rootfs source bootstraps when `--release` is omitted.
///
/// A const rather than a clap `default_value` because the flag has to stay **distinguishable from
/// its default**: the `oci` source cannot honor a release suite, and refusing a flag the operator
/// typed (F1) is impossible once clap has filled the same value in for everyone. Applied at the one
/// arm that consumes it ([`rootfs_stage`]), so the omitted spelling and `--release trixie` build the
/// identical stage.
const DEFAULT_RELEASE: &str = "trixie";

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
        /// Debian release suite for the `mmdebstrap` rootfs source; omitted uses vmcell's pinned
        /// default suite. Naming it against the `oci` source — which pulls a digest-pinned image and
        /// bootstraps no suite of its own — is a typed refusal, not an ignored flag (F1).
        //
        // `Option` with no clap `default_value`, and the default applied at `rootfs_stage` (the one
        // arm that consumes it), so that refusal can tell a value the operator typed from one clap
        // filled in for everybody. `DEFAULT_RELEASE`'s rustdoc carries the rest — kept out of the
        // doc comment because clap prints it as `--help` text.
        #[arg(long)]
        release: Option<String>,
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
        /// Inject this prebuilt `vmcell-guest-tools` binary instead of building one from a vmcell
        /// checkout (§4.2, v33 delta 7) — `--steward-musl`'s missing mirror, and what makes a
        /// repack runnable from **outside** a checkout. Its CONTENT hash is what the cache keys
        /// on, never this path, so re-staging the same binary under a fresh directory is a cache
        /// hit. Without it, and with no vmcell sources above the working directory, the build
        /// refuses naming `vmcell-guest-tools` rather than packing an image with no applets.
        /// A durable alternative is a digest-pinned `handlers` registration (§10.5); this flag is
        /// the per-run override shape, so an image packed with it carries no provenance for the
        /// binary it baked.
        #[arg(long)]
        tools: Option<PathBuf>,
        /// Parent directory for this invocation's staging tree (§4.2, v33 delta 7). Defaults to
        /// the artifacts dir (`$VMCELL_ARTIFACTS_DIR`, else `<workspace>/target/vmcell-artifacts`),
        /// which downstream lands under the caller's own `target/`. vmcell creates — and, at the
        /// end, deletes — a per-invocation `oci2erofs-stage-<pid>` directory **inside** it, and
        /// never touches the directory named here, so pointing this at a populated tree is safe.
        /// The pulled-layer blob cache is not moved by this flag: it is a shared accelerator sited
        /// on the artifacts dir, and `$VMCELL_ARTIFACTS_DIR` is its knob.
        #[arg(long)]
        work_dir: Option<PathBuf>,
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

/// Refuses a `vmcell build` input the **selected rootfs source** cannot honor (F1): a `rootfs`
/// registry selector against the `mmdebstrap` source, or a release suite against the `oci` one.
///
/// One table rather than a check per flag, because the two halves are one law read from both sides —
/// each source honors exactly one of these inputs, and every accepted input is honored or rejected
/// at construction:
///
/// * `--rootfs-label` selects a `rootfs` registry entry (§10.5), which the `mmdebstrap` source does
///   not read at all: it builds from `--release`. Keyed on the RAW flag, deliberately —
///   [`build_stages`] normalizes the reserved `default` label to `None`, but that normalization is
///   about which pins keys a REGISTRY request flattens to, and letting the normalized form through
///   would make `--rootfs-label default --rootfs-source mmdebstrap` the one spelling that is
///   silently ignored instead of refused.
/// * `--release` names a Debian suite for `mmdebstrap` to bootstrap, which the `oci` source does not
///   read: it pulls the digest-pinned image its registry entry names. It was accepted and dropped,
///   with "(ignored for `oci`)" written in the flag's own help — the accept-then-ignore shape
///   documented instead of fixed.
///
/// Both refusals name the route that works, so the operator's next command is runnable.
///
/// # Errors
/// [`vmcell::Error::Artifact`] naming the flag, the source that cannot honor it, and the fix.
fn reject_unhonorable_rootfs_source_inputs(
    source: RootfsSourceKind,
    rootfs_label: Option<&str>,
    release: Option<&str>,
) -> vmcell::Result<()> {
    match source {
        RootfsSourceKind::Mmdebstrap => {
            if rootfs_label.is_some() {
                return Err(vmcell::Error::Artifact(
                    "--rootfs-label selects a `rootfs` registry entry (§10.5), which the \
                     `mmdebstrap` source does not read: it builds from --release. Use \
                     --rootfs-source oci, or drop --rootfs-label."
                        .into(),
                ));
            }
        }
        RootfsSourceKind::Oci => {
            if let Some(release) = release {
                return Err(vmcell::Error::Artifact(format!(
                    "--release {release} names a Debian suite for the `mmdebstrap` source to \
                     bootstrap (§4.3), which the `oci` source does not read: it pulls the \
                     digest-pinned image its `rootfs` registry entry names, userland already \
                     built. Use --rootfs-source mmdebstrap, or drop --release."
                )));
            }
        }
    }
    Ok(())
}

/// Refuses a `handlers` registration the `mmdebstrap` source cannot bake (F1, §10.5).
///
/// That source's stage carries no handler field at all: its pack tail is handed
/// `PackOptions::new()`, which bakes the binary under the **default** artifact key with the
/// **default** applet roster. So a labelled handler — published as `guest_tools-<label>`, a key that
/// tail never looks up — and an entry declaring its own `applets` are both selections it would
/// accept and drop: silently for the roster (the image gets the default symlinks), and as a
/// missing-artifact failure stages later for the label, which is remedial advice the operator cannot
/// act on (M3's shape, one flag over).
///
/// Keyed on the RESOLVED entry rather than on the flag, and that is the difference from the
/// `--rootfs-label` half of [`reject_unhonorable_rootfs_source_inputs`]: `--handler-label default`
/// IS honorable — it names the very handler this source bakes — so refusing the flag's presence
/// would refuse the default request spelled out. `applets` is read off the entry rather than
/// compared against a roster spelled here: an entry that declares none MEANS the default handler's
/// roster ([`vmcell::artifact::handler::HandlerRegistryEntry::applet_roster`]), which is exactly
/// what the tail bakes.
///
/// The `applets` clause is **unreachable by construction today**, and written as a refusal for the
/// reason the handler parser's own two-shape arm is: the overlay merge is leaf-wise, so the
/// baseline's `build: workspace:…` leaf on the default label survives every overlay, and the parser
/// refuses `applets` beside a workspace build. The day the baseline registers a digest-shaped default
/// handler that clause becomes live, and it must fail loud then rather than drop the roster —
/// `the_baseline_default_handler_declares_no_roster_of_its_own` is what says so from the other side.
///
/// # Errors
/// [`vmcell::Error::Artifact`] naming the entry, what about it cannot be baked, and the fix.
fn reject_unbakeable_handler_for_mmdebstrap(
    source: RootfsSourceKind,
    handler: Option<&vmcell::artifact::handler::HandlerRegistryEntry>,
) -> vmcell::Result<()> {
    if !matches!(source, RootfsSourceKind::Mmdebstrap) {
        return Ok(());
    }
    let Some(entry) = handler else {
        // No `handlers` namespace at all is the pre-v33 workspace build, which this source has
        // always produced.
        return Ok(());
    };
    let (unbakeable, fix) = if entry.label != vmcell::artifact::registry::DEFAULT_LABEL {
        (
            "is not the `default` handler",
            "use --rootfs-source oci, or drop --handler-label",
        )
    } else if !entry.applets.is_empty() {
        (
            "declares its own `applets` roster",
            "use --rootfs-source oci, or drop the entry's `applets` key",
        )
    } else {
        return Ok(());
    };
    Err(vmcell::Error::Artifact(format!(
        "the `handlers.{}` entry {unbakeable}, and the `mmdebstrap` source bakes the default \
         handler with the default applet roster — it carries no field for either, so the selection \
         would be accepted and dropped (§10.5): {fix}.",
        entry.label
    )))
}

/// Refuses a `rootfs` registration whose **packing** declarations the `mmdebstrap` source cannot
/// honor (F1, §4.7, §10.5).
///
/// The same shape as [`reject_unbakeable_handler_for_mmdebstrap`], on the other registry: that
/// source's stage packs through the erofs door with a hardcoded [`vmcell::artifact::XattrPolicy`]
/// `Strip` and carries no format field at all, so a declared `xattrs: preserve` would be dropped
/// silently — the packer strips, the image ships, and the entry's own derived
/// `xattr_preserved: true` declaration (§4.7's one derivation) then travels beside bytes that
/// contradict it — and a declared `format: ext4` would produce a `rootfs.erofs` under an entry that
/// says otherwise.
///
/// Keyed on the RESOLVED entry, and that is what makes it reachable at all: `--rootfs-label` is
/// refused against this source, so the label is always `None` — but `None` resolves the **default**
/// entry, and the default entry is precisely the one describing the artifact this source writes
/// (`rootfs.erofs`). Both clauses are inert against the committed baseline, whose default entry
/// declares neither key; an overlay that declares either is what they exist for.
///
/// The comparison is against each type's own `default()` rather than a named variant, so the
/// refusal tracks the packer's actual behavior: the day this source honors a policy, the honoring —
/// not this predicate — is what changes.
///
/// # Errors
/// [`vmcell::Error::Artifact`] naming the entry, the declaration that cannot be produced, and the
/// source that can.
fn reject_unproducible_rootfs_entry_for_mmdebstrap(
    source: RootfsSourceKind,
    entry: Option<&vmcell::artifact::RootfsRegistryEntry>,
) -> vmcell::Result<()> {
    if !matches!(source, RootfsSourceKind::Mmdebstrap) {
        return Ok(());
    }
    let Some(entry) = entry else {
        // No `rootfs` namespace at all: nothing declared, nothing to honor.
        return Ok(());
    };
    let unproducible = if entry.xattrs != vmcell::artifact::XattrPolicy::default() {
        format!(
            "declares `xattrs: {}`, and this source packs with `{}`",
            entry.xattrs.name(),
            vmcell::artifact::XattrPolicy::default().name()
        )
    } else if entry.format != vmcell::artifact::RootfsFormat::default() {
        format!(
            "declares `format: {}`, and this source packs `{}`",
            entry.format.name(),
            vmcell::artifact::RootfsFormat::default().name()
        )
    } else {
        return Ok(());
    };
    Err(vmcell::Error::Artifact(format!(
        "the `rootfs.{}` entry {unproducible} — it carries no field for that declaration, so it \
         would be accepted and dropped (§4.7): use --rootfs-source oci, which honors it, or drop \
         the key.",
        entry.label
    )))
}

/// Assembles the `vmcell build` pipeline's stages in run order: resolved pins, the selected kernel
/// producer, the steward and tools, and the selected rootfs producer (§5.4, The guest-kernel contract and the bootstrap seed; §4.3, The rootfs-construction contract).
///
/// Separate from [`dispatch`] so the wiring — including the refusals above — is assertable without
/// running a build that downloads and compiles for hours.
///
/// # Errors
/// As [`reject_seed_needing_source_for_build`] (a producer `build` cannot seed),
/// [`reject_unhonorable_rootfs_source_inputs`], [`reject_unbakeable_handler_for_mmdebstrap`],
/// [`reject_unproducible_rootfs_entry_for_mmdebstrap`] and [`kernel_stage`].
fn build_stages(
    kernel_source: KernelSource,
    rootfs_source: RootfsSourceKind,
    release: Option<&str>,
    rootfs_label: Option<&str>,
    handler_label: Option<&str>,
    pins: Option<&std::path::Path>,
    cid_alloc: std::sync::Arc<vmcell::vmm::CidAllocator>,
) -> vmcell::Result<Vec<Box<dyn vmcell::artifact::Stage>>> {
    reject_seed_needing_source_for_build(kernel_source)?;
    // The flag-vs-source table, on the RAW labels — before the normalization below, and before any
    // registry is resolved, so a flag this source cannot honor costs an error message rather than a
    // pins read that reports a different problem.
    reject_unhonorable_rootfs_source_inputs(rootfs_source, rootfs_label, release)?;
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
    // The same law on `--handler-label`, for the same reason and with the same defect behind it:
    // `--handler-label default` composed `guest_tools-default` — a stage name, artifact key, output
    // file and cache key the omitted spelling does not use — so the rootfs stage looked for the
    // handler the operator named and the handler stage had published a differently-keyed one. The
    // two stages below and the entry resolution above must be handed ONE spelling; the two stage
    // constructors normalize as well, so no other caller can compose the split artifact either.
    let handler_label = handler_label.and_then(vmcell::artifact::registry::registry_label);
    let rootfs_entry = resolve_rootfs_entry(rootfs_label, pins)?;
    let handler = resolve_handler_entry(handler_label, pins)?;
    // The entry half of the same law, from the ONE resolution above rather than a second one: what
    // the `mmdebstrap` arm below cannot bake is a property of the registration, not of the flag.
    reject_unbakeable_handler_for_mmdebstrap(rootfs_source, handler.as_ref())?;
    // …and the same reading on the `rootfs` entry's own packing declarations (§4.7): that arm has no
    // field for `xattrs` or `format`, and the DEFAULT entry describes the very artifact it writes.
    reject_unproducible_rootfs_entry_for_mmdebstrap(rootfs_source, rootfs_entry.as_ref())?;
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
            rootfs_entry.as_ref(),
            handler_label,
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

/// The `resolved_pins.json` an artifacts dir carries — the document the pipeline published **into
/// that dir**, and therefore the record of what the artifacts beside it were built from.
///
/// Composed through the stage that writes it rather than spelled a second time here, so the reader
/// and the writer of that filename cannot drift.
fn recorded_pins_path(dir: &std::path::Path) -> PathBuf {
    use vmcell::artifact::Stage as _;
    vmcell::artifact::ResolvePinsStage::default().out_path(dir)
}

/// The registrations an artifacts dir recorded — what `vmcell bundle` reads to learn how a label is
/// **spelled** and, for a rootfs, **which format is the current one**.
///
/// The dir's own [`recorded_pins_path`] is the source, for the same reason `bundle` deliberately
/// gains no `--pins`: a dir judged against today's overlay is the wrong fact, while the document
/// stage 0 of the build that filled it published is exactly right. Read back through the library's
/// own registry resolvers with that document as the overlay — the merge is leaf-wise over the
/// committed baseline, and the recorded document is that baseline plus whatever the build's overlay
/// added, so re-resolving it yields the build's own registry rather than a second parser's idea of
/// it.
///
/// An absent record is not an error: a dir no pipeline has filled has nothing to record, and both
/// rosters stay empty so every candidate falls back to what the filenames say.
#[derive(Default)]
struct RecordedRegistrations {
    /// The `kernels` registry the recorded pins resolve to.
    kernels: Vec<vmcell::artifact::KernelRegistryEntry>,
    /// The `rootfs` registry the recorded pins resolve to.
    rootfs: Vec<vmcell::artifact::RootfsRegistryEntry>,
}

impl RecordedRegistrations {
    /// Reads what `dir`'s own resolved pins recorded.
    ///
    /// # Errors
    /// [`vmcell::Error::Artifact`] when the recorded document is malformed, holds a retired pins
    /// shape, or registers two labels that collide on one artifact — the same refusals every other
    /// reader of those registries raises. A manifest composed against a document vmcell cannot parse
    /// would name artifacts by keys nobody can resolve, which is the one thing this walk's names
    /// exist to prevent.
    fn read_from(dir: &std::path::Path) -> vmcell::Result<Self> {
        let recorded = recorded_pins_path(dir);
        if !recorded.exists() {
            return Ok(Self::default());
        }
        Ok(Self {
            kernels: vmcell::artifact::resolve_kernel_registry(Some(&recorded))?,
            rootfs: vmcell::artifact::resolve_rootfs_registry(Some(&recorded))?,
        })
    }

    /// The **registered** spelling of a kernel label read off a `vmlinux-<label>` filename.
    ///
    /// The filename law sanitizes `.`→`-` while the artifact key keeps the dots, so
    /// `kernels.6.12.94` builds `vmlinux-6-12-94` and the filename alone cannot say which of
    /// `6.12.94` and `6-12-94` was registered. `bundle` composed the on-disk spelling, so the
    /// manifest recorded `kernel-6-12-94` — a name no producer registers, and therefore one no
    /// consumer can look up, which is exactly what [`bundle_candidates`]'s own rules forbid.
    ///
    /// Matched by composing each registered label THROUGH the producers' filename law and its
    /// inverse, never by re-spelling the sanitization here. An unregistered label (a kernel built
    /// from pins that no longer name it) keeps its on-disk spelling: that is all that is known about
    /// it, and dropping it from the manifest would be the N-BIN-4 omission.
    fn kernel_label<'a>(&'a self, on_disk: &'a str) -> &'a str {
        self.kernels
            .iter()
            .find(|e| {
                vmcell::artifact::kernel::kernel_label_from_filename(
                    &vmcell::artifact::kernel::kernel_filename(Some(&e.label)),
                ) == Some(on_disk)
            })
            .map_or(on_disk, |e| e.label.as_str())
    }

    /// The `rootfs` registration whose on-disk artifact **stem** is `stem`.
    ///
    /// The stem rather than the filename because that is the registry's own collision key (§18
    /// delta 8): both formats of one label share it, which is precisely why a registration — and not
    /// a directory listing — is what says which of the two images is current.
    fn rootfs_by_stem(&self, stem: &str) -> Option<&vmcell::artifact::RootfsRegistryEntry> {
        self.rootfs.iter().find(|e| {
            vmcell::artifact::rootfs::rootfs_artifact_stem(
                vmcell::artifact::registry::registry_label(&e.label),
            ) == stem
        })
    }
}

/// The rootfs image present in `dir` for `label` — `bundle`'s fallback for an artifact whose
/// registration the dir does not record.
///
/// In `RootfsFormat::ALL` order rather than `read_dir` order, so an unrecorded label whose two
/// formats are both on disk pins the same one on every run. Erofs when neither is present, so an
/// empty dir still names the artifact it is missing rather than naming nothing.
fn present_rootfs_image(dir: &std::path::Path, label: Option<&str>) -> PathBuf {
    use vmcell::artifact::RootfsFormat;
    use vmcell::artifact::rootfs::rootfs_filename;
    RootfsFormat::ALL
        .into_iter()
        .map(|f| dir.join(rootfs_filename(label, f)))
        .find(|p| p.exists())
        .unwrap_or_else(|| dir.join(rootfs_filename(label, RootfsFormat::Erofs)))
}

/// Every `(artifact key, image path)` the **rootfs** half of `vmcell bundle` pins for `dir`: the
/// default artifact, plus one candidate per labelled image the dir holds, each resolved against the
/// registrations that dir recorded.
///
/// Two questions only the registrations can answer, and both were answered wrong from the filenames
/// alone:
///
/// * **Which format is current.** A label's two formats share one stem (§18 delta 8), so an entry
///   re-registered from `erofs` to `ext4` leaves the old image sitting beside the new one. The
///   `RootfsFormat::ALL`-first scan then pinned the STALE erofs for the default artifact, and — worse
///   — named BOTH files for a labelled one, so the manifest carried two digests under `rootfs-<label>`
///   and a consumer resolved whichever `read_dir` happened to yield first. The declaration wins:
///   `resolved_pins.json` is written by stage 0 of the very build that packed these images, so the
///   format it names is the format that build wrote.
/// * **How the label is spelled** — see [`RecordedRegistrations::kernel_label`], one kind over.
///
/// Discovery still comes from the DIRECTORY rather than from the roster: naming every registered
/// label would report a skipped artifact for every label the operator has not built, and a skip
/// notice that always fires is one nobody reads. A registered label whose declared format is absent
/// while its other format is present IS named, and so reported skipped — that artifact is stale, and
/// saying so is the point.
fn rootfs_bundle_candidates(
    dir: &std::path::Path,
    recorded: &RecordedRegistrations,
) -> Vec<(String, PathBuf)> {
    use vmcell::artifact::registry::registry_label;
    use vmcell::artifact::rootfs::{
        rootfs_artifact_from_filename, rootfs_artifact_key, rootfs_artifact_stem, rootfs_filename,
    };

    // One candidate per artifact, composed through the key/filename laws from the recorded
    // registration when there is one. The DEFAULT artifact is always a candidate: the walk below
    // keys on a `-<label>` filename and so cannot see it at all, which is the N-BIN-4 hole one
    // format over.
    let declared = |label: Option<&str>| -> Option<(String, PathBuf)> {
        let entry = recorded.rootfs_by_stem(&rootfs_artifact_stem(label))?;
        let label = registry_label(&entry.label);
        Some((
            rootfs_artifact_key(label),
            dir.join(rootfs_filename(label, entry.format)),
        ))
    };
    let mut candidates: Vec<(String, PathBuf)> = vec![
        declared(None)
            .unwrap_or_else(|| (rootfs_artifact_key(None), present_rootfs_image(dir, None))),
    ];
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let fname = e.file_name();
            let name = fname.to_string_lossy();
            // The library's one label law (the inverse of the producers' filename composer), which
            // answers for `.ext4` as well as `.erofs` (§18 delta 8) and returns `None` for a
            // `.features` or `.cache_key` sidecar — the property that keeps a sidecar from being
            // bundled as a rootfs in its own right.
            let Some((on_disk, _format)) = rootfs_artifact_from_filename(&name) else {
                continue;
            };
            let candidate = declared(Some(on_disk)).unwrap_or_else(|| {
                // Unrecorded: the manifest can only say what the filename says. Composed through
                // `present_rootfs_image` rather than from this entry's own path so that both
                // formats of an unrecorded label resolve to the SAME candidate below.
                (
                    rootfs_artifact_key(Some(on_disk)),
                    present_rootfs_image(dir, Some(on_disk)),
                )
            });
            // Both of a label's formats resolve to that one candidate, so the second file must not
            // push a duplicate: two entries under one artifact key is the defect above.
            if !candidates.iter().any(|(key, _)| *key == candidate.0) {
                candidates.push(candidate);
            }
        }
    }
    candidates
}

/// Every `(manifest name, path)` `vmcell bundle` considers in `dir`, present or not — the whole
/// candidate roster, as a function of the directory's contents and the registrations it recorded.
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
/// Every name is composed through the library's own key laws, never spelled here, and a label's
/// spelling comes from its **registration** rather than from its sanitized filename: a manifest
/// entry under a name the producers do not register is a name no consumer can look up.
fn bundle_candidates(
    dir: &std::path::Path,
    recorded: &RecordedRegistrations,
) -> Vec<(String, PathBuf)> {
    use vmcell::artifact::rootfs::features_artifact_key;
    use vmcell::feature::feature_manifest_path;

    let mut candidates: Vec<(String, PathBuf)> = vec![
        ("kernel".to_string(), dir.join("vmlinux")),
        ("ca".to_string(), dir.join("ca.pem")),
        // The RESOLVED pins (baseline + any overlay), not the committed baseline: with an
        // overlay in play the repo file is not what the artifacts were built from, and the
        // baseline is embedded in the binary now anyway (§10.2). Absent until a pipeline
        // has run, which the skipped-artifact notice below reports.
        ("pins".to_string(), recorded_pins_path(dir)),
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
    // Every rootfs artifact, each with its §7.4 feature-declaration sidecar (§18 delta 6c) — the
    // rootfs's counterpart of the kernel-config candidate above, and it closes the same N-BIN-4 hole
    // for a strictly worse consequence: a bundled rootfs that arrives WITHOUT its declaration reads
    // to `FeatureDeclaration::load_beside` exactly like an un-annotated artifact, so the consumer's
    // cell silently re-claims every capability the declaration existed to withdraw (today, that
    // vmcell's packer strips xattrs). A missing kernel config is a gap; a missing declaration is a
    // lie the consumer cannot detect. The sidecar is derived from the image's own path, so it
    // travels with whichever format the registration declared.
    for (key, image) in rootfs_bundle_candidates(dir, recorded) {
        candidates.push((features_artifact_key(&key), feature_manifest_path(&image)));
        candidates.push((key, image));
    }
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
                // under is a name no consumer can look up. The label is the REGISTERED
                // spelling, which the sanitized filename cannot supply.
                let key = vmcell::artifact::kernel::kernel_artifact_key(Some(
                    recorded.kernel_label(label),
                ));
                candidates.push((
                    vmcell::artifact::kernel::config_artifact_key(&key),
                    vmcell::artifact::kernel::resolved_config_path(&e.path()),
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
/// unpinned registration (§10.5, F7) or cannot be resolved into their registries, or when an
/// artifact cannot be hashed or the manifest written.
fn bundle_artifacts(dir: &std::path::Path, out: Option<&std::path::Path>) -> vmcell::Result<()> {
    // F7 (§10.5): an unpinned registration is REFUSED before a byte of manifest is written — a
    // manifest naming an artifact whose registration meant "whatever was at that path that day" is
    // a provenance claim vmcell cannot back, and writing it first and complaining afterwards would
    // leave that claim on disk. Read from the artifacts dir's own `resolved_pins.json`, so `bundle`
    // still needs no `--pins` (see `reject_unpinned_registrations`).
    //
    // FIRST, ahead of the roster below, because the roster is now composed from that same recorded
    // document: the refusal and the read must not be able to disagree about which document they
    // read, and the refusal must land before either.
    vmcell::artifact::bundle::reject_unpinned_registrations(&recorded_pins_path(dir))?;
    let recorded = RecordedRegistrations::read_from(dir)?;
    let candidates = bundle_candidates(dir, &recorded);
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
    release: Option<&str>,
    rootfs_label: Option<&str>,
    rootfs_entry: Option<&vmcell::artifact::RootfsRegistryEntry>,
    handler_label: Option<&str>,
    applets: Option<Vec<String>>,
    cid_alloc: std::sync::Arc<vmcell::vmm::CidAllocator>,
) -> Box<dyn vmcell::artifact::Stage> {
    match source {
        // `vmcell build` produces vmcell's own canonical rootfs and takes no `--inject`; the
        // downstream extra-file surface is `oci2erofs` (§10.4's documented consumer
        // invocation), so both arms compose nothing.
        RootfsSourceKind::Oci => Box::new(
            vmcell::artifact::rootfs::RootfsStage::labelled(rootfs_label)
                .with_applets(applets.unwrap_or_default())
                // …and WHICH handler those applet symlinks point at (§10.5, delta 6b): the roster
                // above and this label come from the one resolved `handlers` entry, and the pack
                // tail reads the binary from `handler_artifact_key(this)`. Passing the roster
                // without the label is how a labelled handler's binary reached no image at all.
                .with_handler_label(handler_label)
                // §4.7's per-artifact xattr policy (§18 delta 7), from the SAME resolved entry the
                // declaration stage beside it renders — so the bytes the packer produces and the
                // `xattr_preserved` stance the sidecar claims are derived from one declaration.
                // No entry (an artifacts dir built against pins with no `rootfs` registry) is the
                // default `Strip`, which is the pre-delta-7 packer exactly.
                .with_xattrs(
                    rootfs_entry.map_or_else(vmcell::artifact::XattrPolicy::default, |e| e.xattrs),
                )
                // §4.7's per-artifact filesystem format (§18 delta 8), from the SAME resolved entry
                // the xattr policy above comes from — so the file this stage writes, the identity
                // it claims, and the emitter the tail picks are one declaration. No entry is the
                // default `Erofs`, which is the pre-delta-8 producer exactly.
                .with_format(
                    rootfs_entry.map_or_else(vmcell::artifact::RootfsFormat::default, |e| e.format),
                ),
        ),
        // The mmdebstrap source builds from a release suite, not from a registered digest, so it
        // has neither a rootfs label nor a handler registration to honor — and the refusals at
        // the head of `build_stages` are what keep this arm from *dropping* them: an
        // accepted-and-ignored `--rootfs-label` would build the default userland and report
        // success, an ignored applet roster would bake the default symlinks under an entry
        // that asked for others, and an ignored `xattrs`/`format` on the DEFAULT entry — the entry
        // that describes the very `rootfs.erofs` this arm writes, reached even though the label is
        // always `None` here — would ship an image contradicting its own declaration (§4.7).
        // `rootfs_entry` is therefore deliberately unread in this arm rather than partly honored.
        //
        // `--release`'s default is applied HERE, at the one arm that consumes it, so the omitted
        // spelling and `--release trixie` compose the identical stage (and the same cache key)
        // while the `oci` arm above still sees an untouched `None` to refuse.
        RootfsSourceKind::Mmdebstrap => Box::new(vmcell_rootfs_builder::MmdebstrapRootfsStage {
            release: release.unwrap_or(DEFAULT_RELEASE).to_string(),
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
            // One CID allocator shared by any in-VM builder stage this pipeline runs.
            let cid_alloc = std::sync::Arc::new(vmcell::vmm::CidAllocator::new());
            // Assemble — and so honor or reject every flag, including the flag-vs-source table
            // (F1) — BEFORE announcing the build: a refused `--kernel-source` (M3) must not first
            // print "Building artifacts...". Every refusal lives in `build_stages` so it is
            // assertable without a build; this arm holds none of its own.
            let stages = build_stages(
                *kernel_source,
                *rootfs_source,
                release.as_deref(),
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
            tools,
            work_dir,
            pins,
        } => {
            oci2erofs(
                image,
                output,
                steward_musl.as_deref(),
                inject,
                tools.as_deref(),
                work_dir.as_deref(),
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
                relay_guest_output(&mut std::io::stdout(), &outcome.stdout);
                relay_guest_output(&mut std::io::stderr(), &outcome.stderr);
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

/// Resolves the `cloud-hypervisor` binary path through the library's **one** resolver
/// ([`vmcell::artifact::ch_binary_path`]: `$VMCELL_CH_BIN`, else `cloud-hypervisor` on `PATH`).
///
/// A one-line delegation for the reason [`pins_overlay`] is one. This was a byte-identical THIRD
/// copy of that resolver (A2), so a change to the law — a second env var, a fallback list, a
/// `PATH` probe — would have moved the library and every builder stage that reads it and left
/// `vmcell run`/`create`/`snapshot`/`stats` resolving the old way, which is the per-call-site drift
/// `ch_binary_path`'s own rustdoc exists to describe. Delegating is not a compile-checked fact, so
/// `the_cli_resolves_the_ch_binary_through_the_one_library_law` scans for it: this crate names the
/// env var nowhere and calls the one resolver in exactly one place.
fn ch_bin() -> String {
    vmcell::artifact::ch_binary_path()
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

/// Relays a chunk of the guest command's captured output to a host stream, best-effort.
///
/// WHY THE `Result` IS DISCARDED, once, instead of at six call sites (AGENTS.md "Fail loud" plus
/// its Suppressions rule): the only realistic failure is `EPIPE` — the consumer on the other side
/// of this CLI's stdout/stderr closed it, which is what `head`, a closed pager, or a killed
/// pipeline reader all look like. Aborting the run there would be wrong twice over: the guest
/// command has already run, and its exit code is what this CLI contracts to propagate
/// (`std::process::exit(code)` at the one-shot site, `Ok(code)` at the interactive one). A relay
/// failure must never become the guest's answer.
///
/// The flush is part of the same statement rather than a second discarded `Result`: stdout is line
/// buffered, and interactive output that arrives only at the next newline is not interactive.
fn relay_guest_output(out: &mut impl std::io::Write, data: &[u8]) {
    #[expect(
        clippy::let_underscore_must_use,
        reason = "EPIPE on the consumer side must not abort the run or mask the guest's exit code, which is this CLI's contract"
    )]
    let _ = out.write_all(data).and_then(|()| out.flush());
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
                    relay_guest_output(&mut std::io::stdout(), &data);
                }
                Some(SessionEvent::Stderr(data)) => {
                    relay_guest_output(&mut std::io::stderr(), &data);
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
                    if let Err(e) = session.close_stdin().await {
                        eprintln!("vmcell: stdin close was not delivered to the guest: {e}");
                    }
                    stdin_open = false;
                }
                Ok(n) => {
                    // `read` guarantees n <= buf.len(); `get(..n)` is the non-panicking form.
                    //
                    // A failed `write_stdin` means the session transport is gone. Discarding it
                    // (the pre-fix `let _ =`) kept this arm re-armed, so every subsequent keystroke
                    // was read off the local terminal and thrown away in silence until the output
                    // side happened to notice the same death. Stop forwarding and say so — the same
                    // handling as the local read error below, which is the same situation from the
                    // other end.
                    if let Err(e) = session.write_stdin(buf.get(..n).unwrap_or_default()).await {
                        eprintln!("vmcell: stdin is no longer reaching the guest: {e}");
                        stdin_open = false;
                    }
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

/// The handler stage `oci2-erofs` runs: `--tools`'s bytes when the flag is present, the pre-delta-7
/// workspace build when it is not (§4.2, v33 delta 7).
///
/// Extracted from the pipeline assembly so the threading is assertable without running a build —
/// the composition root is where a flag gets silently dropped, and a green unit test beside an
/// unchanged call site is exactly the invisible PARTIAL the delta register warns about.
///
/// `oci2-erofs` exposes no `--handler-label`, so there is no registry entry here for the override to
/// disagree with — and there could not be one anyway: the stage holds ONE source slot, which makes
/// "two sources for one artifact" unrepresentable rather than merely refused.
fn oci2erofs_tools_stage(
    tools: Option<&std::path::Path>,
) -> vmcell::artifact::guest_tools::GuestToolsStage {
    match tools {
        Some(path) => vmcell::artifact::guest_tools::GuestToolsStage::labelled(
            None,
            Some(vmcell::artifact::handler::HandlerSource::Prebuilt {
                path: path.to_path_buf(),
            }),
        ),
        None => vmcell::artifact::guest_tools::GuestToolsStage::new(),
    }
}

/// Validates `--tools` (§4.2, v33 delta 7): the value must name a readable regular file.
///
/// Checked here rather than at the stage, so a typo costs an error message instead of a full OCI
/// pull followed by one — and so the flag is *honored or rejected at construction* rather than
/// accepted and discovered later (F1). A directory is called out separately because it is the
/// mistake this flag invites: `--tools target/release` instead of `target/release/vmcell-guest-tools`.
///
/// # Errors
/// [`vmcell::Error::Artifact`] naming the flag, the path, and what was found there.
fn validate_tools_binary(tools: Option<&std::path::Path>) -> vmcell::Result<Option<PathBuf>> {
    let Some(path) = tools else {
        return Ok(None);
    };
    let meta = std::fs::metadata(path).map_err(|e| {
        vmcell::Error::Artifact(format!(
            "`--tools {}` cannot be read: {e}. It must name a prebuilt `vmcell-guest-tools` \
             binary — the mirror of `--steward-musl` (§4.2)",
            path.display()
        ))
    })?;
    if !meta.is_file() {
        return Err(vmcell::Error::Artifact(format!(
            "`--tools {}` is not a regular file. It must name the prebuilt `vmcell-guest-tools` \
             BINARY itself, not the directory holding it (§4.2)",
            path.display()
        )));
    }
    Ok(Some(path.to_path_buf()))
}

/// Resolves `--work-dir` to the parent the per-invocation staging tree is composed under (§4.2,
/// v33 delta 7); `None` is the artifacts dir, which is the pre-delta-7 behavior exactly.
///
/// The directory is created if absent — a build flag that demands the operator `mkdir` first is a
/// flag they will script around — and a non-directory is a loud refusal rather than a confusing
/// failure three stages later.
///
/// # Errors
/// [`vmcell::Error::Artifact`] naming the flag and the path when it cannot be made a directory.
fn resolve_work_dir(work_dir: Option<&std::path::Path>) -> vmcell::Result<PathBuf> {
    let Some(dir) = work_dir else {
        return Ok(vmcell::artifact::artifacts_dir());
    };
    std::fs::create_dir_all(dir).map_err(|e| {
        vmcell::Error::Artifact(format!(
            "`--work-dir {}` cannot be used as a staging parent: {e}. It must name a directory \
             vmcell may create a per-invocation `oci2erofs-stage-<pid>` tree inside (§4.2)",
            dir.display()
        ))
    })?;
    Ok(dir.to_path_buf())
}

/// The per-invocation `oci2erofs-stage-<pid>` tree, owned — it is removed when this value drops, on
/// **every** path out of [`oci2erofs`].
///
/// Teardown is ownership (AGENTS.md), and this tree used to be swept by two hand-placed
/// `remove_dir_all` calls that between them covered the happy path and the copy's error path only:
/// a `pipeline.build(...)?` failure returned early and left the tree on disk. Harmless while the
/// parent was always the artifacts dir; an operator-visible accumulation in a directory they named
/// once `--work-dir` existed (§4.2, v33 delta 7).
///
/// **The leaf is composed here and nowhere else**, which is what keeps the rule "the only directory
/// vmcell may delete is one it composed itself" structural rather than remembered: this type cannot
/// be handed an operator's `--work-dir` to remove, only a `<parent>/oci2erofs-stage-<pid>` it
/// appended itself.
struct StagingTree {
    /// The composed leaf, and the only path this value will ever remove.
    path: PathBuf,
}

impl StagingTree {
    /// Composes (and creates) the per-invocation staging leaf under `parent`.
    ///
    /// Pre-cleans a leftover from a prior run killed hard enough to skip this type's `Drop` — the
    /// same pid can come round again, and a stale tree would be served to the new run's stages.
    ///
    /// # Errors
    /// [`vmcell::Error::Io`] if the leaf cannot be created; that is a refusal before any blob is
    /// pulled, not a failure discovered by a stage minutes later.
    fn compose_under(parent: &std::path::Path) -> vmcell::Result<Self> {
        let path = parent.join(format!("oci2erofs-stage-{}", std::process::id()));
        // Pre-clean of a stale tree from an aborted run of THIS pid. The expected outcome is
        // `NotFound`; anything else is caught immediately by the `create_dir_all` below, which is
        // fallible and reports.
        #[expect(
            clippy::let_underscore_must_use,
            reason = "pre-clean whose expected outcome is NotFound; the fallible create_dir_all below is the real check"
        )]
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).map_err(vmcell::Error::Io)?;
        Ok(StagingTree { path })
    }

    /// The staging leaf the pipeline builds into.
    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for StagingTree {
    fn drop(&mut self) {
        // Best-effort, and deliberately so: `Drop` cannot report, and a leftover scratch tree is
        // not worth aborting a run that otherwise succeeded. The gate is that it RUNS on every
        // path, which a `?` on the build call is what defeated.
        #[expect(
            clippy::let_underscore_must_use,
            reason = "Drop cannot report; a leftover scratch tree must not abort a run that otherwise succeeded"
        )]
        let _ = std::fs::remove_dir_all(&self.path);
    }
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
///
/// `tools` (`--tools`) and `work_dir` (`--work-dir`) are §4.2's two severances (v33 delta 7): the
/// first supplies a prebuilt `vmcell-guest-tools` so the pipeline needs no vmcell checkout, the
/// second names where the staging tree lands. **Both absent reproduces the pre-delta-7 behavior
/// exactly**, including the cache keys.
///
/// # Errors
/// [`vmcell::Error::Artifact`] when the image is not digest-pinned, when `--tools` does not name a
/// readable file, or when `--work-dir` cannot be used as a directory — all three before any
/// network work, so a mistyped argument costs no pull.
async fn oci2erofs(
    image_ref: &str,
    output: &std::path::Path,
    steward_musl: Option<&std::path::Path>,
    inject: &[vmcell::artifact::rootfs::ExtraFile],
    tools: Option<&std::path::Path>,
    work_dir: Option<&std::path::Path>,
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

    // Both flags are honored-or-rejected HERE, before the pipeline is assembled and therefore
    // before any blob is pulled: a mistyped `--tools` must cost an error message, not a download.
    let tools = validate_tools_binary(tools)?;
    let work_parent = resolve_work_dir(work_dir)?;

    // Build into a per-invocation staging dir, NOT the canonical `artifacts_dir` root
    // (M-BIN-6): the rootfs stage writes `<target_dir>/rootfs.erofs`, so building at
    // `artifacts_dir` would clobber the canonical `rootfs.erofs` that every test/bench
    // boots. The staging dir is a *distinct sibling* under `artifacts_dir` (same real
    // disk — not the system temp dir, which is often a size-limited tmpfs), so a large
    // rootfs has room. `--work-dir` renames that parent and nothing else (§4.2, v33 delta 7):
    // the per-pid leaf stays, because the leaf is DELETED when this scope ends and the only
    // directory vmcell may ever delete is one it composed itself. Copy only the final image out
    // to `--output`. Trade-off: the staging dir has no cache history, so the steward/tools/rootfs
    // stages rebuild.
    //
    // Owned by `StagingTree`, so the sweep covers the `?` below as well as the success path: two
    // hand-placed `remove_dir_all`s used to cover the happy path and the copy's error path, and a
    // failed `pipeline.build(...)` returned between them and left the tree behind.
    let stage = StagingTree::compose_under(&work_parent)?;
    let stage_dir = stage.path().to_path_buf();
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
        .add_stage(Box::new(oci2erofs_tools_stage(tools.as_deref())))
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
    // No cleanup call here: `stage` sweeps the tree when this scope ends, which is the same moment
    // on the copy's error path and on the success path — and, unlike the two calls this replaced,
    // also on the `?` above.
    std::fs::copy(&built, output).map_err(vmcell::Error::Io)?;
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
            None,
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
                let stages = build_stages(source, rootfs, None, None, None, None, alloc())
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

    // F1 AT THE ASSEMBLY (§4.3/§10.5): each rootfs source REFUSES exactly the input the other one
    // reads. `--release` was accepted and dropped by the `oci` source, with "(ignored for `oci`)"
    // written into the flag's own help — the accept-then-ignore shape documented instead of fixed —
    // and `--rootfs-label` is refused by `mmdebstrap` on the RAW spelling, so the reserved `default`
    // label is refused too rather than being the one spelling that is silently ignored.
    //
    // Driven through `build_stages`, not the predicate alone: this is a call-site rule (no flag may
    // outlive the assembly unhonored, and nothing is printed or downloaded before it), and a green
    // predicate beside an assembly that never calls it is the invisible PARTIAL AGENTS.md names.
    //
    // RED on the inverse, four ways: drop the `--release` arm (the oci leg assembles instead of
    // refusing); drop the `--rootfs-label` arm (the mmdebstrap leg assembles); key the label arm on
    // the NORMALIZED label (the `default` leg assembles); refuse `--release` on both sources (the
    // mmdebstrap positive control fails).
    #[test]
    fn build_refuses_the_input_the_selected_rootfs_source_cannot_honor() {
        use vmcell::artifact::registry::DEFAULT_LABEL;
        let assemble = |source, release, rootfs_label| {
            build_stages(
                KernelSource::Prebuilt,
                source,
                release,
                rootfs_label,
                None,
                None,
                std::sync::Arc::new(vmcell::vmm::CidAllocator::new()),
            )
            // Render the roster so a regression reports WHAT it assembled (`Box<dyn Stage>` is not
            // `Debug`).
            .map(|s| {
                s.iter()
                    .map(|st| st.name().to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            })
        };

        // `--release` against `oci`: refused, naming the flag, the value the operator typed, and the
        // route that reads it.
        let msg = assemble(RootfsSourceKind::Oci, Some("bookworm"), None)
            .expect_err("`--release` against the oci source must be refused, not dropped")
            .to_string();
        for named in ["--release bookworm", "--rootfs-source mmdebstrap"] {
            assert!(
                msg.contains(named),
                "the refusal must name `{named}`, got: {msg}"
            );
        }

        // `--rootfs-label` against `mmdebstrap`: refused for EVERY spelling, the reserved default
        // included — that one normalizes to `None` a line later, which is why the refusal reads the
        // raw flag.
        for label in ["acme", DEFAULT_LABEL] {
            let msg = assemble(RootfsSourceKind::Mmdebstrap, None, Some(label))
                .expect_err("`--rootfs-label` against the mmdebstrap source must be refused")
                .to_string();
            assert!(
                msg.contains("--rootfs-label") && msg.contains("--rootfs-source oci"),
                "the refusal must name the flag and the route, got: {msg}"
            );
        }

        // THE POSITIVE CONTROLS: each source still honors the input it does read, and both omitted
        // forms assemble. Without these the legs above would pass just as well against a `build`
        // that refused every combination it was handed.
        assemble(RootfsSourceKind::Mmdebstrap, Some("bookworm"), None)
            .expect("the mmdebstrap source reads --release");
        assemble(RootfsSourceKind::Oci, None, Some(DEFAULT_LABEL))
            .expect("the oci source reads --rootfs-label");
        assemble(RootfsSourceKind::Oci, None, None).expect("both flags omitted must assemble");
        assemble(RootfsSourceKind::Mmdebstrap, None, None)
            .expect("both flags omitted must assemble");

        // THE ARGUMENT SURFACE, which is what makes the refusal expressible at all: an omitted
        // `--release` must reach `build_stages` as `None`. Re-adding clap's `default_value` would
        // hand every invocation `Some("trixie")` and turn the refusal above into a refusal of every
        // `oci` build — a break the legs above cannot see, because they pass `None` in directly.
        // RED on the inverse (restore `default_value = "trixie"`, or make the field a `String`): the
        // first claim fails, or this does not compile.
        use clap::Parser as _;
        match Cli::try_parse_from(["vmcell", "build"])
            .expect("a bare `build` parses")
            .command
        {
            Commands::Build { release, .. } => assert_eq!(
                release, None,
                "an omitted `--release` must stay distinguishable from a value the operator typed"
            ),
            other => panic!("expected Build, got {:?}", std::mem::discriminant(&other)),
        }
        match Cli::try_parse_from(["vmcell", "build", "--release", "bookworm"])
            .expect("`--release` parses")
            .command
        {
            Commands::Build { release, .. } => assert_eq!(release.as_deref(), Some("bookworm")),
            other => panic!("expected Build, got {:?}", std::mem::discriminant(&other)),
        }
    }

    // The other half of `--release`'s F1 fix, and its migration promise: dropping clap's
    // `default_value` — so a value the operator typed is distinguishable from the one clap filled in
    // for everybody, which is what makes the refusal above possible at all — must not move the stage
    // the omitted spelling composes. [`DEFAULT_RELEASE`] is applied at the one arm that consumes it.
    //
    // The observable is `Stage::cache_key`, the only one a `dyn Stage` has and the honest one: the
    // key decides whether the warm artifacts dir is served, so a default that moved would silently
    // re-run an hours-long mmdebstrap build for every existing caller.
    //
    // RED on the inverse: change `DEFAULT_RELEASE` away from the literal clap's `default_value`
    // carried (the first claim fails), or make the mmdebstrap arm ignore `release` (the second
    // collapses, which is the vacuity guard on the first).
    #[test]
    fn the_omitted_release_composes_the_stage_claps_default_did() {
        let inputs = vmcell::artifact::StageInputs::default();
        let key = |release| {
            rootfs_stage(
                RootfsSourceKind::Mmdebstrap,
                release,
                None,
                None,
                None,
                None,
                std::sync::Arc::new(vmcell::vmm::CidAllocator::new()),
            )
            .cache_key(&inputs)
        };
        assert_eq!(
            key(None),
            key(Some("trixie")),
            "the omitted `--release` must compose the stage `default_value = \"trixie\"` composed"
        );
        assert_ne!(
            key(None),
            key(Some("bookworm")),
            "…and the suite must actually reach the stage (non-vacuity)"
        );
    }

    // F1 on the OTHER registry selector (§10.5), keyed on the RESOLVED entry rather than on the
    // flag: `--rootfs-source mmdebstrap` hands its pack tail `PackOptions::new()`, which bakes the
    // DEFAULT handler with the DEFAULT applet roster and carries no field for either. So the roster
    // `build_stages` resolves was accepted and dropped — silently for an entry that declares its own
    // (the image gets the default symlinks), and as a missing-`guest_tools` failure stages later for
    // a labelled one, which is remedial advice the operator cannot act on.
    //
    // RED on the inverse (delete the `reject_unbakeable_handler_for_mmdebstrap` call, or the
    // `applets` clause alone): the corresponding leg assembles and reports the pipeline it cannot
    // honor.
    #[test]
    fn build_refuses_a_handler_registration_mmdebstrap_cannot_bake() {
        use vmcell::artifact::registry::DEFAULT_LABEL;
        let dir = tempfile::tempdir().expect("tempdir");
        let assemble = |source, handler_label, overlay: &std::path::Path| {
            build_stages(
                KernelSource::Prebuilt,
                source,
                None,
                None,
                handler_label,
                Some(overlay),
                std::sync::Arc::new(vmcell::vmm::CidAllocator::new()),
            )
            .map(|s| {
                s.iter()
                    .map(|st| st.name().to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            })
        };

        // 1. A LABELLED handler: `GuestToolsStage` publishes it as `guest_tools-acme`, a key the
        //    mmdebstrap tail never looks up.
        let labelled = dir.path().join("labelled.json");
        std::fs::write(
            &labelled,
            format!(
                r#"{{ "handlers": {{ "acme": {{ "digest": "sha256:{}",
                     "source": {{ "url": "https://example.invalid/tools" }} }} }} }}"#,
                "a".repeat(64)
            ),
        )
        .expect("write overlay");
        let msg = assemble(RootfsSourceKind::Mmdebstrap, Some("acme"), &labelled)
            .expect_err("a labelled handler against the mmdebstrap source must be refused")
            .to_string();
        assert!(
            msg.contains("handlers.acme") && msg.contains("--rootfs-source oci"),
            "the refusal must name the entry and the route, got: {msg}"
        );

        // 2. The `applets` clause's PREMISE, which is why that clause is written as an
        //    unreachable-by-construction guard rather than as a drivable arm: a roster declared on
        //    the DEFAULT label cannot reach any arm at all. The overlay merge is leaf-wise, so the
        //    baseline's `build: workspace:vmcell-guest-tools` leaf survives, and the entry parser
        //    refuses `applets` beside a workspace build — the default handler's roster IS
        //    `GUEST_TOOLS_APPLETS`, which is exactly what the mmdebstrap tail bakes. Refused for
        //    BOTH sources, because the refusal is the library's and not this file's.
        //
        //    RED on the inverse (a parser that accepted the pair): the roster would resolve, and the
        //    mmdebstrap arm would drop it silently — the case the guard exists for, and the case
        //    `the_baseline_default_handler_declares_no_roster_of_its_own` re-checks from the other
        //    side.
        let roster = dir.path().join("roster.json");
        std::fs::write(
            &roster,
            format!(r#"{{ "handlers": {{ "{DEFAULT_LABEL}": {{ "applets": ["ip"] }} }} }}"#),
        )
        .expect("write overlay");
        for source in [RootfsSourceKind::Mmdebstrap, RootfsSourceKind::Oci] {
            let msg = assemble(source, None, &roster)
                .expect_err("a roster declared on the default handler must be refused")
                .to_string();
            assert!(
                msg.contains("applets") && msg.contains(&format!("handlers.{DEFAULT_LABEL}")),
                "the refusal must name the key that cannot be honored, got: {msg}"
            );
        }

        // THE POSITIVE CONTROL. The `oci` source honors the labelled registration — it has a field
        // for it — so the refusal above is about what mmdebstrap can bake, not about the entry.
        assemble(RootfsSourceKind::Oci, Some("acme"), &labelled)
            .expect("the oci source bakes a labelled handler");
        // …and mmdebstrap still assembles for the handler it DOES bake: the baseline default entry,
        // spelled out as well as omitted. `--handler-label default` names the very handler this
        // source bakes, so refusing the flag's mere presence would have refused it.
        for label in [None, Some(DEFAULT_LABEL)] {
            build_stages(
                KernelSource::Prebuilt,
                RootfsSourceKind::Mmdebstrap,
                None,
                None,
                label,
                None,
                std::sync::Arc::new(vmcell::vmm::CidAllocator::new()),
            )
            .map(|s| s.len())
            .unwrap_or_else(|e| {
                panic!("mmdebstrap + `--handler-label {label:?}` must assemble: {e}")
            });
        }
    }

    // F1 on the `rootfs` entry's PACKING declarations (§4.7, v33 deltas 7-8), the sibling of the
    // handler gate above and the same shape: `--rootfs-source mmdebstrap` hands its tail a
    // hardcoded `XattrPolicy::Strip` and packs through the erofs door, so a declared
    // `xattrs: preserve` was stripped silently — beside an entry whose derived `xattr_preserved:
    // true` then travels with bytes that contradict it — and a declared `format: ext4` produced a
    // `rootfs.erofs`.
    //
    // Reachable even though `--rootfs-label` is refused against this source: the label is `None`,
    // and `None` resolves the DEFAULT entry, which is the entry describing the artifact this source
    // writes.
    //
    // RED on the inverse (delete the `reject_unproducible_rootfs_entry_for_mmdebstrap` call, or
    // either clause): the corresponding leg assembles and reports a pipeline that drops the
    // declaration.
    #[test]
    fn build_refuses_a_rootfs_declaration_mmdebstrap_cannot_produce() {
        use vmcell::artifact::registry::DEFAULT_LABEL;
        let dir = tempfile::tempdir().expect("tempdir");
        let assemble = |source, overlay: &std::path::Path| {
            build_stages(
                KernelSource::Prebuilt,
                source,
                None,
                None,
                None,
                Some(overlay),
                std::sync::Arc::new(vmcell::vmm::CidAllocator::new()),
            )
            .map(|s| s.len())
        };

        // The two declarations, each on the DEFAULT label (the only one this source can reach), and
        // each written through the type's own spelling so the fixture cannot drift from the parser.
        for (key, value, source_says) in [
            (
                "xattrs",
                vmcell::artifact::XattrPolicy::Preserve.name(),
                vmcell::artifact::XattrPolicy::default().name(),
            ),
            (
                "format",
                vmcell::artifact::RootfsFormat::Ext4.name(),
                vmcell::artifact::RootfsFormat::default().name(),
            ),
        ] {
            let overlay = dir.path().join(format!("{key}.json"));
            std::fs::write(
                &overlay,
                format!(r#"{{ "rootfs": {{ "{DEFAULT_LABEL}": {{ "{key}": "{value}" }} }} }}"#),
            )
            .expect("write overlay");

            let msg = assemble(RootfsSourceKind::Mmdebstrap, &overlay)
                .expect_err("a declaration this source cannot produce must be refused")
                .to_string();
            assert!(
                msg.contains(&format!("rootfs.{DEFAULT_LABEL}"))
                    && msg.contains(&format!("`{key}: {value}`"))
                    && msg.contains(source_says)
                    && msg.contains("--rootfs-source oci"),
                "the refusal must name the entry, the declaration, what this source does instead, \
                 and the route that works, got: {msg}"
            );

            // THE POSITIVE CONTROL, per declaration: the `oci` source has a field for it (the
            // `.with_xattrs`/`.with_format` on its stage), so the refusal is about what mmdebstrap
            // can produce and not about the entry being malformed.
            assemble(RootfsSourceKind::Oci, &overlay)
                .unwrap_or_else(|e| panic!("the oci source honors `{key}: {value}`: {e}"));
        }

        // …and mmdebstrap still assembles against the COMMITTED baseline, whose default entry
        // declares neither key: both clauses are inert until an overlay declares one, so this is the
        // leg that keeps the refusals from refusing the shipped invocation.
        build_stages(
            KernelSource::Prebuilt,
            RootfsSourceKind::Mmdebstrap,
            None,
            None,
            None,
            None,
            std::sync::Arc::new(vmcell::vmm::CidAllocator::new()),
        )
        .expect("mmdebstrap must still assemble against the committed pins");
    }

    // The other side of that premise, on the BASELINE itself: the default `handlers` entry declares
    // no roster of its own, so `applet_roster()` answers `GUEST_TOOLS_APPLETS` — the roster
    // `PackOptions::new()` bakes. That is what makes the mmdebstrap arm's dropped roster provably a
    // no-op rather than a silent loss, and it is a fact about the committed pins rather than about
    // this file, so it gets its own claim.
    //
    // RED on the inverse: register a `digest` + `applets` default handler in the baseline. That is
    // the day `reject_unbakeable_handler_for_mmdebstrap`'s `applets` clause becomes reachable and
    // this test says so, instead of the mmdebstrap image quietly baking the wrong symlinks.
    #[test]
    fn the_baseline_default_handler_declares_no_roster_of_its_own() {
        let entry = resolve_handler_entry(None, None)
            .expect("the baseline handlers registry resolves")
            .expect("the baseline registers a default handler");
        assert_eq!(entry.label, vmcell::artifact::registry::DEFAULT_LABEL);
        assert!(
            entry.applets.is_empty(),
            "the default handler must declare no `applets` — its roster is the const its dispatch \
             table is asserted against, and the mmdebstrap tail bakes that same one; got {:?}",
            entry.applets
        );
        // Non-vacuity: the entry really does resolve to a roster (the shared const), so "declares
        // none" is a statement about the DECLARATION and not about an empty handler.
        assert!(!entry.applet_roster().is_empty());
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
                None,
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
                None,
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
            dir.join(rootfs_filename(None, vmcell::artifact::RootfsFormat::Erofs)),
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

    // THE CALL-SITE SCAN for `vmcell build` (§18 delta 7): the selected label's §4.7 xattr policy
    // reaches the IMAGE stage the pipeline actually runs, not merely the entry `build_stages`
    // resolved. A policy that stops at the entry is a declaration a consumer built a fixture on —
    // the image packs under the pre-delta-7 default while the sidecar beside it claims the
    // attributes survived.
    //
    // Read through `Stage::cache_key`, which is the only observable a `dyn Stage` has and the
    // honest one anyway: the key is what decides whether the warm artifacts dir is served, so a
    // policy that does not move it is a policy that never re-packs.
    //
    // RED on dropping `.with_xattrs(...)` from `rootfs_stage`'s OCI arm: the assembled stage keys
    // as `Strip`, so the first assertion fails (`left` = the `Strip` key) and the second — the
    // non-vacuity control — starts passing for the wrong reason, which is why both are here.
    #[test]
    fn the_build_pipelines_rootfs_stage_carries_the_labels_xattr_policy() {
        use vmcell::artifact::rootfs::{RootfsStage, rootfs_artifact_key};
        use vmcell::artifact::{Stage, StageInputs, XattrPolicy, resolve_pins};

        let tmp = tempfile::tempdir().expect("tempdir");
        let overlay = tmp.path().join("overlay.json");
        std::fs::write(
            &overlay,
            format!(
                r#"{{ "rootfs": {{ "{}": {{ "image": "docker.io/library/debian",
                     "digest": "sha256:{}", "xattrs": "preserve" }} }} }}"#,
                vmcell::artifact::registry::DEFAULT_LABEL,
                "a".repeat(64)
            ),
        )
        .expect("write overlay");

        let stages = build_stages(
            KernelSource::Prebuilt,
            RootfsSourceKind::Oci,
            None,
            None,
            None,
            Some(&overlay),
            std::sync::Arc::new(vmcell::vmm::CidAllocator::new()),
        )
        .expect("a declaring registry entry must assemble");

        let mut inputs = StageInputs::default();
        inputs.pins = resolve_pins(Some(&overlay)).expect("the overlay resolves");
        let image = stages
            .iter()
            .find(|s| s.name() == rootfs_artifact_key(None))
            .expect("the image stage");
        // Same applet roster the composition root hands it, so the comparison isolates the ONE
        // property under test rather than depending on which fields the key happens to fold.
        let applets = resolve_handler_entry(None, Some(&overlay))
            .expect("the handler registry resolves")
            .map(|e| e.applet_roster())
            .unwrap_or_default();
        let expected = |policy| {
            RootfsStage::labelled(None)
                .with_applets(applets.clone())
                .with_xattrs(policy)
                .cache_key(&inputs)
        };
        assert_eq!(
            image.cache_key(&inputs),
            expected(XattrPolicy::Preserve),
            "the entry's `xattrs` policy must reach the image stage `vmcell build` runs (§4.7)"
        );
        assert_ne!(
            image.cache_key(&inputs),
            expected(XattrPolicy::Strip),
            "…and the two policies must be two artifacts (non-vacuity)"
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

    // A2: the CLI resolved the Cloud Hypervisor binary with its own byte-identical copy of
    // `vmcell::artifact::ch_binary_path` — a THIRD copy of the one resolver (`harness::ch_bin` is the
    // other), and the copy every VM-lifecycle verb (`run`, `create`, `snapshot`, `stats`) went
    // through. `ch_binary_path`'s own rustdoc exists because a second env var name had already
    // shipped once: overriding one left the other on the default.
    //
    // A parity assertion (`ch_bin() == ch_binary_path()`) was the first draft and it CANNOT FAIL:
    // with the variable unset both copies answer `cloud-hypervisor`, so a private copy reading a
    // different variable stays green. `set_var` would make it drivable and is banned here
    // (`disallowed-methods`, process-global besides). So the law is scanned in the PRODUCTION half of
    // this file, the shape `vmcell-privilege`'s call-site gates use — excluding the test half is also
    // what keeps these needles from matching themselves.
    //
    // RED on the inverse (verified both ways): restore the private `std::env::var("VMCELL_CH_BIN")`
    // body and the ban fails; drop the delegation and the positive control fails.
    #[test]
    fn the_cli_resolves_the_ch_binary_through_the_one_library_law() {
        let production = include_str!("main.rs")
            .split_once("#[cfg(test)]")
            .expect("the test module is gated in this file")
            .0;
        // Comments stripped, so prose NAMING the variable (this resolver's own rustdoc does) is not
        // counted as a read of it.
        let code: String = production
            .lines()
            .map(|l| l.split_once("//").map_or(l, |(before, _)| before))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            code.matches("VMCELL_CH_BIN").count(),
            0,
            "the CH binary's env var belongs to `vmcell::artifact::ch_binary_path` alone; naming it \
             here is that resolver's third copy"
        );
        // THE POSITIVE CONTROL, without which the ban above would pass on a CLI that resolved no VMM
        // binary at all: the delegation is there, in exactly one place.
        assert_eq!(
            code.matches("artifact::ch_binary_path()").count(),
            1,
            "the CLI must resolve the CH binary through the library's one resolver, in one place"
        );
        // …and that resolver answers something, so `ch_bin` is not a stub the scan approves of.
        assert!(!ch_bin().is_empty());
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
        use vmcell::artifact::RootfsFormat;
        use vmcell::artifact::rootfs::{
            features_artifact_key, rootfs_artifact_key, rootfs_filename,
        };
        use vmcell::feature::feature_manifest_path;

        let dir = tempfile::tempdir().expect("tempdir");
        // A dir as `vmcell build --rootfs-label acme` leaves it: two images, two declarations, and
        // a cache sidecar beside them (the near-miss that must not read as an artifact).
        for label in [None, Some("acme")] {
            let image = dir.path().join(rootfs_filename(label, RootfsFormat::Erofs));
            std::fs::write(&image, b"erofs").expect("write image");
            std::fs::write(feature_manifest_path(&image), b"xattr_preserved = false\n")
                .expect("write declaration");
        }
        std::fs::write(dir.path().join("rootfs-acme.cache_key"), b"k").expect("write sidecar");

        // No `resolved_pins.json`: the UNRECORDED leg, where every candidate falls back to what the
        // filenames say. `acme` carries no dot, so its on-disk and registered spellings coincide —
        // the recorded leg is `bundle_names_a_rootfs_by_its_registered_spelling_and_declared_format`.
        let recorded =
            RecordedRegistrations::read_from(dir.path()).expect("an unrecorded dir reads");
        let candidates = bundle_candidates(dir.path(), &recorded);
        let named = |name: &str| -> Option<PathBuf> {
            candidates
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, p)| p.clone())
        };
        // Both kinds of entry, both labels, each name composed through the library's own laws.
        for label in [None, Some("acme")] {
            let key = rootfs_artifact_key(label);
            let image = dir.path().join(rootfs_filename(label, RootfsFormat::Erofs));
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

    // The same walk, for an `ext4` artifacts dir (§4.7, §18 delta 8). An ext4 rootfs invisible to
    // `bundle` is the N-BIN-4 defect class re-armed by the second format — the manifest would
    // report success while covering nothing the consumer needs.
    //
    // RED on the inverse two ways: revert `rootfs_artifact_from_filename` to an `.erofs`-only
    // suffix strip and the labelled leg's `named(&key)` is `None`; revert the DEFAULT rootfs
    // candidate to a hardcoded `rootfs.erofs` and the default leg's is.
    #[test]
    fn bundle_covers_an_ext4_rootfs_and_its_declaration_sidecar() {
        use vmcell::artifact::RootfsFormat;
        use vmcell::artifact::rootfs::{
            features_artifact_key, rootfs_artifact_key, rootfs_filename,
        };
        use vmcell::feature::feature_manifest_path;

        let dir = tempfile::tempdir().expect("tempdir");
        // A dir as `vmcell build` leaves it when both entries declare `"format": "ext4"`: no
        // `.erofs` anywhere, which is exactly what makes an erofs-only walk find nothing.
        for label in [None, Some("acme")] {
            let image = dir.path().join(rootfs_filename(label, RootfsFormat::Ext4));
            std::fs::write(&image, b"ext4").expect("write image");
            std::fs::write(feature_manifest_path(&image), b"xattr_preserved = true\n")
                .expect("write declaration");
        }

        // The UNRECORDED leg again (no `resolved_pins.json`): the format comes from the directory,
        // which is the only thing there is to read.
        let recorded =
            RecordedRegistrations::read_from(dir.path()).expect("an unrecorded dir reads");
        let candidates = bundle_candidates(dir.path(), &recorded);
        for label in [None, Some("acme")] {
            let key = rootfs_artifact_key(label);
            let image = dir.path().join(rootfs_filename(label, RootfsFormat::Ext4));
            assert!(
                candidates.iter().any(|(n, p)| *n == key && *p == image),
                "the manifest must cover the ext4 rootfs `{key}` at {image:?}: {candidates:?}"
            );
            let sidecar_key = features_artifact_key(&key);
            let sidecar = feature_manifest_path(&image);
            assert!(
                candidates
                    .iter()
                    .any(|(n, p)| *n == sidecar_key && *p == sidecar),
                "the manifest must cover `{sidecar_key}` at {sidecar:?}: {candidates:?}"
            );
        }
        // Every rootfs candidate really exists: an ext4 dir must not have the walk still naming
        // `rootfs.erofs` as the default and reporting it skipped.
        for (name, path) in &candidates {
            if name.starts_with("rootfs") {
                assert!(
                    path.exists(),
                    "`{name}` points at {path:?}, which is not there — the walk is still looking \
                     for the other format"
                );
            }
        }
    }

    // The RECORDED leg (§18 delta 8, §10.5): the two things a filename cannot tell `bundle`, and it
    // got both wrong.
    //
    // The fixture is an artifacts dir mid-migration — the state delta 8 makes ordinary: two entries
    // re-registered from `erofs` to `ext4`, so each label's stale image still sits beside its current
    // one, both under the SAME stem (which is the registry's collision key, precisely because the two
    // formats share their `.cache_key` and `.features` sidecars). And one of the labels carries a
    // dot, like every label in the committed `kernels` registry does.
    //
    // Three claims, each a defect that shipped:
    //   * the DEFAULT artifact is the declared `rootfs.ext4`, not the `RootfsFormat::ALL`-first
    //     `rootfs.erofs` the scan found — a manifest that pins the stale image is a durable digest
    //     claim about bytes no build produced;
    //   * a labelled artifact is named by its REGISTERED spelling (`rootfs-6.12`), not by the
    //     sanitized filename spelling (`rootfs-6-12`) — the producers register the dotted key, so the
    //     sanitized one is a name no consumer can look up;
    //   * each artifact key appears EXACTLY once — the old walk pushed one candidate per image FILE,
    //     so a mid-migration label landed twice under one key with two different digests and a
    //     consumer resolved whichever `read_dir` yielded first.
    //
    // RED on the inverse, three ways: revert the default arm to the present-format scan (claim 1);
    // drop the registered-spelling lookup (claim 2); push `e.path()` per file instead of the one
    // declared candidate (claim 3, and claim 1's `.erofs` assertion goes with it).
    #[test]
    fn bundle_names_a_rootfs_by_its_registered_spelling_and_declared_format() {
        use vmcell::artifact::RootfsFormat;
        use vmcell::artifact::rootfs::{
            features_artifact_key, rootfs_artifact_key, rootfs_filename,
        };
        use vmcell::feature::feature_manifest_path;

        let dir = tempfile::tempdir().expect("tempdir");
        // The record the pipeline published into this dir: stage 0 writes it on the very run that
        // packed these images, which is what makes its `format` the format that build wrote.
        std::fs::write(
            recorded_pins_path(dir.path()),
            format!(
                r#"{{ "rootfs": {{
                     "default": {{ "image": "docker.io/library/debian",
                                   "digest": "sha256:{a}", "format": "ext4" }},
                     "6.12": {{ "image": "docker.io/library/debian",
                                "digest": "sha256:{b}", "format": "ext4" }} }} }}"#,
                a = "a".repeat(64),
                b = "b".repeat(64)
            ),
        )
        .expect("write the recorded pins");
        // Both formats of both labels on disk: the ext4 pair is current, the erofs pair is what the
        // pre-migration build left behind.
        for label in [None, Some("6-12")] {
            for format in RootfsFormat::ALL {
                let image = dir.path().join(rootfs_filename(label, format));
                std::fs::write(&image, format.name()).expect("write image");
                std::fs::write(feature_manifest_path(&image), b"xattr_preserved = false\n")
                    .expect("write declaration");
            }
        }

        let recorded = RecordedRegistrations::read_from(dir.path()).expect("the record reads");
        let candidates = bundle_candidates(dir.path(), &recorded);
        let paths = |name: &str| -> Vec<PathBuf> {
            candidates
                .iter()
                .filter(|(n, _)| n == name)
                .map(|(_, p)| p.clone())
                .collect()
        };
        // Composed through the library's laws, never spelled: the KEY keeps the dots, the FILENAME
        // sanitizes them, and that gap is the whole finding.
        for (key, image) in [
            (
                rootfs_artifact_key(None),
                dir.path().join(rootfs_filename(None, RootfsFormat::Ext4)),
            ),
            (
                rootfs_artifact_key(Some("6.12")),
                dir.path()
                    .join(rootfs_filename(Some("6.12"), RootfsFormat::Ext4)),
            ),
        ] {
            assert_eq!(
                paths(&key),
                vec![image.clone()],
                "`{key}` must be the ONE declared image {image:?}: {candidates:?}"
            );
            let sidecar_key = features_artifact_key(&key);
            assert_eq!(
                paths(&sidecar_key),
                vec![feature_manifest_path(&image)],
                "…and its §7.4 declaration must travel with that image: {candidates:?}"
            );
        }
        // The sanitized spelling is a key the producers never register, so nothing may be named it.
        assert!(
            paths(&rootfs_artifact_key(Some("6-12"))).is_empty(),
            "`rootfs-6-12` is the FILENAME's spelling, not the registration's: {candidates:?}"
        );
        // And no candidate points at a stale erofs image — the whole dir still holds two.
        for (name, path) in &candidates {
            assert!(
                !path.to_string_lossy().ends_with(".erofs"),
                "`{name}` pins the stale pre-migration image {path:?}"
            );
        }

        // THE CALL SITE, which is the level the manifest is actually written at: `bundle_artifacts`
        // must put those same names on disk. Asserted on the manifest TEXT because this crate
        // deliberately carries no `serde_json` (a `cargo machete` gate); the artifact name is the
        // only field that renders as a bare quoted `rootfs-6.12`, since the path renders with its
        // `.ext4` extension.
        bundle_artifacts(dir.path(), None).expect("a digest-pinned dir must bundle");
        let manifest = std::fs::read_to_string(dir.path().join("manifest.json"))
            .expect("the manifest was written");
        assert!(
            manifest.contains(&format!("\"{}\"", rootfs_artifact_key(Some("6.12")))),
            "the written manifest must name the registered spelling: {manifest}"
        );
        assert!(
            !manifest.contains(&format!("\"{}\"", rootfs_artifact_key(Some("6-12")))),
            "…and never the sanitized one: {manifest}"
        );
    }

    // The case every real `vmcell bundle` hits, and the one this fix could have broken outright: a
    // build with no `--pins` publishes `resolved_pins.json` as the committed baseline VERBATIM (the
    // §18 delta-1 migration promise), so reading the record back is re-resolving that whole document
    // as an overlay over itself. The merge is leaf-wise, so it must reproduce the build's own
    // registries rather than a hybrid — or a colliding shape, or a parse refusal on a namespace the
    // overlay reader treats differently from the baseline reader.
    //
    // The fixture is the committed `pins.json` itself, `include_str!`-ed the way
    // `vmcell/tests/systemd_cell.rs` reads the justfile: a hand-written stand-in would prove
    // something about the stand-in.
    //
    // RED on the inverse: hand `read_from` a document the overlay reader refuses (drop the
    // `.exists()` guard and point it at a dir with no record — the read errors instead of yielding
    // the empty rosters), or let the merge lose a namespace (the equalities fail naming the kind).
    #[test]
    fn bundle_reads_the_record_a_no_overlay_build_publishes() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            recorded_pins_path(dir.path()),
            include_str!("../../../pins.json"),
        )
        .expect("write the record a no-overlay build publishes");

        let recorded = RecordedRegistrations::read_from(dir.path())
            .expect("the record a real build publishes must read back");
        assert_eq!(
            recorded.kernels,
            vmcell::artifact::resolve_kernel_registry(None).expect("the baseline kernels registry"),
            "re-resolving the published record must reproduce the build's own `kernels` registry"
        );
        assert_eq!(
            recorded.rootfs,
            vmcell::artifact::resolve_rootfs_registry(None).expect("the baseline rootfs registry"),
            "…and its `rootfs` registry"
        );
        // Non-vacuity: both rosters are non-empty, so the equalities are not two empty vectors — and
        // the dotted-label lookup the walk depends on really answers off this record.
        assert!(!recorded.kernels.is_empty() && !recorded.rootfs.is_empty());
        let dotted = recorded
            .kernels
            .iter()
            .find(|e| e.label.contains('.'))
            .expect("the baseline registers a dotted kernel label");
        assert_eq!(
            recorded.kernel_label(&dotted.label.replace('.', "-")),
            dotted.label,
            "the record must resolve a sanitized filename label back to its registered spelling"
        );
        // An artifacts dir with NO record is not an error: the rosters are empty and every candidate
        // falls back to the filenames.
        let empty = tempfile::tempdir().expect("tempdir");
        let none = RecordedRegistrations::read_from(empty.path())
            .expect("a dir no pipeline has filled records nothing");
        assert!(none.kernels.is_empty() && none.rootfs.is_empty());
    }

    // The same law one kind over, on the live instance: every label in the committed `kernels`
    // registry carries dots (`6.12.94`), the producers write `vmlinux-6-12-94`, and the artifact key
    // keeps the dots — so `bundle` recorded `kernel-6-12-94`, a name `build-kernels` registers
    // nothing under. A consumer looking up what it built found nothing.
    //
    // The unregistered leg beside it is what keeps the fix from becoming an omission: a kernel whose
    // label the recorded pins no longer name keeps its on-disk spelling and stays in the manifest,
    // rather than being dropped (N-BIN-4) or renamed to something invented.
    //
    // RED on the inverse (drop `recorded.kernel_label(...)` and compose the on-disk label): the first
    // claim fails with `kernel-6-12-94`.
    #[test]
    fn bundle_names_a_kernel_by_its_registered_spelling() {
        use vmcell::artifact::kernel::{kernel_artifact_key, kernel_filename};

        let dir = tempfile::tempdir().expect("tempdir");
        // An empty overlay: the record resolves to the COMMITTED baseline registry, so the dotted
        // label under test is the one `vmcell build-kernels` really builds rather than a fixture's
        // invention.
        std::fs::write(recorded_pins_path(dir.path()), b"{}").expect("write the recorded pins");
        let registry =
            vmcell::artifact::resolve_kernel_registry(None).expect("the baseline kernels registry");
        let dotted = registry
            .iter()
            .find(|e| e.label.contains('.'))
            .expect("the baseline registers a dotted kernel label — the case this test is about");
        // Written through the producers' own filename composer, so the fixture is the file
        // `build-kernels` writes and not a hand-sanitized guess.
        std::fs::write(
            dir.path().join(kernel_filename(Some(&dotted.label))),
            b"vmlinux",
        )
        .expect("write the labelled kernel");
        std::fs::write(dir.path().join(kernel_filename(Some("legacy"))), b"vmlinux")
            .expect("write an unregistered labelled kernel");

        let recorded = RecordedRegistrations::read_from(dir.path()).expect("the record reads");
        let names: Vec<String> = bundle_candidates(dir.path(), &recorded)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        let named = |key: &str| names.iter().any(|n| n == key);
        let registered = kernel_artifact_key(Some(&dotted.label));
        assert!(
            named(&registered),
            "the manifest must name the kernel the way `build-kernels` registers it \
             (`{registered}`): {names:?}"
        );
        // The sanitized spelling is composed here through the same `.`→`-` law the producers' own
        // filename composer applies, and asserted ABSENT: it is what the pre-fix walk recorded.
        let sanitized = kernel_artifact_key(Some(&dotted.label.replace('.', "-")));
        assert!(
            !named(&sanitized),
            "…and never the sanitized filename spelling (`{sanitized}`): {names:?}"
        );
        // The unregistered one is still covered, under the only spelling there is for it.
        assert!(
            named(&kernel_artifact_key(Some("legacy"))),
            "an unregistered labelled kernel must stay in the manifest: {names:?}"
        );
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

    // §4.2 (v33 delta 7): the `--tools`/`--work-dir` argument surface, on the same terms
    // `parse_inject` is held to — a well-formed value PARSES and reaches the variant, and a
    // malformed one is named rather than ignored. Neither flag has a `value_parser` (both are
    // plain paths), so "malformed" is semantic: a `--tools` that names nothing, or names a
    // directory instead of the binary; a `--work-dir` that cannot be a directory.
    //
    // RED on the inverse, four ways: (a) drop either field from the `Oci2Erofs` variant — this
    // does not compile, the strongest form; (b) make `validate_tools_binary` return `Ok` for a
    // missing path — the pipeline then runs a full OCI pull before failing, and the operator's
    // typo costs a download; (c) drop the `is_file` check — `--tools target/release` is accepted
    // and the copy fails three stages later naming a directory the operator did not type;
    // (d) make `resolve_work_dir` ignore its argument — the staging tree lands in the artifacts
    // dir the flag existed to move it out of.
    #[test]
    fn oci2erofs_tools_and_work_dir_are_honored_or_named() {
        use clap::Parser;
        let dir = tempfile::tempdir().expect("tempdir");
        let tools = dir.path().join("vmcell-guest-tools");
        std::fs::write(&tools, b"prebuilt").expect("seed the --tools target");

        // 1. The positive control: both flags parse and land on the variant.
        let parsed = Cli::try_parse_from([
            "vmcell",
            "oci2-erofs",
            "debian:trixie-slim@sha256:abc",
            "-o",
            "/tmp/out.erofs",
            "--tools",
            tools.to_str().expect("utf-8 fixture path"),
            "--work-dir",
            "/tmp/vmcell-wd",
        ])
        .expect("both flags must parse");
        match parsed.command {
            Commands::Oci2Erofs {
                tools: t,
                work_dir: w,
                ..
            } => {
                assert_eq!(t.as_deref(), Some(tools.as_path()));
                assert_eq!(w.as_deref(), Some(std::path::Path::new("/tmp/vmcell-wd")));
            }
            other => panic!(
                "expected Oci2Erofs, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
        // …and their ABSENCE parses to `None`, which is what "additive, absence reproduces
        // today's behavior" has to mean at the argument surface.
        match Cli::try_parse_from(["vmcell", "oci2-erofs", "img@sha256:abc", "-o", "/tmp/o"])
            .expect("the flags are optional")
            .command
        {
            Commands::Oci2Erofs {
                tools: t,
                work_dir: w,
                ..
            } => assert!(t.is_none() && w.is_none()),
            other => panic!(
                "expected Oci2Erofs, got {:?}",
                std::mem::discriminant(&other)
            ),
        }

        // 2. `--tools`, honored and refused.
        assert_eq!(
            validate_tools_binary(None).expect("absent is legal"),
            None,
            "an absent `--tools` is the pre-delta-7 workspace build, not an error"
        );
        assert_eq!(
            validate_tools_binary(Some(&tools)).expect("a readable file is legal"),
            Some(tools.clone())
        );
        for (label, path, needle) in [
            (
                "a path that is not there",
                dir.path().join("nope"),
                "--tools",
            ),
            (
                "a directory",
                dir.path().to_path_buf(),
                "not a regular file",
            ),
        ] {
            let msg = validate_tools_binary(Some(&path))
                .map(|v| format!("{v:?}"))
                .expect_err(&format!("{label} must be refused"))
                .to_string();
            assert!(
                msg.contains(needle) && msg.contains(&path.display().to_string()),
                "{label} must be named ({needle} + the path), got: {msg}"
            );
        }

        // 3. `--work-dir`, honored and refused. Absent is the artifacts dir — the one fact that
        // makes "absence reproduces today's behavior exactly" true of the staging tree.
        assert_eq!(
            resolve_work_dir(None).expect("absent is legal"),
            vmcell::artifact::artifacts_dir()
        );
        let wanted = dir.path().join("nested/work");
        assert_eq!(
            resolve_work_dir(Some(&wanted)).expect("a nameable directory is legal"),
            wanted
        );
        assert!(
            wanted.is_dir(),
            "`--work-dir` must be created, not demanded"
        );
        let a_file = dir.path().join("a-file");
        std::fs::write(&a_file, b"not a dir").expect("seed");
        let msg = resolve_work_dir(Some(&a_file))
            .map(|p| p.display().to_string())
            .expect_err("a file cannot be a staging parent")
            .to_string();
        assert!(
            msg.contains("--work-dir") && msg.contains(&a_file.display().to_string()),
            "the refusal must name the flag and the path, got: {msg}"
        );
    }

    // The call-site scan beside the gate above (§4.2, v33 delta 7): `--tools` must reach the stage
    // `oci2-erofs` actually runs, and its absence must leave that stage byte-identical to the
    // pre-delta-7 `GuestToolsStage::new()`. The observable is `Stage::cache_key` — the only one a
    // stage has, and the honest one, since the key is what decides a warm-cache hit.
    //
    // RED on the inverse: `oci2erofs_tools_stage` ignoring its argument (the "green unit test
    // beside an unchanged call site" shape) collapses the two keys into one.
    #[test]
    fn the_tools_flag_reaches_the_stage_oci2erofs_runs() {
        use vmcell::artifact::Stage as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let tools = dir.path().join("vmcell-guest-tools");
        std::fs::write(&tools, b"prebuilt").expect("seed");
        let inputs = vmcell::artifact::StageInputs::default();

        let with = oci2erofs_tools_stage(Some(&tools)).cache_key(&inputs);
        let without = oci2erofs_tools_stage(None).cache_key(&inputs);
        assert_ne!(
            with, without,
            "`--tools` must reach the stage; an ignored flag would pack a workspace build under \
             the operator's nose"
        );
        assert_eq!(
            without,
            vmcell::artifact::guest_tools::GuestToolsStage::new().cache_key(&inputs),
            "no `--tools` is the pre-delta-7 stage exactly — the migration promise is that the \
             default cache key does not move"
        );
        assert_eq!(
            with,
            vmcell::artifact::guest_tools::GuestToolsStage::labelled(
                None,
                Some(vmcell::artifact::handler::HandlerSource::Prebuilt {
                    path: tools.clone()
                })
            )
            .cache_key(&inputs),
            "the flag must compose the per-run OVERRIDE shape, not a registration"
        );
    }

    // The two flags are validated BEFORE the pipeline is assembled, so a mistyped argument costs
    // an error message rather than a full digest-pinned OCI pull. Driven through the verb itself
    // (not the validators) because that ordering is a property of the verb: a check that exists
    // but runs after `Pipeline::build` is a check the operator waits minutes for.
    //
    // RED on the inverse (move `validate_tools_binary` below the `pipeline.build(...)` call): this
    // test stops returning promptly and starts trying to reach a registry.
    #[test]
    fn a_bad_tools_path_is_refused_before_any_pull() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let dir = tempfile::tempdir().expect("tempdir");
        let err = rt
            .block_on(oci2erofs(
                &format!("debian:trixie-slim@sha256:{}", "a".repeat(64)),
                &dir.path().join("out.erofs"),
                None,
                &[],
                Some(&dir.path().join("no-such-tools")),
                Some(&dir.path().join("wd")),
                None,
            ))
            .expect_err("a `--tools` path that is not there is a hard stop");
        assert!(
            err.to_string().contains("--tools"),
            "the verb must surface the flag's own refusal, got: {err}"
        );
        // Nothing was staged for the refused run: the staging tree is composed after the checks.
        assert!(
            !dir.path()
                .join("wd")
                .join(format!("oci2erofs-stage-{}", std::process::id()))
                .exists(),
            "a refused invocation must leave no staging residue"
        );
    }

    // THE RESIDUE SHAPE, on the owner itself: the tree exists before the drop and is gone after it
    // (AGENTS.md's residue rule, stated in that order so the check cannot pass vacuously against a
    // tree that was never created).
    //
    // Also the composition law: the value can only ever remove a leaf IT appended, which is what
    // makes "the only directory vmcell may delete is one it composed itself" structural. An
    // operator's `--work-dir` is the parent and must survive — asserted, because a `StagingTree`
    // that took the parent verbatim would `rm -rf` the directory they named.
    //
    // RED on the inverse: drop the `Drop` impl (the second assertion fails), or have
    // `compose_under` keep `parent` as its own path (the third fails, and the operator's directory
    // is gone).
    #[test]
    fn the_staging_tree_is_swept_on_drop_and_only_ever_owns_what_it_composed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let parent = dir.path().join("work");
        let leaf = {
            let stage = StagingTree::compose_under(&parent).expect("composing the staging leaf");
            assert!(
                stage.path().is_dir(),
                "the staging tree must exist while the run owns it, or the residue check below \
                 proves nothing"
            );
            assert!(
                stage.path().starts_with(&parent) && stage.path() != parent,
                "the leaf must be composed UNDER the parent and never be the parent itself: {}",
                stage.path().display()
            );
            stage.path().to_path_buf()
        };
        assert!(
            !leaf.exists(),
            "the staging tree must be gone once its owner drops: {}",
            leaf.display()
        );
        assert!(
            parent.is_dir(),
            "the operator's `--work-dir` is the PARENT and must survive; only the composed leaf is \
             vmcell's to delete"
        );
    }

    // The gap the owner closes, end to end through the verb: a run whose PIPELINE fails must leave
    // no staging residue. The two hand-placed `remove_dir_all`s this replaced covered the happy
    // path and the copy's error path; `pipeline.build(...)?` returned between them, so every failed
    // pack accumulated a tree in the directory `--work-dir` names.
    //
    // The failure is forced with an unreadable `--pins` overlay: `ResolvePinsStage` is the FIRST
    // stage, so this reaches `pipeline.build` and fails there without a network round trip — and
    // the refusal is the pipeline's, not one of the pre-pipeline flag checks, which is asserted so
    // the leg cannot silently degrade into a copy of `a_bad_tools_path_is_refused_before_any_pull`.
    //
    // Non-vacuity: `--work-dir` is a fresh directory, so "no residue" is "the parent is EMPTY", and
    // the sibling test above is what proves the tree was really created in the first place.
    //
    // RED on the inverse: restore the two hand-placed sweeps and drop the `StagingTree` owner —
    // the parent is left holding `oci2erofs-stage-<pid>`.
    #[test]
    fn a_failed_pipeline_leaves_no_staging_residue() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let dir = tempfile::tempdir().expect("tempdir");
        let bad_pins = dir.path().join("broken-pins.json");
        std::fs::write(&bad_pins, b"{ this is not json").expect("write the broken overlay");
        let work = dir.path().join("wd");

        let err = rt
            .block_on(oci2erofs(
                &format!("debian:trixie-slim@sha256:{}", "a".repeat(64)),
                &dir.path().join("out.erofs"),
                None,
                &[],
                None,
                Some(&work),
                Some(&bad_pins),
            ))
            .expect_err("an unreadable pins overlay must fail the pipeline");
        let msg = err.to_string();
        assert!(
            !msg.contains("--tools") && !msg.contains("--work-dir"),
            "this leg must reach the PIPELINE, not a pre-pipeline flag refusal; got: {msg}"
        );
        assert!(
            work.is_dir(),
            "`--work-dir` is created up front and is the operator's, so it survives the failure"
        );
        let residue: Vec<_> = std::fs::read_dir(&work)
            .expect("the work dir is readable")
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .collect();
        assert!(
            residue.is_empty(),
            "a failed pipeline must leave no staging tree in the directory the operator named, \
             found {residue:?}"
        );
    }
}
