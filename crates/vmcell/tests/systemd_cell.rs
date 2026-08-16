//! v33 delta 9's **systemd proof cell** (design §18 delta 9, §15.4): the one configuration in
//! which every v33 request composes at once — a registered artifact (delta 6), packed under its
//! own declared xattr policy (delta 7), booting **real systemd as PID 1**, with the steward
//! running as a systemd *unit* under `StewardPlacement::Service` (deltas 4 + 5), the control plane
//! driven end to end, and the §10.6 conformance kit (delta 3) run over the composition with its
//! declared-feature provenance (delta 2) asserted.
//!
//! # Why this cannot be a per-delta gate
//!
//! Every per-delta gate in this pass is blind to the same thing: what a real init does. `FakeVmm`
//! never boots one; delta 5's service battery boots `mini-init`, which is vmcell's own applet
//! calling vmcell's own `assemble_guest_root`; delta 6's and 7's batteries never boot the labelled
//! image at all. So "the steward works as a service" was, until this file, only ever demonstrated
//! under an init that vmcell wrote. This is the leg where somebody else's init starts it.
//!
//! # Opt-in, and how the opt-in actually holds
//!
//! `test-privileged`'s filterset excludes only `unprivileged`/`smoltcp`, so **writing the
//! `just test-systemd` recipe does not by itself keep this out of the privileged suite** — the
//! recipe's `-E 'kind(test) & test(systemd_cell)'` selects a strict subset of what
//! `test-privileged` already selects. The opt-in therefore lives in the test, exactly as
//! `usb_passthrough.rs`'s does: absent [`OPT_IN_ENV`] each live leg records a capability skip and
//! returns, so `test-privileged` reports a reviewable skip instead of pulling a ~59 MB image on
//! every KVM host. (A skip outside `require_cap!` is a recorded deviation — the v30 delta-9
//! precedent in `docs/implementation-notes.md`; the recorded reason is the same one: hard-failing
//! every KVM host that has not opted into a large network pull would make the privileged suite
//! unrunnable.)
//!
//! Two gates hold that opt-in, in the two directions it can break:
//!
//! * a leg that forgets to ask is a **compile error**, not a review miss — [`OptedIn`] is
//!   constructible only inside `mod opt_in`, and both costly entry points ([`pack_systemd_rootfs`],
//!   which pulls, and [`boot_systemd_cell`], which boots) take one;
//! * [`the_opt_in_is_declared_by_the_systemd_recipe_and_by_no_other`] checks the justfile wiring —
//!   `test-systemd` sets the variable, is runner-wrapped, selects this binary, and **no other
//!   recipe sets it**. KVM-free, so it runs on every machine rather than only on the ones that
//!   already opted in.
//!
//! # The image, and the design deviation it carries
//!
//! §10.5's illustration registers `debian-systemd` against `docker.io/library/debian`. That is
//! **unrealizable**: no digest of that repo ships a systemd binary (it is the base/slim variant —
//! only unit files, `libsystemd.so.0` and dpkg shims). The committed entry therefore pins
//! `docker.io/jrei/systemd-debian`'s amd64 manifest by digest, which does carry
//! `usr/lib/systemd/systemd`, `usr/bin/systemctl` and `usr/bin/systemd-run`. Third-party
//! provenance, pinned by digest like every other registration (R7), and recorded as a deviation.
//!
//! The entry declares `"xattrs": "strip"` rather than §10.5's sketched `"preserve"`, and that is
//! the delta-7 law being *honored* rather than dodged: all four of this image's layers carry zero
//! PAX `SCHILY.xattr` records, so a `preserve` declaration would derive
//! `Feature::XattrPreserved = true` for an artifact that demonstrably carries none — and the §10.6
//! battery below would (correctly) report it as a broken claim. The `Preserve` half of §4.7 is
//! proved by `tests/xattr_policy.rs`, which synthesizes a layer that actually has attributes.
//!
//! # Two things this file deliberately does NOT do
//!
//! * **It never asserts on a steward log line.** The steward logs at `tracing::info!`, the guest
//!   sets no `RUST_LOG`, and `tracing_subscriber`'s default filter drops everything below `error`,
//!   so its startup and bind lines do not reach the console at all. The corroborating serial
//!   evidence here is **systemd's own** console output; everything else is a data-plane fact read
//!   back through the control plane.
//! * **It does not assert a placement refusal from a steward-less cell.** §18 delta 9's sketch
//!   says the reddening "names the placement", and for a `Service{port}` cell that message is
//!   unreachable: `steward_port()` is `Some` there, so `MicroVm::steward` never takes the
//!   `StewardPlacement::None` fail-loud arm and the honest outcome is a transport timeout.
//!   [`systemd_cell_without_the_steward_unit_times_out_without_naming_the_placement`] asserts that
//!   — plus refusal *identity*, that the message does **not** name `StewardPlacement::None`.
//!
//! **These legs mean nothing against a stale tree.** The steward and the guest-tools multicall
//! binary are built by the real stages into this test's own staging dir, so they are always this
//! tree's; the *kernel* is not, and must be a `host-make` one (`vmcell build --kernel-source
//! host-make`) — see `common::get_vmlinux`.
//!
//! CH-only, like `service_steward.rs` and `custom_init.rs`: this is a guest-side composition
//! reached through host-side cmdline and packing features, so one primary-backend proof suffices.

#![cfg(feature = "cloud-hypervisor")]

use std::time::Duration;

use vmcell::config::{KernelVerbosity, RootfsSource, StewardPlacement, VmConfig};
use vmcell::steward::{ExecRequest, SessionEvent, SessionSpecBuilder};

mod common;

// -----------------------------------------------------------------------------------------------
// The opt-in, and the gate that keeps it wired.
// -----------------------------------------------------------------------------------------------

/// The opt-in, in its own module so its capability token cannot be forged.
///
/// Rust privacy is per-module, so a token type declared beside the live legs would be
/// constructible by them and the gate would be a convention. Here [`OptedIn`]'s field is private
/// to this module and [`opt_in_or_record_skip`] is its only constructor — which makes "no leg
/// pulls the image or boots without asking" a **compile error** rather than a source-scan
/// convention. That is the point: the two costly entry points ([`super::pack_systemd_rootfs`] and
/// [`super::boot_systemd_cell`]) each take an `OptedIn`, so a new leg that forgets the guard does
/// not build.
mod opt_in {
    /// The environment variable `just test-systemd` sets, and the only thing that lets the live
    /// legs here do any work.
    ///
    /// A *presence* switch rather than a value switch: there is nothing to configure, and a value
    /// vocabulary would be one more accepted input to honor or reject. Any non-empty value opts
    /// in; empty is treated as unset, because `FOO= just …` is how a shell spells "no".
    pub const OPT_IN_ENV: &str = "VMCELL_TEST_SYSTEMD";

    /// Proof that this run opted into the systemd proof cell.
    ///
    /// Constructible only by [`opt_in_or_record_skip`] (the tuple field is private to this
    /// module), and required by every function that pulls the image or boots a guest.
    #[derive(Clone, Copy, Debug)]
    pub struct OptedIn(());

    /// `Some(OptedIn)` when this run opted in; `None`, after recording a reviewable capability
    /// skip, otherwise.
    ///
    /// The recorded skip rather than a hard failure is the `usb_passthrough` shape and the same
    /// recorded deviation from "skips go through `require_cap!` only": `test-privileged` selects
    /// these legs, and hard-failing every KVM host that has not opted into a large network pull
    /// would make the privileged suite unrunnable.
    #[must_use]
    pub fn opt_in_or_record_skip() -> Option<OptedIn> {
        if std::env::var_os(OPT_IN_ENV).is_some_and(|v| !v.is_empty()) {
            return Some(OptedIn(()));
        }
        crate::common::record_capability_skip(
            "cloud-hypervisor",
            "systemd_proof_cell_not_opted_in",
        );
        println!(
            "SKIP: the v33 delta-9 systemd proof cell pulls a ~59 MB image; run \
             `just test-systemd` (which sets {OPT_IN_ENV}) to exercise it"
        );
        None
    }
}

use opt_in::{OPT_IN_ENV, OptedIn, opt_in_or_record_skip};

/// A justfile with its comment lines removed, so prose that merely *names* the opt-in variable is
/// never counted as an opt-in.
///
/// The `ban-ci-script-handcopy.sh` rule, applied one file over: that gate strips line comments
/// before asserting no ci.yml line names a script, for exactly this reason.
fn without_comments(text: &str) -> String {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The `justfile` recipe body for `name`, or `None` when there is no such recipe.
///
/// A recipe is `^<name>:` followed by every line that is indented (or blank) until the next line
/// starting at column 0. Deliberately a tiny, total extractor rather than a call out to
/// `just --show`: this test runs in `just test-unit`/`cargo test`, where a `just` binary is not
/// guaranteed to be on `PATH`, and the property under test is textual anyway.
fn justfile_recipe_body<'a>(justfile: &'a str, name: &str) -> Option<&'a str> {
    let header = format!("\n{name}:");
    let start = justfile.find(&header)? + header.len();
    let rest = &justfile[start..];
    let end = rest
        .match_indices('\n')
        .find(|(i, _)| {
            let line = rest[i + 1..].lines().next().unwrap_or("");
            !line.is_empty() && !line.starts_with([' ', '\t'])
        })
        .map_or(rest.len(), |(i, _)| i);
    Some(&rest[..end])
}

/// **The opt-in gate** (§18 delta 9): `just test-systemd` is the one recipe that opts in, it is
/// runner-wrapped like every sibling live suite, and its filter selects this binary.
///
/// Both directions matter and both are asserted, because each catches a different way the opt-in
/// stops holding:
///
/// * the export missing from `test-systemd` → the recipe selects these legs and they all skip, so
///   the capstone silently stops running while its recipe reports success;
/// * the export appearing anywhere else — `test-privileged` above all — → every KVM host starts
///   pulling a ~59 MB image, which is the exact cost `test-crosvm`'s header says opt-in exists to
///   avoid.
///
/// KVM-free on purpose: an opt-in whose wiring could only be checked on a KVM host would be
/// checked by the runs that already opted in.
///
/// RED ON INVERSE: delete the `VMCELL_TEST_SYSTEMD=1` line from the recipe (arm 1 fails), or add
/// it to `test-privileged` (arm 3 fails), or drop the runner export (arm 2 fails).
#[test]
fn the_opt_in_is_declared_by_the_systemd_recipe_and_by_no_other() {
    const JUSTFILE: &str = include_str!("../../../justfile");

    let body = justfile_recipe_body(JUSTFILE, "test-systemd").unwrap_or_else(|| {
        panic!(
            "the justfile must carry a `test-systemd` recipe: it is delta 9's named gate, and \
             AGENTS.md describes it in the present tense at three sites"
        )
    });

    // 1. It opts in. Composed from the const, so a rename of the variable moves both sides at once.
    assert!(
        body.contains(&format!("{OPT_IN_ENV}=")),
        "`just test-systemd` must set {OPT_IN_ENV}, or every leg it selects skips and the recipe \
         reports a green run that exercised nothing. Recipe body:\n{body}"
    );

    // 2. It is runner-wrapped and skip-manifest-scoped, like every sibling live suite, and it
    //    actually selects this binary's legs.
    for needle in [
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER",
        "VMCELL_SKIP_MANIFEST",
        "--no-tests=fail",
        "systemd_cell",
    ] {
        assert!(
            body.contains(needle),
            "`just test-systemd` must carry {needle:?} — the shape every sibling live-suite \
             recipe has. Recipe body:\n{body}"
        );
    }

    // 3. THE opt-in property: nothing else in the justfile sets it. `test-privileged` selects
    //    these legs too (its filterset excludes only unprivileged/smoltcp), so this export is the
    //    only thing standing between a routine privileged run and a ~59 MB pull. Counted over the
    //    comment-stripped text, so the prose above the recipe (which names the variable) is not a
    //    false positive — and a commented-out export is not a false negative either.
    let occurrences = without_comments(JUSTFILE).matches(OPT_IN_ENV).count();
    let in_body = without_comments(body).matches(OPT_IN_ENV).count();
    assert_eq!(
        occurrences, in_body,
        "{OPT_IN_ENV} is set {occurrences} time(s) in the justfile but only {in_body} inside the \
         `test-systemd` recipe: some other recipe opts in, so the proof cell is no longer opt-in \
         and every run of that recipe pulls the image"
    );
    assert_eq!(
        in_body, 1,
        "the `test-systemd` recipe must set {OPT_IN_ENV} exactly once (found {in_body}); zero \
         means every leg it selects skips and the recipe reports a green run that exercised \
         nothing"
    );
}

// -----------------------------------------------------------------------------------------------
// The artifact: the registered `debian-systemd` label, packed with the steward's unit baked in.
// -----------------------------------------------------------------------------------------------

/// The committed `rootfs` registry label this cell boots (§10.5). Resolved through
/// [`vmcell::artifact::resolve_rootfs_entry`] below, which fails loud if the pins no longer carry
/// it — so a rename cannot leave this file silently packing the default base.
const SYSTEMD_ROOTFS_LABEL: &str = "debian-systemd";

/// The `init=` target: systemd's real binary, not the `/usr/sbin/init` symlink beside it. Both
/// exist in the image; naming the binary keeps the leg's failure mode "systemd did not come up"
/// rather than "the kernel could not resolve a symlink".
const SYSTEMD_INIT: &str = "/usr/lib/systemd/systemd";

/// The declared `Service` port. **Non-default on purpose**: the default emits no
/// `vmcell_steward_port=` token at all, so a default-port cell cannot tell a steward that read the
/// kernel cmdline from one that merely fell back. Under systemd the steward is started by a unit
/// file that says nothing about ports — it still has to read `/proc/cmdline` — which is a fact
/// only this composition can show.
const DECLARED_PORT: u32 = 5200;

/// Scratch inside the guest. **`/run`, not `/tmp`.**
///
/// The root is mounted `ro` — `build_kernel_cmdline` emits it unconditionally and F3 reserves `rw`
/// so no caller can invert it — and under `Service` placement nobody assembles a writable overlay
/// over it (the steward's `assemble_guest_root` runs only under `Pid1`). So scratch has to be a
/// tmpfs, and `/run` is one PID 1 mounts itself before any unit runs. `/tmp` is a tmpfs in this
/// image too, as it happens, but only because a `tmp.mount` unit ran — the very unit this image's
/// packaging un-enables — so depending on it would make these legs hostage to a systemd-version
/// detail rather than to the property under test.
const GUEST_SCRATCH: &str = "/run/vmcell-delta9";

/// systemd's own console announcement that it reached the target the steward's drop-in hooks into
/// — the corroborating serial evidence §18 delta 9 asks for, from the only source that has any.
///
/// **Two contiguous needles rather than one**, because systemd wraps the unit name in ANSI colour
/// codes on the console (`Reached target \x1b[0;1;39mmulti-user.target\x1b[0m - Multi-User
/// System.`), so no single literal spans both halves.
///
/// The obvious needle — a bare `"systemd"` — is **vacuous** and was measured to be: the kernel
/// echoes its whole `Command line:` at boot, and this cell's cmdline says
/// `init=/usr/lib/systemd/systemd`, so the needle matches on a guest where systemd never ran a
/// single instruction. Neither half below can come from anywhere but systemd: the kernel prints
/// no "Reached target" line and the cmdline names no target at all.
const SYSTEMD_REACHED: &str = "Reached target ";
/// See [`SYSTEMD_REACHED`] — the second half, matched separately across the colour codes.
const SYSTEMD_MULTI_USER: &str = "multi-user.target";

/// The steward's systemd unit, baked into the image as an [`ExtraFile`].
///
/// `Restart=always` is delta 5's contract read from systemd's side: a `Service` steward exits
/// cleanly on SIGTERM precisely so the init that started it can bring it back, and here that init
/// is systemd rather than `mini-init`.
///
/// The `[Install]` section is what a consumer would ship and is **inert in this image**:
/// `systemctl enable` installs it by creating a `multi-user.target.wants/` symlink, and
/// [`ExtraFile`](vmcell::artifact::rootfs::ExtraFile) is regular-files-only. The drop-in below is
/// how the unit is actually pulled in — see [`WANTS_DROPIN`].
const STEWARD_UNIT: &str = "\
[Unit]
Description=vmcell steward (vsock control plane)
Documentation=https://example.invalid/vmcell

[Service]
Type=simple
ExecStart=/usr/sbin/vmcell-steward
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
";

/// The in-guest path of [`STEWARD_UNIT`].
const STEWARD_UNIT_DEST: &str = "/etc/systemd/system/vmcell-steward.service";

/// The drop-in that **enables** the unit, and the reason the enablement is a drop-in at all.
///
/// The two routes an artifact-baked enablement can take are a `multi-user.target.wants/<unit>`
/// symlink and a `multi-user.target.d/*.conf` drop-in. The symlink is not expressible — the packer
/// emits symlinks only for the guest-tools applet roster, and `ExtraFile` is documented as
/// regular-files-only — which leaves the drop-in and one alternative outside the artifact
/// entirely: a `systemd.wants=` kernel-cmdline token.
///
/// The drop-in wins, deliberately. `systemd.*` is not in `RESERVED_CMDLINE_KEYS`, so the token
/// *would* be accepted today — and that is the argument against it, not for it: F3's law covers
/// **aliases**, not just key-equal collisions, and `systemd.wants=` is an alias for exactly the
/// kind of boot-time unit selection an artifact is supposed to own. Putting the enablement in the
/// image keeps §18 delta 9's own words true ("the steward installed as a unit baked in via
/// `ExtraFile`"), keeps the cmdline byte-identical to any other `Service` cell's, and means the
/// artifact a consumer registers is self-contained rather than only working when the host
/// remembers to add a token.
const WANTS_DROPIN: &str = "\
# Pulls vmcell-steward.service into multi-user.target. This is `systemctl enable`'s effect,
# expressed as a regular file: the enable symlink itself cannot be baked by `ExtraFile`.
[Unit]
Wants=vmcell-steward.service
";

/// The in-guest path of [`WANTS_DROPIN`]. A `.d` drop-in directory the base image does not ship,
/// so this also exercises the packer's parent-directory synthesis.
const WANTS_DROPIN_DEST: &str = "/etc/systemd/system/multi-user.target.d/10-vmcell-steward.conf";

/// Packs the registered `debian-systemd` rootfs into `staging`, composing `extra` at pack time.
///
/// Everything about the artifact — image, digest, xattr policy, feature declaration — comes from
/// the **one** registry reader ([`vmcell::artifact::resolve_rootfs_entry`]), and the image is
/// produced by the **one** labelled stage, so this leg exercises the delta-6/6c/7 route a consumer
/// takes rather than a hand-assembled parallel one. The `.features` sidecar is emitted beside it by
/// `RootfsFeaturesStage`, which is what makes the §7.4 provenance assertion below reach
/// `Source::Rootfs` at all.
///
/// Never into the canonical artifacts dir (M-BIN-6): packing there would clobber the image every
/// other suite boots. The OCI blob cache is sited on the artifacts dir rather than on `staging`, so
/// the ~59 MB pull is paid once per machine and not once per leg.
///
/// Returns `(packed image path, the resolved registry entry)`.
///
/// Takes an [`OptedIn`] because this is the function that performs the ~59 MB network pull on a
/// cold cache — the cost the opt-in exists to keep off `test-privileged`.
async fn pack_systemd_rootfs(
    _opted_in: OptedIn,
    staging: &std::path::Path,
    extra: Vec<vmcell::artifact::rootfs::ExtraFile>,
) -> (std::path::PathBuf, vmcell::artifact::RootfsRegistryEntry) {
    std::fs::create_dir_all(staging).expect("create the staging dir");

    let overlay = vmcell::artifact::pins_overlay_path();
    let entry = vmcell::artifact::resolve_rootfs_entry(
        Some(SYSTEMD_ROOTFS_LABEL),
        overlay.as_deref(),
    )
    .expect("the rootfs registry must resolve")
    .unwrap_or_else(|| {
        panic!(
            "the committed pins must register `rootfs.{SYSTEMD_ROOTFS_LABEL}` (§18 delta 9): \
                 without it this leg would pack the default base and prove nothing about systemd"
        )
    });
    assert!(
        matches!(
            entry.registration,
            vmcell::artifact::RootfsRegistration::Digest { .. }
        ),
        "the proof cell's base must be a DIGEST registration (R7 — a path is an override, never a \
         registration): got {:?}",
        entry.registration
    );

    let pipeline = vmcell::artifact::Pipeline::new(staging.to_path_buf())
        .add_stage(Box::new(vmcell::artifact::ResolvePinsStage {
            overlay_file: overlay.clone(),
        }))
        .add_stage(Box::new(vmcell::artifact::steward::StewardStage {}))
        .add_stage(Box::new(
            vmcell::artifact::guest_tools::GuestToolsStage::new(),
        ))
        .add_stage(Box::new(
            vmcell::artifact::rootfs::RootfsStage::labelled(Some(SYSTEMD_ROOTFS_LABEL))
                .with_extra(extra)
                // From the SAME resolved entry the declaration stage below renders, exactly as
                // `vmcell build` wires it: the packed bytes and the declared stance are two
                // readings of one declaration, never two independent decisions.
                .with_xattrs(entry.xattrs),
        ))
        .add_stage(Box::new(
            vmcell::artifact::rootfs::RootfsFeaturesStage::labelled(Some(SYSTEMD_ROOTFS_LABEL))
                .with_features(entry.features.clone()),
        ));
    pipeline
        .build(&vmcell::artifact::Cache::default())
        .await
        .expect("packing the registered `debian-systemd` rootfs must succeed");

    let image = staging.join(vmcell::artifact::rootfs::rootfs_filename(
        Some(SYSTEMD_ROOTFS_LABEL),
        vmcell::artifact::RootfsFormat::Erofs,
    ));
    assert!(
        image.exists(),
        "the labelled rootfs stage must write {}",
        image.display()
    );
    // The §7.4 declaration sidecar has to be beside it, or `resolve_cell_features` reads a
    // baseline declaration and the provenance assertion below passes for the wrong reason.
    let sidecar = vmcell::feature::feature_manifest_path(&image);
    assert!(
        sidecar.exists(),
        "the declaration sidecar must be emitted beside the image at {}",
        sidecar.display()
    );
    (image, entry)
}

/// The two [`ExtraFile`](vmcell::artifact::rootfs::ExtraFile)s that install the steward as a unit,
/// with their host-side sources written into `dir`.
fn steward_unit_files(dir: &std::path::Path) -> Vec<vmcell::artifact::rootfs::ExtraFile> {
    use vmcell::artifact::rootfs::ExtraFile;
    let unit_src = dir.join("vmcell-steward.service");
    let dropin_src = dir.join("10-vmcell-steward.conf");
    std::fs::write(&unit_src, STEWARD_UNIT).expect("write the unit source");
    std::fs::write(&dropin_src, WANTS_DROPIN).expect("write the drop-in source");
    vec![
        ExtraFile::new(STEWARD_UNIT_DEST, unit_src, 0o644),
        ExtraFile::new(WANTS_DROPIN_DEST, dropin_src, 0o644),
    ]
}

/// Boots `image` as a `Service`-placement cell whose PID 1 is real systemd.
///
/// Takes an [`OptedIn`] for the reason [`pack_systemd_rootfs`] does: booting is the other half of
/// the cost, and a token on both is what makes a guard-less leg fail to compile.
async fn boot_systemd_cell(
    _opted_in: OptedIn,
    vmm: &vmcell::vmm::cloud_hypervisor::CloudHypervisor,
    image: std::path::PathBuf,
) -> vmcell::MicroVm<vmcell::vmm::cloud_hypervisor::CloudHypervisor> {
    let cfg = VmConfig::builder(common::get_vmlinux(), RootfsSource::Erofs { image })
        .init(SYSTEMD_INIT)
        .steward_placement(StewardPlacement::Service {
            port: DECLARED_PORT,
        })
        // systemd's own status output goes to `/dev/console`, which is this cell's only
        // observable while the control plane is still coming up (and the ONLY one at all in the
        // steward-less leg).
        .kernel_verbosity(KernelVerbosity::Verbose)
        .network_disabled()
        .build()
        .expect("`Service` placement composes with a custom init — only `Pid1` + init is refused");

    common::start_vm(vmm, cfg).await
}

/// Polls the serial log until it contains `needle`, or fails naming what it was waiting for.
///
/// The `service_steward.rs` helper, copied rather than shared: cross-binary sharing would mean
/// putting a live-VM poller into `tests/common`, which every KVM-free binary in the crate then
/// links.
async fn await_serial<V: vmcell::vmm::Vmm>(
    vm: &vmcell::MicroVm<V>,
    needle: &str,
    within: Duration,
) -> String {
    let log = vmcell::vmm::VmInstance::serial_log(vm.instance()).to_path_buf();
    let deadline = std::time::Instant::now() + within;
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        if let Ok(content) = tokio::fs::read_to_string(&log).await {
            if content.contains(needle) {
                return content;
            }
            last = content;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let tail: String = last
        .chars()
        .skip(last.chars().count().saturating_sub(4000))
        .collect();
    panic!(
        "serial log never contained {needle:?} within {within:?} (log {}); tail:\n{tail}",
        log.display(),
    );
}

/// The trimmed stdout of one guest command, failing loud with stderr and the exit code.
async fn sh_out(steward: &mut vmcell::StewardClient, script: &str) -> String {
    let out = steward
        .exec(
            ExecRequest::new(vec!["/bin/sh".into(), "-c".into(), script.into()])
                .with_timeout(Duration::from_secs(120)),
        )
        .await
        .unwrap_or_else(|e| panic!("exec {script:?} failed: {e}"));
    assert_eq!(
        out.code,
        0,
        "`sh -c {script:?}` exited {}: stderr {:?}",
        out.code,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

// -----------------------------------------------------------------------------------------------
// The capstone.
// -----------------------------------------------------------------------------------------------

/// **The proof cell** (§18 delta 9): real systemd as PID 1, the steward as one of its units, the
/// control plane driven end to end, and the composed feature set carrying the registered
/// artifact's own provenance.
///
/// Read as a sequence of claims, each of which some earlier delta asserted only against a fake or
/// against an init vmcell wrote:
///
/// 1. **systemd really is PID 1** — `/proc/1/comm`, plus `systemctl` and `systemd-run` on `PATH`
///    and uid 0, which is what §18 delta 9 records the downstream consumer's probe mechanism as
///    needing. Not a serial-log substring: `comm` is the kernel's own answer.
/// 2. **The steward is a systemd UNIT** — `systemctl is-active vmcell-steward.service`. This is
///    the assertion that separates "the steward is running" from "systemd started it": a steward
///    that somehow came up by another route leaves the unit `inactive`.
/// 3. **The declared port travelled** — the cell declares 5200, so the steward can only be
///    answering because it read `vmcell_steward_port=` off `/proc/cmdline` under systemd. The
///    default 5000 must have nobody on it, proved at the wire with a placement-blind dial.
/// 4. **`exec`, `put_file` and sessions all work**, each asserted on data rather than on a code.
/// 5. **§7.4 provenance** — `why_absent(SnapshotRestore)` names the *rootfs*, not the backend and
///    not the config, because an artifact declaration is the most specific statement about a cell
///    and `Source::axis_rank` puts it first.
/// 6. **§8.1's per-op law stays authoritative** — `snapshot()` refuses with the C8 placement arm
///    even though the intersection already removed the feature for a different reason. The pair is
///    the honest picture of a doubly-unavailable operation.
/// 7. **The §10.6 kit runs green over the composition**, with the one under-claim it finds
///    dispositioned rather than hidden.
#[tokio::test]
#[ignore = "needs KVM + the opt-in (`just test-systemd`); pulls a ~59 MB image"]
async fn systemd_cell_boots_real_systemd_with_the_steward_as_a_unit() {
    let Some(opted_in) = opt_in_or_record_skip() else {
        return;
    };

    // Ensure the canonical artifacts FIRST: that is what warms the shared OCI blob cache and
    // builds the kernel this cell boots (at most once across the suite).
    let _ = common::get_rootfs();

    // `TempDir`s, not per-pid directories removed on the success path: a panicking assertion below
    // must not leave a ~200 MB image behind, and cleanup has to be on the panic path too.
    let src_dir = tempfile::tempdir().expect("unit-source tempdir");
    let staging_dir = tempfile::tempdir().expect("staging tempdir");
    let (image, entry) = pack_systemd_rootfs(
        opted_in,
        staging_dir.path(),
        steward_unit_files(src_dir.path()),
    )
    .await;

    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    let mut vm = boot_systemd_cell(opted_in, &vmm, image.clone()).await;

    // ---- 5. §7.4 provenance, read before anything boots a second VM ----------------------------
    //
    // Computed at `start`, so it is available regardless of whether the control plane came up —
    // and asserted first for exactly that reason: a transport failure below must not hide whether
    // the declaration travelled.
    {
        use vmcell::feature::{Feature, Source};
        let removal = vm
            .features()
            .why_absent(Feature::SnapshotRestore)
            .unwrap_or_else(|| {
                panic!(
                    "the registered `{SYSTEMD_ROOTFS_LABEL}` artifact declares \
                     `{}: false`, so the composed set must not carry it",
                    Feature::SnapshotRestore.name()
                )
            });
        // The declaration really is the entry's, not a coincidence of the backend's descriptor.
        assert_eq!(
            entry.features.get(&Feature::SnapshotRestore),
            Some(&false),
            "the registry entry itself must carry the stance this removal is attributed to"
        );
        // `Source::Rootfs` carries the artifact's on-disk FILENAME, which is what
        // `resolve_cell_features` composes it from — recomputed here through the one filename law
        // rather than spelled out, so a change to either side reddens instead of drifting. (§18
        // delta 9's text says `Source::Rootfs("debian-systemd")`, i.e. the bare label; the shipped
        // constructor and delta 6c's own gates both say the filename. Asserting what the code
        // produces keeps one law rather than adding a second.)
        assert_eq!(
            removal.by,
            Source::Rootfs(vmcell::artifact::rootfs::rootfs_filename(
                Some(SYSTEMD_ROOTFS_LABEL),
                vmcell::artifact::RootfsFormat::Erofs,
            )),
            "the removal must be attributed to the ROOTFS axis — an artifact declaration is the \
             most specific statement about a cell, and `Source::axis_rank` ranks it above the \
             backend and the config. Got {removal:?}"
        );
        assert_eq!(
            removal.feature,
            Feature::SnapshotRestore,
            "the removal names the feature it is about (F6)"
        );
    }

    let steward = vm.steward(Some(Duration::from_secs(90))).await.expect(
        "the steward must be reachable on the declared port under real systemd. A timeout \
             here means systemd never started the unit (check the drop-in), or the steward did \
             not bind the declared port.",
    );

    // ---- 1. systemd really is PID 1 -----------------------------------------------------------
    assert_eq!(
        sh_out(steward, "cat /proc/1/comm").await,
        "systemd",
        "PID 1 must be real systemd — the whole point of this cell. A `vmcell-steward` here means \
         the cell fell back to the default init and every assertion below is about the ordinary \
         Pid1 path."
    );
    assert_eq!(
        sh_out(steward, "id -u").await,
        "0",
        "the control plane runs as uid 0 (the consumer's probe mechanism depends on it)"
    );
    // `systemctl` and `systemd-run` resolvable on the exec PATH, which is what a consumer's own
    // probe needs and what a base-variant Debian image cannot provide at all.
    assert_eq!(
        sh_out(
            steward,
            "command -v systemctl >/dev/null && command -v systemd-run >/dev/null && echo both"
        )
        .await,
        "both",
        "the registered image must ship systemctl AND systemd-run; the pinned `default` base ships \
         neither, which is why delta 9 needs its own registration"
    );

    // ---- 2. The steward is one of systemd's units ----------------------------------------------
    assert_eq!(
        sh_out(steward, "systemctl is-active vmcell-steward.service").await,
        "active",
        "the steward must be an ACTIVE systemd unit, not merely a running process: this is the \
         difference between `Service` placement working and something else having started it"
    );
    // Non-vacuity for the line above: `is-active` on a unit nobody installed answers `inactive`
    // (and exits non-zero), so a shell that reported `active` for everything would fail here.
    let bogus = steward
        .exec(ExecRequest::new(vec![
            "systemctl".into(),
            "is-active".into(),
            "vmcell-no-such-unit.service".into(),
        ]))
        .await
        .expect("exec the negative control");
    assert_ne!(
        bogus.code, 0,
        "`systemctl is-active` on an uninstalled unit must fail — otherwise the assertion above \
         is satisfied by any answer at all"
    );
    // …and the steward's pid is NOT 1, which is what makes this a service placement rather than a
    // Pid1 cell wearing a unit file.
    let steward_pid: u32 = sh_out(
        steward,
        "systemctl show -p MainPID --value vmcell-steward.service",
    )
    .await
    .parse()
    .expect("systemd must report the unit's MainPID");
    assert_ne!(
        steward_pid, 1,
        "under `Service` placement the steward must not be pid 1 — systemd is"
    );
    assert_eq!(
        sh_out(steward, &format!("cat /proc/{steward_pid}/comm")).await,
        "vmcell-steward",
        "systemd's MainPID for the unit must really be the steward process"
    );

    // ---- 4. exec / put_file / sessions ---------------------------------------------------------
    //
    // Scratch under /run: see GUEST_SCRATCH. Created through the control plane, so a later
    // `put_file` into it is a genuine round trip rather than a write into a directory the image
    // happened to ship.
    assert_eq!(
        sh_out(steward, &format!("mkdir -p {GUEST_SCRATCH} && echo made")).await,
        "made"
    );
    const PUT_BYTES: &[u8] = b"vmcell-delta9-put-file\n\xff\x00payload";
    let put_dst = format!("{GUEST_SCRATCH}/put.bin");
    steward
        .put_file(&put_dst, PUT_BYTES, Some(Duration::from_secs(30)))
        .await
        .expect("put_file into the systemd cell");
    // Read the bytes back as hex so a non-UTF-8, NUL-bearing payload is compared exactly rather
    // than through a lossy rendering.
    let want_hex: String = PUT_BYTES.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        sh_out(steward, &format!("od -An -v -tx1 {put_dst} | tr -d ' \\n'")).await,
        want_hex,
        "put_file must land the caller's exact bytes in the systemd cell"
    );

    // ---- 3. The declared port travelled --------------------------------------------------------
    //
    // A placement-blind dial at the wire, because a log line would not exist (the steward logs its
    // bound port at `info`). Nobody on 5000 is what makes "5200 answers" mean the steward MOVED
    // rather than that it bound both.
    let default_port = vm
        .dial_vsock(vmcell_protocol::STEWARD_VSOCK_PORT, Duration::from_secs(5))
        .await;
    assert!(
        default_port.is_err(),
        "the steward must bind ONLY the declared port {DECLARED_PORT}; something is still \
         listening on the default {}",
        vmcell_protocol::STEWARD_VSOCK_PORT
    );

    // Sessions, over the same declared port.
    {
        let mux = vm
            .connect_sessions(Some(Duration::from_secs(30)))
            .await
            .expect("the session mux must connect on the declared port");
        let mut session = mux
            .open(
                SessionSpecBuilder::new(vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "echo session-under-systemd".into(),
                ])
                .build(),
            )
            .await
            .expect("the session must open");
        let mut acc = Vec::new();
        let read = async {
            loop {
                match session.recv().await {
                    Some(SessionEvent::Stdout(d)) => {
                        acc.extend(d);
                        if acc.contains(&b'\n') {
                            return;
                        }
                    }
                    Some(SessionEvent::Exit(c)) => {
                        assert_eq!(c, 0, "the session payload must succeed");
                        return;
                    }
                    Some(_) => {}
                    None => panic!("the session closed before producing output"),
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(30), read)
            .await
            .expect("the session must produce its line well inside 30s");
        assert_eq!(
            String::from_utf8_lossy(&acc).trim(),
            "session-under-systemd",
            "a session's stdout must stream back from a systemd cell"
        );
    }

    // ---- Corroboration on systemd's OWN console output -----------------------------------------
    //
    // Not a steward line (there are none below `error`), and not the kernel's: systemd writes its
    // unit-status lines to `/dev/console`, which is this cell's serial port. It is already there
    // by now, so this reads rather than waits.
    let serial = await_serial(&vm, SYSTEMD_MULTI_USER, Duration::from_secs(30)).await;
    assert!(
        serial.contains(SYSTEMD_REACHED),
        "systemd must announce reaching a target on the console — the half of the needle the \
         colour codes split off (see SYSTEMD_REACHED)"
    );
    assert!(
        !serial.contains("Kernel panic"),
        "a booted cell must not have panicked; serial tail:\n{}",
        serial
            .chars()
            .skip(serial.len().saturating_sub(3000))
            .collect::<String>()
    );

    // ---- 6. §8.1's per-op law is authoritative -------------------------------------------------
    {
        use vmcell::feature::{Feature, Source};
        let snap_dir = tempfile::tempdir().expect("snapshot tempdir");
        let err = vm
            .snapshot(snap_dir.path())
            .await
            .expect_err("a `Service`-placement cell can never be snapshotted (C8)");
        let vmcell::Error::Unsupported { vmm: who, feature } = err else {
            panic!("the refusal must be the typed `Unsupported` one, got {err:?}");
        };
        assert_eq!(
            feature,
            Feature::SnapshotRestore.name(),
            "F6: the refusal's feature string IS `Feature::name()`, never a hand-spelled paraphrase"
        );
        assert!(
            who.contains(&Source::Config.to_string()),
            "the refusal is the orchestrator's OWN eligibility law on the config axis, not a \
             backend's: got {who:?}"
        );
        assert!(
            who.starts_with("orchestrator"),
            "a non-backend boundary names itself rather than blaming the VMM: got {who:?}"
        );
        // Non-vacuity: the snapshot really was refused before anything was written.
        assert_eq!(
            std::fs::read_dir(snap_dir.path())
                .expect("read the snapshot dir")
                .count(),
            0,
            "the refusal must happen BEFORE any snapshot bytes are written"
        );
    }

    vm.shutdown().await.expect("shutdown");

    // ---- 7. The §10.6 conformance kit, over this composition ------------------------------------
    //
    // Run after `shutdown()`: the battery boots its own VMs, and one guest at a time keeps the
    // cost linear instead of contending for the host.
    run_conformance_over_the_composition(&vmm, &image).await;

    // Drops the ~200 MB of staging. The shared OCI blob cache lives in the artifacts dir, not
    // here, so the next run still gets its cache hit.
    drop(staging_dir);
    drop(src_dir);
}

/// The §10.6 two-directional battery over the proof cell's artifact pair (§18 delta 3 + delta 2).
///
/// The candidate is the registered `debian-systemd` artifact **with its own declaration** — read
/// from the sidecar the pack emitted, not restated here, so what the battery judges is exactly what
/// the registry says. The control is the canonical pair under a different label, declaring the two
/// features the candidate declares absent; the battery refuses a control that is the candidate, and
/// refuses up front if the control does not declare what the candidate denies.
///
/// **The one `Warn` is dispositioned, not hidden — and it is a real finding, measured here.** The
/// registry entry declares `snapshot_restore: false`, and the kit's probe boots the artifact the
/// ordinary `Pid1` way and watches it snapshot and restore successfully. Both are true: what cannot
/// snapshot is this cell's **placement** (§8.1's per-op arm, asserted separately above), and a
/// placement is a property of the cell, not of the artifact. So the artifact's declaration is an
/// under-claim by §10.6's definition, and the honest verdict is a `Warn` — a documentation defect
/// to triage, not a runtime failure to redden. Leaving it un-dispositioned would promote it to a
/// `Fail`; dispositioning it is what makes the *other* direction of the lifecycle live, because an
/// expectation that stops firing is itself reported as an error.
///
/// **What the xattr leg can and cannot show, stated rather than implied.** The candidate declares
/// `xattr_preserved: false` (derived from its `"xattrs": "strip"`), and the only control this suite
/// has is the canonical pair — also packed `strip`. So the control cannot demonstrate the feature
/// and the verdict is `Unverified`, which is not a failure and is exactly what the validator's own
/// `conformance_live_xattr_probe_*` leg reports for the same reason. The `Works` side is proved by
/// `tests/xattr_policy.rs`, which packs an image that really carries attributes.
///
/// RED ON INVERSE: drop the `expected_warnings` entry (the promoted warning fails the run), or
/// remove `"features": {"snapshot_restore": false}` from the registry entry (the stance disappears,
/// the check becomes a Skip, and the now-stale expectation is reported by the lifecycle).
async fn run_conformance_over_the_composition(
    vmm: &vmcell::vmm::cloud_hypervisor::CloudHypervisor,
    image: &std::path::Path,
) {
    use vmcell::feature::{Feature, FeatureDeclaration, Source};
    use vmcell_artifact_validator::conformance::{
        ArtifactId, ConformanceOptions, ConformanceSubject, LiveProbe, Substrate, run_battery,
    };
    use vmcell_artifact_validator::{ArtifactSet, CheckStatus};

    let candidate_id = ArtifactId::new(SYSTEMD_ROOTFS_LABEL);
    let control_id = ArtifactId::new("canonical-default-control");

    // The candidate's claim, straight off the sidecar the pack emitted (§7.4's travel form).
    let declaration = FeatureDeclaration::load_beside(
        image,
        Source::Rootfs(vmcell::artifact::rootfs::rootfs_filename(
            Some(SYSTEMD_ROOTFS_LABEL),
            vmcell::artifact::RootfsFormat::Erofs,
        )),
    )
    .expect("the emitted declaration sidecar must load");
    assert_eq!(
        declaration.stances.get(&Feature::SnapshotRestore),
        Some(&false),
        "the sidecar must carry the registry entry's declared stance, or the battery below judges \
         a claim nobody made"
    );

    let candidate = ConformanceSubject {
        id: candidate_id.clone(),
        artifacts: ArtifactSet::new(common::get_vmlinux(), image),
        declaration,
    };
    // The control declares present everything the candidate declares absent, over the canonical
    // artifacts — the pair the rest of the suite proves does snapshot.
    let control = {
        let mut d = FeatureDeclaration::baseline(Source::Rootfs(control_id.to_string()));
        for (feature, stance) in &candidate.declaration.stances {
            if !stance {
                d.stances.insert(*feature, true);
            }
        }
        ConformanceSubject {
            id: control_id.clone(),
            artifacts: ArtifactSet::new(common::get_vmlinux(), common::get_rootfs()),
            declaration: d,
        }
    };

    let opts = ConformanceOptions {
        expected_warnings: [(Feature::SnapshotRestore, candidate_id.clone())]
            .into_iter()
            .collect(),
        ..ConformanceOptions::default()
    };
    let report = run_battery(
        &LiveProbe::new(vmm),
        &Substrate::of(vmm),
        &candidate,
        &control,
        &opts,
    )
    .await
    .expect("the battery must run over the proof cell's composition");
    for o in &report.outcomes {
        println!("[{:?}] {} -> {:?}", o.level, o.id, o.status);
    }

    // The declared-absence leg really was MEASURED. A `Skip` here would mean the substrate could
    // not exercise the feature and nothing booted; an `Unverified` would mean the control could
    // not demonstrate it. Either way the green report below would be certifying nothing, which is
    // §10.6's own "a constant that certifies everything".
    let snapshot = report
        .outcomes
        .iter()
        .find(|o| o.id == "conformance.snapshot_restore")
        .expect("the paired snapshot check is in the roster");
    let CheckStatus::Warn(why) = &snapshot.status else {
        panic!(
            "measured live (2026-08-16): the `{SYSTEMD_ROOTFS_LABEL}` artifact snapshots fine when \
             booted the ordinary `Pid1` way — what cannot snapshot is this cell's `Service` \
             PLACEMENT, which is a per-op eligibility arm and not an intersection axis. So the \
             entry's `{}: false` is an UNDER-CLAIM by the kit's definition and the honest verdict \
             is a dispositioned Warn. Got {:?}",
            Feature::SnapshotRestore.name(),
            snapshot.status
        );
    };
    // …and the paired probe really ran TWICE: the verdict names the positive control, which is what
    // separates "the probe measured this artifact" from "the probe always answers absent".
    assert!(
        why.contains(control_id.as_str()),
        "the verdict must name the positive control that ran against the same live backend: {why}"
    );
    assert!(
        why.contains(Feature::SnapshotRestore.name()),
        "F6: the verdict names the feature through the vocabulary, never a paraphrase: {why}"
    );

    // The OTHER direction of the lifecycle: an expectation that no longer fires is itself an
    // error. This check passing is what says the disposition above is still earning its place —
    // and it is the assertion that reddens if the registry entry stops declaring the stance.
    let lifecycle = report
        .outcomes
        .iter()
        .find(|o| o.id == "conformance.expected_warnings")
        .expect("the lifecycle check is in the roster");
    assert_eq!(
        lifecycle.status,
        CheckStatus::Pass,
        "the dispositioned warning must still fire; a stale expectation is reported as an error of \
         its own (§10.6)"
    );

    assert!(
        report.is_ok(),
        "the §10.6 kit must be green over the composition; failures: {:?}",
        report.failures().collect::<Vec<_>>()
    );
}

/// **The respecified reddening leg** (§18 delta 9's "drop the unit file and the steward must be
/// unreachable").
///
/// The design's sketch says the fail-loud "names the placement". It cannot, and this leg is the
/// honest form of the same experiment. `StewardPlacement::Service { port }` always has
/// `steward_port() == Some(port)`, so `MicroVm::steward` never reaches the
/// `StewardPlacement::None` fail-loud arm — it goes to the transport and, with nothing listening,
/// returns `Error::Timeout`. Asserting the placement message here would have asserted something
/// unreachable; asserting the timeout **plus refusal identity** (the message does *not* name
/// `StewardPlacement::None`) is the property that actually distinguishes the two.
///
/// Everything else is identical to the capstone's cell — same registry entry, same base layers,
/// same pack tail, same cmdline — so the single variable really is the unit file. That makes this
/// the capstone's negative control and the capstone its positive one.
///
/// One **bounded** connect rather than the retrying form, for the reason `service_steward.rs`
/// measured: with nothing listening, a retry loop turns a 20-second answer into a ten-minute
/// stall, and a stalled leg is indistinguishable from a slow box.
#[tokio::test]
#[ignore = "needs KVM + the opt-in (`just test-systemd`); pulls a ~59 MB image"]
async fn systemd_cell_without_the_steward_unit_times_out_without_naming_the_placement() {
    let Some(opted_in) = opt_in_or_record_skip() else {
        return;
    };

    let _ = common::get_rootfs();

    let staging_dir = tempfile::tempdir().expect("staging tempdir");
    // THE one variable: no unit, no drop-in. The steward BINARY is still injected at
    // /usr/sbin/vmcell-steward (that injection is unconditional, invariant F5) — nothing starts it.
    let (image, _entry) = pack_systemd_rootfs(opted_in, staging_dir.path(), Vec::new()).await;

    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    let mut vm = boot_systemd_cell(opted_in, &vmm, image).await;

    // Non-vacuity FIRST, on systemd's own console output: the guest really booted, so the timeout
    // below is "nobody is listening" and not "the cell never came up". This is the corroboration
    // the design asks for, taken from the only source that exists here — the steward is not
    // running to log anything, and there is no `mini-init` printing either.
    let serial = await_serial(&vm, SYSTEMD_MULTI_USER, Duration::from_secs(120)).await;
    assert!(
        serial.contains(SYSTEMD_REACHED),
        "systemd must announce reaching a target on the console — see SYSTEMD_REACHED for why the \
         needle is in two halves, and why the obvious one-word needle is vacuous here"
    );

    let err = tokio::time::timeout(
        Duration::from_secs(60),
        vm.steward(Some(Duration::from_secs(20))),
    )
    .await
    .expect("a single bounded connect must ANSWER inside its budget, not stall")
    .expect_err("with no unit installed there is no steward to answer");

    assert!(
        matches!(err, vmcell::Error::Timeout(_)),
        "a `Service` cell with no steward reaches the TRANSPORT and times out; got {err:?}"
    );
    let msg = err.to_string();
    assert!(
        !msg.contains("StewardPlacement::None"),
        "REFUSAL IDENTITY: `steward()` took the placement fail-loud arm for a `Service` cell. Some \
         guard is keyed on `cfg.init.is_some()` again — the exact conflation v33 removed. Got: \
         {msg}"
    );

    // At the wire, placement-blind: nobody is listening on the declared port. This is the same
    // fact one layer down, and it is what rules out "the client gave up early".
    assert!(
        vm.dial_vsock(DECLARED_PORT, Duration::from_secs(5))
            .await
            .is_err(),
        "with no unit installed, the declared port {DECLARED_PORT} must have no listener"
    );

    vm.kill().await.expect("kill");
    drop(staging_dir);
}
