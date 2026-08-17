//! The downstream consumer's own program (design §5.6 / §10.4; v30 §18 delta 5, extended by the
//! v33 register's registry, declaration and conformance surface).
//!
//! Three subcommands, deliberately separate **processes** rather than functions or `#[test]`s:
//!
//! * `getters` — the §10.4 harness-getter contract probe. `vmcell::artifact::ensure_test_artifacts`
//!   memoizes its outcome in a process-global `OnceLock`, so the "full override set" leg and the
//!   "no override set" leg cannot both run in one process without the first poisoning the second.
//!   `ci-check.sh` runs this subcommand twice, with different environments.
//! * `bins` — the other half of the `VMCELL_*` table (§10.4): the four backend-binary resolvers,
//!   which are *the* documented way any harness finds a VMM. A separate process for the same reason
//!   `getters` is: the contract is about what the environment does, so the assertion has to be made
//!   from outside it.
//! * `live` — the toolkit end to end: build `vmlinux-ikconfig` from this consumer's overlay, assert
//!   the fragment survived in the resolved-config sidecar, emit and read back the §7.4 feature
//!   manifests, run the validator battery **and** the two-directional conformance battery, then
//!   prove the fragment took **on the data plane** by reading `/proc/config.gz` out of the booted
//!   guest. Needs `/dev/kvm` and a rootfs (`VMCELL_ROOTFS`), so it runs on the self-hosted KVM job.

#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use downstream_kernel::{
    IN_GUEST_CONFIG, KERNEL_DECLARES, KERNEL_LABEL, ROOTFS_LABEL, artifacts_dir,
    conformance_candidate, emit_feature_manifest, fragment_survived, guest_config_round_trips,
    handler_entry, overlay_path, positive_control, read_resolved_config, registry_entry,
    rootfs_entry,
};
use vmcell::config::{RootfsSource, VmConfig};
use vmcell::feature::{FeatureDeclaration, Source, feature_manifest_path};
use vmcell::vmm::cloud_hypervisor::CloudHypervisor;
use vmcell_artifact_validator::conformance::{
    ConformanceOptions, LiveProbe, Substrate, conformance_check_id, run_battery,
};
use vmcell_artifact_validator::harness;
use vmcell_artifact_validator::kconfig::KconfigValues;
use vmcell_artifact_validator::{ArtifactSet, CheckStatus, ValidationOptions, validate};

/// How long the steward gets to come up before the live leg calls the boot failed. The battery
/// has already booted this exact kernel by the time this runs, so a generous single budget is
/// enough; it is stated once here rather than inline at the call.
const STEWARD_BUDGET: Duration = Duration::from_secs(60);

/// Usage text — one statement of the subcommand roster, printed by both the no-argument and the
/// unknown-argument paths.
const USAGE: &str = "usage: downstream-kernel <getters|bins|live>";

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let outcome = match args.next().as_deref() {
        Some("getters") => cmd_getters(),
        Some("bins") => cmd_bins(),
        Some("live") => cmd_live().await,
        other => {
            eprintln!("downstream-kernel: unknown subcommand {other:?}\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("downstream-kernel: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The §10.4 harness-getter contract, from the consumer position.
///
/// With `VMCELL_KERNEL` + `VMCELL_ROOTFS` set — the documented downstream configuration — the
/// getters return exactly those paths after an existence check, and this prints them so the caller
/// can assert the identity rather than merely that "something came back".
///
/// **Without** them the getters must fail loud. This function deliberately does not catch that:
/// the panic *is* the observable contract, and `ci-check.sh` asserts both the non-zero exit and
/// the message's content. Anything that turned the missing-override case into a quiet build
/// attempt against the consumer's cargo checkout would show up here as an unexpected success.
fn cmd_getters() -> Result<(), String> {
    for var in [
        "VMCELL_ARTIFACTS_DIR",
        "VMCELL_KERNEL",
        "VMCELL_ROOTFS",
        "VMCELL_PINS",
    ] {
        println!(
            "env {var}={}",
            std::env::var(var).unwrap_or_else(|_| "<unset>".to_string())
        );
    }
    let vmlinux = harness::get_vmlinux();
    let rootfs = harness::get_rootfs();
    println!("vmlinux={}", vmlinux.display());
    println!("rootfs={}", rootfs.display());
    Ok(())
}

/// The backend-binary half of the `VMCELL_*` contract (§10.4).
///
/// `VMCELL_CH_BIN` / `_FC_BIN` / `_QEMU_BIN` / `_CROSVM_BIN` are the **one** way any harness —
/// `bench-vm` included — finds a VMM binary, and the resolvers' two behaviors are the contract: the
/// named path verbatim when the variable is set, the documented default name when it is not. Both
/// are printed so `ci-check.sh` can assert the identity rather than merely that "something came
/// back"; a resolver that ignored its variable prints the default in the set case and reddens there.
fn cmd_bins() -> Result<(), String> {
    println!("ch={}", harness::ch_bin());
    println!("fc={}", harness::fc_bin());
    println!("qemu={}", harness::qemu_bin());
    println!("crosvm={}", harness::crosvm_bin());
    Ok(())
}

/// The toolkit end to end (§5.6): overlay → labelled build → sidecar assertion → battery →
/// in-guest `/proc/config.gz`.
async fn cmd_live() -> Result<(), String> {
    let overlay = overlay_path();
    let dir = artifacts_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("creating this consumer's artifacts dir {dir:?} failed: {e}"))?;

    // 1. The overlay resolves and declares the fragment (deltas 1 + 3).
    let entry = registry_entry()?;
    println!(
        "resolved kernels.{} fragments={:?} (overlay {})",
        entry.label,
        entry.fragments,
        overlay.display()
    );

    // 2. The library build entry point — the half of the toolkit a git-dep consumer calls from its
    //    own harness, with no vmcell CLI and no vmcell workspace bootstrap involved.
    let kernel = vmcell::artifact::build_labelled_kernel(KERNEL_LABEL, &dir, Some(&overlay))
        .await
        .map_err(|e| format!("build_labelled_kernel({KERNEL_LABEL}) failed: {e}"))?;
    println!("built {}", kernel.display());

    // 3. Assert against the RESULT, not the fragment: the resolved-config sidecar (delta 3) parsed
    //    by the validator's `KconfigValues` (delta 4).
    let sidecar = read_resolved_config(&kernel)?;
    fragment_survived(&sidecar, "resolved-config sidecar")?;
    println!(
        "sidecar records {} symbols; the {} fragment survived olddefconfig",
        sidecar.len(),
        KERNEL_LABEL
    );

    // 4. The v33 registry and its declarations (§10.5), from the same overlay: the `rootfs` and
    //    `handlers` namespaces this consumer added, and the feature-manifest sidecar the shipped
    //    pipeline emits for the labelled rootfs (§7.4). The IMAGE that sidecar describes is not built
    //    here — packing one needs an OCI pull, and the env contract is how a downstream consumes a
    //    rootfs — but the declaration half is the half a path-consuming cell actually reads.
    let rootfs_entry = rootfs_entry()?;
    let handler = handler_entry()?;
    println!(
        "resolved rootfs.{} xattrs={} features={:?}; handlers.{} applets={:?}",
        rootfs_entry.label,
        rootfs_entry.xattrs.name(),
        rootfs_entry
            .features
            .iter()
            .map(|(f, s)| format!("{f}={s}"))
            .collect::<Vec<_>>(),
        handler.label,
        handler.applet_roster()
    );
    let manifest = emit_feature_manifest(&dir).await?;
    println!(
        "emitted the {ROOTFS_LABEL} declaration at {}",
        manifest.display()
    );

    // 5. This consumer's KERNEL declares one property about itself, and a declaration travels in the
    //    sidecar beside the artifact (§7.4). Authored here rather than resolved, because the `kernels`
    //    registry has no `features` key — a downstream kernel producer is the declarer, and
    //    `feature_manifest_path`'s own contract covers `vmlinux` → `vmlinux.features`.
    let declared = FeatureDeclaration {
        source: None,
        stances: [(KERNEL_DECLARES, true)].into_iter().collect(),
    };
    std::fs::write(feature_manifest_path(&kernel), declared.render_manifest()).map_err(|e| {
        format!(
            "cannot write the kernel's feature manifest beside {}: {e}",
            kernel.display()
        )
    })?;
    let kernel_declaration =
        FeatureDeclaration::load_beside(&kernel, Source::Kernel(KERNEL_LABEL.to_string()))
            .map_err(|e| format!("the kernel's own feature manifest does not read back: {e}"))?;
    if kernel_declaration.stances.get(&KERNEL_DECLARES) != Some(&true) {
        return Err(format!(
            "the kernel's declaration did not survive the sidecar round trip: {:?}",
            kernel_declaration.stances
        ));
    }

    // 6. The level battery against this consumer's own artifact pair. The rootfs comes from
    //    the env contract (`VMCELL_ROOTFS`) — a downstream builds kernels, not rootfs images.
    let rootfs = harness::get_rootfs();
    let artifacts = ArtifactSet::new(kernel.clone(), rootfs.clone());
    let report = validate(&artifacts, &ValidationOptions::default())
        .await
        .map_err(|e| format!("validation battery refused to run: {e}"))?;
    let skipped = report.skipped().count();
    report.into_result().map_err(|failures| {
        let named = failures
            .iter()
            .map(|o| format!("{}: {:?}", o.id, o.status))
            .collect::<Vec<_>>()
            .join("; ");
        format!("validation battery failed: {named}")
    })?;
    println!("validation battery green ({skipped} skipped with reason)");

    // 7. …and the two-directional CONFORMANCE battery (§10.6) over the declaration above, on the
    //    real substrate (backend descriptor × probed host). The kit has no data-plane probe for
    //    `proc_config_gz`, so the honest verdict is `Unverified` — asserted, because "undecided" is
    //    the answer that must never quietly read as a pass. Step 8 is the differential the kit
    //    cannot make.
    let vmm = CloudHypervisor::new(harness::ch_bin());
    let candidate = conformance_candidate(artifacts, kernel_declaration);
    let control = positive_control(&candidate);
    let conformance = run_battery(
        &LiveProbe::new(&vmm),
        &Substrate::of(&vmm),
        &candidate,
        &control,
        &ConformanceOptions::default(),
    )
    .await
    .map_err(|e| format!("the conformance battery refused to run: {e:?}"))?;
    let id = conformance_check_id(KERNEL_DECLARES);
    match conformance.outcomes.iter().find(|o| o.id == id) {
        Some(outcome) => match &outcome.status {
            CheckStatus::Unverified(why) => println!("conformance {id}: Unverified — {why}"),
            other => {
                return Err(format!(
                    "{id} reported {other:?}; this kit has no probe for {}, so anything but \
                     Unverified means the kit's own mapping moved and this consumer's claim is \
                     being judged by something new",
                    KERNEL_DECLARES.name()
                ));
            }
        },
        None => return Err(format!("the conformance battery did not report {id}")),
    }
    conformance.into_result().map_err(|failures| {
        let named = failures
            .iter()
            .map(|o| format!("{}: {:?}", o.id, o.status))
            .collect::<Vec<_>>()
            .join("; ");
        format!("conformance battery failed: {named}")
    })?;

    // 8. The data plane: the booted guest exposes `/proc/config.gz`, which exists only if the
    //    fragment took, and its content round-trips the sidecar.
    prove_in_guest(&kernel, &rootfs, &sidecar).await
}

/// Boots `kernel` + `rootfs` and reads [`IN_GUEST_CONFIG`] back out of the guest.
///
/// This is the assertion the fakes structurally cannot make (v30 §18 delta 5, "live leg
/// non-optional"):
/// a sidecar is a host file a broken producer could publish from any build, while `/proc/config.gz`
/// is produced by the kernel that is actually running.
async fn prove_in_guest(
    kernel: &Path,
    rootfs: &Path,
    sidecar: &KconfigValues,
) -> Result<(), String> {
    let vmm = CloudHypervisor::new(harness::ch_bin());
    let cfg = VmConfig::builder(
        kernel.to_path_buf(),
        RootfsSource::Erofs {
            image: rootfs.to_path_buf(),
        },
    )
    .network_disabled()
    .build()
    .map_err(|e| format!("building the probe VM config failed: {e}"))?;
    let mut vm = harness::try_start_vm(&vmm, cfg)
        .await
        .map_err(|e| format!("the probe VM failed to start on the freshly built kernel: {e}"))?;

    let text = read_in_guest_config(&mut vm).await;
    // The VM is torn down on both arms — a failed probe must not leak a running guest.
    let shutdown = vm.shutdown().await;
    let text = text?;
    shutdown.map_err(|e| format!("probe VM shutdown failed: {e}"))?;

    let guest = KconfigValues::parse(&text)
        .map_err(|e| format!("{IN_GUEST_CONFIG} did not parse as a .config: {e}"))?;
    fragment_survived(&guest, IN_GUEST_CONFIG)?;
    let compared = guest_config_round_trips(&guest, sidecar)?;
    println!(
        "{IN_GUEST_CONFIG} present in-guest and round-trips the sidecar ({compared} symbols, \
         {} in the guest copy)",
        guest.len()
    );
    Ok(())
}

/// Decompresses [`IN_GUEST_CONFIG`] **inside** the guest and returns its text.
///
/// `zcat` and `gzip -dc` are the same decompressor under two names; whichever the base image ships
/// is fine, and a base image with neither is a real, nameable failure rather than a skip.
async fn read_in_guest_config<V: vmcell::Vmm>(
    vm: &mut vmcell::orchestrator::MicroVm<V>,
) -> Result<String, String> {
    let steward = vm
        .steward(Some(STEWARD_BUDGET))
        .await
        .map_err(|e| format!("the probe VM's steward never came up: {e}"))?;
    let mut refusals = Vec::new();
    for argv in [
        vec!["zcat", IN_GUEST_CONFIG],
        vec!["gzip", "-dc", IN_GUEST_CONFIG],
    ] {
        let req = vmcell::ExecRequest::new(argv.iter().map(|s| (*s).to_string()).collect());
        match steward.exec(req).await {
            Ok(out) if out.code == 0 => {
                return String::from_utf8(out.stdout)
                    .map_err(|e| format!("{argv:?} returned non-UTF-8 config text: {e}"));
            }
            Ok(out) => refusals.push(format!(
                "{argv:?} exited {} ({})",
                out.code,
                String::from_utf8_lossy(&out.stderr).trim()
            )),
            Err(e) => refusals.push(format!("{argv:?} failed at the transport level: {e}")),
        }
    }
    Err(format!(
        "could not read {IN_GUEST_CONFIG} in the guest — the fragment did not take, or the base \
         image ships no gzip: {}",
        refusals.join("; ")
    ))
}
