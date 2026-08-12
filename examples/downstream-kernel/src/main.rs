//! The downstream consumer's own program (design v30 §5.6 / §10.4; §18 delta 5).
//!
//! Two subcommands, deliberately separate **processes** rather than two functions or two `#[test]`s:
//!
//! * `getters` — the §10.4 harness-getter contract probe. `vmcell::artifact::ensure_test_artifacts`
//!   memoizes its outcome in a process-global `OnceLock`, so the "full override set" leg and the
//!   "no override set" leg cannot both run in one process without the first poisoning the second.
//!   `ci-check.sh` runs this subcommand twice, with different environments.
//! * `live` — the toolkit end to end: build `vmlinux-ikconfig` from this consumer's overlay, assert
//!   the fragment survived in the resolved-config sidecar, run the validator battery, then prove the
//!   fragment took **on the data plane** by reading `/proc/config.gz` out of the booted guest.
//!   Needs `/dev/kvm` and a rootfs (`VMCELL_ROOTFS`), so it runs on the self-hosted KVM job.

#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use downstream_kernel::{
    IN_GUEST_CONFIG, KERNEL_LABEL, artifacts_dir, fragment_survived, guest_config_round_trips,
    overlay_path, read_resolved_config, registry_entry,
};
use vmcell::config::{RootfsSource, VmConfig};
use vmcell::vmm::cloud_hypervisor::CloudHypervisor;
use vmcell_artifact_validator::harness;
use vmcell_artifact_validator::kconfig::KconfigValues;
use vmcell_artifact_validator::{ArtifactSet, ValidationOptions, validate};

/// How long the guest agent gets to come up before the live leg calls the boot failed. The battery
/// has already booted this exact kernel by the time this runs, so a generous single budget is
/// enough; it is stated once here rather than inline at the call.
const AGENT_BUDGET: Duration = Duration::from_secs(60);

/// Usage text — one statement of the subcommand roster, printed by both the no-argument and the
/// unknown-argument paths.
const USAGE: &str = "usage: downstream-kernel <getters|live>";

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let outcome = match args.next().as_deref() {
        Some("getters") => cmd_getters(),
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

    // 4. The conformance battery against this consumer's own artifact pair. The rootfs comes from
    //    the env contract (`VMCELL_ROOTFS`) — a downstream builds kernels, not rootfs images.
    let rootfs = harness::get_rootfs();
    let report = validate(
        &ArtifactSet::new(kernel.clone(), rootfs.clone()),
        &ValidationOptions::default(),
    )
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

    // 5. The data plane: the booted guest exposes `/proc/config.gz`, which exists only if the
    //    fragment took, and its content round-trips the sidecar.
    prove_in_guest(&kernel, &rootfs, &sidecar).await
}

/// Boots `kernel` + `rootfs` and reads [`IN_GUEST_CONFIG`] back out of the guest.
///
/// This is the assertion the fakes structurally cannot make (§18 delta 5, "live leg non-optional"):
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
    let agent = vm
        .agent(Some(AGENT_BUDGET))
        .await
        .map_err(|e| format!("the probe VM's agent never came up: {e}"))?;
    let mut refusals = Vec::new();
    for argv in [
        vec!["zcat", IN_GUEST_CONFIG],
        vec!["gzip", "-dc", IN_GUEST_CONFIG],
    ] {
        let req = vmcell::ExecRequest::new(argv.iter().map(|s| (*s).to_string()).collect());
        match agent.exec(req).await {
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
