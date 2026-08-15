//! Delta 6's live leg (design §18 item 6, §4.2 FR-V4): a downstream `ExtraFile` composed into
//! the rootfs at pack time is really in the booted guest, with the caller's bytes and the
//! caller's mode.
//!
//! This leg is **non-optional** for delta 6 because every fake in the suite is filesystem-blind
//! and the KVM-free injection tests all inspect the packer's in-memory node map — neither can
//! see the erofs the kernel actually mounts. The assertion is a data-plane one (`cat` of the
//! marker + `stat -c %a` of the mode), not a proxy signal, and it is the FIRST thing the test
//! execs in the guest, so nothing else could have created the file.
//!
//! CH-only: composing files into the image is a host-side packing feature with no
//! backend-specific surface, so one primary-backend proof suffices (the `custom_init.rs`
//! precedent).

use vmcell::artifact::rootfs::ExtraFile;
use vmcell::config::{RootfsSource, VmConfig};

mod common;

/// The marker's in-guest destination, content, and mode. `/opt/acme` is a directory the Debian
/// base does not ship, so this also exercises the packer's parent-directory synthesis; and it
/// carries no `bin`/`sbin` component, so the `injected_file_mode` heuristic would pack it
/// `0o644` — only the explicit mode gives `0o755`.
const MARKER_DEST: &str = "/opt/acme/acme-daemon";
const MARKER_CONTENT: &str = "vmcell-delta6-extra-file-marker";
const MARKER_MODE: u32 = 0o755;

/// Packs a rootfs carrying the marker as an [`ExtraFile`], into a staging dir that is never the
/// canonical artifacts dir (M-BIN-6): building at `artifacts_dir()` itself would clobber the image
/// every other suite boots. Returns the packed image path.
///
/// Mirrors `vmcell oci2-erofs`'s pipeline: resolve pins → guest agent → guest tools → rootfs.
///
/// The staging dir needs no OCI-cache plumbing of its own: the blob cache is sited on
/// [`oci_cache_dir`](vmcell::artifact::oci_cache_dir) (the artifacts dir), not on the stage's
/// output dir, so the pack below is a cache HIT off whatever `get_rootfs()` already pulled. It was
/// the output-relative siting that made this leg re-pull the whole digest-pinned base per run and
/// fail four nextest tries in a row inside the full privileged suite while passing in isolation.
async fn pack_rootfs_with_marker(
    staging: &std::path::Path,
    src: &std::path::Path,
) -> std::path::PathBuf {
    std::fs::create_dir_all(staging).expect("create the staging dir");
    let pipeline = vmcell::artifact::Pipeline::new(staging.to_path_buf())
        .add_stage(Box::new(vmcell::artifact::ResolvePinsStage {
            overlay_file: vmcell::artifact::pins_overlay_path(),
        }))
        .add_stage(Box::new(vmcell::artifact::guest_agent::GuestAgentStage {}))
        .add_stage(Box::new(vmcell::artifact::guest_tools::GuestToolsStage {}))
        .add_stage(Box::new(vmcell::artifact::rootfs::RootfsStage {
            image_override: None,
            agent_musl: None,
            extra: vec![ExtraFile::new(MARKER_DEST, src, MARKER_MODE)],
        }));
    pipeline
        .build(&vmcell::artifact::Cache::default())
        .await
        .expect("packing a rootfs with an extra file must succeed");
    let built = staging.join("rootfs.erofs");
    assert!(
        built.exists(),
        "the rootfs stage must write {}",
        built.display()
    );
    built
}

#[cfg(feature = "cloud-hypervisor")]
#[tokio::test]
#[ignore = "needs KVM"]
async fn extra_file_is_present_in_guest_with_its_explicit_mode() {
    // The marker's host-side source.
    let src_dir = tempfile::tempdir().expect("tempdir");
    let src = src_dir.path().join("acme-daemon");
    std::fs::write(&src, MARKER_CONTENT).expect("write marker source");

    // Ensure the canonical artifacts FIRST: that is what populates the shared `oci-cache` the
    // staging pack below reuses (and it is at-most-once across the suite).
    let _ = common::get_rootfs();

    // Stage OUTSIDE the canonical artifacts dir, never over it (M-BIN-6). A `TempDir` — rather
    // than a per-pid dir removed on the success path — so a panicking assertion leaves no
    // 100 MB image behind: the four leaked `delta6-extra-stage-*` dirs from a failing run are
    // exactly the residue `Drop` exists to prevent.
    let staging_dir = tempfile::tempdir().expect("staging tempdir");
    let staging = staging_dir.path();
    let rootfs = pack_rootfs_with_marker(staging, &src).await;

    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    let cfg = VmConfig::builder(
        common::get_vmlinux(),
        RootfsSource::Erofs {
            image: rootfs.clone(),
        },
    )
    .network_disabled()
    .build()
    .expect("VmConfig");

    let mut vm = common::start_vm(&vmm, cfg).await;
    let agent = vm.agent(None).await.expect("agent");

    // THE data-plane assertion, and the first exec this guest ever runs: the marker's bytes
    // come back out of the mounted image. A packer that dropped the extra file, packed a
    // different source, or lost it behind the layer merge fails here.
    let cat = agent
        .exec(vmcell::ExecRequest::new(vec![
            "cat".to_string(),
            MARKER_DEST.to_string(),
        ]))
        .await
        .expect("cat the injected marker");
    assert_eq!(cat.code, 0, "cat {MARKER_DEST} failed: {cat:?}");
    assert_eq!(
        String::from_utf8_lossy(&cat.stdout),
        MARKER_CONTENT,
        "the injected extra file must carry exactly the caller's bytes"
    );

    // …and the caller's EXPLICIT mode, not the packer's bin/sbin heuristic (which would say
    // 0o644 for this dest). `stat -c %a` prints the octal permission bits.
    let stat = agent
        .exec(vmcell::ExecRequest::new(vec![
            "stat".to_string(),
            "-c".to_string(),
            "%a".to_string(),
            MARKER_DEST.to_string(),
        ]))
        .await
        .expect("stat the injected marker");
    assert_eq!(stat.code, 0, "stat {MARKER_DEST} failed: {stat:?}");
    assert_eq!(
        String::from_utf8_lossy(&stat.stdout).trim(),
        format!("{:o}", MARKER_MODE),
        "the injected extra file must carry the caller's explicit mode"
    );

    vm.shutdown().await.expect("shutdown");
    // `staging_dir`'s `Drop` removes the ~100 MB image — on this path AND on a panicking one.
    // The shared OCI blob cache lives in the artifacts dir, not here, so it is untouched.
    drop(staging_dir);
}
