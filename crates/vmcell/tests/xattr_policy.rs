//! The §15.4 **xattr battery**, live half (design §4.7, §18 delta 7): the `Preserve` twin, read
//! back **in the guest** with the `xattr` applet, and the `Strip` negative control over the very
//! same input.
//!
//! This leg is non-optional for delta 7 and cannot be simulated. Everything the KVM-free half
//! asserts stops at the packer's in-memory node map (`tar2erofs::pax_xattrs_are_*`) or at a
//! `fs_erofs::mkfs::XattrSpec` — neither can see whether the attribute survives the erofs *image*,
//! the kernel's erofs xattr reader, and the capability LSM's own `getxattr` path. Three layers no
//! fake in this repository touches, and the one that already had a recorded surprise: a
//! `security.capability` value the kernel considers malformed is answered with `EINVAL`, not with
//! the bytes, so "the packer wrote it" and "the guest can read it" are genuinely different claims.
//!
//! **The input is synthesized, deliberately.** The pinned Debian base carries zero PAX
//! `SCHILY.xattr` records (docs/87 blocker #2, re-verified), so a `Preserve` leg over the canonical
//! layers alone asserts nothing — it would be green with the policy ignored. The base's layers are
//! therefore composed with **one synthetic tar layer** ([`synthetic_pax_layer`]) carrying a single
//! file with two PAX xattr records. The alternative input — a full-Debian image that ships real
//! file capabilities — would make delta 7's live gate depend on delta 9's image provenance, which
//! design §10.5 records as unresolved.
//!
//! **The two legs are one experiment with one variable.** Both pack the *same* base layers and the
//! *same* [`synthetic_pax_layer`] bytes through the *same* tail; only [`PackOptions::with_xattrs`]
//! differs. So the `Strip` leg is a real negative control and the `Preserve` leg is its positive
//! control — AGENTS.md's "a negative security result needs a positive control (the allowed path
//! reaches the same target)". The `Strip` leg additionally proves the FILE is there
//! (`cat` of its bytes) and that the reader WORKS (`xattr list` exits 0 with an empty listing), so
//! it cannot pass vacuously because the probe was never packed or the applet was never baked.
//!
//! Two `#[test]`s rather than one, so each ~100 MB staging tree is created, booted and **dropped**
//! before the next one exists — the residue discipline a leaked snapshot fixture already taught
//! this suite the hard way — and so the suite reports which half broke.
//!
//! CH-only: the xattr policy is a host-side packing property with no backend-specific surface, and
//! the reader is the guest kernel's, so one primary-backend proof suffices (the
//! `rootfs_extra_files.rs` / `custom_init.rs` precedent).

use vmcell::artifact::XattrPolicy;
use vmcell::config::{RootfsSource, VmConfig};

mod common;

/// The probe file's in-guest path. `/opt` exists in the Debian base but is empty, so nothing in the
/// base can be masking or contributing to what is read back here.
const PROBE_PATH: &str = "/opt/vmcell-xattr/probe";

/// The probe file's path **inside the synthetic tar layer** (tar members are relative).
const PROBE_MEMBER: &str = "opt/vmcell-xattr/probe";

/// The probe file's bytes. Asserted in both legs: under `Strip` it is what proves the negative
/// control is not vacuous.
const PROBE_CONTENT: &[u8] = b"vmcell-delta7-xattr-probe";

/// A **well-formed** `struct vfs_cap_data` (`linux/include/uapi/linux/capability.h`), revision 2:
/// `magic_etc` = `VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE` (`0x0200_0001`, little-endian),
/// then two `{permitted, inheritable}` `__le32` pairs — 20 bytes, `XATTR_CAPS_SZ_2`. The single
/// permitted bit is `CAP_NET_RAW` (13), the capability a real `/usr/bin/ping` carries.
///
/// Well-formed is **load-bearing**, not decoration. `security.capability` is not returned raw:
/// `cap_inode_getsecurity` parses it, and answers `EINVAL` for any value whose revision or length
/// it does not recognize. The KVM-free fixture in `tar2erofs.rs` uses an 8-byte stand-in because
/// nothing there ever asks the kernel; this one is read by the real thing, so an opaque payload
/// would fail the readback for a reason that has nothing to do with the packer.
const CAP_XATTR_NAME: &str = "security.capability";
/// The 20 bytes of [`CAP_XATTR_NAME`]'s value — see that constant's rationale.
const CAP_XATTR_VALUE: [u8; 20] = [
    0x01, 0x00, 0x00, 0x02, // magic_etc = VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE
    0x00, 0x20, 0x00, 0x00, // data[0].permitted   = 1 << CAP_NET_RAW
    0x00, 0x00, 0x00, 0x00, // data[0].inheritable
    0x00, 0x00, 0x00, 0x00, // data[1].permitted
    0x00, 0x00, 0x00, 0x00, // data[1].inheritable
];

/// A second attribute in the `user` namespace, carried beside the `security` one so the live leg
/// pins **two** of `xattr_spec`'s namespace folds (erofs name_index 1 and 6) rather than one, and
/// so the byte-for-byte claim rests on at least one value no LSM is allowed to reinterpret.
const USER_XATTR_NAME: &str = "user.vmcell_delta7";
/// [`USER_XATTR_NAME`]'s value: deliberately neither printable nor valid UTF-8, with an interior
/// `0x00` (a NUL inside a value must not terminate it) and both hex-nibble edges (`0x0f`, `0xf0`).
const USER_XATTR_VALUE: &[u8] = &[0x00, 0xff, 0x0f, 0xf0, 0x80, 0x7f, 0x00];

/// An attribute nothing ever writes. Read in the `Preserve` leg so the guest proves the applet's
/// failure answer (exit 1) is reachable *in that guest* — without which the `Strip` leg's exit 1
/// could equally mean "the applet is broken here".
const ABSENT_XATTR_NAME: &str = "user.vmcell_never_written";

/// Renders bytes as the lowercase hex the `xattr` applet prints.
///
/// Recomputed here from the source constants rather than copied from the applet: the point of the
/// assertion is that two independent renderings of the *same bytes* agree, and a shared helper
/// would make a hex bug invisible on both sides at once. (The applet's own hex rendering — padding,
/// case, NUL handling — is pinned host-side by `run_xattr`'s unit battery; this is the end-to-end
/// half.)
fn hex(bytes: &[u8]) -> String {
    const DIGITS: [char; 16] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[usize::from(b >> 4)]);
        out.push(DIGITS[usize::from(b & 0x0f)]);
    }
    out
}

/// The synthetic OCI-style tar layer that carries the only extended attributes in the whole image:
/// `opt/vmcell-xattr/` and, inside it, one regular file with two PAX `SCHILY.xattr.*` records.
///
/// `SCHILY.xattr.*` is the convention GNU tar, libarchive's `--xattrs` and every OCI layer producer
/// in practice emit, and the one prefix `tar_entry_xattrs` decodes — so this is a layer the packer
/// would meet in the wild, not a shape invented for the test.
///
/// One function, called by **both** legs, so "the same base under a different policy" is true by
/// construction rather than by two constants staying in sync.
fn synthetic_pax_layer() -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut buf);

        // The parent, as a real layer would ship it. (The packer would synthesize it either way;
        // a synthesized parent carries no xattrs under EITHER policy, which is F5's law and is
        // pinned KVM-free — nothing here depends on which of the two paths creates it.)
        let mut dir = tar::Header::new_gnu();
        dir.set_entry_type(tar::EntryType::Directory);
        dir.set_size(0);
        dir.set_mode(0o755);
        builder
            .append_data(&mut dir, "opt/vmcell-xattr/", std::io::empty())
            .expect("append the probe's parent directory");

        // The PAX extended header applies to the NEXT member — the probe itself.
        builder
            .append_pax_extensions([
                (
                    format!("SCHILY.xattr.{CAP_XATTR_NAME}").as_str(),
                    &CAP_XATTR_VALUE[..],
                ),
                (
                    format!("SCHILY.xattr.{USER_XATTR_NAME}").as_str(),
                    USER_XATTR_VALUE,
                ),
            ])
            .expect("append the probe's PAX xattr records");

        let mut file = tar::Header::new_gnu();
        file.set_size(PROBE_CONTENT.len() as u64);
        file.set_mode(0o755);
        builder
            .append_data(&mut file, PROBE_MEMBER, PROBE_CONTENT)
            .expect("append the probe");

        builder.finish().expect("finish the synthetic layer");
    }
    buf
}

/// Packs a bootable rootfs under `policy` from the **registered default base's layers plus**
/// [`synthetic_pax_layer`], into `staging`.
///
/// Never into the canonical artifacts dir (M-BIN-6): packing there would clobber the image every
/// other suite boots.
///
/// The steward and the guest tools are built by the real stages into `staging`, so the `xattr`
/// applet in the booted guest is **this tree's**, freshly compiled from source — not whatever
/// `vmcell build` last published into the artifacts dir. That matters because the applet is new in
/// this delta: a run against a warm published binary would exec a `/vmcell-tools/xattr` symlink
/// pointing at a multicall binary that has no such applet, and would fail for the wrong reason.
/// (`GuestToolsStage`'s cache key folds the guest-tools source closure, so the fresh staging dir is
/// a miss and the stage really rebuilds.)
///
/// The OCI blob cache is NOT staging-relative — it is sited on the artifacts dir
/// ([`vmcell::artifact::oci_cache_dir`]) — so the base layers below are a cache hit off whatever
/// the canonical build already pulled, and this does not re-download the base per leg.
async fn pack_probe_rootfs(staging: &std::path::Path, policy: XattrPolicy) -> std::path::PathBuf {
    std::fs::create_dir_all(staging).expect("create the staging dir");

    // The upstream half of the pipeline `vmcell build` runs, minus the rootfs stage: this test
    // owns the pack itself because no stage composes an extra layer over a registered base.
    let built = vmcell::artifact::Pipeline::new(staging.to_path_buf())
        .add_stage(Box::new(vmcell::artifact::ResolvePinsStage {
            overlay_file: vmcell::artifact::pins_overlay_path(),
        }))
        .add_stage(Box::new(vmcell::artifact::steward::StewardStage {}))
        .add_stage(Box::new(
            vmcell::artifact::guest_tools::GuestToolsStage::new(),
        ))
        .build(&vmcell::artifact::Cache::default())
        .await
        .expect("building the steward + guest tools must succeed");

    // `extend`, not a struct literal: `StageInputs` is `#[non_exhaustive]`, so an out-of-crate
    // caller seeds it through its public fields.
    let mut inputs = vmcell::artifact::StageInputs::default();
    inputs.artifacts.extend(built.paths.clone());
    // The binary the pack tail is about to bake must be the one the stage just built HERE, in the
    // fresh staging dir — never the canonical artifacts dir's, which is whatever the last
    // `vmcell build` published and which predates this delta's applet on any warm checkout. Pinned
    // rather than commented, because "the readback ran against a stale multicall binary" is the one
    // way this battery could fail (or pass) for a reason that has nothing to do with the policy.
    let baked_tools = inputs.artifacts.get("guest_tools").expect(
        "the guest-tools stage must register its artifact; the pack tail bakes it from this key",
    );
    assert!(
        baked_tools.starts_with(staging),
        "the guest-tools binary baked into the probe image must come from this run's staging dir \
         ({}), so the in-guest `xattr` applet is THIS tree's — got {}",
        staging.display(),
        baked_tools.display()
    );

    // The registered base, through the one registry reader — never a hand-parsed `pins.json`.
    let entry = vmcell::artifact::resolve_rootfs_entry(
        None,
        vmcell::artifact::pins_overlay_path().as_deref(),
    )
    .expect("resolving the rootfs registry must succeed")
    .expect("the `default` rootfs label must be registered");
    let (image, digest) = match entry.registration {
        vmcell::artifact::RootfsRegistration::Digest { image, digest } => (image, digest),
        other => panic!(
            "this battery composes a layer over the DIGEST-pinned default base; \
             `rootfs.default` resolved to {other:?} instead"
        ),
    };

    // The base's own layers, decoded through the one pull→verify→decode law, then ours on top so
    // the probe wins any collision.
    let mut streams = vmcell::artifact::rootfs::oci::base_layer_tar_streams(&image, &digest)
        .await
        .expect("resolving the pinned base's layers must succeed");
    streams.push(Box::new(std::io::Cursor::new(synthetic_pax_layer())));

    let out = staging.join("rootfs.erofs");
    vmcell::artifact::rootfs::pack_erofs_with_injection(
        streams,
        &inputs,
        &out,
        // THE one variable between the two legs.
        &vmcell::artifact::rootfs::PackOptions::new().with_xattrs(policy),
    )
    .await
    .expect("packing the probe rootfs must succeed");

    assert!(out.exists(), "the pack must write {}", out.display());
    out
}

/// Boots `rootfs` on Cloud Hypervisor with networking off and hands back the running VM.
#[cfg(feature = "cloud-hypervisor")]
async fn boot_probe_vm(
    vmm: &vmcell::vmm::cloud_hypervisor::CloudHypervisor,
    rootfs: std::path::PathBuf,
) -> vmcell::MicroVm<vmcell::vmm::cloud_hypervisor::CloudHypervisor> {
    let cfg = VmConfig::builder(common::get_vmlinux(), RootfsSource::Erofs { image: rootfs })
        .network_disabled()
        .build()
        .expect("VmConfig");
    common::start_vm(vmm, cfg).await
}

/// Execs `argv` in the guest and returns `(exit code, stdout as lines)`.
///
/// Fails loud, naming the rebuild, when the multicall binary in the image has no `xattr` applet —
/// the one confusing failure this battery can produce, and the one an operator running against a
/// stale rootfs will hit first.
#[cfg(feature = "cloud-hypervisor")]
async fn exec_lines(
    steward: &mut vmcell::StewardClient,
    argv: &[&str],
) -> (i32, Vec<String>, String) {
    let out = steward
        .exec(vmcell::ExecRequest::new(
            argv.iter().map(|s| (*s).to_string()).collect(),
        ))
        .await
        .unwrap_or_else(|e| panic!("exec {argv:?} failed: {e}"));
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.code != 127 && !stderr.contains("unknown applet"),
        "the guest has no `{}` applet (exit {}, stderr {stderr:?}) — the guest-tools binary baked \
         into this image predates it. This battery builds its own, so this means the STAGE served \
         a stale artifact; rebuild with `vmcell build --kernel-source host-make`",
        argv[0],
        out.code
    );
    let lines = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect();
    (out.code, lines, stderr)
}

/// The **`Preserve` twin** (§4.7, §18 delta 7): an artifact whose registry entry declares
/// `"xattrs": "preserve"` really carries its source layers' extended attributes into the booted
/// guest, byte for byte, in two namespaces.
///
/// The assertion is a data-plane one — the value bytes as `getxattr(2)` answers them, recomputed
/// independently from the constants that were packed — not an exit code, not a substring, and not
/// the packer's own node map.
///
/// Paired with [`the_strip_policy_packs_the_same_probe_without_its_xattrs`], which is the negative
/// control over identical input; this test is that control's positive control.
///
/// RED on the inverse: make `Preserve` behave as `Strip` (drop the policy check in
/// `tar_entry_xattrs`, or hand `XattrPolicy::Strip` to the pack below) and the `get` legs go from
/// the packed hex to an exit-1 `ENODATA`.
#[cfg(feature = "cloud-hypervisor")]
#[tokio::test]
#[ignore = "needs KVM"]
async fn preserved_xattrs_are_readable_in_guest_under_the_preserve_policy() {
    // Ensure the canonical artifacts FIRST: that is what warms the shared OCI blob cache the pack
    // below reuses (and it is at-most-once across the suite).
    let _ = common::get_rootfs();

    // A `TempDir` — rather than a per-pid dir removed on the success path — so a panicking
    // assertion cannot leave a ~100 MB image behind. Cleanup is on the panic path too.
    let staging_dir = tempfile::tempdir().expect("staging tempdir");
    let rootfs = pack_probe_rootfs(staging_dir.path(), XattrPolicy::Preserve).await;

    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    let mut vm = boot_probe_vm(&vmm, rootfs.clone()).await;
    let steward = vm.steward(None).await.expect("steward");

    // The probe file itself, first: everything below is about an attribute ON it, so a missing
    // file must not be reported as a missing attribute.
    let (code, lines, stderr) = exec_lines(steward, &["cat", PROBE_PATH]).await;
    assert_eq!(code, 0, "cat {PROBE_PATH} failed: {stderr}");
    assert_eq!(
        lines,
        vec![String::from_utf8_lossy(PROBE_CONTENT).into_owned()],
        "the synthetic layer's probe must be in the image with its own bytes"
    );

    // THE assertion: the `security.capability` value, as the guest kernel hands it back. The
    // capability LSM parses this attribute rather than returning it raw, so this pins the packed
    // bytes AND their well-formedness end to end.
    let (code, lines, stderr) =
        exec_lines(steward, &["xattr", "get", PROBE_PATH, CAP_XATTR_NAME]).await;
    assert_eq!(
        code, 0,
        "under `Preserve` the guest must be able to read {CAP_XATTR_NAME} off {PROBE_PATH}: {stderr}"
    );
    assert_eq!(
        lines,
        vec![hex(&CAP_XATTR_VALUE)],
        "the preserved {CAP_XATTR_NAME} must be the packed value BYTE FOR BYTE"
    );

    // …and the `user`-namespace twin, whose value no LSM may reinterpret.
    let (code, lines, stderr) =
        exec_lines(steward, &["xattr", "get", PROBE_PATH, USER_XATTR_NAME]).await;
    assert_eq!(
        code, 0,
        "under `Preserve` the guest must be able to read {USER_XATTR_NAME}: {stderr}"
    );
    assert_eq!(
        lines,
        vec![hex(USER_XATTR_VALUE)],
        "the preserved {USER_XATTR_NAME} must be the packed value BYTE FOR BYTE, NUL and all"
    );

    // Both names, and ONLY those two: a listing that also showed something the packer never wrote
    // would mean the merge invented an attribute.
    let (code, mut lines, stderr) = exec_lines(steward, &["xattr", "list", PROBE_PATH]).await;
    assert_eq!(code, 0, "listing the probe's attributes failed: {stderr}");
    lines.sort();
    let mut want = vec![CAP_XATTR_NAME.to_string(), USER_XATTR_NAME.to_string()];
    want.sort();
    assert_eq!(
        lines, want,
        "the preserved probe must carry exactly the two attributes the synthetic layer declared"
    );

    // The applet's FAILURE answer, proven reachable in this very guest — so the `Strip` leg's
    // exit-1 is a real "no such attribute" and not a broken reader. Exit 1, never `EXIT_USAGE`
    // (2): a typo'd name must stay distinguishable from a stripped one.
    let (code, lines, _) =
        exec_lines(steward, &["xattr", "get", PROBE_PATH, ABSENT_XATTR_NAME]).await;
    assert_eq!(
        code, 1,
        "an attribute that was never written is a failed READ (1), not a usage error (2)"
    );
    assert!(
        lines.is_empty(),
        "a failed read prints no value line, got {lines:?}"
    );

    vm.shutdown().await.expect("shutdown");

    // THE CONFORMANCE KIT'S OWN `Works` ANSWER, on the only image in the tree that can produce one.
    //
    // `vmcell-artifact-validator`'s §10.6 battery gained a data-plane probe for `xattr_preserved`
    // once this delta put a reader in the guest, and its live leg (`tests/smoke.rs`) can only drive
    // the probe against the canonical artifacts — which are packed `strip`, so that leg exercises
    // the `DoesNotWork` answer and the control pairing and nothing else. A probe that could only
    // ever answer "absent" is the constant that certifies everything, and this is the one place in
    // the tree that already has a `Preserve`-packed image to disprove it with.
    //
    // Booted after `shutdown()` above, deliberately: the probe boots its own VM, and one guest at a
    // time keeps this leg's cost one boot rather than two concurrent ones.
    //
    // RED on the inverse: pack under `Strip` here (the whole test reddens earlier), or make
    // `classify_xattr_scan` answer `DoesNotWork` for the present marker — this assertion is then
    // the only thing in either crate that notices.
    let outcome = vmcell_artifact_validator::checks::xattr_preserved_probe(
        &vmm,
        &vmcell_artifact_validator::ArtifactSet::new(common::get_vmlinux(), rootfs),
    )
    .await;
    assert_eq!(
        outcome,
        vmcell_artifact_validator::conformance::ProbeOutcome::Works,
        "the conformance kit's xattr probe must find this image's attributes: it is the same \
         applet this test just read them back with, and an image that demonstrably carries two \
         must not come back as a verified absence"
    );

    // Drops the ~100 MB staging tree. The shared OCI blob cache lives in the artifacts dir, not
    // here, so the next leg still gets its cache hit.
    drop(staging_dir);
}

/// The **`Strip` negative control** (§4.7, §18 delta 7): the default policy packs the *same*
/// synthetic layer, over the *same* base, through the *same* tail — and the booted guest finds the
/// probe file present and its extended attributes gone.
///
/// Non-vacuity is built in, because "the attribute is absent" is trivially true of a file that was
/// never packed and of a reader that never ran: the probe's bytes are `cat`-ed back first, and
/// `xattr list` must **succeed** with an empty listing (a working `listxattr(2)` on a real inode)
/// before the `get` is allowed to mean anything. The path's positive control — the same probe, the
/// same applet, the attribute readable — is
/// [`preserved_xattrs_are_readable_in_guest_under_the_preserve_policy`].
///
/// RED on the inverse: make `Strip` behave as `Preserve` (invert the policy check in
/// `tar_entry_xattrs`, or hand `XattrPolicy::Preserve` to the pack below) and the listing stops
/// being empty while the `get` legs start exiting 0.
#[cfg(feature = "cloud-hypervisor")]
#[tokio::test]
#[ignore = "needs KVM"]
async fn the_strip_policy_packs_the_same_probe_without_its_xattrs() {
    let _ = common::get_rootfs();

    let staging_dir = tempfile::tempdir().expect("staging tempdir");
    // `XattrPolicy::default()`, not the `Strip` variant spelled out: the claim under test is about
    // the DEFAULT arm — an artifact that declares no policy — which is the least-tested path and
    // the one every pre-delta-7 caller lands on.
    let rootfs = pack_probe_rootfs(staging_dir.path(), XattrPolicy::default()).await;

    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    let mut vm = boot_probe_vm(&vmm, rootfs).await;
    let steward = vm.steward(None).await.expect("steward");

    // Non-vacuity 1: the probe IS in this image, with its bytes. Without this the whole test is
    // "an attribute is missing from a file that does not exist".
    let (code, lines, stderr) = exec_lines(steward, &["cat", PROBE_PATH]).await;
    assert_eq!(
        code, 0,
        "the `Strip` pack must still contain {PROBE_PATH} — only its ATTRIBUTES are dropped: \
         {stderr}"
    );
    assert_eq!(
        lines,
        vec![String::from_utf8_lossy(PROBE_CONTENT).into_owned()],
        "the `Strip` pack must carry the probe's bytes unchanged"
    );

    // Non-vacuity 2: the reader reached the inode and answered successfully — with nothing.
    let (code, lines, stderr) = exec_lines(steward, &["xattr", "list", PROBE_PATH]).await;
    assert_eq!(
        code, 0,
        "listing a stripped file's attributes SUCCEEDS with an empty list; a failure here would \
         mean the reader never reached the inode: {stderr}"
    );
    assert!(
        lines.is_empty(),
        "under the default (`Strip`) policy the probe must carry NO extended attributes, got \
         {lines:?}"
    );

    // THE negative assertion, for each attribute the synthetic layer declared. Exit 1 is the read
    // that reached the kernel and got `ENODATA`; exit 2 would mean the applet rejected the argv,
    // which would make this pass for the wrong reason.
    for name in [CAP_XATTR_NAME, USER_XATTR_NAME] {
        let (code, lines, _) = exec_lines(steward, &["xattr", "get", PROBE_PATH, name]).await;
        assert_eq!(
            code, 1,
            "under the default (`Strip`) policy {name} must be ABSENT (a failed read, exit 1), \
             not present and not a usage error"
        );
        assert!(
            lines.is_empty(),
            "a stripped attribute prints no value line, got {lines:?}"
        );
    }

    vm.shutdown().await.expect("shutdown");
    drop(staging_dir);
}
