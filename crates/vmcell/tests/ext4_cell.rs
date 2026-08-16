//! The §15.4 **ext4** battery, live half (design §4.7, §18 delta 8): pack the merged tar into an
//! ext4 image, boot it as [`RootfsSource::Block`], and diff the tree, the extended attributes and
//! the device nodes **in the guest** against the manifest that was packed.
//!
//! `RootfsSource::Block` had **never been booted** by any test in this repository — before this
//! file the only reference outside in-crate unit tests was one fuzz target — so every runtime claim
//! about that variant was unverified, including the `rootfstype=ext4` / `rootflags=noload` cmdline
//! the builder has emitted for it since v28. This is that variant's first live exercise, and §18
//! delta 8 makes it the delta's named gate: *"pack from the merged tar, boot as
//! `RootfsSource::Block`, in-guest tree/xattr/device-node diff against the tar manifest"*.
//!
//! # What the diff is against, and why it is not one thing
//!
//! Two manifests, because they answer two different questions and neither is sufficient alone:
//!
//! * [`fixture_layer`] — a synthetic tar layer this file authors, carrying **every POSIX shape the
//!   erofs default cannot demonstrate**: character and block device nodes with numbers wider than
//!   eight bits, a FIFO, a symlink, a setuid file, a file owned by a non-root uid/gid, extended
//!   attributes in two namespaces, and a member three directories deep whose parents the layer
//!   never ships. The pinned Debian base carries **zero** device nodes and **zero** xattrs
//!   (measured, not assumed — `docs/87` blocker #2 and re-measured for this delta), so a diff over
//!   the canonical layers alone would be green with device and xattr support entirely absent.
//! * [`base_sample`] — a deterministic sample of real members of the **pinned base layer tar**,
//!   compared attribute for attribute. That is the "tree diff against the tar manifest" half: it
//!   walks a real ~3 200-member tree rather than a fixture the test also wrote, so a producer that
//!   mangled modes, ownership or sizes at scale reddens here even though the fixture legs pass.
//!
//! # The clean mount, and why the diff does not read `/`
//!
//! Under the default `Pid1` placement the steward overlays a tmpfs over `/` and `pivot_root`s
//! (`vmcell-steward`'s `assembly.rs`), so `/` in the guest is an **overlayfs** whose lower layer is
//! the ext4 root. Reading the diff through it would measure overlayfs as much as ext4. So the legs
//! mount `/dev/vda` a second time, read-only, at [`CLEAN_MOUNT`] and diff **there** — a raw view of
//! the filesystem the producer wrote. [`the_overlay_never_reaches_the_ext4_beneath_it`] is what
//! makes that non-vacuous: a guest write lands in the overlay's tmpfs upper and is **absent** from
//! the clean mount, which simultaneously proves the clean mount is not a bind of `/` and pins the
//! read-only ratification's most surprising consequence (a `Pid1` guest's `/` is writable while the
//! ext4 beneath it is not).
//!
//! # e2fsprogs is a probed facility, not an opt-in
//!
//! Unlike `systemd_cell`'s `VMCELL_TEST_SYSTEMD`, nothing here is switched on by an environment
//! variable: the battery is cheap (no network pull beyond the base every suite already fetches)
//! and `test-privileged` selects it. What it *needs* is `mkfs.ext4` from e2fsprogs ≥
//! [`MIN_E2FSPROGS_VERSION`], whose `-d <tarball>` form is younger than several distributions'
//! packages — including, most likely, the `ubuntu-24.04` image the CI KVM job runs on. So the legs
//! ask the **product's own probe** and record a reviewable capability skip when the facility is
//! genuinely absent (§7.2), rather than baking in a belief about any particular host: if CI's
//! e2fsprogs is new enough the gate runs there for free, and if it is not, the skip is in the
//! manifest `just skip-manifest-show` prints. Anything the probe classifies as a *broken* facility
//! rather than an absent one still fails loud.
//!
//! CH-only. The image is a host-side packing product and the reader is the guest kernel's ext4
//! driver; the per-backend half of `RootfsSource::Block` — that each backend attaches the root
//! read-only — is pinned by each backend's own root-disk unit test, KVM-free.

#![cfg(all(feature = "pipeline", feature = "ext4-producer"))]

use std::collections::BTreeMap;

use vmcell::artifact::RootfsFormat;
use vmcell::artifact::ext4::{Ext4Producer, MIN_E2FSPROGS_VERSION};
use vmcell::artifact::rootfs::{PackOptions, XattrPolicy};
use vmcell::config::{RootfsSource, VmConfig};
use vmcell::error::Error;

mod common;

// -----------------------------------------------------------------------------------------------
// The facility probe, in its own module so no leg can pack or boot without it.
// -----------------------------------------------------------------------------------------------

/// The e2fsprogs probe, in its own module so its receipt cannot be forged.
///
/// Rust privacy is per-module: [`Ext4Available`]'s field is private here and
/// [`probe_or_record_skip`] is its only constructor, so "no leg packs an ext4 image without first
/// asking the product whether this host can" is a **compile error** rather than a convention. The
/// same shape `systemd_cell`'s `OptedIn` uses, for a different reason — that one gates a cost, this
/// one gates a facility.
mod producer_gate {
    use super::{Error, Ext4Producer, MIN_E2FSPROGS_VERSION};

    /// Proof that this host's `mkfs.ext4` passed [`Ext4Producer::probe`]'s full gate.
    #[derive(Clone, Copy, Debug)]
    pub struct Ext4Available(());

    /// `Some(Ext4Available)` when the producer's own probe succeeds; `None`, after recording a
    /// reviewable capability skip, when it classifies the facility as **absent**.
    ///
    /// A probe result the product calls *broken* — present but unexecutable, an unparseable banner
    /// — **panics**: that is a host misconfiguration this battery must not paper over, and it is
    /// exactly the distinction §7.2 rule 3 draws. Skipping on it would be the
    /// `println!("SKIP") + return` green-PASS defect wearing the probe's clothes.
    #[must_use]
    pub fn probe_or_record_skip() -> Option<Ext4Available> {
        match Ext4Producer::probe() {
            Ok(_) => Some(Ext4Available(())),
            Err(Error::CapabilityUnavailable { op, needed }) => {
                crate::common::record_capability_skip("cloud-hypervisor", "ext4_producer");
                let (ma, mi, pa) = MIN_E2FSPROGS_VERSION;
                println!(
                    "SKIP: this host cannot produce ext4 rootfs images ({op}: {needed}). The \
                     §15.4 ext4 battery needs e2fsprogs >= {ma}.{mi}.{pa} with libarchive support"
                );
                None
            }
            Err(other) => panic!(
                "`mkfs.ext4` is present but BROKEN on this host, which is a misconfiguration and \
                 not an absent facility — fix it rather than skipping the delta-8 gate: {other}"
            ),
        }
    }
}

use producer_gate::{Ext4Available, probe_or_record_skip};

// -----------------------------------------------------------------------------------------------
// The fixture layer: every POSIX shape the pinned Debian base cannot demonstrate.
// -----------------------------------------------------------------------------------------------

/// Where the fixture's members live in the guest. `/opt` exists in the Debian base and is empty, so
/// nothing in the base can mask or contribute to what is read back.
const FIXTURE_DIR: &str = "opt/vmcell-ext4";

/// Where the raw ext4 root is mounted a second time, read-only, for the diff — see the module docs.
const CLEAN_MOUNT: &str = "/mnt/vmcell-ext4-ro";

/// A **well-formed** revision-2 `struct vfs_cap_data` whose single permitted bit is `CAP_NET_RAW`.
///
/// Well-formed is load-bearing: `security.capability` is not returned raw, `cap_inode_getsecurity`
/// parses it and answers `EINVAL` for a value whose revision or length it does not recognize. Same
/// blob and same reasoning as the delta-7 xattr battery — an opaque payload would fail the readback
/// for a reason that has nothing to do with the ext4 producer. Written as bytes rather than as the
/// command that produces it because `vmcell-privilege`'s drift gate walks the tree for `setcap …`
/// copies and would (rightly) flag a doc comment quoting a different grant.
const CAP_XATTR_NAME: &str = "security.capability";
/// The 20 bytes of [`CAP_XATTR_NAME`]'s value — see that constant.
const CAP_XATTR_VALUE: [u8; 20] = [
    0x01, 0x00, 0x00, 0x02, // magic_etc = VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE
    0x00, 0x20, 0x00, 0x00, // data[0].permitted = 1 << CAP_NET_RAW
    0x00, 0x00, 0x00, 0x00, // data[0].inheritable
    0x00, 0x00, 0x00, 0x00, // data[1].permitted
    0x00, 0x00, 0x00, 0x00, // data[1].inheritable
];

/// An attribute nothing ever writes, read in the guest so the reader's *failure* answer is proven
/// reachable there — without which the successful read above could equally be an applet that
/// answers 0 to everything.
///
/// This constant is also the scar of a finding. It started out as a **second packed attribute**,
/// `user.vmcell_delta8`, on the theory that the byte-for-byte claim should rest on at least one
/// value no LSM may reinterpret. The live leg answered `ENODATA` for it while
/// `security.capability` on the same member came back byte-exact — and the cause was not the
/// packer: `mkfs.ext4 -d <tarball>` carries **only** `security.capability` across and drops
/// `user.*`, `trusted.*` and even `security.selinux` silently (the directory form of `-d` does not;
/// see `EXT4_TARBALL_XATTRS`). So the producer now refuses such an input rather than packing a
/// quiet subset of what `XattrPolicy::Preserve` promised, this battery packs only what the route
/// can carry, and the two KVM-free gates in `ext4_producer.rs` own the refusal and the
/// re-measurement.
const ABSENT_XATTR_NAME: &str = "user.vmcell_never_written";

/// The character device's numbers. **Not** `1:3`: `dev_t` is not `(major << 8) | minor` — it
/// scatters the high bits — so `1:3` round-trips correctly under either reading and discriminates
/// nothing. These do.
const CHR_MAJOR: u32 = 234;
/// See [`CHR_MAJOR`].
const CHR_MINOR: u32 = 456;
/// The block device's numbers, `nvme0n1`-shaped and wider than eight bits apiece for the same
/// reason as [`CHR_MAJOR`].
const BLK_MAJOR: u32 = 259;
/// See [`BLK_MAJOR`].
const BLK_MINOR: u32 = 300;

/// The bytes of the deep member, read back with `cat` so the diff has a content leg and not only a
/// metadata one.
const LEAF_CONTENT: &[u8] = b"vmcell-delta8-ext4-leaf";

/// Linux `S_IF*` bits, spelled here rather than pulled from `libc` so the expectation is
/// independent of the constants the *packer* uses (the two agreeing is the claim).
const S_IFREG: u32 = 0o100_000;
/// See [`S_IFREG`].
const S_IFDIR: u32 = 0o040_000;
/// See [`S_IFREG`].
const S_IFLNK: u32 = 0o120_000;
/// See [`S_IFREG`].
const S_IFCHR: u32 = 0o020_000;
/// See [`S_IFREG`].
const S_IFBLK: u32 = 0o060_000;
/// See [`S_IFREG`].
const S_IFIFO: u32 = 0o010_000;

/// What one member of the packed tree must look like when the guest kernel `lstat`s it.
///
/// `size` is `None` for anything but a regular file: a directory's size is a filesystem-chosen
/// block multiple and a symlink's is its target's length, neither of which the tar header states.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Expected {
    /// The full raw mode — file-type bits `|` permission bits — as `lstat` reports it.
    raw_mode: u32,
    /// Numeric owner.
    uid: u32,
    /// Numeric group.
    gid: u32,
    /// Byte size, for regular files only.
    size: Option<u64>,
    /// `(major, minor)`, for device nodes only.
    rdev: Option<(u32, u32)>,
}

impl Expected {
    /// A regular file.
    fn file(mode: u32, uid: u32, gid: u32, size: u64) -> Self {
        Self {
            raw_mode: S_IFREG | mode,
            uid,
            gid,
            size: Some(size),
            rdev: None,
        }
    }
    /// A directory.
    fn dir(mode: u32, uid: u32, gid: u32) -> Self {
        Self {
            raw_mode: S_IFDIR | mode,
            uid,
            gid,
            size: None,
            rdev: None,
        }
    }
    /// A symlink.
    fn symlink(mode: u32, uid: u32, gid: u32) -> Self {
        Self {
            raw_mode: S_IFLNK | mode,
            uid,
            gid,
            size: None,
            rdev: None,
        }
    }
    /// A device node of `type_bits` (`S_IFCHR`/`S_IFBLK`).
    fn device(type_bits: u32, mode: u32, major: u32, minor: u32) -> Self {
        Self {
            raw_mode: type_bits | mode,
            uid: 0,
            gid: 0,
            size: None,
            rdev: Some((major, minor)),
        }
    }
    /// A FIFO.
    fn fifo(mode: u32) -> Self {
        Self {
            raw_mode: S_IFIFO | mode,
            uid: 0,
            gid: 0,
            size: None,
            rdev: None,
        }
    }
}

/// The fixture manifest: in-guest path (relative to the mount point) → what `lstat` must report.
///
/// Written beside [`fixture_layer`], which is what builds the tar these entries describe. The two
/// are deliberately *separate* renderings of the same intent: a single helper emitting both would
/// make a shared mistake invisible on both sides at once, which is the whole failure mode a
/// manifest diff exists to catch.
fn fixture_manifest() -> BTreeMap<String, Expected> {
    let d = FIXTURE_DIR;
    BTreeMap::from([
        (d.to_string(), Expected::dir(0o755, 0, 0)),
        // The three parents the layer never declares. `mkfs.ext4 -d` performs NO implicit directory
        // synthesis, so their presence here is the packer's parent synthesis surviving all the way
        // into a mounted filesystem — the live half of `merged_tar_carries_synthesized_parents`.
        // A synthesized parent is `0o755 root:root` by the merge's own law.
        (format!("{d}/deep"), Expected::dir(0o755, 0, 0)),
        (format!("{d}/deep/nested"), Expected::dir(0o755, 0, 0)),
        (format!("{d}/deep/nested/dir"), Expected::dir(0o755, 0, 0)),
        (
            format!("{d}/deep/nested/dir/leaf"),
            Expected::file(0o640, 1234, 5678, LEAF_CONTENT.len() as u64),
        ),
        // The full twelve permission bits, not just the low nine: a producer that wrote the mode
        // through a `& 0o777` drops setuid silently, and a setuid binary that quietly stops being
        // setuid is the kind of difference a workload notices in production and not in a test.
        (format!("{d}/setuid"), Expected::file(0o4755, 0, 0, 4)),
        (
            format!("{d}/chr"),
            Expected::device(S_IFCHR, 0o666, CHR_MAJOR, CHR_MINOR),
        ),
        (
            format!("{d}/blk"),
            Expected::device(S_IFBLK, 0o660, BLK_MAJOR, BLK_MINOR),
        ),
        (format!("{d}/fifo"), Expected::fifo(0o644)),
        (format!("{d}/link"), Expected::symlink(0o777, 0, 0)),
        (format!("{d}/xattrs"), Expected::file(0o755, 0, 0, 6)),
    ])
}

/// Where `{FIXTURE_DIR}/link` points. Relative, so it resolves inside whichever mount it is read
/// from — the clean ext4 mount included.
const LINK_TARGET: &str = "deep/nested/dir/leaf";

/// The synthetic OCI-style layer described by [`fixture_manifest`].
///
/// Its members are the shapes `RootfsFormat::Ext4` exists for. The parents of the deep member are
/// deliberately **absent** from the layer: they must arrive in the merged tar by the packer's own
/// synthesis, or `mkfs.ext4` refuses the build naming the missing directory.
fn fixture_layer() -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut b = tar::Builder::new(&mut buf);
        let d = FIXTURE_DIR;

        let mut dir = tar::Header::new_gnu();
        dir.set_entry_type(tar::EntryType::Directory);
        dir.set_size(0);
        dir.set_mode(0o755);
        dir.set_mtime(0);
        b.append_data(&mut dir, format!("{d}/"), std::io::empty())
            .expect("append the fixture directory");

        // A regular file under three directories the layer never declares.
        let mut leaf = tar::Header::new_gnu();
        leaf.set_size(LEAF_CONTENT.len() as u64);
        leaf.set_mode(0o640);
        leaf.set_uid(1234);
        leaf.set_gid(5678);
        leaf.set_mtime(0);
        b.append_data(&mut leaf, format!("{d}/deep/nested/dir/leaf"), LEAF_CONTENT)
            .expect("append the deep member");

        let mut setuid = tar::Header::new_gnu();
        setuid.set_size(4);
        setuid.set_mode(0o4755);
        setuid.set_mtime(0);
        b.append_data(&mut setuid, format!("{d}/setuid"), &b"suid"[..])
            .expect("append the setuid member");

        let mut chr = tar::Header::new_gnu();
        chr.set_entry_type(tar::EntryType::Char);
        chr.set_size(0);
        chr.set_mode(0o666);
        chr.set_device_major(CHR_MAJOR).expect("char major");
        chr.set_device_minor(CHR_MINOR).expect("char minor");
        chr.set_mtime(0);
        b.append_data(&mut chr, format!("{d}/chr"), std::io::empty())
            .expect("append the character device");

        let mut blk = tar::Header::new_gnu();
        blk.set_entry_type(tar::EntryType::Block);
        blk.set_size(0);
        blk.set_mode(0o660);
        blk.set_device_major(BLK_MAJOR).expect("block major");
        blk.set_device_minor(BLK_MINOR).expect("block minor");
        blk.set_mtime(0);
        b.append_data(&mut blk, format!("{d}/blk"), std::io::empty())
            .expect("append the block device");

        let mut fifo = tar::Header::new_gnu();
        fifo.set_entry_type(tar::EntryType::Fifo);
        fifo.set_size(0);
        fifo.set_mode(0o644);
        fifo.set_mtime(0);
        b.append_data(&mut fifo, format!("{d}/fifo"), std::io::empty())
            .expect("append the fifo");

        let mut link = tar::Header::new_gnu();
        link.set_entry_type(tar::EntryType::Symlink);
        link.set_size(0);
        link.set_mode(0o777);
        link.set_mtime(0);
        link.set_link_name(LINK_TARGET).expect("symlink target");
        b.append_data(&mut link, format!("{d}/link"), std::io::empty())
            .expect("append the symlink");

        // The PAX extended header applies to the NEXT member. One attribute, not two: see
        // [`ABSENT_XATTR_NAME`] for why a second one in the `user` namespace is not merely omitted
        // here but *refused* by the producer.
        b.append_pax_extensions([(
            format!("SCHILY.xattr.{CAP_XATTR_NAME}").as_str(),
            &CAP_XATTR_VALUE[..],
        )])
        .expect("append the PAX xattr record");
        let mut xattrs = tar::Header::new_gnu();
        xattrs.set_size(6);
        xattrs.set_mode(0o755);
        xattrs.set_mtime(0);
        b.append_data(&mut xattrs, format!("{d}/xattrs"), &b"xattrs"[..])
            .expect("append the xattr-bearing member");

        b.finish().expect("finish the fixture layer");
    }
    buf
}

// -----------------------------------------------------------------------------------------------
// The base-layer sample: the "tree diff against the tar manifest" over a real tree.
// -----------------------------------------------------------------------------------------------

/// Every `stride`-th eligible member of the **pinned base layer tar**, as an expectation map.
///
/// Deterministic by construction — the base is digest-pinned, the walk is in archive order and the
/// stride is fixed — so this samples the same members on every host and every run. Not the whole
/// tree: ~3 200 `stat` results would have to cross the vsock exec channel in one reply, and the
/// property under test (attributes survive the producer) does not get truer with more members. It
/// does get truer with *real* members, which is why this is not more fixture.
///
/// Excluded, each for a reason and not for convenience:
///
/// * **hardlinks** — the one merge materializes them into copies (H-ART-2, recorded on
///   `merge_to_tar`), so the packed `st_nlink` is legitimately 1 where the base had N. Contents,
///   mode, ownership and xattrs are all correct; asserting the count would be asserting a
///   documented, deliberate loss.
/// * **paths vmcell itself injects or reserves** — the steward, the CA and the guest-tools tree are
///   put there by the tail *after* the merge, so the base's version of such a path (if any) is not
///   what is in the image, by design (H-ART-3).
/// * **the fixture's own subtree** — it has its own, sharper manifest above.
/// * **paths with characters that would fight the `stat` output parser** — a `|`, whitespace or a
///   newline in a member name is a parsing problem, not a producer problem, and quietly
///   mis-parsing one would be a false failure. Skipping is safe here *because* the sample is a
///   sample: nothing depends on any particular member being in it.
fn base_sample(
    layers: Vec<Box<dyn std::io::Read + Send>>,
    stride: usize,
    cap: usize,
) -> BTreeMap<String, Expected> {
    let mut out = BTreeMap::new();
    let mut eligible = 0usize;
    for layer in layers {
        let mut archive = tar::Archive::new(layer);
        for entry in archive.entries().expect("the base layer must be a tar") {
            let entry = entry.expect("the base layer's members must decode");
            let header = entry.header();
            let Ok(path) = entry.path() else { continue };
            let Some(path) = path.to_str().map(str::to_string) else {
                continue;
            };
            let path = path.trim_end_matches('/').to_string();
            if path.is_empty() || !path_is_parser_safe(&path) || is_excluded(&path) {
                continue;
            }
            // Permission bits only: the file-type bits come from the tar entry type below, exactly
            // the split the producer's emitter makes.
            let mode = header.mode().unwrap_or(0) & 0o7777;
            let uid = u32::try_from(header.uid().unwrap_or(0)).expect("a tar uid fits in u32");
            let gid = u32::try_from(header.gid().unwrap_or(0)).expect("a tar gid fits in u32");
            let expected = match header.entry_type() {
                tar::EntryType::Regular => {
                    Expected::file(mode, uid, gid, header.size().unwrap_or(0))
                }
                tar::EntryType::Directory => Expected::dir(mode, uid, gid),
                tar::EntryType::Symlink => Expected::symlink(mode, uid, gid),
                // Hardlinks and everything else: see the doc comment.
                _ => continue,
            };
            eligible += 1;
            if eligible.is_multiple_of(stride) && out.len() < cap {
                out.insert(path, expected);
            }
        }
    }
    assert!(
        out.len() >= cap / 2,
        "the base-layer sample collapsed to {} members (wanted ~{cap}): the pinned base changed \
         shape, or the exclusions above now swallow it — a sample that shrank silently is a diff \
         that stopped diffing",
        out.len()
    );
    out
}

/// Whether `path` can be round-tripped through the `stat` output parser without ambiguity.
fn path_is_parser_safe(path: &str) -> bool {
    !path.is_empty()
        && path
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'|' && b != b'\\')
}

/// Whether `path` is one the sample must not claim to know the base's answer for — see
/// [`base_sample`]'s doc comment for the three classes.
fn is_excluded(path: &str) -> bool {
    let injected = [
        "usr/sbin/vmcell-steward",
        "vmcell-tools",
        "usr/local/share/ca-certificates",
        "etc/ssl",
        FIXTURE_DIR,
    ];
    injected
        .iter()
        .any(|p| path == *p || path.starts_with(&format!("{p}/")))
}

// -----------------------------------------------------------------------------------------------
// Packing and booting.
// -----------------------------------------------------------------------------------------------

/// The pinned default rootfs registration, through the one registry reader.
fn registered_base() -> (String, String) {
    let entry = vmcell::artifact::resolve_rootfs_entry(
        None,
        vmcell::artifact::pins_overlay_path().as_deref(),
    )
    .expect("resolving the rootfs registry must succeed")
    .expect("the `default` rootfs label must be registered");
    match entry.registration {
        vmcell::artifact::RootfsRegistration::Digest { image, digest } => (image, digest),
        other => panic!(
            "this battery composes a layer over the DIGEST-pinned default base; \
             `rootfs.default` resolved to {other:?} instead"
        ),
    }
}

/// Packs a bootable **ext4** rootfs — the registered base's layers plus [`fixture_layer`] — into
/// `staging`, and returns its path.
///
/// Never into the canonical artifacts dir: packing there would clobber the image every other suite
/// boots. The steward and the guest tools are built by the real stages into `staging`, so the
/// `xattr` applet in the booted guest is this tree's rather than whatever `vmcell build` last
/// published.
///
/// Takes the [`Ext4Available`] receipt, so a leg cannot reach `mkfs.ext4` without having asked
/// whether this host has one.
async fn pack_ext4_rootfs(staging: &std::path::Path, _probed: Ext4Available) -> std::path::PathBuf {
    std::fs::create_dir_all(staging).expect("create the staging dir");

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

    let mut inputs = vmcell::artifact::StageInputs::default();
    inputs.artifacts.extend(built.paths.clone());
    let baked_tools = inputs
        .artifacts
        .get("guest_tools")
        .expect("the guest-tools stage must register its artifact");
    assert!(
        baked_tools.starts_with(staging),
        "the guest-tools binary baked into this image must come from this run's staging dir ({}), \
         so the in-guest `xattr` applet is THIS tree's — got {}",
        staging.display(),
        baked_tools.display()
    );

    let (image, digest) = registered_base();
    let mut streams = vmcell::artifact::rootfs::oci::base_layer_tar_streams(&image, &digest)
        .await
        .expect("resolving the pinned base's layers must succeed");
    streams.push(Box::new(std::io::Cursor::new(fixture_layer())));

    let out = staging.join("rootfs.ext4");
    vmcell::artifact::rootfs::pack_rootfs_with_injection(
        streams,
        &inputs,
        &out,
        // `Preserve`, so the fixture's PAX records reach the image: the whole point of the format
        // is POSIX-completeness, and the xattr leg would be vacuous under the default `Strip`.
        &PackOptions::new()
            .with_format(RootfsFormat::Ext4)
            .with_xattrs(XattrPolicy::Preserve),
    )
    .await
    .expect("the one tail must pack the base plus the fixture as ext4");

    assert!(out.exists(), "the pack must write {}", out.display());
    out
}

/// Boots `image` on Cloud Hypervisor as a [`RootfsSource::Block`] root, networking off.
#[cfg(feature = "cloud-hypervisor")]
async fn boot_ext4_cell(
    vmm: &vmcell::vmm::cloud_hypervisor::CloudHypervisor,
    image: std::path::PathBuf,
) -> vmcell::MicroVm<vmcell::vmm::cloud_hypervisor::CloudHypervisor> {
    let cfg = VmConfig::builder(
        common::get_vmlinux(),
        // THE variant this file exists to exercise. No overlay: the root is read-only, so there is
        // nothing for a per-VM private copy to protect here.
        RootfsSource::Block {
            image,
            overlay: None,
        },
    )
    .network_disabled()
    .build()
    .expect("VmConfig");
    common::start_vm(vmm, cfg).await
}

/// Execs `argv` in the guest and returns `(exit code, stdout, stderr)`.
#[cfg(feature = "cloud-hypervisor")]
async fn exec(steward: &mut vmcell::StewardClient, argv: &[&str]) -> (i32, String, String) {
    let out = steward
        .exec(vmcell::ExecRequest::new(
            argv.iter().map(|s| (*s).to_string()).collect(),
        ))
        .await
        .unwrap_or_else(|e| panic!("exec {argv:?} failed: {e}"));
    (
        out.code,
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Mounts the root block device a second time, read-only, at [`CLEAN_MOUNT`] — the un-overlaid view
/// of the filesystem the producer wrote (see the module docs).
#[cfg(feature = "cloud-hypervisor")]
async fn mount_clean_view(steward: &mut vmcell::StewardClient) {
    let (code, stdout, stderr) = exec(
        steward,
        &[
            "sh",
            "-c",
            &format!("mkdir -p {CLEAN_MOUNT} && mount -o ro /dev/vda {CLEAN_MOUNT}"),
        ],
    )
    .await;
    assert_eq!(
        code, 0,
        "mounting /dev/vda read-only at {CLEAN_MOUNT} must succeed — without it the diff below \
         would be reading the tmpfs overlay rather than the ext4 image.\nstdout: {stdout}\n\
         stderr: {stderr}"
    );
}

/// `lstat`s `paths` in the guest and returns what it saw, keyed by path.
///
/// One `stat` invocation for the whole batch: a per-path exec would spend a vsock round trip per
/// member and turn a 40-member diff into 40 boots' worth of latency. `%f` is the **raw** mode (type
/// bits included), `%t`/`%T` the device numbers in hex; `stat` does not follow symlinks unless
/// asked, which is what makes the symlink's own mode observable.
#[cfg(feature = "cloud-hypervisor")]
async fn lstat_batch(
    steward: &mut vmcell::StewardClient,
    paths: &[String],
) -> BTreeMap<String, Expected> {
    let mut argv: Vec<&str> = vec!["stat", "-c", "%n|%f|%u|%g|%s|%t|%T"];
    argv.extend(paths.iter().map(String::as_str));
    let (code, stdout, stderr) = exec(steward, &argv).await;
    assert_eq!(
        code,
        0,
        "`stat` over {} guest paths must succeed; a missing member is a MISSING member, not a \
         skipped one.\nstderr: {stderr}",
        paths.len()
    );
    let mut out = BTreeMap::new();
    for line in stdout.lines() {
        let f: Vec<&str> = line.split('|').collect();
        assert_eq!(
            f.len(),
            7,
            "unparseable `stat` line {line:?} — the format string and this parser disagree"
        );
        let hex = |s: &str| u32::from_str_radix(s, 16).unwrap_or_else(|e| panic!("hex {s:?}: {e}"));
        let raw_mode = hex(f[1]);
        let is_dev = raw_mode & 0o170_000 == S_IFCHR || raw_mode & 0o170_000 == S_IFBLK;
        let is_reg = raw_mode & 0o170_000 == S_IFREG;
        out.insert(
            f[0].to_string(),
            Expected {
                raw_mode,
                uid: f[2].parse().expect("uid"),
                gid: f[3].parse().expect("gid"),
                size: is_reg.then(|| f[4].parse().expect("size")),
                rdev: is_dev.then(|| (hex(f[5]), hex(f[6]))),
            },
        );
    }
    out
}

/// Diffs `want` (keyed by path relative to the mount) against what the guest reports under
/// [`CLEAN_MOUNT`], failing with every mismatching member rather than the first.
#[cfg(feature = "cloud-hypervisor")]
async fn diff_against_guest(
    steward: &mut vmcell::StewardClient,
    want: &BTreeMap<String, Expected>,
    what: &str,
) {
    let paths: Vec<String> = want.keys().map(|p| format!("{CLEAN_MOUNT}/{p}")).collect();
    let got = lstat_batch(steward, &paths).await;
    let mut mismatches = Vec::new();
    for (rel, expected) in want {
        let full = format!("{CLEAN_MOUNT}/{rel}");
        match got.get(&full) {
            None => mismatches.push(format!("{rel}: absent from the guest's view")),
            Some(actual) if actual != expected => {
                mismatches.push(format!("{rel}: want {expected:?}, got {actual:?}"));
            }
            Some(_) => {}
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} {what} members differ between the tar manifest and the booted ext4 root:\n  {}",
        mismatches.len(),
        want.len(),
        mismatches.join("\n  ")
    );
}

/// Renders bytes as the lowercase hex the `xattr` applet prints.
///
/// Recomputed here rather than shared with the applet: the assertion is that two independent
/// renderings of the same bytes agree, and a shared helper would hide a hex bug on both sides.
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

// -----------------------------------------------------------------------------------------------
// The legs.
// -----------------------------------------------------------------------------------------------

/// **§18 delta 8's named live gate**: an ext4 image packed from the merged tar boots as
/// `RootfsSource::Block`, and its tree, device nodes and extended attributes match the manifest
/// that was packed — read back through the guest kernel's own ext4 driver.
///
/// One test rather than several, because the expensive part is shared: the ~130 MiB pack and the
/// boot. Each leg below carries its own message, so a failure still names which property broke.
///
/// RED on the inverse, per leg:
/// * drop the parent synthesis in `merged_node_map` → the pack itself fails (`mkfs.ext4`:
///   `cannot find directory "opt" to create "vmcell-ext4"`), so the deep-member legs never run;
/// * emit the full `st_mode` in `nodes_to_tar`'s header instead of `mode & 0o7777` → the mode legs
///   differ by the type bits;
/// * split `rdev` with `>> 8` / `& 0xff` instead of `libc::major`/`libc::minor` → the block
///   device's numbers come back as `(4355, 44)`;
/// * hand the pack `XattrPolicy::Strip` → the two `xattr get` legs go from the packed hex to
///   `ENODATA`;
/// * flip any backend's root attach back to read-write → the `/dev/vda` refusal leg passes a write.
#[cfg(feature = "cloud-hypervisor")]
#[tokio::test]
#[ignore = "needs KVM"]
async fn an_ext4_root_boots_and_matches_the_packed_manifest() {
    let Some(probed) = probe_or_record_skip() else {
        return;
    };
    // Ensure the canonical artifacts FIRST: that is what warms the shared OCI blob cache the pack
    // below reuses (and it is at-most-once across the suite).
    let _ = common::get_rootfs();

    // A `TempDir` — cleanup on the panic path as well as the success path. A leaked ~130 MiB image
    // per attempt is how this suite once filled a host tmpfs and reddened an unrelated one.
    let staging = tempfile::tempdir().expect("staging tempdir");
    let image = pack_ext4_rootfs(staging.path(), probed).await;

    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    let mut vm = boot_ext4_cell(&vmm, image).await;
    let steward = vm.steward(None).await.expect("steward");

    // --- The root really is the ext4 image, and the kernel was told to mount it read-only. -------
    // Asserted before the diff: everything below is about what is IN that filesystem, so "the guest
    // booted something else entirely" must not be reported as a manifest mismatch.
    //
    // MEASURED, and worth writing down: the boot-time root mount is **not in `/proc/mounts`** in a
    // `Pid1` cell. The steward `pivot_root`s onto the overlay and then lazily unmounts the old root
    // (`assembly.rs`), so the only `/` line is `overlay / overlay rw,…,lowerdir=/,…`; the ext4
    // superblock stays alive only because overlayfs holds its lower layer. So the boot mount's
    // read-onlyness is asserted from the cmdline the kernel was given, and the *filesystem's* own
    // read-onlyness is asserted where it is observable — the clean mount below, and the
    // rw-mount refusal in `the_ext4_root_is_read_only_and_the_overlay_never_reaches_it`.
    let (code, cmdline, stderr) = exec(steward, &["cat", "/proc/cmdline"]).await;
    assert_eq!(code, 0, "reading /proc/cmdline failed: {stderr}");
    let tokens: Vec<&str> = cmdline.split_ascii_whitespace().collect();
    for token in ["root=/dev/vda", "rootfstype=ext4", "rootflags=noload", "ro"] {
        assert!(
            tokens.contains(&token),
            "a `RootfsSource::Block` cell must boot with `{token}`, or this is not the path delta \
             8 claims to have exercised: {cmdline}"
        );
    }
    assert!(
        !tokens.contains(&"rw"),
        "the root must be mounted `ro`: `rw` plus the `rootflags=noload` above is the silent \
         filesystem corruption F3 reserves the alias to prevent: {cmdline}"
    );
    let (code, mounts, stderr) = exec(steward, &["cat", "/proc/mounts"]).await;
    assert_eq!(code, 0, "reading /proc/mounts failed: {stderr}");
    assert!(
        mounts
            .lines()
            .any(|l| l.contains("overlay / overlay") && l.contains("lowerdir=/")),
        "the `Pid1` cell must have overlaid its root — the ext4 is that overlay's lower layer, \
         which is why the diff below reads the clean mount instead:\n{mounts}"
    );

    // --- The clean, un-overlaid view of the produced filesystem. ---------------------------------
    mount_clean_view(steward).await;
    let (code, mounts, stderr) = exec(steward, &["cat", "/proc/mounts"]).await;
    assert_eq!(code, 0, "re-reading /proc/mounts failed: {stderr}");
    let clean = mounts
        .lines()
        .find(|l| l.split_whitespace().nth(1) == Some(CLEAN_MOUNT))
        .unwrap_or_else(|| panic!("no mount at {CLEAN_MOUNT}:\n{mounts}"));
    let fields: Vec<&str> = clean.split_whitespace().collect();
    assert_eq!(
        fields.get(2),
        Some(&"ext4"),
        "the root block device must carry an ext4 filesystem — the producer's own output, read by \
         the kernel's driver rather than by `debugfs`: {clean}"
    );
    assert!(
        fields
            .get(3)
            .is_some_and(|o| o.split(',').any(|f| f == "ro")),
        "the produced filesystem must be mounted read-only (§4.7): {clean}"
    );

    // --- The fixture manifest: every POSIX shape, attribute for attribute. -----------------------
    diff_against_guest(steward, &fixture_manifest(), "fixture").await;

    // The symlink's target, which `lstat` does not carry.
    let (code, target, stderr) = exec(
        steward,
        &["readlink", &format!("{CLEAN_MOUNT}/{FIXTURE_DIR}/link")],
    )
    .await;
    assert_eq!(code, 0, "readlink on the packed symlink failed: {stderr}");
    assert_eq!(
        target.trim_end(),
        LINK_TARGET,
        "the symlink's target must survive the producer verbatim"
    );

    // The deep member's bytes: a metadata-only diff would be green over an empty file.
    let (code, content, stderr) = exec(
        steward,
        &[
            "cat",
            &format!("{CLEAN_MOUNT}/{FIXTURE_DIR}/deep/nested/dir/leaf"),
        ],
    )
    .await;
    assert_eq!(code, 0, "cat on the deep member failed: {stderr}");
    assert_eq!(
        content.as_bytes(),
        LEAF_CONTENT,
        "the deep member's bytes must survive the producer"
    );

    // --- The extended attribute, byte for byte, through the guest kernel's own getxattr. ---------
    // Three layers no host-side check touches: the ext4 image's inode xattr block, the kernel's
    // ext4 xattr reader, and the capability LSM's `cap_inode_getsecurity`, which parses this value
    // and answers `EINVAL` rather than bytes for anything it does not recognize. "`debugfs` can see
    // it" and "the guest can read it" are genuinely different claims.
    let xattr_path = format!("{CLEAN_MOUNT}/{FIXTURE_DIR}/xattrs");
    let (code, got, stderr) = exec(steward, &["xattr", "get", &xattr_path, CAP_XATTR_NAME]).await;
    assert_eq!(
        code, 0,
        "the guest must be able to read {CAP_XATTR_NAME} off the packed ext4 member: {stderr}"
    );
    assert_eq!(
        got.trim_end(),
        hex(&CAP_XATTR_VALUE),
        "{CAP_XATTR_NAME} must survive the ext4 producer byte for byte"
    );
    // The reader's failure answer is reachable in THIS guest, so the success above is not the
    // applet answering 0 to everything.
    let (code, _, _) = exec(steward, &["xattr", "get", &xattr_path, ABSENT_XATTR_NAME]).await;
    assert_eq!(
        code, 1,
        "an attribute that was never written must be a failed read, or the success above proves \
         nothing about the reader"
    );

    // --- The real base tree, sampled from its own tar. -------------------------------------------
    let (image_ref, digest) = registered_base();
    let layers = vmcell::artifact::rootfs::oci::base_layer_tar_streams(&image_ref, &digest)
        .await
        .expect("re-reading the pinned base's layers must succeed");
    let sample = base_sample(layers, 97, 40);
    println!(
        "ext4 battery: diffing {} sampled base members",
        sample.len()
    );
    diff_against_guest(steward, &sample, "base-layer").await;

    vm.shutdown().await.expect("shutdown");
}

/// The **read-only ratification, on the data plane** (§4.7): the guest cannot write to `/dev/vda`,
/// and the overlay that makes its `/` writable never reaches the ext4 beneath it.
///
/// Two claims one test, because they are two halves of one fact and both need the same boot:
///
/// 1. **The device is read-only.** The backends attach the root disk with
///    `RootfsSource::root_device_read_only()`, so `open("/dev/vda", O_WRONLY)` fails. The positive
///    control is the same `dd` to a path the guest *can* write — without it, "the write failed"
///    could equally mean the exec path is broken. The target offset is the ext4 boot block (the
///    first 1 024 bytes, which the filesystem reserves and never uses), so the inverse run
///    corrupts nothing it will then be blamed for.
/// 2. **A guest write never reaches the image.** Under `Pid1` the steward overlays a tmpfs over
///    `/`, so a write to `/` succeeds — and lands in the upper layer. Reading the same path back
///    through the second, clean mount of `/dev/vda` proves it did not reach the ext4, which is
///    simultaneously what makes the manifest diff above non-vacuous: [`CLEAN_MOUNT`] is genuinely
///    the block device and not a bind of `/`.
///
/// RED on the inverse: flip any backend's root-disk attach back to read-write (`readonly: false` /
/// `is_read_only: false` / dropping `readonly=on` / dropping `ro=true`) and leg 1's `dd` succeeds.
#[cfg(feature = "cloud-hypervisor")]
#[tokio::test]
#[ignore = "needs KVM"]
async fn the_ext4_root_is_read_only_and_the_overlay_never_reaches_it() {
    let Some(probed) = probe_or_record_skip() else {
        return;
    };
    let _ = common::get_rootfs();
    let staging = tempfile::tempdir().expect("staging tempdir");
    let image = pack_ext4_rootfs(staging.path(), probed).await;

    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    let mut vm = boot_ext4_cell(&vmm, image).await;
    let steward = vm.steward(None).await.expect("steward");

    // 1a. Positive control: this guest can write, through this exec path, with this `dd`.
    let (code, stdout, stderr) = exec(
        steward,
        &[
            "sh",
            "-c",
            "dd if=/dev/zero of=/tmp/vmcell-ext4-write-probe bs=512 count=1 2>&1; echo rc=$?",
        ],
    )
    .await;
    assert_eq!(code, 0, "the control `dd` must run: {stderr}");
    assert!(
        stdout.contains("rc=0"),
        "the guest must be able to write SOMEWHERE, or the refusal below proves nothing: {stdout}"
    );

    // 1b. The device itself refuses. `conv=notrunc` and the boot-block offset keep an inverse run
    //     from destroying the filesystem it is about to be asked about.
    let (code, stdout, stderr) = exec(
        steward,
        &[
            "sh",
            "-c",
            "dd if=/dev/zero of=/dev/vda bs=512 count=1 conv=notrunc 2>&1; echo rc=$?",
        ],
    )
    .await;
    assert_eq!(code, 0, "the probing `dd` must run: {stderr}");
    assert!(
        !stdout.contains("rc=0"),
        "writing to /dev/vda must FAIL: the root disk is attached read-only \
         (`RootfsSource::root_device_read_only`) because the kernel mounts it `ro`, and a writable \
         attachment beneath a read-only mount is a write path with no reader — and N zygote clones \
         share one image. Got: {stdout}"
    );

    // 1c. …and the *filesystem* refuses a writable mount, which is the same fact one layer up.
    //     The boot-time root mount is detached by the steward's `pivot_root`, so this is where a
    //     `Pid1` cell's root filesystem read-onlyness is observable at all.
    let (code, stdout, stderr) = exec(
        steward,
        &[
            "sh",
            "-c",
            "mkdir -p /mnt/vmcell-ext4-rw && mount -o rw /dev/vda /mnt/vmcell-ext4-rw 2>&1; \
             echo rc=$?",
        ],
    )
    .await;
    assert_eq!(code, 0, "the rw-mount probe must run: {stderr}");
    assert!(
        !stdout.contains("rc=0"),
        "mounting the root filesystem READ-WRITE must fail — the device is attached read-only and \
         `rootflags=noload` suppresses the journal recovery a writable ext4 mount would need. \
         Got: {stdout}"
    );

    // 2. The overlay's writability does not reach the ext4.
    mount_clean_view(steward).await;
    const MARKER: &str = "/vmcell-ext4-overlay-marker";
    let (code, stdout, stderr) = exec(
        steward,
        &[
            "sh",
            "-c",
            &format!("echo marker > {MARKER} 2>&1; echo rc=$?"),
        ],
    )
    .await;
    assert_eq!(code, 0, "the overlay write must run: {stderr}");
    assert!(
        stdout.contains("rc=0"),
        "under `Pid1` the guest's `/` is an overlay with a tmpfs upper, so this write must \
         SUCCEED — if it does not, the leg below is vacuous: {stdout}"
    );
    let (code, _, _) = exec(steward, &["cat", MARKER]).await;
    assert_eq!(
        code, 0,
        "the marker must be readable back through the overlay"
    );
    let (code, stdout, _) = exec(steward, &["cat", &format!("{CLEAN_MOUNT}{MARKER}")]).await;
    assert_ne!(
        code, 0,
        "a guest write must NOT reach the ext4 image: the root is read-only and the write lands in \
         the overlay's tmpfs upper. Reading it back through the clean mount returned: {stdout}"
    );

    vm.shutdown().await.expect("shutdown");
}

// -----------------------------------------------------------------------------------------------
// The wiring gate.
// -----------------------------------------------------------------------------------------------

/// **The selection gate**: a live suite recipe actually runs this binary's `#[ignore]`d legs.
///
/// The defect class is m24, not delta 9's: the artifact-conformance battery sat `#[ignore]`d and
/// *selected by no invocation in the tree* — compiled, never run, its only proof that it could go
/// red silently dead. `test-privileged`'s filterset is `kind(test) & !(test(unprivileged) |
/// test(smoltcp))`, so this binary is selected by construction — provided its **name** stays
/// outside those two exclusions and the recipe keeps `--run-ignored all`. Both are textual
/// properties of the justfile and the binary's own name, so both are checked here, KVM-free.
///
/// Deliberately *not* an opt-in: unlike the systemd proof cell there is no image to pull and no
/// designated device to nominate, so the only reason a host cannot run these legs is an e2fsprogs
/// too old for `-d <tarball>` — which the product's own probe answers, and which is recorded as a
/// capability skip rather than smuggled into a filter (delta 9's lesson: a nextest name filter is
/// not an opt-in, and it is not an opt-out either).
///
/// RED ON INVERSE: rename this binary to something matching `unprivileged`/`smoltcp` (arm 2), or
/// drop `--run-ignored all` from `test-privileged` (arm 1).
#[test]
fn the_live_legs_are_selected_by_a_suite_recipe() {
    const JUSTFILE: &str = include_str!("../../../justfile");
    /// This integration-test binary's name, which is the file's stem and what nextest filters on.
    const BINARY: &str = "ext4_cell";

    let body = JUSTFILE
        .split_once("\ntest-privileged:")
        .map(|(_, rest)| rest.split("\n\n").next().unwrap_or(rest))
        .unwrap_or_else(|| panic!("the justfile must carry a `test-privileged` recipe"));

    // 1. The recipe runs ignored tests at all. Without this every leg here is compiled and skipped.
    assert!(
        body.contains("--run-ignored all"),
        "`just test-privileged` must pass `--run-ignored all`, or this binary's `#[ignore]`d live \
         legs are compiled and never run (the m24 defect). Recipe body:\n{body}"
    );

    // 2. This binary's name survives the recipe's exclusions. Composed from the recipe's own text
    //    so a change to the filterset's exclusions is what reddens, not a copy of them here.
    for excluded in ["unprivileged", "smoltcp"] {
        assert!(
            body.contains(&format!("test({excluded})")),
            "`test-privileged`'s filterset no longer excludes `{excluded}` — this gate reads the \
             recipe's exclusions from the recipe, so it must be re-derived rather than assumed. \
             Recipe body:\n{body}"
        );
        assert!(
            !BINARY.contains(excluded),
            "the `{BINARY}` test binary's name matches `test({excluded})`, which \
             `test-privileged` excludes: these legs would be filtered out of the one suite that \
             selects them"
        );
    }
}

/// The fixture manifest and the fixture layer describe the same members.
///
/// KVM-free, and it exists because the two are deliberately independent renderings (see
/// [`fixture_manifest`]): independent is only a virtue if a member added to one and forgotten in
/// the other is caught, rather than silently dropping out of the diff.
#[test]
fn the_fixture_manifest_and_the_fixture_layer_agree_on_the_member_set() {
    let mut in_layer: Vec<String> = Vec::new();
    let mut archive = tar::Archive::new(std::io::Cursor::new(fixture_layer()));
    for entry in archive.entries().expect("the fixture layer is a tar") {
        let entry = entry.expect("fixture member");
        // PAX extension headers are metadata for the next member, never members themselves.
        if entry.header().entry_type().is_pax_local_extensions() {
            continue;
        }
        let path = entry.path().expect("fixture member path");
        in_layer.push(path.to_string_lossy().trim_end_matches('/').to_string());
    }
    in_layer.sort();

    let mut in_manifest: Vec<String> = fixture_manifest().keys().cloned().collect();
    // The three synthesized parents are in the manifest ON PURPOSE and are absent from the layer
    // ON PURPOSE — that gap is the property the deep member exists to prove. Everything else must
    // match exactly.
    let synthesized = [
        format!("{FIXTURE_DIR}/deep"),
        format!("{FIXTURE_DIR}/deep/nested"),
        format!("{FIXTURE_DIR}/deep/nested/dir"),
    ];
    for parent in &synthesized {
        assert!(
            !in_layer.contains(parent),
            "the fixture layer must NOT ship {parent}: the packer's parent synthesis is what has \
             to put it in the image, and a layer that shipped it would make the live leg vacuous"
        );
        assert!(
            in_manifest.contains(parent),
            "the manifest must expect the synthesized parent {parent}"
        );
    }
    in_manifest.retain(|p| !synthesized.contains(p));
    in_manifest.sort();

    assert_eq!(
        in_manifest, in_layer,
        "every fixture-layer member must have a manifest expectation and vice versa, or a shape \
         quietly drops out of the live diff"
    );
}
