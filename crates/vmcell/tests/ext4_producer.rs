//! The §15.4 **ext4** battery, producer half (design §4.7, §18 delta 8).
//!
//! Everything here is KVM-free. It covers the three things a live boot cannot see and the three the
//! live boot depends on:
//!
//! * the **merged tar** — the interchange §4.7 names and that did not exist before this delta —
//!   carries the parents `mkfs.ext4 -d` refuses to synthesize, in parents-before-children order;
//! * the **version probe** refuses both halves of its gate (too-old e2fsprogs, absent libarchive),
//!   each against a stand-in that produces exactly that failure;
//! * the produced image is **byte-deterministic**, which `mkfs.ext4` is not by default — delta 7's
//!   pack-twice gate, extended to this producer, with the un-pinned invocation as its control;
//! * and the image really carries the POSIX shapes the format was added for (device nodes, xattrs,
//!   modes, ownership), read back with `debugfs` rather than asserted from the tar we wrote.
//!
//! The in-guest tree/xattr/device diff against a booted `RootfsSource::Block` cell is the battery's
//! live half and lives with the boot harness.
//!
//! # An absent e2fsprogs is a RECORDED skip, and CI obtains the facility rather than living with it
//!
//! The legs that pack an image used to **panic** here, on the argument that `e2fsprogs` is
//! `Priority: required` everywhere vmcell builds. The package is; the *version* is not. GitHub's
//! `ubuntu-24.04` image ships 1.47.0 and `-d <tarball>` needs
//! [`MIN_E2FSPROGS_VERSION`] — one patch release — so the panic made `test-unit` and
//! `test-integration` red for four commits (four failing tests, each retried four times by the
//! integration profile) while the review pass that introduced it ran the suites only on a host with
//! 1.47.2. A permanently-red job is a job nobody reads, which is a worse outcome than a skip.
//!
//! So the legs ask [`common::probe_ext4_or_record_skip`] — **the one law**, shared with `ext4_cell.rs`
//! and `repack_outside_checkout.rs` — which records `SKIP cloud-hypervisor ext4_producer` to
//! `VMCELL_SKIP_MANIFEST` before returning `None`. That keeps the gap reviewable through
//! `just skip-manifest-show` instead of green, which is the whole difference between a recorded skip
//! and the `println!("SKIP") + return` AGENTS.md names as a green PASS. A *broken* facility still
//! panics (§7.2 rule 3).
//!
//! A skip is not a substitute for coverage, so the other half of the fix is in
//! `.github/workflows/ci.yml`: every job that runs these legs builds a pinned, checksum-verified
//! e2fsprogs from source first, non-gating, so the normal outcome is that the battery **runs** and
//! the recorded skip is the fallback. [`ci_obtains_the_ext4_facility_rather_than_living_with_the_skip`]
//! is that step's gate, and [`every_ext4_battery_asks_the_one_law`] is the call-site scan that keeps
//! a fourth answer to "this host has no `mkfs.ext4`" from appearing.

#![cfg(all(feature = "pipeline", feature = "ext4-producer"))]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use vmcell::artifact::RootfsFormat;
use vmcell::artifact::ext4::{
    EXT4_PRODUCER_BIN, EXT4_TARBALL_XATTRS, Ext4Identity, Ext4Producer, MIN_E2FSPROGS_VERSION,
};
use vmcell::artifact::rootfs::{PackOptions, XattrPolicy};
use vmcell::artifact::tar2erofs::{merge_to_tar, tar_to_erofs};
use vmcell::error::Error;

mod common;

/// A real v3 `security.capability` blob (the on-disk form of an effective+permitted
/// `CAP_NET_RAW`), so the readback below proves the exact bytes survived rather than that
/// *something* survived.
///
/// Written as a byte array rather than as the shell command that produces it, deliberately: the
/// `vmcell-privilege` drift gate walks the whole tree for `setcap …` copies and asserts each one
/// grants `BLESSED_FILE_CAPS`, so a doc comment quoting a different grant reddens it. That gate is
/// right and this fixture has nothing to do with blessing.
const CAP_XATTR: &[u8] = &[
    0x01, 0x00, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

/// A source layer with every node shape the merge can produce, plus a member whose parents the
/// layer deliberately does **not** ship.
///
/// The missing parents are the point: `mkfs.ext4 -d` performs no implicit directory synthesis and
/// errors loud naming the directory it cannot find, so a merged tar that did not carry them would
/// fail the build. The packer's own synthesis is what puts them there, and
/// [`merged_tar_carries_synthesized_parents`] is what pins that it reaches the tar.
fn probe_layer() -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut b = tar::Builder::new(&mut buf);

        // A regular file under THREE directories the layer never declares.
        let mut f = tar::Header::new_gnu();
        f.set_size(5);
        f.set_mode(0o755);
        f.set_uid(0);
        f.set_gid(0);
        f.set_mtime(0);
        b.append_data(&mut f, "deep/nested/dir/thing", &b"hello"[..])
            .expect("append the orphaned member");

        // A libc6 the packer's own scan demands (the tail is called with `require_libc6`).
        let mut libc = tar::Header::new_gnu();
        libc.set_size(2);
        libc.set_mode(0o644);
        libc.set_mtime(0);
        b.append_data(&mut libc, "usr/lib/libc.so.6", &b"so"[..])
            .expect("append libc6");

        // A file carrying a real `security.capability` — the attribute the ext4 format exists for.
        b.append_pax_extensions([("SCHILY.xattr.security.capability", CAP_XATTR)])
            .expect("append the PAX xattr record");
        let mut ping = tar::Header::new_gnu();
        ping.set_size(4);
        ping.set_mode(0o755);
        ping.set_uid(0);
        ping.set_gid(0);
        ping.set_mtime(0);
        b.append_data(&mut ping, "usr/bin/ping", &b"ping"[..])
            .expect("append the capability-bearing file");

        // A character device: `/dev/null`, 1:3.
        let mut dev = tar::Header::new_gnu();
        dev.set_entry_type(tar::EntryType::Char);
        dev.set_size(0);
        dev.set_mode(0o666);
        dev.set_device_major(1).expect("major");
        dev.set_device_minor(3).expect("minor");
        dev.set_mtime(0);
        b.append_data(&mut dev, "dev/null", std::io::empty())
            .expect("append the device node");

        // A BLOCK device whose numbers exceed 8 bits apiece — `nvme0n1`-shaped, 259:300. Load
        // bearing: Linux's `dev_t` encoding is NOT `(major << 8) | minor`, it scatters the high
        // bits, and 1:3 comes back right under either reading. This node is the one that
        // discriminates, which is why the emitter goes through `libc::major`/`libc::minor` rather
        // than a shift/mask (the same defect the decode arm's `makedev` comment records).
        let mut big = tar::Header::new_gnu();
        big.set_entry_type(tar::EntryType::Block);
        big.set_size(0);
        big.set_mode(0o660);
        big.set_device_major(259).expect("major");
        big.set_device_minor(300).expect("minor");
        big.set_mtime(0);
        b.append_data(&mut big, "dev/nvme0n1", std::io::empty())
            .expect("append the wide device node");

        // A FIFO, a symlink, and an owned-by-non-root file — the remaining node shapes.
        let mut fifo = tar::Header::new_gnu();
        fifo.set_entry_type(tar::EntryType::Fifo);
        fifo.set_size(0);
        fifo.set_mode(0o644);
        fifo.set_mtime(0);
        b.append_data(&mut fifo, "run/pipe", std::io::empty())
            .expect("append the fifo");

        let mut link = tar::Header::new_gnu();
        link.set_entry_type(tar::EntryType::Symlink);
        link.set_size(0);
        link.set_mode(0o777);
        link.set_mtime(0);
        link.set_link_name("ping").expect("symlink target");
        b.append_data(&mut link, "usr/bin/ping6", std::io::empty())
            .expect("append the symlink");

        let mut owned = tar::Header::new_gnu();
        owned.set_size(3);
        owned.set_mode(0o600);
        owned.set_uid(1234);
        owned.set_gid(5678);
        owned.set_mtime(0);
        b.append_data(&mut owned, "var/owned", &b"abc"[..])
            .expect("append the owned file");

        b.finish().expect("finish the probe layer");
    }
    buf
}

/// The merged tar of [`probe_layer`], through the one merge, under `policy`.
fn merged(policy: XattrPolicy) -> Vec<u8> {
    merge_to_tar(
        vec![tar::Archive::new(std::io::Cursor::new(probe_layer()))],
        vec![],
        vec![],
        vec![],
        true,
        policy,
    )
    .expect("the merge produces a tar")
}

/// Every member of `tar`, in emitted order, as `(path, entry type byte)`.
fn members(tar_bytes: &[u8]) -> Vec<(String, u8)> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    let mut out = Vec::new();
    for entry in archive.entries().expect("entries") {
        let entry = entry.expect("entry");
        let entry_type = entry.header().entry_type();
        if entry_type.is_pax_global_extensions()
            || entry_type.is_pax_local_extensions()
            || entry_type.is_gnu_longname()
            || entry_type.is_gnu_longlink()
        {
            continue;
        }
        out.push((
            entry.path().expect("path").to_string_lossy().into_owned(),
            entry_type.as_byte(),
        ));
    }
    out
}

/// One `debugfs -R "<request>"` against `image`, as text.
fn debugfs(image: &Path, request: &str) -> String {
    let out = std::process::Command::new("debugfs")
        .arg("-R")
        .arg(request)
        .arg(image)
        .output()
        .unwrap_or_else(|e| {
            panic!("debugfs (e2fsprogs) must be on PATH for the readback leg: {e}")
        });
    assert!(
        out.status.success(),
        "debugfs -R {request:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Runs `e2fsck -fn` over `image` and asserts it reports a clean filesystem.
///
/// The strongest KVM-free statement this battery can make about the produced bytes: `e2fsck` is the
/// reference implementation's own consistency checker, and it walks the same structures the kernel
/// mounts — a bad extent tree, a wrong `st_nlink`, an orphaned inode or a bad checksum is a
/// non-zero exit here, before the live leg spends a boot discovering it. `-n` answers no to every
/// repair, so the image is never modified.
fn fsck_clean(image: &Path) {
    let out = std::process::Command::new("e2fsck")
        .arg("-fn")
        .arg(image)
        .output()
        .unwrap_or_else(|e| panic!("e2fsck (e2fsprogs) must be on PATH for the fsck leg: {e}"));
    assert!(
        out.status.success(),
        "e2fsck must report the produced image clean (exit {:?}):\n{}\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Writes an executable stand-in for `mkfs.ext4` that answers `-V` with `version_banner` and
/// answers every other invocation by writing `failure` to stderr and exiting 1.
///
/// The probe has to be drivable against a tool that fails the way a real one fails, or the refusals
/// it classifies are refusals nobody has watched it produce.
fn stub_mkfs(dir: &Path, version_banner: &str, failure: &str) -> PathBuf {
    let path = dir.join("mkfs.ext4");
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\nif [ \"$1\" = \"-V\" ]; then printf '%s\\n' '{version_banner}' >&2; \
             exit 0; fi\nprintf '%s\\n' '{failure}' >&2\nexit 1\n"
        ),
    )
    .expect("write the stub");
    let mut perms = std::fs::metadata(&path)
        .expect("stat the stub")
        .permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    std::fs::set_permissions(&path, perms).expect("chmod the stub");
    path
}

/// [`Ext4Producer::probe_binary`] against a stub, retried past **ETXTBSY**.
///
/// A test's own fixture is its own problem (AGENTS.md's residue rule, one hazard over). The tests in
/// this file run as threads of one process: while thread A is inside `std::fs::write` for its stub,
/// thread B's `Command` forks and the child inherits A's still-open write descriptor, so A's very
/// next `execve` of that path gets `ETXTBSY` until the child execs and closes it. That surfaces
/// from the production probe as `Error::Io` — correct behavior (a present-but-unrunnable binary is
/// a BROKEN facility keeping its errno, §7.2), and a wrong verdict about a stub the test itself
/// just created.
///
/// Only `ExecutableFileBusy` is retried, and only for a bounded window, so a genuine `Error::Io`
/// classification is never masked: an `EACCES` stub would return on the first pass exactly as it
/// does today. Observed in a full-file run before this existed, green in isolation — the shape of a
/// flake that reads as a product defect and is not one.
fn probe_stub(path: &Path) -> Result<Ext4Producer, Error> {
    for _ in 0..50 {
        match Ext4Producer::probe_binary(path) {
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            other => return other,
        }
    }
    Ext4Producer::probe_binary(path)
}

// ---------------------------------------------------------------------------------------------
// The merged tar
// ---------------------------------------------------------------------------------------------

/// **The parent-dirs-present pin**, tar half.
///
/// `mkfs.ext4 -d` performs no implicit directory synthesis: a member whose parent is absent is
/// `File not found by ext2_lookup … cannot find directory` and exit 1, measured on e2fsprogs 1.47.2.
/// §4.7 claims the merged tail "already guarantees" the parents — it guarantees them in an EROFS
/// node map, and this is where that guarantee becomes true of a tar.
///
/// RED on the inverse two ways: delete the parent-synthesis loop from `merged_node_map` and the
/// `deep`/`deep/nested`/`deep/nested/dir` assertions fail; replace the emitter's ascending sort with
/// the `HashMap`'s own order and the ordering assertion fails (non-deterministically, which is why
/// it is asserted as a property rather than against a fixed list).
#[test]
fn merged_tar_carries_synthesized_parents() {
    let tar_bytes = merged(XattrPolicy::Strip);
    let members = members(&tar_bytes);
    let paths: Vec<&str> = members.iter().map(|(p, _)| p.as_str()).collect();

    // The layer shipped NONE of these; the merge synthesized all three.
    for parent in ["deep", "deep/nested", "deep/nested/dir"] {
        let found = members
            .iter()
            .find(|(p, _)| p == parent)
            .unwrap_or_else(|| {
                panic!("the merged tar must carry the synthesized `{parent}`: {paths:?}")
            });
        assert_eq!(
            found.1,
            tar::EntryType::Directory.as_byte(),
            "`{parent}` must be a DIRECTORY member, not whatever type happened to precede it"
        );
    }
    // The root itself is `mkfs.ext4`'s (inode 2) and is deliberately not emitted.
    assert!(
        !paths.contains(&""),
        "the synthesized root must not be emitted as a member: {paths:?}"
    );

    // Parents before children, for EVERY member — the property `mkfs.ext4 -d` actually needs. An
    // emitter that got this right for the fixture and wrong in general would pass a fixed list.
    let mut seen: Vec<&str> = Vec::new();
    for path in &paths {
        if let Some(parent) = Path::new(path).parent().and_then(Path::to_str)
            && !parent.is_empty()
        {
            assert!(
                seen.contains(&parent),
                "`{path}` precedes its parent `{parent}` in the merged tar: {paths:?}"
            );
        }
        seen.push(path);
    }
}

/// The merged tar carries every node SHAPE the merge produces, with the type, mode, ownership and
/// device numbers intact — not just the regular files.
///
/// RED on the device arm re-deriving `(major, minor)` as a shift/mask instead of through
/// `libc::major`/`libc::minor`: `dev/null` comes back with the wrong numbers. RED on writing the
/// full `st_mode` into the header: the modes below gain their `S_IF*` bits.
#[test]
fn merged_tar_carries_every_node_shape() {
    let tar_bytes = merged(XattrPolicy::Preserve);
    let mut archive = tar::Archive::new(std::io::Cursor::new(&tar_bytes));
    let mut seen: BTreeMap<String, (u8, u32, u64, u64)> = BTreeMap::new();
    let mut device: Option<(u32, u32)> = None;
    let mut wide_device: Option<(u32, u32)> = None;
    let mut symlink_target = String::new();
    let mut cap_xattr: Option<Vec<u8>> = None;
    for entry in archive.entries().expect("entries") {
        let mut entry = entry.expect("entry");
        let path = entry.path().expect("path").to_string_lossy().into_owned();
        let header = entry.header();
        let entry_type = header.entry_type();
        if entry_type.is_pax_global_extensions()
            || entry_type.is_pax_local_extensions()
            || entry_type.is_gnu_longname()
            || entry_type.is_gnu_longlink()
        {
            continue;
        }
        if path == "dev/null" {
            device = Some((
                header
                    .device_major()
                    .expect("major")
                    .expect("major present"),
                header
                    .device_minor()
                    .expect("minor")
                    .expect("minor present"),
            ));
        }
        if path == "dev/nvme0n1" {
            wide_device = Some((
                header
                    .device_major()
                    .expect("major")
                    .expect("major present"),
                header
                    .device_minor()
                    .expect("minor")
                    .expect("minor present"),
            ));
        }
        if path == "usr/bin/ping6" {
            symlink_target = header
                .link_name()
                .expect("link name")
                .expect("link name present")
                .to_string_lossy()
                .into_owned();
        }
        seen.insert(
            path.clone(),
            (
                entry_type.as_byte(),
                header.mode().expect("mode"),
                header.uid().expect("uid"),
                header.gid().expect("gid"),
            ),
        );
        if path == "usr/bin/ping"
            && let Some(exts) = entry.pax_extensions().expect("pax extensions")
        {
            for ext in exts {
                let ext = ext.expect("pax record");
                if ext.key().expect("key") == "SCHILY.xattr.security.capability" {
                    cap_xattr = Some(ext.value_bytes().to_vec());
                }
            }
        }
    }

    assert_eq!(
        seen.get("dev/null").map(|s| s.0),
        Some(tar::EntryType::Char.as_byte()),
        "the character device must survive as a Char member: {seen:?}"
    );
    assert_eq!(device, Some((1, 3)), "the device numbers must round-trip");
    assert_eq!(
        seen.get("dev/nvme0n1").map(|s| s.0),
        Some(tar::EntryType::Block.as_byte()),
        "the block device must survive as a Block member, not as a Char one: {seen:?}"
    );
    assert_eq!(
        wide_device,
        Some((259, 300)),
        "device numbers WIDER than 8 bits must round-trip — `dev_t` is not `(major << 8) | minor`,          and 1:3 above comes back right under either reading, so this is the discriminating leg"
    );
    assert_eq!(
        seen.get("run/pipe").map(|s| s.0),
        Some(tar::EntryType::Fifo.as_byte())
    );
    assert_eq!(
        seen.get("usr/bin/ping6").map(|s| s.0),
        Some(tar::EntryType::Symlink.as_byte())
    );
    assert_eq!(symlink_target, "ping");
    // Permission bits only — no `S_IFREG` leaking into the header's mode field.
    assert_eq!(seen.get("usr/bin/ping").map(|s| s.1), Some(0o755));
    assert_eq!(seen.get("var/owned").map(|s| s.1), Some(0o600));
    assert_eq!(seen.get("deep").map(|s| s.1), Some(0o755));
    // Ownership travels; the synthesized parents are root:root.
    assert_eq!(
        seen.get("var/owned").map(|s| (s.2, s.3)),
        Some((1234, 5678))
    );
    assert_eq!(seen.get("deep").map(|s| (s.2, s.3)), Some((0, 0)));
    // And the xattr, under `Preserve`, as a `SCHILY.xattr.*` record.
    assert_eq!(
        cap_xattr.as_deref(),
        Some(CAP_XATTR),
        "the `Preserve` policy must reach the merged tar as a PAX record"
    );
}

/// The [`XattrPolicy`] governs the merged tar exactly as it governs the erofs image — the ext4
/// route inherits the policy rather than reimplementing it (§4.7, obligation 3 of §4.3).
///
/// RED on the tar emitter ignoring the merged nodes' xattrs (both legs would carry none) or on it
/// inventing them (the `Strip` leg would carry one).
#[test]
fn the_xattr_policy_governs_the_merged_tar_too() {
    let has_record = |bytes: &[u8]| -> bool {
        let mut archive = tar::Archive::new(std::io::Cursor::new(bytes.to_vec()));
        archive.entries().expect("entries").any(|e| {
            let mut e = e.expect("entry");
            e.pax_extensions().ok().flatten().is_some_and(|exts| {
                exts.filter_map(std::result::Result::ok)
                    .any(|x| x.key().is_ok_and(|k| k.starts_with("SCHILY.xattr.")))
            })
        })
    };
    assert!(
        has_record(&merged(XattrPolicy::Preserve)),
        "`Preserve` must carry the source record into the merged tar"
    );
    assert!(
        !has_record(&merged(XattrPolicy::Strip)),
        "`Strip` must carry none — the default artifact's tar is the pre-v33 tree exactly"
    );
}

/// Both emitters consume the **one** merge, so the two artifacts describe the same tree.
///
/// The property that makes §4.7's "inherited for free" checkable rather than a claim: the erofs
/// image and the merged tar are produced from the same `merged_node_map`, so the erofs pack still
/// succeeds over the same inputs and the tar's member set is exactly the merged tree's paths.
///
/// RED on the ext4 route growing its own merge: a second implementation would drift on the
/// synthesized parents (the erofs half has them, the tar half would not), which the path comparison
/// below catches.
#[test]
fn both_emitters_consume_the_one_merge() {
    let image = tar_to_erofs(
        vec![tar::Archive::new(std::io::Cursor::new(probe_layer()))],
        vec![],
        vec![],
        vec![],
        true,
        XattrPolicy::Strip,
    )
    .expect("the erofs emitter still packs the same tree");
    assert!(!image.is_empty());

    let paths: Vec<String> = members(&merged(XattrPolicy::Strip))
        .into_iter()
        .map(|(p, _)| p)
        .collect();
    for expected in [
        "deep",
        "deep/nested",
        "deep/nested/dir",
        "deep/nested/dir/thing",
        "dev",
        "dev/null",
        "dev/nvme0n1",
        "run",
        "run/pipe",
        "usr",
        "usr/bin",
        "usr/bin/ping",
        "usr/bin/ping6",
        "usr/lib",
        "usr/lib/libc.so.6",
        "var",
        "var/owned",
    ] {
        assert!(
            paths.iter().any(|p| p == expected),
            "the merged tar must carry `{expected}`: {paths:?}"
        );
    }
    assert_eq!(
        paths.len(),
        17,
        "and nothing else — an extra member is a node the merge invented: {paths:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// The version probe
// ---------------------------------------------------------------------------------------------

/// **The version-probe typed refusal**, half one: e2fsprogs older than the gate.
///
/// Classified as an ABSENT facility (`CapabilityUnavailable`), per §7.2 — the tool is there and
/// works, it simply has no `-d <tarball>`. A silent mis-build here is the worst outcome the gate
/// exists to prevent: pre-1.47.1 `-d` accepts only a DIRECTORY, so it would have built the image
/// from an empty scratch path and reported success.
///
/// RED on the inverse: drop the `version < MIN_E2FSPROGS_VERSION` arm from `probe_binary` and this
/// stub is accepted.
#[test]
fn the_version_probe_refuses_a_too_old_e2fsprogs() {
    let dir = tempfile::tempdir().expect("tempdir");
    for banner in ["mke2fs 1.46.5 (30-Dec-2021)", "mke2fs 1.47.0 (5-Feb-2023)"] {
        let stub = stub_mkfs(dir.path(), banner, "should never run");
        match probe_stub(&stub) {
            Err(Error::CapabilityUnavailable { op, needed }) => {
                assert!(op.contains("ext4"), "the op names the operation: {op}");
                assert!(
                    needed.contains("1.47.1"),
                    "the refusal must name the required version: {needed}"
                );
            }
            other => panic!("`{banner}` must be refused as an absent facility, got {other:?}"),
        }
    }
}

/// **The version-probe typed refusal**, half two: libarchive absent.
///
/// This is the hard half. `mke2fs` **dlopen**s libarchive rather than linking it, so `-V` reports a
/// perfectly new-enough version whether or not tarballs work and `ldd` shows nothing at all — a
/// probe built on the version string alone would wave this through and then fail after the merge,
/// or worse, build something. The stub answers `-V` with 1.47.2 and fails a real invocation with
/// the tool's own marker, which is exactly the shape of the failure on a host without libarchive.
///
/// RED on the inverse: delete the `probe_libarchive` call from `probe_binary` and the stub is
/// accepted despite being unable to read a tarball.
#[test]
fn the_version_probe_refuses_an_absent_libarchive() {
    let dir = tempfile::tempdir().expect("tempdir");
    let stub = stub_mkfs(
        dir.path(),
        "mke2fs 1.47.2 (1-Jan-2025)",
        "__populate_fs_from_tar: you need libarchive to be able to process tarballs",
    );
    match probe_stub(&stub) {
        Err(Error::CapabilityUnavailable { op, needed }) => {
            assert!(op.contains("ext4"), "the op names the operation: {op}");
            assert!(
                needed.contains("libarchive"),
                "the refusal must name libarchive: {needed}"
            );
        }
        other => panic!(
            "a version-new-enough tool that cannot read tarballs must be refused as an absent facility, got {other:?}"
        ),
    }
}

/// A trial build that fails for some OTHER reason is an `Artifact` error quoting the tool, not a
/// capability claim — the two are different problems with different fixes, and flattening them
/// would tell an operator to install a libarchive they already have.
#[test]
fn a_trial_build_failure_that_is_not_libarchive_is_not_a_capability_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let stub = stub_mkfs(
        dir.path(),
        "mke2fs 1.47.2 (1-Jan-2025)",
        "mke2fs: Permission denied while trying to determine filesystem size",
    );
    match probe_stub(&stub) {
        Err(Error::Artifact(message)) => {
            assert!(
                message.contains("Permission denied"),
                "the refusal must quote what the tool said: {message}"
            );
        }
        other => {
            panic!("an unclassified trial-build failure must be an Artifact error, got {other:?}")
        }
    }
}

/// An absent binary is an absent facility, and an unreadable banner is a refusal rather than an
/// assumption — assuming a new-enough version is the silent mis-build the gate exists to prevent.
#[test]
fn the_version_probe_refuses_an_absent_binary_and_an_unreadable_banner() {
    let dir = tempfile::tempdir().expect("tempdir");
    match probe_stub(&dir.path().join("no-such-mkfs")) {
        Err(Error::CapabilityUnavailable { needed, .. }) => {
            assert!(
                needed.contains("e2fsprogs"),
                "the refusal must name the package to install: {needed}"
            );
        }
        other => panic!("an absent binary must be an absent facility, got {other:?}"),
    }

    let stub = stub_mkfs(dir.path(), "mkfs.ext4: unrecognized option '-V'", "unused");
    match probe_stub(&stub) {
        Err(Error::Artifact(message)) => assert!(
            message.contains("cannot read an e2fsprogs version"),
            "an unreadable banner must refuse naming itself: {message}"
        ),
        other => panic!("an unreadable banner must be refused, got {other:?}"),
    }
}

/// The real tool on this host passes both halves — the positive control every negative above needs.
///
/// On a host whose e2fsprogs cannot pack tarballs there is nothing for a positive control to
/// control, so this returns on the one law's recorded skip like every other packing leg. The
/// negatives above are stub-driven and keep running there, which is what makes the refusals'
/// coverage independent of the host's own tool.
#[test]
fn the_real_producer_passes_its_own_gate() {
    let Some(producer) = common::probe_ext4_or_record_skip() else {
        return;
    };
    assert!(
        producer.version() >= MIN_E2FSPROGS_VERSION,
        "the probe must report the version it gated on: {:?}",
        producer.version()
    );
}

// ---------------------------------------------------------------------------------------------
// The produced image
// ---------------------------------------------------------------------------------------------

/// **Pack-twice byte determinism** for the ext4 producer — delta 7's gate, extended (§10.3).
///
/// `mkfs.ext4` is NOT byte-deterministic by default; the control leg below proves it on the host
/// running this test rather than trusting the claim. Byte-identity needs `SOURCE_DATE_EPOCH`, a
/// pinned `-U` **and** a pinned non-null `-E hash_seed=` together, all three derived from the merged
/// tar's own content.
///
/// RED on the inverse: drop any one of the three from `mkfs_args`/the env and the two packs differ.
#[test]
fn packing_twice_is_byte_identical_and_the_unpinned_control_is_not() {
    let Some(producer) = common::probe_ext4_or_record_skip() else {
        return;
    };
    let tar_bytes = merged(XattrPolicy::Preserve);
    let dir = tempfile::tempdir().expect("tempdir");

    let mut digests = Vec::new();
    for leg in ["first", "second"] {
        // A real second apart, so a clock-derived field would differ. Cheap: the images are small.
        if leg == "second" {
            std::thread::sleep(std::time::Duration::from_millis(1100));
        }
        let out = dir.path().join(format!("pack-{leg}.ext4"));
        producer.pack(&tar_bytes, &out).expect("the producer packs");
        digests.push(blake3::hash(&std::fs::read(&out).expect("read the image")));
    }
    assert_eq!(
        digests[0], digests[1],
        "two packs of one merged tar must be byte-identical — a content-addressed artifact whose \
         bytes move on every re-pack invalidates §10.2's tamper check on every build"
    );

    // The control: the same tool over the same tar WITHOUT the three knobs. If this were also
    // identical, the assertion above would be vacuous.
    let mut unpinned = Vec::new();
    let tar_path = dir.path().join("merged.tar");
    std::fs::write(&tar_path, &tar_bytes).expect("stage the tar");
    for leg in ["a", "b"] {
        if leg == "b" {
            std::thread::sleep(std::time::Duration::from_millis(1100));
        }
        let out = dir.path().join(format!("control-{leg}.ext4"));
        let file = std::fs::File::create(&out).expect("create the control image");
        file.set_len(32 * 1024 * 1024).expect("size it");
        drop(file);
        let status = std::process::Command::new(EXT4_PRODUCER_BIN)
            .args([
                "-q",
                "-b",
                "4096",
                "-I",
                "256",
                "-m",
                "0",
                "-O",
                "^has_journal",
                "-d",
            ])
            .arg(&tar_path)
            .arg("-F")
            .arg(&out)
            .status()
            .expect("run the control");
        assert!(
            status.success(),
            "the control pack must succeed: {status:?}"
        );
        unpinned.push(blake3::hash(
            &std::fs::read(&out).expect("read the control"),
        ));
    }
    assert_ne!(
        unpinned[0], unpinned[1],
        "the control must DIFFER — if an unpinned `mkfs.ext4` were already deterministic on this \
         host, the identity assertion above would prove nothing"
    );
}

/// The produced image carries the POSIX shapes the ext4 format was added for, read back from the
/// image itself rather than asserted from the tar we wrote.
///
/// §4.7 sells the ext4 artifact on POSIX-completeness. Device nodes, `security.capability`, modes
/// and non-root ownership are the four the merged tar can express and erofs's consumers most often
/// need; this reads all four back with `debugfs`, which parses the on-disk structures.
///
/// RED on the emitter dropping any node shape, and on the pack forgetting `-d` (the image would be
/// empty and every lookup below would fail).
#[test]
fn the_produced_image_is_posix_complete() {
    let Some(producer) = common::probe_ext4_or_record_skip() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("rootfs.ext4");
    producer
        .pack(&merged(XattrPolicy::Preserve), &out)
        .expect("the producer packs");

    // The reference implementation's own verdict on the bytes, first: everything below reads
    // individual structures, and a structurally broken image can still answer a `stat`.
    fsck_clean(&out);

    // No journal: the root mounts `ro` with `rootflags=noload`, and an unrecovered journal is the
    // one thing `noload` guards. RED on dropping `-O ^has_journal`.
    let features = debugfs(&out, "features");
    assert!(
        !features.contains("has_journal"),
        "the image must carry no journal: {features}"
    );

    // The character device, with its numbers — `debugfs stat` renders `Device major/minor number`.
    let dev = debugfs(&out, "stat /dev/null");
    assert!(
        dev.contains("character special"),
        "`/dev/null` must be a character device: {dev}"
    );
    assert!(
        dev.contains("Device major/minor number: 01:03"),
        "…with its 1:3 numbers, which is what a shift/mask `rdev` split gets wrong: {dev}"
    );

    // The capability xattr, byte-exact.
    let ea = debugfs(&out, "ea_list /usr/bin/ping");
    assert!(
        ea.contains("security.capability"),
        "the `security.capability` attribute must survive into the image: {ea}"
    );
    let hex: String = CAP_XATTR
        .iter()
        .take(8)
        .map(|b| format!("{b:02x} "))
        .collect();
    assert!(
        ea.replace('\n', " ").contains(hex.trim()),
        "the attribute VALUE must be byte-exact, not merely present: wanted `{hex}` in {ea}"
    );

    // Modes and ownership, including the non-root one.
    let owned = debugfs(&out, "stat /var/owned");
    assert!(
        owned.contains("User:  1234") && owned.contains("Group:  5678"),
        "non-root ownership must survive: {owned}"
    );
    assert!(
        owned.contains("Mode:  0600"),
        "the mode must be permission bits only: {owned}"
    );

    // The symlink and the FIFO.
    assert!(
        debugfs(&out, "stat /usr/bin/ping6").contains("symlink"),
        "the symlink must survive as a symlink"
    );
    assert!(
        debugfs(&out, "stat /run/pipe").contains("FIFO"),
        "the FIFO must survive as a FIFO"
    );

    // And the deep member whose parents the source layer never shipped — the parent-dirs-present
    // pin's live half. RED on removing the parent synthesis: `mkfs.ext4` refuses the whole build
    // with `cannot find directory "deep/nested/dir"`, so `pack` above fails.
    assert!(
        debugfs(&out, "stat /deep/nested/dir/thing").contains("regular"),
        "the member under three synthesized parents must be in the image"
    );

    // The volume UUID is the CONTENT-ADDRESSED one, not a random one — the observable half of the
    // determinism triple. RED on dropping `-U` from `mkfs_args`: the image gets a fresh UUID that
    // this derivation cannot predict.
    let identity = Ext4Identity::from_merged_tar(&merged(XattrPolicy::Preserve));
    let superblock = String::from_utf8_lossy(
        &std::process::Command::new("dumpe2fs")
            .arg("-h")
            .arg(&out)
            .output()
            .expect("dumpe2fs (e2fsprogs) must be on PATH")
            .stdout,
    )
    .into_owned();
    assert!(
        superblock.contains(identity.uuid()),
        "the image must carry the volume UUID derived from the merged tar (`{}`): {superblock}",
        identity.uuid()
    );
}

/// A tar `mkfs.ext4` cannot build from fails LOUD, naming what the tool said — never a truncated
/// image left behind for a warm-cache read to serve.
///
/// The negative control for the parent-dirs-present pin: a tar assembled WITHOUT the merge's parent
/// synthesis is exactly the input `mkfs.ext4` refuses, and this asserts vmcell surfaces that refusal
/// instead of absorbing it.
#[test]
fn a_tar_with_missing_parents_fails_loud_and_leaves_no_image() {
    let Some(producer) = common::probe_ext4_or_record_skip() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("rootfs.ext4");

    // Hand-built, deliberately bypassing the merge: one member, three absent parents.
    let mut orphan = Vec::new();
    {
        let mut b = tar::Builder::new(&mut orphan);
        let mut f = tar::Header::new_gnu();
        f.set_size(5);
        f.set_mode(0o644);
        f.set_mtime(0);
        b.append_data(&mut f, "deep/nested/dir/thing", &b"hello"[..])
            .expect("append");
        b.finish().expect("finish");
    }

    let err = producer
        .pack(&orphan, &out)
        .expect_err("a tar with absent parents must be refused");
    let message = err.to_string();
    assert!(
        message.contains("deep/nested/dir") || message.contains("ext2_lookup"),
        "the refusal must quote what the tool said about the missing directory: {message}"
    );
    assert!(
        !out.exists(),
        "a failed pack must leave no image behind — a truncated one would be served by the next \
         warm-cache read as this artifact"
    );
}

// ---------------------------------------------------------------------------------------------
// The tarball route's xattr ceiling — found by the delta-8 live leg, refused here
// ---------------------------------------------------------------------------------------------

/// A tar whose sole member carries the attributes in `attrs`, bypassing the merge so the producer's
/// own refusal can be driven — and so the tool can be driven *past* it in the re-measurement below.
fn one_member_with_xattrs(attrs: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut b = tar::Builder::new(&mut buf);
        b.append_pax_extensions(
            attrs
                .iter()
                .map(|(name, value)| (format!("SCHILY.xattr.{name}"), *value))
                .collect::<Vec<_>>()
                .iter()
                .map(|(k, v)| (k.as_str(), *v)),
        )
        .expect("append the PAX xattr records");
        let mut f = tar::Header::new_gnu();
        f.set_size(5);
        f.set_mode(0o644);
        f.set_mtime(0);
        b.append_data(&mut f, "probe", &b"probe"[..])
            .expect("append the probe");
        b.finish().expect("finish");
    }
    buf
}

/// **The re-measurement.** `mkfs.ext4 -d <tarball>` really does drop every extended attribute
/// except [`EXT4_TARBALL_XATTRS`] — measured against the tool on THIS host, not assumed.
///
/// This is what keeps [`the_producer_refuses_an_xattr_it_would_silently_drop`]'s refusal honest in
/// both directions. The roster is a limitation of the shipped route, and a limitation that quietly
/// stopped applying would leave vmcell refusing an input it could now honor — so a future e2fsprogs
/// that carries `user.*` across reddens **here**, naming the constant to widen, rather than leaving
/// the refusal over-strict forever.
///
/// The producer's own guard is bypassed on purpose (`mkfs.ext4` is spawned directly): the point is
/// what the *tool* does, and the guard exists precisely to stop the producer from reaching it.
///
/// Its positive control is in the same image: `security.capability`, in the same archive, DOES
/// arrive — so "the attribute is absent" cannot be explained by the tar, the flags or the readback.
#[test]
fn the_tarball_route_still_drops_a_user_xattr() {
    let Some(producer) = common::probe_ext4_or_record_skip() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let tar_path = dir.path().join("probe.tar");
    let out = dir.path().join("probe.ext4");
    std::fs::write(
        &tar_path,
        one_member_with_xattrs(&[
            ("security.capability", CAP_XATTR),
            ("user.vmcell_probe", b"abc"),
            ("security.selinux", b"system_u"),
        ]),
    )
    .expect("stage the probe tar");

    // 16 MiB is far more than a one-member tree needs; the sizing law is gated elsewhere.
    let file = std::fs::File::create(&out).expect("create the image");
    file.set_len(16 * 1024 * 1024).expect("size the image");
    drop(file);
    let status = std::process::Command::new(EXT4_PRODUCER_BIN)
        .args([
            "-q",
            "-b",
            "4096",
            "-I",
            "256",
            "-m",
            "0",
            "-O",
            "^has_journal",
            "-d",
        ])
        .arg(&tar_path)
        .arg("-F")
        .arg(&out)
        .status()
        .expect("spawn the producer binary directly");
    assert!(
        status.success(),
        "the direct `{EXT4_PRODUCER_BIN}` invocation must succeed ({status:?}); the producer's \
         version gate already passed for {:?}",
        producer.version()
    );

    let ea = debugfs(&out, "ea_list probe");
    // Positive control, first: without it, "the attribute is absent" is indistinguishable from
    // "the readback is broken" or "the tar carried nothing".
    assert!(
        ea.contains("security.capability"),
        "the positive control must be in the image — otherwise the absences below prove nothing \
         about the route: {ea}"
    );
    for name in ["user.vmcell_probe", "security.selinux"] {
        assert!(
            !ea.contains(name),
            "`{EXT4_PRODUCER_BIN}` now carries `{name}` through its `-d <tarball>` form. That is \
             GOOD NEWS and this gate is where it surfaces: widen \
             `vmcell::artifact::ext4::EXT4_TARBALL_XATTRS` to include it, so the producer stops \
             refusing an input it can now honor. debugfs said: {ea}"
        );
    }
    // …and the roster this file asserts against is the one the producer refuses by.
    assert_eq!(
        EXT4_TARBALL_XATTRS,
        ["security.capability"],
        "the measured roster and the constant the refusal is composed from must be the same list"
    );
}

/// **The refusal** (§4.7, law F1): an extended attribute the tarball route would silently drop is
/// a typed [`Error::CapabilityUnavailable`], not an image whose attributes are quietly a subset of
/// what `XattrPolicy::Preserve` promised.
///
/// This is the delta-8 finding's gate. The live battery packed a `user.*` attribute under
/// `Preserve`, the pack reported success, and the guest's `getxattr` answered `ENODATA` — a silent
/// semantic change of an accepted input, which is exactly what AGENTS.md's honor-or-reject rule
/// exists to forbid. `security.capability` (the one attribute that motivates `Preserve` in
/// practice — file capabilities) is unaffected, so the refusal is scoped to what actually breaks.
///
/// RED on the inverse: delete the `dropped_xattr_sites` guard from `Ext4Producer::pack` and the
/// pack succeeds, producing exactly the image whose `user.*` attribute the guest cannot read.
#[test]
fn the_producer_refuses_an_xattr_it_would_silently_drop() {
    let Some(producer) = common::probe_ext4_or_record_skip() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("rootfs.ext4");

    let err = producer
        .pack(
            &one_member_with_xattrs(&[
                ("security.capability", CAP_XATTR),
                ("user.vmcell_probe", b"abc"),
            ]),
            &out,
        )
        .expect_err("an attribute this route drops must be refused, not silently dropped");
    assert!(
        matches!(err, Error::CapabilityUnavailable { .. }),
        "an attribute the shipped producer cannot write is an ABSENT FACILITY (§7.2), not a \
         malformed artifact: {err:?}"
    );
    let message = err.to_string();
    // Actionable: the attribute, the member it is on, and both ways forward.
    for needle in [
        "user.vmcell_probe",
        "/probe",
        "security.capability",
        "Erofs",
        "strip",
    ] {
        assert!(
            message.contains(needle),
            "the refusal must name {needle:?}, or the operator cannot act on it: {message}"
        );
    }
    assert!(
        !out.exists(),
        "a refused pack must write no image at {}",
        out.display()
    );

    // The positive control, over the SAME producer and the SAME tail: the attribute this route
    // *can* carry packs, so the refusal above is scoped rather than a blanket rejection of
    // `Preserve` — which would have made the ext4 format useless for the case it was added for.
    producer
        .pack(
            &one_member_with_xattrs(&[("security.capability", CAP_XATTR)]),
            &out,
        )
        .expect("an attribute this route CAN write must still pack");
    assert!(
        debugfs(&out, "ea_list probe").contains("security.capability"),
        "…and it must reach the image"
    );
}

// ---------------------------------------------------------------------------------------------
// The format key, the default, and the one tail
// ---------------------------------------------------------------------------------------------

/// The one tail's erofs-named door refuses a non-erofs format rather than silently overriding it —
/// an accepted input is honored or rejected, never quietly reinterpreted (law F1).
///
/// RED on the inverse: have `pack_erofs_with_injection` overwrite `options.format` with `Erofs` and
/// this passes silently while an ext4 request packs erofs.
#[tokio::test]
async fn the_erofs_door_refuses_a_non_erofs_format() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = vmcell::artifact::rootfs::pack_erofs_with_injection(
        vec![],
        &vmcell::artifact::StageInputs::default(),
        &dir.path().join("rootfs.ext4"),
        &PackOptions::new().with_format(RootfsFormat::Ext4),
    )
    .await
    .expect_err("the erofs door must refuse an ext4 request");
    let message = err.to_string();
    assert!(
        message.contains("pack_rootfs_with_injection"),
        "the refusal must name the door that honors every format: {message}"
    );
    assert!(
        message.contains("ext4"),
        "and the format it was handed: {message}"
    );
}

/// The default format is erofs, and the default `PackOptions` packs byte-for-byte what an explicit
/// `Erofs` does — §4.7's "the ext4 producer adds an artifact; it does not move the root", asserted
/// on bytes rather than quoted.
#[test]
fn the_default_format_is_erofs_byte_for_byte() {
    assert_eq!(RootfsFormat::default(), RootfsFormat::Erofs);
    assert_eq!(PackOptions::new().format, RootfsFormat::Erofs);
    assert_eq!(
        PackOptions::new().with_format(RootfsFormat::Erofs).format,
        RootfsFormat::Erofs
    );

    // The emitter the default reaches, over the same inputs, produces the same bytes as the pre-
    // delta-8 packer did: `tar_to_erofs`'s signature and behavior are unchanged, and the merge it
    // now shares with the tar emitter is the same merge it always ran.
    let pack = || {
        tar_to_erofs(
            vec![tar::Archive::new(std::io::Cursor::new(probe_layer()))],
            vec![],
            vec![],
            vec![],
            true,
            XattrPolicy::Strip,
        )
        .expect("erofs packs")
    };
    assert_eq!(
        pack(),
        pack(),
        "the erofs emitter must still be deterministic over one tree"
    );
}

// ---------------------------------------------------------------------------------------------
// The real base, end to end
// ---------------------------------------------------------------------------------------------

/// Packs the **registered default base plus vmcell's own injections** as ext4, through the one
/// tail, exactly as `vmcell build --rootfs-label <an ext4 entry>` would.
///
/// `#[ignore]`d because it pulls (or reads from the OCI cache) a real Debian base and packs ~100 MiB
/// — but it is the leg that matters most, and the synthetic tree above cannot substitute for it.
/// Everything the fixture cannot express lives here: **20k members**, paths past 100 bytes (the tar
/// header's `name` field), materialized hardlinks, thousands of directories, and a size the
/// estimator has to get right in one attempt. The estimator is the part with no other proof — a
/// formula validated only against a 17-node fixture is a formula validated against nothing.
///
/// The in-guest tree/xattr/device diff against this image booted as `RootfsSource::Block` is the
/// battery's live half; this is the producer half it stands on.
#[tokio::test]
#[ignore = "pulls and packs a real Debian base"]
async fn the_real_base_packs_as_ext4() {
    let Some(producer) = common::probe_ext4_or_record_skip() else {
        return;
    };
    let staging = tempfile::tempdir().expect("tempdir");

    // The upstream half of the pipeline `vmcell build` runs, minus the rootfs stage — the same
    // shape the xattr battery uses, because this test owns the pack itself.
    let built = vmcell::artifact::Pipeline::new(staging.path().to_path_buf())
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

    // The registered base, through the one registry reader — never a hand-parsed `pins.json`.
    let entry = vmcell::artifact::resolve_rootfs_entry(
        None,
        vmcell::artifact::pins_overlay_path().as_deref(),
    )
    .expect("resolving the rootfs registry must succeed")
    .expect("the `default` rootfs label must be registered");
    let (image, digest) = match entry.registration {
        vmcell::artifact::RootfsRegistration::Digest { image, digest } => (image, digest),
        other => panic!("`rootfs.default` must be digest-pinned for this leg; got {other:?}"),
    };
    let streams = vmcell::artifact::rootfs::oci::base_layer_tar_streams(&image, &digest)
        .await
        .expect("resolving the pinned base's layers must succeed");

    // Through `pack_rootfs_with_injection` — the ONE tail — with the format as the only variable.
    let out = staging.path().join("rootfs.ext4");
    vmcell::artifact::rootfs::pack_rootfs_with_injection(
        streams,
        &inputs,
        &out,
        &PackOptions::new().with_format(RootfsFormat::Ext4),
    )
    .await
    .expect("the one tail must pack the real base as ext4");

    assert!(out.exists(), "the pack must write {}", out.display());
    // `e2fsck`'s verdict on a REAL ~100 MiB tree: 20k inodes, deep extent trees, thousands of
    // directories. The fixture above cannot produce any of those shapes.
    fsck_clean(&out);

    // The injections vmcell's own manifest bakes, read back OUT OF THE IMAGE: a rootfs whose
    // steward is missing packs fine and panics the guest kernel at boot, which is precisely the
    // failure a producer-level test has to catch before the live leg spends a boot on it.
    let steward = debugfs(&out, "stat /usr/sbin/vmcell-steward");
    assert!(
        steward.contains("regular"),
        "the injected steward must be in the ext4 image: {steward}"
    );
    assert!(
        steward.contains("Mode:  0755"),
        "…and executable, or every boot is an exec failure: {steward}"
    );
    let tools = debugfs(&out, "stat /vmcell-tools/vmcell-guest-tools");
    assert!(
        tools.contains("regular") && tools.contains("Mode:  0755"),
        "the guest-tools multicall must be present and executable: {tools}"
    );
    // One applet symlink, proving the roster reached the image as links rather than as nothing.
    let applet = debugfs(&out, "stat /vmcell-tools/ip");
    assert!(
        applet.contains("symlink"),
        "the applet symlinks must survive the ext4 emitter: {applet}"
    );
    // The libc6 the packer's own scan demands — the base really is the Debian one.
    assert!(
        !debugfs(&out, "ls -l /usr/lib/x86_64-linux-gnu").is_empty(),
        "the base's library tree must be in the image"
    );

    // The estimator got it right on the FIRST rung, not by climbing the ladder: `mkfs.ext4` reports
    // free blocks, and an image that needed a doubling would sit at roughly half-empty. This is the
    // only place the sizing formula meets a real tree.
    let superblock = String::from_utf8_lossy(
        &std::process::Command::new("dumpe2fs")
            .arg("-h")
            .arg(&out)
            .output()
            .expect("dumpe2fs (e2fsprogs) must be on PATH")
            .stdout,
    )
    .into_owned();
    let field = |name: &str| -> u64 {
        superblock
            .lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split(':').nth(1))
            .map(str::trim)
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("`{name}` must be in the superblock: {superblock}"))
    };
    let (blocks, free_blocks) = (field("Block count"), field("Free blocks"));
    let (inodes, free_inodes) = (field("Inode count"), field("Free inodes"));
    println!(
        "ext4 sizing over the real base: {blocks} blocks ({} MiB), {free_blocks} free; \
         {inodes} inodes, {free_inodes} free",
        blocks * 4096 / (1024 * 1024)
    );
    assert!(
        free_blocks * 4 < blocks * 3,
        "more than 75% of the image is free ({free_blocks}/{blocks} blocks) — the estimator \
         climbed the size ladder instead of getting it right, which doubles the guest-visible \
         device for nothing"
    );
    assert!(
        free_inodes > 0 && free_inodes < inodes,
        "the inode count must cover the tree with headroom and not be wildly over: \
         {free_inodes}/{inodes}"
    );

    // And it is deterministic over a REAL tree, not only over the fixture — the property delta 7's
    // pack-twice gate demands and the one `mkfs.ext4` does not provide on its own. The whole tail
    // runs again (the layer streams are consumed by the first pass), a second apart, so a
    // clock-derived superblock field would show up here and nowhere else.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let again = staging.path().join("again.ext4");
    let streams = vmcell::artifact::rootfs::oci::base_layer_tar_streams(&image, &digest)
        .await
        .expect("re-resolving the pinned base's layers must succeed");
    vmcell::artifact::rootfs::pack_rootfs_with_injection(
        streams,
        &inputs,
        &again,
        &PackOptions::new().with_format(RootfsFormat::Ext4),
    )
    .await
    .expect("the second pack must succeed");
    assert_eq!(
        blake3::hash(&std::fs::read(&out).expect("read the first image")),
        blake3::hash(&std::fs::read(&again).expect("read the second image")),
        "two packs of one real base must be byte-identical"
    );
    // The probed producer is what did both — named so the receipt is not an unused binding.
    assert!(producer.version() >= MIN_E2FSPROGS_VERSION);
}

// ---------------------------------------------------------------------------------------------
// The one skip law, its call sites, and the CI step that keeps the skip from becoming permanent
// ---------------------------------------------------------------------------------------------

/// This repository's checked-in CI definition, read as text so the gates below assert on the file
/// that actually runs rather than on a belief about it — the same shape `ext4_cell`'s
/// `the_live_legs_are_selected_by_a_suite_recipe` uses against the justfile.
const CI_WORKFLOW: &str = include_str!("../../../.github/workflows/ci.yml");

/// The one law's own source, so the scan below can prove the direct probe lives THERE and nowhere
/// else.
const COMMON_MOD: &str = include_str!("common/mod.rs");

/// `text` with whole-line comments removed — YAML `#` and Rust `//` alike.
///
/// Every scan below runs on the stripped form, so prose that *quotes* a banned shape (this file's
/// own module docs quote `println!("SKIP") + return`, and `ext4_cell`'s rustdoc names it too) is
/// never a false positive. Stripping can only hide a hit, never invent one.
fn code_only(text: &str) -> String {
    text.lines()
        .filter(|l| {
            let t = l.trim_start();
            !t.starts_with('#') && !t.starts_with("//")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// **The skip law's own gate**: an absent ext4 facility is *recorded*, not merely printed — and a
/// broken one still panics.
///
/// This is the difference the whole law exists for. `println!("SKIP") + return` is a green PASS
/// (AGENTS.md): the test reports success, `just skip-manifest-show` prints nothing, and the reviewer
/// has no signal that the delta-8 claims went unverified. Driving it needs two seams, because the
/// arm that matters is unreachable on any host that *can* run this battery — so
/// [`common::classify_ext4_probe`] takes the probe's verdict and the manifest sink as parameters, and
/// this hands it a synthetic `CapabilityUnavailable` plus a scratch file. The scratch file is not
/// fastidiousness: appending a synthetic `SKIP` to the run's own manifest would put a capability gap
/// that does not exist in front of the next reviewer.
///
/// RED ON THE INVERSE, measured both ways: delete the `record_capability_skip_to` call from
/// `classify_ext4_probe` (i.e. restore the bare `println!` shape docs/90 G3 found in
/// `repack_outside_checkout.rs`) and the manifest is never created; make the broken arm record and
/// skip instead of panicking and the second half fails.
#[test]
fn the_one_skip_law_records_the_gap_rather_than_only_printing_it() {
    let dir = tempfile::tempdir().expect("tempdir");

    // --- An ABSENT facility: no receipt, and a line in the manifest. ------------------------------
    let manifest = dir.path().join("skips.txt");
    let verdict = common::classify_ext4_probe(
        Err(Error::CapabilityUnavailable {
            op: "ext4 rootfs pack (§4.7)".to_string(),
            needed: "a synthetic absent facility, driven by this gate".to_string(),
        }),
        &manifest,
    );
    assert!(
        verdict.is_none(),
        "an absent facility must yield no producer receipt — the receipt is what lets a leg pack"
    );
    let recorded = std::fs::read_to_string(&manifest).unwrap_or_else(|e| {
        panic!(
            "the law must APPEND to the skip manifest, not merely print: {} is unreadable ({e}). A \
             `println!(\"SKIP\") + return` is a green PASS (AGENTS.md) — a suite that skipped the \
             whole delta-8 battery would look identical to one that ran it",
            manifest.display()
        )
    });
    assert_eq!(
        recorded,
        format!(
            "SKIP {} {}\n",
            common::EXT4_SKIP_VMM,
            common::EXT4_SKIP_CAPABILITY
        ),
        "the recorded line must be the one `just skip-manifest-show` surfaces, composed from the \
         one place the pair is spelled"
    );

    // --- A BROKEN facility: panics, and records NOTHING. -----------------------------------------
    // Recording here would let a misconfigured host (an unrunnable binary, an unparseable banner)
    // hide behind a manifest entry that reads like an absent facility — §7.2 rule 3's distinction,
    // which is the reason the law classifies instead of just probing. The panic below is EXPECTED;
    // its message in the log belongs to this gate, not to a failure.
    let broken = dir.path().join("broken.txt");
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        common::classify_ext4_probe(
            Err(Error::Artifact(
                "cannot read an e2fsprogs version from `mkfs.ext4 -V`".to_string(),
            )),
            &broken,
        )
    }));
    assert!(
        caught.is_err(),
        "a BROKEN `{EXT4_PRODUCER_BIN}` must panic rather than skip: skipping on it is the \
         green-PASS defect wearing the probe's clothes"
    );
    assert!(
        !broken.exists(),
        "a broken facility must record no capability skip — it is a host misconfiguration, not an \
         absent facility, and the two have different fixes"
    );
}

/// **The call-site scan** (AGENTS.md: "a gate binds the call sites, not just the extracted
/// predicate"): all three delta-8 files ask the one law, and none of them answers an absent
/// `mkfs.ext4` its own way.
///
/// The three answered it three different ways before this pass — a `panic!` here, a bare
/// `println!("SKIP") + return` in `repack_outside_checkout.rs` (docs/90 G3, in a file that did not
/// even declare `mod common`), and the recorded skip in `ext4_cell.rs` — so a green unit test on the
/// extracted law would have proved nothing about what the batteries actually do. Every needle below
/// is one of those three ways.
///
/// RED ON THE INVERSE, per arm: restore the direct probe in any battery (arm 3), restore a bare
/// SKIP print (arm 4), have a battery record its own manifest line (arm 5), or move the direct probe
/// out of `common/mod.rs` (arm 6).
#[test]
fn every_ext4_battery_asks_the_one_law() {
    // EVERY needle below is COMPOSED rather than written whole, because this gate lives in one of
    // the three files it scans: a literal needle would match its own definition and its own failure
    // message, so `ext4_producer.rs` would report itself as calling the direct probe and printing
    // its own SKIP. Composition keeps the assertions about the batteries' code rather than about
    // this scanner's text. (Stripping string literals instead would need a parser, and a
    // half-parser is how a scan starts lying.)
    let declares = format!("mod {};", "common");
    let law = format!("probe_ext4_or_record_{}", "skip()");
    let direct_probe = format!("Ext4Producer{}", "::probe()");
    let bare_print = format!("println!(\"{}", "SKIP");
    let self_record = format!("record_capability_{}", "skip");
    let batteries = [
        ("ext4_producer.rs", include_str!("ext4_producer.rs")),
        ("ext4_cell.rs", include_str!("ext4_cell.rs")),
        (
            "repack_outside_checkout.rs",
            include_str!("repack_outside_checkout.rs"),
        ),
    ];

    let mut law_sites = 0usize;
    for (name, source) in batteries {
        let code = code_only(source);
        // Non-vacuity first: a scan over stripped-to-nothing text passes every arm below.
        assert!(
            code.contains("fn "),
            "the {name} scan is vacuous — the comment stripper left no code at all"
        );
        // 1. It can reach the law.
        assert!(
            code.contains(&declares),
            "{name} must declare `{declares}` — G3's file did not, which is exactly how its \
             doc-comment came to claim a skip-recording call that existed nowhere in it"
        );
        // 2. …and it does.
        let sites = code.matches(&law).count();
        assert!(
            sites > 0,
            "{name} must ask the one law (`{law}`) before it packs"
        );
        law_sites += sites;
        // 3. No second probe. `probe_binary` is deliberately NOT banned: this file drives it against
        //    stubs to produce the refusals the law classifies, which is the opposite of bypassing it.
        assert!(
            !code.contains(&direct_probe),
            "{name} calls `{direct_probe}` directly instead of through the one law — that is how \
             the three files came to answer an absent facility three different ways, two of them \
             wrong (a red CI job and a green PASS)"
        );
        // 4. Not the shape AGENTS.md names as a green PASS.
        assert!(
            !code.contains(&bare_print),
            "{name} prints its own SKIP (`{bare_print}…`) instead of recording one. That shape is a \
             green PASS (AGENTS.md): nothing reaches VMCELL_SKIP_MANIFEST, so \
             `just skip-manifest-show` shows the reviewer no gap at all. Route it through `{law}`"
        );
        // 5. And it does not record its own line: the `SKIP <vmm> <capability>` identity is the
        //    law's, so two spellings cannot drift apart.
        assert!(
            !code.contains(&self_record),
            "{name} records its own capability skip (`{self_record}`). The line's identity belongs \
             to the one law (`common::EXT4_SKIP_VMM` / `EXT4_SKIP_CAPABILITY`), so a battery that \
             composes its own is a second copy of it"
        );
    }
    assert!(
        law_sites >= 10,
        "only {law_sites} call sites ask the one law across the three batteries — every leg that \
         packs an ext4 image needs one, so a shrinking count means a leg went back to assuming the \
         facility"
    );

    // 6. The direct probe lives in the law, and the law records. Without this the bans above would
    //    be satisfied by a tree in which nothing probes at all — three files agreeing to skip.
    //    STRUCTURAL only: it says the two calls exist somewhere in `common/mod.rs`, not that they
    //    sit on the path a battery takes. The behavioral proof is
    //    `the_one_skip_law_records_the_gap_rather_than_only_printing_it`, which drives the law and
    //    reads the file back; measured, deleting the record call from `classify_ext4_probe` reddens
    //    that gate and leaves this arm green, which is why both exist.
    let one_law = code_only(COMMON_MOD);
    assert!(
        one_law.contains(&direct_probe),
        "common/mod.rs must hold THE direct probe (`{direct_probe}`) — it is the one place the \
         batteries delegate to"
    );
    assert!(
        one_law.contains(&format!("{self_record}_to(")),
        "…and it must RECORD the skip it returns `None` for, which is the entire difference between \
         this law and the `{bare_print}…` shape it replaced"
    );
}

/// **The CI step's gate**: every job that runs the ext4 legs *obtains* e2fsprogs first, so the
/// recorded skip stays a fallback rather than becoming the permanent state of this battery.
///
/// A recorded skip fixes the red job and leaves a coverage hole; obtaining the facility is what
/// closes it. `ubuntu-24.04` packages e2fsprogs 1.47.0 and [`MIN_E2FSPROGS_VERSION`] is 1.47.1, so
/// apt cannot supply it at any pin — the workflow builds a pinned, checksum-verified release from
/// source instead. Two of the arms guard shapes that have already cost this repository something
/// real: a duplicated roster whose fix reached one copy and not the other (three times — see
/// `scripts/ban-ci-script-handcopy.sh`), and a tool install whose failure took its whole job down
/// with it (the `actionlint` install, which reported all 20 lint gates as skipped for two months).
/// The rest — the ordering, the version pin against the producer's own constant, the checksum — are
/// the same class one step away.
///
/// The set of jobs is *derived* from the workflow (any job invoking a recipe that selects these
/// legs), never listed here: a third job that runs the suite must carry the step by construction.
///
/// RED ON THE INVERSE, per arm: delete the step from either job (arm 1), move it after the suite
/// step (arm 2), pin a version below `MIN_E2FSPROGS_VERSION` (arm 3), drop the `sha256sum -c`
/// (arm 4), drop `continue-on-error` (arm 5), drop the `-V` report (arm 6), or edit one job's copy
/// and not the other's (arm 7).
#[test]
fn ci_obtains_the_ext4_facility_rather_than_living_with_the_skip() {
    /// The marker identifying the facility step, and the env var that carries its pin.
    const PIN: &str = "E2FSPROGS_VERSION";
    /// The recipes that select this battery's legs: `test-unit` runs every non-`#[ignore]`d test
    /// here, `test-privileged` adds the `#[ignore]`d live half in `ext4_cell`.
    const SUITES: [&str; 2] = ["just test-unit", "just test-privileged"];

    // Split the workflow into jobs by their two-space-indented keys — the same "read the file that
    // runs, not a copy of it" discipline `scripts/ban-ci-script-handcopy.sh` applies one file over.
    // The `jobs:` guard matters: `on:`'s own `push:` / `pull_request:` keys sit at the same
    // indentation and would otherwise be collected as jobs.
    let mut jobs: Vec<(String, String)> = Vec::new();
    let mut in_jobs = false;
    for line in CI_WORKFLOW.lines() {
        if line == "jobs:" {
            in_jobs = true;
            continue;
        }
        let is_job_key = in_jobs
            && line.starts_with("  ")
            && !line.starts_with("   ")
            && line.trim_end().ends_with(':')
            && !line.trim_start().starts_with('#');
        if is_job_key {
            jobs.push((line.trim().trim_end_matches(':').to_string(), String::new()));
        } else if let Some(last) = jobs.last_mut() {
            last.1.push_str(line);
            last.1.push('\n');
        }
    }
    assert!(
        jobs.len() >= 3,
        "the job split found {} job(s) — the workflow's shape changed and every assertion below \
         would be scanning the wrong text",
        jobs.len()
    );

    let mut facility_steps: Vec<(String, String)> = Vec::new();
    for suite in SUITES {
        let runners: Vec<&(String, String)> = jobs
            .iter()
            .filter(|(_, body)| code_only(body).contains(suite))
            .collect();
        assert_eq!(
            runners.len(),
            1,
            "`{suite}` must be invoked by exactly one job (found {}); this gate derives the jobs \
             that need the facility from that invocation",
            runners.len()
        );
        let (name, body) = runners[0];
        let code = code_only(body);
        // 1 + 2. The step exists in THIS job and runs BEFORE the suite it serves. A facility
        //        installed afterwards is a facility the suite ran without.
        let step_at = code.find(PIN).unwrap_or_else(|| {
            panic!(
                "job `{name}` runs `{suite}`, which selects the §4.7 ext4 legs, but carries no \
                 e2fsprogs step: those legs would record a capability skip on every CI run and the \
                 producer would be exercised nowhere"
            )
        });
        let suite_at = code.find(suite).expect("the filter above matched it");
        assert!(
            step_at < suite_at,
            "job `{name}`'s e2fsprogs step must come BEFORE `{suite}` — $GITHUB_PATH only affects \
             later steps, so a step placed after it obtains the facility for nobody"
        );
        // The step's own text: every `- `-introduced chunk of this job that mentions e2fsprogs,
        // comment lines dropped so the comparison across jobs is over what RUNS.
        let mut chunks: Vec<String> = Vec::new();
        for raw in body.split("\n      - ") {
            let chunk = code_only(raw);
            if chunk.to_ascii_lowercase().contains("e2fsprogs") {
                chunks.push(chunk);
            }
        }
        assert_eq!(
            chunks.len(),
            2,
            "job `{name}` must carry exactly the cache step and the build step for e2fsprogs; \
             found {} chunk(s), so this gate is reading something other than the pair it asserts on",
            chunks.len()
        );
        let step = chunks.join("\n");

        // 3. The pin satisfies the producer's own gate. One law: the constant, not a copied number.
        let pinned = step
            .split_once(&format!("{PIN}: \""))
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(v, _)| v.to_string())
            .unwrap_or_else(|| panic!("job `{name}`'s step must pin `{PIN}: \"<x.y.z>\"`: {step}"));
        let parts: Vec<u32> = pinned
            .split('.')
            .map(|p| {
                p.parse()
                    .unwrap_or_else(|e| panic!("unparseable e2fsprogs pin {pinned:?}: {e}"))
            })
            .collect();
        assert_eq!(
            parts.len(),
            3,
            "the pin must be `major.minor.patch`: {pinned}"
        );
        assert!(
            (parts[0], parts[1], parts[2]) >= MIN_E2FSPROGS_VERSION,
            "job `{name}` pins e2fsprogs {pinned}, below the `-d <tarball>` gate \
             {MIN_E2FSPROGS_VERSION:?} the producer probes for — the build would succeed and the \
             battery would record a capability skip anyway"
        );
        // 4. The download is verified. An unpinned-content fetch in a workflow whose sibling job
        //    blesses a file-capability runner is the supply-chain shape every other install step
        //    here is written against.
        assert!(
            step.contains("sha256sum -c"),
            "job `{name}`'s e2fsprogs tarball must be checksum-verified: {step}"
        );
        assert!(
            step.contains("E2FSPROGS_SHA256"),
            "…against a pinned digest beside the version: {step}"
        );
        // 5. Non-gating: a facility this repo cannot obtain must degrade to the recorded skip, which
        //    is the honest outcome — never to a red job, which is the outcome nobody reads.
        assert_eq!(
            step.matches("continue-on-error: true").count(),
            2,
            "both of job `{name}`'s e2fsprogs steps must be `continue-on-error: true`: a failed \
             install has to leave the recorded capability skip as the outcome, not fail the job"
        );
        // 6. …and the log says which of the two outcomes happened.
        assert!(
            step.contains("mkfs.ext4\" -V") || step.contains("mkfs.ext4 -V"),
            "job `{name}`'s step must print the resolved `mkfs.ext4 -V`, or the log cannot say \
             whether the battery ran or skipped: {step}"
        );
        facility_steps.push((name.clone(), step));
    }

    // 7. The two copies are the same text. A `run:` step cannot be shared between jobs, so the
    //    duplication is forced — and a duplicate that drifts is the defect
    //    `ban-ci-script-handcopy.sh` exists for, one level down.
    let (first_job, first) = &facility_steps[0];
    for (name, step) in &facility_steps[1..] {
        assert_eq!(
            first, step,
            "jobs `{first_job}` and `{name}` carry DIFFERENT e2fsprogs steps. The block is \
             duplicated because YAML cannot share it; a fix that reaches one job and not the other \
             is exactly the hand-copy drift this asserts against"
        );
    }
}
