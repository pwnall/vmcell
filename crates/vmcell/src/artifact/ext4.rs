//! The ext4 rootfs producer (design §4.7, §18 delta 8).
//!
//! `RootfsSource::Block` has been consumable by every backend since v22 — the builder already emits
//! `rootfstype=ext4` and `rootflags=noload` for it — and nothing in-tree ever *produced* an ext4
//! image. This module is that producer. It sits behind the **same** `Stage` as the erofs packer and
//! consumes the **same** merged tree (`tar2erofs::merge_to_tar`), so the injections, the `libc6`
//! scan, the [`XattrPolicy`](crate::artifact::XattrPolicy) and the F5 reserved-path law are
//! inherited rather than reimplemented.
//!
//! # Which route, and why
//!
//! §18 delta 8 directs evaluating a **permissive pure-Rust ext4 writer first**, with external
//! `mkfs.ext4 -d <tarball>` as the validated fallback. The evaluation ran (see the crate roster in
//! `docs/implementation-notes.md`); this ships the **tool route**, and the reason is maturity, not
//! licensing. Every ext4-*writing* crate on crates.io today is months old and pre-1.0 —
//! `am-fs-ext4` (MIT, the same author family as the `am-fs-erofs` this tree already trusts, and the
//! only candidate with a complete write API: `apply_mknod`, `apply_link`, `apply_setxattr`,
//! `apply_utimens`) is the named graduation candidate, and it is two months old with a version
//! cadence of three releases in ten days. §17's own hedge is "*resolved at cut time in the crate's
//! favor **if** a permissive pure-Rust writer passes the mount-and-diff gate*"; nothing has passed
//! it yet.
//!
//! e2fsprogs is a **GPL-2 binary, spawned, never linked** — the QEMU/nft carve-out shape, and no
//! `deny.toml` change (the license scan sees no new crate because there is no new crate). The
//! artifact pipeline already spawns `make` and `cargo` unjailed on the host, so this joins an
//! existing, precedented class.
//!
//! Either route sits behind the one `Stage`, so graduating later is an implementation swap rather
//! than a contract change.
//!
//! # Determinism is not free here
//!
//! `mkfs.ext4` is **not** byte-deterministic by default: the superblock's `s_hash_seed`, `s_uuid`
//! and `s_mkfs_time` all default to freshly generated values, so two runs over identical inputs
//! produce images with 20+ differing bytes. Measured on this host (e2fsprogs 1.47.2), byte-identity
//! needs **three** knobs together — `SOURCE_DATE_EPOCH`, `-U <uuid>` and
//! `-E hash_seed=<non-null uuid>` — and an all-zeros `hash_seed` still reads as "unset, generate
//! one". Neither §4.7 nor §18 delta 8 mentions any of this. [`Ext4Identity`](crate::artifact::ext4::Ext4Identity) derives all three from
//! the merged tar's own content hash, so the artifact's identity comes from the artifact rather
//! than from the clock, and delta 7's pack-twice byte-determinism gate extends to this producer.

use crate::error::{Error, Result};
use std::path::{Path, PathBuf};

/// The external ext4 producer's binary, looked up on `PATH`.
///
/// A bare name, like the pipeline's existing `make` and `cargo` spawns. The `VMCELL_*_BIN` resolver
/// law is scoped to **VMM** binaries (it exists so a harness and a suite agree on which hypervisor
/// they are testing), and this is a build tool, not a backend.
pub const EXT4_PRODUCER_BIN: &str = "mkfs.ext4";

/// The oldest e2fsprogs whose `-d` accepts a **tarball** rather than only a directory
/// (§18 delta 8's version gate).
pub const MIN_E2FSPROGS_VERSION: (u32, u32, u32) = (1, 47, 1);

/// The filesystem block size every produced image uses.
///
/// Pinned rather than left to `mke2fs`'s size-derived default, because the default is read from the
/// host's `/etc/mke2fs.conf` and a host-config-dependent block size is a host-config-dependent
/// image.
const BLOCK_SIZE: u64 = 4096;

/// The inode size every produced image uses. 256 is the modern default; 128 cannot represent dates
/// past 2038 and `mke2fs` warns about it on every invocation.
const INODE_SIZE: u64 = 256;

/// How many times [`Ext4Producer::pack`] doubles its size estimate before giving up.
///
/// The estimate below is deliberately generous, but "generous" is a judgement about tree shapes and
/// a tree shape can always be worse than the judgement. `mkfs.ext4` fails **loud** when it runs out
/// of blocks or inodes (verified: `Could not allocate block in ext2 filesystem while writing file`,
/// exit 1), never silently truncating, so the ladder is a convenience rather than a correctness
/// guard — and it is deterministic, because which rung succeeds is a function of the same inputs.
const SIZE_LADDER_RUNGS: u32 = 3;

/// The marker `mke2fs` prints when `libarchive` cannot be loaded.
///
/// The second half of §18 delta 8's version gate is genuinely undetectable by a version check:
/// `mke2fs` **dlopen**s `libarchive.so.13` rather than linking it, so `ldd` shows nothing, `-V`
/// reports the same 1.47.2 either way, and the only honest probe is to attempt a real tarball build
/// and classify the failure. Matching an external tool's own stderr marker is what classification
/// means here; the F6 ban on substring matchers is about vmcell's *own* typed refusals, whose
/// feature strings are composed from `Feature::name()`.
const LIBARCHIVE_MARKER: &str = "libarchive";

/// The extended attributes `mkfs.ext4 -d <tarball>` actually writes into the image — **measured**,
/// against e2fsprogs 1.47.2, not read off any documentation.
///
/// The tarball route is not the directory route. `-d <dir>` copies every attribute it can
/// `listxattr` (verified: a `user.simple` on a staged file lands in the image); `-d <tarball>`
/// carries exactly **one** name across, and drops `user.*`, `trusted.*` and even the other
/// `security.*` attributes silently — `security.selinux` in the same archive as
/// `security.capability` reaches the image no more than `user.simple` does. Both were probed with
/// `debugfs ea_list` on images built from one tar carrying all four.
///
/// This roster is therefore a **limitation of the shipped route**, not a policy: it exists so
/// [`Ext4Producer::pack`] can refuse an input it cannot honor instead of writing an image whose
/// attributes are quietly a subset of the ones the caller asked to preserve (delta 7's
/// `XattrPolicy::Preserve` is a §10.4 contract-surface promise, and the erofs route keeps it for
/// every namespace). `the_tarball_route_still_drops_a_user_xattr` re-measures it on the host, so a
/// future e2fsprogs that widens the support reddens the gate that asked for the narrow behavior
/// rather than leaving this list quietly over-strict.
pub const EXT4_TARBALL_XATTRS: &[&str] = &["security.capability"];

/// How many dropped-attribute sites [`Ext4Producer::pack`]'s refusal names before it stops.
///
/// A refusal that renders one record per file over a 3,000-member tree is a flood, not a
/// diagnostic — the `capped_debug` discipline, applied to an error message.
const MAX_REPORTED_XATTR_SITES: usize = 8;

/// The PAX record prefix carrying an extended attribute, per the SCHILY convention every tar
/// producer in practice emits — the same prefix `tar2erofs`'s decode reads.
const PAX_SCHILY_XATTR: &str = "SCHILY.xattr.";

/// A probed, usable external ext4 producer — the receipt that the version gate ran.
///
/// Constructed only through [`Ext4Producer::probe`] / [`Ext4Producer::probe_binary`], so a caller
/// cannot hold one without having proven both halves of the gate: e2fsprogs is new enough **and**
/// its tarball path actually works. That is why the probe returns a value rather than a `bool` —
/// "checked the version, then packed" and "packed" are the same call site here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ext4Producer {
    /// The binary the probe validated, as resolved.
    binary: PathBuf,
    /// The `(major, minor, patch)` this binary reported.
    version: (u32, u32, u32),
}

/// The three knobs that make an ext4 image a function of its inputs (see the module doc).
///
/// Derived from the merged tar's content hash, never from the clock or from a random source: two
/// packs of one tree produce one image, and two different trees produce different volume UUIDs (so
/// two artifacts are never mistaken for one by anything keying on the UUID).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ext4Identity {
    /// `-U` — the volume UUID.
    uuid: String,
    /// `-E hash_seed=` — the directory-hash seed. A **different** derivation from `uuid`, and
    /// non-null: `mke2fs` treats an all-zeros seed as "unset" and generates a fresh one, which was
    /// measured on this host as the reason a `-U`-pinned pack still differed run to run.
    hash_seed: String,
    /// `SOURCE_DATE_EPOCH` — the superblock's mkfs/mount/write timestamps. Zero, matching the
    /// `mtime: 0` the packer already stamps on every injected and synthesized node (§10.3).
    source_date_epoch: u64,
}

impl Ext4Identity {
    /// Derives the identity of the image packed from `merged_tar`.
    #[must_use]
    pub fn from_merged_tar(merged_tar: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"vmcell-ext4-identity\0");
        hasher.update(merged_tar);
        let digest = hasher.finalize();
        let bytes = digest.as_bytes();
        // Domain-separated from the volume UUID rather than a second slice of the same hash: the
        // two are independent on-disk fields, and deriving one from the other's bytes would make
        // them correlate for no reason a reader could check.
        let mut seed_hasher = blake3::Hasher::new();
        seed_hasher.update(b"vmcell-ext4-hash-seed\0");
        seed_hasher.update(bytes);
        let seed = seed_hasher.finalize();
        Ext4Identity {
            uuid: uuid_from(&bytes[..16]),
            hash_seed: uuid_from(&seed.as_bytes()[..16]),
            source_date_epoch: 0,
        }
    }

    /// The volume UUID this identity pins (`-U`).
    #[must_use]
    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    /// The directory-hash seed this identity pins (`-E hash_seed=`).
    #[must_use]
    pub fn hash_seed(&self) -> &str {
        &self.hash_seed
    }
}

/// Renders 16 bytes as a canonical UUID string.
///
/// The RFC-4122 version/variant bits are deliberately **not** forced: this is a content-addressed
/// label, not a claim of randomness, and `mke2fs` accepts any 16-byte value. Forcing the bits would
/// discard four bits of the derivation for a property nothing here relies on.
fn uuid_from(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// What the merged tar costs an ext4 image, in the terms `mke2fs` is sized in.
///
/// Counted from the tar the producer is about to hand over — the same bytes, so the estimate cannot
/// describe a different tree than the one being packed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct TarShape {
    /// Blocks the regular files' contents occupy, each file rounded up to a whole block.
    data_blocks: u64,
    /// Blocks the directories occupy — one apiece, which is `mke2fs`'s minimum and the right
    /// estimate for a rootfs whose directories are small.
    dir_blocks: u64,
    /// Blocks the symlinks too long to live inside their inode occupy (ext4 inlines a target of up
    /// to 59 bytes in `i_block`).
    symlink_blocks: u64,
    /// Every member: the inode count has to cover all of them, not just the ones holding data.
    nodes: u64,
}

/// The longest symlink target ext4 stores inside the inode itself (`i_block`, 60 bytes, one of
/// which is the terminator).
const EXT4_MAX_FAST_SYMLINK: u64 = 59;

/// Measures `merged_tar` without extracting it.
///
/// # Errors
/// [`Error::Artifact`] when the archive cannot be walked — the producer is about to hand these
/// exact bytes to `mkfs.ext4`, so a tar this cannot read is one that would fail there anyway, and
/// failing here names the reason.
fn tar_shape(merged_tar: &[u8]) -> Result<TarShape> {
    let mut shape = TarShape::default();
    let mut archive = tar::Archive::new(std::io::Cursor::new(merged_tar));
    for entry in archive
        .entries()
        .map_err(|e| Error::Artifact(format!("cannot walk the merged tar: {e}")))?
    {
        let entry = entry.map_err(|e| Error::Artifact(format!("malformed merged tar: {e}")))?;
        let header = entry.header();
        let entry_type = header.entry_type();
        // The pax/GNU extension pseudo-members describe the member that follows; they are not
        // filesystem objects and must not be counted as inodes.
        if entry_type.is_pax_global_extensions()
            || entry_type.is_pax_local_extensions()
            || entry_type.is_gnu_longname()
            || entry_type.is_gnu_longlink()
        {
            continue;
        }
        shape.nodes += 1;
        if entry_type.is_dir() {
            shape.dir_blocks += 1;
        } else if entry_type.is_symlink() {
            let target_len = header
                .link_name_bytes()
                .map_or(0, |t| t.len() as u64)
                .max(entry.link_name_bytes().map_or(0, |t| t.len() as u64));
            if target_len > EXT4_MAX_FAST_SYMLINK {
                shape.symlink_blocks += 1;
            }
        } else if entry_type.is_file() {
            let size = header
                .size()
                .map_err(|e| Error::Artifact(format!("malformed merged tar member size: {e}")))?;
            shape.data_blocks += size.div_ceil(BLOCK_SIZE);
        }
        // Devices and FIFOs occupy an inode and no blocks.
    }
    Ok(shape)
}

/// Every `(member, attribute)` in `merged_tar` that [`EXT4_TARBALL_XATTRS`] says this route would
/// **silently drop**, capped at [`MAX_REPORTED_XATTR_SITES`].
///
/// A second walk of the tar rather than a field on [`TarShape`]: that type is `Copy` and is a
/// *sizing* answer, and folding a diagnostic list into it would make the size estimate carry state
/// it has nothing to do with. The walk is header-and-pax-body only — no file contents — so it costs
/// milliseconds even on a hundred-megabyte archive.
///
/// # Errors
/// [`Error::Artifact`] when the archive or one of its PAX records cannot be read. A malformed
/// record is refused rather than skipped: skipping it here would be the silent drop this whole
/// function exists to prevent, one level down.
fn dropped_xattr_sites(merged_tar: &[u8]) -> Result<Vec<(String, String)>> {
    let mut sites = Vec::new();
    let mut archive = tar::Archive::new(std::io::Cursor::new(merged_tar));
    for entry in archive
        .entries()
        .map_err(|e| Error::Artifact(format!("cannot walk the merged tar: {e}")))?
    {
        let mut entry = entry.map_err(|e| Error::Artifact(format!("malformed merged tar: {e}")))?;
        let entry_type = entry.header().entry_type();
        // The extension pseudo-members carry the records FOR the member that follows; reading their
        // bodies here would consume the bytes `pax_extensions()` is about to need.
        if entry_type.is_pax_global_extensions() || entry_type.is_pax_local_extensions() {
            continue;
        }
        let path = entry
            .path()
            .map_err(|e| Error::Artifact(format!("merged tar member path: {e}")))?
            .display()
            .to_string();
        let Some(extensions) = entry
            .pax_extensions()
            .map_err(|e| Error::Artifact(format!("cannot read pax extensions: {e}")))?
        else {
            continue;
        };
        for extension in extensions {
            let extension = extension
                .map_err(|e| Error::Artifact(format!("malformed pax extension record: {e}")))?;
            let key = extension
                .key()
                .map_err(|e| Error::Artifact(format!("pax extension key is not UTF-8: {e}")))?;
            let Some(name) = key.strip_prefix(PAX_SCHILY_XATTR) else {
                continue;
            };
            if !EXT4_TARBALL_XATTRS.contains(&name) {
                if sites.len() < MAX_REPORTED_XATTR_SITES {
                    sites.push((path.clone(), name.to_string()));
                } else {
                    // The cap bounds the message, not the verdict: one more site is enough to make
                    // the refusal, and the caller is told how many were shown.
                    return Ok(sites);
                }
            }
        }
    }
    Ok(sites)
}

/// The image size, in bytes, to create for a tree of this shape — a **pure function of the tar**,
/// which is what keeps the produced image deterministic.
///
/// `mkfs.ext4 -d` will not grow the file it is handed, so a size decision has to exist somewhere;
/// nothing in the pipeline had one, because the erofs writer sizes its own output. The margin is
/// measured rather than guessed: a 9,621-node / 95 MiB-payload tree needed 104 MiB on this host
/// (96 MiB and 100 MiB both failed loud), i.e. ~9% over payload for metadata, and this formula
/// yields ~133 MiB for it.
///
/// A too-small estimate is not silent — `mkfs.ext4` refuses and [`Ext4Producer::pack`] climbs the
/// [`SIZE_LADDER_RUNGS`] ladder before failing loud. A too-large one costs unused blocks in a
/// read-only root and a sparse hole on the host.
fn image_size_bytes(shape: TarShape) -> u64 {
    let payload = (shape.data_blocks + shape.dir_blocks + shape.symlink_blocks) * BLOCK_SIZE;
    let inodes = inode_count(shape);
    // The inode table is `inodes * INODE_SIZE`; doubling it covers the bitmaps, the group
    // descriptors and the resize inode, whose sizes all scale with the same geometry.
    let metadata = inodes * INODE_SIZE * 2;
    // 25% over payload plus an 8 MiB floor: the floor is what makes a nearly-empty tree (the
    // libarchive probe's one-member tar) still land on a mountable filesystem.
    let raw = payload + payload / 4 + metadata + 8 * 1024 * 1024;
    // Whole mebibytes, so the number in a build log is one a human can compare.
    raw.div_ceil(1024 * 1024) * 1024 * 1024
}

/// How many inodes to reserve (`-N`).
///
/// Pinned rather than derived, for the same reason the block size is: without `-N`, `mke2fs`
/// computes the inode count from the image size through the host's `/etc/mke2fs.conf` inode ratio,
/// so a file-dense tree (many small files in little data) would run out of inodes on one host and
/// not another. The count is the node count plus a quarter, with a floor.
fn inode_count(shape: TarShape) -> u64 {
    (shape.nodes + shape.nodes / 4 + 256).max(1024)
}

impl Ext4Producer {
    /// Probes `PATH` for [`EXT4_PRODUCER_BIN`] and runs the full version gate.
    ///
    /// # Errors
    /// As [`Ext4Producer::probe_binary`].
    pub fn probe() -> Result<Self> {
        Self::probe_binary(Path::new(EXT4_PRODUCER_BIN))
    }

    /// Runs §18 delta 8's version gate against `binary`, **both halves**, and classifies every
    /// outcome.
    ///
    /// Takes the binary as a parameter — rather than always resolving `PATH` — so the gate can be
    /// driven against a stand-in that reports an old version or a missing libarchive. A probe whose
    /// refusals cannot be produced is a probe nobody has watched refuse.
    ///
    /// # The two halves, and why the second one is a build
    ///
    /// 1. **Version.** `mkfs.ext4 -V` (on stderr, exit 0) reports `mke2fs <maj>.<min>.<patch>`;
    ///    below [`MIN_E2FSPROGS_VERSION`] the `-d <tarball>` form does not exist.
    /// 2. **libarchive.** `mke2fs` **dlopen**s libarchive rather than linking it, so `-V` reports
    ///    the same version whether or not tarballs work and `ldd` shows nothing. The only honest
    ///    check is a real one-member tarball build in a scratch directory (~4 ms), classifying the
    ///    `you need libarchive to be able to process tarballs` refusal. A probe that cannot see the
    ///    thing it claims to check is theater.
    ///
    /// # Errors
    /// * [`Error::CapabilityUnavailable`] when the facility is **absent**: the binary is not on
    ///   `PATH`, its version is below the gate, or its libarchive support is missing (§7.2 —
    ///   `ENOENT` is an absent facility, not a broken one).
    /// * [`Error::Io`] with its errno when the binary is present but cannot be executed (`EACCES`,
    ///   `ENOMEM`, …) — a **broken** facility keeps its errno.
    /// * [`Error::Artifact`] when the version cannot be parsed, or when the trial build fails for a
    ///   reason that is neither of the above, quoting what the tool said.
    pub fn probe_binary(binary: &Path) -> Result<Self> {
        let version = probe_version(binary)?;
        if version < MIN_E2FSPROGS_VERSION {
            let (ma, mi, pa) = version;
            let (rma, rmi, rpa) = MIN_E2FSPROGS_VERSION;
            return Err(Error::CapabilityUnavailable {
                op: "ext4 rootfs pack (§4.7)".to_string(),
                needed: format!(
                    "e2fsprogs >= {rma}.{rmi}.{rpa} at `{}`; found {ma}.{mi}.{pa}, whose `-d` \
                     accepts only a directory and would build the image from the empty scratch \
                     path instead of from the merged tar",
                    binary.display()
                ),
            });
        }
        probe_libarchive(binary)?;
        Ok(Ext4Producer {
            binary: binary.to_path_buf(),
            version,
        })
    }

    /// The e2fsprogs `(major, minor, patch)` the probe read.
    #[must_use]
    pub fn version(&self) -> (u32, u32, u32) {
        self.version
    }

    /// Packs `merged_tar` into an ext4 image at `out`.
    ///
    /// The image is **read-only in use**: the builder emits `ro` plus `rootflags=noload` for a
    /// `RootfsSource::Block` root, and `-O ^has_journal` here is the other half of that — the
    /// journal is the only thing `noload` guards, an unrecovered journal is what makes a read-only
    /// ext4 mount refuse, and an image with no journal is smaller and has nothing to recover. The
    /// `noload` token stays emitted regardless, so F3's reserved-cmdline law is untouched.
    ///
    /// # Extended attributes this route cannot carry
    ///
    /// `mkfs.ext4 -d <tarball>` writes exactly the attributes in [`EXT4_TARBALL_XATTRS`] and drops
    /// every other one **without a word** (measured — see that constant). An input carrying one is
    /// therefore **refused** rather than packed into an image whose attributes are quietly a subset
    /// of what `XattrPolicy::Preserve` promised: an accepted input is honored or rejected, never
    /// silently reinterpreted. The check is automatically scoped to `Preserve`, because under
    /// `Strip` the merged tar carries no attribute records at all.
    ///
    /// # Errors
    /// * [`Error::CapabilityUnavailable`] when the merged tree carries an extended attribute this
    ///   route would drop — naming the members, the attributes, and both ways forward.
    /// * [`Error::Artifact`] when the tar cannot be measured or staged, or when `mkfs.ext4` refuses
    ///   at every rung of the size ladder — quoting the tool's own message and the sizes tried, so a
    ///   sizing miss reads as a sizing miss.
    pub fn pack(&self, merged_tar: &[u8], out: &Path) -> Result<()> {
        let dropped = dropped_xattr_sites(merged_tar)?;
        if !dropped.is_empty() {
            let rendered = dropped
                .iter()
                .map(|(path, name)| format!("{name} on /{path}"))
                .collect::<Vec<_>>()
                .join(", ");
            let more = if dropped.len() >= MAX_REPORTED_XATTR_SITES {
                " (and more)"
            } else {
                ""
            };
            return Err(Error::CapabilityUnavailable {
                op: "ext4 rootfs pack with `XattrPolicy::Preserve` (§4.7)".to_string(),
                needed: format!(
                    "an ext4 producer that carries {rendered}{more} into the image. `{}` writes \
                     only {:?} through its `-d <tarball>` form and drops the rest silently, so \
                     packing this tree would produce an image whose attributes are a SUBSET of the \
                     ones preserved. Either pack it as `RootfsFormat::Erofs` (which keeps every \
                     namespace), or declare `\"xattrs\": \"strip\"` for this artifact if the \
                     attributes are not load-bearing",
                    self.binary.display(),
                    EXT4_TARBALL_XATTRS,
                ),
            });
        }
        let shape = tar_shape(merged_tar)?;
        let identity = Ext4Identity::from_merged_tar(merged_tar);
        // The tool reads `-d` from a PATH, so the merged tar has to land on disk. Beside the output
        // rather than in `/tmp`: the artifacts dir is where this build already writes, and a
        // multi-hundred-megabyte staging file does not belong on a shared host's tmpfs (AGENTS.md's
        // runtime-files rule). `TempDir` removes it on every path, including the panic one.
        let staging = out.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(staging).map_err(Error::Io)?;
        let staging = tempfile::TempDir::new_in(staging).map_err(Error::Io)?;
        let tar_path = staging.path().join("merged.tar");
        std::fs::write(&tar_path, merged_tar).map_err(Error::Io)?;

        let base = image_size_bytes(shape);
        let inodes = inode_count(shape);
        let mut attempts: Vec<String> = Vec::new();
        for rung in 0..SIZE_LADDER_RUNGS {
            let size = base << rung;
            match self.run_mkfs(&tar_path, out, size, inodes, &identity) {
                Ok(()) => return Ok(()),
                Err(message) => attempts.push(format!("{} MiB: {message}", size / (1024 * 1024))),
            }
        }
        // Every rung failed. The output is whatever the last attempt left — a half-populated
        // filesystem — and it MUST NOT survive: the stage's cache sidecar is written by the
        // pipeline on success only, but a stale sidecar from an earlier good build would have the
        // next warm run serve these truncated bytes under a key that still says "this is mine".
        // Reported rather than discarded, on the residue discipline the OCI blob guard already
        // follows: a removal that fails is the one case where the caller's error below is not the
        // whole story.
        match std::fs::remove_file(out) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => attempts.push(format!(
                "and the partial image at {} could not be removed: {e} — DELETE IT before the next \
                 build, or it may be served as this artifact",
                out.display()
            )),
        }
        Err(Error::Artifact(format!(
            "`{}` could not build the ext4 rootfs at {} from {} nodes / {} data blocks after {} \
             size attempts — {}",
            self.binary.display(),
            out.display(),
            shape.nodes,
            shape.data_blocks,
            SIZE_LADDER_RUNGS,
            attempts.join("; ")
        )))
    }

    /// One `mkfs.ext4` invocation at a fixed size. `Err` carries the tool's own message.
    fn run_mkfs(
        &self,
        tar_path: &Path,
        out: &Path,
        size: u64,
        inodes: u64,
        identity: &Ext4Identity,
    ) -> std::result::Result<(), String> {
        // A fresh file per rung: `mkfs.ext4` writes into whatever it is handed, and a failed rung
        // leaves a partial filesystem the next rung would build on top of.
        let file = std::fs::File::create(out).map_err(|e| format!("cannot create {out:?}: {e}"))?;
        file.set_len(size)
            .map_err(|e| format!("cannot size {out:?} to {size} bytes: {e}"))?;
        drop(file);
        let output = std::process::Command::new(&self.binary)
            .args(mkfs_args(tar_path, out, size, inodes, identity))
            // The libext2fs library — not the `mke2fs` binary — is what honors this, which is why
            // it travels as an environment variable rather than as a flag.
            .env("SOURCE_DATE_EPOCH", identity.source_date_epoch.to_string())
            .output()
            .map_err(|e| format!("cannot run `{}`: {e}", self.binary.display()))?;
        if output.status.success() {
            return Ok(());
        }
        Err(format!(
            "exit {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// The argument vector for one ext4 pack — the **one** place the producer's flags are written down.
///
/// Pure and separate from the spawn so every flag that makes the image what it is
/// (`-O ^has_journal`, the determinism triple's two flags, the pinned geometry) is assertable
/// without running anything. Every one of them is here because leaving it to the tool means leaving
/// it to `/etc/mke2fs.conf`, which is a per-host file.
fn mkfs_args(
    tar_path: &Path,
    out: &Path,
    size: u64,
    inodes: u64,
    identity: &Ext4Identity,
) -> Vec<std::ffi::OsString> {
    let mut args: Vec<std::ffi::OsString> = vec![
        "-q".into(),
        // Pinned geometry: see BLOCK_SIZE / INODE_SIZE.
        "-b".into(),
        BLOCK_SIZE.to_string().into(),
        "-I".into(),
        INODE_SIZE.to_string().into(),
        "-N".into(),
        inodes.to_string().into(),
        // No reserved-for-root blocks: this root never gets written to, so the 5% default is 5% of
        // the image spent on nothing.
        "-m".into(),
        "0".into(),
        // The root mounts `ro` with `rootflags=noload`, so recovery is suppressed and a journal has
        // nothing to do but take up space. See `Ext4Producer::pack`.
        "-O".into(),
        "^has_journal".into(),
        // Two of the determinism triple; `SOURCE_DATE_EPOCH` is the third and rides the env.
        "-U".into(),
        identity.uuid().into(),
        "-E".into(),
        format!("hash_seed={}", identity.hash_seed()).into(),
        // The merged tar (§4.7) — the whole reason the version gate exists.
        "-d".into(),
        tar_path.into(),
        // Never prompt: the target is a regular file this producer just created.
        "-F".into(),
        out.into(),
    ];
    // `mke2fs` derives the filesystem size from the device when it is not told; the file was
    // `set_len`'d to exactly this, and stating it keeps the argv self-describing.
    args.push((size / BLOCK_SIZE).to_string().into());
    args
}

/// Reads `binary`'s e2fsprogs version, classifying an absent binary apart from a broken one.
///
/// # Errors
/// As documented on [`Ext4Producer::probe_binary`].
fn probe_version(binary: &Path) -> Result<(u32, u32, u32)> {
    let output = std::process::Command::new(binary)
        .arg("-V")
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                // An absent facility, per §7.2 — `CapabilityUnavailable`, carrying its remediation.
                Error::CapabilityUnavailable {
                    op: "ext4 rootfs pack (§4.7)".to_string(),
                    needed: format!(
                        "the `{}` binary on PATH (e2fsprogs >= {}.{}.{}, built with libarchive); \
                         install e2fsprogs, or register this rootfs with the default \
                         `\"format\": \"erofs\"`",
                        binary.display(),
                        MIN_E2FSPROGS_VERSION.0,
                        MIN_E2FSPROGS_VERSION.1,
                        MIN_E2FSPROGS_VERSION.2
                    ),
                }
            } else {
                // A BROKEN facility keeps its errno (§7.2), rather than being flattened into the
                // same refusal an absent one gets: `EACCES` on a present binary is an operator
                // problem with a different fix than "install e2fsprogs".
                Error::Io(e)
            }
        })?;
    // `-V` writes to stderr and exits 0; read both streams so a future release that moves it does
    // not turn the gate into a parse failure.
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    parse_e2fsprogs_version(&text).ok_or_else(|| {
        Error::Artifact(format!(
            "cannot read an e2fsprogs version from `{} -V`: {:?}. The §4.7 producer refuses rather \
             than assuming a version, because assuming a new-enough one is exactly the silent \
             mis-build the version gate exists to prevent",
            binary.display(),
            text.trim()
        ))
    })
}

/// Extracts `(major, minor, patch)` from an `mke2fs -V` banner.
///
/// Pure, so both the accepted shape (`mke2fs 1.47.2 (1-Jan-2025)`) and every unreadable one are
/// unit-testable without a binary to run.
fn parse_e2fsprogs_version(text: &str) -> Option<(u32, u32, u32)> {
    let line = text.lines().find(|l| l.contains("mke2fs "))?;
    let rest = line.split("mke2fs ").nth(1)?;
    let token = rest.split_whitespace().next()?;
    let mut parts = token.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    // A two-component version (`1.47`) is a real e2fsprogs spelling; a missing patch is 0, not a
    // parse failure.
    let patch = parts.next().map_or(Some(0), |p| p.parse().ok())?;
    Some((major, minor, patch))
}

/// Builds a one-member tarball and asks `binary` to populate an image from it — the only honest
/// libarchive check (see [`Ext4Producer::probe_binary`]).
///
/// # Errors
/// As documented on [`Ext4Producer::probe_binary`].
fn probe_libarchive(binary: &Path) -> Result<()> {
    let dir = tempfile::TempDir::new().map_err(Error::Io)?;
    let tar_path = dir.path().join("probe.tar");
    let img_path = dir.path().join("probe.img");
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_mode(0o755);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(0);
        builder
            .append_data(&mut header, "probe", &[][..])
            .map_err(|e| Error::Artifact(format!("cannot build the libarchive probe tar: {e}")))?;
        builder
            .finish()
            .map_err(|e| Error::Artifact(format!("cannot build the libarchive probe tar: {e}")))?;
    }
    std::fs::write(&tar_path, &tar_bytes).map_err(Error::Io)?;
    let file = std::fs::File::create(&img_path).map_err(Error::Io)?;
    let size = 8 * 1024 * 1024;
    file.set_len(size).map_err(Error::Io)?;
    drop(file);
    let identity = Ext4Identity::from_merged_tar(&tar_bytes);
    let output = std::process::Command::new(binary)
        .args(mkfs_args(&tar_path, &img_path, size, 1024, &identity))
        .env("SOURCE_DATE_EPOCH", identity.source_date_epoch.to_string())
        .output()
        .map_err(Error::Io)?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.to_ascii_lowercase().contains(LIBARCHIVE_MARKER) {
        return Err(Error::CapabilityUnavailable {
            op: "ext4 rootfs pack (§4.7)".to_string(),
            needed: format!(
                "libarchive loadable by `{}` (it is dlopen'd, not linked, so `-V` cannot report \
                 it); install libarchive, or register this rootfs with the default \
                 `\"format\": \"erofs\"`. The tool said: {}",
                binary.display(),
                stderr.trim()
            ),
        });
    }
    Err(Error::Artifact(format!(
        "`{} -d <tarball>` failed its start-up probe with exit {:?}: {}. The §4.7 producer refuses \
         rather than packing, because a producer that cannot build a one-directory image will not \
         build a rootfs either — and finding that out at the end of a multi-minute pack is the \
         silent mis-build the gate exists to prevent",
        binary.display(),
        output.status.code(),
        stderr.trim()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The version parser accepts what the tool actually prints, and refuses everything else rather
    /// than guessing. RED on a parser that falls back to a default version: the `None` arms below
    /// would become `Some`, and `probe_binary` would wave through an e2fsprogs whose `-d` cannot
    /// read a tarball at all.
    #[test]
    fn e2fsprogs_version_parses_the_real_banner_and_refuses_the_rest() {
        assert_eq!(
            parse_e2fsprogs_version("mke2fs 1.47.2 (1-Jan-2025)\n\tUsing EXT2FS Library 1.47.2\n"),
            Some((1, 47, 2))
        );
        // Two components is a real spelling; the patch is 0, not a refusal.
        assert_eq!(parse_e2fsprogs_version("mke2fs 1.47\n"), Some((1, 47, 0)));
        // The gate's own boundary, both sides.
        assert!(parse_e2fsprogs_version("mke2fs 1.47.1\n").unwrap() >= MIN_E2FSPROGS_VERSION);
        assert!(parse_e2fsprogs_version("mke2fs 1.47.0\n").unwrap() < MIN_E2FSPROGS_VERSION);
        assert!(parse_e2fsprogs_version("mke2fs 1.46.5\n").unwrap() < MIN_E2FSPROGS_VERSION);
        for unreadable in [
            "",
            "command not found\n",
            "mkfs.ext4: unrecognized option\n",
            "mke2fs \n",
            "mke2fs vNext\n",
        ] {
            assert_eq!(
                parse_e2fsprogs_version(unreadable),
                None,
                "must refuse to read a version out of {unreadable:?}"
            );
        }
    }

    /// The argv carries every flag the image's shape depends on. RED on dropping any one of them:
    /// `-O ^has_journal` leaves a journal on a root that mounts `noload`; `-U`/`hash_seed` leave the
    /// image non-deterministic (measured: 20 differing bytes per pack); `-b`/`-I`/`-N` hand the
    /// geometry to the host's `/etc/mke2fs.conf`.
    #[test]
    fn the_pack_argv_pins_the_journal_the_determinism_and_the_geometry() {
        let identity = Ext4Identity::from_merged_tar(b"tree");
        let args: Vec<String> = mkfs_args(
            Path::new("/s/merged.tar"),
            Path::new("/a/rootfs.ext4"),
            64 * 1024 * 1024,
            4096,
            &identity,
        )
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
        for expected in [
            "-O",
            "^has_journal",
            "-U",
            identity.uuid(),
            "-E",
            &format!("hash_seed={}", identity.hash_seed()),
            "-b",
            "4096",
            "-I",
            "256",
            "-N",
            "4096",
            "-d",
            "/s/merged.tar",
            "-F",
            "/a/rootfs.ext4",
        ] {
            assert!(
                args.iter().any(|a| a == expected),
                "argv must carry {expected:?}: {args:?}"
            );
        }
        // The block count trails the output path, which is how `mke2fs` is invoked.
        assert_eq!(args.last().map(String::as_str), Some("16384"));
    }

    /// The identity is a function of the tree and of nothing else. RED on deriving either knob from
    /// the clock or from a random source (the two runs would differ), and RED on deriving the
    /// hash_seed from the uuid by copying it (the equality assertion below).
    #[test]
    fn the_ext4_identity_is_content_addressed_and_the_two_knobs_differ() {
        let a = Ext4Identity::from_merged_tar(b"one tree");
        let again = Ext4Identity::from_merged_tar(b"one tree");
        let b = Ext4Identity::from_merged_tar(b"another tree");
        assert_eq!(
            a, again,
            "the same merged tar must derive the same identity"
        );
        assert_ne!(a.uuid(), b.uuid(), "two trees must not share a volume UUID");
        assert_ne!(
            a.uuid(),
            a.hash_seed(),
            "the volume UUID and the directory-hash seed are independent on-disk fields"
        );
        assert_eq!(a.source_date_epoch, 0);
        // Canonical UUID shape, and NOT the all-zeros value `mke2fs` reads as "unset, generate one"
        // — the measured reason a `-U`-pinned pack still differed run to run.
        for knob in [a.uuid(), a.hash_seed()] {
            assert_eq!(knob.len(), 36, "canonical UUID length: {knob}");
            assert_eq!(
                knob.split('-').map(str::len).collect::<Vec<_>>(),
                vec![8, 4, 4, 4, 12],
                "canonical UUID grouping: {knob}"
            );
            assert_ne!(knob, "00000000-0000-0000-0000-000000000000");
        }
    }

    /// The size estimate covers the measured floor. RED on dropping the metadata term or the
    /// margin: the 9,621-node / 95 MiB-payload tree measured on this host needed 104 MiB, and 96
    /// and 100 both failed loud.
    #[test]
    fn the_image_size_covers_the_measured_floor() {
        let measured = TarShape {
            // 87.45 MiB of file data, at 4 KiB blocks.
            data_blocks: 22389,
            dir_blocks: 1941,
            symlink_blocks: 0,
            nodes: 9621,
        };
        let size = image_size_bytes(measured);
        assert!(
            size >= 104 * 1024 * 1024,
            "must cover the measured 104 MiB floor, got {} MiB",
            size / (1024 * 1024)
        );
        // Whole mebibytes, and an empty tree still lands on something mountable.
        assert_eq!(size % (1024 * 1024), 0);
        assert!(image_size_bytes(TarShape::default()) >= 8 * 1024 * 1024);
        // Inodes cover every node, not just the ones holding data.
        assert!(inode_count(measured) > measured.nodes);
    }
}
