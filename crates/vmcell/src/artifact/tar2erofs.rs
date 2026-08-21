//! Conversion of tar archives to EROFS images.
//!
//! This module provides an experimental utility for building an EROFS
//! filesystem directly from a tar archive for use as a root filesystem.

use fs_erofs::mkfs::{Node, NodeMeta, build_image};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};

/// The artifact's extended-attribute policy (design §4.7), re-exported where the packer that
/// honors it lives.
///
/// **Defined** in [`crate::artifact`] rather than here, and that is forced rather than stylistic:
/// the policy is an entry-level property of a `rootfs` registry entry
/// ([`crate::artifact::RootfsRegistryEntry::xattrs`], §18 delta 7), the registry parser is compiled
/// in **every** feature configuration, and this module is gated on `am-fs-erofs`. A definition here
/// would not exist for the entry that declares it.
pub use crate::artifact::XattrPolicy;

/// A `(dest_path, source_path, mode)` file inserted into the merged tree after every layer.
///
/// `mode` is `None` for vmcell's own manifest entries — they take the
/// `injected_file_mode` bin/sbin heuristic — and `Some(perm)` for a downstream
/// [`ExtraFile`](crate::artifact::rootfs::ExtraFile), whose permission bits the caller stated
/// explicitly (design §4.2: "extra files do not inherit the `injected_file_mode` heuristic —
/// the caller said what they meant"). `perm` carries permission bits only; the `S_IFREG` type
/// bit is added here.
#[cfg(feature = "am-fs-erofs")]
pub type InjectedFile<'a> = (&'a str, &'a Path, Option<u16>);

/// Reads `src_path` and inserts it into `entries` at the normalized `dest_path` as a regular
/// file owned by `uid`/`gid` 0 with `mtime` 0 (the deterministic-emission discipline, §10.3).
///
/// The ONE injection insert: both the downstream extra files and vmcell's own manifest entries
/// go through it, so the ownership/mtime/type-bit rules and the explicit-mode-else-heuristic
/// rule exist in exactly one place.
///
/// # Errors
/// Returns [`crate::error::Error::Artifact`] if `src_path` cannot be read.
#[cfg(feature = "am-fs-erofs")]
fn insert_injected_file(
    entries: &mut HashMap<PathBuf, Node>,
    (dest_path, src_path, mode): InjectedFile<'_>,
) -> crate::error::Result<()> {
    let content = std::fs::read(src_path).map_err(|e| {
        crate::error::Error::Artifact(format!("Failed to read injected file {src_path:?}: {e}"))
    })?;
    let meta = NodeMeta {
        uid: 0,
        gid: 0,
        mtime: 0,
        mtime_nsec: 0,
    };
    // An explicit caller mode wins; otherwise only injected binaries (steward -> usr/sbin,
    // guest-tools -> vmcell-tools) are executable and injected DATA files (the CA cert under
    // ca-certificates/) are 0o644.
    let mode = mode.unwrap_or_else(|| injected_file_mode(dest_path)) | fs_erofs::inode::S_IFREG;
    let node = Node::File {
        mode,
        data: content,
        meta,
        // NOT a policy site (§4.7, invariant F5): vmcell's own injections — and the downstream
        // `ExtraFile`s, which are regular files a caller named, never a source layer — carry no
        // xattrs under EITHER policy. `ExtraFile` has no xattr field to carry, and the steward/CA/
        // guest-tools entries are vmcell's, so nothing a consumer declares may add attributes to
        // them. Leaving this `vec![]` is the requirement, not a missed site.
        xattrs: vec![],
    };
    entries.insert(normalize_path(Path::new(dest_path)), node);
    Ok(())
}

/// Which of vmcell's OWN injection-manifest entries claimed a dest — the two node kinds the
/// injection tail of [`build_node_map`] can produce (design §4.2).
#[cfg(feature = "am-fs-erofs")]
#[derive(Clone, Copy, Debug)]
enum InjectionKind {
    /// An `injected_files` entry: a regular file (the steward, the CA, the multicall binary).
    File,
    /// An `injected_symlinks` entry: one applet link pointing at the multicall binary.
    Symlink,
}

#[cfg(feature = "am-fs-erofs")]
impl InjectionKind {
    /// How this kind is named in the collision refusal.
    const fn as_str(self) -> &'static str {
        match self {
            Self::File => "an injected file",
            Self::Symlink => "an applet symlink",
        }
    }
}

/// Claims `dest_path` for one entry of vmcell's own injection manifest, refusing a dest an
/// earlier entry of the SAME manifest already claimed (design §4.2, invariant F5).
///
/// # Why this refusal exists
/// The manifest injects the guest-tools multicall binary as a FILE at
/// `<tools_dir>/<multicall-bin>` and then one applet SYMLINK per roster entry into that same
/// directory — and since v33 delta 6 (§10.5) that roster is registry DATA, not a const. Under the
/// plain last-wins `insert` this tail used to do, a registered handler whose roster names the
/// multicall binary's own file name replaced the binary with a dangling self-symlink: the image
/// shipped with no multicall binary and every applet dangling, and the build reported success.
/// That is the docs/90 H1 failure shape exactly — a silent wrong image, not a missing test helper.
///
/// # What is refused, and what is not
/// **Every** duplicate dest inside vmcell's own tail is refused, not only a file-vs-symlink kind
/// mismatch. Deliberate, for one reason: two manifest entries at one path mean the second's bytes
/// are the image's and the first's are nowhere, whatever their kinds, so an identical-kind
/// duplicate is exactly as silent. It is also the duplicate-dest law the F5 validator one level up
/// already applies to downstream extras (`validate_extra_files`: "listed twice; the last writer
/// would silently win"), applied to the same class of input rather than restated with a weaker
/// rule. The refusal names both claimants and is keyed on the NORMALIZED path, because that is the
/// key the merged tree is built on: `/vmcell-tools/ip`, `vmcell-tools/ip` and
/// `vmcell-tools/x/../ip` are three raw strings and ONE node in the packed image, so a ledger
/// keyed on the dest string would hand the second writer a free pass.
///
/// It deliberately does NOT cover the two collisions the packer resolves BY DESIGN, each with its
/// own pinning test: a layer entry an injection overwrites (H-ART-3 — the injections are inserted
/// last precisely so they win a `.wh.` whiteout or an upper layer), and a downstream
/// [`ExtraFile`](crate::artifact::rootfs::ExtraFile) an injection overwrites (invariant F5's
/// structural backstop; such an extra is rejected by `is_reserved_injection_path` one level up).
/// Nor does it cover an injection whose dest is the PARENT of another injection's dest — that is
/// `nodes_to_erofs`'s "child under non-directory node" refusal (L-ART-6), already loud, and a
/// second copy here would be a second law.
///
/// # The gate binds the CALL SITES
/// Both injection loops in [`build_node_map`] call this, and every test that guards the law drives
/// `build_node_map` rather than this predicate — so dropping either call reddens them, which an
/// extracted-predicate test would not see (AGENTS.md: "a gate binds the call sites, not just the
/// extracted predicate").
///
/// # Errors
/// [`crate::error::Error::Artifact`] naming the dest and both claiming entry kinds.
#[cfg(feature = "am-fs-erofs")]
fn claim_injection_dest(
    claimed: &mut HashMap<PathBuf, InjectionKind>,
    dest_path: &str,
    kind: InjectionKind,
) -> crate::error::Result<()> {
    if let Some(prior) = claimed.insert(normalize_path(Path::new(dest_path)), kind) {
        return Err(crate::error::Error::Artifact(format!(
            "vmcell's rootfs injection manifest claims `{dest_path}` twice: {} and {} both name \
             it. The last writer would silently win and the pack would report success while the \
             image carries only one of them — an applet roster (§10.5) naming the multicall \
             binary's own file name replaces that binary with a dangling self-symlink, leaving \
             the image with no guest tools at all. Rename the colliding entry.",
            prior.as_str(),
            kind.as_str(),
        )));
    }
    Ok(())
}

/// The PAX-record prefix every `SCHILY.xattr.<full name>` extended attribute arrives under.
#[cfg(feature = "am-fs-erofs")]
const PAX_SCHILY_XATTR: &str = "SCHILY.xattr.";

/// Reads one tar entry's extended attributes as EROFS [`XattrSpec`]s, honoring `policy` (§4.7).
///
/// The ONE tar→xattr decode: the six tar-derived node arms below all call it, so the namespace
/// mapping and the `Strip` short-circuit exist in exactly one place and no arm can quietly grow a
/// second reading of the same PAX records.
///
/// Under [`XattrPolicy::Strip`] it reads nothing at all — not the records, not the entry — so the
/// default artifact's pack is byte-for-byte the pre-v33 pack and cannot fail on a record shape it
/// never looks at.
///
/// # Scope
/// `SCHILY.xattr.*` only — the convention GNU tar, libarchive's `--xattrs` and every OCI layer
/// producer in practice emit. `LIBARCHIVE.xattr.*` (whose values are base64) is deliberately NOT
/// decoded: guessing at an encoding would fabricate attribute bytes, and a base carrying only that
/// shape is better served by re-tarring it than by vmcell inventing a second reading.
///
/// The namespace prefix is folded into EROFS's `name_index` the way `mkfs.erofs` does; a name
/// under no known namespace is stored raw (`ns::RAW`), which `fs_erofs::xattr::resolve_full_name`
/// reconstructs byte-for-byte. The result is sorted by `(name_index, name)` so an image's inode
/// bytes do not depend on the order a producer happened to write the records in.
///
/// # Errors
/// [`crate::error::Error::Artifact`] when a PAX record cannot be parsed or its key is not UTF-8 —
/// fail loud, never a silent drop: under `Preserve` the caller asked for these bytes, so packing
/// an image that quietly lacks them is exactly the accepted-then-ignored class.
#[cfg(feature = "am-fs-erofs")]
fn tar_entry_xattrs<R: Read>(
    file: &mut tar::Entry<'_, R>,
    policy: XattrPolicy,
) -> crate::error::Result<Vec<fs_erofs::mkfs::XattrSpec>> {
    if policy == XattrPolicy::Strip {
        return Ok(vec![]);
    }
    // A pax header entry that reaches the caller's match is either skipped (`g`, the archive-wide
    // global header, which names no filesystem object) or REJECTED naming the member (`x`, an
    // unfolded local header — `tar` could not attach it to the member that follows, so that member
    // may carry a truncated path). Reading its body here would consume bytes neither outcome does,
    // and would replace that named refusal with a decode error. Neither carries attributes for a
    // node, because neither becomes one.
    let entry_type = file.header().entry_type();
    if entry_type.is_pax_global_extensions() || entry_type.is_pax_local_extensions() {
        return Ok(vec![]);
    }
    let Some(extensions) = file
        .pax_extensions()
        .map_err(|e| crate::error::Error::Artifact(format!("cannot read pax extensions: {e}")))?
    else {
        return Ok(vec![]);
    };
    let mut out = Vec::new();
    for extension in extensions {
        let extension = extension.map_err(|e| {
            crate::error::Error::Artifact(format!("malformed pax extension record: {e}"))
        })?;
        let key = extension.key().map_err(|e| {
            crate::error::Error::Artifact(format!("pax extension key is not UTF-8: {e}"))
        })?;
        let Some(full_name) = key.strip_prefix(PAX_SCHILY_XATTR) else {
            // Every other pax record (`path`, `mtime`, `size`, GNU sparse…) describes the member
            // itself and is consumed by `tar` already; it is not an extended attribute.
            continue;
        };
        out.push(xattr_spec(full_name, extension.value_bytes()));
    }
    out.sort_by(|a, b| (a.name_index, &a.name).cmp(&(b.name_index, &b.name)));
    Ok(out)
}

/// Splits a full attribute name (`security.capability`) into EROFS's `(name_index, suffix)` form.
///
/// Pure and separate from the PAX walk above so the namespace table is unit-testable without
/// building a tar. The ACL slots (`system.posix_acl_access`/`_default`) carry their whole name in
/// the index and an EMPTY suffix — that is the on-disk shape, not an omission.
#[cfg(feature = "am-fs-erofs")]
fn xattr_spec(full_name: &str, value: &[u8]) -> fs_erofs::mkfs::XattrSpec {
    use fs_erofs::xattr::ns;
    let (name_index, suffix) = match full_name {
        "system.posix_acl_access" => (ns::POSIX_ACL_ACCESS, ""),
        "system.posix_acl_default" => (ns::POSIX_ACL_DEFAULT, ""),
        _ => match full_name.split_once('.') {
            Some(("user", rest)) => (ns::USER, rest),
            Some(("trusted", rest)) => (ns::TRUSTED, rest),
            Some(("security", rest)) => (ns::SECURITY, rest),
            Some(("lustre", rest)) => (ns::LUSTRE, rest),
            // No known namespace prefix: store the name RAW (index 0), which is what
            // `resolve_full_name` reads back unchanged. Rejecting it would fail a pack over an
            // attribute the kernel itself would have accepted.
            _ => (ns::RAW, full_name),
        },
    };
    fs_erofs::mkfs::XattrSpec::new(name_index, suffix.as_bytes().to_vec(), value.to_vec())
}

/// Builds the flat `path -> Node` map from the injected files/symlinks and the given tar
/// archives, applying OCI whiteout semantics (`.wh.<name>` deletions and `.wh..wh..opq`
/// opaque-dir markers) as layers are merged in order.
///
/// Extracted from [`tar_to_erofs`] so the decode paths no gate sees — a device node's
/// `rdev` (which must be `makedev`-encoded, not a naive `(major<<8)|minor`) and the
/// whiteout deletions — are unit-testable (ART-4) by inspecting the resulting nodes
/// directly, rather than only through the opaque packed EROFS bytes.
///
/// `extra_files` are the downstream [`ExtraFile`](crate::artifact::rootfs::ExtraFile)s: they
/// are inserted AFTER the layer merge (so they win base-image collisions and whiteouts —
/// deliberate composition) and BEFORE `injected_files`, which keeps vmcell's own injections
/// unconditional and authoritative (design §4.2, invariant F5). The pack tail rejects an extra
/// dest that collides with vmcell's own list, so the two sets are disjoint by construction; the
/// insert order is the structural backstop.
///
/// `xattrs` is the artifact's [`XattrPolicy`] (§4.7) and governs the **tar-derived** nodes only:
/// the injected and synthesized nodes carry none under either policy (invariant F5).
///
/// # Errors
/// Returns [`crate::error::Error::Artifact`] if an injected file or an archive entry cannot be
/// read, or if an archive member carries an entry type this packer has no node for (contiguous,
/// GNU-sparse, an unfolded `x`/`L`/`K` extension header, or an unknown type byte) — such a member
/// is rejected, never dropped, because a dropped member packs a rootfs that boots as if complete.
/// The archive-wide pax global header (`g`) names no filesystem object and is the one skipped type.
/// Under [`XattrPolicy::Preserve`], also if a member's PAX records cannot be decoded. And, per
/// [`claim_injection_dest`], if two entries of vmcell's OWN injection manifest claim one dest.
#[cfg(feature = "am-fs-erofs")]
fn build_node_map<'a, R: Read + 'a>(
    archives: impl IntoIterator<Item = tar::Archive<R>>,
    extra_files: Vec<InjectedFile<'_>>,
    injected_files: Vec<InjectedFile<'_>>,
    injected_symlinks: Vec<(&str, &str)>,
    xattr_policy: XattrPolicy,
) -> crate::error::Result<HashMap<PathBuf, Node>> {
    let mut entries: HashMap<PathBuf, Node> = HashMap::new();

    // NOTE: the injected files/symlinks (steward, CA, guest-tools) are inserted AFTER
    // the layer merge below — see the tail of this function (H-ART-3 / design §4.2,
    // Rootfs sources and the one packer: "inject ... then stream the tree"). Injecting
    // before the merge let an upper layer's
    // content or a `.wh.` whiteout silently clobber the baked steward or CA.

    for mut archive in archives {
        for file in archive
            .entries()
            .map_err(|e| crate::error::Error::Artifact(e.to_string()))?
        {
            let mut file = file.map_err(|e| crate::error::Error::Artifact(e.to_string()))?;
            let path = file
                .path()
                .map_err(|e| crate::error::Error::Artifact(e.to_string()))?
                .into_owned();

            let meta = NodeMeta {
                uid: file.header().uid().unwrap_or(0) as u32,
                gid: file.header().gid().unwrap_or(0) as u32,
                mtime: file.header().mtime().unwrap_or(0),
                mtime_nsec: 0,
            };

            let mode = file.header().mode().unwrap_or(0) as u16;

            // This member's source xattrs, read ONCE through the one decode (§4.7). Read here,
            // before the arms, because the `Regular` arm consumes the entry body below and the
            // PAX records have to be taken off the entry first. `Strip` reads nothing.
            let xattrs = tar_entry_xattrs(&mut file, xattr_policy)?;

            let node = match file.header().entry_type() {
                tar::EntryType::Regular => {
                    let mut data = Vec::new();
                    file.read_to_end(&mut data)
                        .map_err(|e| crate::error::Error::Artifact(e.to_string()))?;
                    // The artifact's xattr policy decides (§4.7, §18 delta 7), and this arm is
                    // the one the decision was written for: `security.capability` rides a
                    // regular file. Under `Strip` — the default, and every artifact vmcell
                    // itself ships — `xattrs` is empty and the packed bytes are what the
                    // pre-v33 packer produced. Under `Preserve` the member's PAX
                    // `SCHILY.xattr.*` records are carried into the inode. Both directions are
                    // pinned by the `tests::pax_xattrs_are_*` pair.
                    Node::File {
                        mode: mode | fs_erofs::inode::S_IFREG,
                        data,
                        meta,
                        xattrs,
                    }
                }
                tar::EntryType::Directory => Node::Dir {
                    mode: mode | fs_erofs::inode::S_IFDIR,
                    entries: BTreeMap::new(),
                    meta,
                    xattrs,
                },
                tar::EntryType::Symlink => {
                    let target = file
                        .link_name()
                        .map_err(|e| crate::error::Error::Artifact(e.to_string()))?
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned();
                    Node::Symlink {
                        mode: mode | fs_erofs::inode::S_IFLNK,
                        target,
                        meta,
                        xattrs,
                    }
                }
                tar::EntryType::Char => {
                    let major = file
                        .header()
                        .device_major()
                        .map_err(|e| crate::error::Error::Artifact(e.to_string()))?
                        .unwrap_or(0);
                    let minor = file
                        .header()
                        .device_minor()
                        .map_err(|e| crate::error::Error::Artifact(e.to_string()))?
                        .unwrap_or(0);
                    Node::Device {
                        mode: mode | fs_erofs::inode::S_IFCHR,
                        rdev: libc::makedev(major as libc::c_uint, minor as libc::c_uint) as u32,
                        meta,
                        xattrs,
                    }
                }
                tar::EntryType::Block => {
                    let major = file
                        .header()
                        .device_major()
                        .map_err(|e| crate::error::Error::Artifact(e.to_string()))?
                        .unwrap_or(0);
                    let minor = file
                        .header()
                        .device_minor()
                        .map_err(|e| crate::error::Error::Artifact(e.to_string()))?
                        .unwrap_or(0);
                    Node::Device {
                        mode: mode | fs_erofs::inode::S_IFBLK,
                        rdev: libc::makedev(major as libc::c_uint, minor as libc::c_uint) as u32,
                        meta,
                        xattrs,
                    }
                }
                tar::EntryType::Fifo => Node::Special {
                    mode: mode | fs_erofs::inode::S_IFIFO,
                    meta,
                    xattrs,
                },
                // A hardlink must NOT be silently dropped (H-ART-2): the default Debian base
                // carries e.g. `usr/bin/perl5.NN` -> `usr/bin/perl`, which would otherwise
                // vanish from the packed rootfs. MATERIALIZE it — copy the target file's
                // content to the link path (erofs has no hardlink-dedup requirement here).
                // A tar hardlink references an EARLIER entry, so the target is already in the
                // merged tree. Fail loud (never `_ => continue`) only if the target is absent
                // or is not a regular file. (`tar::EntryType` is non-exhaustive, so the
                // trailing `_` still catches genuinely-unknown future types.)
                //
                // XATTRS (§4.7, §18 delta 7): this arm keeps the merged TARGET's xattrs and
                // discards this member's own, under both policies — the eleventh
                // node-construction site, and the one §4.7's "ten" does not count. It is not an
                // oversight: xattrs are an inode property, a hardlink IS the target's inode, so a
                // link entry cannot legitimately carry a different set, and this arm already
                // discards this member's `mode` and `meta` for exactly that reason. Pinned by
                // `tests::hardlink_inherits_the_targets_xattrs`.
                tar::EntryType::Link => {
                    let target = file
                        .link_name()
                        .map_err(|e| crate::error::Error::Artifact(e.to_string()))?
                        .ok_or_else(|| {
                            crate::error::Error::Artifact(format!(
                                "hardlink {} has no target",
                                path.display()
                            ))
                        })?;
                    let target_normalized = normalize_path(&target);
                    match entries.get(&target_normalized) {
                        Some(Node::File {
                            mode,
                            data,
                            meta,
                            xattrs: target_xattrs,
                        }) => Node::File {
                            mode: *mode,
                            data: data.clone(),
                            meta: *meta,
                            // The TARGET's, deliberately — see the arm's comment above. `xattrs`
                            // (this member's own) is dropped here under both policies.
                            xattrs: target_xattrs.clone(),
                        },
                        Some(_) => {
                            return Err(crate::error::Error::Artifact(format!(
                                "hardlink {} -> {} target is not a regular file",
                                path.display(),
                                target.display()
                            )));
                        }
                        None => {
                            return Err(crate::error::Error::Artifact(format!(
                                "hardlink {} -> {} target not found in the merged tree",
                                path.display(),
                                target.display()
                            )));
                        }
                    }
                }
                // A pax GLOBAL header (`g`) carries archive-wide records and names no
                // filesystem object, so skipping it drops nothing. It is the one member type
                // `tar`'s reader hands us unconsumed on a well-formed archive (the per-member
                // `x`/`L`/`K` headers are folded into the member that follows), and real
                // registry layers do carry one.
                tar::EntryType::XGlobalHeader => continue,
                // Every other type is REJECTED, never dropped (AGENTS.md "every accepted input
                // is honored or rejected"; the same fail-loud law as `check_layer_media_type`
                // one level up). The old `_ => continue` left the member out of the packed
                // rootfs, which then boots as if complete — silent corruption. Reaching here
                // means one of:
                //   * `x`/`L`/`K` surfacing at all: `tar` could not fold the header into the
                //     following member (its magic is neither ustar nor GNU), so that member may
                //     keep a TRUNCATED 100-byte path — a mis-named file, not just a missing one;
                //   * `7` (contiguous) or `S` (GNU sparse): real file content this packer has
                //     no node for;
                //   * an unknown type byte: a format this packer has never seen.
                other => {
                    return Err(crate::error::Error::Artifact(format!(
                        "unsupported tar entry type {other:?} (type byte {:?}) for {}: this \
                         packer has no node for it and dropping it would pack an incomplete \
                         rootfs that boots as if complete",
                        char::from(other.as_byte()),
                        path.display()
                    )));
                }
            };

            let file_name = path.file_name().unwrap_or_default().to_string_lossy();
            if let Some(target_name) = file_name.strip_prefix(".wh.") {
                if file_name == ".wh..wh..opq" {
                    // Accepted assumption (recorded): the opaque marker clears the
                    // parent subtree's contents in the single flat merged map at the
                    // moment it is processed, NOT per-layer. This assumes the producer
                    // emits `.wh..wh..opq` as the directory's FIRST entry in a layer; a
                    // same-layer child written before the marker in tar order would
                    // also be cleared. vmcell's first-party sources (OCI merge,
                    // mmdebstrap) satisfy this. Pinned by
                    // `tests::test_opaque_marker_ordering_contract`; per-layer whiteout
                    // application is forward work.
                    let parent = path.parent().unwrap_or(Path::new(""));
                    let parent_normalized = normalize_path(parent);
                    entries.retain(|k, _| {
                        !k.starts_with(&parent_normalized) || k == &parent_normalized
                    });
                } else {
                    let target_path = path.parent().unwrap_or(Path::new("")).join(target_name);
                    let target_normalized = normalize_path(&target_path);
                    entries.retain(|k, _| !k.starts_with(&target_normalized));
                }
                continue;
            }

            let normalized_path = normalize_path(&path);
            entries.insert(normalized_path, node);
        }
    }

    // The downstream extra files (design §4.2, delta 6) land FIRST in the tail: after the
    // layer merge (so they win base-image content and `.wh.` whiteouts — deliberate
    // composition) but before vmcell's own injections below, which stay authoritative.
    for extra in extra_files {
        insert_injected_file(&mut entries, extra)?;
    }

    // Inject the steward/CA/guest-tools AFTER every layer is merged (H-ART-3 / design §4.2,
    // Rootfs sources and the one packer: "inject ... then stream the tree"). Injecting last
    // makes the injected files
    // authoritative: an upper layer's content or a `.wh.` whiteout can no longer clobber the
    // baked steward or the CA under `usr/local/share/ca-certificates/`.
    //
    // Within that tail every dest is claimed EXACTLY ONCE (`claim_injection_dest`): the applet
    // roster is registry data since v33 delta 6, so a roster entry naming the multicall binary's
    // own file name used to overwrite the binary with a self-symlink here, silently.
    let mut claimed: HashMap<PathBuf, InjectionKind> = HashMap::new();
    for injected in injected_files {
        claim_injection_dest(&mut claimed, injected.0, InjectionKind::File)?;
        insert_injected_file(&mut entries, injected)?;
    }
    for (dest_path, target) in injected_symlinks {
        claim_injection_dest(&mut claimed, dest_path, InjectionKind::Symlink)?;
        let node = Node::Symlink {
            mode: 0o777 | fs_erofs::inode::S_IFLNK,
            target: target.to_string(),
            meta: NodeMeta {
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
            },
            // NOT a policy site (§4.7, invariant F5): an applet symlink is vmcell's own,
            // synthesized from the handler roster rather than read from a source layer, so it has
            // no source xattrs to preserve and a consumer's declaration may not give it any.
            xattrs: vec![],
        };
        entries.insert(normalize_path(Path::new(dest_path)), node);
    }

    Ok(entries)
}

/// Fuzz-only entry point onto `build_node_map`: the merged-tree KEYS an OCI layer set produces,
/// without the EROFS pack (non-default `fuzzing` feature; see the feature's stanza in `Cargo.toml`).
///
/// [`tar_to_erofs`] returns the packed image bytes, so the path set a registry-authored archive
/// folds into is not observable through it — and the path set is where the confinement property
/// lives (every key relative, non-empty, and free of `..`, since `normalize_path` POPS a parent
/// component rather than escaping with it). Returns the keys only; the `Node` values stay private.
///
/// `xattr_policy` is the artifact's [`XattrPolicy`]: `Preserve` additionally drives the PAX
/// `SCHILY.xattr.*` decode, which is a parse surface fed by the same registry-authored bytes and
/// is unreachable under the default `Strip`.
///
/// # Errors
/// Propagates `build_node_map`'s error for an unreadable or unsupported archive member.
#[cfg(all(feature = "fuzzing", feature = "am-fs-erofs"))]
pub fn fuzz_node_paths<'a, R: Read + 'a>(
    archives: impl IntoIterator<Item = tar::Archive<R>>,
    xattr_policy: XattrPolicy,
) -> crate::error::Result<Vec<PathBuf>> {
    Ok(
        build_node_map(archives, vec![], vec![], vec![], xattr_policy)?
            .into_keys()
            .collect(),
    )
}

/// Converts a tar archive to an EROFS filesystem image.
///
/// `extra_files` are the downstream [`ExtraFile`](crate::artifact::rootfs::ExtraFile)s and are
/// inserted after the layer merge but before `injected_files` (design §4.2, invariant F5), so
/// they win base-image collisions and whiteouts while vmcell's own injections stay
/// authoritative. Missing parent directories of any entry — including an extra file placed
/// under a directory the base image does not ship — are synthesized `0o755 root:root` below.
///
/// `xattr_policy` is the artifact's [`XattrPolicy`] (§4.7): the tar-derived nodes keep their
/// source `SCHILY.xattr.*` records under `Preserve` and none under `Strip` (the default).
/// vmcell's own injected and synthesized nodes carry none either way (invariant F5).
///
/// # Errors
/// Returns an error if reading the archive or generating the EROFS image fails, or if two entries
/// of vmcell's own injection manifest claim one dest (`claim_injection_dest`) — an applet roster
/// naming the multicall binary's file name is refused rather than packed as a self-symlink.
#[cfg(feature = "am-fs-erofs")]
pub fn tar_to_erofs<'a, R: Read + 'a>(
    archives: impl IntoIterator<Item = tar::Archive<R>>,
    extra_files: Vec<InjectedFile<'_>>,
    injected_files: Vec<InjectedFile<'_>>,
    injected_symlinks: Vec<(&str, &str)>,
    require_libc6: bool,
    xattr_policy: XattrPolicy,
) -> crate::error::Result<Vec<u8>> {
    nodes_to_erofs(merged_node_map(
        archives,
        extra_files,
        injected_files,
        injected_symlinks,
        require_libc6,
        xattr_policy,
    )?)
}

/// Serializes the **merged tree** — the very same one [`tar_to_erofs`] packs — back to a tar
/// archive, which is what §4.7's ext4 producer consumes (`mkfs.ext4 -d <tarball>`, §18 delta 8).
///
/// This is what makes §4.7's *"consuming the same merged-tar tail (injections, `libc6` scan, xattr
/// policy, reserved-path law all inherited for free — obligation 3 of §4.3)"* **true** rather than
/// aspirational. There is no merged tar anywhere upstream of here — the default OCI source hands
/// the tail N un-merged per-layer streams and the merge lands directly in a node map — so the tar
/// §4.7 names is *emitted here*, downstream of the one merge, and inherits every one of those
/// properties by construction rather than by a second implementation of them.
///
/// **Parents are present**, and that is the property the ext4 route needs most:
/// the one merge synthesizes every missing parent, and this emitter walks the paths in
/// ascending order so a parent always precedes its children. `mkfs.ext4 -d` performs **no** implicit
/// directory synthesis — it errors loud naming the missing directory — so the guarantee has to
/// arrive in the tar, not merely in the packer. Pinned by
/// `merged_tar_carries_synthesized_parents`.
///
/// **Two documented losses**, both inherited from the merge rather than introduced here:
///
/// * **hardlinks are materialized**. `build_node_map`'s `Link` arm copies the target's content
///   (H-ART-2 — a dropped hardlink loses `usr/bin/perl5.NN`), so a source inode with N links
///   emits N regular files here and the packed image's `st_nlink` is 1 where the base had N. The
///   content, mode, ownership and xattrs are the target's, so every path still reads correctly;
///   only the link *count* differs. Recorded, not silently absorbed.
/// * **the root's own entry is not emitted**. `mkfs.ext4` creates inode 2 itself and the merged
///   root is synthesized `0o755 root:root` anyway, so emitting a `./` member would only invite a
///   permissions disagreement between the two producers.
///
/// # Errors
/// [`crate::error::Error::Artifact`] on the same inputs [`tar_to_erofs`] rejects, plus a node
/// variant this emitter has no tar entry type for (the erofs writer's chunked/compressed file
/// shapes, which the merge never produces) — rejected, never dropped.
#[cfg(feature = "am-fs-erofs")]
pub fn merge_to_tar<'a, R: Read + 'a>(
    archives: impl IntoIterator<Item = tar::Archive<R>>,
    extra_files: Vec<InjectedFile<'_>>,
    injected_files: Vec<InjectedFile<'_>>,
    injected_symlinks: Vec<(&str, &str)>,
    require_libc6: bool,
    xattr_policy: XattrPolicy,
) -> crate::error::Result<Vec<u8>> {
    nodes_to_tar(&merged_node_map(
        archives,
        extra_files,
        injected_files,
        injected_symlinks,
        require_libc6,
        xattr_policy,
    )?)
}

/// **The one merge**: layers merged, extras and vmcell's injections inserted, the `libc6` scan run,
/// every missing parent and the root synthesized — the complete flat `path -> Node` map both
/// emitters consume.
///
/// Extracted from `tar_to_erofs` by §18 delta 8 so the ext4 producer consumes the *same* merged
/// tree rather than a second implementation of it. Everything §4.7 promises the ext4 route inherits
/// "for free" — the injections, the `libc6` scan, the [`XattrPolicy`], the F5 reserved-path law,
/// the parent synthesis — is inherited because it happens here, once, above the format choice.
///
/// # Errors
/// As [`tar_to_erofs`].
#[cfg(feature = "am-fs-erofs")]
fn merged_node_map<'a, R: Read + 'a>(
    archives: impl IntoIterator<Item = tar::Archive<R>>,
    extra_files: Vec<InjectedFile<'_>>,
    injected_files: Vec<InjectedFile<'_>>,
    injected_symlinks: Vec<(&str, &str)>,
    require_libc6: bool,
    xattr_policy: XattrPolicy,
) -> crate::error::Result<HashMap<PathBuf, Node>> {
    let mut entries = build_node_map(
        archives,
        extra_files,
        injected_files,
        injected_symlinks,
        xattr_policy,
    )?;

    // Fail loud on a base image without glibc (§4.2, Rootfs sources and the one packer / oci2erofs §8.2). One pass over the
    // merged path set for a file named `libc.so.6` at ANY path in the tree (the scan keys
    // on the file NAME, not on a `lib*`-parent-dir restriction — so lib64, lib/<triple>,
    // usr/lib, or any other location all satisfy it).
    // The default steward is built `-C target-feature=+crt-static` (steward stage),
    // so it does not itself need libc6 — but the guest-tools helper and every user `exec`
    // workload in the Debian rootfs do (L-ART-8). The static-musl steward path
    // (`--steward-musl`) also drops the guard (`require_libc6 = false`). This is a hard stop,
    // never a silent pack of a base that cannot run guest-tools / user workloads.
    if require_libc6
        && !entries
            .keys()
            .any(|p| p.file_name().is_some_and(|n| n == "libc.so.6"))
    {
        return Err(crate::error::Error::Artifact(
            "base image is missing libc6 (no `libc.so.6` found): the default steward is \
             statically linked and does not need it, but the guest-tools helper and user exec \
             workloads do. Use a base that includes libc6, or supply a static-musl steward with \
             `--steward-musl`."
                .to_string(),
        ));
    }

    // Ensure all parent directories exist
    let paths: Vec<PathBuf> = entries.keys().cloned().collect();
    for path in paths {
        let mut parent: Option<&Path> = path.parent();
        while let Some(p) = parent {
            if p.as_os_str().is_empty() || p.to_string_lossy() == "." || p.to_string_lossy() == "/"
            {
                break;
            }
            if !entries.contains_key(p) {
                entries.insert(
                    p.to_path_buf(),
                    Node::Dir {
                        mode: 0o755 | fs_erofs::inode::S_IFDIR,
                        entries: BTreeMap::new(),
                        meta: NodeMeta {
                            uid: 0,
                            gid: 0,
                            mtime: 0,
                            mtime_nsec: 0,
                        },
                        // NOT a policy site (§4.7, invariant F5): a SYNTHESIZED parent has no
                        // source entry at all — no layer described it — so there is nothing to
                        // preserve, and inventing attributes for it would be fabrication.
                        xattrs: vec![],
                    },
                );
            }
            parent = p.parent();
        }
    }

    // Add root if missing
    if !entries.contains_key(Path::new("")) {
        entries.insert(
            PathBuf::from(""),
            Node::Dir {
                mode: 0o755 | fs_erofs::inode::S_IFDIR,
                entries: BTreeMap::new(),
                meta: NodeMeta {
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                    mtime_nsec: 0,
                },
                // NOT a policy site (§4.7, invariant F5): the synthesized root, same reason as
                // the synthesized parents above. A base that ships its own `./` entry takes the
                // tar-derived `Directory` arm instead and DOES get its xattrs under `Preserve`.
                xattrs: vec![],
            },
        );
    }

    Ok(entries)
}

/// Nests the merged flat map into the single root [`Node`] and packs it as EROFS — the erofs half
/// of the format choice (§18 delta 8), unchanged in behavior from the pre-delta-8 tail.
///
/// # Errors
/// [`crate::error::Error::Artifact`] when a child's parent path is occupied by a non-directory node
/// (a malformed layer stack, L-ART-6), or when the EROFS writer fails.
#[cfg(feature = "am-fs-erofs")]
fn nodes_to_erofs(mut entries: HashMap<PathBuf, Node>) -> crate::error::Result<Vec<u8>> {
    let mut paths_sorted: Vec<PathBuf> = entries.keys().cloned().collect();
    paths_sorted.sort_by_key(|p: &PathBuf| std::cmp::Reverse(p.components().count()));

    for path in paths_sorted {
        if path.as_os_str().is_empty() {
            continue;
        }
        let node = entries
            .remove(&path)
            .ok_or_else(|| crate::error::Error::Artifact("Missing node".into()))?;
        let parent_path = path
            .parent()
            .ok_or_else(|| crate::error::Error::Artifact("No parent".into()))?;
        let name = path
            .file_name()
            .ok_or_else(|| crate::error::Error::Artifact("No filename".into()))?
            .to_string_lossy()
            .into_owned();
        if let Some(Node::Dir {
            entries: dir_entries,
            ..
        }) = entries.get_mut(parent_path)
        {
            dir_entries.insert(name, node);
        } else {
            // A child whose parent path is occupied by a NON-directory node (e.g. a layer
            // left `a/b` a regular file while another entry provides `a/b/c`) must fail loud,
            // never be silently dropped (L-ART-6) — a malformed layer stack is an error like
            // the media-type check, not a quietly-incomplete tree.
            return Err(crate::error::Error::Artifact(format!(
                "cannot add child {} under non-directory node {}",
                name,
                parent_path.display()
            )));
        }
    }

    let root_node = entries
        .remove(Path::new(""))
        .ok_or_else(|| crate::error::Error::Artifact("Missing root".into()))?;
    let image = build_image(root_node, 12)
        .map_err(|e: fs_erofs::error::Error| crate::error::Error::Artifact(e.to_string()))?;

    Ok(image)
}

/// The permission bits of a node's `mode`, with the `S_IF*` type bits masked off.
///
/// The merged nodes carry a full `st_mode`; a tar header's `mode` field is permission bits only and
/// the entry TYPE is a separate field, so writing the whole `st_mode` would hand `mkfs.ext4` a
/// mode like `0o100755` and produce a file with setuid/setgid/sticky bits nobody asked for.
#[cfg(feature = "am-fs-erofs")]
const fn permission_bits(mode: u16) -> u32 {
    (mode & 0o7777) as u32
}

/// Writes one merged [`Node`]'s extended attributes as PAX `SCHILY.xattr.*` records ahead of its
/// member, honoring what the merge already decided.
///
/// The **inverse** of `xattr_spec`, and it goes through `fs_erofs::xattr::resolve_full_name` — the
/// packer crate's own reconstruction — rather than re-spelling the namespace table, so the two
/// directions cannot drift into two answers about what `(name_index, name)` means. Nothing is
/// emitted for a node with no attributes: an empty `x` header per member would bloat every image
/// and libarchive treats an absent one and an empty one identically anyway.
///
/// `SCHILY.xattr.*` is the shape `mkfs.ext4 -d` reads (verified on e2fsprogs 1.47.2:
/// `security.capability` round-trips byte-exact through `debugfs ea_get`), and it is the shape the
/// decode side already accepts, so an ext4 artifact and an erofs artifact packed from one tree
/// carry one attribute set.
///
/// # Errors
/// [`crate::error::Error::Artifact`] when an attribute name is not UTF-8 (a `&str` is what the tar
/// crate's PAX writer takes) or when the record cannot be written.
#[cfg(feature = "am-fs-erofs")]
fn write_node_xattrs<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    path: &Path,
    xattrs: &[fs_erofs::mkfs::XattrSpec],
) -> crate::error::Result<()> {
    if xattrs.is_empty() {
        return Ok(());
    }
    let mut records: Vec<(String, Vec<u8>)> = Vec::with_capacity(xattrs.len());
    for spec in xattrs {
        let full = fs_erofs::xattr::resolve_full_name(spec.name_index, &spec.name);
        let full = String::from_utf8(full).map_err(|e| {
            crate::error::Error::Artifact(format!(
                "extended attribute on {} has a non-UTF-8 name: {e}",
                path.display()
            ))
        })?;
        records.push((format!("{PAX_SCHILY_XATTR}{full}"), spec.value.clone()));
    }
    builder
        .append_pax_extensions(
            records
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_slice()))
                .collect::<Vec<_>>(),
        )
        .map_err(|e| {
            crate::error::Error::Artifact(format!(
                "cannot write extended attributes for {}: {e}",
                path.display()
            ))
        })
}

/// Serializes the merged flat map as a tar archive — the tar half of the format choice
/// (§18 delta 8). See [`merge_to_tar`] for the contract, the parent guarantee and the two
/// documented losses.
///
/// # Errors
/// [`crate::error::Error::Artifact`] when a node variant has no tar entry type, when an attribute
/// name is not UTF-8, or when the archive cannot be written.
#[cfg(feature = "am-fs-erofs")]
fn nodes_to_tar(entries: &HashMap<PathBuf, Node>) -> crate::error::Result<Vec<u8>> {
    // ASCENDING path order, which is exactly the parents-before-children order `mkfs.ext4 -d`
    // requires: a parent path is a strict component-wise prefix of each of its children, and
    // `PathBuf`'s ordering is component-wise, so `usr` < `usr/bin` < `usr/bin/sh` always. It is
    // also what makes the emitted bytes a function of the tree alone — a `HashMap` iteration order
    // would make the tar, and therefore the ext4 image, differ run to run.
    let mut paths: Vec<&PathBuf> = entries.keys().collect();
    paths.sort();

    let mut out = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut out);
        // Deterministic emission needs the members' own bytes to be a function of the tree, and a
        // GNU header carries a per-member `atime`/`ctime` the ustar one does not. The tar crate's
        // ustar path additionally splits a long path across `prefix`+`name`, and `set_path` falls
        // back to a PAX `path=` record — both deterministic. Verified against e2fsprogs 1.47.2 with
        // a 115-character member path.
        for path in paths {
            // The synthesized root: `mkfs.ext4` owns inode 2 and creates it itself.
            if path.as_os_str().is_empty() {
                continue;
            }
            let node = entries.get(path).ok_or_else(|| {
                crate::error::Error::Artifact(format!("missing merged node {}", path.display()))
            })?;
            let (mode, meta, xattrs) = match node {
                Node::File {
                    mode, meta, xattrs, ..
                }
                | Node::Dir {
                    mode, meta, xattrs, ..
                }
                | Node::Symlink {
                    mode, meta, xattrs, ..
                }
                | Node::Device {
                    mode, meta, xattrs, ..
                }
                | Node::Special {
                    mode, meta, xattrs, ..
                } => (*mode, *meta, xattrs.as_slice()),
                // The erofs writer's chunked/compressed file shapes. `build_node_map` produces
                // neither, so reaching here means the merge grew a variant this emitter was not
                // taught — REJECTED, never dropped, on the same law the tar-entry decode rejects an
                // unknown member type: a dropped node packs a rootfs that boots as if complete.
                other => {
                    return Err(crate::error::Error::Artifact(format!(
                        "merged node {} has a shape the tar emitter has no entry type for \
                         ({other:?}); dropping it would pack an incomplete rootfs that boots as \
                         if complete",
                        path.display()
                    )));
                }
            };
            write_node_xattrs(&mut builder, path, xattrs)?;
            let mut header = tar::Header::new_ustar();
            header.set_mode(permission_bits(mode));
            header.set_uid(u64::from(meta.uid));
            header.set_gid(u64::from(meta.gid));
            header.set_mtime(meta.mtime);
            header.set_size(0);
            let write = |builder: &mut tar::Builder<&mut Vec<u8>>,
                         header: &mut tar::Header,
                         data: &[u8]|
             -> crate::error::Result<()> {
                header.set_size(data.len() as u64);
                builder.append_data(header, path, data).map_err(|e| {
                    crate::error::Error::Artifact(format!(
                        "cannot write tar member {}: {e}",
                        path.display()
                    ))
                })
            };
            match node {
                Node::File { data, .. } => {
                    header.set_entry_type(tar::EntryType::Regular);
                    write(&mut builder, &mut header, data)?;
                }
                Node::Dir { .. } => {
                    header.set_entry_type(tar::EntryType::Directory);
                    write(&mut builder, &mut header, &[])?;
                }
                Node::Symlink { target, .. } => {
                    header.set_entry_type(tar::EntryType::Symlink);
                    // Through the header's own setter (which PAX-escapes an over-long target)
                    // rather than `append_link`, so the mode/uid/gid/mtime set above survive.
                    header.set_link_name(target).map_err(|e| {
                        crate::error::Error::Artifact(format!(
                            "cannot write symlink target for {}: {e}",
                            path.display()
                        ))
                    })?;
                    write(&mut builder, &mut header, &[])?;
                }
                Node::Device { mode, rdev, .. } => {
                    header.set_entry_type(
                        if mode & fs_erofs::inode::S_IFMT == fs_erofs::inode::S_IFBLK {
                            tar::EntryType::Block
                        } else {
                            tar::EntryType::Char
                        },
                    );
                    // The inverse of the decode's `libc::makedev`, through `libc`'s own accessors
                    // rather than a shift/mask reimplementation — the encoding is NOT
                    // `(major << 8) | minor` and hand-rolling it is the exact defect the decode
                    // arm's comment records. Both are safe `const fn`s: they take the device
                    // number by value and touch no pointer.
                    let dev = libc::dev_t::from(*rdev);
                    let major = libc::major(dev);
                    let minor = libc::minor(dev);
                    header.set_device_major(major).map_err(|e| {
                        crate::error::Error::Artifact(format!(
                            "cannot write device major for {}: {e}",
                            path.display()
                        ))
                    })?;
                    header.set_device_minor(minor).map_err(|e| {
                        crate::error::Error::Artifact(format!(
                            "cannot write device minor for {}: {e}",
                            path.display()
                        ))
                    })?;
                    write(&mut builder, &mut header, &[])?;
                }
                Node::Special { .. } => {
                    // `Node::Special` is S_IFIFO or S_IFSOCK; `build_node_map` only ever produces
                    // it from a tar `Fifo`, and tar has no socket member type at all, so FIFO is
                    // the only reading.
                    header.set_entry_type(tar::EntryType::Fifo);
                    write(&mut builder, &mut header, &[])?;
                }
                // Unreachable: the `match` above already rejected every other shape.
                other => {
                    return Err(crate::error::Error::Artifact(format!(
                        "merged node {} has a shape the tar emitter has no entry type for \
                         ({other:?})",
                        path.display()
                    )));
                }
            }
        }
        builder.finish().map_err(|e| {
            crate::error::Error::Artifact(format!("cannot finish the merged tar: {e}"))
        })?;
    }
    Ok(out)
}

/// Mode for an injected file, keyed on its destination path: injected BINARIES are
/// executable (`0o755`), every other injected file — notably the deployment CA cert under
/// `ca-certificates/` — is non-executable data (`0o644`). The executable destinations are a
/// `bin`/`sbin` component (the steward lands in `usr/sbin`) OR the `vmcell-tools` dir that
/// holds the guest-tools multicall (`ip`/`curl`/`kvm-ok`, exec'd off PATH via the symlinks the
/// steward prepends). `vmcell-tools` MUST be in this set: guest-tools moved out of `usr/bin` to
/// the dedicated `/vmcell-tools` dir, and a `bin`/`sbin`-only predicate silently packed it
/// `0o644` → `EACCES` on every `ip`/`curl`/`kvm-ok` exec. That stayed invisible while the rootfs
/// was a warm-cache artifact (CI reuses the cached image); only a fresh pack reddens, so the
/// unit gate `injected_guest_tools_binary_is_executable` pins the mode KVM-free.
#[cfg(feature = "am-fs-erofs")]
fn injected_file_mode(dest_path: &str) -> u16 {
    let is_bin = Path::new(dest_path).components().any(|c| {
        matches!(
            c.as_os_str().to_str(),
            Some("bin" | "sbin" | "vmcell-tools")
        )
    });
    if is_bin { 0o755 } else { 0o644 }
}

/// Folds a tar/injection path into the flat merged-tree key: root and `.` components are
/// dropped, `..` pops. `pub(crate)` so the pack tail's reserved-dest check
/// ([`is_reserved_injection_path`](crate::artifact::rootfs::is_reserved_injection_path))
/// compares against the SAME normal form the packer keys on — a second normalizer there would
/// let `/usr/sbin/./vmcell-steward` sail past the check and then silently lose to the
/// vmcell injection (one law, one predicate).
#[cfg(feature = "am-fs-erofs")]
pub(crate) fn normalize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::Normal(c) => out.push(c),
            std::path::Component::ParentDir => {
                out.pop();
            }
            _ => {}
        }
    }
    out
}

#[cfg(all(test, feature = "am-fs-erofs"))]
mod tests {
    use super::*;

    #[test]
    fn test_tar_to_erofs_empty() {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            builder.finish().unwrap();
        }

        let reader = std::io::Cursor::new(tar_data);
        let archive = tar::Archive::new(reader);
        // require_libc6=false: this packs an empty tar (no steward injected), so the
        // glibc-presence requirement does not apply.
        let image = tar_to_erofs(
            vec![archive],
            vec![],
            vec![],
            vec![],
            false,
            XattrPolicy::Strip,
        );
        assert!(
            image.is_ok(),
            "Failed to convert empty tar to EROFS: {:?}",
            image.err()
        );
        let bytes = image.unwrap();
        assert!(!bytes.is_empty(), "EROFS image bytes should not be empty");
    }

    // Builds a single-file tar at `path` and converts it with `require_libc6`.
    fn pack_one(path: &str, require_libc6: bool) -> crate::error::Result<Vec<u8>> {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let body = b"x";
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, &body[..]).unwrap();
            builder.finish().unwrap();
        }
        let archive = tar::Archive::new(std::io::Cursor::new(tar_data));
        tar_to_erofs(
            vec![archive],
            vec![],
            vec![],
            vec![],
            require_libc6,
            XattrPolicy::Strip,
        )
    }

    // oci2erofs §8.2 fail-loud guard. With `require_libc6=true`, a base that contains a
    // `libc.so.6` packs; a base that LACKS it must error (the default glibc steward would
    // die at PID 1). The inverse — silently packing a libc6-less base — goes red here.
    #[test]
    fn test_require_libc6_rejects_base_without_glibc() {
        // A base WITH glibc (any `lib*/.../libc.so.6`) packs.
        assert!(
            pack_one("lib/x86_64-linux-gnu/libc.so.6", true).is_ok(),
            "a base containing libc.so.6 must pack with require_libc6"
        );
        // A base WITHOUT glibc must be a hard error under require_libc6.
        let err = pack_one("usr/bin/coreutils", true)
            .expect_err("a libc6-less base must be rejected when require_libc6");
        assert!(
            matches!(err, crate::error::Error::Artifact(_)),
            "missing libc6 must be Error::Artifact, got {err:?}"
        );
        // The same libc6-less base packs fine when libc6 is NOT required (the
        // --steward-musl path, which injects a static steward needing no glibc).
        assert!(
            pack_one("usr/bin/coreutils", false).is_ok(),
            "a libc6-less base must pack when require_libc6=false (static-musl steward)"
        );
    }

    // The injected guest-tools multicall (`vmcell-tools/vmcell-guest-tools`, the target of the
    // `ip`/`curl`/`kvm-ok` symlinks the steward puts on PATH) MUST be packed executable (0o755) —
    // it is exec'd, not read. `injected_file_mode` keys on the dest path, and guest-tools moved
    // out of `usr/bin` to `/vmcell-tools`; a `bin`/`sbin`-only predicate packs it 0o644 → EACCES
    // on every `ip`/`curl`/`kvm-ok`, which stayed invisible behind the warm rootfs cache (only a
    // fresh pack reddens the integration suite). This KVM-free unit gate reddens on that
    // regression: dropping `vmcell-tools` from the executable set flips the first assert to 0o644.
    // The paths mirror the injection sites in `artifact::rootfs::mod` (guest-tools + steward)
    // and `artifact::rootfs::oci` (the CA cert).
    #[test]
    fn injected_guest_tools_binary_is_executable() {
        // Executable injected binaries.
        assert_eq!(
            injected_file_mode("vmcell-tools/vmcell-guest-tools"),
            0o755,
            "the guest-tools multicall must be executable; `ip`/`curl`/`kvm-ok` exec it off PATH"
        );
        assert_eq!(
            injected_file_mode("usr/sbin/vmcell-steward"),
            0o755,
            "the steward (PID 1) must be executable"
        );
        // Non-executable injected DATA: the deployment CA cert.
        assert_eq!(
            injected_file_mode("usr/local/share/ca-certificates/vmcell-proxy-ca.pem"),
            0o644,
            "the injected CA cert is data, not a binary"
        );
    }

    // ART-4: a Char/Block device node's `rdev` must be encoded with `libc::makedev`, not a
    // naive `(major<<8)|minor`. With `minor >= 256` the two formulas DIVERGE, so swapping
    // `makedev` for the shift reddens the `assert_eq!` against the makedev value.
    #[test]
    fn test_device_node_rdev_uses_makedev() {
        use fs_erofs::inode::{S_IFBLK, S_IFCHR, S_IFMT};
        use fs_erofs::mkfs::Node;

        // minor 300 (> 255) is what makes makedev(4,300) != (4<<8)|300.
        let (major, minor) = (4u32, 300u32);
        let expected = libc::makedev(major as libc::c_uint, minor as libc::c_uint) as u32;
        let naive = (major << 8) | minor;
        assert_ne!(
            expected, naive,
            "test needs minor>=256 so makedev diverges from the naive shift"
        );

        let mut tar = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar);
            for (et, path) in [
                (tar::EntryType::Char, "dev/mychar"),
                (tar::EntryType::Block, "dev/myblock"),
            ] {
                let mut h = tar::Header::new_gnu();
                h.set_entry_type(et);
                h.set_size(0);
                h.set_mode(0o600);
                h.set_device_major(major).unwrap();
                h.set_device_minor(minor).unwrap();
                h.set_path(path).unwrap();
                h.set_cksum();
                b.append(&h, std::io::empty()).unwrap();
            }
            b.finish().unwrap();
        }
        let archive = tar::Archive::new(std::io::Cursor::new(tar));
        let map = build_node_map(vec![archive], vec![], vec![], vec![], XattrPolicy::Strip)
            .expect("node map");

        match map.get(Path::new("dev/mychar")) {
            Some(Node::Device { rdev, mode, .. }) => {
                assert_eq!(
                    *rdev, expected,
                    "char device rdev must be makedev-encoded (ART-4)"
                );
                assert_eq!(mode & S_IFMT, S_IFCHR, "char device must carry S_IFCHR");
            }
            other => panic!("expected a char device node, got {other:?}"),
        }
        match map.get(Path::new("dev/myblock")) {
            Some(Node::Device { rdev, mode, .. }) => {
                assert_eq!(
                    *rdev, expected,
                    "block device rdev must be makedev-encoded (ART-4)"
                );
                assert_eq!(mode & S_IFMT, S_IFBLK, "block device must carry S_IFBLK");
            }
            other => panic!("expected a block device node, got {other:?}"),
        }
    }

    // ART-4: OCI whiteouts. A `.wh.<name>` entry in a later layer deletes the shadowed path
    // from earlier layers; `.wh..wh..opq` clears a directory's children but keeps the dir.
    // A build that ignored whiteouts would keep `etc/gone` / `opaquedir/child` → red here.
    #[test]
    fn test_whiteout_deletes_shadowed_paths() {
        // Lower layer: two files, plus an opaque dir with a child.
        let mut lower = Vec::new();
        {
            let mut b = tar::Builder::new(&mut lower);
            for (path, body) in [
                ("etc/keep", &b"k"[..]),
                ("etc/gone", &b"g"[..]),
                ("opaquedir/child", &b"c"[..]),
            ] {
                let mut h = tar::Header::new_gnu();
                h.set_size(body.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, path, body).unwrap();
            }
            let mut hd = tar::Header::new_gnu();
            hd.set_entry_type(tar::EntryType::Directory);
            hd.set_size(0);
            hd.set_mode(0o755);
            hd.set_path("opaquedir").unwrap();
            hd.set_cksum();
            b.append(&hd, std::io::empty()).unwrap();
            b.finish().unwrap();
        }
        // Upper layer: whiteout `etc/gone` and opaque-clear `opaquedir`.
        let mut upper = Vec::new();
        {
            let mut b = tar::Builder::new(&mut upper);
            for path in ["etc/.wh.gone", "opaquedir/.wh..wh..opq"] {
                let mut h = tar::Header::new_gnu();
                h.set_size(0);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, path, std::io::empty()).unwrap();
            }
            b.finish().unwrap();
        }
        let a1 = tar::Archive::new(std::io::Cursor::new(lower));
        let a2 = tar::Archive::new(std::io::Cursor::new(upper));
        let map = build_node_map(vec![a1, a2], vec![], vec![], vec![], XattrPolicy::Strip)
            .expect("node map");

        assert!(
            map.contains_key(Path::new("etc/keep")),
            "an unshadowed file must survive"
        );
        assert!(
            !map.contains_key(Path::new("etc/gone")),
            ".wh.gone must delete the shadowed etc/gone"
        );
        assert!(
            !map.contains_key(Path::new("opaquedir/child")),
            ".wh..wh..opq must clear the opaque dir's children"
        );
        assert!(
            map.contains_key(Path::new("opaquedir")),
            ".wh..wh..opq must keep the opaque dir itself"
        );
        // The whiteout markers themselves must never be materialized as files.
        assert!(!map.contains_key(Path::new("etc/.wh.gone")));
        assert!(!map.contains_key(Path::new("opaquedir/.wh..wh..opq")));
    }

    // Builds a single-file (regular) tar entry into `buf`.
    fn append_file(b: &mut tar::Builder<&mut Vec<u8>>, path: &str, body: &[u8]) {
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, path, body).unwrap();
    }

    // The injected CA cert is DATA, not an executable: it must be packed 0o644, while
    // injected binaries (steward/guest-tools under bin|sbin) stay 0o755. The buggy
    // blanket-0o755 marks the CA executable -> the `== 0o644` assertion reddens.
    #[test]
    fn test_injected_ca_is_not_executable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca = dir.path().join("ca.crt");
        std::fs::write(&ca, b"-----CA-----").unwrap();
        let steward = dir.path().join("steward");
        std::fs::write(&steward, b"STEWARD").unwrap();
        let empty = tar::Archive::new(std::io::Cursor::new({
            let mut v = Vec::new();
            tar::Builder::new(&mut v).finish().unwrap();
            v
        }));
        let injected = vec![
            (
                "usr/local/share/ca-certificates/vmcell-ca.crt",
                ca.as_path(),
                None,
            ),
            ("usr/sbin/vmcell-steward", steward.as_path(), None),
        ];
        let map = build_node_map(vec![empty], vec![], injected, vec![], XattrPolicy::Strip)
            .expect("node map");
        match map.get(&normalize_path(Path::new(
            "usr/local/share/ca-certificates/vmcell-ca.crt",
        ))) {
            Some(Node::File { mode, .. }) => assert_eq!(
                mode & 0o777,
                0o644,
                "the injected CA cert is data and must not be executable"
            ),
            other => panic!("expected the injected CA file node, got {other:?}"),
        }
        match map.get(&normalize_path(Path::new("usr/sbin/vmcell-steward"))) {
            Some(Node::File { mode, .. }) => assert_eq!(
                mode & 0o777,
                0o755,
                "the injected steward binary must stay executable"
            ),
            other => panic!("expected the injected steward file node, got {other:?}"),
        }
    }

    /// The one fixture the whole xattr battery packs: a single `usr/bin/ping` regular file
    /// carrying one PAX `SCHILY.xattr.security.capability` record.
    ///
    /// Shared by both policy legs deliberately — the SAME bytes must produce an empty xattr set
    /// under `Strip` and this exact attribute under `Preserve`, so a leg that quietly packed a
    /// different fixture could pass both ways.
    fn pax_xattr_fixture_tar() -> Vec<u8> {
        let mut tar = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar);
            // A realistic security.capability value payload (opaque bytes here).
            let caps: &[u8] = b"\x01\x00\x00\x02\x00\x20\x00\x00";
            b.append_pax_extensions([("SCHILY.xattr.security.capability", caps)])
                .unwrap();
            let body = b"binary";
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o755);
            h.set_cksum();
            b.append_data(&mut h, "usr/bin/ping", &body[..]).unwrap();
            b.finish().unwrap();
        }
        tar
    }

    /// The fixture's node, packed under `policy`.
    fn pax_fixture_node(policy: XattrPolicy) -> Node {
        let archive = tar::Archive::new(std::io::Cursor::new(pax_xattr_fixture_tar()));
        let mut map =
            build_node_map(vec![archive], vec![], vec![], vec![], policy).expect("node map");
        map.remove(&normalize_path(Path::new("usr/bin/ping")))
            .expect("the fixture's regular file node")
    }

    // The `Strip` leg of the §15.4 xattr battery (design §4.7, §18 delta 7). Formerly
    // `test_pax_xattrs_are_not_preserved`, when the drop was unconditional and a recorded
    // limitation; delta 7 made it the DEFAULT POLICY's behavior, so the name and the message move
    // with it. It is no longer waiting to be retired: it is what keeps the canonical artifact
    // byte-identical, and it must stay green forever.
    //
    // RED on the inverse: make `tar_entry_xattrs` read the records regardless of policy (drop its
    // `Strip` short-circuit).
    #[test]
    fn pax_xattrs_are_stripped_under_the_default_policy() {
        match pax_fixture_node(XattrPolicy::Strip) {
            Node::File { xattrs, .. } => assert!(
                xattrs.is_empty(),
                "`XattrPolicy::Strip` is the default and MUST drop every source xattr: the \
                 canonical artifact's bytes and cache key depend on it (§4.7). If this fails, a \
                 policy-blind read crept back into the tar arms"
            ),
            other => panic!("expected a regular file node, got {other:?}"),
        }
        // The default is `Strip`, not merely equal to it by coincidence — the migration claim
        // ("none by default") rests on this, so it is asserted rather than assumed.
        assert_eq!(XattrPolicy::default(), XattrPolicy::Strip);
    }

    // The `Preserve` twin: the SAME fixture's `security.capability` survives into the packed node,
    // with the EROFS namespace folded into `name_index` the way `mkfs.erofs` does.
    //
    // RED on the inverse: revert any tar arm to `xattrs: vec![]`, or drop the `security.` arm from
    // `xattr_spec` (the name_index assertion catches the second, which an `is_empty()`-style
    // assertion would not).
    #[test]
    fn pax_xattrs_are_preserved_under_the_preserve_policy() {
        match pax_fixture_node(XattrPolicy::Preserve) {
            Node::File { xattrs, .. } => {
                assert_eq!(
                    xattrs.len(),
                    1,
                    "the fixture carries exactly one SCHILY.xattr record; got {xattrs:?}"
                );
                let x = &xattrs[0];
                assert_eq!(
                    x.name_index,
                    fs_erofs::xattr::ns::SECURITY,
                    "`security.capability` must fold into the SECURITY namespace index, not be \
                     stored raw — a raw name reads back as `security.capability` only if the \
                     reader guesses"
                );
                assert_eq!(
                    x.name,
                    b"capability".to_vec(),
                    "the namespace-stripped suffix"
                );
                assert_eq!(
                    x.value,
                    b"\x01\x00\x00\x02\x00\x20\x00\x00".to_vec(),
                    "the value bytes travel verbatim, NUL bytes and all"
                );
                // The round trip through the reader's own composer, so the assertion is on what a
                // guest would actually see rather than on our own encoding of it.
                assert_eq!(
                    fs_erofs::xattr::resolve_full_name(x.name_index, &x.name),
                    b"security.capability".to_vec()
                );
            }
            other => panic!("expected a regular file node, got {other:?}"),
        }
    }

    // The registry token parse is STRICT (§10.5, law F1): both valid spellings round-trip through
    // `name()`, and anything else is a hard error that NAMES the offending token and both valid
    // ones. A silent fall back to the default would let `"presevre"` pack a stripped image while
    // the consumer's manifest claimed otherwise — the accept-then-ignore class.
    //
    // RED on the inverse: add `_ => Ok(XattrPolicy::Strip)` to `XattrPolicy::parse`.
    #[test]
    fn xattr_policy_parses_strictly() {
        for policy in [XattrPolicy::Strip, XattrPolicy::Preserve] {
            assert_eq!(
                XattrPolicy::parse(policy.name()).expect("round trip"),
                policy,
                "`name()` and `parse()` are one law: what one writes the other reads"
            );
        }
        for bad in ["", "Preserve", "presevre", "keep", "strip ", "true"] {
            let err = XattrPolicy::parse(bad).expect_err("must be rejected");
            let msg = err.to_string();
            assert!(msg.contains(bad), "the message must name `{bad}`: {msg}");
            assert!(
                msg.contains("strip") && msg.contains("preserve"),
                "the message must name BOTH valid spellings so the fix is in it: {msg}"
            );
        }
    }

    // The packed attribute order is CANONICAL, not the order a producer happened to write its PAX
    // records in: two tars carrying the same two attributes in opposite order must pack the same
    // inode bytes. Without it, re-tarring an unchanged base with a different tool would produce a
    // different image for the same content — a warm-cache miss and a bogus artifact diff.
    //
    // RED on the inverse: drop the `sort_by` at the tail of `tar_entry_xattrs`.
    #[test]
    fn xattr_order_is_canonicalized_not_producer_order() {
        let pack_with = |records: [(&str, &[u8]); 2]| {
            let mut tar = Vec::new();
            {
                let mut b = tar::Builder::new(&mut tar);
                b.append_pax_extensions(records).unwrap();
                append_file(&mut b, "f", b"x");
                b.finish().unwrap();
            }
            let map = build_node_map(
                vec![tar::Archive::new(std::io::Cursor::new(tar))],
                vec![],
                vec![],
                vec![],
                XattrPolicy::Preserve,
            )
            .expect("node map");
            match map.get(&normalize_path(Path::new("f"))) {
                Some(Node::File { xattrs, .. }) => xattrs
                    .iter()
                    .map(|x| (x.name_index, x.name.clone()))
                    .collect::<Vec<_>>(),
                other => panic!("expected a regular file node, got {other:?}"),
            }
        };
        let user = ("SCHILY.xattr.user.zeta", &b"z"[..]);
        let security = ("SCHILY.xattr.security.capability", &b"\x01\x00"[..]);
        let forward = pack_with([user, security]);
        let reverse = pack_with([security, user]);
        assert_eq!(forward.len(), 2, "both records must survive: {forward:?}");
        assert_eq!(
            forward, reverse,
            "the packed xattr order must be canonical (sorted by namespace index then name), not \
             the order the producer wrote the PAX records in"
        );
    }

    // The namespace table, unit-tested without building a tar. Each arm reddens a specific
    // mis-mapping: a missing `security.` arm stores the name raw (index 0), and a `split_once`
    // that kept the prefix would double it on read-back.
    #[test]
    fn xattr_spec_folds_every_known_namespace() {
        use fs_erofs::xattr::ns;
        for (full, index, suffix) in [
            ("security.capability", ns::SECURITY, &b"capability"[..]),
            ("user.acme", ns::USER, &b"acme"[..]),
            (
                "trusted.overlay.opaque",
                ns::TRUSTED,
                &b"overlay.opaque"[..],
            ),
            ("lustre.lov", ns::LUSTRE, &b"lov"[..]),
            ("system.posix_acl_access", ns::POSIX_ACL_ACCESS, &b""[..]),
            ("system.posix_acl_default", ns::POSIX_ACL_DEFAULT, &b""[..]),
            // No known prefix: stored RAW so `resolve_full_name` reads it back unchanged.
            ("wat", ns::RAW, &b"wat"[..]),
            ("system.other", ns::RAW, &b"system.other"[..]),
        ] {
            let spec = xattr_spec(full, b"v");
            assert_eq!(spec.name_index, index, "namespace index for {full}");
            assert_eq!(spec.name, suffix.to_vec(), "suffix for {full}");
            assert_eq!(
                fs_erofs::xattr::resolve_full_name(spec.name_index, &spec.name),
                full.as_bytes().to_vec(),
                "{full} must survive the fold/resolve round trip"
            );
        }
    }

    // Non-xattr PAX records (`path`, `mtime`, …) describe the member, not its attributes, and must
    // NOT become xattrs. RED on the inverse: drop the `SCHILY.xattr.` prefix filter in
    // `tar_entry_xattrs` — then `mtime` packs as an attribute named `mtime`.
    #[test]
    fn non_xattr_pax_records_are_not_attributes() {
        let mut tar = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar);
            b.append_pax_extensions([
                ("mtime", &b"1700000000"[..]),
                ("SCHILY.xattr.user.kept", &b"yes"[..]),
            ])
            .unwrap();
            let mut h = tar::Header::new_gnu();
            h.set_size(0);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "f", std::io::empty()).unwrap();
            b.finish().unwrap();
        }
        let map = build_node_map(
            vec![tar::Archive::new(std::io::Cursor::new(tar))],
            vec![],
            vec![],
            vec![],
            XattrPolicy::Preserve,
        )
        .expect("node map");
        match map.get(&normalize_path(Path::new("f"))) {
            Some(Node::File { xattrs, .. }) => {
                assert_eq!(xattrs.len(), 1, "only the SCHILY.xattr record: {xattrs:?}");
                assert_eq!(xattrs[0].name, b"kept".to_vec());
                assert_eq!(xattrs[0].name_index, fs_erofs::xattr::ns::USER);
            }
            other => panic!("expected a regular file node, got {other:?}"),
        }
    }

    // The ELEVENTH node-construction site (design §4.7 counts ten): a materialized hardlink keeps
    // the merged TARGET's xattrs and discards its own. xattrs are an inode property and a hardlink
    // IS the target's inode, so a link entry cannot legitimately carry a different set — the same
    // reason this arm already discards the link entry's `mode` and `meta`.
    //
    // The fixture makes the two answers DISTINGUISHABLE: the target carries `user.target` and the
    // link entry carries `user.link`, so a per-entry read (the plausible wrong implementation)
    // reddens instead of passing vacuously.
    #[test]
    fn hardlink_inherits_the_targets_xattrs() {
        let mut tar = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar);
            b.append_pax_extensions([("SCHILY.xattr.user.target", &b"t"[..])])
                .unwrap();
            let body = b"content";
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o755);
            h.set_cksum();
            b.append_data(&mut h, "usr/bin/perl", &body[..]).unwrap();

            b.append_pax_extensions([("SCHILY.xattr.user.link", &b"l"[..])])
                .unwrap();
            let mut lh = tar::Header::new_gnu();
            lh.set_size(0);
            lh.set_mode(0o755);
            lh.set_entry_type(tar::EntryType::Link);
            lh.set_link_name("usr/bin/perl").unwrap();
            lh.set_cksum();
            b.append_data(&mut lh, "usr/bin/perl5.36", std::io::empty())
                .unwrap();
            b.finish().unwrap();
        }
        let map = build_node_map(
            vec![tar::Archive::new(std::io::Cursor::new(tar))],
            vec![],
            vec![],
            vec![],
            XattrPolicy::Preserve,
        )
        .expect("node map");
        match map.get(&normalize_path(Path::new("usr/bin/perl5.36"))) {
            Some(Node::File { xattrs, .. }) => {
                assert_eq!(xattrs.len(), 1, "one inherited attribute: {xattrs:?}");
                assert_eq!(
                    xattrs[0].name,
                    b"target".to_vec(),
                    "a materialized hardlink carries the TARGET's xattrs (an inode property), \
                     never the link entry's own"
                );
            }
            other => panic!("expected the materialized hardlink file node, got {other:?}"),
        }
    }

    // vmcell's own injected and synthesized nodes carry NO xattrs under either policy (§4.7,
    // invariant F5): the injections are unconditional and authoritative, so a consumer's
    // declaration must not be able to add attributes to them. This is the call-site scan for the
    // four `vec![]` sites the policy is deliberately NOT threaded into — a unit test on
    // `tar_entry_xattrs` alone would never see them.
    //
    // RED on the inverse: thread `xattrs` into `insert_injected_file` or into either synthesized
    // `Node::Dir`.
    #[test]
    fn injected_and_synthesized_nodes_carry_no_xattrs_under_preserve() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("acme");
        std::fs::write(&src, b"x").unwrap();

        // The source layer carries an xattr on a DIRECTORY too, so a policy that leaked into the
        // synthesized-parent arm would have something to leak.
        let mut tar = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar);
            b.append_pax_extensions([("SCHILY.xattr.user.fromlayer", &b"v"[..])])
                .unwrap();
            let mut h = tar::Header::new_gnu();
            h.set_size(0);
            h.set_mode(0o755);
            h.set_entry_type(tar::EntryType::Directory);
            h.set_cksum();
            b.append_data(&mut h, "usr/", std::io::empty()).unwrap();
            b.finish().unwrap();
        }
        let map = build_node_map(
            vec![tar::Archive::new(std::io::Cursor::new(tar))],
            vec![("/opt/acme/probe", src.as_path(), Some(0o755))],
            vec![("/usr/sbin/vmcell-steward", src.as_path(), None)],
            vec![("/vmcell-tools/ip", "/vmcell-tools/vmcell-guest-tools")],
            XattrPolicy::Preserve,
        )
        .expect("node map");
        for dest in [
            "/opt/acme/probe",
            "/usr/sbin/vmcell-steward",
            "/vmcell-tools/ip",
        ] {
            let node = map
                .get(&normalize_path(Path::new(dest)))
                .unwrap_or_else(|| panic!("{dest} must be in the merged tree"));
            let xattrs = match node {
                Node::File { xattrs, .. } | Node::Symlink { xattrs, .. } => xattrs,
                other => panic!("unexpected node kind for {dest}: {other:?}"),
            };
            assert!(
                xattrs.is_empty(),
                "{dest} is vmcell's own injection: it carries no xattrs under EITHER policy \
                 (§4.7, invariant F5), got {xattrs:?}"
            );
        }
        // The tar-derived directory DID get its attribute — the positive control that proves the
        // assertions above are not vacuously green because `Preserve` never took effect.
        match map.get(&normalize_path(Path::new("usr"))) {
            Some(Node::Dir { xattrs, .. }) => assert_eq!(
                xattrs.len(),
                1,
                "positive control: a tar-derived directory keeps its xattr under `Preserve`"
            ),
            other => panic!("expected the tar-derived directory node, got {other:?}"),
        }
    }

    /// FNV-1a-64 over `bytes` — the image digest the byte-identity gate below pins.
    ///
    /// Hand-rolled rather than `blake3::hash`, and it is not fussiness: `blake3` is an OPTIONAL
    /// dependency enabled by the `pipeline` feature, while this module (and this test module) are
    /// gated on `am-fs-erofs`, which the feature-powerset gate builds on its own. It resolves
    /// today only through dev-dependency feature unification — a fact no one wrote down and one
    /// edit away from turning this gate into a powerset-row compile error. `std`'s own
    /// `DefaultHasher` is explicitly not stable across releases, so it cannot pin a literal.
    /// FNV-1a is 4 lines, fixed forever, and a byte-identity tripwire needs no collision
    /// resistance — nothing adversarial chooses these bytes.
    fn fnv1a64(bytes: &[u8]) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in bytes {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }

    // Migration is free, half 1 (§18 delta 7: "`Strip` + flag-absent behavior byte-identical").
    // The literal below digests the image the packer produced at commit `ae723fc` — the last
    // commit before this delta — over `pax_xattr_fixture_tar()`, captured by running the
    // pre-change packer. It pins the claim that the DEFAULT policy changed no packed byte.
    //
    // A change that legitimately moves the packed bytes (an EROFS writer bump, a new synthesized
    // node) reddens this: re-capture the literal and say so in the same commit — do not delete the
    // gate, which is the only thing standing between "we did not change the default" and a hope.
    //
    // RED on the inverse: pack the fixture with `XattrPolicy::Preserve` here — the image gains the
    // inline xattr and the digest moves.
    #[test]
    fn the_default_policy_packs_the_pre_delta7_bytes() {
        let archive = tar::Archive::new(std::io::Cursor::new(pax_xattr_fixture_tar()));
        let image = tar_to_erofs(
            vec![archive],
            vec![],
            vec![],
            vec![],
            false,
            XattrPolicy::default(),
        )
        .expect("pack");
        assert_eq!(
            (image.len(), fnv1a64(&image)),
            (20480, 0xb46a_722d_260f_dc55),
            "the default (`Strip`) pack must be byte-identical to the pre-delta-7 packer's \
             output over the same fixture"
        );
    }

    // The pack-twice byte-determinism gate (§18 delta 7 adds it because the delta's own
    // migration claim leans on it). The merged tree is a `HashMap`, and `tar_to_erofs` sorts its
    // keys only by component COUNT — not a total order — so same-depth ties resolve in randomized
    // iteration order. That is unobservable only because every child attaches into its parent's
    // `BTreeMap`, which re-sorts by name at each level. This gate is what turns that argument into
    // a fact, under BOTH policies (the `Preserve` leg additionally pins that the xattr order a
    // producer wrote is canonicalized rather than carried).
    //
    // RED on the inverse: make any node's `meta.mtime` a clock read (e.g. the synthesized parent
    // dirs) — both legs redden. Note what does NOT redden it, so the gate is not oversold:
    // dropping the `sort_by` in `tar_entry_xattrs` keeps this green, because PAX record order is
    // itself deterministic for a fixed input; that sort is a CANONICALIZATION (two producers that
    // wrote the same attributes in different orders pack the same image), and the ordering it
    // fixes is pinned by `xattr_order_is_canonicalized_not_producer_order` instead.
    #[test]
    fn packing_the_same_input_twice_is_byte_identical() {
        for policy in [XattrPolicy::Strip, XattrPolicy::Preserve] {
            let pack = || {
                let archive = tar::Archive::new(std::io::Cursor::new(multi_entry_fixture_tar()));
                tar_to_erofs(vec![archive], vec![], vec![], vec![], false, policy).expect("pack")
            };
            let first = pack();
            let second = pack();
            assert_eq!(
                first, second,
                "packing the same input twice under {policy:?} must produce byte-identical \
                 images; the merged tree's HashMap order must not reach the image"
            );
            assert!(
                !first.is_empty(),
                "the fixture must actually pack something"
            );
        }
    }

    /// A fixture broad enough for the determinism gate to mean something: several same-depth
    /// siblings (where the merged tree's `HashMap` order is unconstrained), a nested directory, a
    /// symlink, a hardlink, and two xattr records on one file in non-sorted order.
    fn multi_entry_fixture_tar() -> Vec<u8> {
        let mut tar = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar);
            for name in [
                "usr/bin/aa",
                "usr/bin/bb",
                "usr/bin/cc",
                "etc/one",
                "etc/two",
            ] {
                append_file(&mut b, name, name.as_bytes());
            }
            // Two records, deliberately NOT in sorted order, on one file.
            b.append_pax_extensions([
                ("SCHILY.xattr.user.zeta", &b"z"[..]),
                ("SCHILY.xattr.security.capability", &b"\x01\x00"[..]),
            ])
            .unwrap();
            append_file(&mut b, "usr/bin/dd", b"dd");

            let mut sh = tar::Header::new_gnu();
            sh.set_size(0);
            sh.set_mode(0o777);
            sh.set_entry_type(tar::EntryType::Symlink);
            sh.set_link_name("aa").unwrap();
            sh.set_cksum();
            b.append_data(&mut sh, "usr/bin/link", std::io::empty())
                .unwrap();

            let mut lh = tar::Header::new_gnu();
            lh.set_size(0);
            lh.set_mode(0o644);
            lh.set_entry_type(tar::EntryType::Link);
            lh.set_link_name("etc/one").unwrap();
            lh.set_cksum();
            b.append_data(&mut lh, "etc/one-hard", std::io::empty())
                .unwrap();
            b.finish().unwrap();
        }
        tar
    }

    // OCI opaque-whiteout ordering contract (recorded assumption). `.wh..wh..opq` clears
    // the current contents of its parent subtree at the moment it is processed. vmcell's
    // first-party producers emit the opaque marker as the directory's FIRST entry, so a
    // sibling written AFTER it in the same layer survives (case A). A sibling written
    // BEFORE it in tar order is (accepted footgun) also cleared (case B) — per-layer
    // application that would spare same-layer earlier siblings is forward work.
    #[test]
    fn test_opaque_marker_ordering_contract() {
        // Case A: marker FIRST, then the child -> child survives (the producer contract).
        let mut a = Vec::new();
        {
            let mut b = tar::Builder::new(&mut a);
            let mut h = tar::Header::new_gnu();
            h.set_size(0);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "opaquedir/.wh..wh..opq", std::io::empty())
                .unwrap();
            append_file(&mut b, "opaquedir/kept", b"k");
            b.finish().unwrap();
        }
        let map = build_node_map(
            vec![tar::Archive::new(std::io::Cursor::new(a))],
            vec![],
            vec![],
            vec![],
            XattrPolicy::Strip,
        )
        .expect("node map");
        assert!(
            map.contains_key(&normalize_path(Path::new("opaquedir/kept"))),
            "a same-layer child written AFTER the opaque marker must survive (producer contract)"
        );

        // Case B (accepted footgun): child BEFORE the marker in tar order -> cleared.
        // This pins the documented limitation; it reddens if the retain is made
        // insertion/timestamp-aware without updating the recorded assumption.
        let mut c = Vec::new();
        {
            let mut b = tar::Builder::new(&mut c);
            append_file(&mut b, "opaquedir/early", b"e");
            let mut h = tar::Header::new_gnu();
            h.set_size(0);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "opaquedir/.wh..wh..opq", std::io::empty())
                .unwrap();
            b.finish().unwrap();
        }
        let map = build_node_map(
            vec![tar::Archive::new(std::io::Cursor::new(c))],
            vec![],
            vec![],
            vec![],
            XattrPolicy::Strip,
        )
        .expect("node map");
        assert!(
            !map.contains_key(&normalize_path(Path::new("opaquedir/early"))),
            "documented footgun: a same-layer child BEFORE the opaque marker is cleared"
        );
    }

    // H-ART-2: a tar HARDLINK entry (type byte '1') must be MATERIALIZED — the link path gets
    // the target file's content — never silently dropped (`_ => continue`). The default Debian
    // base carries `usr/bin/perl5.NN` -> `usr/bin/perl`; the old wildcard made it vanish, and a
    // fail-loud variant would break the default build (that base HAS this hardlink). RED on
    // both the drop (link path missing) and the fail-loud (build errors) versions.
    #[test]
    fn test_hardlink_entry_is_materialized() {
        let mut tar = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar);
            append_file(&mut b, "usr/bin/perl", b"real-perl");
            // A hardlink pointing at the regular file above. The caller must set the entry
            // type to `Link` (append_link does not) so the entry reads back as a hardlink.
            let mut hl = tar::Header::new_gnu();
            hl.set_entry_type(tar::EntryType::Link);
            hl.set_size(0);
            hl.set_mode(0o644);
            b.append_link(&mut hl, "usr/bin/perl5.40.1", "usr/bin/perl")
                .unwrap();
            b.finish().unwrap();
        }
        let archive = tar::Archive::new(std::io::Cursor::new(tar));
        let entries = build_node_map(vec![archive], vec![], vec![], vec![], XattrPolicy::Strip)
            .expect("build");
        let link = entries
            .get(&normalize_path(Path::new("usr/bin/perl5.40.1")))
            .expect("the hardlink must be materialized, not dropped");
        match link {
            Node::File { data, .. } => {
                assert_eq!(
                    data, b"real-perl",
                    "hardlink content must equal the target's"
                );
            }
            other => panic!("a materialized hardlink must be a regular file, got {other:?}"),
        }

        // A hardlink whose target is genuinely absent still fails loud (never a silent drop).
        let mut orphan = Vec::new();
        {
            let mut b = tar::Builder::new(&mut orphan);
            let mut hl = tar::Header::new_gnu();
            hl.set_entry_type(tar::EntryType::Link);
            hl.set_size(0);
            hl.set_mode(0o644);
            b.append_link(&mut hl, "usr/bin/dangling", "usr/bin/nonexistent")
                .unwrap();
            b.finish().unwrap();
        }
        let archive = tar::Archive::new(std::io::Cursor::new(orphan));
        assert!(
            matches!(
                build_node_map(vec![archive], vec![], vec![], vec![], XattrPolicy::Strip),
                Err(crate::error::Error::Artifact(_))
            ),
            "a hardlink to a missing target must still fail loud"
        );
    }

    // H-ART-3: injected files (steward/CA/tools) are merged as the TAIL, after all layers.
    // (1) A `.wh.` whiteout in an upper layer that deletes the CA dir must NOT remove the
    // injected CA. (2) A layer that carries the injected path with different content must be
    // overwritten by the injected file. The buggy inject-before-merge order reddens both.
    #[test]
    fn test_injection_survives_whiteout_and_layer_overwrite() {
        // A real file on disk for the injected CA.
        let dir = tempfile::tempdir().expect("tempdir");
        let ca = dir.path().join("ca.crt");
        std::fs::write(&ca, b"-----INJECTED-CA-----").unwrap();
        let steward = dir.path().join("steward");
        std::fs::write(&steward, b"INJECTED-STEWARD").unwrap();

        // Lower layer: a base file, plus a steward with DIFFERENT (stale) content.
        let mut lower = Vec::new();
        {
            let mut b = tar::Builder::new(&mut lower);
            append_file(&mut b, "etc/os-release", b"base");
            append_file(&mut b, "usr/sbin/vmcell-steward", b"STALE-LAYER-STEWARD");
            append_file(
                &mut b,
                "usr/local/share/ca-certificates/other.crt",
                b"other",
            );
            b.finish().unwrap();
        }
        // Upper layer: whiteout the whole CA dir.
        let mut upper = Vec::new();
        {
            let mut b = tar::Builder::new(&mut upper);
            append_file(&mut b, "usr/local/share/.wh.ca-certificates", &[]);
            b.finish().unwrap();
        }
        let a1 = tar::Archive::new(std::io::Cursor::new(lower));
        let a2 = tar::Archive::new(std::io::Cursor::new(upper));
        let injected_files = vec![
            (
                "usr/local/share/ca-certificates/vmcell-ca.crt",
                ca.as_path(),
                None,
            ),
            ("usr/sbin/vmcell-steward", steward.as_path(), None),
        ];
        let map = build_node_map(
            vec![a1, a2],
            vec![],
            injected_files,
            vec![],
            XattrPolicy::Strip,
        )
        .expect("node map");

        // (1) The injected CA survives the whiteout that deleted the CA dir.
        match map.get(Path::new("usr/local/share/ca-certificates/vmcell-ca.crt")) {
            Some(Node::File { data, .. }) => {
                assert_eq!(data, b"-----INJECTED-CA-----");
            }
            other => panic!("injected CA must survive an upper-layer whiteout, got {other:?}"),
        }
        // (2) The injected steward wins over the stale layer content.
        match map.get(Path::new("usr/sbin/vmcell-steward")) {
            Some(Node::File { data, .. }) => {
                assert_eq!(
                    data, b"INJECTED-STEWARD",
                    "the injected steward (tail) must overwrite the layer's stale steward"
                );
            }
            other => panic!("expected the injected steward file, got {other:?}"),
        }
    }

    // §18 delta 6 image-level gate: a downstream extra file must be PRESENT with the caller's
    // exact CONTENT and its EXPLICIT MODE, and must beat both the base layer's content and an
    // upper layer's `.wh.` whiteout (it is inserted after the merge). Three buggy impls redden
    // here: (a) inserting extras before the layer merge — the stale layer content or the
    // whiteout wins; (b) running extras through `injected_file_mode` instead of the explicit
    // mode — `/opt/acme/acme-daemon` has no bin/sbin component, so it packs 0o644 instead of
    // 0o755; (c) applying the heuristic to a dest that DOES have a `bin` component — the
    // 0o600 config below would pack 0o755.
    #[test]
    fn extra_files_are_present_with_their_explicit_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let daemon = dir.path().join("acme");
        std::fs::write(&daemon, b"ACME-DAEMON").unwrap();
        let conf = dir.path().join("acme.conf");
        std::fs::write(&conf, b"secret=1").unwrap();

        // Lower layer: stale content at BOTH extra dests.
        let mut lower = Vec::new();
        {
            let mut b = tar::Builder::new(&mut lower);
            append_file(&mut b, "opt/acme/acme-daemon", b"STALE-LAYER-DAEMON");
            append_file(&mut b, "usr/local/bin/acme.conf", b"STALE-LAYER-CONF");
            b.finish().unwrap();
        }
        // Upper layer: whiteout the whole `opt/acme` directory.
        let mut upper = Vec::new();
        {
            let mut b = tar::Builder::new(&mut upper);
            append_file(&mut b, "opt/.wh.acme", &[]);
            b.finish().unwrap();
        }
        let extra = vec![
            // No `bin`/`sbin` component: the heuristic would say 0o644, the caller says 0o755.
            ("/opt/acme/acme-daemon", daemon.as_path(), Some(0o755u16)),
            // A `bin` component: the heuristic would say 0o755, the caller says 0o600.
            ("/usr/local/bin/acme.conf", conf.as_path(), Some(0o600u16)),
        ];
        let map = build_node_map(
            vec![
                tar::Archive::new(std::io::Cursor::new(lower)),
                tar::Archive::new(std::io::Cursor::new(upper)),
            ],
            extra,
            vec![],
            vec![],
            XattrPolicy::Strip,
        )
        .expect("node map");

        for (dest, want_data, want_mode) in [
            ("opt/acme/acme-daemon", &b"ACME-DAEMON"[..], 0o755),
            ("usr/local/bin/acme.conf", &b"secret=1"[..], 0o600),
        ] {
            match map.get(&normalize_path(Path::new(dest))) {
                Some(Node::File {
                    mode, data, meta, ..
                }) => {
                    assert_eq!(data, want_data, "{dest} must carry the caller's content");
                    assert_eq!(
                        mode & 0o777,
                        want_mode,
                        "{dest} must carry the caller's EXPLICIT mode, not the \
                         injected_file_mode heuristic"
                    );
                    assert_eq!(mode & fs_erofs::inode::S_IFMT, fs_erofs::inode::S_IFREG);
                    // Deterministic emission (§10.3): uid/gid 0, mtime 0.
                    assert_eq!((meta.uid, meta.gid, meta.mtime), (0, 0, 0));
                }
                other => panic!("expected the injected extra file at {dest}, got {other:?}"),
            }
        }
    }

    // Invariant F5's structural backstop: vmcell's own injections are inserted AFTER the
    // extras, so even if a reserved dest ever reached the packer (the pack tail rejects it
    // first), vmcell's content wins rather than being silently clobbered. RED on the inverse
    // (swapping the two loops): the extra's bytes would land at the steward path.
    #[test]
    fn vmcell_injections_win_over_a_colliding_extra_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let steward = dir.path().join("steward");
        std::fs::write(&steward, b"INJECTED-STEWARD").unwrap();
        let impostor = dir.path().join("impostor");
        std::fs::write(&impostor, b"IMPOSTOR").unwrap();
        let empty = tar::Archive::new(std::io::Cursor::new({
            let mut v = Vec::new();
            tar::Builder::new(&mut v).finish().unwrap();
            v
        }));
        let map = build_node_map(
            vec![empty],
            vec![("/usr/sbin/vmcell-steward", impostor.as_path(), Some(0o755))],
            vec![("usr/sbin/vmcell-steward", steward.as_path(), None)],
            vec![],
            XattrPolicy::Strip,
        )
        .expect("node map");
        match map.get(&normalize_path(Path::new("usr/sbin/vmcell-steward"))) {
            Some(Node::File { data, .. }) => assert_eq!(
                data, b"INJECTED-STEWARD",
                "vmcell's own injection is authoritative and is inserted last"
            ),
            other => panic!("expected the injected steward file node, got {other:?}"),
        }
    }

    // The multicall binary's dest as `rootfs_injection_manifest` composes it
    // (`{VMCELL_TOOLS_DIR}/{GUEST_TOOLS_MULTICALL_BIN}`). Those two consts are private to
    // `artifact::rootfs`, so this is fixture data here, not a second spelling of a law: what
    // these tests assert is the packer's collision PREDICATE, and the manifest side is pinned
    // by `rootfs_injection_manifest_pins_truststore_and_tools`.
    const TOOLS_BIN_DEST: &str = "vmcell-tools/vmcell-guest-tools";

    /// One applet name taken from the shared roster const rather than invented, so the
    /// non-colliding control is the shape the default handler actually ships.
    fn first_applet() -> String {
        format!(
            "vmcell-tools/{}",
            vmcell_protocol::GUEST_TOOLS_APPLETS
                .first()
                .expect("the applet roster is non-empty")
        )
    }

    // THE DOCS/90 H1 SHAPE, refused (§4.2, invariant F5). `rootfs_injection_manifest` injects the
    // multicall binary as a FILE at `<tools_dir>/<multicall-bin>` and one applet SYMLINK per
    // roster entry into the SAME directory — and since v33 delta 6 that roster is registry DATA,
    // so a registered handler can name the binary's own file name. Under the old last-wins
    // `insert` the symlink replaced the binary with a dangling self-symlink: the image shipped no
    // multicall binary and every applet dangling, and the pack reported success.
    //
    // RED ON THE INVERSE: delete the `claim_injection_dest` call in the symlink loop of
    // `build_node_map` and this test packs `Ok` with a `Node::Symlink` at `TOOLS_BIN_DEST`.
    #[test]
    fn an_applet_symlink_over_the_injected_multicall_binary_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tools = dir.path().join("vmcell-guest-tools");
        std::fs::write(&tools, b"MULTICALL-BINARY").unwrap();
        let empty = || {
            tar::Archive::new(std::io::Cursor::new({
                let mut v = Vec::new();
                tar::Builder::new(&mut v).finish().unwrap();
                v
            }))
        };

        // The colliding roster: an applet named after the multicall binary itself.
        let err = build_node_map(
            vec![empty()],
            vec![],
            vec![(TOOLS_BIN_DEST, tools.as_path(), None)],
            vec![(TOOLS_BIN_DEST, "vmcell-guest-tools")],
            XattrPolicy::Strip,
        )
        .expect_err("an applet symlink over the multicall binary must be refused, not packed");
        match err {
            crate::error::Error::Artifact(msg) => {
                assert!(
                    msg.contains(TOOLS_BIN_DEST)
                        && msg.contains("an injected file")
                        && msg.contains("an applet symlink"),
                    "the refusal must name the dest and BOTH claimants, got: {msg}"
                );
            }
            other => panic!("expected a typed Artifact refusal, got {other:?}"),
        }

        // POSITIVE CONTROL: the same manifest with a roster entry that does not name the binary
        // packs, and both nodes are present with their own kinds.
        let applet = first_applet();
        let map = build_node_map(
            vec![empty()],
            vec![],
            vec![(TOOLS_BIN_DEST, tools.as_path(), None)],
            vec![(applet.as_str(), "vmcell-guest-tools")],
            XattrPolicy::Strip,
        )
        .expect("a roster that collides with nothing must pack");
        match map.get(&normalize_path(Path::new(TOOLS_BIN_DEST))) {
            Some(Node::File { data, .. }) => assert_eq!(data, b"MULTICALL-BINARY"),
            other => panic!("expected the multicall binary file node, got {other:?}"),
        }
        match map.get(&normalize_path(Path::new(&applet))) {
            Some(Node::Symlink { target, .. }) => assert_eq!(target, "vmcell-guest-tools"),
            other => panic!("expected the applet symlink node, got {other:?}"),
        }
    }

    // The deliberate scope decision, stated in `claim_injection_dest`'s rustdoc and pinned here:
    // an IDENTICAL-kind duplicate is refused too, both ways round. Two manifest entries at one
    // dest mean the second's bytes are the image's and the first's are nowhere, whatever their
    // kinds — the same hazard the F5 extra-file validator already refuses as "listed twice; the
    // last writer would silently win". A duplicated applet name is the reachable instance: the
    // roster is registry data and nothing dedups it.
    //
    // RED ON THE INVERSE: drop either `claim_injection_dest` call and the matching leg packs `Ok`.
    #[test]
    fn an_identical_kind_duplicate_injection_dest_is_refused_too() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = dir.path().join("first");
        std::fs::write(&first, b"FIRST").unwrap();
        let second = dir.path().join("second");
        std::fs::write(&second, b"SECOND").unwrap();
        let empty = || {
            tar::Archive::new(std::io::Cursor::new({
                let mut v = Vec::new();
                tar::Builder::new(&mut v).finish().unwrap();
                v
            }))
        };

        // Two FILES at one dest.
        let err = build_node_map(
            vec![empty()],
            vec![],
            vec![
                ("usr/sbin/vmcell-steward", first.as_path(), None),
                ("usr/sbin/vmcell-steward", second.as_path(), None),
            ],
            vec![],
            XattrPolicy::Strip,
        )
        .expect_err("two injected files at one dest must be refused");
        match err {
            crate::error::Error::Artifact(msg) => assert!(
                msg.contains("usr/sbin/vmcell-steward") && msg.contains("an injected file"),
                "the refusal must name the dest and the claimant kind, got: {msg}"
            ),
            other => panic!("expected a typed Artifact refusal, got {other:?}"),
        }

        // Two SYMLINKS at one dest — the duplicated applet roster entry.
        let applet = first_applet();
        let err = build_node_map(
            vec![empty()],
            vec![],
            vec![],
            vec![
                (applet.as_str(), "vmcell-guest-tools"),
                (applet.as_str(), "vmcell-guest-tools"),
            ],
            XattrPolicy::Strip,
        )
        .expect_err("a roster listing one applet twice must be refused");
        match err {
            crate::error::Error::Artifact(msg) => assert!(
                msg.contains(&applet) && msg.contains("an applet symlink"),
                "the refusal must name the dest and the claimant kind, got: {msg}"
            ),
            other => panic!("expected a typed Artifact refusal, got {other:?}"),
        }
    }

    // The claim is keyed on the NORMALIZED path, because that is the key the merged tree is built
    // on. `/vmcell-tools/x`, `vmcell-tools/x` and `vmcell-tools/y/../x` are ONE dest to
    // `normalize_path` (it drops the root component and POPS a `..`) and therefore one node in the
    // packed image — while as raw `PathBuf`s they are three distinct keys, so a ledger keyed on the
    // dest string would hand the second writer a free pass and restore the silent clobber exactly.
    // (An interior `.` needs no law here: `Path`'s own component equality already folds it.)
    //
    // RED ON THE INVERSE: key `claim_injection_dest`'s ledger on `PathBuf::from(dest_path)` instead
    // of `normalize_path(dest_path)` and both legs pack `Ok` with the symlink winning.
    #[test]
    fn the_injection_claim_is_keyed_on_the_normalized_dest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tools = dir.path().join("vmcell-guest-tools");
        std::fs::write(&tools, b"MULTICALL-BINARY").unwrap();
        let empty = || {
            tar::Archive::new(std::io::Cursor::new({
                let mut v = Vec::new();
                tar::Builder::new(&mut v).finish().unwrap();
                v
            }))
        };
        for spelling in [
            "/vmcell-tools/vmcell-guest-tools",
            "vmcell-tools/vmcell-tools/../vmcell-guest-tools",
        ] {
            // Same normalized dest as `TOOLS_BIN_DEST`, different raw string.
            assert_eq!(
                normalize_path(Path::new(spelling)),
                normalize_path(Path::new(TOOLS_BIN_DEST)),
                "the fixture must be a second SPELLING of the one dest"
            );
            let err = build_node_map(
                vec![empty()],
                vec![],
                vec![(TOOLS_BIN_DEST, tools.as_path(), None)],
                vec![(spelling, "vmcell-guest-tools")],
                XattrPolicy::Strip,
            )
            .unwrap_err();
            assert!(
                matches!(err, crate::error::Error::Artifact(_)),
                "expected a typed Artifact refusal for `{spelling}`, got {err:?}"
            );
        }
    }

    // THE REFUSAL'S SCOPE, guarded from over-reach: it covers vmcell's OWN manifest only. A LAYER
    // entry at an injection dest — including one of a different node KIND, a symlink where the
    // injected steward goes — is still resolved last-wins by design (H-ART-3: the injections are
    // the tail precisely so they win a stale layer). Refusing that would make a base image that
    // happens to ship a `usr/sbin/vmcell-steward` symlink unpackable.
    //
    // RED ON THE INVERSE: claim the layer-merge keys in the same ledger and this errors instead of
    // packing the injected steward.
    #[test]
    fn a_layer_entry_under_an_injection_dest_is_still_last_wins() {
        let dir = tempfile::tempdir().expect("tempdir");
        let steward = dir.path().join("steward");
        std::fs::write(&steward, b"INJECTED-STEWARD").unwrap();
        let mut layer = Vec::new();
        {
            let mut b = tar::Builder::new(&mut layer);
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o777);
            header.set_entry_type(tar::EntryType::Symlink);
            b.append_link(&mut header, "usr/sbin/vmcell-steward", "/bin/true")
                .unwrap();
            b.finish().unwrap();
        }
        let map = build_node_map(
            vec![tar::Archive::new(std::io::Cursor::new(layer))],
            vec![],
            vec![("usr/sbin/vmcell-steward", steward.as_path(), None)],
            vec![],
            XattrPolicy::Strip,
        )
        .expect("a layer symlink at an injection dest is overwritten, not refused");
        match map.get(&normalize_path(Path::new("usr/sbin/vmcell-steward"))) {
            Some(Node::File { data, .. }) => assert_eq!(
                data, b"INJECTED-STEWARD",
                "vmcell's injection wins the layer's symlink of the same path"
            ),
            other => panic!("expected the injected steward file node, got {other:?}"),
        }
    }

    // The parent-synthesis path: `build_node_map` does NOT create parent directories — only
    // `tar_to_erofs` does — so an extra file under a directory the base image does not ship
    // (`/opt/acme/bin/x`) is only proven complete at THIS level. RED on the inverse (dropping
    // the parent-synthesis loop): the pack fails with "cannot add child … under non-directory"
    // / "Missing node" instead of producing an image.
    #[test]
    fn extra_file_under_a_new_directory_packs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let daemon = dir.path().join("acme");
        std::fs::write(&daemon, b"ACME").unwrap();
        // A base with libc6 so `require_libc6` stays exercised on the real path.
        let mut base = Vec::new();
        {
            let mut b = tar::Builder::new(&mut base);
            append_file(&mut b, "lib/x86_64-linux-gnu/libc.so.6", b"libc");
            b.finish().unwrap();
        }
        let image = tar_to_erofs(
            vec![tar::Archive::new(std::io::Cursor::new(base))],
            vec![("/opt/acme/bin/acme-daemon", daemon.as_path(), Some(0o755))],
            vec![],
            vec![],
            true,
            XattrPolicy::Strip,
        )
        .expect("an extra file under a directory absent from the base must pack");
        assert!(!image.is_empty(), "EROFS image bytes should not be empty");
    }

    // L-ART-6: a child whose parent path is occupied by a NON-directory node must fail loud,
    // never be silently dropped. Here `a/b` is a regular file and `a/b/c` is a child under
    // it. The buggy version (no `else` arm) packs Ok with `a/b/c` missing.
    #[test]
    fn test_tar_to_erofs_rejects_child_under_nondir() {
        let mut tar = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar);
            append_file(&mut b, "a/b", b"file");
            append_file(&mut b, "a/b/c", b"child");
            b.finish().unwrap();
        }
        let archive = tar::Archive::new(std::io::Cursor::new(tar));
        let res = tar_to_erofs(
            vec![archive],
            vec![],
            vec![],
            vec![],
            false,
            XattrPolicy::Strip,
        );
        assert!(
            matches!(res, Err(crate::error::Error::Artifact(_))),
            "a child under a non-directory parent must fail loud (L-ART-6), got {res:?}"
        );
    }

    /// A one-member archive whose entry carries `entry_type`, written with `header`'s format.
    ///
    /// The header FORMAT is a parameter because it decides what surfaces: `tar`'s reader folds an
    /// `x`/`L`/`K` extension header into the member that follows only when the magic is ustar or
    /// GNU, so a v7 (`new_old`) header is what makes an unfolded one reach the packer.
    fn tar_with_entry(mut header: tar::Header, entry_type: tar::EntryType, path: &str) -> Vec<u8> {
        let mut tar_data = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar_data);
            header.set_entry_type(entry_type);
            header.set_size(0);
            header.set_mode(0o644);
            header.set_path(path).expect("set the member path");
            header.set_cksum();
            b.append(&header, std::io::empty()).expect("append");
            b.finish().expect("finish");
        }
        tar_data
    }

    // AGENTS.md, "every accepted input is honored or rejected": a member type this packer has no
    // node for must be a hard error naming it — never the old `_ => continue`, which dropped the
    // member and packed a rootfs that boots as if complete (the silent-corruption class
    // `check_layer_media_type` refuses one level up).
    //
    // RED on that inverse: with `_ => continue` every arm below returns `Ok`, so
    // `expect_err` panics.
    #[test]
    fn unsupported_tar_entry_types_are_rejected_not_dropped() {
        let cases: Vec<(&str, tar::Header, tar::EntryType)> = vec![
            (
                "contiguous",
                tar::Header::new_gnu(),
                tar::EntryType::Continuous,
            ),
            (
                "unknown type byte",
                tar::Header::new_gnu(),
                tar::EntryType::new(b'A'),
            ),
            (
                "unfolded pax extended header",
                tar::Header::new_old(),
                tar::EntryType::XHeader,
            ),
            (
                "unfolded gnu long name",
                tar::Header::new_old(),
                tar::EntryType::GNULongName,
            ),
            (
                "unfolded gnu long link",
                tar::Header::new_old(),
                tar::EntryType::GNULongLink,
            ),
        ];
        // BOTH policies (§18 delta 7): the refusal must keep naming the member and the type under
        // `Preserve` too. The "unfolded pax extended header WITH A BODY" leg below is why — a real
        // `x` header always carries one (that is where its records live), and under `Preserve` the
        // packer reads PAX records, so without the local-pax guard in `tar_entry_xattrs` that body
        // is decoded and the named refusal is replaced by a decode error about bytes the packer
        // was never going to use.
        //
        // RED on the inverse: drop `is_pax_local_extensions()` from `tar_entry_xattrs`' early
        // return — the body-carrying `x` leg reddens under `Preserve`. (Note the zero-size `x`
        // leg in `cases` does NOT redden on that inverse: an empty body reads back as no records
        // at all, which is exactly why the body-carrying leg exists beside it.)
        for (label, header, entry_type) in cases {
            for policy in [XattrPolicy::Strip, XattrPolicy::Preserve] {
                let tar_data = tar_with_entry(header.clone(), entry_type, "odd/member");
                let archive = tar::Archive::new(std::io::Cursor::new(tar_data));
                let err = build_node_map(vec![archive], vec![], vec![], vec![], policy)
                    .expect_err(&format!("{label} must be rejected, not silently dropped"));
                let crate::error::Error::Artifact(msg) = &err else {
                    panic!("{label} under {policy:?}: expected Error::Artifact, got {err:?}");
                };
                assert!(
                    msg.contains("odd/member") && msg.contains("unsupported tar entry type"),
                    "{label} under {policy:?}: the refusal must name the member and the type, \
                     got: {msg}"
                );
            }
        }

        // The body-carrying unfolded `x` header, in both directions (see the note above).
        for policy in [XattrPolicy::Strip, XattrPolicy::Preserve] {
            let mut tar_data = Vec::new();
            {
                let mut b = tar::Builder::new(&mut tar_data);
                let mut h = tar::Header::new_old();
                h.set_entry_type(tar::EntryType::XHeader);
                // An UNDECODABLE body, deliberately. An unfolded `x` header only reaches this
                // packer on an already-irregular archive (`tar` could not attach it to the member
                // that follows, because the header magic is neither ustar nor GNU), so its body
                // may be anything at all. The member is rejected by TYPE either way; the point is
                // that the packer must not decode bytes it will never use and report THAT
                // failure instead — a "malformed pax extension record" says nothing about the
                // member, its path, or what to do next.
                let body: &[u8] = b"not a pax record body\n";
                h.set_size(body.len() as u64);
                h.set_mode(0o644);
                h.set_path("odd/member").expect("set the member path");
                h.set_cksum();
                b.append(&h, body).expect("append");
                b.finish().expect("finish");
            }
            let archive = tar::Archive::new(std::io::Cursor::new(tar_data));
            let err = build_node_map(vec![archive], vec![], vec![], vec![], policy)
                .expect_err("a body-carrying unfolded pax header must be rejected");
            let crate::error::Error::Artifact(msg) = &err else {
                panic!("expected Error::Artifact under {policy:?}, got {err:?}");
            };
            assert!(
                msg.contains("odd/member") && msg.contains("unsupported tar entry type"),
                "under {policy:?} the refusal must still name the member and the type — the \
                 packer must not consume an unfolded pax body it will reject anyway, got: {msg}"
            );
        }
    }

    // The positive control for the rejection above: every member type this packer DOES have a
    // node for still packs, and the one metadata-only type (`g`, the archive-wide pax global
    // header that real registry layers carry) is still skipped without an error. RED if the
    // rejection is widened to swallow a handled type or the `g` skip is dropped.
    #[test]
    fn handled_tar_entry_types_still_pack() {
        let mut tar_data = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar_data);
            // The archive-wide pax global header: names no filesystem object, must not error.
            let mut g = tar::Header::new_gnu();
            g.set_entry_type(tar::EntryType::XGlobalHeader);
            g.set_size(0);
            g.set_mode(0o644);
            g.set_path("pax_global_header").expect("path");
            g.set_cksum();
            b.append(&g, std::io::empty()).expect("append pax global");

            let mut d = tar::Header::new_gnu();
            d.set_entry_type(tar::EntryType::Directory);
            d.set_size(0);
            d.set_mode(0o755);
            d.set_path("dir").expect("path");
            d.set_cksum();
            b.append(&d, std::io::empty()).expect("append dir");

            append_file(&mut b, "dir/regular", b"body");

            let mut s = tar::Header::new_gnu();
            s.set_entry_type(tar::EntryType::Symlink);
            s.set_size(0);
            s.set_mode(0o777);
            s.set_path("dir/symlink").expect("path");
            s.set_link_name("regular").expect("link name");
            s.set_cksum();
            b.append(&s, std::io::empty()).expect("append symlink");

            for (et, path) in [
                (tar::EntryType::Char, "dev/chr"),
                (tar::EntryType::Block, "dev/blk"),
            ] {
                let mut h = tar::Header::new_gnu();
                h.set_entry_type(et);
                h.set_size(0);
                h.set_mode(0o600);
                h.set_device_major(1).expect("major");
                h.set_device_minor(3).expect("minor");
                h.set_path(path).expect("path");
                h.set_cksum();
                b.append(&h, std::io::empty()).expect("append device");
            }

            let mut f = tar::Header::new_gnu();
            f.set_entry_type(tar::EntryType::Fifo);
            f.set_size(0);
            f.set_mode(0o600);
            f.set_path("dir/fifo").expect("path");
            f.set_cksum();
            b.append(&f, std::io::empty()).expect("append fifo");

            let mut l = tar::Header::new_gnu();
            l.set_entry_type(tar::EntryType::Link);
            l.set_size(0);
            l.set_mode(0o644);
            l.set_path("dir/hardlink").expect("path");
            l.set_link_name("dir/regular").expect("link target");
            l.set_cksum();
            b.append(&l, std::io::empty()).expect("append hardlink");

            b.finish().expect("finish");
        }
        let archive = tar::Archive::new(std::io::Cursor::new(tar_data));
        let map = build_node_map(vec![archive], vec![], vec![], vec![], XattrPolicy::Strip)
            .expect("every handled member type must pack, and the pax global header be skipped");

        assert!(
            !map.contains_key(Path::new("pax_global_header")),
            "the pax global header names no filesystem object and must not become a node"
        );
        assert!(
            matches!(map.get(Path::new("dir")), Some(Node::Dir { .. })),
            "the directory member must pack"
        );
        assert!(
            matches!(map.get(Path::new("dir/regular")), Some(Node::File { .. })),
            "the regular member must pack"
        );
        assert!(
            matches!(
                map.get(Path::new("dir/symlink")),
                Some(Node::Symlink { .. })
            ),
            "the symlink member must pack"
        );
        assert!(
            matches!(map.get(Path::new("dev/chr")), Some(Node::Device { .. })),
            "the char-device member must pack"
        );
        assert!(
            matches!(map.get(Path::new("dev/blk")), Some(Node::Device { .. })),
            "the block-device member must pack"
        );
        assert!(
            matches!(map.get(Path::new("dir/fifo")), Some(Node::Special { .. })),
            "the fifo member must pack"
        );
        match map.get(Path::new("dir/hardlink")) {
            Some(Node::File { data, .. }) => assert_eq!(
                data, b"body",
                "the hardlink must materialize its target's content"
            ),
            other => panic!("expected the hardlink materialized as a file, got {other:?}"),
        }
    }
}
