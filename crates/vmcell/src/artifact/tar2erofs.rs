//! Conversion of tar archives to EROFS images.
//!
//! This module provides an experimental utility for building an EROFS
//! filesystem directly from a tar archive for use as a root filesystem.

use fs_erofs::mkfs::{Node, NodeMeta, build_image};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};

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
        xattrs: vec![],
    };
    entries.insert(normalize_path(Path::new(dest_path)), node);
    Ok(())
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
/// # Errors
/// Returns [`crate::error::Error::Artifact`] if an injected file or an archive entry cannot be
/// read, or if an archive member carries an entry type this packer has no node for (contiguous,
/// GNU-sparse, an unfolded `x`/`L`/`K` extension header, or an unknown type byte) — such a member
/// is rejected, never dropped, because a dropped member packs a rootfs that boots as if complete.
/// The archive-wide pax global header (`g`) names no filesystem object and is the one skipped type.
#[cfg(feature = "am-fs-erofs")]
fn build_node_map<'a, R: Read + 'a>(
    archives: impl IntoIterator<Item = tar::Archive<R>>,
    extra_files: Vec<InjectedFile<'_>>,
    injected_files: Vec<InjectedFile<'_>>,
    injected_symlinks: Vec<(&str, &str)>,
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

            let node = match file.header().entry_type() {
                tar::EntryType::Regular => {
                    let mut data = Vec::new();
                    file.read_to_end(&mut data)
                        .map_err(|e| crate::error::Error::Artifact(e.to_string()))?;
                    // Accepted limitation: PAX SCHILY.xattr records (incl.
                    // `security.capability`) are intentionally NOT preserved — the
                    // steward and every in-guest `exec` run as root (§4.2), so
                    // file capabilities are moot; the erofs Node/XattrSpec plumbing
                    // exists but is unused. Pinned by
                    // `tests::test_pax_xattrs_are_not_preserved`. Retire this note if
                    // xattr passthrough is implemented.
                    Node::File {
                        mode: mode | fs_erofs::inode::S_IFREG,
                        data,
                        meta,
                        xattrs: vec![],
                    }
                }
                tar::EntryType::Directory => Node::Dir {
                    mode: mode | fs_erofs::inode::S_IFDIR,
                    entries: BTreeMap::new(),
                    meta,
                    xattrs: vec![],
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
                        xattrs: vec![],
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
                        xattrs: vec![],
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
                        xattrs: vec![],
                    }
                }
                tar::EntryType::Fifo => Node::Special {
                    mode: mode | fs_erofs::inode::S_IFIFO,
                    meta,
                    xattrs: vec![],
                },
                // A hardlink must NOT be silently dropped (H-ART-2): the default Debian base
                // carries e.g. `usr/bin/perl5.NN` -> `usr/bin/perl`, which would otherwise
                // vanish from the packed rootfs. MATERIALIZE it — copy the target file's
                // content to the link path (erofs has no hardlink-dedup requirement here).
                // A tar hardlink references an EARLIER entry, so the target is already in the
                // merged tree. Fail loud (never `_ => continue`) only if the target is absent
                // or is not a regular file. (`tar::EntryType` is non-exhaustive, so the
                // trailing `_` still catches genuinely-unknown future types.)
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
                            xattrs,
                        }) => Node::File {
                            mode: *mode,
                            data: data.clone(),
                            meta: *meta,
                            xattrs: xattrs.clone(),
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
    for injected in injected_files {
        insert_injected_file(&mut entries, injected)?;
    }
    for (dest_path, target) in injected_symlinks {
        let node = Node::Symlink {
            mode: 0o777 | fs_erofs::inode::S_IFLNK,
            target: target.to_string(),
            meta: NodeMeta {
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
            },
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
/// # Errors
/// Propagates `build_node_map`'s error for an unreadable or unsupported archive member.
#[cfg(all(feature = "fuzzing", feature = "am-fs-erofs"))]
pub fn fuzz_node_paths<'a, R: Read + 'a>(
    archives: impl IntoIterator<Item = tar::Archive<R>>,
) -> crate::error::Result<Vec<PathBuf>> {
    Ok(build_node_map(archives, vec![], vec![], vec![])?
        .into_keys()
        .collect())
}

/// Converts a tar archive to an EROFS filesystem image.
///
/// `extra_files` are the downstream [`ExtraFile`](crate::artifact::rootfs::ExtraFile)s and are
/// inserted after the layer merge but before `injected_files` (design §4.2, invariant F5), so
/// they win base-image collisions and whiteouts while vmcell's own injections stay
/// authoritative. Missing parent directories of any entry — including an extra file placed
/// under a directory the base image does not ship — are synthesized `0o755 root:root` below.
///
/// # Errors
/// Returns an error if reading the archive or generating the EROFS image fails.
#[cfg(feature = "am-fs-erofs")]
pub fn tar_to_erofs<'a, R: Read + 'a>(
    archives: impl IntoIterator<Item = tar::Archive<R>>,
    extra_files: Vec<InjectedFile<'_>>,
    injected_files: Vec<InjectedFile<'_>>,
    injected_symlinks: Vec<(&str, &str)>,
    require_libc6: bool,
) -> crate::error::Result<Vec<u8>> {
    let mut entries = build_node_map(archives, extra_files, injected_files, injected_symlinks)?;

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
                xattrs: vec![],
            },
        );
    }

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
        let image = tar_to_erofs(vec![archive], vec![], vec![], vec![], false);
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
        tar_to_erofs(vec![archive], vec![], vec![], vec![], require_libc6)
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
        let map = build_node_map(vec![archive], vec![], vec![], vec![]).expect("node map");

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
        let map = build_node_map(vec![a1, a2], vec![], vec![], vec![]).expect("node map");

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
        let map = build_node_map(vec![empty], vec![], injected, vec![]).expect("node map");
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

    // Accepted limitation (recorded): the packer does NOT preserve PAX SCHILY.xattr
    // records (including `security.capability`). The steward and every in-guest
    // `exec` run as root (design §4.2), so file capabilities are moot — preserving
    // them is forward work. This test PINS the current drop: it reddens the day xattr
    // passthrough is added without also updating the documented limitation, forcing a
    // conscious decision + doc/impl-notes reconciliation.
    #[test]
    fn test_pax_xattrs_are_not_preserved() {
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
        let archive = tar::Archive::new(std::io::Cursor::new(tar));
        let map = build_node_map(vec![archive], vec![], vec![], vec![]).expect("node map");
        match map.get(&normalize_path(Path::new("usr/bin/ping"))) {
            Some(Node::File { xattrs, .. }) => assert!(
                xattrs.is_empty(),
                "PAX SCHILY.xattr records are intentionally dropped (accepted limitation); \
                 if this now fails, xattr passthrough was added — update the recorded \
                 limitation + implementation-notes before flipping this assertion"
            ),
            other => panic!("expected a regular file node, got {other:?}"),
        }
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
        let entries = build_node_map(vec![archive], vec![], vec![], vec![]).expect("build");
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
                build_node_map(vec![archive], vec![], vec![], vec![]),
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
        let map = build_node_map(vec![a1, a2], vec![], injected_files, vec![]).expect("node map");

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
        let res = tar_to_erofs(vec![archive], vec![], vec![], vec![], false);
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
        for (label, header, entry_type) in cases {
            let tar_data = tar_with_entry(header, entry_type, "odd/member");
            let archive = tar::Archive::new(std::io::Cursor::new(tar_data));
            let err = build_node_map(vec![archive], vec![], vec![], vec![])
                .expect_err(&format!("{label} must be rejected, not silently dropped"));
            let crate::error::Error::Artifact(msg) = &err else {
                panic!("{label}: expected Error::Artifact, got {err:?}");
            };
            assert!(
                msg.contains("odd/member") && msg.contains("unsupported tar entry type"),
                "{label}: the refusal must name the member and the type, got: {msg}"
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
        let map = build_node_map(vec![archive], vec![], vec![], vec![])
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
