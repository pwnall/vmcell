//! Conversion of tar archives to EROFS images.
//!
//! This module provides an experimental utility for building an EROFS
//! filesystem directly from a tar archive for use as a root filesystem.

use fs_erofs::mkfs::{Node, NodeMeta, build_image};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Builds the flat `path -> Node` map from the injected files/symlinks and the given tar
/// archives, applying OCI whiteout semantics (`.wh.<name>` deletions and `.wh..wh..opq`
/// opaque-dir markers) as layers are merged in order.
///
/// Extracted from [`tar_to_erofs`] so the decode paths no gate sees — a device node's
/// `rdev` (which must be `makedev`-encoded, not a naive `(major<<8)|minor`) and the
/// whiteout deletions — are unit-testable (ART-4) by inspecting the resulting nodes
/// directly, rather than only through the opaque packed EROFS bytes.
///
/// # Errors
/// Returns [`crate::error::Error::Artifact`] if an injected file or an archive entry
/// cannot be read.
#[cfg(feature = "am-fs-erofs")]
fn build_node_map<'a, R: Read + 'a>(
    archives: impl IntoIterator<Item = tar::Archive<R>>,
    injected_files: Vec<(&str, &Path)>,
    injected_symlinks: Vec<(&str, &str)>,
) -> crate::error::Result<HashMap<PathBuf, Node>> {
    let mut entries: HashMap<PathBuf, Node> = HashMap::new();

    // NOTE: the injected files/symlinks (guest-agent, CA, guest-tools) are inserted AFTER
    // the layer merge below — see the tail of this function (H-ART-3 / design v17 §8.2:
    // "inject ... then stream the tree"). Injecting before the merge let an upper layer's
    // content or a `.wh.` whiteout silently clobber the baked agent or CA.

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
                _ => continue,
            };

            let file_name = path.file_name().unwrap_or_default().to_string_lossy();
            if let Some(target_name) = file_name.strip_prefix(".wh.") {
                if file_name == ".wh..wh..opq" {
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

    // Inject the agent/CA/guest-tools AFTER every layer is merged (H-ART-3 / design v17
    // §8.2: "inject ... then stream the tree"). Injecting last makes the injected files
    // authoritative: an upper layer's content or a `.wh.` whiteout can no longer clobber the
    // baked guest-agent or the CA under `usr/local/share/ca-certificates/`.
    for (dest_path, src_path) in injected_files {
        let content = std::fs::read(src_path).map_err(|e| {
            crate::error::Error::Artifact(format!(
                "Failed to read injected file {:?}: {}",
                src_path, e
            ))
        })?;
        let meta = NodeMeta {
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
        };
        let mode = 0o755 | fs_erofs::inode::S_IFREG;
        let node = Node::File {
            mode,
            data: content,
            meta,
            xattrs: vec![],
        };
        entries.insert(normalize_path(Path::new(dest_path)), node);
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

/// Converts a tar archive to an EROFS filesystem image.
///
/// # Errors
/// Returns an error if reading the archive or generating the EROFS image fails.
#[cfg(feature = "am-fs-erofs")]
pub fn tar_to_erofs<'a, R: Read + 'a>(
    archives: impl IntoIterator<Item = tar::Archive<R>>,
    injected_files: Vec<(&str, &Path)>,
    injected_symlinks: Vec<(&str, &str)>,
    require_libc6: bool,
) -> crate::error::Result<Vec<u8>> {
    let mut entries = build_node_map(archives, injected_files, injected_symlinks)?;

    // Fail loud on a base image without glibc (§7.1 / oci2erofs §8.2). One pass over the
    // merged path set for `libc.so.6` under any `lib*` dir (lib64, lib/<triple>, usr/lib...).
    // The default guest-agent is built `-C target-feature=+crt-static` (guest_agent stage),
    // so it does not itself need libc6 — but the guest-tools helper and every user `exec`
    // workload in the Debian rootfs do (L-ART-8). The static-musl agent path
    // (`--agent-musl`) also drops the guard (`require_libc6 = false`). This is a hard stop,
    // never a silent pack of a base that cannot run guest-tools / user workloads.
    if require_libc6
        && !entries
            .keys()
            .any(|p| p.file_name().is_some_and(|n| n == "libc.so.6"))
    {
        return Err(crate::error::Error::Artifact(
            "base image is missing libc6 (no `libc.so.6` found): the default guest-agent is \
             statically linked and does not need it, but the guest-tools helper and user exec \
             workloads do. Use a base that includes libc6, or supply a static-musl agent with \
             `--agent-musl`."
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

#[cfg(feature = "am-fs-erofs")]
fn normalize_path(path: &Path) -> PathBuf {
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
        // require_libc6=false: this packs an empty tar (no agent injected), so the
        // glibc-presence requirement does not apply.
        let image = tar_to_erofs(vec![archive], vec![], vec![], false);
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
        tar_to_erofs(vec![archive], vec![], vec![], require_libc6)
    }

    // oci2erofs §8.2 fail-loud guard. With `require_libc6=true`, a base that contains a
    // `libc.so.6` packs; a base that LACKS it must error (the default glibc agent would
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
        // --agent-musl path, which injects a static agent needing no glibc).
        assert!(
            pack_one("usr/bin/coreutils", false).is_ok(),
            "a libc6-less base must pack when require_libc6=false (static-musl agent)"
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
        let map = build_node_map(vec![archive], vec![], vec![]).expect("node map");

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
        let map = build_node_map(vec![a1, a2], vec![], vec![]).expect("node map");

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
        let entries = build_node_map(vec![archive], vec![], vec![]).expect("build");
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
                build_node_map(vec![archive], vec![], vec![]),
                Err(crate::error::Error::Artifact(_))
            ),
            "a hardlink to a missing target must still fail loud"
        );
    }

    // H-ART-3: injected files (agent/CA/tools) are merged as the TAIL, after all layers.
    // (1) A `.wh.` whiteout in an upper layer that deletes the CA dir must NOT remove the
    // injected CA. (2) A layer that carries the injected path with different content must be
    // overwritten by the injected file. The buggy inject-before-merge order reddens both.
    #[test]
    fn test_injection_survives_whiteout_and_layer_overwrite() {
        // A real file on disk for the injected CA.
        let dir = tempfile::tempdir().expect("tempdir");
        let ca = dir.path().join("ca.crt");
        std::fs::write(&ca, b"-----INJECTED-CA-----").unwrap();
        let agent = dir.path().join("agent");
        std::fs::write(&agent, b"INJECTED-AGENT").unwrap();

        // Lower layer: a base file, plus a guest-agent with DIFFERENT (stale) content.
        let mut lower = Vec::new();
        {
            let mut b = tar::Builder::new(&mut lower);
            append_file(&mut b, "etc/os-release", b"base");
            append_file(&mut b, "usr/sbin/vmcell-guest-agent", b"STALE-LAYER-AGENT");
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
            ),
            ("usr/sbin/vmcell-guest-agent", agent.as_path()),
        ];
        let map = build_node_map(vec![a1, a2], injected_files, vec![]).expect("node map");

        // (1) The injected CA survives the whiteout that deleted the CA dir.
        match map.get(Path::new("usr/local/share/ca-certificates/vmcell-ca.crt")) {
            Some(Node::File { data, .. }) => {
                assert_eq!(data, b"-----INJECTED-CA-----");
            }
            other => panic!("injected CA must survive an upper-layer whiteout, got {other:?}"),
        }
        // (2) The injected agent wins over the stale layer content.
        match map.get(Path::new("usr/sbin/vmcell-guest-agent")) {
            Some(Node::File { data, .. }) => {
                assert_eq!(
                    data, b"INJECTED-AGENT",
                    "the injected agent (tail) must overwrite the layer's stale agent"
                );
            }
            other => panic!("expected the injected agent file, got {other:?}"),
        }
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
        let res = tar_to_erofs(vec![archive], vec![], vec![], false);
        assert!(
            matches!(res, Err(crate::error::Error::Artifact(_))),
            "a child under a non-directory parent must fail loud (L-ART-6), got {res:?}"
        );
    }
}
