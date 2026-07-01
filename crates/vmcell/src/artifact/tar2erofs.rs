//! Conversion of tar archives to EROFS images.
//!
//! This module provides an experimental utility for building an EROFS
//! filesystem directly from a tar archive for use as a root filesystem.

use fs_erofs::mkfs::{Node, NodeMeta, build_image};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};

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
    let mut entries: HashMap<PathBuf, Node> = HashMap::new();

    // Inject extra files
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

    // Inject symlinks (e.g. the guest test-helper's ip/curl/kvm-ok multicall links).
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

    // Fail loud on a base image without glibc when the injected agent is the default
    // (dynamic-glibc) build: it would die at PID 1 (§7.1 / oci2erofs §8.2). One pass over
    // the merged path set for `libc.so.6` under any `lib*` dir (lib64, lib/<triple>,
    // usr/lib...). The static-musl agent path (`--agent-musl`) needs no libc6 and sets
    // `require_libc6 = false`. This is a hard stop, never a silent pack of a base that
    // cannot run the agent.
    if require_libc6
        && !entries
            .keys()
            .any(|p| p.file_name().is_some_and(|n| n == "libc.so.6"))
    {
        return Err(crate::error::Error::Artifact(
            "base image is missing libc6 (no `libc.so.6` found): the default glibc guest-agent \
             would fail at PID 1. Use a base that includes libc6, or supply a static-musl agent \
             with `--agent-musl`."
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
        if let Some(Node::Dir {
            entries: dir_entries,
            ..
        }) = entries.get_mut(parent_path)
        {
            dir_entries.insert(
                path.file_name()
                    .ok_or_else(|| crate::error::Error::Artifact("No filename".into()))?
                    .to_string_lossy()
                    .into_owned(),
                node,
            );
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
}
