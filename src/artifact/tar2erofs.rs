use fs_erofs::mkfs::{build_image, Node, NodeMeta};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};

#[cfg(feature = "experiment-erofs")]
pub fn tar_to_erofs(mut archive: tar::Archive<impl Read>) -> crate::error::Result<Vec<u8>> {
    let mut entries: HashMap<PathBuf, Node> = HashMap::new();

    for file in archive.entries().map_err(|e| crate::error::Error::Other(e.to_string()))? {
        let mut file = file.map_err(|e| crate::error::Error::Other(e.to_string()))?;
        let path = file.path().map_err(|e| crate::error::Error::Other(e.to_string()))?.into_owned();
        
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
                file.read_to_end(&mut data).map_err(|e| crate::error::Error::Other(e.to_string()))?;
                Node::File {
                    mode: mode | fs_erofs::inode::S_IFREG,
                    data,
                    meta,
                    xattrs: vec![],
                }
            },
            tar::EntryType::Directory => {
                Node::Dir {
                    mode: mode | fs_erofs::inode::S_IFDIR,
                    entries: BTreeMap::new(),
                    meta,
                    xattrs: vec![],
                }
            },
            tar::EntryType::Symlink => {
                let target = file.link_name().map_err(|e| crate::error::Error::Other(e.to_string()))?.unwrap_or_default().to_string_lossy().into_owned();
                Node::Symlink {
                    mode: mode | fs_erofs::inode::S_IFLNK,
                    target,
                    meta,
                    xattrs: vec![],
                }
            },
            tar::EntryType::Char => {
                let major = file.header().device_major().map_err(|e| crate::error::Error::Other(e.to_string()))?.unwrap_or(0) as u32;
                let minor = file.header().device_minor().map_err(|e| crate::error::Error::Other(e.to_string()))?.unwrap_or(0) as u32;
                Node::Device {
                    mode: mode | fs_erofs::inode::S_IFCHR,
                    rdev: (major << 8) | minor,
                    meta,
                    xattrs: vec![],
                }
            },
            tar::EntryType::Block => {
                let major = file.header().device_major().map_err(|e| crate::error::Error::Other(e.to_string()))?.unwrap_or(0) as u32;
                let minor = file.header().device_minor().map_err(|e| crate::error::Error::Other(e.to_string()))?.unwrap_or(0) as u32;
                Node::Device {
                    mode: mode | fs_erofs::inode::S_IFBLK,
                    rdev: (major << 8) | minor,
                    meta,
                    xattrs: vec![],
                }
            },
            tar::EntryType::Fifo => {
                Node::Special {
                    mode: mode | fs_erofs::inode::S_IFIFO,
                    meta,
                    xattrs: vec![],
                }
            },
            _ => continue,
        };
        
        let normalized_path = normalize_path(&path);
        entries.insert(normalized_path, node);
    }

    // Ensure all parent directories exist
    let paths: Vec<PathBuf> = entries.keys().cloned().collect();
    for path in paths {
        let mut parent: Option<&Path> = path.parent();
        while let Some(p) = parent {
            if p.as_os_str().is_empty() || p.to_string_lossy() == "." || p.to_string_lossy() == "/" {
                break;
            }
            if !entries.contains_key(p) {
                entries.insert(p.to_path_buf(), Node::Dir {
                    mode: 0o755 | fs_erofs::inode::S_IFDIR,
                    entries: BTreeMap::new(),
                    meta: NodeMeta { uid: 0, gid: 0, mtime: 0, mtime_nsec: 0 },
                    xattrs: vec![],
                });
            }
            parent = p.parent();
        }
    }

    // Add root if missing
    if !entries.contains_key(Path::new("")) {
        entries.insert(PathBuf::from(""), Node::Dir {
            mode: 0o755 | fs_erofs::inode::S_IFDIR,
            entries: BTreeMap::new(),
            meta: NodeMeta { uid: 0, gid: 0, mtime: 0, mtime_nsec: 0 },
            xattrs: vec![],
        });
    }

    let mut paths_sorted: Vec<PathBuf> = entries.keys().cloned().collect();
    paths_sorted.sort_by_key(|p: &PathBuf| std::cmp::Reverse(p.components().count()));

    for path in paths_sorted {
        if path.as_os_str().is_empty() {
            continue;
        }
        let node = entries.remove(&path).unwrap();
        let parent_path = path.parent().unwrap();
        if let Some(Node::Dir { entries: dir_entries, .. }) = entries.get_mut(parent_path) {
            dir_entries.insert(path.file_name().unwrap().to_string_lossy().into_owned(), node);
        }
    }

    let root_node = entries.remove(Path::new("")).unwrap();
    let image = build_image(root_node, 12).map_err(|e: fs_erofs::error::Error| crate::error::Error::Other(e.to_string()))?;
    
    Ok(image)
}

#[cfg(feature = "experiment-erofs")]
fn normalize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::Normal(c) => out.push(c),
            std::path::Component::ParentDir => { out.pop(); }
            _ => {}
        }
    }
    out
}
