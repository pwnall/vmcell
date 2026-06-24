use std::path::PathBuf;

pub fn get_vmlinux() -> Option<PathBuf> {
    let p = std::env::var("IMP_KERNEL")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/imp-artifacts/vmlinux"));
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

pub fn get_rootfs() -> Option<PathBuf> {
    let p = std::env::var("IMP_ROOTFS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/imp-artifacts/rootfs.erofs"));
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

pub fn ch_bin() -> String {
    std::env::var("IMP_CH_BIN").unwrap_or_else(|_| "cloud-hypervisor".to_string())
}
