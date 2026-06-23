use std::path::PathBuf;

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct VmConfig {
    pub vcpus: u8,
    pub mem_mib: u32,
    pub kernel: PathBuf,
    pub rootfs: RootfsSource,
    pub shares: Vec<Share>,
    pub net: NetConfig,
    pub nested_virt: bool,
    pub limits: ResourceLimits,
    pub snapshot_dir: Option<PathBuf>,
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum RootfsSource {
    Erofs {
        image: PathBuf,
    },
    Block {
        image: PathBuf,
        overlay: Option<PathBuf>,
    },
    VirtioFs {
        dir: PathBuf,
    },
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Share {
    pub tag: String,
    pub host_path: PathBuf,
    pub access: Access,
    pub cache: CachePolicy,
}

impl Share {
    pub fn new(
        tag: impl Into<String>,
        host_path: impl Into<PathBuf>,
        access: Access,
        cache: CachePolicy,
    ) -> Self {
        Self {
            tag: tag.into(),
            host_path: host_path.into(),
            access,
            cache,
        }
    }
}

#[derive(Clone, Debug)]
pub enum Access {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Debug)]
pub enum CachePolicy {
    Never,
    Auto,
    Always,
}

#[derive(Clone, Debug, Default)]
pub enum NetConfig {
    Privileged {
        egress: Egress,
        host_services: bool,
    },
    Rootless {
        egress: Egress,
        host_services: bool,
    },
    #[default]
    None,
}

#[derive(Clone, Debug, Default)]
pub enum Egress {
    Filtered(ProxyConfig),
    Blocked,
    #[default]
    Open,
}

#[derive(Clone, Debug, Default)]
pub struct ProxyConfig {
    // Additional proxy config can go here
}

#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct ResourceLimits {
    pub mem_max_mib: Option<u32>,
    pub cpu_max_pct: Option<u32>,
    pub pids_max: Option<u32>,
    pub io_max: Option<IoMax>,
}

#[derive(Clone, Debug)]
pub struct IoMax {
    // TODO
}

impl VmConfig {
    pub fn builder(kernel: impl Into<PathBuf>, rootfs: RootfsSource) -> VmConfigBuilder {
        VmConfigBuilder {
            kernel: kernel.into(),
            rootfs,
            vcpus: 1,
            mem_mib: 128,
            shares: vec![],
            net: NetConfig::default(),
            nested_virt: false,
            limits: ResourceLimits::default(),
            snapshot_dir: None,
        }
    }
}

pub struct VmConfigBuilder {
    kernel: PathBuf,
    rootfs: RootfsSource,
    vcpus: u8,
    mem_mib: u32,
    shares: Vec<Share>,
    net: NetConfig,
    nested_virt: bool,
    limits: ResourceLimits,
    snapshot_dir: Option<PathBuf>,
}

impl VmConfigBuilder {
    pub fn with_share(mut self, share: Share) -> Self {
        self.shares.push(share);
        self
    }

    pub fn network_disabled(mut self) -> Self {
        self.net = NetConfig::None;
        self
    }

    pub fn build(self) -> VmConfig {
        VmConfig {
            kernel: self.kernel,
            rootfs: self.rootfs,
            vcpus: self.vcpus,
            mem_mib: self.mem_mib,
            shares: self.shares,
            net: self.net,
            nested_virt: self.nested_virt,
            limits: self.limits,
            snapshot_dir: self.snapshot_dir,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_builder_defaults() {
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::VirtioFs {
                dir: PathBuf::from("/rootfs"),
            },
        )
        .build();
        assert_eq!(cfg.vcpus, 1);
        assert_eq!(cfg.mem_mib, 128);
        assert!(!cfg.nested_virt);
    }
}
