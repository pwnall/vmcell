//! Configuration models and builder for virtual machine instances.

use std::path::PathBuf;

/// Configuration for a virtual machine instance.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct VmConfig {
    /// Number of virtual CPUs to allocate.
    pub vcpus: u8,
    /// Amount of memory in MiB.
    pub mem_mib: u32,
    /// Path to the kernel image (vmlinux).
    pub kernel: PathBuf,
    /// Source for the root filesystem.
    pub rootfs: RootfsSource,
    /// Shared directories to expose to the VM.
    pub shares: Vec<Share>,
    /// Networking configuration.
    pub net: NetConfig,
    /// Whether to expose KVM for nested virtualization.
    pub nested_virt: bool,
    /// Cgroup resource limits for the VM and its processes.
    pub limits: ResourceLimits,
}

/// Options for the root filesystem backing the VM.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum RootfsSource {
    /// Read-only EROFS image. Shared across multiple VMs.
    Erofs {
        /// Path to the EROFS image file.
        image: PathBuf,
    },
    /// Writable or read-only block device image.
    Block {
        /// Base image file.
        image: PathBuf,
        /// Optional writable overlay file.
        overlay: Option<PathBuf>,
    },
    /// Root filesystem mounted via virtio-fs.
    VirtioFs {
        /// Path to the host directory serving as root.
        dir: PathBuf,
    },
}

/// A host directory shared with the guest VM via virtio-fs.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Share {
    /// The mount tag used by the guest to identify this share.
    pub tag: String,
    /// Path to the directory on the host.
    pub host_path: PathBuf,
    /// Access permissions for the guest.
    pub access: Access,
    /// Caching policy for the shared directory.
    pub cache: CachePolicy,
}

impl Share {
    /// Creates a new `Share` configuration.
    #[must_use]
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

/// Access level for a shared directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Access {
    /// Share is read-only.
    ReadOnly,
    /// Share is read-write.
    ReadWrite,
}

/// Cache policy for virtio-fs shares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CachePolicy {
    /// Never cache file contents in the guest.
    Never,
    /// Automatically cache based on standard filesystem rules.
    Auto,
    /// Always cache.
    Always,
}

/// Networking mode and configuration for the VM.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetConfig {
    /// Privileged mode using TAP and netns (requires root/CAP_NET_ADMIN).
    Privileged {
        /// Egress proxy configuration.
        egress: Egress,
        /// Whether host services are accessible from the guest.
        host_services: bool,
    },
    /// Rootless mode using passt or userspace networking.
    Rootless {
        /// Egress proxy configuration.
        egress: Egress,
        /// Whether host services are accessible from the guest.
        host_services: bool,
    },
    /// No networking configuration.
    #[default]
    None,
}

/// Egress filtering strategy for outbound network traffic.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Egress {
    /// Traffic is transparently routed through a proxy.
    Filtered(ProxyConfig),
    /// All egress traffic is blocked.
    Blocked,
    /// Egress traffic is allowed without interception.
    #[default]
    Open,
}

/// Configuration for the transparent proxy.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct ProxyConfig {
    /// Test doubles to intercept and mock requests.
    #[cfg(feature = "proxy")]
    pub doubles: std::sync::Arc<Vec<crate::proxy::doubles::TestDouble>>,
    /// Domains that should be blocked.
    pub blocked_domains: Vec<String>,
}

impl std::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyConfig").finish_non_exhaustive()
    }
}

impl PartialEq for ProxyConfig {
    fn eq(&self, _other: &Self) -> bool {
        let same_blocked = self.blocked_domains == _other.blocked_domains;
        #[cfg(feature = "proxy")]
        {
            same_blocked && std::sync::Arc::ptr_eq(&self.doubles, &_other.doubles)
        }
        #[cfg(not(feature = "proxy"))]
        {
            same_blocked
        }
    }
}

impl Eq for ProxyConfig {}

/// Resource limits enforced via cgroup v2.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct ResourceLimits {
    /// Maximum memory in MiB (`memory.max`).
    pub mem_max_mib: Option<u32>,
    /// CPU usage limit as a percentage (`cpu.max`).
    pub cpu_max_pct: Option<u32>,
    /// Maximum number of processes/threads (`pids.max`).
    pub pids_max: Option<u32>,
    /// I/O bandwidth/IOPS limits (`io.max`).
    pub io_max: Option<IoMax>,
}

/// I/O maximum limits mapping to `io.max`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct IoMax {
    // TODO
}

impl VmConfig {
    /// Creates a builder for `VmConfig` with required parameters.
    #[must_use]
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
        }
    }
}

/// A builder for constructing a `VmConfig`.
pub struct VmConfigBuilder {
    kernel: PathBuf,
    rootfs: RootfsSource,
    vcpus: u8,
    mem_mib: u32,
    shares: Vec<Share>,
    net: NetConfig,
    nested_virt: bool,
    limits: ResourceLimits,
}

impl VmConfigBuilder {
    /// Adds a shared directory.
    pub fn with_share(mut self, share: Share) -> Self {
        self.shares.push(share);
        self
    }

    /// Sets the number of virtual CPUs.
    pub fn vcpus(mut self, vcpus: u8) -> Self {
        self.vcpus = vcpus;
        self
    }

    /// Sets the memory size in MiB.
    pub fn mem_mib(mut self, mem_mib: u32) -> Self {
        self.mem_mib = mem_mib;
        self
    }

    /// Sets the networking configuration.
    pub fn net(mut self, net: NetConfig) -> Self {
        self.net = net;
        self
    }

    /// Enables or disables nested virtualization.
    pub fn nested_virt(mut self, nested_virt: bool) -> Self {
        self.nested_virt = nested_virt;
        self
    }

    /// Sets the cgroup resource limits.
    pub fn limits(mut self, limits: ResourceLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Disables network access.
    pub fn network_disabled(mut self) -> Self {
        self.net = NetConfig::None;
        self
    }

    /// Builds the final `VmConfig`.
    ///
    /// # Errors
    /// Returns an error if the kernel or rootfs paths do not exist.
    ///
    /// # Examples
    /// ```rust
    /// use imp_testing::config::{VmConfig, RootfsSource};
    /// let cfg = VmConfig::builder("/path/to/kernel", RootfsSource::Erofs { image: "/path/to/rootfs".into() })
    ///     .vcpus(4)
    ///     .mem_mib(2048)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn build(self) -> Result<VmConfig, crate::error::Error> {
        if self.vcpus == 0 {
            return Err(crate::error::Error::Config("vcpus must be > 0".into()));
        }
        if self.mem_mib < 64 {
            return Err(crate::error::Error::Config("mem_mib must be >= 64".into()));
        }
        if self.kernel.as_os_str().is_empty() {
            return Err(crate::error::Error::Config(
                "kernel path cannot be empty".into(),
            ));
        }

        let mut tags = std::collections::HashSet::new();
        for share in &self.shares {
            if share.tag.is_empty() {
                return Err(crate::error::Error::Config(
                    "share tag cannot be empty".into(),
                ));
            }
            if !tags.insert(share.tag.clone()) {
                return Err(crate::error::Error::Config(format!(
                    "duplicate share tag: {}",
                    share.tag
                )));
            }
        }

        Ok(VmConfig {
            kernel: self.kernel,
            rootfs: self.rootfs,
            vcpus: self.vcpus,
            mem_mib: self.mem_mib,
            shares: self.shares,
            net: self.net,
            nested_virt: self.nested_virt,
            limits: self.limits,
        })
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
        .build()
        .unwrap();
        assert_eq!(cfg.vcpus, 1);
        assert_eq!(cfg.mem_mib, 128);
        assert!(!cfg.nested_virt);
    }

    #[test]
    fn test_builder_methods() {
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::VirtioFs {
                dir: PathBuf::from("/rootfs"),
            },
        )
        .with_share(Share::new(
            "test",
            "/tmp/test",
            Access::ReadOnly,
            CachePolicy::Auto,
        ))
        .network_disabled()
        .build()
        .unwrap();

        assert_eq!(cfg.shares.len(), 1);
        assert_eq!(cfg.shares[0].tag, "test");
        assert!(matches!(cfg.net, NetConfig::None));
    }
}
