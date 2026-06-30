//! Configuration models and builder for virtual machine instances.

#![forbid(unsafe_code)]

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
    /// Indicates if this VM is configured to be snapshot-eligible.
    pub snapshotting: bool,
    /// Optional explicitly-configured VMID.
    pub vmid: Option<u32>,
    /// Memory-restore strategy applied on the snapshot-restore path.
    pub restore_mode: RestoreMode,
    /// Mark guest memory `MADV_MERGEABLE` so host KSM can deduplicate identical
    /// guest pages (CH `mergeable=on`). KSM only merges private-anonymous pages,
    /// so enabling this also disables memory sharing (`shared=off`), making it
    /// incompatible with vhost-user paths (rootless net, virtio-fs). A
    /// density-vs-CPU trade measured in §13.5.
    pub ksm_mergeable: bool,
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

/// Memory-restore strategy for snapshot restore (Cloud Hypervisor `prefault`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum RestoreMode {
    /// The VMM's default (CH: lazy/demand-paged).
    #[default]
    Default,
    /// Eagerly fault all guest memory at restore (`prefault=on`).
    Eager,
    /// Lazily demand-page guest memory (`prefault=off`, userfaultfd).
    Lazy,
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
        /// Optional port for host services accessible from the guest.
        host_services_port: Option<u16>,
    },
    /// Rootless mode using passt or userspace networking.
    Rootless {
        /// Egress proxy configuration.
        egress: Egress,
        /// Optional port for host services accessible from the guest.
        host_services_port: Option<u16>,
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
    pub doubles: std::sync::Arc<std::sync::RwLock<Vec<crate::proxy::doubles::TestDouble>>>,
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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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
    /// Device node string, e.g., "8:0" or "254:0"
    pub device: String,
    /// Read bandwidth max in bytes per second
    pub rbps: Option<u64>,
    /// Write bandwidth max in bytes per second
    pub wbps: Option<u64>,
    /// Read IOPS max
    pub riops: Option<u64>,
    /// Write IOPS max
    pub wiops: Option<u64>,
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
            snapshotting: false,
            vmid: None,
            restore_mode: RestoreMode::Default,
            ksm_mergeable: false,
        }
    }
}

/// A builder for constructing a `VmConfig`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VmConfigBuilder {
    kernel: PathBuf,
    rootfs: RootfsSource,
    vcpus: u8,
    mem_mib: u32,
    shares: Vec<Share>,
    net: NetConfig,
    nested_virt: bool,
    limits: ResourceLimits,
    snapshotting: bool,
    vmid: Option<u32>,
    restore_mode: RestoreMode,
    ksm_mergeable: bool,
}

impl VmConfigBuilder {
    /// Adds a shared directory.
    #[must_use]
    pub fn with_share(mut self, share: Share) -> Self {
        self.shares.push(share);
        self
    }

    /// Sets the number of virtual CPUs.
    #[must_use]
    pub fn vcpus(mut self, vcpus: u8) -> Self {
        self.vcpus = vcpus;
        self
    }

    /// Sets the memory size in MiB.
    #[must_use]
    pub fn mem_mib(mut self, mem_mib: u32) -> Self {
        self.mem_mib = mem_mib;
        self
    }

    /// Sets the networking configuration.
    #[must_use]
    pub fn net(mut self, net: NetConfig) -> Self {
        self.net = net;
        self
    }

    /// Enables or disables nested virtualization.
    #[must_use]
    pub fn nested_virt(mut self, nested_virt: bool) -> Self {
        self.nested_virt = nested_virt;
        self
    }

    /// Sets the cgroup resource limits.
    #[must_use]
    pub fn limits(mut self, limits: ResourceLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Sets whether the VM is expected to be snapshot-eligible.
    #[must_use]
    pub fn snapshotting(mut self, snapshotting: bool) -> Self {
        self.snapshotting = snapshotting;
        self
    }

    /// Explicitly sets the VMID for validation.
    #[must_use]
    pub fn vmid(mut self, vmid: u32) -> Self {
        self.vmid = Some(vmid);
        self
    }

    /// Sets the memory-restore strategy used on the snapshot-restore path.
    #[must_use]
    pub fn restore_mode(mut self, mode: RestoreMode) -> Self {
        self.restore_mode = mode;
        self
    }

    /// Enables KSM-mergeable (private-anonymous) guest memory (§13.5). See
    /// [`VmConfig::ksm_mergeable`] for the sharing trade-off.
    #[must_use]
    pub fn ksm_mergeable(mut self, mergeable: bool) -> Self {
        self.ksm_mergeable = mergeable;
        self
    }

    /// Disables network access.
    #[must_use]
    pub fn network_disabled(mut self) -> Self {
        self.net = NetConfig::None;
        self
    }

    /// Builds the final [`VmConfig`], validating its internal consistency.
    ///
    /// # Errors
    /// Returns [`Error::Config`](crate::error::Error::Config) when the
    /// configuration is internally inconsistent. The validations performed are:
    /// - `vcpus == 0` (at least one vCPU is required);
    /// - `mem_mib` below the 64 MiB floor;
    /// - an empty kernel path;
    /// - an explicit `vmid` outside the `1..=254` window used by the `/30`
    ///   host-IP math;
    /// - a share with an empty mount tag, or two shares sharing a mount tag;
    /// - `snapshotting` combined with any vhost-user device — a virtio-fs
    ///   rootfs, any virtio-fs data share, or rootless (vhost-user-net)
    ///   networking — which violates the §3.3 snapshot-eligibility law;
    /// - `ksm_mergeable` combined with any vhost-user device (it sets CH
    ///   `shared=off`, mutually exclusive with the vhost-user paths — §13.5).
    ///
    /// This validates internal consistency only; it does **not** check that the
    /// kernel, rootfs, or share paths exist on disk.
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

        if self.snapshotting {
            if let RootfsSource::VirtioFs { .. } = self.rootfs {
                return Err(crate::error::Error::Config(
                    "virtio-fs rootfs cannot be combined with snapshotting".into(),
                ));
            }
            // Snapshot-eligibility law: a snapshot-eligible VM must have no
            // vhost-user device attached. A virtio-fs data `Share` is served
            // by virtiofsd (a vhost-user device), so reject it here as well as
            // for the virtio-fs *rootfs* above.
            if !self.shares.is_empty() {
                return Err(crate::error::Error::Config(
                    "virtio-fs data shares cannot be combined with snapshotting".into(),
                ));
            }
            // Snapshot-eligibility law (§3.3), third boundary case: the rootless
            // network path is an in-process vhost-user-net device, so it is
            // mutually exclusive with snapshotting just like virtiofsd above.
            if matches!(self.net, NetConfig::Rootless { .. }) {
                return Err(crate::error::Error::Config(
                    "rootless (vhost-user-net) networking cannot be combined with snapshotting"
                        .into(),
                ));
            }
        }

        // §13.5 KSM lever: `ksm_mergeable` sets CH `mergeable=on, shared=off`,
        // and KSM only merges private-anonymous pages — so `shared=off` is
        // mutually exclusive with every vhost-user path. Enforce here (boundary
        // 1) so an invalid combination never becomes a `VmConfig` and instead
        // fails late at the backend, which sets `shared: !ksm_mergeable` while
        // still attaching the vhost-user device.
        if self.ksm_mergeable {
            if let RootfsSource::VirtioFs { .. } = self.rootfs {
                return Err(crate::error::Error::Config(
                    "ksm_mergeable cannot be combined with a virtio-fs rootfs (vhost-user)".into(),
                ));
            }
            if !self.shares.is_empty() {
                return Err(crate::error::Error::Config(
                    "ksm_mergeable cannot be combined with virtio-fs data shares (vhost-user)"
                        .into(),
                ));
            }
            if matches!(self.net, NetConfig::Rootless { .. }) {
                return Err(crate::error::Error::Config(
                    "ksm_mergeable cannot be combined with rootless (vhost-user-net) networking"
                        .into(),
                ));
            }
        }

        if let Some(vmid) = self.vmid {
            if vmid == 0 {
                return Err(crate::error::Error::Config("vmid must be >= 1".into()));
            }
            if vmid > 254 {
                return Err(crate::error::Error::Config("vmid must be <= 254".into()));
            }
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
            snapshotting: self.snapshotting,
            vmid: self.vmid,
            restore_mode: self.restore_mode,
            ksm_mergeable: self.ksm_mergeable,
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

    // Guards the §13.3 eager-vs-lazy restore toggle: the builder must carry the
    // selected `RestoreMode` onto the built config, and default to `Default`.
    // Buggy impl: builder drops the field (always `Default`) — the `Eager`
    // assertion below would then fail.
    #[test]
    fn test_builder_restore_mode() {
        let default_cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .build()
        .unwrap();
        assert_eq!(default_cfg.restore_mode, RestoreMode::Default);

        let eager_cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .restore_mode(RestoreMode::Eager)
        .build()
        .unwrap();
        assert_eq!(eager_cfg.restore_mode, RestoreMode::Eager);
        assert_ne!(eager_cfg.restore_mode, RestoreMode::Default);
    }

    // Guards the §13.5 KSM density lever: the builder must carry `ksm_mergeable`
    // onto the built config and default to `false` (so normal VMs keep shared
    // memory). Buggy impl: builder drops the field — the `true` assertion fails.
    #[test]
    fn test_builder_ksm_mergeable() {
        let mk = |mergeable: bool| {
            VmConfig::builder(
                PathBuf::from("/vmlinux"),
                RootfsSource::Erofs {
                    image: PathBuf::from("/rootfs.erofs"),
                },
            )
            .ksm_mergeable(mergeable)
            .build()
            .unwrap()
        };
        assert!(!mk(false).ksm_mergeable);
        assert!(mk(true).ksm_mergeable);
        // Default (builder untouched) must be false.
        let default_cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .build()
        .unwrap();
        assert!(!default_cfg.ksm_mergeable);
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

    #[test]
    fn test_reject_virtio_fs_snapshot() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::VirtioFs {
                dir: PathBuf::from("/rootfs"),
            },
        )
        .snapshotting(true)
        .build()
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("virtio-fs rootfs cannot be combined with snapshotting")
        );
    }

    #[test]
    fn test_reject_out_of_range_vmid() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .vmid(255)
        .build()
        .unwrap_err();
        assert!(err.to_string().contains("vmid must be <= 254"));
    }

    // Guards C1 / snapshot-eligibility law. Buggy impl: build() only rejects a
    // virtio-fs *rootfs* + snapshot and lets a data `Share` (served by
    // virtiofsd, a vhost-user device) through on the snapshot path.
    #[test]
    fn test_reject_shares_with_snapshot() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .with_share(Share::new(
            "data",
            "/tmp/data",
            Access::ReadOnly,
            CachePolicy::Auto,
        ))
        .snapshotting(true)
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(
            err.to_string()
                .contains("virtio-fs data shares cannot be combined with snapshotting"),
            "unexpected error: {err}"
        );
    }

    // Buggy impl: build() accepts vmid == 0, which is out of range for the /30
    // host-IP math.
    #[test]
    fn test_reject_zero_vmid() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .vmid(0)
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(err.to_string().contains("vmid must be >= 1"));
    }

    // Buggy impl: build() does not reject vcpus == 0.
    #[test]
    fn test_reject_zero_vcpus() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .vcpus(0)
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(err.to_string().contains("vcpus must be > 0"));
    }

    // Buggy impl: build() does not enforce the memory floor.
    #[test]
    fn test_reject_mem_below_floor() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .mem_mib(32)
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(err.to_string().contains("mem_mib must be >= 64"));
    }

    // Buggy impl: build() accepts an empty kernel path.
    #[test]
    fn test_reject_empty_kernel() {
        let err = VmConfig::builder(
            PathBuf::from(""),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(err.to_string().contains("kernel path cannot be empty"));
    }

    // Buggy impl: build() does not reject two shares with the same mount tag.
    #[test]
    fn test_reject_duplicate_share_tags() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .with_share(Share::new(
            "dup",
            "/tmp/a",
            Access::ReadOnly,
            CachePolicy::Auto,
        ))
        .with_share(Share::new(
            "dup",
            "/tmp/b",
            Access::ReadOnly,
            CachePolicy::Auto,
        ))
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(err.to_string().contains("duplicate share tag: dup"));
    }

    // M-RESTORE-3: the §3.3 snapshot-eligibility law's third boundary case.
    // Buggy impl: build() rejects snapshot + virtio-fs rootfs and snapshot +
    // data share but lets the rootless vhost-user-net path through, so this VM
    // would reach the backend and fail late attaching a vhost-user device.
    #[test]
    fn test_reject_rootless_net_with_snapshot() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .net(NetConfig::Rootless {
            egress: Egress::Open,
            host_services_port: None,
        })
        .snapshotting(true)
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(
            err.to_string().contains(
                "rootless (vhost-user-net) networking cannot be combined with snapshotting"
            ),
            "unexpected error: {err}"
        );
    }

    // M-RESTORE-3 positive guard: the privileged tap path is NOT a vhost-user
    // device, so snapshot + Privileged net must still build. An over-broad
    // impl that rejects every net mode on the snapshot path turns this red
    // (the over-block smell AGENTS.md warns about).
    #[test]
    fn test_accept_snapshot_with_privileged_net() {
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .net(NetConfig::Privileged {
            egress: Egress::Open,
            host_services_port: None,
        })
        .snapshotting(true)
        .build()
        .unwrap();
        assert!(cfg.snapshotting);
        assert!(matches!(cfg.net, NetConfig::Privileged { .. }));
    }

    // M-CONFIG-1: ksm_mergeable (CH shared=off) is mutually exclusive with a
    // virtio-fs rootfs (virtiofsd, a vhost-user device). Buggy impl: build()
    // accepts the combination and it fails late at the VMM.
    #[test]
    fn test_reject_ksm_mergeable_with_virtio_fs_rootfs() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::VirtioFs {
                dir: PathBuf::from("/rootfs"),
            },
        )
        .ksm_mergeable(true)
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(
            err.to_string()
                .contains("ksm_mergeable cannot be combined with a virtio-fs rootfs"),
            "unexpected error: {err}"
        );
    }

    // M-CONFIG-1: ksm_mergeable is mutually exclusive with a virtio-fs data
    // share (virtiofsd, a vhost-user device).
    #[test]
    fn test_reject_ksm_mergeable_with_data_share() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .with_share(Share::new(
            "data",
            "/tmp/data",
            Access::ReadOnly,
            CachePolicy::Auto,
        ))
        .ksm_mergeable(true)
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(
            err.to_string()
                .contains("ksm_mergeable cannot be combined with virtio-fs data shares"),
            "unexpected error: {err}"
        );
    }

    // M-CONFIG-1: ksm_mergeable is mutually exclusive with rootless
    // vhost-user-net networking.
    #[test]
    fn test_reject_ksm_mergeable_with_rootless_net() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .net(NetConfig::Rootless {
            egress: Egress::Open,
            host_services_port: None,
        })
        .ksm_mergeable(true)
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(
            err.to_string()
                .contains("ksm_mergeable cannot be combined with rootless"),
            "unexpected error: {err}"
        );
    }

    // M-CONFIG-1 positive guard: ksm_mergeable with NO vhost-user device (erofs
    // rootfs over virtio-blk, privileged tap net, no shares) is the supported
    // density combination and must still build. An impl that rejects every
    // ksm_mergeable config turns this red (over-block smell).
    #[test]
    fn test_accept_ksm_mergeable_without_vhost_user() {
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .net(NetConfig::Privileged {
            egress: Egress::Open,
            host_services_port: None,
        })
        .ksm_mergeable(true)
        .build()
        .unwrap();
        assert!(cfg.ksm_mergeable);
    }
}
