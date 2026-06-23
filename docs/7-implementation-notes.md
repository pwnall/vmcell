# Implementation Notes

This document records the architectural findings, constraints, and solutions discovered during the implementation of the end-to-end testing infrastructure.

## 1. Kernel Boot & Disk I/O Constraints
- **Ext4 Journal Recovery on Read-Only Disks:** When booting micro-VMs with a read-only root filesystem via `virtio-blk`, the guest kernel's `ext4` driver attempts to recover the journal. This inherently involves disk writes, which fail (`EIO`) when the underlying block device is restricted. This failure causes a kernel panic (`Unable to mount root fs on unknown-block`).
  - **Solution:** Pass `ro rootflags=noload` via the kernel command line. This instructs the `ext4` driver to mount the filesystem strictly read-only without attempting journal recovery.

## 2. Test Concurrency & Artifact State
- **Shared Block Device Corruption:** Running concurrent `cargo test` threads utilizing the same underlying `rootfs.ext4` block image leads to fatal filesystem corruption, as `ext4` does not support multi-instance concurrent mounts.
  - **Solution:** The VMM Orchestrator (`src/orchestrator.rs`) must uniquely clone the base `rootfs.ext4` to a temporary path (e.g., `/tmp/imp-rootfs-{vmid}.ext4`) for each VM run when an overlay isn't provided.

## 3. Vsock Communication & Guest Agent Initialization
- **Kernel Vsock Support:** The custom kernel built from `kvm_guest.config` does not include `vsock` support by default. The `imp-guest-agent` will panic with `EAFNOSUPPORT` (`Address family not supported by protocol`) when attempting to bind to the `vsock` port.
  - **Solution:** Explicitly append `CONFIG_VSOCKETS=y`, `CONFIG_VIRTIO_VSOCKETS=y`, and `CONFIG_VHOST_VSOCK=y` to the kernel `microvm_config` to compile vsock support directly into the `vmlinux` image.
- **Guest Agent Deployment:** The `imp-guest-agent` binary must be compiled and actively injected into the rootfs. `mmdebstrap` provides an efficient mechanism for this via `--customize-hook=copy-in`.
- **Bypassing Systemd:** To speed up boot times and ensure the guest agent runs immediately, the kernel command line is set to `init=/sbin/imp-guest-agent`. This configures the agent to run directly as PID 1, where it takes responsibility for mounting `/sys`, `/proc`, and `virtiofs` shares.
- **Host-Guest Synchronization:** The host `AgentClient` connects to the Cloud Hypervisor `vsock.sock` Unix Domain Socket. However, Cloud Hypervisor accepts connections *before* the guest agent has fully booted and bound to the port. The host `AgentClient` must implement a resilient retry loop to avoid `Connection refused` errors.

## 4. Execution Environment: Network Namespaces & Cgroups
- **Root Requirements:** Integration tests that create network namespaces (`ip netns add`, `ip tuntap add`) and manipulate cgroup v2 limits (`cgroups-rs`) inherently require elevated privileges (`CAP_NET_ADMIN` and `CAP_SYS_ADMIN`).
- **Unprivileged Namespaces (Ubuntu Restrict):** While Linux supports unprivileged user namespaces (`unshare -U -n -r`), modern Ubuntu environments restrict this via AppArmor profiles (`kernel.apparmor_restrict_unprivileged_userns=1`), rendering rootless `netns` creation impossible out-of-the-box.
- **Options Investigated for CI/Local Execution:**
  1. **Privileged Runner (Standard):** Configure `.cargo/config.toml` with `runner = "sudo -E"` to run integration tests seamlessly with root.
  2. **User-Mode Networking:** Migrate from `tap` devices to user-mode networking daemons like `passt` or `slirp4netns` to bridge guest traffic unprivileged.
  3. **Cgroup Delegation:** For cgroups testing without root, systemd must explicitly delegate a cgroup subtree to the user session, and the orchestrator must target that specific slice path instead of root-level slices.
