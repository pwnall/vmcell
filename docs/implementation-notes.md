# Implementation Notes

## Rootless Networking and Passt (`vhost-user` issue)
- We attempted to use `passt` for rootless networking with `cloud-hypervisor` via `--net vhost_user=true`.
- However, `passt` fundamentally crashes during the `vhost-user` socket connection phase. A system call trace (`strace`) reveals that `passt`'s strict `seccomp` sandbox drops the `accept4` syscall (used to accept the connection from `cloud-hypervisor`) with `EACCES` (Permission denied). This immediately cascades into `epoll` errors (`Failed to add fd to epoll: Bad file descriptor`).
- Since `passt` is written in C and does not provide an option to disable its seccomp profile, it is incompatible with `cloud-hypervisor` in this setup.
- **Resolution:** To achieve rootless networking, we successfully implemented **Experiment 5** from the design doc: a pure-Rust userspace network NAT using the `vhost-user-backend` and `smoltcp` crates.
- **Smoltcp Implementation Details:**
  - **MAC Collisions:** `smoltcp` will silently drop packets if the Ethernet destination MAC is Broadcast but the Source MAC happens to equal the `smoltcp` interface's configured MAC. To avoid a collision with the guest's MAC (which is derived from the `vmid`), we statically assign the host's `smoltcp` MAC to `02:00:00:00:00:fe`.
  - **RX Queue Iteration:** When polling `smoltcp` in the background thread, it processes packets and pushes replies (like ARP and SYN-ACKs) into an `rx_queue`. The virtio RX queue descriptor chain must *only* be iterated if we actually have packets in the `rx_queue` ready to send to the guest. Iterating `vring_state.get_queue_mut().iter()` automatically consumes and advances the `avail_idx` pointer; doing this when `rx_queue` is empty effectively drops all of the guest's provided RX buffers, permanently breaking the connection.
  - **Notifications:** We must call `vring_state.enable_notification()` for the `TX` queue inside the `vhost-user-backend` `handle_event` loop so the guest agent knows when to kick the eventfd for subsequent packets.
- With these fixes, the integration tests `test_egress_proxy.rs` and `test_host_endpoint.rs` now run successfully without requiring `sudo` or TAP interfaces.
## Rootless Cgroup v2 Delegation
- To enforce memory and CPU limits unprivileged, we must nest the per-VM cgroups inside the test runner's current systemd delegated cgroup slice.
- `cgroups-rs`'s `CgroupBuilder` defaults to creating cgroups at the root (`/sys/fs/cgroup/imp-vm-XXX`), which fails with `Permission denied` without root.
- **Resolution:** We updated the `orchestrator` to read `/proc/self/cgroup` and dynamically construct a nested path for the VM's cgroup.
- **Cgroup v2 Constraints:** The kernel enforces a "no internal processes" rule: a cgroup can either have processes or distribute resources to children (by enabling controllers in `cgroup.subtree_control`), but not both. Because the test runner (`cargo test`) itself constitutes an internal process within its parent scope, we cannot easily enable `memory` or `cpu` controllers for child cgroups created directly underneath it. To bypass this for testing environments where we manually moved the agent to a `supervisor` sibling, we strip the `/supervisor` suffix from the path when creating the VM cgroup, ensuring it gets created as a sibling with full controller access.
- **cgroups-rs Limitations:** `cgroups-rs`'s `Cgroup::load().add_task()` throws a `CgroupMode` error when attempting to add processes to deeply nested unprivileged cgroups. To avoid this and a subsequent test-hanging panic, we directly write the PID via `std::fs::write(cgroup.procs)`.
- **Missing Memory Delegations (Ubuntu 26.04):** Even on modern systems with fairly new software (e.g., Ubuntu 26.04), we observed that the sandbox or test environment might not fully delegate the `memory` controller to unprivileged users or test runners by default. As a result, attempts to set `memory.high` or similar limits within the delegated nested cgroups can fail with "Operation not supported" or "No such file or directory". This limitation is an environment issue rather than an implementation flaw, and the codebase correctly attempts to configure the delegated cgroup as specified in the architecture design.

## Subprocess and virtiofsd Fixes
- When falling back to the external `virtiofsd` binary (when `experiment-fuse` is disabled), passing `--read-only` crashes the subprocess (`error: unexpected argument '--read-only' found. tip: a similar argument exists: '--readonly'`).
- Since `std::process::Command` errors aren't surfaced automatically if the parent process merely polls for the socket's existence, `cloud-hypervisor` hangs indefinitely waiting for `virtiofsd`'s vhost-user socket.
- **Resolution:** We corrected the flag to `--readonly` and added robust timeout error handling when waiting for the socket file to exist.

## Snapshot and Restore
- `cloud-hypervisor`'s `/api/v1/vm.snapshot` API requires the VM to be paused first using `/api/v1/vm.pause`. Resuming after snapshot with `/api/v1/vm.resume` is not strictly necessary if the VM is immediately shut down, but is generally good practice.
- When a VM is restored from a snapshot (via `--restore source_url=file:///...`), the guest's state is fully resumed. The VM does NOT require an explicit `/api/v1/vm.create` or `/api/v1/vm.boot` API call. Trying to boot a restored VM returns a `500 VM is already created` error from `cloud-hypervisor`.
- Instead, for restored VMs, we just call `/api/v1/vm.resume` to ensure execution continues.

## Guest Agent Vsock Connection
- When the VM is snapshotted and restored, the original vsock connection (between the host test runner and the guest agent) is severed because the host-side `vhost-vsock` device is re-created with a new socket.
- As a result, the guest agent receives an EOF on the vsock stream.
- The guest agent's connection handling loop must properly detect this EOF and exit the `handle_connection` loop so that it can `accept` a new connection from the test runner after the restore completes.
- We switched the guest agent serialization to use `postcard` consistently with the host, ensuring length-delimited framing works correctly.

## Dependencies
- `mmdebstrap` uses `dash` by default on Ubuntu, but `dash` fails. Setting `SHELL=/bin/bash` in the environment works around this limitation.
- It's also important to ensure `/bin/sh` points to `/bin/bash` when using `mmdebstrap` directly without `SHELL` environment overrides. The `imp-testing build` script explicitly checks for this symlink and halts execution if it's not configured correctly.

## Rootfs and EROFS
- `mkfs.erofs` is used to build the root filesystem. The kernel needs `CONFIG_EROFS_FS=y` built-in, otherwise it panics when attempting to mount the rootfs.
- If `imp-guest-agent` is dynamically linked in the EROFS image, it will work because `mmdebstrap` via `minbase` installs `libc6`. Attempting to statically link against `musl` requires `musl-tools` installed on the host, which is not available without root on some test environments.

## Architectural Experiments
- **Experiment 2 (Pure-Rust Nftables):** Skipped. The goal was to replace the `iptables` / `nft` CLI invocations with a pure-Rust implementation using permissive crates. `jip-nftables` was evaluated but only provides read capabilities. `rustables` provides write capabilities but is GPLv3 licensed, disqualifying it. Writing complex netlink payloads from scratch for a tiny ruleset was deemed unjustified.
- **Experiment 3 (Pure-Rust EROFS Build):** Successfully implemented. Replaced the `mkfs.erofs` shell-out with the `am-fs-erofs` crate. The `mmdebstrap` output is streamed directly into a custom `tar_to_erofs` in-memory parser, which converts the tar entries into an `am-fs-erofs` `Node` tree and compiles the image. This bypasses the host filesystem entirely, avoiding permission issues with creating device nodes or setting root uids as a non-root user.
- **Experiment 4 (OCI-image rootfs):** Skipped. Postponed to preserve the `apt` signing chain verification provided by Debian's `mmdebstrap`.

## Design Deviations and Quality Improvements
- **CidAllocator:** Originally, the CID for `vhost-vsock` was hardcoded to `3`. We have introduced a thread-safe `CidAllocator` in `vmm/mod.rs` that dynamically increments and allocates guest CIDs, resolving port conflicts and complying with the design requirement to support concurrent testing.
- **Pause/Resume support:** To ensure safety across checkpoints, we added explicit `pause()` and `resume()` lifecycle hooks to the `VmInstance` trait and correctly wired them to the Cloud Hypervisor REST API.
- **Documentation and Rust API Guidelines:** `#![deny(missing_docs)]` and `#![deny(clippy::missing_errors_doc)]` were added to the crate root to ensure comprehensive documentation. We documented all structs, traits, properties, and methods in the framework, adhering strictly to the Rust API Guidelines.
- **Iptables REDIRECT instead of Nftables TPROXY:** The design originally called for `nft` TPROXY to intercept egress traffic transparently. However, `iptables` REDIRECT rule (`-j REDIRECT --to-ports`) is used instead for simplicity as it relies on fewer kernel dependencies and is easier to invoke directly from the test orchestrator.
- **Guest Agent Networking Setup:** The design document suggested that the agent should not be responsible for networking setup. Currently, `imp-guest-agent` still actively configures its own network (e.g., setting IP, creating routes, and resolving DNS). This deviation was kept to minimize boot-time dependency on host-driven configuration.
- **wget instead of reqwest:** We use the system `wget` rather than compiling `reqwest` into the orchestrator for downloading kernel sources to reduce the dependency graph size and compilation times.
- **DefaultHasher instead of blake3:** We opted for `std::collections::hash_map::DefaultHasher` instead of `blake3` for caching keys (`cache_key`) to avoid pulling in external cryptographic dependencies for simple cache busting.
- **Pipeline Caching Stubs:** The `StageOutputs` and `StageInputs` for artifact building are currently empty stubs, meaning the cache keys are calculated but the artifact build steps run unconditionally in some setups.
- **No HTTPS/MITM Proxy Support:** Currently, only HTTP proxy interception is fully implemented in the integration tests. HTTPS MITM via custom CA generation is not yet supported in the orchestrator.

## Code Review Bug Findings & Fixes
- **Unsafe setns Syscalls:** The raw `libc::setns` syscalls in the test orchestrator lacked documentation and safety comments. These have been hardened with `Result` mappings to propagate errors gracefully, avoiding unexpected thread crashes.
- **Guest Agent `SIGTERM` Ignoring:** The `imp-guest-agent` registered a `SIGTERM` handler flag but immediately exited its main loop instead of gracefully waiting. This was fixed by utilizing `term.load()` properly inside a long-running event loop.
- **cgroups-rs Panic on Missing Controllers:** In environments where `memory` controllers are not delegated to the test runner slice, calling `m.memory_stat()` via `cgroups-rs` panicked (as `memory.high` is absent). This was bypassed by reading `memory.current` and `memory.peak` from `sysfs` manually to maintain robustness across constrained environments.
- **VMID Generation Collision:** `TestVm::vmid` generation originally utilized a raw atomic addition combined with PID multiplication, which occasionally produced VMIDs > 255. Because these IDs were substituted into IPv4 octets (`10.200.<vmid>.1`), it generated invalid IPs. This was fixed by wrapping the atomic counter specifically within `(c % 254) + 1`.
- **Guest Agent `EINTR` Race Condition:** The agent's `exec` handler was occasionally dropping stdout/stderr chunks due to a subtle race condition when the `std::process::Child` exited. `SIGCHLD` signals interrupted the blocking `read` syscalls on the pipe, returning `EINTR`, which our loop mistakenly treated as a fatal read error. We resolved this by explicitly handling `ErrorKind::Interrupted` and tightly joining the output reader threads before signaling completion.
