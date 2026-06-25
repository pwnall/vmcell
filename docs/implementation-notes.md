# Implementation Notes

This document captures the rationale behind key architectural decisions and non-obvious implementations in the current codebase.

## VMM Backends
### Cloud Hypervisor
- **Snapshot/Restore:** The `/api/v1/vm.snapshot` API requires the VM to be paused first using `/api/v1/vm.pause`. When a VM is restored from a snapshot (via `--restore source_url=file:///...`), the guest's state is fully resumed. The VM does NOT require an explicit `/api/v1/vm.create` or `/api/v1/vm.boot` API call. Trying to boot a restored VM returns a `500 VM is already created` error. We just call `/api/v1/vm.resume`.
- **Clock Resync on Restore:** When a VM is restored from a snapshot, Cloud Hypervisor restores the RTC to the exact time of the snapshot. Because the `snapshot_restore` test runs with networking disabled (precluding NTP), we manually fetch the host's `SystemTime::now()` and inject it via `date -s` over the guest agent connection.

### Firecracker
- **Virtio MMIO & Snapshotting:** The guest kernel is configured with `CONFIG_VIRTIO_MMIO=y`, and Firecracker runs in its native MMIO mode (without the `--enable-pci` flag). Because of this, Firecracker's snapshot/restore capability is fully supported.
- **REST API:** Instead of relying on an external SDK (like `firecracker-rs-sdk`), we implement the REST client manually using `hyper` over Unix domain sockets.
- **Boot Sequence:** Firecracker requires multiple sequential `PUT` API calls to endpoints like `/machine-config`, `/boot-source`, `/drives/rootfs`, `/network-interfaces/eth0`, `/vsock`, and `/logger` before calling `PUT /actions` with `InstanceStart` to boot.
- **FPU XSAVE limitation:** Firecracker snapshot/restore tests can panic during restore (`restore_fpregs_from_fpstate`) if the guest environment (like Ubuntu 24.04's libc) aggressively utilizes highly optimized `glibc` AVX instructions exposing extended FPU states. For this reason, we apply a static CPU template (`T2`) to the Firecracker `MachineConfig` to mask the offending extended-state CPUID bits, allowing us to safely use our default `debian:trixie-slim` base image.
- **Cargo Installation:** Firecracker must be compiled via a custom containerized toolchain (`tools/devtool build`), not a naked Cargo install on the host. We use pre-compiled binaries.

### QEMU
- **Vhost-User Networking:** To integrate our rootless `vhost-user-backend` with QEMU, we locally vendored `vhost-user-backend` and `vhost` (via `[patch.crates-io]`) to comment out strict `PROTOCOL_FEATURES` checks when processing `SET_VRING_ENABLE`, as QEMU often sends this before `SET_FEATURES` has finalized.
- **Machine Type:** QEMU's `microvm` machine type uses `virtio-net-device` (MMIO) which falls back to legacy virtio header sizing (10 bytes), breaking networking. We use the QEMU `q35` machine type and `virtio-net-pci` which supports expected 12-byte headers.
- **Vsock Snapshot limitations:** QEMU relies on an external stateless `vhost-device-vsock` daemon for rootless vsock proxying, which does not support `vhost-user` state migration. Therefore, QEMU cannot support snapshot/restore over vsock in rootless mode.

## Networking
- **Agent-free Networking:** The guest agent does not perform manual network initialization. Instead, the Linux kernel's `CONFIG_IP_PNP=y` feature and `ip=` bootline arguments are used to automatically configure the network interface (`eth0`) and routes upon boot.
- **Rootless Networking (smoltcp NAT):** We use a pure-Rust userspace network NAT using the `vhost-user-backend` and `smoltcp` crates. `passt` is not used because its strict `seccomp` sandbox blocks `accept4`, making it incompatible with Cloud Hypervisor's `vhost-user` socket connection phase.
- **Smoltcp Implementation Details:**
  - **MAC Collisions:** `smoltcp` will silently drop packets if the Ethernet destination MAC is Broadcast but the Source MAC happens to equal the `smoltcp` interface's configured MAC. We statically assign the host's `smoltcp` MAC to `02:00:00:00:00:fe` to avoid collisions with the guest's MAC (derived from the `vmid`).
  - **RX Queue Iteration:** The virtio RX queue descriptor chain must *only* be iterated if we actually have packets in the `rx_queue` ready to send to the guest. Iterating `vring_state.get_queue_mut().iter()` automatically consumes and advances the `avail_idx` pointer; doing this when `rx_queue` is empty drops guest buffers, breaking the connection.
  - **Socket Allocation:** We allocate 16 `TcpSocket` instances per forwarded port to prevent socket pool exhaustion during sequential Keep-Alive HTTP requests.
- **Iptables REDIRECT:** Egress traffic is intercepted using the `iptables` REDIRECT rule (`-j REDIRECT --to-ports`) rather than `nft` TPROXY, as it requires fewer kernel dependencies and is simpler to invoke.
- **HTTPS MITM Proxy:** `hudsucker` is used for full HTTPS interception with a dynamic CA generated at runtime via `rcgen` and injected into the rootfs. To prevent `hudsucker` from crashing on initial `CONNECT` requests, test doubles explicitly ignore `hyper::Method::CONNECT`.

## Cgroup v2 Delegation (Rootless)
- To enforce memory and CPU limits unprivileged, the `orchestrator` reads `/proc/self/cgroup` and dynamically constructs a nested path for the VM's cgroup.
- **Cgroup v2 Constraints:** The kernel enforces a "no internal processes" rule. Because the test runner (`cargo test`) itself is an internal process, we cannot easily enable `memory` or `cpu` controllers for child cgroups directly underneath it. In environments where the agent is moved to a `supervisor` sibling, we strip the `/supervisor` suffix from the path when creating the VM cgroup, ensuring it is a sibling with full controller access.
- **cgroups-rs Limitations:** To avoid `CgroupMode` errors when attempting to add processes to deeply nested unprivileged cgroups via `Cgroup::load().add_task()`, we directly write the PID via `std::fs::write(cgroup.procs)`.
- **Missing Memory Delegations:** In some constrained test environments, the `memory` controller may not be delegated to unprivileged users. We bypass `cgroups-rs` panic by reading `memory.current` and `memory.peak` from `sysfs` manually.

## Guest Agent Protocol & Vsock
- **Serialization:** The guest agent uses `postcard` for length-delimited framing of messages.
- **Connection Handshake:** The `AgentClient::connect` handshake performs exact 1-byte asynchronous reads (`stream.read(&mut byte)`) to read the initial `OK <port>\n` string. This prevents Tokio's `BufReader` from over-reading and silently dropping bytes from the subsequent framed protocol payload.
- **EOF Handling (Restore):** When a VM is snapshotted and restored, the host-side `vhost-vsock` device is re-created, severing the original connection and sending an EOF to the guest. The guest agent detects this EOF, exits the `handle_connection` loop, and `accept`s a new connection.
- **VMID Allocation:** `VmidAllocator` uses a global `Mutex<Vec<u32>>` static variable to ensure VM IDs remain strictly unique across the entire test runner process, preventing socket binding conflicts during parallel `cargo test` execution. The raw atomic addition is wrapped within `(c % 254) + 1` to ensure valid IPv4 octets.

## Rootfs Construction and Execution
- **In-Memory EROFS Build:** We use the `am-fs-erofs` crate to parse `mmdebstrap` output in-memory and convert tar entries into an `am-fs-erofs` `Node` tree. This bypasses the host filesystem entirely, avoiding permission issues with creating device nodes or setting root uids as a non-root user.
- **OCI Whiteouts:** `tar2erofs.rs` takes an iterator of `tar::Archive` streams and correctly parses OCI whiteout files (`.wh.filename` and `.wh..wh..opq`) directly in-memory, mutating the node tree before final EROFS generation.
- **Builder VM:** The `MmdebstrapVm` source dynamically invokes `oci::build_rootfs` to build its own transient `builder_rootfs.erofs` before booting. The `ExecRequest` protocol includes a `timeout` field to safely support long-running `apt-get install` commands over the vsock connection, defaulting to 10 seconds for standard commands.
- **External virtiofsd:** When falling back to the external `virtiofsd` binary, the `--readonly` flag is required.

## Privileged Test Runner (`imp-test-runner`)
- `imp-test-runner` executes privileged integration tests without invoking `cargo test` under `sudo`. It verifies it has `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` file capabilities, drops its bounding set to the bare minimum, elevates these to the Ambient set, and switches its `euid`, `egid`, and groups to the developer's identity before `execve`ing the test binary.

## Benchmarking
- **Micro and Macro Benchmarks:** `criterion` drives micro-benchmarks for hot-path operations (`postcard` protocol encoding, `/30` host IP generation, `cache_key` computation) under `benches/micro.rs`.
- **Macro-Benchmark Harness:** `bench-vm` (`src/bin/bench-vm.rs`) acts as a custom harness capable of recording detailed lifecycle metrics like cold-boot and restore distributions (p50, p95, p99, max). It catches and reports boot failures gracefully for basic CI dry-runs missing KVM.

## Remaining Divergences from the Design
- **Concurrency Testing (`loom`):** The design document recommended introducing `loom` for deep concurrency testing. This is skipped in the current phase.
- **Rootless Networking Default:** `net-privileged` (TAP/TUN with `sudo`) is still frequently relied upon in the core integration test suite. Complete deprecation of privileged tests in favor of rootless `vhost-user-backend` is pending further network performance validation.

## Design Alignment (Pass 5)
- **In-VM mmdebstrap:** `mmdebstrap` has been successfully migrated to execute inside a builder micro-VM. It uses the `oci::build_rootfs` target as its builder image, boots with Cloud Hypervisor under rootless networking, installs `mmdebstrap`, runs the bootstrap inside the guest, and writes the output tarball to a shared folder. This eliminates host-side `mmdebstrap`, `apt`, `gpg`, and shell dependencies (and solves the Ubuntu `dash`/`bash` symlink issue).
- **Serial Panic Fail-Fast:** `AgentClient::connect` now accepts `timeout` and `serial_log`. During the connection retry loop, it continuously checks if the serial log has been populated with `"panic"` or `"Kernel panic"` and aborts immediately with a fail-fast error rather than waiting for the timeout.
- **Automatic Clock Resync:** `TestVm` tracks if it was restored from a snapshot and automatically pushes the host's `SystemTime` to the guest via `date -s` upon the first agent connection, ensuring consistent clock state across snapshot restores.
- **Warm Restore Benchmarks:** `bench-vm` has been updated to support warm snapshot restore benchmarking, capturing p50, p95, p99, and max latency distributions for restoring from a snapshot and establishing the agent handshake.
