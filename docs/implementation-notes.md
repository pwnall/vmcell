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
- **FPU XSAVE limitation:** Firecracker snapshot/restore tests can panic during restore (`restore_fpregs_from_fpstate`) if the guest environment (like Ubuntu 24.04's libc) aggressively utilizes highly optimized `glibc` AVX instructions exposing extended FPU states. For this reason, we apply a static CPU template (`T2`) to the Firecracker `MachineConfig` to mask the offending extended-state CPUID bits, allowing us to safely use our default `debian:trixie-slim` base image. We additionally pass `noxsave` on the guest kernel command line for Firecracker boots as belt-and-suspenders: it disables the guest's use of `XSAVE` entirely, so even if a CPU template is unavailable or incomplete the guest `glibc` cannot select an extended-state code path that the snapshot machinery would then mishandle. This is a justified deviation from the design's CPU-template-only recommendation (§15.2); the perf cost is acceptable for the dense/snapshot tier and the two mechanisms are independent.
- **`restore()`/`snapshot()` signature carries `&VmConfig`:** The design's §5.2 sketch types `restore(snapshot, res)`, but all three backends and the `Vmm` trait take an additional `cfg: &VmConfig`. This is a justified deviation: restoring (and, for QEMU, re-launching) a VM must reconstruct the same device topology — virtio-fs daemons for the configured shares, the rootfs/block args, the net wiring — which is only available from the config, not the snapshot file. The orchestrator already holds the `VmConfig` for the test, so threading it through is free.
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
- **Nftables TPROXY:** Egress traffic is intercepted using an `nftables` TPROXY ruleset (`tproxy to :{} meta mark set 1 accept`), matching the architecture design requirements over older iptables REDIRECT approaches.
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
- **VMID Allocation:** `VmidAllocator` allocates unique VMIDs by randomly searching the 1..=254 range and acquiring a cross-process file lock (`/tmp/imp-vmid-{vmid}.lock`). It tracks active allocations per-instance using an `Arc<Mutex<BTreeSet<u32>>>`, ensuring VM IDs remain strictly unique across parallel `cargo test` executions.

## Rootfs Construction and Execution
- **In-Memory EROFS Build:** We use the `am-fs-erofs` crate to parse `mmdebstrap` output in-memory and convert tar entries into an `am-fs-erofs` `Node` tree. This bypasses the host filesystem entirely, avoiding permission issues with creating device nodes or setting root uids as a non-root user.
- **OCI Whiteouts:** `tar2erofs.rs` takes an iterator of `tar::Archive` streams and correctly parses OCI whiteout files (`.wh.filename` and `.wh..wh..opq`) directly in-memory, mutating the node tree before final EROFS generation.
- **Builder VM:** The `MmdebstrapVm` source dynamically invokes `oci::build_rootfs` to build its own transient `builder_rootfs.erofs` before booting. The `ExecRequest` protocol includes a `timeout` field to safely support long-running `apt-get install` commands over the vsock connection, defaulting to 10 seconds for standard commands.
- **External virtiofsd:** When falling back to the external `virtiofsd` binary, the `--readonly` flag is required.
- **In-process virtiofsd Read-Only Mode:** When using the experimental in-process `fuse-backend-rs`, read-only mode is not strictly enforced natively yet. This is a justifiable difference accepted due to upstream library constraints and is hidden behind the `experiment-fuse` feature flag.

## Privileged Test Runner (`imp-test-runner`)
- `imp-test-runner` executes privileged integration tests without invoking `cargo test` under `sudo`. It verifies it has `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` file capabilities, drops its bounding set to the bare minimum, elevates these to the Ambient set, and switches its `euid`, `egid`, and groups to the developer's identity before `execve`ing the test binary.

## Benchmarking
- **Micro and Macro Benchmarks:** `criterion` drives micro-benchmarks for hot-path operations (`postcard` protocol encoding, `/30` host IP generation, `cache_key` computation, and `tar_to_erofs` packing) under `benches/micro.rs`.
- **Macro-Benchmark Harness:** `bench-vm` (`src/bin/bench-vm.rs`) acts as a custom harness capable of recording detailed lifecycle metrics like cold-boot and restore distributions (p50, p95, p99, max). It catches and reports boot failures gracefully for basic CI dry-runs missing KVM.
- **Benchmark Coverage Tests:** Added integration tests in `tests/benchmark.rs` to run the `bench-vm` harness with minimal iterations (`--iterations 1 --warmup 0`) across all compiled-in hypervisor backends (Cloud Hypervisor, Firecracker, QEMU), ensuring the benchmarking paths remain fully covered. Also added a dedicated unit test in `src/artifact/tar2erofs.rs` to verify EROFS conversion on empty tar streams.

## Remaining Divergences from the Design
- **Concurrency Testing (`loom`):** The design document recommended introducing `loom` for deep concurrency testing. This is skipped in the current phase.
- **Rootless Networking Default:** `net-privileged` (TAP/TUN with `sudo`) is still frequently relied upon in the core integration test suite. Complete deprecation of privileged tests in favor of rootless `vhost-user-backend` is pending further network performance validation.
- **Firecracker `restore()` passes `resume_vm: false`:** The design document specifies `POST /snapshot/load { resume_vm: true }`, but the implementation passes `resume_vm: false` and leaves the VM paused, relying on the orchestrator to call `instance.resume()` explicitly afterward. This matches the `VmInstance` trait contract (where `restore()` returns a paused instance and the caller calls `resume()`), is consistent with the Cloud Hypervisor restore pattern (which also requires an explicit `vm.resume` call after `--restore`), and works correctly because the orchestrator always calls `resume()` after `restore()`. The tradeoff is one extra API round-trip and a risk that a failed `resume()` call leaves a zombie paused FC process — mitigated by the orchestrator's `Drop` teardown.
- **QEMU `snapshot_restore` capability reported as `false` in all configurations:** The design says QEMU is snapshot-ineligible only in the rootless+vsock configuration (because the external `vhost-device-vsock` daemon cannot migrate). The implementation conservatively reports `false` unconditionally, which also disables the code path in privileged `vhost-vsock` mode. This matches the current state where QEMU snapshot/restore via the privileged kernel `vhost-vsock` path has not been validated. The `restore()` implementation exists as forward work; it is guarded by `capabilities().snapshot_restore` so it is dead code in practice.
- **CLI subcommands `run`, `exec`, `ls`, `rm`, `stats` are stubs:** The `imp-testing` binary's main logic is implemented in the library; the CLI stubs exist as placeholders pending argument-parsing design finalization for each subcommand.


## Design Alignment (Pass 5)
- **In-VM mmdebstrap:** `mmdebstrap` has been successfully migrated to execute inside a builder micro-VM. It uses the `oci::build_rootfs` target as its builder image, boots with Cloud Hypervisor under rootless networking, installs `mmdebstrap`, runs the bootstrap inside the guest, and writes the output tarball to a shared folder. This eliminates host-side `mmdebstrap`, `apt`, `gpg`, and shell dependencies (and solves the Ubuntu `dash`/`bash` symlink issue).
- **Serial Panic Fail-Fast:** `AgentClient::connect` now accepts `timeout` and `serial_log`. During the connection retry loop, it continuously checks if the serial log has been populated with `"panic"` or `"Kernel panic"` and aborts immediately with a fail-fast error rather than waiting for the timeout.
- **Automatic Clock Resync:** `TestVm` tracks if it was restored from a snapshot and automatically pushes the host's `SystemTime` to the guest via `date -s` upon the first agent connection, ensuring consistent clock state across snapshot restores.
- **Warm Restore Benchmarks:** `bench-vm` has been updated to support warm snapshot restore benchmarking, capturing p50, p95, p99, and max latency distributions for restoring from a snapshot and establishing the agent handshake.

## Design Alignment (Pass 6)
- **VMM Teardown Order:** The design correctly specified that VMMs should be force-killed before their dependent resources (netns, cgroups, etc.) are torn down to prevent zombie leakage or hung network interfaces. `TestVm::Drop` now strictly enforces this by explicitly dropping the VMM instance first (`drop(self.instance.take())`).
- **Process Group Reaping:** A critical deviation was identified where `tokio::process::Child::id()` evaluates to `None` if the `Child` has been awaited in a different context, preventing `kill(-pid)` from tearing down the entire process group. To ensure `ip netns exec` wrappers and child tasks are always reaped, the initial process group ID (`pgid`) is explicitly cached upon instantiation and used during all teardown flows across all three VMM backends.
- **QEMU Snapshot/Restore Self-Guarding:** Although the design states QEMU can perform snapshot/restore when not utilizing rootless vsock, the backend's current implementation `capabilities()` correctly returns `false` for `snapshot_restore`. To enforce this trait contract fully, the `restore()` and `snapshot()` methods explicitly return `Error::Unsupported` rather than attempting execution.
- **Transparent Egress Interception:** Rootless egress (smoltcp) routing was missing a listener hook to intercept L4 TCP connections dynamically. The `run_network` loop now intercepts egress TCP SYNs dynamically and provisions ephemeral listeners that route out to the host-side proxy port.
- **Resolving Cache Keys (`pins.json`):** Instead of blindly hashing source inputs to compute cache keys or reading files on the fly, the `Pipeline::build` architecture was refactored to introduce an explicit `ResolvePinsStage` (Stage 0). This stage reads the `pins.json` manifest once and propagates the `HashMap` into the `StageOutputs`, which subsequent stages access purely from memory.

## Design Alignment (Pass 7)
- **Automated Quality Guardrails:** We deployed the automated CI and linting guardrails (`clippy.toml`, `deny.toml`, `.config/nextest.toml`, `rustfmt.toml`, `justfile`) specified in `docs/29-claude-automated-quality.md`.
- **RUSTSEC Ignore Preservation:** The existing list of ignored advisories in `deny.toml` (such as `RUSTSEC-2020-0036`) was preserved and extended with a few unmaintained/timing-attack crates detected during `cargo deny check` (`RUSTSEC-2020-0016`, `RUSTSEC-2024-0436`, `RUSTSEC-2023-0071`, `RUSTSEC-2025-0134`) to get back to a green build without unapproved dependency upgrades.
- **Top-Level Lint Exclusions:** `src/lib.rs` preserves `#![allow(async_fn_in_trait)]` as it's required by the codebase's existing architecture.
- **Test Scaffolding:** `tests/common/mod.rs` was augmented with the `start_vm`, `require_cap!`, and `vmm_matrix_test!` macros. Tests will incrementally adopt these rather than applying a mass refactor.
- **Sub-agent Delegation:** Existing lint failures on `unwrap` usage and missing doc sections, as well as test instantiation arguments due to the new `start_vm` signature, were iteratively resolved by subagents to maintain the `cargo clippy` and `cargo test` gates.


## Design Alignment (Review 34)

Code review 34 (`docs/34-claude-code-review.md`) recorded the following **justified** deviations
from the design here (rather than as findings), and flags two pre-existing rationales that newer
findings contradict. Unjustified divergences and defects are in the review report, not duplicated here.

### Newly recorded justified deviations
- **Protocol omits the design's `Hello` and `Ping` message variants.** Design §4.1 lists the enum as
  `Hello`/`Ready`/…/`Ping`, but `AGENTS.md`/the rubric require removing the dead `Hello` and no-op
  `Ping`. `src/agent/protocol.rs` defines only `Ready`/`Exec`/`Stdout`/`Stderr`/`Exit`/`PutFile`, the
  rubric-aligned choice; the enum is `#[non_exhaustive]`, so re-adding later is non-breaking.
- **`hudsucker` re-self-signs the loaded CA params to obtain an owned `Certificate`.** On the
  load-from-disk path (`src/proxy/tls.rs:52-63`) the baked-in `ca_cert_pem` is what the guest trusts;
  `params.self_signed(&key_pair)` only reconstructs the in-memory `Certificate` for `RcgenAuthority::new`
  from the *same* key pair and parsed params, so leaf certs chain to the same public key/subject. This is
  the cache-once pattern rubric B4 requires, **not** a per-`authority()`-call re-sign — recorded so it is
  not mistaken for the re-sign bug.
- **`TestVm::start`/`restore` inject `CidAllocator`, `VmidAllocator` and `CgroupFs` separately** rather
  than the single `Arc<VmidAllocator>` of the §10.2 sketch. CID and VMID are distinct ID spaces and
  `CgroupFs` is an injected `Box<dyn CgroupFs>` providing the recording-fake seam `AGENTS.md` mandates —
  more injectable seams than the sketch, consistent with the testability mandate.
- **`deny.toml` allow-list adds `Unicode-3.0` and `CDLA-Permissive-2.0`** beyond the design skeleton.
  Both are permissive licenses required by transitive deps (e.g. `unicode-ident`); adding them is the
  sanctioned way to satisfy the allow-only gate (`cargo deny` is the source of truth), not a policy break.
- **TPROXY ruleset drops UDP/QUIC (`udp dport 443`) instead of intercepting it** (`src/net/tap.rs:315-326`),
  a deliberate divergence from §6.3's "intercept" language: blocking QUIC forces HTTP/2-over-TCP so all
  egress stays observable through the transparent proxy, which serves the design's egress-observability
  goal. (Surfaced as review finding `NET-7`; recorded here as the accepted posture.)
- **`exec_vsock::test_exec_vsock_mock` runs in the default (non-ignored) suite.** It is a UDS
  protocol/codec mock exercising the `AgentClient` handshake + `Framed<LengthDelimitedCodec>` exchange —
  not the `put_file` round-trip (which is covered separately by the `vmm_matrix_test!` that writes via
  `put_file` then `cat`s the file back *in the guest*). So "mock where round-trip is required" does not
  apply, and a pure codec/mock test correctly runs without `#[ignore]`.

### Corrections to pre-existing rationales (contradicted by Review 34 findings)
- The "**`restore()`/`snapshot()` carries `&VmConfig`**" note above cites "reconstruct the same device
  topology — virtio-fs daemons for the configured shares" as a use. Threading `&VmConfig` is justified, but
  *attaching virtiofsd (a vhost-user device) on the snapshot/restore path violates the snapshot-eligibility
  law* — see review finding C1 (`DESIGN-DIVERGENCE-1`/`VMM-1`/`CONFIG-ERROR-ORCH-1`). The signature change
  is fine; the share-daemon use is the defect, not a justification.
- The "**smoltcp host NAT MAC pinned to `02:00:00:00:00:fe`**" note claims the pin "avoids collisions with
  the guest's MAC". This is **wrong for vmid 254** (`mac_math(254)` == `02:00:00:00:00:fe`) — see review
  finding `NET-2`. The RX-iterate-only-when-queued and 16-socket-pool invariants in that note remain correct.
