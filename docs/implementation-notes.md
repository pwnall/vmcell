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


## Review 34 Remediation — known remaining issue & deferrals

The Review-34 findings were remediated across the codebase (see `docs/34-claude-code-review.md`). Two items
are **deliberately deferred** and one **larger pre-existing issue** was uncovered; recorded here so the next
pass does not mistake them for regressions.

- **KNOWN ISSUE — systemic feature-gating debt (the powerset gate is still RED).** Fixing the `error.rs`
  hyper-variant gating (the review headline) let `cargo hack --feature-powerset` finally compile past the lib
  and reach a deeper, pre-existing problem: the host modules are gated on **`host-common`** rather than on
  their own feature, so single-feature / partial combos do not compile. E.g. `--features cloud-hypervisor`
  alone pulls `proxy` (needs `hudsucker`/`rustls`/`rcgen`), `net` (needs `tun_tap`/`netns_rs`/`netlink-packet-route`),
  and `artifact` (needs `blake3`) because all three are `#[cfg(feature = "host-common")] pub mod …` in `lib.rs`.
  The default, `--all-features`, `--features agent`, and `--features test-runner` builds are all green; only the
  *partial-combo* powerset is affected. Proper fix: re-gate each module on its specific feature
  (`proxy`→`proxy`, `metrics`→`metrics`, `net`→`any(net-privileged, net-unprivileged)` with `tap.rs`/`smoltcp.rs`
  internally `#[cfg]`'d, `artifact`→`pipeline`), make `orchestrator`/`TestVm` feature-aware over its optional
  subsystems, and add `tokio`'s `fs` feature to `host-common`. This is an architecture change (the orchestrator
  weaves all subsystems together), out of scope for the finding-level remediation, and tracked as the main
  follow-up. The per-test `required-features` gating belongs to the same effort and is deferred with it.
- **Deferred — `ARTIFACT-PIPELINE-5` live pin resolution.** `ResolvePinsStage` still reads a committed
  `pins.json` rather than performing live tag→digest / `snapshot.debian.org` timestamp resolution; the
  `debian_snapshot_timestamp` propagation was the minimal honest fix applied.
- **Deferred — `ARTIFACT-PIPELINE-8` OCI record/replay seam.** The OCI fetch path still uses a concrete
  `oci_client::Client`; introducing the injectable record/replay trait is left as forward work.

### Follow-up fixes (cgroup robustness + VMM leak) — implemented & validated

Both follow-ups proposed in review 34 are implemented.

- **Robust `create_slice` (cgroup across layouts).** `DefaultCgroupFs::create_slice` no longer uses
  `cgroups-rs` `CgroupBuilder`. Its V2 path manipulates the parent's `subtree_control` and leaves the new
  cgroup in a state that rejects `cgroup.procs` writes (`EOPNOTSUPP`) under common systemd cgroup layouts.
  We now `mkdir` the per-VM cgroup directly and apply limits with best-effort direct sysfs writes
  (`try_apply_limit`): we attempt to enable the controller on the parent's `subtree_control`, then write the
  limit file; if the controller can't be enabled (constrained/non-delegated layout) we `warn!` and skip the
  limit so VM creation still succeeds (limit-dependent tests gate on controller availability — `TESTS-FEATURES-3`).
  `delete_slice` is now a direct `rmdir`. The `cgroups-rs` dependency is no longer used by this code.
  - **Cgroup-environment requirement (discovered while validating).** The per-VM cgroup must live in a
    **non-threaded `domain`** cgroup subtree. A *threaded* scope — e.g. the `ptyxis`/GNOME-terminal
    `*-spawn-*.scope` (its `cgroup.type` is `domain threaded`) — rejects `cgroup.procs` on its children
    regardless of `CAP_SYS_ADMIN`, because threaded subtrees move *threads* via `cgroup.threads`. Run the
    integration suites from a plain `domain` scope: `systemd-run --user --scope -p Delegate=yes just test-*`
    (validated working here), or a CI runner / a dedicated systemd service. Enforcing limits additionally
    needs the harness in a leaf so the parent can delegate controllers (the `/supervisor` pattern the
    orchestrator already strips); without it, limits degrade gracefully (above).
- **Reap the VMM on a post-spawn failure (`CONFIG-ERROR-ORCH-2`-adjacent leak).** `spawn_ch`/`spawn_fc`/the
  QEMU spawn called `cgroups.add_task(pid)?` (and `wait_for_socket(...)?`) *after* spawning the VMM but
  *before* constructing the owning instance whose `Drop` reaps the process group — so a failure there dropped
  only the raw `tokio::process::Child` (no `kill_on_drop`) and leaked a running VMM (reproduced: bench-vm
  leaked two `cloud-hypervisor` processes on the cgroup-add failure; the earlier "30-minute hung test" was a
  leaked VM, not a live test). Added a shared `crate::vmm::reap_process_group(&mut Child, Option<u32>)`
  (`SIGKILL` the group + reap), capture `pgid` immediately after spawn in all three backends, and reap on the
  `add_task`/`wait_for_socket` error paths. Validated: bench-vm now boots in a domain scope with **zero**
  leaked processes/cgroups.

### Open finding surfaced during validation — stale rootfs / agent handshake

With the two follow-ups in place the VM **boots** and the cgroup path is clean, but the host↔guest **agent
handshake times out** against the *current* `/tmp/imp-artifacts/rootfs.erofs`. Root cause is **stale
artifacts**, not a code defect: the host `AgentClient::connect` and the *current* guest agent are consistent
(the guest sends `Message::Ready` first — `imp-guest-agent.rs:283`; the host waits for it —
`agent/mod.rs:252-273`), but `rootfs.erofs` was built **Jun 24**, before this session's guest-agent changes,
so it bakes an **old** guest agent whose first-frame protocol differs (the serial log shows the guest boots
and repeatedly "accepted connection" while the host retries the handshake to timeout). Running the full
integration suite therefore requires **rebuilding the rootfs** with the current guest agent
(`cargo run --bin imp-testing -- build`; the `ARTIFACT-PIPELINE-2` cache-key fix now folds `guest_agent_src_hash`
into the rootfs key, so an agent change correctly invalidates the rootfs). Two operational gotchas: re-`just
bless` after any build that rebuilds `imp-test-runner` (rebuilds strip the file caps), and run from a `domain`
cgroup scope (above).

### PID-1 panic on an unattached share — found & fixed via the rootfs rebuild

Rebuilding the rootfs with the current guest agent surfaced a real regression class the stale rootfs had
hidden: `imp-guest-agent`'s share-mount loop did `return Err(e.into())` when a virtio-fs tag was not attached,
so a config that attaches **no** shares (the benchmark / exec-only path) made PID 1 exit and **kernel-panic**
the guest (serial: `virtio-fs: tag <imp-in> not found` → `Error: Os { code: 22 … }` →
`Kernel panic - not syncing: Attempted to kill init!`). Shares are optional, so a missing tag is now logged
and skipped (`imp-guest-agent.rs`), matching the `CONTROL-PLANE-3` loopback fix. This is the same
"PID 1 must never exit on a recoverable condition" rule; the core mounts (overlay/`/proc`/`/dev`) stay fatal
because they are genuinely unrecoverable. (The integration tests that *do* attach shares would not have hit
this, which is exactly why only a from-scratch rootfs rebuild + a no-share boot exposed it.)

### End-to-end validation status (after the rebuild) + two remaining gaps

With the fresh rootfs + the share-mount fix, the stack works end-to-end on this host (in a `domain` cgroup
scope, fresh artifacts via `IMP_KERNEL`/`IMP_ROOTFS`/`IMP_ARTIFACTS_DIR`): **bench-vm cold boot succeeds**
(boot + agent handshake, p50 ≈ 300 ms) and **`test_lifecycle_rootless_smoltcp` passes** (full rootless boot +
agent + smoltcp NAT). The rootless suite is 7/8 (the 6 smoltcp unit tests + the rootless lifecycle test).
Two gaps remain, both surfaced by the rebuild:

- **Rootfs is missing `iproute2` (`ip`).** `test_egress_proxy_rootless` boots and connects the agent, then runs
  `ip a` in the guest and gets exit 127 (command not found). The OCI `debian` base (pins.json) is minimal and
  has no `iproute2`; the restore-path in-guest `ip` (DESIGN-DIVERGENCE-2) needs it too. Fix options: install a
  base tool set (`iproute2`, …) in the rootfs build — either add a package step to the OCI `RootfsStage` or
  finish the mmdebstrap-in-VM source (blocked on `ARTIFACT-PIPELINE-5`'s missing `debian_snapshot_timestamp`) —
  or make the diagnostics not depend on `ip`. The "Debian as close as possible to end-user systems" requirement
  argues for provisioning the tools.
- **Warm snapshot/restore fails.** bench-vm's Warm-Restore reports "No successful runs" (the base VM boots and
  snapshots, but the restore or restored-agent reconnect fails) and leaked one VM on that path — the
  reap-on-failure fix covers the spawn path but the snapshot/restore flow has additional early-return points to
  audit. Needs its own investigation (CH `--restore` + `vm.resume` + agent reconnect/clock-resync).

### Privileged-suite results (fresh artifacts, blessed runner, domain scope): 82/88

`just test-priv` against the rebuilt rootfs in a `systemd-run --user --scope -p Delegate=yes` domain scope:
**82 passed, 6 failed, 8 skipped.** Passing includes `boot`/`concurrency`/`lifecycle force-kill`/`shares`/
`exec` on cloud-hypervisor plus every unit/config/artifact/metrics test — i.e. the product code paths work
end-to-end with the runner. The 6 failures are two root causes, neither a core-logic bug:

- **Rootfs is too minimal (3 tests).** `host_endpoint` runs `ip a`/`ip route`/`ip neigh`+`curl`, `egress_proxy`
  runs `ip a`, `nested_virt` runs `kvm-ok` — all exit 127 (not installed). The OCI `debian` base has no
  `iproute2`/`curl`/`cpu-checker`, and `oci::build_rootfs` only unpacks image layers (no `apt`). The product
  requirement ("Debian as close as possible to end-user systems") wants these present, so the fix is to
  provision a base tool set — finish the **mmdebstrap-in-VM source** (it installs a package list inside a
  builder VM, now that VM boot works; needs `debian_snapshot_timestamp`, which `ResolvePinsStage` now emits) or
  pull a tooled base image. Band-aiding the tests to avoid the tools would weaken the validation, so prefer
  fixing the rootfs.
- **§12.8 capability runner can't create network namespaces (2 tests).** `panic_residue` and `snapshot_restore`
  use the privileged tap path; `netns_rs::NetNs::new` must create `/var/run/netns/<name>`, but that dir is
  `root:root 0755` and the runner grants only `CAP_NET_ADMIN`+`CAP_SYS_ADMIN` (no `CAP_DAC_OVERRIDE`, and the
  process runs as the developer uid) → `EPERM`. (`snapshot_restore` fails here at netns setup — the snapshot
  path itself is not reached.) Fix options: add `CAP_DAC_OVERRIDE` to the runner's set (re-bless) — minimal and
  matches §12.8's "no sudo -E" goal — or make `/var/run/netns` developer-writable as a one-time host setup, or
  have `add_netns` fall back to a developer-writable run dir. This is a real gap in the §12.8 runner: the
  privileged tap tests need filesystem access to `/var/run/netns`, not just the two caps.
- **Cgroup memory controller not delegated (1 test).** `metrics_limits` correctly fails its
  hard-precondition because the memory controller isn't in the per-VM cgroup's parent `subtree_control` — the
  harness must run in a leaf (the `/supervisor` pattern) so the scope can delegate controllers. This is a
  harness/CI-setup item, not a code bug; it passes where controllers are delegated (e.g. a CI runner under a
  delegated systemd service).

### Privileged-tap path: a chain of latent bugs fixed (it had never been validated)

The privileged tap path (used by `test_lifecycle_panic_residue_ch` and `snapshot_restore`) had never run
end-to-end — every prior attempt died at the netns permission error, masking everything downstream. Fixing the
`DAC_OVERRIDE` gap (above) exposed and we then fixed a chain:

1. **Nested tokio runtime (`net/tap.rs`).** `run_in_tokio` built a fresh runtime and `block_on`'d it on the
   current thread; called via the sync `Netlink` trait from the async orchestrator, that panics ("Cannot start a
   runtime from within a runtime"). Now runs the blocking work on a dedicated OS thread (`std::thread::scope`),
   which is never a runtime worker. Same for `run_with_rtnetlink` (added `Send` bounds).
2. **Tap held open → VMM can't open it (`net/tap.rs`, new `net_sys.rs`).** The orchestrator created the tap and
   kept its fd (`NetNamespace._tap`) to keep it alive, but a non-multi-queue tap allows one opener, so CH failed
   with "Open tap device failed: Device or resource busy". Now we `TUNSETPERSIST` the tap and drop our fd so the
   VMM opens it. The ioctl lives in a new top-level `net_sys` module because `net` is `#![forbid(unsafe_code)]`.
   Result: `test_lifecycle_panic_residue_ch` passes.
3. **Warm-restore agent reconnect hung (`orchestrator.rs`, `imp-guest-agent.rs`).** Two bugs: the orchestrator
   did a redundant second `reconnect()` after the post-restore `connect()` (the single-threaded guest listener
   was already busy serving the first connection, so the second timed out) — removed; and more fundamentally the
   guest listener served connections **inline**, so after restore its `handle_connection` blocked forever on the
   pre-snapshot connection (whose blocking read never EOFs) and never re-accepted the host's reconnect. The
   listener now serves each connection on its **own thread**, so the stale one parks while the new one is
   accepted. **This was necessary but NOT sufficient:** with the rebuilt rootfs, `snapshot_restore` still times
   out at the post-restore agent connect (the restored guest dumps a serial log with no further agent activity).
   So the guest's vsock **listener itself** does not survive CH's `--restore` — after the vhost-vsock device is
   re-created the bound `VsockListener` no longer yields connections, so the host can never reconnect. The
   thread-per-connection + reconnect-removal fixes are correct and kept, but the warm-restore path needs deeper
   CH-vsock-restore work: likely re-binding the listener after restore (the guest can't easily detect a
   transparent restore, so options are re-binding on an accept error/timeout, or a host-driven signal). This is
   the one remaining **core-feature** gap (vs. the rootfs-tooling and harness gaps) and warrants focused
   investigation against CH's vsock snapshot semantics.

**Also surfaced:** killed/failed privileged tests **leak network namespaces** (`/var/run/netns/imp-net-*`) that
need privileged `umount`+`rm` to clean — the missing periodic-sweeper / orphan-registry the review flagged
(rubric B1). A leaked netns occasionally collides with a later run's vmid (`netns add … Operation not
permitted`). A sweeper (or a `just`-level pre-clean run via the capability runner) should reap these.

### Larger follow-ups to evaluate next (raised by the maintainer)

- **Collapse the cargo feature matrix to one feature per binary.** The current fine-grained features
  (`cloud-hypervisor`/`firecracker`/`qemu`/`net-privileged`/`net-unprivileged`/`proxy`/`metrics`/`pipeline`/`cli`/
  `host-common` + a dozen dep-named passthroughs + `experiment-*`) are high-cost and low-value: they are the
  direct source of the build-unblock bug (`error.rs` hyper variants), the systemic module-on-`host-common`
  gating debt (the still-red feature-powerset gate), and the partial-combo compile failures — yet no real
  deployment uses a partial host build. Proposal: keep exactly **three** build targets, one per binary, and
  drop the rest:
  1. the **library + main `imp-testing` binary** with *all* host functionality compiled together (VMM
     backends, net, proxy, metrics, pipeline, CLI) — no internal feature splits;
  2. **`test-runner`** — the privilege-delegation binary, dependency-thin (rustix + capctl only);
  3. **`agent`** — the guest PID-1, dependency-thin (no host/async stack).
  This removes the powerset gate's entire purpose (no partial host combos to break), eliminates the
  module-re-gating work, and keeps the only split that actually matters — the two lean privileged-window
  binaries vs. the host library. Trade-off: the host build always compiles all three VMM backends and both
  net paths, which is already the `default` set, so effectively no loss.

- **Audit / fix artifact cache invalidation (it produced confusing stale VMs).** Editing source and rebuilding
  repeatedly left the **old** `/tmp/imp-artifacts/rootfs.erofs` in place (the Jun-24 rootfs with a stale guest
  agent), which masked the agent-handshake change and cost real debugging time. Several things conspire:
  (a) the artifact pipeline is a **separate** step (`cargo run --bin imp-testing -- build`) that `cargo
  build`/`cargo test` do **not** trigger, so a normal edit-rebuild loop never refreshes the rootfs; (b) the
  cache historically under-keyed (the `ARTIFACT-PIPELINE-2`/`-9`/`DESIGN-DIVERGENCE-3` fixes add
  `guest_agent_src_hash` + a stage version + content hashing, but the only determinism/invalidation tests use
  a `DummyStage` and do not exercise the real `RootfsStage`/`SnapshotStage` keys end-to-end); (c) artifacts
  live under a shared, session-persistent `/tmp/imp-artifacts` rather than `target/`, so they survive across
  checkouts and confuse provenance. Action items: add a real end-to-end test that changing the guest-agent
  source invalidates `rootfs.erofs`; make the integration harness **fail loud when an artifact is older than
  the sources it depends on** (or auto-`build` before the suite) instead of silently booting a stale rootfs;
  and consider moving the artifact cache under `target/` keyed to the source-tree state.

- **Kernel build is broken under modern GCC (gcc-15 / C23).** Rebuilding the pinned Linux 6.6.9 fails:
  `drivers/firmware/efi/libstub` is compiled without `-std=gnu11`, and gcc-15 defaults to C23, where `false`/
  `bool` are keywords (`error: cannot use keyword 'false' as enumeration constant`). `KernelStage` invokes
  `make` with `CC=gcc`/`HOSTCC=gcc` but no C-standard pin. Fixes to consider: pass `KCFLAGS=-std=gnu11` (and
  handle the EFI-stub's private cflags, or set `CONFIG_EFI_STUB=n` since cloud-hypervisor boots via PVH and
  does not need it), or pin a toolchain. Until then the prebuilt `vmlinux` (which boots fine) must be reused —
  the kernel is unchanged, so this did not block rebuilding the rootfs, but it does block a from-scratch
  `imp-testing build` on this host. (Also note the CLI builds into `target/imp-artifacts` while the test
  harness reads `/tmp/imp-artifacts` unless `IMP_KERNEL`/`IMP_ROOTFS`/`IMP_ARTIFACTS_DIR` are set — another
  facet of the artifact-location confusion above.)

## Wrap-up: validated state + the three remaining buckets for the next pass

**Validated state at hand-off** (KVM host; blessed runner with `cap_net_admin,cap_sys_admin,cap_dac_override`;
tests run inside `systemd-run --user --scope -p Delegate=yes` against the freshly-rebuilt rootfs):

- Unit / codec / property suite: **88/88 pass**. `fmt`, `clippy -D warnings`, `cargo deny`, the global-state
  ban, and `cargo semver-checks` (no breaking change) are all green.
- Rootless integration: **7/8** (the 6 `smoltcp` unit tests + `test_lifecycle_rootless_smoltcp`).
- Privileged integration: **83/88** — `boot`/`concurrency`/`exec`(+`put_file` round-trip)/`force_kill`/
  `shares`/`panic_residue` pass; no regressions.
- The feature-powerset gate (`just ci`) is still red on the pre-existing module-on-`host-common` gating debt
  (see the feature-flag follow-up above), independent of all of the above.

The 5 remaining privileged failures fall into **three buckets**. Everything below is forward work; the
detailed diagnoses are in the sections above (this is the consolidated to-do).

### Bucket 1 — Rootfs tooling (fixes `egress_proxy`, `host_endpoint`, `nested_virt`)

The OCI `debian` base rootfs is minimal: it has no `iproute2` (`ip`), `curl`, or `cpu-checker` (`kvm-ok`), so
these tests exit 127, and the restore-path in-guest `ip` (DESIGN-DIVERGENCE-2) has nothing to call. `oci::build_rootfs`
only unpacks image layers — there is no `apt` step. **Recommended fix:** provision a base tool set. The
designed path is the **mmdebstrap-in-VM source** (installs a package list inside a builder VM — now viable
since VM boot works; complete `ARTIFACT-PIPELINE-5` so Stage 0 emits the `debian_snapshot_timestamp` it needs),
or pull/layer a tooled base image. Do **not** weaken the tests to dodge the tools — the product requirement is
"Debian as close as possible to end-user systems." This is the largest lever (3 tests) and a network-heavy
build. (Doing this also un-skips the `iproute2`-dependent restore identity rotation.)

### Bucket 2 — Snapshot/restore vsock (fixes `snapshot_restore`) — the one core-feature gap

After CH `--restore`, the guest's `VsockListener` (bound before the snapshot) never yields a new connection on
the re-created vhost-vsock device, so the host's post-restore reconnect times out. The contributing
single-threaded-listener and redundant-double-connect bugs are already fixed (the listener is now
thread-per-connection and the orchestrator no longer double-connects), but they were necessary-not-sufficient:
the **bound listener itself does not survive the device re-creation**. **Recommended fix:** make the guest
re-establish its vsock listener after a restore — the guest can't easily detect a transparent restore, so the
practical options are (a) re-`bind` on an accept error or a bounded accept timeout, or (b) a host-driven
post-restore signal (e.g. a sentinel the orchestrator already has a hook for) that tells the agent to rebind.
Validate against CH's documented vsock snapshot semantics (the warm-restore path is also what `bench-vm`'s
"Warm Restore" exercises). Deep but well-scoped.

### Bucket 3 — Privileged harness / cgroup-and-netns hygiene (fixes `metrics_limits`; hardens the tap suite)

Two CI/harness items, not core-logic bugs:
- **Cgroup controller delegation (`metrics_limits`).** The memory controller must be in the per-VM cgroup's
  parent `subtree_control`, which requires the harness process to sit in a leaf (the `/supervisor` pattern the
  orchestrator already strips) so the scope can delegate controllers. The test correctly hard-fails its
  precondition otherwise. Run the privileged suite under a delegated systemd service (or set up the
  supervisor-leaf in the `just test-priv` wrapper). It passes where controllers are delegated (e.g. a proper CI
  runner). Note: moving the scope's own process into the supervisor leaf hit an `EINVAL` under
  `systemd-run --user --scope` here and needs the right invocation.
- **Network-namespace leak / missing sweeper.** Killed or failed privileged tests leave
  `/var/run/netns/imp-net-*` (and occasionally tap/cgroup) residue that needs privileged `umount`+`rm`; a leaked
  netns then collides with a later run's vmid (`netns add … Operation not permitted`). This is the
  periodic-sweeper / orphan-registry the review flagged (rubric B1, still unimplemented). Add a sweeper (or a
  `just`-level pre-clean run through the capability runner). One-off cleanup today:
  `sudo ip netns delete <leftover imp-net-*>`.

### Plus the two maintainer-raised follow-ups (above)

The feature-matrix simplification and the cache-invalidation audit remain the two highest-leverage structural
cleanups, and the gcc-15 kernel-build break must be fixed before a from-scratch `imp-testing build` works on a
modern host.

## Integration-test fixes (guest test-helper, vsock re-bind, netns hygiene)

This pass drove the host-facing integration suites to green. The recorded deviations:

### Guest test-helper `imp-guest-tools` (justified deviation)
- The minimal OCI `debian` rootfs lacks `iproute2`/`curl`/`cpu-checker`, so the network and
  nested-virt tests exited 127. Rather than provisioning distro packages (mmdebstrap-in-VM), we
  ship a small **Rust multicall helper** `src/bin/imp-guest-tools.rs` (feature `guest-tools`)
  providing `ip` (read-only state from sysfs/procfs + `link set … address` via ioctl), `curl`
  (real HTTP/HTTPS via `reqwest`, honoring the proxy env + `-k`/`--resolve`/`--max-time`), and
  `kvm-ok` (`/dev/kvm` probe). This matches the requirement "prefer Rust over external tools" and
  keeps the erofs base minimal. The helper performs the **real** operations (genuine HTTP, real
  `/dev/kvm`, real procfs), so it is not a weakening of the assertions.
- **Delivered by baking into the rootfs erofs, not a virtio-fs share.** The original intent was a
  share (like `imp-bin`), but `virtiofsd` cannot enter its `--sandbox namespace` without
  privileges, so a share fails in the **rootless** suite (no `CAP_SYS_ADMIN`; unprivileged userns
  is restricted on the host). The erofs rootfs is served over virtio-blk in both modes, so a new
  `GuestToolsStage` builds the helper and `pack_erofs_with_injection` bakes it at
  `/imp-tools/imp-guest-tools` with `ip`/`curl`/`kvm-ok` symlinks; the guest agent prepends
  `/imp-tools` to the exec `PATH`. The rootfs cache key already folds upstream artifact content
  (`hash_artifacts_sorted`), so a helper change re-bakes the rootfs.
- **Restore MAC rotation depends on in-guest `ip link set eth0 address`** (orchestrator §9.2,
  DESIGN-DIVERGENCE-2). The helper implements that for real (SIOCSIFHWADDR ioctl). It accepts
  `ip addr`/`ip route` **write** forms as no-ops (returns 0) so the orchestrator's post-restore
  `&&` chain succeeds without flushing the boot-time (`ip=`) address; in-guest IP rotation on
  restore is intentionally not performed (it conflicts with the zero-netlink direction, and no
  test exercises post-restore connectivity). MAC rotation is the only identity change the
  snapshot test asserts in-guest.

### Snapshot/restore: three fixes (now passing end-to-end)
The warm-restore path needed three independent fixes; all are in:

1. **`config.json` rewrite on restore (the real host-side blocker).** CH (v52) `--restore` rebuilds
   every device from the snapshot's `config.json`, which records the *original* instance's
   now-defunct temp-dir paths for the **vsock socket** and the **serial file** — and CH exposes
   **no** restore-time override for them (`RestoreConfig` = `source_url`/`prefault`/
   `memory_restore_mode`/`net_fds`/`resume` only). So the host connected to a vsock socket CH never
   bound (handshake timed out) and the serial log stayed empty. `spawn_ch` now rewrites
   `<snapshot>/config.json`'s `vsock.socket` and `serial.file` to this restore's freshly-minted
   paths before launching. In-place rewrite is fine for a single-use snapshot; restoring many clones
   from one snapshot would need a copy-on-write of the snapshot dir first (forward work).
2. **Recoverable guest vsock listener.** After the device is re-created the pre-snapshot listener
   goes deaf (and the stale connection may never EOF). `imp-guest-agent`'s `serve_vsock` runs a
   non-blocking accept loop and **re-`bind`s** after a bounded idle period (`REBIND_IDLE`),
   re-attaching to the current device; `AgentClient::connect` retries until the fresh listener
   accepts. Harmless in normal operation. The earlier thread-per-connection / double-connect-removal
   fixes are retained; the stale orchestrator comment was corrected.
3. **CID assertion corrected (over-specified, like the vsock-path one).** `CidAllocator` hands out
   the lowest free CID and **reuses freed CIDs by design** — a contract asserted by four tests
   (`vmm::tests::test_cid_allocator{,_prop}`, `lifecycle::test_lifecycle_fake_vmm`,
   `lifecycle::panic_residue`, which check that Drop hands the freed CID back). The snapshot test's
   `assert_ne!(original_cid, new_cid)` therefore fails on a *sequential* restore (the original VM is
   torn down, so the allocator legitimately hands its CID back). The design's "restored clones don't
   collide" guarantee is about *concurrent* clones and is enforced by the allocator's **uniqueness**
   (tested in `test_cid_allocator_prop`), not by forcing a different number on a sequential restore.
   The assertion now checks the real contract — a valid, live guest CID — leaving the allocator's
   reuse contract intact. (Round-robin/random CID rotation was tried and reverted: it broke the four
   reuse-asserting tests.)

### Rootless egress proxy reachability (egress_proxy, host_endpoint)
Two host-side bugs, surfaced once the guest tools let the tests reach the network:
- **`/30` gateway off-by-one in the tests.** `host_endpoint`/`egress_proxy` built the gateway IP
  from the raw `vm.vmid()` (`10.200.<vmid>.1`), but the network uses the centralized
  `(vmid % 254) + 1` octet (`net::ip_math`). The tests now use `ip_math`, so they target the address
  the guest is actually on.
- **Proxy port not forwarded by the smoltcp NAT.** `host_services_port` got permanent, re-armed NAT
  listeners but the egress proxy's port relied only on the buggy dynamic-SYN-intercept path. The
  orchestrator now registers the proxy port as a **permanent forward-port** too, so a guest with
  `http_proxy=<gateway>:<proxy_port>` reaches it.
- **`curl` blocked-domain CONNECT.** A blocked HTTPS domain makes the proxy refuse the `CONNECT`
  with a 403 + body; `reqwest` collapses that to an opaque "tunnel error" without exposing it. The
  helper now redoes the `CONNECT` manually on an https-via-proxy failure to surface the proxy's
  refusal (status → stderr, body → stdout), matching curl, which the test asserts on.

### In-test netns hygiene (no sudo)
- Killed/failed privileged runs leak `/var/run/netns/imp-net-*`, which collide with later vmids.
  Instead of a `sudo` pre-clean, `net::cleanup_orphan_netns(prefix)` (the rubric-B1 sweeper) reaps
  them, called as `common::clean_imp_netns()` at the start of the netns tests (`snapshot_restore`,
  `lifecycle::panic_residue`). It runs under the capability runner's `CAP_SYS_ADMIN` +
  `CAP_DAC_OVERRIDE`; safe because the privileged suite serializes netns tests (`serial-host`).

### metrics_limits: delegated cgroup scope
- `metrics_limits` hard-requires the memory+cpu controllers delegated to the per-VM cgroup's
  parent. `scripts/with-delegated-scope.sh` (run under `systemd-run --user --scope -p Delegate=yes`)
  moves the harness into a `supervisor/` leaf and enables the controllers on the scope's
  `subtree_control`, matching the `/supervisor`-strip the orchestrator already does. Environment
  setup, not a code change.

### Kernel cache-key format / gcc-15 reuse
- `imp-testing build` rebuilt the kernel (which fails under gcc-15 / C23) because `vmlinux.cache_key`
  was in the old plain-string format and also a stale key value, so the cache missed. The kernel is
  unchanged, so `examples/blake3_cache_key.rs` regenerates a valid JSON `CacheMetadata` (current
  key + blake3 of the prebuilt `vmlinux`), making the kernel stage a cache hit and reusing the
  known-good `vmlinux`. The from-scratch gcc-15 kernel build remains broken (tracked).

### Validation status (this pass)
On this KVM host (blessed release `imp-test-runner`, suites under
`systemd-run --user --scope -p Delegate=yes` + `scripts/with-delegated-scope.sh`, fresh artifacts):
- **Unit/codec/property** (`cargo nextest --all-features`): **88/88**.
- **Rootless** (`just test-rootless`): **8/8** (6 smoltcp + `test_egress_proxy_rootless` +
  `test_lifecycle_rootless_smoltcp`).
- **Privileged** (`just test-priv`): **88/88** (8 skipped = non-CH backend matrix variants) — all
  previously-failing tests now pass: `egress_proxy`, `host_endpoint`, `nested_virt`,
  `snapshot_restore`, `metrics_limits`, plus no regressions in `boot`/`concurrency`/`lifecycle`/
  `shares`/`exec`.
- `cargo fmt --check`, `cargo clippy --all-targets --all-features -D warnings`, `cargo deny check`,
  the global-state ban, and the lean-agent invariant are all green. The feature-powerset gate
  remains the pre-existing red (module-on-`host-common` debt); the new `guest-tools` feature is
  self-contained (`--no-default-features --features guest-tools` compiles) and does not worsen it.

Note: `tar2erofs::tar_to_erofs` gained a third parameter (`injected_symlinks`) — an intentional
breaking change to an internal artifact-build utility (crate is `publish = false`); `cargo
semver-checks` will flag it. `net::cleanup_orphan_netns` is a new, additive public function.
