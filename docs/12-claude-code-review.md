# Imp Testing — Rust Code Review Report

*Reviewed: 2026-06-23. Covers all source files in `src/`, `tests/`, `Cargo.toml`, `deny.toml`.*

This report checks the Rust implementation against the Rust API Guidelines, the design document (`12-claude-design-v6.md`), and general code quality standards. Findings are categorized by severity:

- **Critical** — correctness bugs, unsound unsafe code, or data loss risks
- **Major** — significant API guideline violations, missing error handling, architectural deviations
- **Minor** — style issues, missing documentation, suboptimal patterns
- **Suggestion** — nice-to-haves that would improve quality

---

## 1. Crate-level issues

### 1.1 `#![warn(missing_docs)]` instead of `#![deny(missing_docs)]` (Minor)

[lib.rs:7](file:///home/pwnall/workspace/imp-testing/src/lib.rs#L7) uses `#![warn(missing_docs)]` but `implementation-notes.md` line 53 claims `#![deny(missing_docs)]` was added. The design document (§5.2) expects comprehensive documentation enforced at compile time. `warn` allows undocumented items to silently pass CI.

**Recommendation:** Change to `#![deny(missing_docs)]`.

### 1.2 Module doc comments are placed after `#[cfg]` attributes (Minor)

In [lib.rs:14-37](file:///home/pwnall/workspace/imp-testing/src/lib.rs#L14-L37), doc comments like `/// Artifact building stages and pipeline.` appear *between* `#[cfg(...)]` and `pub mod artifact`. Rustdoc correctly associates these, but the conventional placement is before the `#[cfg]` attribute. This is a readability nitpick.

### 1.3 `log` is an unconditional dependency but `tracing` is the intended logging framework (Minor)

[Cargo.toml:102](file:///home/pwnall/workspace/imp-testing/Cargo.toml#L102) lists `log = "0.4"` as an unconditional (non-optional) dependency, while `tracing` is optional under `host-common`. The design (§5.5) standardizes on `tracing`. Having both `log` and `tracing` in the dependency graph is confusing. The `log` crate appears used only in `smoltcp.rs` via `log::trace!()`.

**Recommendation:** Use `tracing::trace!()` consistently, or enable tracing's `log` compatibility feature and drop the direct `log` dependency.

### 1.4 Feature flag naming inconsistency (Minor)

The Cargo.toml defines features like `experiment-fuse`, `experiment-smoltcp`, `experiment-erofs`, `experiment-nftables` — but the design document (§10) graduated `smoltcp` NAT (Exp 5) and `am-fs-erofs` (Exp 3) to default features. The code still gates them behind `experiment-*` flags, suggesting the naming hasn't been updated to reflect graduation.

The design's `net-rootless` feature (§5.5) should include `smoltcp` + `vhost-user-backend` deps, but the actual [Cargo.toml net-rootless](file:///home/pwnall/workspace/imp-testing/Cargo.toml#L136) is `net-rootless = ["host-common"]` — empty of actual networking deps.

**Recommendation:** Rename graduated experiments (e.g., `experiment-smoltcp` → include in `net-rootless`). The `net-rootless` feature should pull in `smoltcp`, `vhost-user-backend`, etc.

---

## 2. Rust API Guidelines violations

### 2.1 Types are not `#[non_exhaustive]` where the design requires (Major)

The design (§5.2) says: *"Types are `#[non_exhaustive]` where future fields are likely."* Most public types correctly have `#[non_exhaustive]`, but several important types do not:

| Type | File | Missing `#[non_exhaustive]` |
|---|---|---|
| `ExecRequest` | [protocol.rs:37](file:///home/pwnall/workspace/imp-testing/src/agent/protocol.rs#L37) | Yes — likely to grow (stdin, timeout, rlimits) |
| `ExecOutcome` | [protocol.rs:47](file:///home/pwnall/workspace/imp-testing/src/agent/protocol.rs#L47) | Yes — likely to grow (resource usage, duration) |
| `VmConfigBuilder` | [config.rs:187](file:///home/pwnall/workspace/imp-testing/src/config.rs#L187) | Yes (builders are typically exhaustive, but this one is public) |
| `KernelStage` | [kernel.rs:13](file:///home/pwnall/workspace/imp-testing/src/artifact/kernel.rs#L13) | Yes |
| `RootfsStage` | [rootfs.rs:13](file:///home/pwnall/workspace/imp-testing/src/artifact/rootfs.rs#L13) | Yes |
| `SnapshotStage` | [snapshot.rs:17](file:///home/pwnall/workspace/imp-testing/src/artifact/snapshot.rs#L17) | Yes |
| `Pipeline` | [artifact/mod.rs:57](file:///home/pwnall/workspace/imp-testing/src/artifact/mod.rs#L57) | Yes |
| `ProxyConfig` (in proxy/mod.rs) | [proxy/mod.rs:19](file:///home/pwnall/workspace/imp-testing/src/proxy/mod.rs#L19) | Yes — different type from `config.rs` version which does have it |

**Recommendation:** Add `#[non_exhaustive]` to all public structs/enums that are likely to grow.

### 2.2 Missing `Debug` implementations on key types (Minor)

| Type | File | Issue |
|---|---|---|
| `Pipeline` | [artifact/mod.rs:57](file:///home/pwnall/workspace/imp-testing/src/artifact/mod.rs#L57) | No `Debug` (contains `Vec<Box<dyn Stage>>`) |
| `AgentClient` | [agent/mod.rs:27](file:///home/pwnall/workspace/imp-testing/src/agent/mod.rs#L27) | Has `Debug` ✓ |

**Recommendation:** Implement `Debug` manually for `Pipeline` (can use `"Pipeline { N stages }"` format). Per Rust API Guidelines C-DEBUG, all public types should implement `Debug`.

### 2.3 Missing common trait implementations (Minor)

Per [C-COMMON-TRAITS](https://rust-lang.github.io/api-guidelines/interoperability.html#c-common-traits):

- `ResourceUsage` lacks `Hash` — it has all integer fields and derives `Eq`, so `Hash` is trivially correct.
- `CacheKey` lacks `Hash` — it wraps a `String` and derives `Eq`.
- `ExecRequest` and `ExecOutcome` lack `Hash`.
- `StageInputs`, `StageOutputs` lack `Hash` and `Default`.
- `Artifacts`, `Cache` lack `Hash`.
- `Error` does not implement `Clone` — this is expected for errors containing `std::io::Error`, which is fine.

### 2.4 `VmConfigBuilder.build()` does not validate (Major)

[config.rs:249](file:///home/pwnall/workspace/imp-testing/src/config.rs#L249): `build()` returns `VmConfig` directly, not `Result<VmConfig>`. The design (§5.3) specifically calls out validation: *"builder defaults, validation that share tags are unique, that a virtio-fs rootfs combined with snapshotting is rejected."*

**Recommendation:** Change `build()` to return `Result<VmConfig>` and validate:
- Share tags are unique
- `VirtioFs` rootfs + `snapshot_dir` combination is rejected (§3.2 contested fact)
- `vcpus > 0`, `mem_mib > 0`
- `kernel` path is non-empty

### 2.5 The `Vmm` trait uses `async_trait` but design says native `async fn` (Minor)

The design (§5.2) says: *"Async is via native `async fn` in traits; `#[async_trait]` is used only where `dyn Vmm` object-safety is required."* Since Rust 2024 edition supports `async fn` in traits natively, `#[async_trait]` is unnecessary unless `dyn Vmm` is used. Currently `Vmm` is only used as `V: Vmm` (generic bound), so native async would work.

**Recommendation:** Remove `async_trait` for `Vmm` and `VmInstance` traits if `dyn` dispatch is not needed. If `dyn` dispatch is needed for the Pipeline's `Stage` trait, only keep it there.

### 2.6 `Vmm` trait is missing `restore()` method (Major — Design Deviation)

The design (§5.2) specifies:
```rust
async fn restore(&self, snapshot: &Path, res: &PerVmResources) -> Result<Self::Instance>;
```

This method is **absent from the `Vmm` trait** in [vmm/mod.rs](file:///home/pwnall/workspace/imp-testing/src/vmm/mod.rs#L47-L58). Snapshot restore is handled implicitly via `VmConfig.snapshot_dir` inside `create()`, which conflates two semantically different operations (cold-boot vs warm-restore).

**Recommendation:** Add `restore()` to the `Vmm` trait as the design specifies. This keeps the two paths (cold create+boot vs warm restore+resume) explicit and reduces the chance of accidentally calling `boot()` on a restored VM.

---

## 3. Error handling issues

### 3.1 `Error` enum is too coarse (Major)

[error.rs:6-16](file:///home/pwnall/workspace/imp-testing/src/error.rs#L6-L16) has only three variants: `Vmm(String)`, `Io`, `Other(String)`. The design (§5.3) says: *"One `Error` enum (`thiserror`) with variants per subsystem."*

Missing variants that would improve diagnostics:
- `Agent(String)` — vsock connection/protocol errors
- `Config(String)` — validation errors
- `Proxy(String)` — egress proxy errors
- `Artifact(String)` — build pipeline errors
- `Net(String)` — networking setup errors
- `Cgroup(String)` — cgroup/metrics errors
- `Timeout` — connection/operation timeouts

The heavy use of `Error::Other(...)` throughout the codebase suggests the error enum needs expansion.

### 3.2 `.unwrap()` in production code paths (Critical)

Several `.unwrap()` calls in non-test code could panic:

| Location | unwrap() | Risk |
|---|---|---|
| [proxy/mod.rs:57](file:///home/pwnall/workspace/imp-testing/src/proxy/mod.rs#L57) | `rt.block_on(...)` builder `.unwrap()` | Panics if tokio runtime can't be created |
| [proxy/mod.rs:60](file:///home/pwnall/workspace/imp-testing/src/proxy/mod.rs#L60) | `TcpListener::bind().unwrap()` | Panics if port is unavailable |
| [proxy/mod.rs:61](file:///home/pwnall/workspace/imp-testing/src/proxy/mod.rs#L61) | `.local_addr().unwrap()` | Should not fail but still unwrap |
| [proxy/mod.rs:78](file:///home/pwnall/workspace/imp-testing/src/proxy/mod.rs#L78) | `host.to_str().unwrap_or("")` | OK — has fallback |
| [imp-guest-agent.rs:37](file:///home/pwnall/workspace/imp-testing/src/bin/imp-guest-agent.rs#L37) | `set_current_dir().unwrap()` | Panics if overlay mount failed |
| [imp-guest-agent.rs:250](file:///home/pwnall/workspace/imp-testing/src/bin/imp-guest-agent.rs#L250) | `child.wait().unwrap()` | Panics if wait fails |
| [cloud_hypervisor.rs:166](file:///home/pwnall/workspace/imp-testing/src/vmm/cloud_hypervisor.rs#L166) | hardcoded `/tmp` path | Not unwrap but fragile |
| [smoltcp.rs:164](file:///home/pwnall/workspace/imp-testing/src/net/smoltcp.rs#L164) | `signal_used_queue().unwrap()` | Panics in vhost-user backend |
| [smoltcp.rs:202](file:///home/pwnall/workspace/imp-testing/src/net/smoltcp.rs#L202) | `self.state.lock().unwrap()` | Panics on poisoned mutex |
| [smoltcp.rs:277-286](file:///home/pwnall/workspace/imp-testing/src/net/smoltcp.rs#L277-L286) | Multiple `.unwrap()` in daemon startup | Panics on any init failure |

**Recommendation:** Replace `.unwrap()` with `.expect("descriptive message")` at minimum, or better yet propagate errors where possible. The proxy's thread-spawned listener should send errors back through a channel.

### 3.3 Unsafe `setns` call lacks safety documentation (Major)

[proxy/mod.rs:47](file:///home/pwnall/workspace/imp-testing/src/proxy/mod.rs#L47):
```rust
let ret = unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) };
```
Per Rust API Guidelines [C-FAILURE](https://rust-lang.github.io/api-guidelines/documentation.html#c-failure), all unsafe blocks should have `// SAFETY:` comments explaining why the invariants are upheld. The comment on line 46 is helpful but uses `//` style instead of the `// SAFETY:` convention.

Additionally, `implementation-notes.md` says these were "hardened with Result mappings" but the code still uses `eprintln!` and continues silently on failure (line 49).

### 3.4 Unsafe `set_var` in `imp-testing.rs` (Critical)

[imp-testing.rs:22-24](file:///home/pwnall/workspace/imp-testing/src/bin/imp-testing.rs#L22-L24):
```rust
unsafe {
    std::env::set_var("SHELL", "/bin/bash");
}
```
`std::env::set_var` is unsafe in Rust 2024 edition because it is not thread-safe. This is called in `main()` before the tokio runtime starts (so technically safe), but the unsafe block lacks a `// SAFETY:` comment.

**Recommendation:** Add `// SAFETY: Called before tokio runtime starts; no other threads exist yet.`

---

## 4. Design deviations

### 4.1 iptables REDIRECT instead of nftables TPROXY (Already noted in implementation-notes.md)

[tap.rs:83-109](file:///home/pwnall/workspace/imp-testing/src/net/tap.rs#L83-L109) uses `iptables -j REDIRECT` instead of the design's `nft` TPROXY. This is documented in `implementation-notes.md` line 54 but has a significant consequence: REDIRECT only works for TCP, changes the destination, and doesn't preserve the original destination for the proxy to inspect. TPROXY preserves both.

### 4.2 Guest agent does network setup despite design saying it should not (Already noted)

The design (§5.4) says: *"Networking config stays out of the agent."* [imp-guest-agent.rs:92-106](file:///home/pwnall/workspace/imp-testing/src/bin/imp-guest-agent.rs#L92-L106) configures IP, routes, and DNS. This is documented in `implementation-notes.md` line 55.

### 4.3 `wget` instead of `reqwest` for kernel downloads (Design Deviation)

[kernel.rs:44](file:///home/pwnall/workspace/imp-testing/src/artifact/kernel.rs#L44) uses the external `wget` binary. The design (§5.4) specifies `reqwest` as the Rust crate to replace `curl`/`wget`. This is noted in `implementation-notes.md` line 56.

### 4.4 `DefaultHasher` instead of `blake3` for cache keys (Design Deviation)

[kernel.rs:29-34](file:///home/pwnall/workspace/imp-testing/src/artifact/kernel.rs#L29-L34) uses `std::collections::hash_map::DefaultHasher`. The design uses `blake3` for content-addressed cache keys. `DefaultHasher` is **not stable across Rust versions** — it may produce different hashes with different Rust compiler versions, breaking the cache. This is noted in `implementation-notes.md` line 57 but the risk is understated.

**Recommendation:** Use `blake3` or `sha2` (both already in deps) for cache keys. `DefaultHasher` is explicitly documented as not portable.

### 4.5 Missing `reconnect()` method on `AgentClient` (Major — Design Deviation)

The design (§5.2) specifies:
```rust
pub async fn reconnect(vsock_path: &Path, port: u32) -> Result<Self>;
```
This method is **absent** from [agent/mod.rs](file:///home/pwnall/workspace/imp-testing/src/agent/mod.rs). The design explains it's needed because CH re-creates the vsock socket on restore, severing the prior connection.

### 4.6 Missing serial-log panic watch in `AgentClient::connect()` (Major — Design Deviation)

The design (§5.2) specifies that `connect()` should accept a `serial_log: &Path` parameter and watch the serial log for kernel panics to fail-fast instead of retrying until timeout. The current [agent/mod.rs:37](file:///home/pwnall/workspace/imp-testing/src/agent/mod.rs#L37) `connect()` signature doesn't accept a serial log path. The retry loop in [orchestrator.rs:183-189](file:///home/pwnall/workspace/imp-testing/src/orchestrator.rs#L183-L189) is simplistic — 50 retries with 100ms sleep, no serial log watching.

### 4.7 `put_file()` is a no-op (Minor — Incomplete Implementation)

[agent/mod.rs:126-128](file:///home/pwnall/workspace/imp-testing/src/agent/mod.rs#L126-L128): `put_file()` always returns `Ok(())` without doing anything. Should either be implemented or marked with `todo!()` / `unimplemented!()`, or documented as unimplemented.

### 4.8 No `Drop` on `TestVm` for ordered teardown (Critical — Design Deviation)

The design (§5.3) says: *"`TestVm` composes everything and owns **ordered** teardown. Its `Drop` kills the VMM process group, then the virtiofsd processes, then removes the tap/netns/cgroup/overlay/sockets."*

[orchestrator.rs](file:///home/pwnall/workspace/imp-testing/src/orchestrator.rs) has **no `Drop` implementation for `TestVm`**. If a test panics, all VM resources (processes, namespaces, cgroups) will leak. The `Drop` impl on `ChInstance` handles the VMM process and cgroup, but nothing handles the `NetNamespace`, `SmoltcpProcess`, or `EgressProxy` in the panic path of `TestVm`.

**Recommendation:** Implement `Drop for TestVm<V>` that calls `kill()` on the instance, cleans up netns, stops the proxy, etc. The current design relies solely on `shutdown()` which is not called on panic.

> **Note:** `NetNamespace` does have a `Drop` impl that calls `delete()`, so if `TestVm` is dropped, the netns will be cleaned up through `Option<NetNamespace>` dropping. However, the VMM instance won't be killed in the correct order relative to the netns cleanup. The design explicitly requires ordered teardown.

### 4.9 Hardcoded `/tmp` paths throughout (Major)

Multiple locations use hardcoded `/tmp` paths:
- [cloud_hypervisor.rs:166](file:///home/pwnall/workspace/imp-testing/src/vmm/cloud_hypervisor.rs#L166): `std::env::temp_dir().join(format!("imp-vm-{}", std::process::id()))`
- [artifact/mod.rs:68](file:///home/pwnall/workspace/imp-testing/src/artifact/mod.rs#L68): `Path::new("/tmp/imp-artifacts")`
- [snapshot.rs:33-37](file:///home/pwnall/workspace/imp-testing/src/artifact/snapshot.rs#L33-L37): `"/tmp/vmlinux"`, `"/tmp/rootfs.ext4"`
- [orchestrator.rs:116](file:///home/pwnall/workspace/imp-testing/src/orchestrator.rs#L116): `/tmp/imp-smoltcp-{}.sock`

These paths collide across concurrent test processes. The VM tmp directory uses only PID, not vmid, so all VMs in the same process share a tmp dir — overwriting each other's api.sock, vsock.sock, serial.log.

**Recommendation:** Include `vmid` in the temp directory path: `imp-vm-{pid}-{vmid}`.

### 4.10 `Vmm` trait only has `create()`, missing the `restore()` warm path

This is the same issue as §2.6 but has architectural consequences: the snapshot restore path in `cloud_hypervisor.rs` is handled by checking `cfg.snapshot_dir.is_some()` inside `create()`, and the `ChInstance.restored` field gates `boot()` to call `resume` instead of `boot`. This works but makes the API less self-documenting and makes it impossible for `FakeVmm` to test the restore path independently.

---

## 5. Code quality issues

### 5.1 `ChInstance::api_request` is fragile (Major)

[cloud_hypervisor.rs:123-156](file:///home/pwnall/workspace/imp-testing/src/vmm/cloud_hypervisor.rs#L123-L156):

1. **Response buffer is fixed at 4096 bytes** (line 149). A large error response would be truncated, and a chunked response would be partially read.
2. **Only one `read()` call** — doesn't handle partial reads or responses larger than 4096 bytes.
3. **Hand-rolled HTTP parsing** — checks if response starts with `"HTTP/1.1 200"` or `"HTTP/1.1 204"`. This misses other 2xx status codes, doesn't parse headers or body, and is fragile against HTTP/1.0 or different whitespace.
4. **No connection reuse** — opens a new Unix socket for every API call, which has overhead.

**Recommendation:** Use `hyperlocal` (already in deps) with `hyper` for proper HTTP/1.1 over Unix sockets, or at minimum handle partial reads and more robust status checking.

### 5.2 `EgressProxy` spawns a thread with multiple unwraps (Major)

[proxy/mod.rs:42-107](file:///home/pwnall/workspace/imp-testing/src/proxy/mod.rs#L42-L107): The proxy listener runs in a detached thread with no error propagation. If `TcpListener::bind()` fails, the thread panics and the `oneshot::channel` receiver will get a `RecvError` — but the error message won't explain *why* binding failed.

**Recommendation:** Send errors back through the oneshot channel as `Result<u16>`.

### 5.3 No HTTPS interception (Noted — Implementation Gap)

The proxy only handles HTTP. The design (§5.3 / §6) requires HTTPS MITM with on-the-fly cert minting via `rcgen`. The `rustls`, `tokio-rustls`, `rcgen`, `rustls-pemfile` crates are declared in deps but unused. This is noted in `implementation-notes.md` line 59.

### 5.4 `EgressProxy` lacks request logging and test doubles (Major — Design Gap)

The design (§5.2) specifies:
```rust
pub fn requests(&self) -> RequestLog;              // observed requests
pub fn install_double(&self, m: Matcher, r: Responder);
pub fn record_to(&self, cassette: &Path);
```

None of these are implemented. The proxy just forwards requests with `println!()` logging. There's no `proxy/doubles.rs` or `proxy/tls.rs` module as the design layout specifies.

### 5.5 `metrics.rs` is a stub (Major — Incomplete)

[metrics.rs](file:///home/pwnall/workspace/imp-testing/src/metrics.rs) is only 22 lines — just the `ResourceUsage` struct. The design (§5.3) calls for a metrics module that:
- Creates per-VM cgroup v2 slices
- Applies `ResourceLimits`
- Reads `memory.peak`/`cpu.stat`/`io.stat`
- Computes average from periodic deltas

The cgroup logic is split across [orchestrator.rs:130-153](file:///home/pwnall/workspace/imp-testing/src/orchestrator.rs#L130-L153) (creation) and [cloud_hypervisor.rs:379-414](file:///home/pwnall/workspace/imp-testing/src/vmm/cloud_hypervisor.rs#L379-L414) (reading). This scattering violates the design's module responsibility separation.

**Recommendation:** Move cgroup creation, reading, and limit enforcement into `metrics.rs` as the design specifies.

### 5.6 No `firecracker.rs` or `qemu.rs` backends (Minor — Expected)

The design describes Firecracker and QEMU backends behind feature flags. These don't exist yet, which is fine for current milestones.

### 5.7 `Pipeline::build()` uses filename-based stage dispatch (Minor)

[artifact/mod.rs:74-80](file:///home/pwnall/workspace/imp-testing/src/artifact/mod.rs#L74-L80):
```rust
let out_path = if stage.name() == "kernel" {
    out_dir.join("vmlinux")
} else if stage.name() == "rootfs" {
    out_dir.join("rootfs.erofs")
} else {
    out_dir.join(stage.name())
};
```
This hardcodes output filenames based on stage names using string comparisons. The design's `Stage` trait has `cache_key()` for this purpose.

**Recommendation:** Each stage should declare its output filename(s) through the trait, or the `cache_key` should determine the output path.

### 5.8 `Pipeline::reset_to()` is a no-op (Minor)

[artifact/mod.rs:98-100](file:///home/pwnall/workspace/imp-testing/src/artifact/mod.rs#L98-L100) always returns `Ok(())` without deleting any outputs. This is a documented stub.

### 5.9 `StageInputs` and `StageOutputs` are empty structs (Minor — Noted in implementation-notes.md)

The pipeline currently ignores stage chaining — stages don't pass outputs to downstream stages. This makes the pipeline unable to fulfill the design's "deterministic given inputs" guarantee.

---

## 6. Testing gaps

### 6.1 Missing unit tests

| Module | What needs testing | Priority |
|---|---|---|
| `config.rs` | **Duplicate share tag validation** (once implemented), vcpus=0 rejection, snapshot+virtiofs rejection | High |
| `config.rs` | Builder `snapshot_dir()` method, all builder methods combined | Medium |
| `net/tap.rs` | `/30` address math: guest IP, subnet mask, boundary vmids (0, 254, 255) | High |
| `vmm/mod.rs` | `CidAllocator` — concurrent allocation, wraparound behavior at `u32::MAX` | High |
| `orchestrator.rs` | `allocate_vmid` — wraparound at 254, thread-safety under contention | High |
| `agent/protocol.rs` | Round-trip with `LengthDelimitedCodec` framing (not just postcard) | Medium |
| `proxy/mod.rs` | URI reconstruction logic | Medium |
| `artifact/mod.rs` | `Pipeline::build` caching logic (skip when output exists) | Medium |
| `artifact/tar2erofs.rs` | `normalize_path` function (pure), directory creation for missing parents | High |
| `error.rs` | All error variant `Display` implementations, `From` conversions | Low (exists) |

### 6.2 Missing integration tests

| Test | What's missing | Design requirement |
|---|---|---|
| `snapshot_restore.rs` | Tests restore path but doesn't verify vsock **reconnection** (severed+reconnected) | §5.2 |
| `snapshot_restore.rs` | No CID/MAC **rotation** verification on restore | §7 snapshot stage |
| `snapshot_restore.rs` | No entropy reseed / clock resync verification | §7 snapshot stage |
| `egress_proxy.rs` | No **HTTPS** interception test | §6 req 4 |
| `egress_proxy.rs` | No **test double** registration test (`install_double`) | §5.2 proxy |
| `egress_proxy.rs` | No **filter/block** test (guest sees the block) | M5 integration test |
| `metrics_limits.rs` | No `memory.max` **kill** test (runaway allocator OOM-killed) | M6 |
| `metrics_limits.rs` | No average CPU computation test | M6 |
| All tests | No `FakeVmm` unit test exercising orchestrator logic without KVM | §5.6 |
| Missing | No **lifecycle** test for ordered `Drop` teardown on panic | §5.3 orchestrator |
| Missing | No **concurrent VMs** test verifying CID/VMID collision freedom | §9 |
| Missing | No **signing-chain verification** test (tampered package digest) | §7 build pipeline |
| Missing | No **cache hit** test (second build skips stages) | §7 build pipeline |
| Missing | No `reset_to` test | §7 build pipeline |

### 6.3 Test infrastructure issues

1. [tests/common/mod.rs](file:///home/pwnall/workspace/imp-testing/tests/common/mod.rs) has no doc comments.
2. No test helper for creating a `VmConfig` with standard test defaults — each test duplicates the config setup.
3. No `#[ignore]` attributes on tests requiring real VMs — `cargo test` on a laptop without KVM/artifacts will fail, not skip.
4. No serial_test annotations despite the implementation notes mentioning they were needed.

### 6.4 Design's testability accommodations (§5.6) — assessment

| Accommodation | Status |
|---|---|
| `FakeVmm` + `FakeVmInstance` | ✅ Implemented in [vmm/mod.rs](file:///home/pwnall/workspace/imp-testing/src/vmm/mod.rs#L106-L171) |
| Pure/imperative split for unit testing | ⚠️ Partial — `host_ip()` and `allocate_vmid()` are testable pure functions, but nft-rule rendering, CH REST payload builder, vsock handshake state machine, and cgroup-path construction are NOT extracted as pure functions |
| Injectable side-effect traits (`Netlink`, `NftApplier`, `CgroupFs`, `SerialLog`) | ❌ Not implemented — the code calls `ip` commands directly, reads cgroups directly, no trait abstraction |
| Deterministic IDs and clocks | ⚠️ Partial — `CidAllocator` and `allocate_vmid` exist but use global atomics (not injectable); no `Clock` trait |

---

## 7. Documentation issues

### 7.1 Missing module-level documentation

While most modules have module-level doc comments (`//! ...`), they are sparse. Per Rust API Guidelines [C-CRATE-DOC](https://rust-lang.github.io/api-guidelines/documentation.html#c-crate-doc):

- [lib.rs](file:///home/pwnall/workspace/imp-testing/src/lib.rs#L1-L5): Good crate docs but could include a usage example.
- [smoltcp.rs](file:///home/pwnall/workspace/imp-testing/src/net/smoltcp.rs): No module-level doc comment (just `#[cfg]` gating).
- [fs_in_process.rs:1](file:///home/pwnall/workspace/imp-testing/src/fs_in_process.rs#L1): The `//!` doc comment has a blank line before the text.

### 7.2 Missing doc examples (C-EXAMPLE)

No public API has `# Examples` sections in doc comments. At minimum, `VmConfig::builder()`, `AgentClient::connect()`, `TestVm::start()`, and `Pipeline::build()` should have examples.

### 7.3 Missing `# Panics` documentation

Functions that can panic should document it:
- `imp-guest-agent.rs` `main()` — can panic from multiple `.unwrap()` calls
- `SmoltcpProcess::start()` — panics on thread initialization failures

### 7.4 Missing `# Safety` documentation on unsafe blocks

- [proxy/mod.rs:47](file:///home/pwnall/workspace/imp-testing/src/proxy/mod.rs#L47): `unsafe { libc::setns(...) }` — needs `// SAFETY:` comment
- [imp-testing.rs:22-24](file:///home/pwnall/workspace/imp-testing/src/bin/imp-testing.rs#L22-L24): `unsafe { std::env::set_var(...) }` — needs `// SAFETY:` comment

---

## 8. Concurrency and resource management

### 8.1 Global mutable atomics for CID and VMID allocation (Major)

Both `NEXT_CID` ([vmm/mod.rs:18](file:///home/pwnall/workspace/imp-testing/src/vmm/mod.rs#L18)) and `VMID_COUNTER` ([orchestrator.rs:14](file:///home/pwnall/workspace/imp-testing/src/orchestrator.rs#L14)) are `static AtomicU32`. Problems:

1. **No wraparound protection** for CID — `fetch_add` will wrap to 0 at `u32::MAX`, producing CID 0, 1, 2 which are reserved (0=hypervisor, 1=host, 2=host).
2. **VMID wraps at 254** (`(c % 254) + 1`) but the atomic counter keeps incrementing, so after 254 VMs, VMIDs start colliding with currently-running VMs (assuming some are still alive).
3. **Not injectable** — unit tests can't reset or control these, so CID/VMID values leak between test cases.

**Recommendation:** Make `CidAllocator` a proper struct with `allocate()` and `release()` methods, injected into the orchestrator. Track which CIDs/VMIDs are in-use, not just a monotonic counter.

### 8.2 Mutex poisoning in smoltcp backend

[smoltcp.rs:202](file:///home/pwnall/workspace/imp-testing/src/net/smoltcp.rs#L202), [smoltcp.rs:224](file:///home/pwnall/workspace/imp-testing/src/net/smoltcp.rs#L224), [smoltcp.rs:308](file:///home/pwnall/workspace/imp-testing/src/net/smoltcp.rs#L308) and many other locations use `.lock().unwrap()` on a shared `Mutex`. If any thread panics while holding the lock, all other threads will also panic due to mutex poisoning. This is a cascading failure risk.

**Recommendation:** Use `lock().unwrap_or_else(|e| e.into_inner())` to recover from poisoned mutexes, or use `parking_lot::Mutex` which doesn't poison.

### 8.3 Thread leak in `SmoltcpProcess` and `EgressProxy` (Major)

Both `SmoltcpProcess::start()` and `EgressProxy::start()` spawn threads/runtimes that run forever. Neither has a `Drop` implementation or shutdown mechanism. When a `TestVm` is dropped:

- The smoltcp background threads continue running
- The proxy thread continues running
- There's no way to shut them down

**Recommendation:** Store `JoinHandle` and implement shutdown signaling (e.g., through a cancellation token or kill eventfd).

---

## 9. Cargo.toml and build system

### 9.1 `cgroups-rs` is imported conditionally but used unconditionally (Critical)

[orchestrator.rs:10](file:///home/pwnall/workspace/imp-testing/src/orchestrator.rs#L10):
```rust
use cgroups_rs::{cgroup_builder::CgroupBuilder, hierarchies};
```
This is a top-level import without `#[cfg(feature = "metrics")]` gating. If someone builds with `--no-default-features --features cloud-hypervisor`, the `cgroups-rs` crate won't be available and compilation will fail.

Similarly, [cloud_hypervisor.rs:383](file:///home/pwnall/workspace/imp-testing/src/vmm/cloud_hypervisor.rs#L383) uses `cgroups_rs::Cgroup` without feature-gating.

**Recommendation:** Gate all `cgroups-rs` usage behind `#[cfg(feature = "metrics")]` and make the orchestrator's cgroup logic conditional.

### 9.2 Feature flag `fuse-backend-rs`, `vhost`, etc. conflict with dep names (Minor)

[Cargo.toml:153-159](file:///home/pwnall/workspace/imp-testing/Cargo.toml#L153-L159) defines features named identically to their dependencies (`fuse-backend-rs = ["dep:fuse-backend-rs"]`). These features are unnecessary — `dep:fuse-backend-rs` can be used directly. Having both a feature and dep with the same name can cause confusion.

### 9.3 `am-fs-erofs` not in `deny.toml` allow-list verification (Minor)

The design (§5.4) warns: *"`am-fs-erofs` is obscure — confirm its license and maintenance via `cargo-deny`."* The `deny.toml` allow-list should be verified against this crate's actual license.

### 9.4 `qapi` features don't match design (Minor)

[Cargo.toml:52](file:///home/pwnall/workspace/imp-testing/Cargo.toml#L52) uses `features = ["qmp", "qga", "async-tokio"]` but the design (§5.5) says `["qmp", "qga", "tokio-stream"]`.

---

## 10. Implementation deviations to add to `implementation-notes.md`

The following justified deviations are observed but **not yet documented** in `implementation-notes.md`:

1. **`CONFIG_IP_PNP` not actually used** — The design (§5.4 / §7) says the guest IP is set via the kernel `ip=` boot parameter so PID 1 needs no netlink. But the kernel cmdline in [cloud_hypervisor.rs:250-261](file:///home/pwnall/workspace/imp-testing/src/vmm/cloud_hypervisor.rs#L250-L261) does NOT include an `ip=` parameter. Instead, the guest agent does network setup with `ip addr add` / `ip route add` commands ([imp-guest-agent.rs:95-106](file:///home/pwnall/workspace/imp-testing/src/bin/imp-guest-agent.rs#L95-L106)). This means the guest kernel doesn't need `CONFIG_IP_PNP=y` in the current implementation, contrary to the design.

2. **`experiment-fuse` is in default features** — [Cargo.toml:120](file:///home/pwnall/workspace/imp-testing/Cargo.toml#L120) includes `experiment-fuse` in the default feature set, meaning the in-process virtiofsd is the default path, not the virtiofsd daemon. The design (§10 Exp 1) says this experiment is "underway" and "virtiofsd remains the fallback." The status mismatch should be documented.

3. **`tokio-util` with `codec` feature added** — [Cargo.toml:40](file:///home/pwnall/workspace/imp-testing/Cargo.toml#L40) includes `tokio-util` for the `LengthDelimitedCodec` framing. This dependency is not mentioned in the design's `Cargo.toml` sketch (§5.5), but is justified — it provides the length-delimited framing that the design describes.

---

## 11. Summary of recommendations by priority

### Critical (fix before next milestone)
1. **Add `Drop` for `TestVm`** — ordered teardown on panic (§4.8)
2. **Fix temp directory collision** — include vmid in path (§4.9)
3. **Fix `cgroups-rs` unconditional import** — feature-gate it (§9.1)
4. **Replace `.unwrap()` in production code** with proper error handling (§3.2)
5. **Fix `DefaultHasher` for cache keys** — use stable hash function (§4.4)

### Major (fix soon)
6. Add `restore()` to `Vmm` trait per design (§2.6)
7. Expand `Error` enum with per-subsystem variants (§3.1)
8. Add `reconnect()` to `AgentClient` (§4.5)
9. Make `VmConfigBuilder.build()` return `Result` with validation (§2.4)
10. Move cgroup logic into `metrics.rs` (§5.5)
11. Add shutdown mechanism for spawned threads (§8.3)
12. Fix CID/VMID allocation to handle in-use tracking (§8.1)
13. Replace hand-rolled HTTP in `api_request()` with proper client (§5.1)
14. Add `#[non_exhaustive]` to remaining public types (§2.1)

### Minor (improve incrementally)
15. Change `#![warn(missing_docs)]` to `#![deny(missing_docs)]` (§1.1)
16. Add doc examples to key public APIs (§7.2)
17. Fix feature flag naming (experiment-* → graduated names) (§1.4)
18. Implement `put_file()` or mark it `todo!()` (§4.7)
19. Add `// SAFETY:` comments to all unsafe blocks (§7.4)
20. Remove dual `log`/`tracing` dependency (§1.3)
21. Add `#[ignore]` to tests requiring real VM infrastructure (§6.3)
22. Implement injectable traits for testability (§6.4)
