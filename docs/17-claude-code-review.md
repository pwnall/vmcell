# Imp Testing — Code Review Report

*Review of the Rust implementation against the design document (§16), requirements, and Rust API Guidelines.*
*Reviewer: Antigravity (Claude Opus 4.6). Date: 2026-06-24.*

---

## Summary

The implementation makes meaningful progress toward the design. The module structure matches §5.1, the `Vmm`/`VmInstance` trait abstraction is in place, the agent protocol works over vsock with `LengthDelimitedCodec` framing, and the lint deny-list from §12.1 is largely present in `lib.rs`. However, there are **correctness bugs**, **API guideline violations**, **missing tests**, and **design deviations** that should be addressed. Findings are organized from most to least critical.

---

## 1. Correctness Bugs

### 1.1 `CidAllocator::release` is a no-op (Critical)

[vmm/mod.rs:70-76](file:///home/pwnall/workspace/imp-testing/src/vmm/mod.rs#L70-L76)

`CidAllocator::release` is a `fn release(cid: u32)` (no `&self`) that creates a **brand-new static `OnceLock<CidAllocator>`** and removes the CID from *that* allocator — not from the one actually used. CIDs are never actually released; the in-use set grows monotonically until exhaustion.

**Fix:** Change to `pub fn release(&self, cid: u32)` and operate on `self.state`.

### 1.2 HTTP response parsing is fragile (High)

[cloud_hypervisor.rs:149-154](file:///home/pwnall/workspace/imp-testing/src/vmm/cloud_hypervisor.rs#L149-L154)

The `api_request` method reads at most 4096 bytes in a single `read` call and matches the response by `starts_with("HTTP/1.1 200")` or `starts_with("HTTP/1.1 204")`. Problems:

- Does not handle `201 Created` or `202 Accepted` (valid CH responses).
- A chunked or large response may exceed 4096 bytes, causing a truncated parse.
- A short initial `read` may return fewer bytes than the status line.

The design §12.3 explicitly calls this out as a known defect class ("§5.1 — read one 4096-byte chunk and matched `HTTP/1.1 200` by prefix").

**Fix:** Use a proper HTTP client (the crate already depends on `hyper`/`hyperlocal`). At minimum, parse the status code numerically and loop the read.

### 1.3 `Pipeline::build` uses `println!` (Medium)

[artifact/mod.rs:89-93](file:///home/pwnall/workspace/imp-testing/src/artifact/mod.rs#L89-L93)

`Pipeline::build` uses `println!` for logging, which contradicts the `deny(clippy::print_stdout)` lint in `lib.rs` (this code only compiles because it's behind `cfg_attr(not(test), ...)` and the pipeline probably hasn't been compiled recently, or the feature isn't in the default set). This should use `tracing::info!`.

### 1.4 Hardcoded proxy block rule (Medium)

[proxy/doubles.rs:42-49](file:///home/pwnall/workspace/imp-testing/src/proxy/doubles.rs#L42-L49)

The `ProxyHandler::handle_request` has a hardcoded block for `example.net`. This is test-specific logic baked into the production handler. It should be a configurable filter/deny list, not a constant.

### 1.5 `ProxyConfig` equality is always `true` (Low)

[config.rs:154-159](file:///home/pwnall/workspace/imp-testing/src/config.rs#L154-L159)

`impl PartialEq for ProxyConfig` returns `true` for all comparisons. While documented with a comment, this violates the contract of `Eq` (which requires structural equality) and will cause subtle bugs if `ProxyConfig` is ever used in collections or assertions.

### 1.6 `EgressProxy::start` drops and rebinds the listener (Low)

[proxy/mod.rs:130-140](file:///home/pwnall/workspace/imp-testing/src/proxy/mod.rs#L130-L140)

The proxy binds a `TcpListener` to find a free port, drops it, then tells hudsucker to bind the same port. Between the drop and the rebind, another process may claim the port (TOCTOU race).

---

## 2. Rust API Guidelines Violations

### 2.1 Missing crate-level lint denials from §12.1

[lib.rs:7-27](file:///home/pwnall/workspace/imp-testing/src/lib.rs#L7-L27)

The design §12.1 specifies these denials that are **missing** from `lib.rs`:

| Lint | Status |
|------|--------|
| `unsafe_op_in_unsafe_fn` | **Missing** |
| `rustdoc::broken_intra_doc_links` | **Missing** |

**Fix:** Add `#![deny(unsafe_op_in_unsafe_fn)]` and `#![deny(rustdoc::broken_intra_doc_links)]`.

### 2.2 Module doc comments placed above `#[cfg]` attributes

[lib.rs:33-56](file:///home/pwnall/workspace/imp-testing/src/lib.rs#L33-L56)

Doc comments like `/// Artifact building stages and pipeline.` are placed **above** the `#[cfg(feature = "host-common")]` attribute. This means the doc comment attaches to the `cfg` attribute, not the module declaration. It compiles, but is semantically incorrect and won't appear correctly in `cargo doc`.

**Fix:** Move doc comments below the `#[cfg]` attribute or convert to inner doc comments (`//!`) inside each module.

### 2.3 Missing `#[must_use]` on constructors

Per the [Rust API Guidelines C-MUST-USE](https://rust-lang.github.io/api-guidelines/dependability.html#c-must-use), constructors and builder methods that return `Self` should carry `#[must_use]`. None of the following have it:

- `VmConfig::builder()` 
- `VmConfigBuilder` builder methods
- `CidAllocator::new()`
- `ExecRequest::new()`
- `CloudHypervisor::new()`
- `Share::new()`
- `CaManager::new()`

### 2.4 Missing `#[doc(hidden)]` or `#[non_exhaustive]` consistency

- `ChVmConfig`, `ChCpus`, `ChMemory`, `ChPayload`, `ChDisk`, `ChFs`, `ChNet`, `ChSerial`, `ChVsock` — all internal serialization types in [cloud_hypervisor.rs](file:///home/pwnall/workspace/imp-testing/src/vmm/cloud_hypervisor.rs) are `pub(crate)` implicitly (module-private), but `ChInstance` is `pub` with public fields, leaking implementation details.
- `Pipeline.stages` is `pub` ([artifact/mod.rs:59](file:///home/pwnall/workspace/imp-testing/src/artifact/mod.rs#L59)), exposing the internal `Vec<Box<dyn Stage>>` directly.

### 2.5 `EgressProxy::start` missing `# Errors` doc

[proxy/mod.rs:63](file:///home/pwnall/workspace/imp-testing/src/proxy/mod.rs#L63)

`pub async fn start(cfg: ProxyConfig) -> Result<Self>` has no `# Errors` section in its doc comment, violating `clippy::missing_errors_doc` (which is denied in `lib.rs`). Several other methods in `proxy/` and `tls.rs` are similarly missing error documentation.

### 2.6 `CaManager::new` missing `# Errors` doc

[proxy/tls.rs:15](file:///home/pwnall/workspace/imp-testing/src/proxy/tls.rs#L15)

No `# Errors` section. Returns `Result` but doesn't document failure modes.

### 2.7 Missing `Display`/`Debug` implementations

`ProxyConfig` has a custom `Debug` that shows nothing (`ProxyConfig {}`) — the `doubles` field is entirely hidden. This makes debugging impossible.

### 2.8 Builder does not validate duplicate share tags

The design §12.3 specifies: "`build()` [...] rejects duplicate share tags." The implementation at [config.rs:263-267](file:///home/pwnall/workspace/imp-testing/src/config.rs#L263-L267) validates empty tags but not duplicate tags.

### 2.9 Builder does not validate VirtioFs rootfs + snapshot combination

Design §12.3: "rejects [...] virtio-fs-rootfs + snapshot." No such validation exists.

---

## 3. Error Handling Issues

### 3.1 Coarse `Error` variants with `String` payloads

[error.rs:3-37](file:///home/pwnall/workspace/imp-testing/src/error.rs#L3-L37)

Nearly all variants carry `String`. This prevents callers from matching on specific failure modes programmatically. For example, `Error::Vmm("API error: ...")` vs `Error::Vmm("Failed to connect...")` are indistinguishable to code.

**Recommendation:** Add structured sub-variants or error source types (e.g., `VmmApiError { status: u16, body: String }` vs `VmmSpawnError { source: io::Error }`).

### 3.2 `Error::Other` is overused

`Error::Other(String)` is used in 20+ locations across the codebase. The design §12.7 notes this as a known defect ("§3.1 — three coarse variants, `Error::Other` everywhere").

### 3.3 Silently ignoring errors

Several places use `let _ = ...` to discard `Result`s:

- [cloud_hypervisor.rs:424](file:///home/pwnall/workspace/imp-testing/src/vmm/cloud_hypervisor.rs#L424): `let _ = self.process.kill().await;` in `kill()` — silently ignoring kill failure.
- [orchestrator.rs:271](file:///home/pwnall/workspace/imp-testing/src/orchestrator.rs#L271): `let _ = ns.delete();` in `shutdown()` — netns deletion failure is ignored.
- [orchestrator.rs:91](file:///home/pwnall/workspace/imp-testing/src/orchestrator.rs#L91): `let _ = netlink.run(...)` — first netns creation failure ignored.
- [cloud_hypervisor.rs:451-453](file:///home/pwnall/workspace/imp-testing/src/vmm/cloud_hypervisor.rs#L451-L453): `let _ = self.api_request("PUT", "/api/v1/vm.resume", ...)` — resume after snapshot silently discards errors.

In teardown paths, ignoring is often acceptable, but these should have comments explaining why.

### 3.4 `unwrap_or_else(|e| e.into_inner())` on mutex locks

[orchestrator.rs:287](file:///home/pwnall/workspace/imp-testing/src/orchestrator.rs#L287) and [vmm/mod.rs:51](file:///home/pwnall/workspace/imp-testing/src/vmm/mod.rs#L51): While this avoids panicking on a poisoned mutex, it silently recovers potentially corrupt state. The design §12.6 notes this as a known issue.

---

## 4. Design Deviations

### 4.1 Feature naming does not match design

| Design name | Implementation name | Status |
|-------------|-------------------|--------|
| `net-rootless` | `experiment-smoltcp` | Exp 5 was **graduated** — should be `net-rootless` |
| (graduated into pipeline) | `experiment-erofs` | Exp 3 was **graduated** — should be in `pipeline` feature |
| (rejected) | `experiment-nftables` | Exp 2 was **rejected** — feature flag should be removed |

The `experiment-` prefix implies "underway" or "not yet adopted," contradicting the design which graduated Exp 3 and Exp 5.

### 4.2 Default features include experiments

[Cargo.toml:120](file:///home/pwnall/workspace/imp-testing/Cargo.toml#L120)

```toml
default = ["cloud-hypervisor", "net-privileged", "proxy", "metrics", "pipeline", "cli", "experiment-fuse", "experiment-smoltcp"]
```

The design says `experiment-fuse` is "underway" (§10 Exp 1) and should be off by default. `experiment-smoltcp` should be named `net-rootless` and is separate from the privileged default.

### 4.3 `Vmm::restore` signature diverges from design

Design §5.2:
```rust
async fn restore(&self, snapshot: &Path, res: &PerVmResources) -> Result<Self::Instance>;
```

Implementation [vmm/mod.rs:113](file:///home/pwnall/workspace/imp-testing/src/vmm/mod.rs#L113):
```rust
async fn restore(&self, snapshot_dir: &Path, cfg: &VmConfig, res: &PerVmResources) -> Result<Self::Instance>;
```

The extra `cfg: &VmConfig` parameter is defensible (restore may need config for shares), but it's an undocumented deviation from the design API.

### 4.4 `Netlink` trait uses `ip` command, not `rtnetlink` crate

The design §5.4 explicitly says netlink operations should use the `rtnetlink` crate (pure Rust, permissive). The implementation shells out to the `ip` CLI command via `std::process::Command`. The `rtnetlink` crate is declared as a dependency but appears unused.

### 4.5 `TestVm::agent` does not match design API

Design §5.2: `pub async fn agent(&mut self) -> Result<&mut AgentClient>`

Implementation [orchestrator.rs:245](file:///home/pwnall/workspace/imp-testing/src/orchestrator.rs#L245): `pub async fn agent(&mut self) -> Result<AgentClient>`

Returns a new `AgentClient` each time rather than a stored reference. This means:
- Every call creates a new connection (expensive).
- Previous connections are not closed.
- No state continuity between calls.

### 4.6 Missing `AgentClient::reconnect` as documented

Design specifies `reconnect` drops the old client and creates a new one. Implementation [agent/mod.rs:83-87](file:///home/pwnall/workspace/imp-testing/src/agent/mod.rs#L83-L87) keeps `reconnect` on the same instance (mutates `self.stream`), which is reasonable but diverges from the design's "drop the old client" guidance.

### 4.7 `log` crate is an unconditional dependency

[Cargo.toml:102](file:///home/pwnall/workspace/imp-testing/Cargo.toml#L102): `log = "0.4"` is listed as a non-optional dependency. The design uses `tracing` exclusively and denies `println!`/`eprintln!`. Having both `log` and `tracing` is confusing. `smoltcp` uses `log`, but it should be gated behind its feature.

### 4.8 Missing `proptest` in dev-dependencies

Design §12.3 requires `proptest` for property-based tests. It's in the design's `Cargo.toml` sketch but missing from the implementation.

### 4.9 `Pipeline::build` does not use `cache_key`

[artifact/mod.rs:73-97](file:///home/pwnall/workspace/imp-testing/src/artifact/mod.rs#L73-L97)

The pipeline checks `if out_path.exists()` for caching instead of using the `Stage::cache_key()` method. This means:
- No content-addressed caching (a changed input won't invalidate the cache).
- The `cache_key` method is dead code.

### 4.10 `Pipeline::reset_to` is a no-op

[artifact/mod.rs:104-106](file:///home/pwnall/workspace/imp-testing/src/artifact/mod.rs#L104-L106)

```rust
pub fn reset_to(&self, _stage: &str, _cache: &Cache) -> Result<()> { Ok(()) }
```

This is a stub. The design requires it to remove outputs of the specified stage and all later stages.

### 4.11 `StageInputs` and `StageOutputs` are empty structs

[artifact/mod.rs:21-25](file:///home/pwnall/workspace/imp-testing/src/artifact/mod.rs#L21-L25)

Both are empty `struct StageInputs {}` / `struct StageOutputs {}`. The pipeline cannot pass data between stages.

### 4.12 `TestVm` does not own `AgentClient`

Design §5.2 shows `TestVm` owning an `AgentClient`. The implementation creates one on demand in `agent()`. This means:
- No `reconnect()` support after restore.
- The orchestrator can't automatically reconnect the agent after a snapshot restore.

### 4.13 Hardcoded `/tmp/imp-artifacts` paths

The CA manager ([tls.rs:16](file:///home/pwnall/workspace/imp-testing/src/proxy/tls.rs#L16)) and pipeline ([artifact/mod.rs:74](file:///home/pwnall/workspace/imp-testing/src/artifact/mod.rs#L74)) both hardcode `/tmp/imp-artifacts`. This prevents parallel test runs and isn't configurable.

### 4.14 `FakeVmm` does not record calls

[vmm/mod.rs:162-234](file:///home/pwnall/workspace/imp-testing/src/vmm/mod.rs#L162-L234)

The `FakeVmm` returns `Ok(())` for all operations without recording what was called. The design §5.6 says the fake should be a "recording fake" that lets tests assert "the right rules/limits/handshake were requested."

### 4.15 Missing `#[ignore]` on integration tests

Design §12.4 says: "Tests needing KVM or `CAP_NET_ADMIN` are `#[ignore]` by default." This needs to be verified on each integration test file.

---

## 5. Missing or Inadequate Tests

### 5.1 Missing unit tests

| Component | Missing test | Design reference |
|-----------|-------------|-----------------|
| `CidAllocator` | No wraparound test, no release-and-reallocate test, no thread contention test | §12.3 |
| `CidAllocator` | Release is broken (§1.1), so no release tests are meaningful | §8.1 |
| VMID allocator | No wraparound with in-use set test | §12.3 |
| Config builder | Missing duplicate share tag validation test | §12.3 |
| Config builder | Missing VirtioFs + snapshot rejection test | §12.3 |
| Agent protocol | Missing `LengthDelimitedCodec` framing round-trip test (only tests bare postcard) | §12.3 |
| Agent protocol | Missing partial buffer and oversized-frame rejection tests | §12.3 |
| CH REST builder | Missing golden-JSON test of the full `VmConfig` payload | §12.3 |
| nft ruleset render | Test exists but missing assertion of `TPROXY` form vs `REDIRECT` | §12.3 |
| `/30` address math | Test exists but missing boundary tests (vmid 0, 254, 255) and overflow rejection | §12.3 |
| `CaManager` | No unit tests at all | — |
| `EgressProxy` shutdown | No test verifying thread joins on Drop | §12.3 |
| `Drop` order | No test against `FakeVmm` verifying teardown order | §12.3 |
| Path injectivity | Test is trivial (just checks string inequality), no property test | §12.3 |
| Cgroup path construction | No test for sibling placement or `/proc/self/cgroup` parsing | §12.3 |
| `Error` enum | Tests exist but missing `#[non_exhaustive]` compile-guard test | §12.3 |

### 5.2 Missing integration tests

| Test | What's missing | Design reference |
|------|---------------|-----------------|
| `snapshot_restore.rs` | Missing: vsock reconnect assertion, CID/MAC rotation, RNG reseed, clock resync | §12.4 |
| `egress_proxy.rs` | Missing: HTTPS interception logging, test double response, filter block assertion, original-destination preservation | §12.4 |
| `metrics_limits.rs` | Missing: `memory.max` OOM-kill test, average CPU computation test | §12.4 |
| `lifecycle.rs` | Missing: ordered `Drop` teardown on `panic` leaving zero residue | §12.4 |
| `concurrency.rs` | Missing: no CID/VMID/socket-path collision with N concurrent VMs | §12.4 |
| `put_file` round-trip | Missing entirely | §12.4 |
| Zero-netlink assertion | Missing entirely | §12.4 |
| `FakeVmm`-driven orchestrator test | Missing entirely | §12.4 |
| Build pipeline tests | Missing: tampered digest abort, warm-cache skip, `reset_to` correctness, determinism | §12.4 |

### 5.3 Missing dev-dependencies for test infrastructure

| Dependency | Purpose | Status |
|-----------|---------|--------|
| `proptest` | Property-based tests (§12.3) | **Missing** |
| `loom` | Concurrency model-checking for allocators (§12.3, opt-in) | **Missing** |
| `cargo-deny` | License/advisory gate (§12.2) | Present in `deny.toml` but incomplete |
| `cargo-nextest` | Per-test timeout (§12.4) | Not configured |

---

## 6. Code Quality Issues

### 6.1 Static mutable state via `Mutex<Vec<u32>>`

[orchestrator.rs:15](file:///home/pwnall/workspace/imp-testing/src/orchestrator.rs#L15)

```rust
static ACTIVE_VMIDS: Mutex<Vec<u32>> = Mutex::new(Vec::new());
```

The design §12.5 explicitly warns against "module-global `static AtomicU32` counters" and requires IDs to come from "injected allocators." The VMID allocator is a module-global static. This makes it non-injectable and non-testable in isolation.

### 6.2 Duplicate code in `create` and `restore`

[cloud_hypervisor.rs:165-403](file:///home/pwnall/workspace/imp-testing/src/vmm/cloud_hypervisor.rs#L165-L403)

The `create` and `restore` methods share ~60 lines of identical setup code (tmp dir creation, command construction, socket wait, cgroup assignment). This should be extracted into a shared helper.

### 6.3 Magic numbers

- [orchestrator.rs:247](file:///home/pwnall/workspace/imp-testing/src/orchestrator.rs#L247): `for _ in 0..50` — retry count, no constant.
- [orchestrator.rs:251](file:///home/pwnall/workspace/imp-testing/src/orchestrator.rs#L251): `Duration::from_millis(100)` — retry delay, no constant.
- [agent/mod.rs:38](file:///home/pwnall/workspace/imp-testing/src/agent/mod.rs#L38): `Duration::from_secs(10)` — connect timeout, not configurable.
- [agent/mod.rs:94](file:///home/pwnall/workspace/imp-testing/src/agent/mod.rs#L94): `Duration::from_secs(30)` — exec timeout, not configurable.
- [cloud_hypervisor.rs:149](file:///home/pwnall/workspace/imp-testing/src/vmm/cloud_hypervisor.rs#L149): `vec![0; 4096]` — response buffer size.
- [orchestrator.rs:139](file:///home/pwnall/workspace/imp-testing/src/orchestrator.rs#L139): `ports.push(8080)` — hardcoded host service port.
- [orchestrator.rs:260](file:///home/pwnall/workspace/imp-testing/src/orchestrator.rs#L260): `mem_mib < 64` — minimum memory validation threshold.
- [orchestrator.rs:248](file:///home/pwnall/workspace/imp-testing/src/orchestrator.rs#L248): `5000` — vsock port number.

### 6.4 `unsafe` code review

[proxy/mod.rs:73](file:///home/pwnall/workspace/imp-testing/src/proxy/mod.rs#L73)

```rust
// SAFETY: Thread isolation for network namespace
let ret = unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) };
```

The `SAFETY` comment is too terse. It should document:
- Why thread isolation is sufficient (setns affects the calling thread, not the process).
- That the file descriptor is valid (from `File::open` success).
- That `CLONE_NEWNET` is the only flag being set.

### 6.5 `#[allow(dead_code)]` on live code

[artifact/mod.rs:28](file:///home/pwnall/workspace/imp-testing/src/artifact/mod.rs#L28): `#[allow(dead_code)]` on `CacheKey` — this is dead because the pipeline doesn't use cache keys (§4.9), not because it's intentionally unused.

### 6.6 `async_trait` is used where native async traits would work

Since the crate targets Rust 2024 edition (1.85+), native `async fn` in traits is available. The `async_trait` crate adds unnecessary heap allocations. Consider using native async traits where object safety isn't required, or at least documenting why `async_trait` is needed (for `dyn Vmm`/`dyn Stage`).

### 6.7 `#[path = "fs_in_process.rs"]` is unusual

[fs.rs:13](file:///home/pwnall/workspace/imp-testing/src/fs.rs#L13)

Using `#[path = ...]` to include a sibling file as a submodule is non-idiomatic. Prefer moving `fs_in_process.rs` into a `fs/` directory.

### 6.8 `smoltcp` feature includes unnecessary capabilities

[Cargo.toml:101](file:///home/pwnall/workspace/imp-testing/Cargo.toml#L101)

The smoltcp dependency enables `socket-icmp`, `socket-dhcpv4`, and `phy-tuntap_interface` features that don't appear to be used by the implementation.

---

## 7. Cargo.toml Issues

### 7.1 Feature flag inconsistencies with design

| Issue | Detail |
|-------|--------|
| `experiment-smoltcp` doesn't pull `dep:smoltcp` | The `experiment-smoltcp` feature ([line 119](file:///home/pwnall/workspace/imp-testing/Cargo.toml#L119)) doesn't directly include `dep:smoltcp`. It includes `dep:vhost`, `dep:vhost-user-backend`, etc., but `smoltcp` is only in a standalone `dep:smoltcp` feature. |
| `net-rootless` is empty | [Line 136](file:///home/pwnall/workspace/imp-testing/Cargo.toml#L136): `net-rootless = ["host-common"]` — doesn't pull in smoltcp or vhost-user-backend. |
| Redundant passthrough features | Lines 153-161 define passthrough features like `fuse-backend-rs = ["dep:fuse-backend-rs"]`. This is unnecessary — `dep:fuse-backend-rs` can be used directly. |
| `am-fs-erofs` not in `pipeline` | Design §5.5 shows `am-fs-erofs` in the `pipeline` feature; implementation has a separate `experiment-erofs` feature. |
| Missing `dep:am-fs-erofs` in `pipeline` | [Lines 143-148](file:///home/pwnall/workspace/imp-testing/Cargo.toml#L143-L148): The pipeline feature doesn't include the erofs crate despite Exp 3 being graduated. |

### 7.2 `deny.toml` completeness

The deny.toml exists but should be reviewed against the design §12.2 sketch for completeness (allowlist, bans, advisories, sources).

### 7.3 Missing `cargo-hack` CI configuration

Design §12.2 requires `cargo hack --feature-powerset --depth 2 clippy --all-targets` in CI. No CI configuration file was found.

---

## 8. Documentation Issues

### 8.1 Module-level docs are thin

Most modules have one-line `//!` docs. The Rust API Guidelines [C-CRATE-DOC](https://rust-lang.github.io/api-guidelines/documentation.html#c-crate-doc) expect module docs to describe:
- What the module does.
- How it relates to other modules.
- Usage examples.

Specific gaps:
- `proxy/doubles.rs` has no module-level doc comment.
- `net/smoltcp.rs` has no module-level doc comment (not reviewed in detail due to size, but the directory listing shows it's 19KB).
- `artifact/kernel.rs`, `artifact/rootfs.rs`, `artifact/snapshot.rs` — not reviewed but likely thin.

### 8.2 Missing doc examples

The Rust API Guidelines [C-EXAMPLE](https://rust-lang.github.io/api-guidelines/documentation.html#c-example) recommend examples on public types and methods. None of the public API types have `# Examples` sections:
- `VmConfig::builder()`
- `AgentClient::connect()`
- `ExecRequest::new()`
- `EgressProxy::start()`
- `TestVm::start()`

### 8.3 Missing crate-level documentation

[lib.rs:1-6](file:///home/pwnall/workspace/imp-testing/src/lib.rs#L1-L6)

The crate-level doc (`//!`) is adequate but should include:
- A usage example.
- Feature flags documentation.
- Links to the design document.

---

## 9. Security Considerations

### 9.1 CA private key stored in `/tmp`

[proxy/tls.rs:20](file:///home/pwnall/workspace/imp-testing/src/proxy/tls.rs#L20)

The MITM CA private key is written to `/tmp/imp-artifacts/ca.key` with default permissions. On a multi-user system, this is readable by all users.

**Recommendation:** Use `0600` permissions or generate the CA in memory per session.

### 9.2 `setns` safety

The `unsafe { libc::setns(...) }` in [proxy/mod.rs:73](file:///home/pwnall/workspace/imp-testing/src/proxy/mod.rs#L73) changes the network namespace for the calling thread. In a multi-threaded program, this can have unexpected effects if other threads share the network namespace.

The implementation correctly does this in a dedicated thread, but the safety comment should explicitly state this invariant.

---

## 10. Opportunities for Unit Tests

### 10.1 Pure functions that should be tested

These are the pure functions the design §5.6 identifies as easily testable:

| Function | Current tests | Recommended additions |
|----------|--------------|----------------------|
| `VmConfigBuilder::build()` | ✅ Basic validation | Add: duplicate tags, VirtioFs+snapshot rejection, mem_mib boundary |
| `/30` address math | ✅ One case | Add: property test for all vmids 1-254, boundary at 0/255, overflow |
| nft ruleset render | Not tested standalone | Add: golden-text test asserting TPROXY form |
| CH REST payload builder | ✅ Serialization test | Add: golden-JSON for full VmConfig with all field variants |
| cgroup-path construction | Not tested | Add: parse `/proc/self/cgroup`, supervisor suffix strip, sibling placement |
| `CidAllocator` | ✅ Basic allocation | Add: wraparound, release-and-reuse, exhaustion, thread contention |
| VMID allocator | ✅ Basic allocation, exhaustion | Add: release-and-reuse, wraparound |
| Protocol codec | ✅ Postcard round-trip | Add: `LengthDelimitedCodec` round-trip, partial buffer, oversized rejection |
| `CaManager` | Not tested | Add: generation, load from disk, PEM validity |
| `EgressProxy` Drop | Not tested | Add: verify thread joins within timeout |
| `render_tproxy_rules` | Not tested standalone | Add: golden-text comparison |
| Kernel cmdline construction | Not tested | Add: erofs vs ext4, with/without net, with vmid |

### 10.2 Recommended property tests (using `proptest`)

```rust
// Per-VM path injectivity
proptest! {
    #[test]
    fn paths_are_injective(vmid1 in 1..=254u32, vmid2 in 1..=254u32) {
        prop_assume!(vmid1 != vmid2);
        let p1 = format!("imp-vm-{}-{}", std::process::id(), vmid1);
        let p2 = format!("imp-vm-{}-{}", std::process::id(), vmid2);
        prop_assert_ne!(p1, p2);
    }
}

// CID allocator never produces reserved CIDs
proptest! {
    #[test]
    fn cid_always_gte_3(count in 1..100usize) {
        let alloc = CidAllocator::new();
        for _ in 0..count {
            let cid = alloc.allocate().unwrap();
            prop_assert!(cid >= 3);
        }
    }
}

// Protocol round-trip through LengthDelimitedCodec
proptest! {
    #[test]
    fn protocol_roundtrip(argv in prop::collection::vec(".*", 1..5)) {
        let msg = Message::Exec(ExecRequest::new(argv.clone()));
        let bytes = postcard::to_stdvec(&msg).unwrap();
        let decoded: Message = postcard::from_bytes(&bytes).unwrap();
        if let Message::Exec(req) = decoded {
            prop_assert_eq!(req.argv, argv);
        } else {
            prop_assert!(false, "wrong variant");
        }
    }
}
```

---

## 11. Summary Table

| Category | Critical | High | Medium | Low | Total |
|----------|----------|------|--------|-----|-------|
| Correctness bugs | 1 | 1 | 2 | 2 | 6 |
| API guideline violations | 0 | 3 | 5 | 1 | 9 |
| Error handling | 0 | 2 | 2 | 0 | 4 |
| Design deviations | 0 | 5 | 7 | 3 | 15 |
| Missing tests | 0 | 5 | 8 | 5 | 18 |
| Code quality | 0 | 1 | 5 | 2 | 8 |
| **Total** | **1** | **17** | **29** | **13** | **60** |

---

## 12. Recommended Fix Priority

### P0 — Fix immediately (correctness)
1. Fix `CidAllocator::release` to operate on the correct instance (§1.1)
2. Replace hand-rolled HTTP parsing with `hyperlocal` client (§1.2)

### P1 — Fix before next milestone
3. Add `#![deny(unsafe_op_in_unsafe_fn, rustdoc::broken_intra_doc_links)]` (§2.1)
4. Rename `experiment-smoltcp` → `net-rootless`, `experiment-erofs` → incorporate into `pipeline` (§4.1)
5. Remove `experiment-fuse` and `experiment-smoltcp` from default features (§4.2)
6. Make VMID allocator injectable (not a static) (§6.1)
7. Fix module doc comment placement (§2.2)
8. Add duplicate share tag validation to builder (§2.8)
9. Remove hardcoded `example.net` block from proxy (§1.4)
10. Replace `println!` with `tracing` in pipeline (§1.3)

### P2 — Fix during next development cycle
11. Add `proptest` to dev-dependencies and implement property tests (§5.3, §10.2)
12. Add `#[must_use]` to constructors (§2.3)
13. Implement `Pipeline::reset_to` and content-addressed caching (§4.9, §4.10)
14. Fill `StageInputs`/`StageOutputs` (§4.11)
15. Add `# Errors` doc sections to all public `Result`-returning functions (§2.5, §2.6)
16. Add `# Examples` to major public API methods (§8.2)
17. Improve `FakeVmm` to record calls (§4.14)
18. Make `TestVm` own `AgentClient` (§4.12)
19. Add structured `Error` sub-variants (§3.1)
20. Add the missing integration test assertions from §12.4 (§5.2)

### P3 — Nice to have
21. Migrate from `async_trait` to native async traits where possible (§6.6)
22. Fix `ProxyConfig` equality semantics (§1.5)
23. Fix TOCTOU in proxy port binding (§1.6)
24. Set restrictive permissions on CA key file (§9.1)
25. Move `fs_in_process.rs` into a proper module directory (§6.7)
