# Imp Testing - Comprehensive Code Review Report

This code review was conducted against the `imp-testing` codebase, evaluating adherence to the system contracts, architecture design docs (`33-claude-design-v12p2.md`), and the Code Review Rubric (`28-claude-code-review-rubric.md`).

The review was split across five specialized focus areas (VMM & Orchestration, Pipeline & Storage, Networking & Proxy, Agent & Core, and Integration Tests) and consolidated below.

**Note:** No code changes were made during this review. No newly discovered justified deviations were added to `implementation-notes.md` as all findings represent explicit violations of the rubric or bugs in implementation.

---

## 1. Tests That Cannot Fail (Part C Anti-Patterns)

The test suite suffers from severe testing theater, where tests appear green but are incapable of failing when the underlying implementation breaks.

- **Asserts Nothing:** `tests/nested_virt.rs` (`test_nested_virt_impl`) runs `kvm-ok` but drops the exit code, only printing stdout/stderr. A failing `kvm-ok` still passes the test.
- **Loose OR Assertions:** 
  - `tests/metrics_limits.rs`: The OOM-kill check asserts `code == 137 || code == 137 - 256 || code == 1 || code == -1`. Exit code `1` is a generic failure, allowing a crashing binary (non-OOM) to pass. CPU load tests similarly accept any non-zero exit code.
  - `tests/egress_proxy.rs`: Domain-block tests assert loosely `blocked_stderr.contains("403 Forbidden") || blocked_stderr.contains("Blocked") || ...`, risking passes on unintended output.
- **Coincidental Passes:** 
  - `tests/snapshot_restore.rs`: The clock resync test asserts `post_time >= pre_time + 2` after a host sleep. This is true for any advancing clock and doesn't test guest `clock_settime`. 
  - RNG Reseed tests assert that two sequential reads from `/dev/urandom` differ. A PRNG will always yield differing bytes even if never reseeded on snapshot restore.
- **Tests the Opposite of its Name:** `tests/pipeline.rs` (`test_pipeline_tampered_digest_aborts`) corrupts a sidecar `.cache_key` instead of the artifact, then asserts the pipeline *rebuilds* rather than aborting.
- **Mock Where Round-Trip is Required:** `tests/exec_vsock.rs` (`test_put_file_mock`) only verifies the AgentClient sends bytes to the Unix Domain Socket mock correctly but never reads the file back from the guest.
- **String Stand-ins:** `tests/proptests.rs` blindly compares formatted strings like `imp-vm-{vmid}` and `ends_with(".2/30")` instead of inspecting real system paths and bounded IP octets.
- **Invalid Panic Residue Verification:** `tests/lifecycle.rs` (`test_lifecycle_panic_residue_ch`) instantiates `TestVm` *outside* the `catch_unwind` block. When the panic occurs inside the block, `TestVm` drops normally when the outer scope ends, meaning the "Drop on panic" path is never truly exercised.
- **"Skip == Pass" Smells:** Tests across `snapshot_restore.rs`, `shares_ro_rw.rs`, `egress_proxy.rs`, `concurrency.rs`, and `boot.rs` silently `return;` if capabilities or artifacts (`vmlinux`/`rootfs`) are missing. The `require_cap!` macro emits a printed `SKIP` and returns `Ok(())`, defeating CI failure tracking.

## 2. Resource Lifecycle & Cleanup (Rubric B1)

- **CID Pool Exhaustion:** `guest_cid` is leaked on teardown. `TestVm::start` acquires a CID but never releases it back to the allocator when dropped.
- **`smoltcp` Thread Leak:** In `SmoltcpProcess::Drop`, the implementation sets a `stop_flag` but never `.join()`s the background threads. If a panic triggers the drop, these threads detach and leak.
- **In-process virtio-fs Thread Leak:** The background thread `handle` spawned in `in_process.rs` (when `experiment-fuse` is enabled) is never signaled or joined in `Drop`.
- **Virtio-fs Zombie Teardown:** `VirtioFsDaemon::Drop` uses `self.process.start_kill()`. The rubric explicitly bans this: process teardown must use a group kill that waits (`kill -9 -<pgid>`), otherwise wrappers and zombies survive.

## 3. Failure Visibility & Capability Contracts (Rubric B2 / B3)

- **Firecracker Silent Degradation:** `Firecracker::create()` completely ignores `res.vhost_user_socket`. A `NetConfig::Rootless` config results in silently booting a netless VM instead of checking capabilities and returning `Error::Unsupported`.
- **Stringly-Typed Errors:** Multiple subsystems (Firecracker, `src/error.rs`) return `Error::Vmm("...")` or `Error::Agent("...")` string payloads rather than typed variants wrapping source errors like `std::io::Error`.
- **QEMU Teardown Hang Risk:** `QemuInstance::kill()` writes to QMP and awaits a response without any internal timeout. A hung QEMU process will cause `kill()` (and the panic teardown path) to hang forever.
- **Agent Swallowed Errors:** 
  - `imp-guest-agent.rs` relies heavily on `let _ = ` for critical path setups (`mount`, `pivot_root`, `handle_connection`). Connection drops in `AgentClient::exec` result in a silent `Ok(outcome)` with `code: -1` instead of erroring out.
  - Cgroup creation errors (`DefaultCgroupFs::create_slice`) and `add_task` file writes log warnings and swallow the error by returning `Ok(())`.
- **Blind Readiness Polling:** `wait_for_socket()` in `src/vmm/mod.rs` loops on a sleep timer without checking `process.try_wait()`. VMM immediate exit errors are masked until the timeout.
- **Missing Boot-Time Diagnostic Checklist:** PID-1 (`imp-guest-agent`) blindly attempts mounts and proceeds directly to `VsockListener::bind` instead of probing the environment and emitting the required explicit boot-time diagnostic payload.
- **Proxy Filter Bypass & Silent Mutex Failures:** `handle_request` in `doubles.rs` returns early for `hyper::Method::CONNECT`, bypassing `self.blocked_domains`. Additionally, proxy loggers silently swallow lock poison errors.

## 4. Concurrency & Injected State (Rubric B6)

- **Module-Global Mutable State:** `src/vmm/mod.rs` defines a `CidAllocator` wrapping a module-global `static GLOBAL_CIDS`. `egress_proxy.rs` and `snapshot_restore.rs` both use static atomic counters. The rubric bans this, mandating real injected dependencies.
- **Cgroup Trait Bypass:** `ChInstance`, `FcInstance`, and `QemuInstance` all bypass the injected `CgroupFs` trait and directly call `cgroups_rs::Cgroup::load().delete()`. A test using `FakeCgroupFs` will still mutate host cgroups.
- **Un-injected Allocators in Pipeline:** `SnapshotStage::run` spins up a new `CidAllocator::new()` locally rather than receiving the injected allocator context.
- **Missing Serial Annotations:** Tests hitting mutating allocators (like `CidAllocator` in `proptests.rs`) omit `#[serial_test::serial]`.

## 5. Determinism, Caching & Provenance (Rubric B4 / B5)

- **Cache Key Correctness (Pipeline State Loss):** When a pipeline stage is skipped via cache hit, `Pipeline::build` populates `inputs.artifacts` but fails to merge `outputs.pins` into `inputs.pins`. A fully cached run thus fails later stages entirely.
- **Existence-based Cache Validation:** Caching relies entirely on the `.cache_key` sidecar's contents rather than hashing the actual artifact payload, violating content-addressed caching rules.
- **Network Seam Bypass:** `reqwest::get` is invoked directly inside `kernel.rs` build logic, violating the rule that side-effect network access must be split into distinct record/replay seams.
- **`tar2erofs.rs` Device Node Provenance:** Device `rdev` bits are computed manually via `(major << 8) | minor` instead of `makedev`, as strictly banned by the rubric.
- **Missing Timestamp Pin:** `mmdebstrap` pulls release codenames (e.g., `bookworm`) without enforcing a `snapshot.debian.org` timestamp pin.
- **Trust Chain Breakage:** `CaManager::authority()` calls `params.self_signed` on every invocation, generating a new certificate and breaking the guest trust chain. CA temporary files are not written atomically and do not enforce `0600` permissions.
- **Sandbox Contracts:** `virtiofsd` command construction hardcodes `--sandbox=none` instead of the mandated `--sandbox namespace` + a dedicated UID.

## 6. Duplication & Module Boundaries (Rubric B7)

- **Duplicated Host-IP / MAC Math:** The `/30` and IP math is duplicated across all hypervisor implementations and `orchestrator.rs` instead of utilizing a unified, unit-tested helper applying `(vmid % 254) + 1`.
- **Duplicated Tokio Runtimes:** `setup_tap` and `setup_tproxy_routing` independently construct Tokio threads.
- **Hand-rolled Sniffing:** Smoltcp transparent proxy port-forwarding manually extracts offsets (`packet.get(14)`) instead of using `smoltcp` parsers.
- **Invalid Boundaries:** `tap.rs` incorrectly utilizes `assert!(vmid <= 254)` inside `setup_tap` instead of properly bubbling an out-of-range `Result` up the validation boundary.

## 7. Public-API Hygiene & Rust Best Practices (Rubric B8)

- **Dead Code:** `Message::Hello` and `Message::Ping` remain in the protocol definition and property tests.
- **PID-1 Panics:** `imp-guest-agent` utilizes `.expect()` and `.unwrap()` heavily. Because it runs as PID 1, any panic results in an immediate guest kernel panic.
- **`println!` instead of `tracing`:** Widespread use of `println!` and `eprintln!` exists in `imp-guest-agent` and `imp-test-runner` instead of proper `tracing` hooks.
- **Missing P/E Set Trimming:** `imp-test-runner` drops the bounding capability set and raises ambient sets correctly but forgets to trim the `PERMITTED` and `EFFECTIVE` capability sets after assuming its developer identity, violating the privileged window security contract.
- **Unchecked Harness Unwraps:** `bench-vm.rs` and `imp-testing.rs` leverage `.unwrap()` unsafely across execution paths rather than explicitly defining `.expect("...")` invariants.
