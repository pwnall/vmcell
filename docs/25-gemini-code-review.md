# Gemini Code Review against v11p1 Design

This document contains the consolidated findings from a comprehensive review of the `imp-testing` codebase, comparing the current implementation against `docs/24-claude-design-v11p1.md` and `docs/implementation-notes.md`.

The codebase demonstrates excellent alignment with the high-level architecture, properly abstracting VMMs, networking structures, and guest agent interactions. However, several avoidable divergences and correctness bugs were identified.

## 1. Core Orchestration & VMM (`src/orchestrator.rs`, `src/vmm/`, `src/config.rs`)

### Avoidable Divergences & Bugs
- **Ordered Teardown, Zombie Processes, and Cgroup Leaks**: 
  - `TestVm::shutdown` deletes the `netns` before waiting for the VM to die, violating the strict ordered teardown requirement and risking kernel namespace hangs.
  - VMM processes are not reaped via `wait()`, leaving zombie processes.
  - Processes are not spawned in their own process group (`process_group(0)`), meaning "force-kill the VMM process group" is not fully implemented.
  - Due to un-reaped processes, `cgroup.delete()` in the `Drop` implementation will fail with `EBUSY`, leaking cgroups.
- **Missing Cgroup Limits**: While `mem_max_mib` is applied, the configured `cpu.max`, `pids.max`, and `io.max` are ignored in `CgroupBuilder`.
- **Nested Virtualization Configuration Ignored**: Backends do not check the `nested_virt` switch, and the required `kvm-intel.nested=1` bootline argument is missing from Cloud Hypervisor and QEMU.

## 2. Agent and File System (`src/agent/`, `src/fs/`)

### Avoidable Divergences & Bugs
- **`virtiofsd` Sandbox Configuration**: `src/fs.rs` hardcodes `--sandbox=none`, turning off the virtiofsd sandbox. The design explicitly mandates `--sandbox namespace` with a dedicated uid to constrain daemon access.
- **Missing Subprocess Error Surfacing**: When an external `virtiofsd` process is spawned, the supervisor does not check `process.try_wait()` or read standard error. If virtiofsd immediately exits due to a misconfiguration, the orchestrator sleeps until a generic timeout, swallowing the underlying error.

### Justifiable Differences
- **In-process Read-Only Mode**: `fuse-backend-rs` (used in `experiment-fuse`) does not natively enforce read-only mode. This is accepted due to upstream library constraints and hidden behind a feature flag. (Added to implementation notes).

## 3. Networking and Proxy (`src/net/`, `src/proxy/`)

### Avoidable Divergences & Bugs
- **Bug: `EgressProxy::start` Hides Builder Failures**: The proxy initialization thread sends an `Ok(port)` over the channel even if `ProxyBuilder::build()` fails. This causes mysterious test timeouts as the orchestrator assumes the proxy is alive.
- **Missing Public API on `EgressProxy`**: The required methods for dynamic orchestration (`ca_cert_pem`, `requests`, `install_double`, `record_to`) are not implemented. Test doubles and CA parameters are instead statically written or injected at startup.
- **Bug: Swallowed Errors in `NetNamespace::delete`**: The orchestrator ignores errors from `delete_netns`, hiding cleanup leaks.
- **Lack of Framework Protection for `CONNECT` Requests**: `ProxyHandler` relies entirely on the developer's `Matcher` closure to ignore `CONNECT` requests, creating a risk of `hudsucker` crashing on initial TLS tunneling.

## 4. Artifact Pipeline, Binaries, and Tests (`src/artifact/`, `src/bin/`, `tests/`)

### Avoidable Divergences & Bugs
- **Stage 0 & Version Pinning Absent**: There is no deterministic `pins.lock` mechanism. Kernel versions and OCI digests are hardcoded directly into the CLI instantiation.
- **Cache Key Fragility**: `SnapshotStage` uses a hardcoded string `"snapshot-v1"` for its cache key, and `RootfsStage` uses array length (`inputs.len()`). Cache keys must be pure hashes of inputs and pins.
- **OCI Blob Caching & Offline Replays**: The OCI client fetches blobs from the network unconditionally (`client.pull()`). The design requires caching blobs by digest for offline replays.
- **Unnecessary External Tools**: `KernelStage` uses `std::process::Command` to call `wget` and `tar` instead of native Rust HTTP and extraction libraries.
- **Hardcoded Pipeline Outputs & Agent Injection**: Pipeline targets (`vmlinux`, `rootfs.erofs`) and cache directories (`/tmp/imp-artifacts`) are hardcoded, preventing concurrent/isolated builds. The guest agent binary injection path is also hardcoded to `target/x86_64-unknown-linux-gnu/release/imp-guest-agent`.
- **Guest Agent Timeout Neglect**: `imp-guest-agent.rs` does not read or enforce the `timeout` parameter in `ExecRequest`. A hanging command inside the VM will run indefinitely, leading to orphaned processes after the host client times out.
- **Abandoned Test Script**: `src/oci_test.rs` performs an anonymous OCI pull but contains no assertions and performs no setup, contrary to standard integration tests.
