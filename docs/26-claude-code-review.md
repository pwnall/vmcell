# Code Review — Pass 6

This review covers the full implementation against the v11p1 design document
(`docs/24-claude-design-v11p1.md`), `docs/requirements.md`, and
`docs/implementation-notes.md`.  Justified deviations from the design are
documented in `docs/implementation-notes.md` rather than reported here.

Findings are grouped by severity within each category.

---

## 1. Critical Correctness Bugs

These issues will cause crashes, hangs, silent incorrect results, or resource
leaks in normal use.

### 1.1 `TestVm::Drop` is a no-op — all resources leak on panic

**File:** `src/orchestrator.rs`, lines 452–456

```rust
impl<V: Vmm> Drop for TestVm<V> {
    fn drop(&mut self) {
        self.vmid_alloc.release(self.vmid);
    }
}
```

The `Drop` implementation releases only the VMID.  The VMM process, network
namespace, smoltcp NAT thread, egress proxy, cgroup, virtiofsd daemons, and
overlay are never killed or cleaned up when the struct is dropped.  If a test
panics (or simply never calls `shutdown()`), every per-VM host resource leaks.
This is the most load-bearing gap in the implementation — §12.3's
`Drop`-order unit test and §12.4's `lifecycle.rs` panic-residue test both
exist to gate exactly this.

`shutdown()` also does not stop `self.smoltcp` or `self.proxy` before dropping
them (lines 439–449), and never deletes the cgroup (`cgroup_name`).  The
ordering is uncontrolled.

### 1.2 Firecracker `probe_t2_template` boot-failure detection is inverted

**File:** `src/vmm/firecracker.rs`, lines 296–308

```rust
Err(_) => true,  // any error other than a 400 with "template" body → T2 claimed supported
```

Any error that is **not** a 400 with "template" in the body (e.g., a network
error, process crash, or other API error) sets `success = true`, claiming T2
is supported when it clearly is not.  Every subsequent FC `create()` call will
then fail with a T2-related configuration error with no clear root cause.

### 1.3 TPROXY routing policy never installed

**File:** `src/net/tap.rs`, lines 235–253

`render_tproxy_rules` emits `meta mark set 1 accept`, but the matching routing
policy (`ip rule add fwmark 1 lookup 100` + `ip route add local default dev lo
table 100`) is never applied.  Without the policy, the kernel routing stack
drops TPROXY-redirected packets.  The privileged TPROXY egress path is
non-functional.

### 1.4 smoltcp Invariant #2 violated: `iter()` advances `avail_idx` unconditionally

**File:** `src/net/smoltcp.rs`, lines 411–456

`vring_state.get_queue_mut().iter(...)` is called inside `while let Some(packet)
= state_guard.rx_queue.pop_front()`.  The `iter()` call advances `avail_idx`
regardless of whether a descriptor chain is available.  When the guest has no
pending receive buffers this discards descriptor entries, permanently wedging
the virtio RX link.  The fix is to only call `iter()` when packets are queued.

### 1.5 smoltcp Invariant #3 violated: `enable_notification()` missing in non-`event_idx` path

**File:** `src/net/smoltcp.rs`, lines 249–251

In `handle_event`, when `event_idx` is `false`, `process_tx_queue` is called
without re-enabling notifications.  The event_idx path correctly calls
`enable_notification()` in its loop, but the non-event_idx path does not.
After the first TX event the queue goes silent — the guest can send packets
that are never processed.

### 1.6 `CaManager::authority()` re-signs the CA cert on every call

**File:** `src/proxy/tls.rs`, lines 73–88

`authority()` loads the saved PEM, then calls `params.self_signed(&key_pair)`
generating a **new** self-signed cert with a fresh validity window.  The
returned `RcgenAuthority` signs leaf certs under this newly-generated cert,
which is not the cert saved to disk and injected into the guest trust store.
HTTPS interception will fail with a chain-validation error because the guest
trusts the on-disk cert but the proxy signs with the reconstructed one.

The fix is to reconstruct the authority from the saved PEM using
`CertificateParams::from_ca_cert_pem` (rcgen API) rather than re-signing.

### 1.7 Proxy `netns` open failure is silently ignored

**File:** `src/proxy/mod.rs`, lines 98–109

```rust
if let Ok(file) = std::fs::File::open(format!("/var/run/netns/{}", netns)) {
    // enter netns
}
```

If the network namespace file cannot be opened (namespace not yet created, wrong
path), the proxy binds on the **default** network namespace and `tx.send(Ok(...))`
succeeds.  The caller has no way to know the proxy is listening on the wrong
interface, silently breaking the per-VM network isolation.

### 1.8 `SnapshotStage` reads kernel/rootfs paths from environment variables

**File:** `src/artifact/snapshot.rs`, lines 38–43

`SnapshotStage::run` reads the kernel and rootfs paths from `IMP_KERNEL` and
`IMP_ROOTFS` env vars instead of `inputs.artifacts`.  This breaks the pipeline
dependency contract: the snapshot stage does not actually depend on the outputs
of the kernel/rootfs stages.  Running with an empty environment uses
`/tmp/vmlinux` and `/tmp/rootfs.ext4` regardless of the actual build outputs.

### 1.9 `SnapshotStage` boots with `RootfsSource::Block`, not the erofs rootfs

**File:** `src/artifact/snapshot.rs`, lines 45–51

The warm-snapshot artifact is supposed to boot from the erofs image produced
by the rootfs stage and snapshot it at "agent-ready".  The implementation
hardcodes `RootfsSource::Block`, bypassing the erofs path the design's entire
snapshot-tier density argument rests on.

### 1.10 Kernel `make` receives `HOSTCC`/`CC` as a single string argument

**File:** `src/artifact/kernel.rs`, lines 93–96, 127–128

```rust
Command::new("make").arg("HOSTCC=gcc -std=gnu11")
```

This passes `HOSTCC` set to the literal string `"gcc -std=gnu11"` (with space)
as a single argument, which is not a valid compiler path.  The kernel `Makefile`
will not interpret it correctly.  Use `.env("HOSTCC", "gcc")` or separate args.

### 1.11 Kernel source tarball not hash-verified

**File:** `src/artifact/kernel.rs`, lines 41–49

The kernel tarball is downloaded from `kernel_source_url` with no integrity
check against a pinned hash from `pins.lock`.  The design mandates
refuse-on-mismatch verification for all downloaded artifacts.

### 1.12 No OCI layer blob sha256 verification

**File:** `src/artifact/rootfs/oci.rs`, lines 40–44

After downloading each OCI layer blob, the content is cached and used without
verifying it against the digest recorded in the manifest.  The design requires
that every blob be verified against its sha256 before use; a compromised or
truncated download would silently produce a corrupted rootfs.

### 1.13 `restore()` does not enforce privileged (tap) network path

**File:** `src/orchestrator.rs`, lines 343–375

Per §15.5, the warm-snapshot tier must use the privileged network path because
vhost-user devices (including the smoltcp NAT) make a VM snapshot-ineligible.
`restore()` rejects `VirtioFs` rootfs (lines 350–354) but does not reject
`NetConfig::Rootless`.  A restore with rootless smoltcp networking will proceed,
violating the snapshot eligibility law.

### 1.14 `restore()` does not rotate vsock CID/MAC, reseed entropy, or resync clock

**File:** `src/orchestrator.rs`, lines 343–375

The design (§7, §8) requires every restore to rotate the vsock CID, rotate
MAC/IP, reseed entropy via virtio-rng, and resync the clock.  Only clock
resync is present (via the subsequent `agent()` call).  CID rotation is implicit
in allocating a new CID in `setup_env`, but MAC/IP rotation and virtio-rng
entropy reseeding are not performed.

### 1.15 QEMU `boot()` silently swallows QMP `cont` errors

**File:** `src/vmm/qemu.rs`, lines 319–322

```rust
let _ = self.qmp_command(r#"{"execute": "cont"}"#).await;
Ok(())
```

If the QEMU process failed to start or `cont` returns an error, `boot()` returns
`Ok(())` and the VM never starts.  The orchestrator then times out trying to
connect the agent, with no actionable error.

### 1.16 QEMU `snapshot()`/`restore()` polling loops ignore timeout

**File:** `src/vmm/qemu.rs`, lines 364–385, 296–303

Both polling loops run at most 50 iterations × 50 ms = 2.5 s.  If migration
takes longer, the loop exits silently, `cont` is called unconditionally, and
`Ok(())` is returned — the caller believes the operation succeeded when it has
not.

---

## 2. Design Divergences

### 2.1 `DefaultHasher` used in cache keys — not stable across Rust versions

**Files:** `src/artifact/rootfs/mod.rs:49`, `src/artifact/snapshot.rs:28–34`

Both stages use `std::collections::hash_map::DefaultHasher` for their
`cache_key`.  `DefaultHasher` is documented as non-portable across Rust
versions; a cache entry written by one toolchain will not match one written by
another.  §12.3 explicitly guards this: "golden digest pinned to a stable hash;
identical across processes and runs."  Replace with `blake3::Hasher` as
`artifact/kernel.rs` already does.

### 2.2 OCI pull uses tag fallback, not digest-pinned pull

**File:** `src/artifact/rootfs/oci.rs`, lines 10–14; `src/artifact/rootfs/mmdebstrap.rs:23`

`build_rootfs` silently falls back to a tag-based pull when the second argument
does not start with `"sha256:"`.  `mmdebstrap.rs` line 23 passes `"trixie-slim"`
(a tag), so the builder VM rootfs is tag-pinned.  The design requires all OCI
pulls to use a manifest digest — a tag pull bypasses the integrity guarantee and
breaks reproducibility.  The tag-fallback path should be an error, not a
silent degradation.

### 2.3 Guest agent is built inside `RootfsStage::run()`, not cached

**File:** `src/artifact/rootfs/mod.rs`, lines 70–83

`run()` invokes `cargo build` for `imp-guest-agent` as a subprocess every time
the rootfs stage runs.  This build is not covered by the stage's `cache_key`,
so modifying the guest agent does not invalidate the rootfs cache.  The agent
binary should be a `StageInputs` artifact with its own cache key, not a
side-effect of `run()`.

### 2.4 `ExecRequest` timeout hardcoded to 10 s in `reconnect()`, `put_file()`, and `agent()`

**Files:** `src/agent/mod.rs:133,186`; `src/orchestrator.rs:390`

The design (§5.2, §14.3, §15.3) requires a **per-request** `timeout` on
`ExecRequest` — short for normal test commands, long (≈600 s) only for the
builder-VM `mmdebstrap` call — to preserve fast-fail for tests while allowing
long-running builds.  Three sites hardcode 10 s:
- `AgentClient::reconnect()` (line 133)
- `AgentClient::put_file()` (line 186)
- `TestVm::agent()` (line 390)

A builder VM executing `apt-get install mmdebstrap` over the agent will time
out in 10 s, silently failing the rootfs build.

### 2.5 VMIDs used as raw IPv4 octets without range enforcement at the use site

**Files:** `src/vmm/cloud_hypervisor.rs:320–321`, `src/vmm/firecracker.rs:374–375`,
`src/vmm/qemu.rs:209–212`, `src/net/tap.rs:60`

The allocator maps VMIDs to `1..=254`, but none of the use sites applies the
`(vmid % 254) + 1` mapping the design specifies (§5.3).  If the allocator
contract ever changes, these sites will silently produce invalid IPv4 addresses
(e.g., `10.200.256.1`).  The mapping should be applied at each use site.

`src/net/tap.rs` does not apply the modular mapping while
`src/net/smoltcp.rs:359` uses `(vmid % 256) as u8` — inconsistent between the
two networking paths.

### 2.6 `VmInstance::boot()` conflates restore path and cold-boot path (CH backend)

**File:** `src/vmm/cloud_hypervisor.rs`, lines 435–443

`boot()` checks `self.restored` and calls `vm.resume` on a restored instance.
The `VmInstance::boot()` contract says "boot the VM from a created state" — using
it to resume a restored VM is a semantic mismatch.  The correct shape is for
`Vmm::restore()` to return an already-resumed instance (or for the orchestrator
to call `resume()` explicitly and `boot()` to be unconditional).  As written, a
caller who accidentally calls `boot()` on a restored instance rather than
`resume()` gets silent `vm.resume` behavior instead of a clear error.

### 2.7 `snapshot()` resumes even when the snapshot API call failed

**File:** `src/vmm/cloud_hypervisor.rs`, lines 480–491

The snapshot API result is stored, a resume attempt is made regardless, and the
snapshot result is returned.  If both snapshot and resume fail, the caller sees
only the snapshot error — the VM is left permanently paused and there is no
indication the resume also failed.  The resume error should be surfaced (at
minimum via `tracing::warn`) even when masked by the primary error.

### 2.8 Firecracker `capabilities()` does not reject rootless network config in `create()`

**File:** `src/vmm/firecracker.rs`, lines 432–438

`capabilities()` correctly reports `rootless_vhost_user_net: false`, but
`create()` silently ignores `res.vhost_user_socket` when set.  A caller
configuring `NetConfig::Rootless` on Firecracker will spawn a VM with no
network device and no error.  `create()` should return
`Error::Unsupported { vmm: "firecracker", feature: "rootless_vhost_user_net" }`
if a rootless socket is provided.

### 2.9 `StageOutputs` is unused; `Artifacts` carries no artifact paths

**File:** `src/artifact/mod.rs`, lines 27–31, 59

Every stage returns `StageOutputs::default()` (empty map).  `Pipeline::build`
discards the outputs.  The caller of `Pipeline::build` receives `Artifacts {}`,
an empty struct that cannot tell them where any built artifact lives.  The
pipeline is effectively opaque — there is no programmatic way to locate the
produced `vmlinux` or `rootfs.erofs` without hard-coding the path.

### 2.10 `reset_to` silently succeeds when stage name is not found

**File:** `src/artifact/mod.rs`, lines 134–159

If a caller passes an unknown stage name, no outputs are removed and `Ok(())`
is returned.  This should return an error so callers are not misled into
thinking a reset occurred.

### 2.11 `VmidAllocator` uses `Vec` (O(n) lookup) vs `CidAllocator`'s `BTreeSet`

**File:** `src/orchestrator.rs`, lines 15, 33–43

`GLOBAL_VMIDS` is a `Mutex<Vec<u32>>` using `contains()` in a nested loop (O(n²)
worst-case to find the last free VMID).  The `CidAllocator` uses `BTreeSet`.
Unify on `BTreeSet` for consistency and O(log n) lookup.

### 2.12 `Drop` does not release the CID allocated to the VM

**File:** `src/orchestrator.rs`, `Drop` impl

`Drop` releases the VMID via `vmid_alloc.release(self.vmid)` but never releases
the `guest_cid` back to `CidAllocator`.  Over a long test run, the 252-CID pool
will be exhausted.  The `CidAllocator` reference should be stored in `TestVm`
and `release()` called in `Drop`.

### 2.13 `shutdown()` calls `request_shutdown()` then `kill()` immediately

**File:** `src/orchestrator.rs`, lines 440–443

`request_shutdown()` sends a graceful ACPI poweroff and then `kill()` SIGKILLs
the process before the guest can process the signal.  The VM never gets to flush
guest filesystems.  Either `shutdown()` should wait for the VM to exit after
`request_shutdown()` before calling `kill()` as a fallback, or the two should
not be called unconditionally in sequence.

### 2.14 Injectable seam traits absent — unit testing side-effects is impossible

**File:** Multiple modules

The design (§5.6, §12.5) requires `Netlink`, `NftApplier`, `CgroupFs`,
`SerialLog`, and `Clock` to be small traits with real and fake implementations,
so `net`, `metrics`, and `agent` orchestration can be unit-tested.  None of
these trait boundaries exist.  `RtNetlink` and `DefaultNftApplier` are concrete
types with no trait abstraction.  `CgroupFs` logic is inline.  `SerialLog`
reads use `std::fs::read_to_string`.  `Clock` calls `SystemTime::now()`
directly.  This is the direct cause of the corresponding §12.3 unit tests being
impossible to write.

### 2.15 `pub mod kernel` and other artifact modules not gated on `pipeline` feature

**File:** `src/artifact/mod.rs`, line 8

`pub mod kernel;` (and `pub mod snapshot`) are declared unconditionally.
`kernel.rs` uses `blake3::Hasher` which is `optional` and only pulled in by the
`pipeline` feature.  If someone enables `host-common` without `pipeline`, the
`artifact` module will be compiled but `blake3` won't be available, causing a
compile error.  Add `#[cfg(feature = "pipeline")]` guards.

---

## 3. Testing Coverage Gaps

### 3.1 `lifecycle.rs` missing panic-then-zero-residue test

**File:** `tests/lifecycle.rs`

There is no test that panics inside a live `TestVm` scope, catches the unwind,
and asserts all host resources (VMM process, netns, cgroup, socket files) were
cleaned up.  This is the primary guard for the §1.1 `Drop` bug above and the
test §12.4 and §12.7 explicitly require.

### 3.2 `snapshot_restore.rs` — missing assertions for key restore-correctness properties

**File:** `tests/snapshot_restore.rs`

Per the design's §12.4 requirements:
- **Vsock reconnect:** The test comment says vsock reconnect is "implicitly"
  tested, but no assertion checks that the vsock *path* changed post-restore.  A
  buggy implementation that re-uses the stale socket could pass.
- **RNG entropy reseeding:** No test verifies that `/dev/urandom` produces
  distinct output before snapshot vs after restore.
- **MAC rotation:** Wrapped in `if !pre_mac.is_empty()` which silently skips the
  assertion when using `network_disabled()`.  The snapshot-restore test should
  run with a network-enabled config (privileged/tap, per design §15.5) so MAC
  rotation is a hard assertion.
- Missing `#[serial_test::serial]` — concurrent `--ignored` runs will race on
  global host state (netns, cgroups).

### 3.3 `egress_proxy.rs` — missing required assertions

**File:** `tests/egress_proxy.rs`

Per §12.4:
- HTTPS interception is not asserted to appear in the proxy request log.
- No assertion that the proxy observes the guest's intended destination.
- No test that a `CONNECT` request falls through to the default proxy behavior
  rather than being answered by a registered test double.
- Missing `#[serial_test::serial]`.

### 3.4 `metrics_limits.rs` — weak assertions

**File:** `tests/metrics_limits.rs`

- `cpu_test_outcome.code` is never checked; a failing workload silently passes
  the test.
- Average CPU is not computed as a CPU-percentage value; `cpu_usec` delta is
  read but never divided by elapsed wall-clock × vcpu count.
- The OOM-kill test asserts only `code != 0`, not exit code 137 (SIGKILL) or a
  cgroup OOM event.  Any exec failure passes the assertion.
- Missing `#[serial_test::serial]`.

### 3.5 `concurrency.rs` — CID collision not asserted

**File:** `tests/concurrency.rs`

The test asserts distinct VMIDs and vsock paths but not distinct guest CIDs.
The design (§12.4) requires "no CID/VMID/socket-path collision."
`vm.instance().guest_cid()` should be verified across all VMs.
Missing `#[serial_test::serial]`.

### 3.6 `pipeline.rs` missing three of four required tests

**File:** `tests/pipeline.rs`

Per §12.4's build-pipeline hardening track, the following tests are absent:
- **Tampered digest aborts:** modify a cached blob's content and assert the
  pipeline returns an error (the signing chain is a hard stop).
- **Warm-cache build skips stages:** run the pipeline twice and assert no
  `stage.run()` is called on the second pass.
- **Determinism:** identical pins produce a byte-identical erofs image and
  identical `cache_key`.

The existing `reset_to` test checks directory deletion but does not call
`pipeline.build()` afterward to verify only later stages are rebuilt.

### 3.7 `proptests.rs` missing path-injectivity and /30 subnet math tests

**File:** `tests/proptests.rs`

Per §12.3, property tests are required for:
- **Path injectivity:** distinct VMIDs produce distinct cgroup names, socket
  paths, and netns names across the full 1–254 range.
- **/30 subnet math:** the IP address scheme produces valid, non-overlapping /30
  subnets for all valid VMIDs.

### 3.8 Mock-only tests in `exec_vsock.rs` incorrectly gated with `#[ignore]`

**File:** `tests/exec_vsock.rs`, lines 9, 83

`test_exec_vsock_mock` and `test_put_file_mock` use only Unix domain socket
mocks — no KVM, no privileges required.  Marking them `#[ignore]` means they
are skipped by `cargo test` and only run with `--ignored`, silently omitting
agent-codec tests from the default suite.

### 3.9 `FakeVmm` orchestrator test exists but is unused

**File:** `tests/lifecycle.rs`; `src/vmm/mod.rs`

`FakeVmm` is defined but `tests/lifecycle.rs` tests that use it only verify
that VMM lifecycle methods were called — the orchestrator's full lifecycle
(allocation order, retry/timeout, restore-vs-cold-boot selection, ordered
teardown) is never exercised against `FakeVmm` alone.  §12.4 requires a
"FakeVmm-driven orchestrator test" that exercises these paths with no KVM.

### 3.10 `src/test_tokio.rs` is a dead scratch file

**File:** `src/test_tokio.rs`

This file contains a single `#[tokio::test]` that spawns `ls` to test
`process_group(0)`.  It is not declared in `lib.rs` (no `mod test_tokio;`), is
not a standalone integration test (it lives in `src/`, not `tests/`), and is
not a binary.  It will never be compiled or run.  Delete it.

### 3.11 `VmidAllocator` unit tests contend on the process-global static

**File:** `src/orchestrator.rs`, lines 462–484

`test_allocate_vmid_exhaustion` allocates all 254 IDs from `GLOBAL_VMIDS`.  If
run concurrently with any other test allocating VMIDs in the same process
(including integration tests), both will contend on the global mutex and produce
spurious failures.  These tests need `#[serial_test::serial]`.

---

## 4. Rust Best Practice Violations

### 4.1 `clippy::print_stdout` violated in `qemu.rs` non-test code

**File:** `src/vmm/qemu.rs`, line 225

```rust
println!("QEMU CMD: {}", cmd_str);
```

This is in production code (not `#[cfg(test)]`).  The `#![cfg_attr(not(test),
deny(clippy::print_stdout))]` gate in `lib.rs` will fail CI in non-test builds.

### 4.2 `clippy::unwrap_used` violated in several production paths

The `not(test)` deny on `clippy::unwrap_used` must fail these sites:

| File | Location | Expression |
|---|---|---|
| `src/vmm/mod.rs` | line 40, 60, 61, 76 | `GLOBAL_CIDS.lock().unwrap()` in `CidAllocator` |
| `src/proxy/mod.rs` | line 214 | `self.requests.lock().unwrap().clone()` |
| `src/proxy/doubles.rs` | line 85 | `Response::builder()...expect(...)` |
| `src/net/smoltcp.rs` | line 171 | `signal_used_queue().expect("invariant")` |
| `src/net/smoltcp.rs` | line 338 | `Runtime::new().expect("invariant")` |

### 4.3 Missing `#[non_exhaustive]` on public types

Per §5.2 and §12.2, public structs and enums where future fields are likely
should be `#[non_exhaustive]`:
- `VmConfigBuilder` (also missing `#[derive(Debug, Clone)]`)
- `ResourceLimits` (missing `PartialEq`/`Eq`)
- `Error` enum (adding a variant is otherwise a breaking change caught only by
  `cargo semver-checks`, not at compile time)

### 4.4 `unsafe` blocks without `// SAFETY:` comments

The `#![deny(clippy::undocumented_unsafe_blocks)]` gate requires a `// SAFETY:`
comment for every `unsafe` block.  `src/bin/imp-test-runner.rs` contains
`unsafe` blocks using raw `libc::setresgid`/`setgroups`/`setresuid` without
SAFETY comments.

### 4.5 `Error` enum lacks `From` implementations for wrapped error types

**File:** `src/error.rs`

Most error variants take `String`, with no `From<reqwest::Error>`,
`From<serde_json::Error>`, `From<postcard::Error>`, etc.  All error sites must
call `.map_err(|e| Error::Variant(e.to_string()))`, which loses the original
type and makes downcasting impossible.  The `#[from]` derive on `std::io::Error`
is the correct pattern; apply it to the other wrapped types.

### 4.6 `ExecRequest` missing a `with_timeout` builder method

**File:** `src/agent/protocol.rs`

`ExecRequest` exposes `with_env` and `with_cwd` but no `with_timeout`.  Setting
a per-request timeout requires bypassing `new()` and constructing the struct
directly, creating an awkward API.  This also makes the intended long-timeout
usage for builder-VM calls easy to accidentally omit.

### 4.7 CA certificate file written non-atomically

**File:** `src/proxy/tls.rs`, lines 44–52

`std::fs::write(&cert_path, &ca_cert_pem)` followed by `std::fs::write(&key_path,
...)` is not atomic.  On a crash between the two writes, the cert and key are
mismatched.  The existing `exists()` check will load the mismatched pair and
fail later with no clear error.  Use write-to-temp-then-rename for both files.

### 4.8 CA certificate directory is shared across concurrent test runs

**File:** `src/proxy/tls.rs`, lines 19–21

The CA lives at a fixed path (`/tmp/imp-artifacts/ca.pem`).  If two test suite
processes run concurrently, one may overwrite the other's CA, causing TLS
handshake failures mid-test.  The path should incorporate a per-run identifier
(e.g., PID or UUID).

### 4.9 `bench-vm` p50 percentile computation missing `.floor()`

**File:** `src/bin/bench-vm.rs`, lines 30–32

```rust
let p50 = latencies[(count * 0.5) as usize];   // missing floor()
let p95 = latencies[(count * 0.95).floor() as usize];
```

`p50` lacks `.floor()` before the `usize` cast, producing inconsistent rounding
with `p95`/`p99`.  For an even-count array the standard median is the average of
the two middle elements, not a single indexed value — the current formula
over-reports by one.

### 4.10 `imp-test-runner` capability check verifies permitted set, not effective set

**File:** `src/bin/imp-test-runner.rs`, lines 15–35

`ensure_blessed_or_explain` checks `caps.permitted.has(c)`.  `CAP_NET_ADMIN`
and `CAP_SYS_ADMIN` must be in the *effective* set for this process to act on
them.  If they are permitted-but-not-effective, the check passes but the runner
cannot perform privileged operations.

### 4.11 `imp-test-runner` drops bounding set after raising ambient

**File:** `src/bin/imp-test-runner.rs`, lines 113–128

Ambient capabilities are raised before the bounding set is dropped.  The correct
hardening order is: drop bounding set first, then raise ambient.  A child of the
exec'd process could otherwise re-acquire the dropped caps via inheritable
before the bounding set shrinks.

### 4.12 `Message::Hello` protocol variant is dead code

**File:** `src/agent/protocol.rs`

The `Hello` variant is never sent by the host and never handled by the guest.
The vsock handshake uses the raw `CONNECT <port>\n` / `OK <port>\n` exchange at
the binary level, and the first framed message is always `Ready`.  Remove
`Hello` or document why it is reserved.

### 4.13 `virtiofsd` `in_process.rs` logs startup at `error!` level

**File:** `src/fs/in_process.rs`, line 254

```rust
tracing::error!("in-process virtiofsd: thread started, listening on {:?}", ...)
```

A normal startup message at error level will trigger alerts in any production
tracing setup.  Use `tracing::info!`.

### 4.14 `in_process.rs` silently ignores `read_only = true`

**File:** `src/fs/in_process.rs`, lines 229–233

The in-process virtiofsd logs a warning if `read_only` is `true` but mounts
the filesystem read-write.  Read-only enforcement is security-relevant for
`imp-in` shares; silently ignoring it is a correctness bug, not just a style
issue.  The code should return an error or implement the restriction.

### 4.15 Serial log read uses blocking I/O inside async context

**File:** `src/agent/mod.rs`, lines 62–71

`std::fs::read_to_string` in a Tokio async loop blocks the runtime thread on
I/O.  Use `tokio::fs::read_to_string` or a proper async tail-follow.

---

## 5. Minor Quality Improvements

### 5.1 `VmidAllocator`'s `Arc<VmidAllocator>` wrapper is misleading

**File:** `src/orchestrator.rs`

`VmidAllocator` is a zero-size-type wrapper around a process-global `static`.
Creating a second `VmidAllocator` does not give an independent ID pool — both
share the same global.  The `Arc<VmidAllocator>` parameter to `TestVm::start`
implies injection but is hollow.  Document this clearly or replace with a true
injected allocator backed by an `Arc<Mutex<BTreeSet<u32>>>`.

### 5.2 QEMU `qmp_command` opens a new socket per call

**File:** `src/vmm/qemu.rs`, lines 50–82

Each QMP command incurs a full Unix socket connect + `qmp_capabilities`
negotiation.  The `snapshot()` poll loop calls `qmp_command` 50+ times, making
this expensive.  More importantly, QMP async events (e.g., `STOP`, `RESUME`)
arrive on the connection and are discarded when the socket is closed per-command.
A persistent QMP connection is the correct approach.

### 5.3 `virtiofsd` timeout error message omits stderr output

**File:** `src/fs.rs`, lines 84–88

On socket-wait timeout, `start_kill()` is called but stderr is not read.
The error message provides no diagnostic context.  Read stderr before returning
the error.

### 5.4 `pub mod kernel` (artifact) hardcodes output file names in the pipeline runner

**File:** `src/artifact/mod.rs`, lines 90–96

The pipeline maps stage names `"kernel"` / `"rootfs"` to specific file names
(`.join("vmlinux")`, `.join("rootfs.erofs")`) with hardcoded strings.  New
stages added without these exact names get bare-name outputs.  The output path
should be determined by each `Stage` impl, not by the pipeline.

### 5.5 `deny.toml` bulk-suppresses advisories without rationale

**File:** `deny.toml`, lines 12–17

Fourteen advisory IDs are suppressed with no inline comment explaining why each
is safe to ignore.  `cargo-deny` is the project's primary security gate; bulk
suppression with no rationale defeats its purpose.  Each `ignore` entry should
document the reasoning.

### 5.6 `VmmSpawn` error variant is never used

**File:** `src/error.rs`, lines 19–24

The `VmmSpawn { source: std::io::Error }` variant with typed source is never
constructed — all VMM spawn errors map to `Error::Vmm(String)`.  Either route
spawn errors through `VmmSpawn` to benefit from the `#[source]` chain, or
remove the variant.

### 5.7 QEMU `restored: bool` field is never read

**File:** `src/vmm/qemu.rs`, line 46

`restored` is set in `restore()` but never consulted anywhere.  Remove the field
or use it to guard `boot()` as CH does.

### 5.8 `bench-vm` pipeline tests only verify exit code, not output

**File:** `tests/benchmark.rs`, lines 17–18

`cmd.assert().success()` passes even if `run_bench` silently produced zero
successful iterations.  Assert that at least one p50/p95/p99/max line was
printed.

### 5.9 `CidAllocator` initializer can panic if `allocate()` is called before `new()`

**File:** `src/vmm/mod.rs`, line 61

`active.as_mut().unwrap()` in `allocate()` will panic if the global `GLOBAL_CIDS`
was never initialized via `new()`.  The lazy init should be handled inside
`allocate()` or the global should be initialized with `OnceLock::get_or_init`.
