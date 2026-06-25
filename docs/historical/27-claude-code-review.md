# Code Review — Imp Testing implementation

Review date: 2026-06-25. Scope: the entire `imp-testing` crate (`src/`, `tests/`,
`benches/`) reviewed against `docs/24-claude-design-v11p1.md`, `docs/requirements.md`,
and `docs/implementation-notes.md`.

Deviations that are already documented in `implementation-notes.md` (in-VM mmdebstrap,
in-memory EROFS, smoltcp MAC/RX-queue/socket-pool invariants, iptables-vs-TPROXY,
hand-rolled REST clients, global VMID/CID allocation, cgroup-v2 delegation, the FC
`resume_vm:false` and QEMU `snapshot_restore:false` choices, the CLI/metrics stubs,
etc.) are **not** re-reported here. Two further deviations found during this review were
judged justified and have been moved into `implementation-notes.md` (the FC `noxsave`
kernel arg, and the `restore()/snapshot()` `&VmConfig` parameter); they are likewise not
reported below.

Severity legend: **Critical** (correctness/safety hole or unmet hard requirement) ·
**Major** (significant defect or design-contract violation) · **Minor** · **Nit**.

---

## 0. Executive summary

The implementation is broad and tracks the design closely on the hard parts (the `Vmm`
trait + capability descriptor, the three backends, the vsock handshake, the rootless
smoltcp NAT, the EROFS-in-memory packer, the cgroup-v2 delegation dance). The CI gate
infrastructure is largely in place (`ci.yml` runs `cargo hack` feature-powerset clippy
with `-D warnings`, the lean-agent `cargo tree` assertion, and `cargo-deny`), and the
crate-root lint deny-list from §12.1 is present in `src/lib.rs`.

The most consequential problems cluster in three areas:

1. **Teardown ordering (Critical).** `TestVm::Drop` tears down the netns/cgroup *before*
   the VMM process is reaped, inverting the design's central no-leak ordering — and it
   never force-kills the VMM process group at all. This is the panic path the whole
   §4-step-7 / §12.4 lifecycle story exists to protect.
2. **Trait-contract gaps.** There is no `Error::Unsupported` variant; `restore()`/
   `snapshot()` do not self-guard on `capabilities()`; `config::build()` does not reject
   the virtio-fs-rootfs + snapshot combination; the `restore()` path never calls
   `AgentClient::reconnect()`.
3. **Artifact-pipeline requirements unmet.** No "resolve pins" first stage, no
   record/replay split, cache keys hash absolute paths (non-portable, non-deterministic),
   cache validity is existence-based rather than content-addressed, and the
   tamper-abort test does not actually test tamper-abort.

A large fraction of the design's §12.3/§12.4 test matrix is missing or asserts only the
happy path, and several integration tests silently pass when artifacts/KVM are absent
while CI never runs the `--ignored` suite — so those scenarios are effectively
CI-invisible.

Build hygiene: `cargo clippy --all-targets` (default features) is clean for the crate,
but **`cargo fmt --check` fails** — two test files have formatting drift (requirement
"source 6").

---

## 1. Divergences from the design

### Critical

- **C1 — `TestVm::Drop` does not enforce the ordered teardown and never force-kills the
  VMM.** `src/orchestrator.rs:536-551`. The `Drop` body removes smoltcp, proxy, netns
  (`ns.delete()`), then the cgroup, and never calls `self.instance.kill()`. The VMM is
  only reaped by the implicit field-drop that runs *after* the body, and that drop is
  `start_kill()` (non-blocking, leader-only — `src/vmm/cloud_hypervisor.rs:557-568`), not
  the live `kill -9 -<pgid>` group kill used by `kill()`. The design (§4 step 7, lines
  117/417) mandates **VMM process group first, then virtiofsd, then netns/cgroup/overlay/
  sockets**, precisely because "removing a netns while the VMM still holds interfaces or
  threads in it can hang or leak." The `shutdown()` path (`orchestrator.rs:514-533`) gets
  the order right; the panic path (`Drop`) does not. This is the single most important
  contract violation, and it is exactly the §12.3/§12.4 "Drop order … still runs on
  panic!" guard — which is also untested (see §3).

### Major

- **M1 — No `Error::Unsupported { vmm, feature }` variant.** `src/error.rs` has no such
  variant; unsupported ops return stringly-typed `Error::Vmm("…does not support…")`
  (`src/vmm/firecracker.rs:321,421`). The design mandates `Error::Unsupported { vmm,
  feature }` "never a panic" in §4 (line 120), §5.2 (lines 269/280/289), and §5.3 (line
  398). Callers cannot match structurally on capability gaps.

- **M2 — `restore()`/`snapshot()` do not self-guard on `capabilities().snapshot_restore`.**
  `src/vmm/qemu.rs:353` `Qemu::restore` reports `snapshot_restore: false` (`qemu.rs:400`)
  yet runs a full `migrate-incoming` sequence rather than returning early. The trait
  contract (§5.2 lines 252/263/289) requires these to return `Err(Error::Unsupported)`
  when the capability is false. `implementation-notes.md` claims this restore is "guarded
  by `capabilities().snapshot_restore`," but nothing inside `restore()` actually checks
  it — the guarantee depends entirely on callers never calling it.

- **M3 — `config::build()` does not reject virtio-fs-rootfs + snapshot.**
  `src/config.rs:291-329` validates vcpus/mem/kernel/share-tag-uniqueness only. Design
  §5.3 (line 397) and the §12.3 unit-test table explicitly require rejecting a virtio-fs
  *rootfs* combined with snapshotting (the §3.2 contested combo). Unimplemented and
  untested.

- **M4 — Artifact pipeline has no "resolve pins" Stage 0.** Requirement 2 and design §7
  mandate a first, non-deterministic stage that resolves the OCI digest, Debian snapshot
  timestamp, kernel version, and tool tags into a committed `pins.lock`. Pins are instead
  read from a static `pins.json` outside the pipeline (`src/bin/imp-testing.rs:55-57`);
  no `Stage` resolves them. The staged-production requirement's defining first step is
  absent.

- **M5 — No record/replay separation (requirement 7).** No stage splits network access
  into a record step and a replay step; `grep record|replay|cassette` in `src/artifact/`
  is empty. The OCI path's blob-by-digest cache (`oci.rs:51-73`) is a partial nod, but the
  kernel fetch (`kernel.rs:47-62`) and mmdebstrap apt fetches have no record/replay seam.

- **M6 — Rootless egress is not transparent; it relies on guest `http_proxy`/`https_proxy`
  env vars.** `src/net/smoltcp.rs:384-393,468-477` only listens on the literal
  `forward_ports` (proxy + host-services) and connects to `127.0.0.1:<same port>`; there
  is no L4 rewriting of guest tcp/80,443 into the proxy. Egress only works because
  `tests/egress_proxy.rs:137-146` injects the proxy env vars into the guest. A guest
  process that ignores those vars egresses with zero proxy visibility — defeating
  requirement 4's "filter and log *all* Web access." Design §5.3/§6.4 place interception
  "at L4 inside the NAT."

- **M7 — `AgentClient::reconnect()` is never called.** `src/agent/mod.rs:149` defines it,
  but the orchestrator's restore path (`orchestrator.rs:433-500`) only calls `connect`
  when `agent_client.is_none()` and otherwise reuses the cached client. The design (lines
  115/318/408) is emphatic that after a restore the host must drop the dead connection and
  reconnect. It happens to work today only because `agent_client` starts `None` on the
  current restore flow; the documented reconnect contract is unexercised and a latent bug
  if a client is ever cached across a snapshot.

- **M8 — CH `restore()` (and cold `create()`) attach virtiofsd to a snapshot-eligible VM.**
  `src/vmm/cloud_hypervisor.rs:406-410` starts a `VirtioFsDaemon` per share on the restore
  path (and `:270-279` on cold boot) with no guard. Per the §15.5 unifying law a
  snapshot-eligible VM must have **no vhost-user device** attached, and virtiofsd is
  vhost-user. The backend silently sets up the impossible combination instead of rejecting
  it.

- **M9 — No periodic sweeper / orphan registry.** Design lines 167/417 and §12.3/§12.4
  require "a periodic sweeper reaps anything orphaned by a hard crash" plus a registry the
  lifecycle test asserts against. Neither exists (`grep sweeper|registry|orphan` is empty).
  This is also why the only residue test (`tests/lifecycle.rs:118`) can only probe
  filesystem paths. (Candidate for `implementation-notes.md` if deferral is intentional —
  but it is a named design element, so it should at least be acknowledged there.)

- **M10 — PID-1 boot-time self-check missing.** Design line 407 requires `imp-guest-agent`
  to probe for vsock/virtio-fs support and emit a clear diagnostic *before binding*, so a
  missing-kernel-symbol regression fails legibly. `src/bin/imp-guest-agent.rs` has no such
  probe.

### Minor

- **m1 — Privileged ruleset has no `drop`/`log` rules.** `src/net/tap.rs:267-277`
  (`render_tproxy_rules`) emits only the prerouting TPROXY redirect with `policy accept`;
  design §5.3 specifies "plus `drop`/`log` rules." Non-HTTP egress on other ports leaves
  the netns unfiltered/unlogged; filtering is entirely delegated to the proxy's
  application-layer `blocked_domains`.

- **m2 — virtiofsd runs with `--sandbox=none`.** `src/fs.rs:49`. Design §5.3 specifies
  `--sandbox namespace` + a dedicated uid so each daemon "can reach only its one
  directory." `--sandbox=none` removes that confinement. If this is a rootless-environment
  necessity it should be documented in `implementation-notes.md`; as-is it is an
  undocumented isolation weakening.

- **m3 — `RootfsBuildSource::Mmdebstrap` doc says "on the host."** `src/artifact/rootfs/
  mod.rs:28` documents it as running mmdebstrap "on the host," contradicting both the
  in-VM design and the actual code (`mmdebstrap.rs` boots a builder VM). Stale/incorrect.

- **m4 — Record/replay "cassette" is record-only.** `src/proxy/mod.rs:254` /
  `src/proxy/doubles.rs:55-66` append only `METHOD URI` lines; nothing replays, and
  headers/body/response are not captured. The requirement-4 "great extra" is partial.
  (Candidate for `implementation-notes.md`.)

- **m5 — mmdebstrap signing-chain/snapshot-timestamp not enforced or pinned.**
  `src/artifact/rootfs/mmdebstrap.rs:111-131` trusts mmdebstrap's exit code; it does not
  force apt gpg verification or pass a `snapshot.debian.org` timestamp pin (only `release`
  is an input, `mmdebstrap.rs:15`). Requirement-3 reproducibility and requirement-8
  signing-chain verification are therefore not met for this source. The builder base image
  is also a hardcoded digest (`mmdebstrap.rs:26-32`), bypassing the pin model.

---

## 2. Correctness issues / bugs

### Critical

- (C1 from §1 — teardown ordering — is also the highest-severity correctness bug.)

### Major

- **B1 — PID-1 reaper races `child.wait()`, producing false exit code 127.**
  `src/bin/imp-guest-agent.rs:108-127` runs a `waitpid(None, WNOHANG)` reaper over *any*
  child, while `handle_exec` (`:268`) spawns a dedicated `child.wait()` thread. The reaper
  can reap the exec'd child first, making `child.wait()` return `ECHILD` → exit code `127`
  (`:282`) for a command that actually succeeded. Classic PID-1 reaper-vs-waiter race.

- **B2 — `blocked_domains` filter over-blocks sibling domains.**
  `src/proxy/doubles.rs:81` `host.ends_with(blocked)` — blocking `blocked.com` also blocks
  `notblocked.com`, `evil-blocked.com`, etc. Should match on label boundaries (`host ==
  blocked || host.ends_with(&format!(".{blocked}"))`). Trivially fixable and testable.

- **B3 — Cache keys are non-portable and non-deterministic; they hash absolute paths.**
  `src/artifact/snapshot.rs:31-38` and `src/artifact/rootfs/mod.rs:65-68` hash the
  `inputs.artifacts` *values*, which are absolute `PathBuf`s under `target_dir`. Two
  checkouts (or temp dirs) yield different keys for identical content, defeating
  cross-machine caching (requirement 4) and the §7 "pure cache_key" goal. No stage embeds a
  "stage version" either.

- **B4 — Cache validity is existence-based, not content-addressed.**
  `src/artifact/mod.rs:107-117` treats a stage as cached when the output file exists and the
  saved key string matches; it never hashes the output. A tampered artifact with an intact
  `.cache_key` is silently accepted — contradicting the requirement-8/§7 hard-stop.

- **B5 — `KernelStage` cache_key omits the SHA256 pin.** `src/artifact/kernel.rs:34-39`
  hashes the URL and microvm config but not `kernel_source_sha256`. Repointing the pinned
  digest at a new tarball at the same URL reuses the stale `vmlinux`.

- **B6 — zstd OCI layers are silently dropped.** `src/artifact/rootfs/oci.rs:45-48,77`
  only handles gzip; the design calls for zstd support (`flate2`/`zstd`). A
  `…tar+zstd`-layer image produces an empty/partial rootfs with no error.

- **B7 — `.expect("invariant")` saturates the smoltcp packet hot path.**
  `src/net/smoltcp.rs:455,459,471,479,495,510` (and the daemon-start `.expect`s at
  `:303-331`). A guest-driven transient (`send_slice` on a full buffer, `listen` on a
  non-closed socket, a vring op failing) panics the network thread and kills the VM's
  networking with no recovery. The crate denies `clippy::unwrap_used` under `not(test)`,
  but `.expect` is the permitted escape hatch — these uses are on a remotely-driven path
  where graceful degradation (log + continue/close) is required.

- **B8 — `probe_t2_template` leaks the probe socket and may leak the probe VM.**
  `src/vmm/firecracker.rs:192-314`: the probe API socket is never removed on success, and
  the booted probe microVM (`InstanceStart`, `:290`) is never explicitly shut down — its
  `FcInstance` is dropped, and `Drop` only `start_kill()`s without reaping.

- **B9 — `kill()`/`Drop` reaping is incomplete across all three backends.** `kill()` only
  signals/waits when `process.id()` is `Some` (`cloud_hypervisor.rs:455-464`,
  `firecracker.rs:581-591`, `qemu.rs:434-457`); `Drop` uses `start_kill()` with no `wait()`
  (`cloud_hypervisor.rs:559`, `firecracker.rs:712`, `qemu.rs:548`). With tokio's default
  (no kill-on-drop) a `TestVm` dropped without an explicit `kill()` leaves a zombie until
  the runtime reaps it, and `start_kill` signals only the leader, not the process group —
  so an `ip netns exec` wrapper or child VMM can survive. (Compounds C1.)

### Minor

- **B10 — smoltcp socket pool has no dead-socket eviction / hard cap.**
  `src/net/smoltcp.rs:468-528`: sockets stuck in `TIME_WAIT`/`CLOSE_WAIT` are not
  immediately `!is_open()`, and there is no backpressure; the documented 16-socket pool
  raises but does not remove the exhaustion threshold (17th concurrent keep-alive → RST).

- **B11 — Unbounded `rx_queue` growth on a wedged RX ring.**
  `src/net/smoltcp.rs:74-76,100-109`: `transmit()` always returns a token and `consume`
  pushes to `rx_queue` with no capacity check; if the guest RX ring stops draining
  (`:446-448`), smoltcp keeps producing packets into `rx_queue` without bound.

- **B12 — Device `rdev` uses legacy 8-bit encoding.** `src/artifact/tar2erofs.rs:111,128`
  compute `(major << 8) | minor` instead of Linux `makedev`. Wrong for `minor > 255` /
  `major > 255`; works for small-numbered base-image device nodes only.

- **B13 — `cgroup.procs` write failures are silently ignored for QEMU but logged for
  CH/FC.** `src/vmm/qemu.rs:303-307` (`let _ = …write(...)`) vs the `warn!` on the same op
  in `cloud_hypervisor.rs:231-240`. A QEMU VM silently escaping its cgroup (and thus
  resource limits) is not even logged. Also: no backend verifies the VMM actually joined
  the cgroup.

- **B14 — `assert!(res.vmid <= 254, …)` panics inside `create()`.**
  `cloud_hypervisor.rs:319,356`, `firecracker.rs:380,444`, `qemu.rs:245,273`. A vmid past
  the documented `/16` ceiling (§5.3 notes the address scheme must widen) panics the whole
  test runner instead of returning an `Error` as §4/§5.3 require.

- **B15 — QEMU `query-migrate` poll re-handshakes QMP every 50 ms.**
  `src/vmm/qemu.rs:49-90,380-389`: each poll opens a fresh `UnixStream` + greeting +
  `qmp_capabilities`, and any transient connect failure aborts restore via `?`. Dead in
  practice (M2), but the only place QMP correctness matters.

- **B16 — Clock resync truncates to whole seconds and runs in-band with in-guest
  `ip` rewrites.** `src/orchestrator.rs:455-496`: `date -s @<secs>` drops sub-second skew,
  and the restore path re-runs `ip link/addr` inside the guest — contradicting the
  agent-free/zero-netlink-in-guest invariant (line 403) — spread across multiple `exec`
  round-trips lazily inside `agent()`.

- **B17 — API-socket readiness loop hides early VMM death.**
  `cloud_hypervisor.rs:244-255`, `firecracker.rs:162-173`: a VMM that dies immediately
  (bad binary, missing KVM) surfaces as the generic "API socket failed to appear" error;
  the loop never checks `process.try_wait()` to fail fast with the real cause.

### Nit

- **B18 — `bench-vm` percentile indexing can touch `len`.** `src/bin/bench-vm.rs:33-36`
  computes `latencies[(count*p).floor() as usize]` without clamping to `len-1`.

---

## 3. Testing coverage gaps

The §12.3/§12.4 matrix is the design's own checklist; many rows are missing or weak.

### Critical / Major — missing entirely

- **T1 — vsock handshake FSM untested.** No test exercises `refused→OK` retry, `EOF→accept`
  (restore survival), or serial-log-panic fast-fail (`src/agent/mod.rs:47-108,149`). Only a
  happy-path UDS mock exists (`tests/exec_vsock.rs`).
- **T2 — Codec framing untested at the `LengthDelimitedCodec` layer.**
  `src/agent/protocol.rs` and `tests/proptests.rs:42` only test bare postcard; partial
  buffers and oversized-frame rejection (the §5.2 BufReader landmine) are unguarded.
- **T3 — No Drop-order-on-panic test against `FakeVmm`.** `tests/lifecycle.rs:56` checks
  happy-path call order only; it cannot catch C1. The panic-residue test (`:118`) is
  `#[ignore]`, needs real CH, checks only file paths, and silently returns if artifacts are
  absent.
- **T4 — `CidAllocator` is a process-global static and its wraparound/reserved/in-use
  assertions are missing.** `src/vmm/mod.rs:30-35` violates §12.5 ("IDs from injected
  allocators, never module-global statics"). `test_cid_allocator_prop` (`:332`) discards
  results and asserts nothing; `test_cid_allocator` (`:319`) is order-dependent on shared
  global state with no `#[serial]` (flaky under parallel tests).
- **T5 — No zero-netlink assertion.** A `MockNetlink` fake exists (`src/net/tap.rs:302`)
  but no test asserts it records **zero** calls (§12.4 / §4.2 contract).
- **T6 — cgroup-path construction untested and duplicated.** The sibling-placement logic is
  inline (`src/orchestrator.rs:230-234`) and copy-pasted into `tests/metrics_limits.rs:75-85`
  rather than extracted into a unit-tested pure function (§12.3 row).
- **T7 — `cache_key` cross-process determinism not asserted.** `src/artifact/kernel.rs:180`
  only checks intra-process equality; no pinned golden digest (so a hash-impl swap — the
  §4.4 defect class — passes green).
- **T8 — No `SmoltcpProcess`/`EgressProxy` shutdown-joins-worker test** (§12.3 row).
- **T9 — `render_tproxy_rules` untested.** §5.3 mandates unit-testing the ruleset render;
  no assertion that the output carries the tap/ports/proxy port/mark (`src/net/tap.rs:267`).
- **T10 — No FakeVmm orchestrator test of retry/timeout and restore-vs-cold-boot
  selection** (§12.4); `test_lifecycle_fake_vmm` covers call sequencing only.
- **T11 — Build-pipeline `reset_to(rootfs) rebuilds rootfs+snapshot but not kernel`
  untested** (only generic dummy-stage `reset_to`).

### Major — present but weak / wrong

- **T12 — `test_pipeline_tampered_digest_aborts` is misnamed and tests the opposite.**
  `tests/pipeline.rs:197-233` corrupts the `.cache_key` file (not the artifact) and asserts
  a rebuild; its own comment admits the pipeline stores no digests. The requirement-8
  hard-stop is unverified (and per B4, unimplemented).
- **T13 — OOM-kill assertion accepts almost any exit.** `tests/metrics_limits.rs:158-163`
  accepts `137 || -119 || 1 || -1`; code `1` is generic failure, so it passes even with no
  OOM kill. The CPU-load assertion (`:119`) accepts any non-zero (a missing binary passes).
- **T14 — `put_file` round-trip is mock-only.** `tests/exec_vsock.rs:87` asserts bytes
  arrived at a UDS mock; it never reads the file back in a guest, so a guest-side no-op
  `Ok(())` would still pass (§12.4 "write then read back").
- **T15 — snapshot reseed/resync assertions are coincidental.**
  `tests/snapshot_restore.rs:263` asserts two `/dev/urandom` reads differ (true even without
  reseeding); `:243` asserts the clock advanced after a host sleep (true even on a plain
  resume). Neither isolates the actual rotate/reseed/resync behavior.
- **T16 — egress block-detection is loose.** `tests/egress_proxy.rs:193-200` passes if
  stdout **or** stderr contains `"403 Forbidden"` **or** `"Blocked"`; an unrelated 403 page
  satisfies it.
- **T17 — path-injectivity prop test is string-only and omits `pid`.**
  `tests/proptests.rs:88` and `src/orchestrator.rs:584` format `imp-vm-{vmid}` strings and
  compare; they never build the actual per-VM socket paths and `pid` is never a variable
  (§12.3 requires injectivity in `(pid, vmid)`).
- **T18 — `/30` math has no boundary/overflow-rejection test.** `tests/proptests.rs:104`
  does a string `ends_with(".2/30")` check; no `vmid ∈ {0,1,254,255}` boundary and no
  octet-overflow rejection (§12.3 row).
- **T19 — `config::build()` has no negative tests.** `src/config.rs:337-368` covers only
  the happy path; no test asserts any rejection returns `Err` (incl. M3's virtio-fs+snapshot).

### Tests that assert nothing / silently pass

- **T20 — `tests/nested_virt.rs:81-90`** runs `kvm-ok`, ignores its exit, only `println!`s.
- **T21 — `tests/benchmark.rs:10-26`** CH case has its `cmd.assert().success()` commented
  out (`:23-25`) — builds args and exits without running or checking.
- **T22 — Artifact-absent skip == pass.** `boot.rs:34-42`, `shares_ro_rw.rs:52-55`,
  `lifecycle.rs:36-39`, `concurrency.rs:38-41`, `benchmark.rs:11` `return` green when
  `/tmp/imp-artifacts/*` is missing. Combined with CI not running `--ignored`, an
  environment misconfiguration is indistinguishable from a pass.

### Quality-gate infrastructure (§12.1/§12.2) — status

Present: crate-root lint deny-list (`src/lib.rs:7-30`); `cargo fmt --check`,
feature-powerset clippy `-D warnings`, lean-agent `cargo tree` assertion, and `cargo-deny`
(all in `.github/.../ci.yml`); `deny.toml` and `rustfmt.toml` exist.

Missing:
- **Per-module `#![forbid(unsafe_code)]`** on the I/O-free modules (`config`,
  `agent::protocol`, `artifact` cache_key, `net` /30 math) — the §12.1 structural rule;
  `grep forbid(unsafe_code)` is empty.
- **`cargo semver-checks`** — the §12.2 public-API gate is absent.
- **`cargo nextest` with per-test timeouts** — CI runs plain `cargo test`; the
  hang-as-timeout guard (the virtiofsd-socket-wait / cgroups-add_task hangs) does not exist.
- **A CI job that runs the `--ignored` integration matrix on a KVM-capable runner** — the
  entire §12.4 suite is CI-invisible.
- **The optional grep banning new `static …: Atomic…`** outside an allocator module (and it
  would currently fail on the CID global, T4).

---

## 4. Documentation issues

- **D1 — `cargo fmt --check` fails.** `tests/metrics_limits.rs:156` and
  `tests/snapshot_restore.rs:63` have formatting drift. Requirement "source 6" (rustfmt
  compliance). (Strictly a hygiene/CI issue, listed here as it's a "doc/format" gate.)
- **D2 — `src/vmm/firecracker.rs` has no module-level (`//!`) doc**, unlike its CH/QEMU
  siblings; `detect_cpu_template`/`probe_t2_template` (`:182,192`) are undocumented.
- **D3 — `restore()` trait doc omits the core invariant** (`src/vmm/mod.rs:133-142`): that
  the returned instance is **paused** and the caller must `resume()` (never `boot()`), and
  that it returns `Err(Error::Unsupported)` when unsupported.
- **D4 — `AgentClient::reconnect` doc claims it reconnects** (`src/agent/mod.rs:149-159`)
  but the body just swaps the stream and the method is never called (M7); the doc should
  reflect reality.
- **D5 — Stale "experimental" / wrong-location docs.** `src/artifact/tar2erofs.rs:3` calls
  the production-default packer "experimental"; `src/artifact/rootfs/mod.rs:28` says
  mmdebstrap runs "on the host" (m3).
- **D6 — Undocumented panics on PID 1.** `src/bin/imp-guest-agent.rs:37,215,216` `.expect`
  will kernel-panic the guest; the bin denies `missing_errors_doc` but not
  `missing_panics_doc`.
- **D7 — Under-justified `unsafe` SAFETY comments.** `src/proxy/mod.rs:102-103` ("Thread
  isolation for network namespace") does not state the `setns` preconditions; the smoltcp
  virtqueue ring ops (`smoltcp.rs:130-175,411-460`) carry no invariant comments despite the
  `avail_idx` consume-on-iterate hazard being load-bearing; `src/bin/imp-test-runner.rs:82`
  does not document the ambient-after-uid-change ordering requirement.
- **D8 — `CidAllocator::allocate` "252" vs the `3..=254` loop** and missing-ceiling comment
  (`src/vmm/mod.rs:38,61`) are mildly inconsistent.
- **D9 — `src/orchestrator.rs:425-432`** has a duplicated/garbled `agent()` doc comment
  (two `# Errors` blocks).
- **D10 — Missing `# Errors`/`# Panics`** on several items: `render_tproxy_rules`,
  `EgressProxy::install_double`/`record_to` (silent no-op on lock poison),
  `pack_erofs_with_injection` (the `cfg(not)` twin), `kernel.rs:120` (`spawn_blocking`
  `.expect`), and the many `.expect("invariant")` in `src/fs/in_process.rs`.

---

## 5. Rust best-practice deviations

- **R1 — `imp-test-runner` does not trim permitted/effective caps after raising ambient,
  and swallows bounding-drop errors.** `src/bin/imp-test-runner.rs:115-123` drops bounding
  caps one-by-one with `let _ =` (a failed drop silently leaves a wider set) and never
  trims `P`/`E` (§12.8 line 1129). In a privileged window, hygiene matters.
- **R2 — `setgroups` passes the address of a temporary.** `imp-test-runner.rs:87`
  `&gid.as_raw() as *const u32`; idiomatic form is a bound `let g = [gid.as_raw()];`.
- **R3 — `assert!`/`panic` on input-validation paths** (B14; also `config` would be the
  right place for the vmid-range check). Library code should return `Error`.
- **R4 — `.expect("invariant")` on remotely-driven hot paths** (B7; also
  `src/fs/in_process.rs:81-99,153-202` where `signal_used_queue().expect` panics on a
  transient ring error while the adjacent `add_used` path logs).
- **R5 — `byte[0] as char` for handshake bytes** (`src/agent/mod.rs:100`) is a lossy,
  non-idiomatic cast.
- **R6 — `/tmp` fallback paths mask pipeline-ordering bugs.**
  `src/artifact/snapshot.rs:44-50` and `rootfs/mod.rs:99-100` substitute `/tmp/vmlinux`,
  `/tmp/rootfs.erofs`, `/tmp/guest_agent` when an upstream artifact is missing; mmdebstrap
  correctly errors instead (`mmdebstrap.rs:17-19`).
- **R7 — `guest_agent.rs:27` hashes a source file via a CWD-relative path** and swallows
  the error with `if let Ok`, so the cache_key silently becomes a constant when CWD differs;
  it already uses `CARGO_MANIFEST_DIR` at `:50` and should there too.
- **R8 — Mixed logging facades.** `src/net/smoltcp.rs` mixes `log::trace!` (`:104,150`) and
  `tracing::*` (`:166,272`); pick one. Redundant `(vmid % 256) as u8` after `assert!(vmid
  <= 254)` (`smoltcp.rs:357-358`).
- **R9 — `format!("{}", x)` instead of inline `{x}` captures** throughout the VMM backends
  (clippy `uninlined_format_args`), and `(cfg.mem_mib as u64)` instead of
  `u64::from(cfg.mem_mib)` (`cloud_hypervisor.rs:300`).

---

## 6. Code quality improvements

- **Q1 — Triplicated cgroup-`stats()` reader.** Identical `memory.current`/`memory.peak`/
  `cpu.stat` parsing in `cloud_hypervisor.rs:499-542`, `firecracker.rs:652-695`,
  `qemu.rs:488-531`. This is the metrics-module extraction `implementation-notes.md`
  already flags as a refactoring gap — three copies to keep in sync.
- **Q2 — Triplicated spawn boilerplate.** `spawn_ch`/`spawn_fc`/`spawn_qemu` reimplement the
  tmp-dir naming, `ip netns exec` wrapper, `process_group(0)`, cgroup-procs write, and the
  50×20 ms readiness poll. A shared helper would also fix C1/B9/B13 in one place.
- **Q3 — Duplicated HTTP-over-Unix client.** `ChInstance::api_request`
  (`cloud_hypervisor.rs:124-182`) and `FcInstance::api_request` (`firecracker.rs:43-102`)
  are near-identical (~60 lines).
- **Q4 — Empty `Cache` struct threaded as `_cache`.** `src/artifact/mod.rs:64` — dead API
  surface; either implement or drop. `#[allow(dead_code)]` on `CacheKey` (`:40`) is likely
  stale (read via `key.0`).
- **Q5 — Dead protocol messages.** `Message::Hello` is never sent/received; `Message::Ping`
  is handled as a no-op (`imp-guest-agent.rs:142-144`) and never answered, so the
  advertised liveness check (`protocol.rs:31`) does not exist.
- **Q6 — Inconsistent CH-binary env var.** `snapshot.rs:62-63` reads
  `CLOUD_HYPERVISOR_PATH`; `mmdebstrap.rs:35` reads `IMP_CH_BIN`. Pick one.
- **Q7 — `-trace vhost_user_*` left on the production QEMU command line**
  (`src/vmm/qemu.rs:177-178`) — debug instrumentation on every boot.
- **Q8 — `CaManager` re-self-signs the CA on every `authority()` call**
  (`src/proxy/tls.rs:81-90`), so the persisted `ca.pem` and the in-use cert can differ in
  serial; cache the parsed authority.
- **Q9 — `/30` host-IP construction duplicated** across `net/tap.rs:261`, `net/tap.rs:66`,
  and `net/smoltcp.rs:357-358` with no shared (unit-testable) helper — the exact function
  §5.3 says to centralize.
- **Q10 — Test-helper duplication.** `common/mod.rs` provides artifact getters but no
  `start_vm` helper; the CID+VMID-alloc+`TestVm::start` boilerplate is copy-pasted in ~9
  integration tests, the per-backend `_ch`/`_fc`/`_qemu` triplet is hand-written in all 8
  matrix files with inconsistent skip-reason strings, and the CH variant never consults
  `capabilities()` (so a CH regression hard-fails instead of skipping). A
  `vmm_matrix_test!` macro + `common::start_vm` would remove ~40+ lines and fix the
  inconsistency. Also `tests/host_endpoint.rs:109-110` leaks the server process if an
  assertion panics first (vs the `Drop`-guarded server in `egress_proxy.rs:83-90`).

---

## 7. Suggested remediation order

1. **C1 / B9** — fix `TestVm::Drop` to force-kill the VMM process group first, then
   virtiofsd, then netns/cgroup; add the FakeVmm Drop-order-on-panic test (T3). This is the
   no-leakage guarantee.
2. **M1 / M2 / M3 / B14** — add `Error::Unsupported`, self-guard `restore()`/`snapshot()`,
   and make `config::build()` reject virtio-fs-rootfs + snapshot and out-of-range vmid
   (return `Err`, don't `assert!`).
3. **B2 / B7 / B1** — fix domain-suffix matching, replace hot-path `.expect` with graceful
   degradation, and fix the PID-1 reaper/waiter race.
4. **M4 / M5 / B3 / B4 / B5** — the artifact-pipeline requirement gaps (resolve-pins stage,
   record/replay split, content-addressed cache keys incl. stage version + SHA pin).
5. **M6 / M7** — make rootless egress actually transparent (L4 steering) and call
   `reconnect()` on the restore path.
6. **Test matrix** — T1–T11 (the missing unit guards) and fix T12/T13/T14/T22 (assertions
   that pass when they shouldn't); add `cargo nextest` timeouts, `cargo semver-checks`, the
   per-module `#![forbid(unsafe_code)]`, and a CI job that runs the `--ignored` suite.
7. **Hygiene** — `cargo fmt` the two drifted test files; the §6 refactors (Q1–Q3 especially)
   reduce the triplicated surface that several of these bugs live in.
