# Imp Testing — Code Review (Review 34)

**Date:** 2026-06-27
**Reviewer:** Claude (Opus 4.8), multi-agent review
**Scope:** Entire `imp-testing` crate — `src/**` (≈8,500 LOC), `tests/**` + `benches/` (≈2,100 LOC),
the build/gate config (`Cargo.toml`, `justfile`, `deny.toml`, `clippy.toml`, `.config/nextest.toml`,
`.github/workflows/ci.yml`, `scripts/`). The vendored `vendor/vhost*` fork is out of scope except its
carried `SET_VRING_ENABLE` patch.
**Standard:** `docs/28-claude-code-review-rubric.md` (Parts A–D) + `AGENTS.md` contracts, checked against
`docs/33-claude-design-v12p2.md` and `docs/requirements.md`. Recorded deviations cross-checked against
`docs/implementation-notes.md`.
**Method:** A full grounding build/test run on this KVM host, then 12 delegated sub-reviews (8 subsystem +
2 test-suite + gates + design-divergence), then adversarial verification of every Critical/High finding
(18 of 19 confirmed, 1 downgraded, 0 refuted). No fixes were applied. Justified design deviations were
recorded in `implementation-notes.md` rather than reported here (see §“Design conformance”).

---

## 1. Executive summary

The codebase is, on the whole, **well-built and unusually faithful to its own rubric**: the control plane
avoids the false-127 reaper race, PID-1 is genuinely zero-netlink and panic-resistant, the HTTP-over-Unix
client is a real client (not the banned 4096-byte prefix match), `/30` math is centralized and
boundary-tested, Drop force-kills the process *group* and releases both CID and VMID, the egress proxy makes
specific falsifiable assertions, and the lint header / nextest timeouts / deny allow-list match Part D. The
many “done well” items in §10 are real.

But the green-CI claim in `AGENTS.md`/`implementation-notes.md` (Pass 7) **does not hold as built**, and the
review found defects in every severity tier. Headlines:

- **`just ci` / GitHub CI is currently RED.** A single feature-gating bug breaks compilation in every
  configuration that excludes `cloud-hypervisor`/`firecracker`: `src/error.rs:58` `Hyper(#[from] hyper::Error)`
  and `:61` `Http(#[from] hyper::http::Error)` are not `#[cfg]`-gated (unlike the neighboring `SerdeJson` and
  `Reqwest` variants). Consequences, all **reproduced** in the grounding run:
  - the **guest agent** binary cannot be built (`cargo build --no-default-features --features agent` → E0433);
  - the **privileged test-runner** binary cannot be built (`--features test-runner` → E0433);
  - the **feature-powerset clippy** gate (`cargo hack`, in `just ci` and `ci.yml:35`) fails — so the gate that
    AGENTS.md leans on is red, catching exactly the “dep imported unconditionally under a feature gate” class
    it exists for.
- **The snapshot-eligibility law is not enforced for virtio-fs data shares** (Critical). The law is enforced
  for a virtio-fs *rootfs* and rootless net, but a snapshot config with a data `Share` passes `config::build()`,
  passes `orchestrator::restore()`, and `CloudHypervisor::restore()` then attaches `virtiofsd` (a vhost-user
  device) to the restored VM — “enforce in code, not just docs” is unmet at all three boundaries.
- **A guest-drivable panic exists in the rootless smoltcp NAT** (Critical): the RX path calls
  `add_used(...).expect("add used")` on a guest-controlled descriptor index (`src/net/smoltcp.rs:469`), while
  the TX path at `:168` handles the identical call defensively. A malformed avail-ring entry panics the
  net-thread and silently wedges guest networking.
- **`just test-rootless` runs zero tests** (and the same step in `ci.yml:82`): the filter
  `test(rootless) | test(smoltcp)` matches no test name, so nextest exits 4 (“no tests to run”). The rootless
  tier the design wants to “keep honest” is exercised by *nothing* — recipe-level skip == pass.
- **Several required integration assertions are theater**: the snapshot-restore clock-resync, RNG-reseed, and
  ordered-Drop-on-panic guards, and the memory-limit OOM test, all pass on their own inverse (§7).

**Counts (corrected for verification):** 2 Critical · 16 High · 37 Medium · 25 Low · 2 Info = **82 findings**.
(As filed: 2 Critical · 17 High · 36 Medium; `NET-2` was filed High and downgraded to Medium on verification.)

**Bottom line:** none of the Critical/High issues is unfixable, and several are one-liners (gate the two error
variants; reject shares on the snapshot path; swap one `.expect` for the TX path’s `is_err()` handling). But the
pattern from prior passes recurs — **a green local build masking broken non-default configurations, and required
tests that cannot fail** — so the first remediation is to make the gates actually run (fix the powerset break,
make `test-rootless` select tests) and to turn the four theatrical assertions red-on-inverse.

---

## 2. How the review was grounded (observed gate status)

Run on this host (KVM present; `cloud-hypervisor`, `virtiofsd`, `nft` installed; `cargo 1.92`). `cargo-nextest`
and `cargo-hack` were installed for the run; `cargo-semver-checks` was not available; **the privileged tier
could not run** (no passwordless `sudo` for `setcap`, so `just bless`/`just test-priv` were not validated — not
reported as passing).

| Gate / step | Observed | Notes |
|---|---|---|
| `cargo fmt --all --check` | ✅ clean | |
| `cargo build --all-features` | ✅ | |
| `cargo clippy --all-targets --all-features` (`-D warnings` too) | ✅ clean | even with `-D warnings` |
| `cargo build --no-default-features --features agent` | ❌ **E0433** | guest PID-1 binary does not compile (error.rs hyper) |
| `cargo build --no-default-features --features test-runner` | ❌ **E0433** | privileged runner does not compile |
| `cargo hack --feature-powerset --depth 2 clippy` (in `just ci`, `ci.yml:35`) | ❌ **fails** | same root cause → **`just ci` is red** |
| `cargo deny check` | ✅ | (advisory-ignore hygiene is weak — `GATES-3`) |
| `scripts/ban-global-state.sh` | ✅ passes | but under-matches (`GATES-2`) |
| `cargo nextest run --all-features` (= `just test-unit`) | ✅ **32 passed / 34 ignored** | |
| `just test-rootless` (`ci.yml:82`) | ⚠️ **exit 4** | “0 tests run, 44 skipped → no tests to run” |
| `just test-priv` | ⛔ not run | no passwordless `setcap` here — **not validated** |
| `cargo semver-checks` | ⛔ not run | not installed here (PR-only gate in `ci.yml:51`) |
| lean-agent `cargo tree` assert (`ci.yml:40`) | resolves | graph-only; does **not** build the agent (`GATES-4`); `netlink-packet-route`+`http` are non-optional deps and appear in the agent tree |

---

## 3. Critical findings

### C1 — Snapshot-eligibility law unenforced for virtio-fs data shares
`DESIGN-DIVERGENCE-1` (== `VMM-1`, `CONFIG-ERROR-ORCH-1` at other boundaries) · rubric B3/§3.3 · **verified Critical**

- **Where:** `src/config.rs:326-332` (build() guards only virtio-fs *rootfs* + snapshot), `src/orchestrator.rs:407-417`
  (restore() guards only VirtioFs rootfs + `NetConfig::Rootless`, never `cfg.shares`), `src/vmm/cloud_hypervisor.rs:320-324`
  (restore() unconditionally `VirtioFsDaemon::start()` per share) and `:394-414` (`ChInstance::snapshot()` checks nothing).
- **Defect:** A config with `snapshotting=true` and a virtio-fs data `Share` passes all three boundaries; the
  create()+snapshot() path literally wires `virtiofsd` into `ch_cfg` (`:193-202`), and restore() re-attaches it.
  The design (§3.3 “CH + a virtio-fs data share attached → No”, §5.2) and `AGENTS.md` (“restore()/snapshot() …
  must not attach virtiofsd. Enforce in code, not just docs.”) make this a hard stop. It is enforced in **none**
  of the three boundaries, and restore() never consults `capabilities()` — the latent-bug pattern the rubric forbids.
- **Fix:** Reject non-empty `cfg.shares` on the snapshot/restore path (or serve RO data as an extra erofs/block
  image), and make `ChInstance::snapshot()` / `CloudHypervisor::restore()` self-guard against any vhost-user
  device (shares, Rootless net) with `Error::Unsupported`. Add a negative test.

### C2 — Guest-drivable panic in the rootless smoltcp NAT RX/vring loop
`NET-1` · rubric B2 / “no panic on a guest-drivable path” · **verified Critical**

- **Where:** `src/net/smoltcp.rs:469` `vring_state.add_used(head_index, written).expect("add used")`, where
  `head_index` comes from the guest-controlled avail ring (`:427`,`:435`). Secondary guest-driven `.expect`s in
  the same loop: `:561` (`send slice`), `:576` (`recv block`); framework `.expect`s at `:243`,`:422`.
- **Defect:** Verified against `virtio-queue 0.17`: `AvailIter` passes the raw guest head index unvalidated, and
  `add_used` returns `Err(InvalidDescriptorIndex)` when it is `>= queue size`. A guest posting a bogus avail-ring
  index (plus any pending host→guest packet) panics the net-thread. The panic is contained to the background
  thread and swallowed by `Drop`’s `let _ = t.join()` (`:285`), so the VM silently loses networking — a fail-loud
  violation on top of the panic. The **TX path at `:168` already does this defensively** (`is_err()` + `tracing::error!`).
- **Fix:** Mirror the TX path on RX: on `add_used` error log and skip the descriptor; on send/recv error close the
  socket; never `.expect`/`.unwrap` on guest-shaped input.

---

## 4. High findings (16 net)

Each verified `confirmed` unless noted. Locations are `file:line`.

**Resource lifecycle (B1):**
- `VMM-2` — **Firecracker T2-template probe orphans a booted firecracker process.** `probe_t2_template()`
  builds `FcInstance { …, pgid: None }` (`src/vmm/firecracker.rs:148-155`) after `process_group(0)` and issues
  `InstanceStart`; `FcInstance::drop` only kills/reaps inside `if let Some(pgid)` (`:604`) and `kill_on_drop` is
  unset, so every probe exit path leaks a live firecracker (and on error paths it idles forever on an unlinked
  socket). Route the probe through the shared spawn/teardown helper and capture its pgid.
- `CONFIG-ERROR-ORCH-2` — **Cgroup v2 slice leaks on construction failure.** `setup_env()` creates the slice
  (`src/orchestrator.rs:297`) but returns it as a bare `String`; if `create()/boot()/restore()/resume()` errors
  (`:358/360/426/430`) `TestVm` is never built, so `delete_slice` (only in `Drop`/`shutdown`) never runs. CID,
  VMID and netns have RAII guards; the cgroup does not. Add a `CgroupGuard` mirroring `CidGuard`/`VmidGuard`.

**Capability / config contracts (B3):** `VMM-1`, `CONFIG-ERROR-ORCH-1` — the data-share half of C1, surfaced at the
backend and orchestrator boundaries (see C1).

**Determinism, caching & provenance (B4):**
- `ARTIFACT-PIPELINE-1` — **Cache key hashed in nondeterministic HashMap order.** `RootfsStage`/`SnapshotStage`
  `cache_key` iterate `&inputs.artifacts` (a `HashMap`, `src/artifact/mod.rs:31`) feeding blake3 in random order
  (`rootfs/mod.rs:80-83`, `snapshot.rs:37-40`); with ≥2 artifacts the key varies across processes → spurious
  cache miss → a forced, very expensive rebuild. Sort or use a `BTreeMap`.
- `ARTIFACT-PIPELINE-2` — **Keys hash absolute artifact paths, not upstream content/keys.** The same loop hashes
  `v.to_string_lossy()` (path strings under `target_dir`) and the rootfs key omits `guest_agent_src_hash`. Rebuilding
  the guest agent at the same path leaves the rootfs key unchanged → a **stale agent stays baked in**; new
  kernel/rootfs bytes leave the snapshot key unchanged → a stale snapshot is served. Hash upstream content hashes.
- `ARTIFACT-PIPELINE-3` — **`/tmp/vmlinux`, `/tmp/rootfs.erofs`, `/tmp/guest_agent` fallbacks mask a missing
  upstream.** `snapshot.rs:49,54` and `rootfs/mod.rs:123` use `unwrap_or_else(|| PathBuf::from("/tmp/…"))`. A
  missing input silently becomes a boot from a world-writable, attacker-plantable path (and `ARTIFACT-PIPELINE-6`
  makes the `/tmp/vmlinux` branch reachable). Use `ok_or_else(Error::Artifact)` as `mmdebstrap.rs:21-24` already does.
- `ARTIFACT-PIPELINE-4` — **Proxy CA is never written to the path it is injected from.** `rootfs/mod.rs:126`
  binds `let _ca_mgr = CaManager::new()?` (discarded), computes `ca_path = out.parent()/ca.pem`, injects it, but
  never writes it; `CaManager` writes to `IMP_ARTIFACTS_DIR`/`/tmp/imp-artifacts-{pid}` (`tls.rs:42-49`), a
  different dir. With `proxy`+`pipeline` default, `tar_to_erofs` then `std::fs::read`s a nonexistent `ca.pem` and
  the default rootfs build aborts (or, by dir coincidence, works). Write the CA explicitly.
- `ARTIFACT-PIPELINE-7` — **Cached OCI blob reused on replay without re-verifying its digest.** The sha256 check
  is nested in `if !cache_path.exists()` (`oci.rs:54-74`); the cache-hit path opens and decodes the blob with no
  re-hash (`:76`). A tampered cached blob (intact digest-derived filename, altered bytes) is packed silently —
  validity is existence-based, not content-addressed. Re-hash on every use.

**Failure visibility / divergence:**
- `DESIGN-DIVERGENCE-2` (== `CONFIG-ERROR-ORCH-3` Medium) — **Zero-netlink violated on restore.** `orchestrator.rs:547-549`
  runs `ip link set eth0 address … && ip addr flush dev eth0 && ip addr add … dev eth0` *inside the guest* on
  every restore, with the `Result` discarded (`let _ =`). `AGENTS.md` (“The restore path must not re-run `ip`
  inside the guest either”) and design Appendix A.3 reversal #2 forbid this; it is **unrecorded** in
  implementation-notes, and `ip addr flush` drops the IP-PNP default route (only the connected `/30` is re-added),
  **breaking post-restore egress to non-local destinations**. Rotate identity at the device layer, or record +
  gate it and re-add the route + surface the error.
- `PRIVILEGED-CLI-BENCH-1` — **Lean privileged-runner build is broken** (the `error.rs` hyper-gating headline;
  compounded by `src/lib.rs:67` re-exporting `AgentClient` un-gated, and `just bless` building `imp-test-runner`
  without `--features test-runner`). The §12.8 helper cannot compile in its intended rustix+capctl-only config,
  dragging the full host stack into the elevated binary. Gate the two error variants and the re-export; fix `bless`.

**Test quality (Part C — required integration assertions that cannot fail):**
- `TESTS-FEATURES-1` — **OOM test is a coincidental pass.** `tests/metrics_limits.rs:27` caps only the host
  cgroup (`mem_max_mib=256`) but guest RAM defaults to 128 MiB (`config.rs:217`); the in-guest `tail /dev/zero`
  is OOM-killed by the guest’s own 128 MiB (exit 137) regardless of `memory.max`. Deleting the cgroup cap leaves
  the test green. Set `mem_mib(512)`+`mem_max_mib(256)` and assert `memory.events oom_kill > 0`.
- `TESTS-LIFECYCLE-1` — **Clock-resync assertion is dead.** Resync fires once on the first post-restore `agent()`
  call (`orchestrator.rs:489-490,511-516`), which the test makes at `snapshot_restore.rs:157` with `RealClock`;
  the injected `FakeClock` (`:221-226`) is consulted on a later call where `restored==false`, so it is never read,
  and the assertion (`:243`) can never hold. Drive the *first* call with the FakeClock.
- `TESTS-LIFECYCLE-2` — **RNG-reseed assertion is theater.** `snapshot_restore.rs:248-261` runs the reseed
  *itself* and asserts only `code==0`; deleting the orchestrator’s restore-path reseed (`orchestrator.rs:535-541`,
  also `let _ =`-discarded) leaves it green. Capture pre/post entropy without the test issuing its own reseed.
- `TESTS-LIFECYCLE-3` — **Panic-residue cgroup check targets the wrong path.** `lifecycle.rs:184-188` asserts
  `!exists("/sys/fs/cgroup/imp-vm-{vmid}")`, but the real slice is nested at `{base}/imp-vm-{vmid}`
  (`orchestrator.rs:284-295`) under systemd/the capability runner, so a leaked cgroup leaves the assertion
  trivially true. Assert the computed name; extend to netns/tap/overlay/temp-dir/CID/VMID.
- `TESTS-LIFECYCLE-4` — **Ordered-teardown-on-panic guard checks only `.contains("drop")`.** `lifecycle.rs:191-230`
  uses the real `DefaultCgroupFs` and `network_disabled()`, so only one `FakeVmInstance::drop` event is recorded
  and **no ordering is asserted**; reordering Drop (delete netns before killing the VMM group — the exact
  documented hang/leak) is undetectable. Wire recording fakes and assert the full order, on normal drop and panic.

> `NET-2` (host smoltcp NAT MAC collides with `mac_math(254)` → silent link wedge for vmid 254) was **filed High,
> downgraded to Medium on verification** — real defect, ~1/254 blast radius on the non-default rootless path; the
> recorded MAC-pin rationale in implementation-notes is wrong for vmid 254. Listed under Medium (`net`).

---

## 5. Medium findings (37)

Grouped by subsystem; `id` · `file:line` · one-line defect → fix.

**vmm**
- `VMM-3` · `qemu.rs:362-384` — QEMU `pause()/resume()/request_shutdown()` swallow QMP `{"error":…}` replies and
  return `Ok(())`; `resume()` is on the restore path, so a failed resume masquerades as success → apply `boot()`’s
  error check (ideally a shared JSON-`error` parser) to all three.
- `VMM-4` · `firecracker.rs:95-105` — process-global `OnceLock CPU_TEMPLATE` memoizes the probe result for the
  whole process (stale for a later differing cfg; unfakeable seam; the `static Atomic` ban doesn’t catch it) →
  per-instance cache or an injectable seam.

**net**
- `NET-2` *(filed High → Medium)* · `smoltcp.rs:375` + `net/mod.rs:47-53` — host NAT MAC `02:00:00:00:00:fe`
  equals `mac_math(254)`; vmid 254 is allocatable → silent link wedge. Pin the host MAC outside `mac_math`’s
  range (nonzero 3rd octet) or exclude vmid 254; add a collision test.
- `NET-3` · `smoltcp.rs:273-288` — `SmoltcpProcess::Drop` joins workers with **no timeout** → a wedged worker
  hangs teardown forever. Bound the join; add a no-KVM start/drop test.
- `NET-4` · `smoltcp.rs:296-301,372` — `start()` doesn’t self-guard vmid; `ip_math(vmid).expect` panics the
  net-thread for vmid 0/>254 → validate in `start()` and return `Result`.
- `NET-5` · `smoltcp.rs:477-518,533-594` — guest-driven unbounded socket/port-map growth (~512 KiB per distinct
  dst port, never reclaimed) → memory DoS. Cap the pool and reclaim idle/closed mappings.
- `NET-6` · `tap.rs:399-434` — the `NftApplier`/`Netlink` recording fakes assert nothing and `smoltcp.rs` has
  zero tests → add tests asserting the rendered ruleset/netlink order, and that block attempts are exercised.

**proxy**
- `PROXY-1` · `doubles.rs:71,75,91,95` — hot-path lock-poison `.expect()` panics (diverges from `mod.rs`’s
  `into_inner` recovery); a panicking responder poisons the lock and bricks the proxy → `unwrap_or_else(|e| e.into_inner())`.
- `PROXY-2` · `doubles.rs:53-73` — **blocked egress requests are not recorded** in the request log; the most
  security-relevant events (denials) are invisible to capability-5 observability → record a `403 BLOCKED <host>` entry.
- `PROXY-3` · `doubles.rs:40-102` — no unit test guards the domain label-boundary match or CONNECT fall-through;
  reverting to a bare `ends_with` would pass CI → extract `is_blocked(host,&[String])` and unit-test siblings.

**control-plane**
- `CONTROL-PLANE-1` · `agent/mod.rs:159-196` + `imp-guest-agent.rs:346-357` — exec timeout leaks the guest child
  (default `None` timeout) and **desyncs the cached `AgentClient` stream** → later calls read stale framed data
  and return silently wrong results. Reset the connection on timeout; propagate the 10s default to the guest.
- `CONTROL-PLANE-3` · `imp-guest-agent.rs:138-140` — loopback bring-up ioctl failure returns `Err` from PID-1
  `main`, **kernel-panicking the guest** on a recoverable/cosmetic condition → log+continue.
- `CONTROL-PLANE-6` · `tests/exec_vsock.rs` — no non-KVM test exercises the reaper/exec coordination, EOF
  re-accept, or the zero-netlink assertion → extract a library-testable unit and drive concurrent execs + a
  signal-killed child (assert exit 137).

**artifact-pipeline**
- `ARTIFACT-PIPELINE-5` · `mod.rs:288-337` — `ResolvePinsStage` performs **no resolution** and never emits
  `debian_snapshot_timestamp`, so the mmdebstrap source can’t run → make Stage 0 actually resolve, or document
  `pins.json` as the committed lock and add the missing key.
- `ARTIFACT-PIPELINE-6` · `mod.rs:170-224`,`kernel.rs:215` — the `kernel` artifact is registered only on the
  warm-cache path; a cold build loses it downstream (reaching the `/tmp/vmlinux` fallback) → `insert("kernel",…)`
  in `run()` like `GuestAgentStage`.
- `ARTIFACT-PIPELINE-8` · `oci.rs:16-31` — OCI fetch has no injectable record/replay seam
  (`oci_client::Client::default()` hardcoded), so requirement-7 record/replay and tamper tests can’t run for
  OCI → add an injectable pull trait with a recording fake.
- `ARTIFACT-PIPELINE-10` · `tests/pipeline.rs` — the determinism/cache tests use a trivial `DummyStage` whose
  key is constant, so they cannot catch `ARTIFACT-PIPELINE-1/2`; `reset_to(unknown)` is untested → add real-stage
  determinism + golden key + `reset_to` negative tests.

**config-error-orch**
- `CONFIG-ERROR-ORCH-3` — see `DESIGN-DIVERGENCE-2` (zero-netlink on restore), Medium-rated half.
- `CONFIG-ERROR-ORCH-4` · `config.rs:313-353` vs `413-442` — **missing negative tests for 4 of the 6 required
  `build()` validations** (`vcpus==0`, mem floor, empty kernel, duplicate tag) → one red-on-inverse test each.
- `CONFIG-ERROR-ORCH-5` · `config.rs:29-30,287-291` — `VmConfig.vmid` is validated but **never applied**;
  `start()/restore()` always use the allocator → honor it (reserve through the allocator) or remove the field.
- `CONFIG-ERROR-ORCH-6` · `orchestrator.rs:82-104` — `VmidAllocator`’s hidden `/tmp/imp-vmid-*.lock` files
  break unit-test hermeticity (two `new()` instances collide globally) and erode capacity on crash → flock with
  owner liveness; keep `new()` hermetic for units.

**metrics-fs**
- `METRICS-FS-1` · `metrics.rs:127-169` — `io.stat` and net counters are never read; **4 public `ResourceUsage`
  fields are permanently 0** → populate them or delete the unfulfilled fields (requirement 8 underreporting).
- `METRICS-FS-2` · `metrics.rs:58-114` — `create_slice()` limit mapping (cpu quota, MiB→bytes, io.max/pids.max
  rendering) has no test that fails on an inverted formula → extract pure helpers and assert exact control-file
  contents.
- `METRICS-FS-3` · `metrics.rs:131-149` — the “sysfs bypass” memory read still depends on cgroups-rs detecting a
  Mem subsystem, so it **silently returns 0** when `subsystems()` is empty (the very constrained case the
  deviation claims to handle) → read `memory.current`/`memory.peak` unconditionally.

**privileged-cli-bench**
- `PRIVILEGED-CLI-BENCH-2` · `imp-testing.rs:57-62` — CLI `run/exec/ls/rm/stats` **return `Ok(())` and print
  success while doing nothing** → return a typed “not implemented” (non-zero) so they fail loud.
- `PRIVILEGED-CLI-BENCH-3` · `bench-vm.rs:115-124` — cold-boot benchmark never drops the page cache, so “cold”
  numbers are warm-cache (systematically optimistic) → drop caches via the capability runner before each cold iter.
- `PRIVILEGED-CLI-BENCH-4` · `imp-test-runner.rs:51` — runner is not dependency-thin and inits
  `tracing-subscriber` at full privilege before dropping caps → drop tracing from the `test-runner` feature; init
  after dropping privilege.
- `PRIVILEGED-CLI-BENCH-5` · `imp-test-runner.rs:116-125` — bounding-set drop silently no-ops (helper lacks
  `CAP_SETPCAP`) and the error is swallowed without comment → raise `CAP_SETPCAP` first and surface failure, or
  document that the step is best-effort.
- `PRIVILEGED-CLI-BENCH-6` · `imp-test-runner.rs:18,30` — the blessing remediation prints `+p` but the
  precondition checks the **effective** set, so following the printed command still fails → print `+ep`.

**tests-lifecycle / tests-features**
- `TESTS-LIFECYCLE-5` · `lifecycle.rs:60-126` — the FakeVmm orchestrator test doesn’t assert allocation
  order/retry/timeout (fake exists but under-driven) → extend it.
- `TESTS-LIFECYCLE-6` · `snapshot_restore.rs:36-38` — gates the privileged run on `geteuid()==0` instead of
  capability presence, demanding `sudo -E` and diverging from §12.8 → probe `CAP_NET_ADMIN`.
- `TESTS-FEATURES-2` · `tests/benchmark.rs:9-22` — `test_benchmark_ch` asserts nothing (commented-out assertion)
  → the primary backend’s benchmark coverage is theater; restore a real assertion or delete + correct the notes.
- `TESTS-FEATURES-3` · `tests/metrics_limits.rs:47-71,108-121` — memory/CPU assertions silently skip when the
  controller isn’t delegated (skip == pass) → make delegation a hard precondition or a visible skip.

**design-divergence**
- `DESIGN-DIVERGENCE-3` · `mod.rs:320-329` — `ResolvePinsStage` reads the guest-agent source via a CWD-relative
  path with a silent `"unknown"` fallback, omitted from the cache key → declare it an absolute cached input;
  fail hard if missing.

**gates (Part D)**
- `GATES-1` · `justfile:28-31` — local `just ci` clippy + powerset omit `-D warnings` (CI sets it via RUSTFLAGS),
  and the lean-agent assertion is absent locally, so the local gate is weaker than CI → add `-D warnings` + the
  `cargo tree` step.
- `GATES-2` · `scripts/ban-global-state.sh:8-10` — under-matches: misses `OnceLock`/`OnceCell`/`Mutex`/`Lazy`
  module-globals (e.g. `CA_CACHE`, `CPU_TEMPLATE`) and blanket-exempts two files → broaden the regex; use
  per-line allow comments.
- `GATES-3` · `deny.toml:15-41` — advisory ignores are bulk-suppressed with placeholder rationales and duplicate
  entries (`RUSTSEC-2021-0124`, `RUSTSEC-2026-0058`) → one real rationale (crate, exposure, why acceptable) per ignore.

---

## 6. Low & Info findings (27)

Compact; each is `id` · `file:line` — defect → fix.

- `VMM-5` · `cloud_hypervisor.rs:310`,`firecracker.rs:423` — CH/FC `restore()` don’t self-check
  `capabilities().snapshot_restore` → add the early guard (QEMU already does).
- `VMM-6` · `vmm/mod.rs:508-516` — `CidAllocator` proptest asserts nothing → assert uniqueness/≥3/round-trip.
- `VMM-7` · `vmm/mod.rs:229,246` — CID allocator `.expect()` on mutex poison → `parking_lot`/`into_inner`+comment.
- `NET-7` · `tap.rs:315-326` — TPROXY ruleset **drops** UDP/QUIC (udp/443) instead of intercepting (§6.3) →
  defensible (forces interceptable TCP); recorded as a justified deviation in implementation-notes (see §8).
- `NET-8` · `tap.rs` — stringly-typed Network/Subprocess errors lose `nft` stderr/exit; uncommented `let _ =` →
  typed sub-variants + capture diagnostics.
- `PROXY-4` · `proxy/mod.rs:233-240` — `requests()` `# Panics` doc claims a panic that cannot occur → fix the doc.
- `PROXY-5` · `doubles.rs:75-84` — cassette recording swallows open/write errors silently → `tracing::warn!`.
- `PROXY-6` · `tls.rs:28` — CA generation behind a process-global `OnceLock` (unfakeable; a second `new()` with a
  different `IMP_ARTIFACTS_DIR` reuses the first CA) → key the cache on the dir or inject the provider.
- `CONTROL-PLANE-2` · `imp-guest-agent.rs:201-372` — PID-1 reaper status map grows unbounded (orphan exit
  statuses never removed) → prune/bound.
- `CONTROL-PLANE-4` · `imp-guest-agent.rs:145-151` — boot self-check is info-only, doesn’t gate binding, doesn’t
  probe virtio-fs, and has a meaningless `/dev/vhost-vsock` OR-term → probe by opening AF_VSOCK, warn before bind.
- `CONTROL-PLANE-5` · `imp-guest-agent.rs:184-215` — reaper polls every 100 ms (up to ~100 ms added to every
  exec, against a ~35 ms warm-restore p50) → SIGCHLD/signalfd-driven wakeup.
- `ARTIFACT-PIPELINE-9` · kernel/rootfs/snapshot/guest_agent — **no stage version in any cache_key** → a build-logic
  change with unchanged pins serves a stale artifact; mix a per-stage version constant in.
- `ARTIFACT-PIPELINE-11` · `mmdebstrap.rs:31-37` — builder base digest hardcoded in source instead of pinned via
  Stage 0/pins.lock (can drift from the pinned rootfs) → source it from resolved pins.
- `CONFIG-ERROR-ORCH-7` · `error.rs:17-71` — internal-subsystem variants are stringly-typed (no typed sources);
  acceptable but loses matchable cause → prefer `#[from]`/structured fields where a real source exists.
- `CONFIG-ERROR-ORCH-8` · `config.rs:246-297` — `VmConfigBuilder` chain methods returning `Self` lack
  `#[must_use]` → add it.
- `METRICS-FS-4` · `metrics.rs`,`fs/in_process.rs` — mutex poison handled by `.lock().unwrap()`/`.expect`
  cascades → `parking_lot` or `into_inner`+comment (test fakes may keep unwrap with a note).
- `METRICS-FS-5` · `fs.rs:86,134-139` — virtiofsd success path drops the tokio `Child` with an **undrained piped
  stderr** (can wedge a chatty daemon) → redirect stderr to a log file / `Stdio::null`.
- `METRICS-FS-6` · `fs.rs:61-70` — virtiofsd runs as `SUDO_UID` (the developer) rather than a dedicated uid (RO
  `--sandbox=namespace` is correctly applied) → allocate a dedicated uid or record the approximation.
- `PRIVILEGED-CLI-BENCH-7` · `imp-test-runner.rs:127-137` — a **dead second setuid block** obscures the
  security-critical ordering (the real uid drop is at `:70-97`) → remove the dead block; comment the real one.
- `TESTS-LIFECYCLE-7` · `lifecycle.rs:129` — redundant ad-hoc `#[serial_test::serial]` instead of the nextest
  `serial-host` group → drop it.
- `TESTS-FEATURES-4` · `tests/pipeline.rs:157-194` — determinism test exercises only `DummyStage` (overlaps
  `ARTIFACT-PIPELINE-10`) → assert a real stage + golden key.
- `TESTS-FEATURES-5` · `tests/host_endpoint.rs:10-44` — hardcodes `/tmp/imp-artifacts` and bypasses the mandated
  `vmm_matrix_test!`/`require_cap!` harness → convert to the harness + `common::get_*`.
- `GATES-4` · `ci.yml:40-46` — lean-agent gate is graph-only (`cargo tree`); no gate builds the agent target (the
  reason the broken agent build slipped past) → add `cargo clippy --no-default-features --features agent`.
- `GATES-5` · `ci.yml:67-86` — integration matrix depends on a self-hosted KVM runner and uses `sudo -E` rather
  than the §12.8 capability runner → make it a required check / fail loud when absent; switch to `imp-test-runner`.
- `DESIGN-DIVERGENCE-4` · `config.rs:334-338` — `build()` accepts `vmid==0` (out-of-range for `/30`), and
  `cfg.vmid` is never plumbed into VM creation (overlaps `CONFIG-ERROR-ORCH-5`) → reject 0 + negative test.
- `CONFIG-ERROR-ORCH-9` *(Info)* · `orchestrator.rs:556-568` — `usage()` documents a panic it cannot raise → fix doc.
- `TESTS-FEATURES-6` *(Info)* · `tests/egress_proxy.rs:196-220` — the “CONNECT falls through” sub-test sends plain
  HTTP, not a CONNECT (the behavior is covered elsewhere) → rename or add a real CONNECT assertion.

---

## 7. Test-suite quality (Part C) — synthesis

The harness foundations are good: `nextest` `serial-host` group + per-test timeouts; `vmm_matrix_test!`/`require_cap!`
with the **primary CH path never exempted** (it panics on a missing cap rather than skipping); the `put_file`
matrix test is a **real guest round-trip**; `shares_ro_rw` asserts an RO share **rejects a write in the guest**;
`egress_proxy` has all four required, specific assertions; `proptests` assert (not compute-and-drop) and reject
vmid ∈ {0,255}; the **tamper test corrupts the artifact (not the `.cache_key`) and asserts abort**, backed by real
content-addressing. These are exactly the patterns prior passes lacked.

The gaps are concentrated and serious because they hit **required integration assertions**:
- **Four theatrical guards** (`TESTS-LIFECYCLE-1/2/3/4`, `TESTS-FEATURES-1`): clock-resync (dead FakeClock),
  RNG-reseed (re-runs the reseed itself), panic-residue (wrong cgroup path), ordered-Drop-on-panic (only
  `.contains("drop")`, no order), and memory-OOM (guest-RAM OOM, not `memory.max`). Each passes on its own inverse.
- **Skip == pass** at two levels: the recipe (`just test-rootless` selects 0 tests) and tests
  (`TESTS-FEATURES-3` silently skips when controllers aren’t delegated).
- **Under-driven fakes / missing negatives**: `FakeVmm` not exercised for allocation order/retry (`TESTS-LIFECYCLE-5`);
  no non-KVM reaper/exec test (`CONTROL-PLANE-6`); 4 of 6 `build()` validations have no negative test
  (`CONFIG-ERROR-ORCH-4`); `CidAllocator` proptest asserts nothing (`VMM-6`); `NftApplier`/`Netlink` fakes assert
  nothing and `smoltcp.rs` has zero tests (`NET-6`); the determinism test can’t catch the real cache-key bugs
  (`ARTIFACT-PIPELINE-10`/`TESTS-FEATURES-4`).

The meta-rubric question — *“write the buggy impl; does the test go red?”* — answers **no** for each of the above.

---

## 8. Design conformance & divergences

Conformance is strong on the load-bearing invariants: capability matrix matches §3.4; `/30` math centralized and
boundary-tested; zero-netlink-in-PID-1 holds **at boot** (broken only on the restore path, `DESIGN-DIVERGENCE-2`);
`build()` rejects most invalid configs; QEMU snapshot self-guards; the snapshot stage boots erofs; provenance
(kernel sha256, OCI digest-pinning, gzip+zstd, `makedev`) is correct on the cold path.

**Unjustified / incorrect divergences are reported as findings above** (the snapshot-law data-share gap C1; the
restore-path `ip` re-run `DESIGN-DIVERGENCE-2`; `ResolvePinsStage` not resolving `ARTIFACT-PIPELINE-5`;
guest-agent-source CWD path + “unknown” fallback `DESIGN-DIVERGENCE-3`; `vmid==0`/unused `cfg.vmid`
`DESIGN-DIVERGENCE-4`).

**Justified divergences were recorded in `docs/implementation-notes.md` (Review 34 section), not reported here**, per
instruction. The newly-recorded ones: the `hudsucker` re-self-sign of loaded CA params (preserves the trust chain,
not a per-call re-sign); the protocol’s deliberate omission of the dead `Hello`/no-op `Ping` variants; the separate
injection of `CidAllocator`/`VmidAllocator`/`CgroupFs` (more seams than the §10.2 sketch); the `deny.toml` allow-list
additions (`Unicode-3.0`, `CDLA-Permissive-2.0`, both permissive); the `exec_vsock` `_mock` test classification; and
the TPROXY QUIC-block posture (`NET-7`, blocking UDP/443 to force interceptable TCP). The already-recorded deviations
in implementation-notes (the `&VmConfig` thread-through, FC `resume_vm:false`, QEMU snapshot=false, `noxsave`, the
smoltcp invariants, in-VM mmdebstrap, etc.) were re-validated and remain justified — **except** the implementation-notes
entries whose stated rationale is now contradicted by a finding: line 15 (the `&VmConfig` note cites “reconstruct
virtio-fs daemons” — the C1 defect) and line 27 (the MAC-pin rationale — wrong for vmid 254, `NET-2`).

---

## 9. Code-quality opportunities (no behavior change required)

- **De-triplicate the remaining divergence-prone spots.** Spawn/readiness and the HTTP client are already shared
  (good); add a shared QMP/JSON-error parser (`VMM-3`) and route the FC probe through the shared spawn/teardown
  helper (`VMM-2`).
- **Replace module-global singletons with injectable seams**: `CPU_TEMPLATE` (`VMM-4`), `CA_CACHE` (`PROXY-6`) —
  also closes the `GATES-2` blind spot.
- **Tighten the error type** where a real typed source exists (`CONFIG-ERROR-ORCH-7`, `NET-8`) and add `#[must_use]`
  to builders (`CONFIG-ERROR-ORCH-8`).
- **Comment or surface every `let _ = result`** (`orchestrator.rs:535-549`, `tap.rs`, `doubles.rs:75-84`,
  `imp-test-runner.rs:116-125`) — the rubric’s default-stance rule.
- **Delete dead code**: the second setuid block (`PRIVILEGED-CLI-BENCH-7`), and either honor or remove `cfg.vmid`
  (`CONFIG-ERROR-ORCH-5`) and the always-zero `ResourceUsage` fields (`METRICS-FS-1`).
- **Make local `just ci` match CI** (`-D warnings`, lean-agent build) so “green locally” means “green in CI”.

---

## 10. What’s done well (representative)

- Control plane: real hyper http1 client shared across backends; **no false-127 reaper race** (single WNOHANG
  reaper, no `child.wait()`, poison-tolerant status map + condvar); PID-1 survives hostile input via typed Results.
- **Zero-netlink-in-PID-1 by construction** at boot (eth0 via kernel `ip=`, only `lo` via ioctl, no rtnetlink dep).
- Teardown: all three `Drop`s force-kill the process **group** (`kill -9 -<pgid>`, pgid cached at spawn) and reap;
  `TestVm::Drop` releases **both** CID and VMID; guards mutate the **real** allocator state; QEMU also reaps its
  `vhost-device-vsock` group.
- `wait_for_socket` fails fast via `try_wait()` (no fall-through-to-success); fs.rs bounds the wait + surfaces stderr.
- Capabilities: `create()` rejects unsupported FC configs with `Error::Unsupported`; QEMU `restore()/snapshot()`
  self-guard; descriptors match §3.4.
- `/30` math centralized in `net::ip_math`, consumed identically everywhere, unit- and prop-tested with exact octets
  and boundary rejection; `Netlink`/`NftApplier` use pure-Rust rtnetlink/nft-stdin (no `ip`/shell, no injection).
- Provenance: blake3 (no `DefaultHasher`); kernel sha256 hard-stop; OCI digest-pinned with gzip+zstd and `makedev`;
  **content-addressed tamper test** corrupts the payload (not the sidecar) and asserts abort.
- Proxy: correct **label-boundary** domain match (siblings not over-blocked), CONNECT fall-through, configurable
  deny list, CA key `0600`+atomic-rename, worker joined on Drop; specific MITM/block/intended-dest assertions.
- Gates: lint header matches Part D exactly; `#![forbid(unsafe_code)]` on the four I/O-free modules; real per-test
  timeouts + `serial-host`; deny is allow-only with `wildcards=deny`; the powerset gate **is effective** — it is
  red and correctly catching the hyper leak.

---

## 11. Prioritized remediation

1. **Unbreak the build/gates** (one root cause + two recipe fixes): `#[cfg(any(feature="cloud-hypervisor",
   feature="firecracker"))]` on `Error::Hyper`/`Http` (`error.rs:58,61`); `#[cfg(feature="host-common")]` on the
   `AgentClient` re-export (`lib.rs:67`); make `just test-rootless`/`ci.yml:82` actually select tests (name a
   `rootless`/`smoltcp` test or fix the filter); fix `just bless` to pass `--features test-runner`.
2. **C1 — snapshot-law for data shares**: reject shares on the snapshot/restore path and self-guard the backend.
3. **C2 — smoltcp guest-drivable panic**: mirror the TX path’s `is_err()` handling on RX; de-`expect` the loop.
4. **Turn the theatrical guards red-on-inverse**: `TESTS-LIFECYCLE-1/2/3/4`, `TESTS-FEATURES-1` (and add the 4
   missing `build()` negatives, `CONFIG-ERROR-ORCH-4`).
5. **Stop the leaks**: FC probe orphan (`VMM-2`), cgroup-slice-on-failure (`CONFIG-ERROR-ORCH-2`), smoltcp
   unbounded sockets (`NET-5`) and no-timeout join (`NET-3`).
6. **Restore-path correctness**: remove/record the in-guest `ip` re-run and fix the dropped default route
   (`DESIGN-DIVERGENCE-2`); reset the desynced agent stream on exec timeout (`CONTROL-PLANE-1`).
7. **Cache-key correctness**: order-independent + content-hashed keys + stage version (`ARTIFACT-PIPELINE-1/2/9`);
   replace `/tmp/*` fallbacks with errors (`-3`); re-verify cached OCI blobs (`-7`); write the proxy CA (`-4`).
8. **Privileged-window + CLI honesty**: stub subcommands fail loud (`PRIVILEGED-CLI-BENCH-2`); fix the `+p`→`+ep`
   blessing message (`-6`); surface the bounding-set-drop failure (`-5`); slim the runner (`-4`).
9. **Lower-priority quality** (§9) and the remaining Low/Info items.

---

## Appendix — finding index (82)

Severities are post-verification. `▸` = verified `confirmed`; `▽` = downgraded on verification.

| ID | Sev | Area | Location |
|---|---|---|---|
| DESIGN-DIVERGENCE-1 ▸ | Critical | B3/§3.3 | cloud_hypervisor.rs:320; orchestrator.rs:407; config.rs:326 |
| NET-1 ▸ | Critical | B2 | net/smoltcp.rs:469 |
| ARTIFACT-PIPELINE-1 ▸ | High | B4 | artifact/{snapshot.rs:37,rootfs/mod.rs:80} |
| ARTIFACT-PIPELINE-2 ▸ | High | B4/B5 | artifact/{rootfs/mod.rs:80,snapshot.rs:37} |
| ARTIFACT-PIPELINE-3 ▸ | High | B5 | artifact/{snapshot.rs:49,54;rootfs/mod.rs:123} |
| ARTIFACT-PIPELINE-4 ▸ | High | B4 | rootfs/mod.rs:126; proxy/tls.rs:42; tar2erofs.rs:24 |
| ARTIFACT-PIPELINE-7 ▸ | High | B4 | rootfs/oci.rs:54-77 |
| CONFIG-ERROR-ORCH-1 ▸ | High | B3 | orchestrator.rs:407; cloud_hypervisor.rs:321 |
| CONFIG-ERROR-ORCH-2 ▸ | High | B1 | orchestrator.rs:297,358,426,606 |
| DESIGN-DIVERGENCE-2 ▸ | High | Divergence/§4.3 | orchestrator.rs:547-549,535-541 |
| PRIVILEGED-CLI-BENCH-1 ▸ | High | Correctness/§12.8 | error.rs:58,61; lib.rs:67; justfile:7 |
| TESTS-FEATURES-1 ▸ | High | PartC | metrics_limits.rs:27,123-142 |
| TESTS-LIFECYCLE-1 ▸ | High | PartC | snapshot_restore.rs:157,221-246 |
| TESTS-LIFECYCLE-2 ▸ | High | PartC | snapshot_restore.rs:248-261 |
| TESTS-LIFECYCLE-3 ▸ | High | PartC | lifecycle.rs:184-188 |
| TESTS-LIFECYCLE-4 ▸ | High | PartC | lifecycle.rs:191-230 |
| VMM-1 ▸ | High | B3 | cloud_hypervisor.rs:320-324,394-414 |
| VMM-2 ▸ | High | B2 | firecracker.rs:148-155,604 |
| NET-2 ▽ | Medium | Correctness | net/smoltcp.rs:375; net/mod.rs:47-53 |
| VMM-3 / VMM-4 | Medium | Correctness/Quality | qemu.rs:362; firecracker.rs:95 |
| NET-3/4/5/6 | Medium | B1/Correctness/PartC | net/smoltcp.rs:273,296,477; net/tap.rs:399 |
| PROXY-1/2/3 | Medium | Quality/Correctness | proxy/doubles.rs:40-102 |
| CONTROL-PLANE-1/3/6 | Medium | Correctness/B2/PartC | agent/mod.rs:159; imp-guest-agent.rs:138; exec_vsock.rs |
| ARTIFACT-PIPELINE-5/6/8/10 | Medium | B5/PartC | artifact/mod.rs:288,170; oci.rs:16; pipeline.rs |
| CONFIG-ERROR-ORCH-3/4/5/6 | Medium | Divergence/PartC/Quality | orchestrator.rs; config.rs:313 |
| METRICS-FS-1/2/3 | Medium | Divergence/B8 | metrics.rs:127,58,131 |
| PRIVILEGED-CLI-BENCH-2..6 | Medium | B2/Correctness/Divergence | imp-testing.rs:57; bench-vm.rs:115; imp-test-runner.rs |
| TESTS-LIFECYCLE-5/6; TESTS-FEATURES-2/3 | Medium | PartC/Divergence | lifecycle.rs; snapshot_restore.rs; benchmark.rs; metrics_limits.rs |
| DESIGN-DIVERGENCE-3 | Medium | Divergence | artifact/mod.rs:320 |
| GATES-1/2/3 | Medium | PartD | justfile:28; ban-global-state.sh; deny.toml:15 |
| VMM-5/6/7 | Low | B4/PartC/Quality | vmm/{cloud_hypervisor.rs:310,mod.rs:508,mod.rs:229} |
| NET-7/8 | Low | Divergence/Quality | net/tap.rs:315,73 |
| PROXY-4/5/6 | Low | Doc/Quality | proxy/{mod.rs:233,doubles.rs:75,tls.rs:28} |
| CONTROL-PLANE-2/4/5 | Low | Correctness/B2/Quality | imp-guest-agent.rs:201,145,184 |
| ARTIFACT-PIPELINE-9/11 | Low | B4/B5 | kernel.rs; mmdebstrap.rs:31 |
| CONFIG-ERROR-ORCH-7/8 | Low | Quality | error.rs:17; config.rs:246 |
| METRICS-FS-4/5/6 | Low | Quality/PartD | metrics.rs; fs.rs:86,61 |
| PRIVILEGED-CLI-BENCH-7 | Low | Quality | imp-test-runner.rs:127-137 |
| TESTS-LIFECYCLE-7; TESTS-FEATURES-4/5 | Low | Quality/PartC | lifecycle.rs:129; pipeline.rs:157; host_endpoint.rs |
| GATES-4/5 | Low | PartD | ci.yml:40,67 |
| DESIGN-DIVERGENCE-4 | Low | PartC | config.rs:334 |
| CONFIG-ERROR-ORCH-9; TESTS-FEATURES-6 | Info | Doc/PartC | orchestrator.rs:556; egress_proxy.rs:196 |

*Full per-finding evidence, the buggy-impl framing, and the adversarial verdict reasoning for every Critical/High
item are preserved in the review working set; this document is the synthesis.*
