# Perf experiments log — recovering cold-boot / restore latency

Working log for the "buggy-fast → correct-slow" latency-recovery effort. Goal: recover
cold-boot and warm-restore latency **without** reintroducing the bugs the correct code fixed.
Folded into `benchmark-results.md` + design once experiments settle.

## Substrate (this pass, 2026-07-01)

Intel Core Ultra 7 258V (Lunar Lake, 8c/8t), 30 GiB RAM, ext4-on-NVMe (`/tmp` tmpfs);
CH v52.0.0 / FC v1.16.0; guest kernel 6.12.94; freq-pinned `performance`+turbo-off (2.2 GHz base)
via the capability runner; **"cold" is warm-cache** (`drop_caches` is euid==0-gated). Numbers are
`bench-vm` p50 unless noted. Run via `scripts/run-bench.sh` (delegated scope + blessed runner).

## Baseline (current `main`, correct code)

| Metric | p50 | p95 |
| --- | --- | --- |
| CH cold boot → ready | **642 ms** | 674 |
| CH warm restore → ready | **166 ms** | 174 |
| FC cold boot → ready | **1019 ms** | 1037 |
| vsock exec round-trip | 694 µs | 827 |

Phase budget (CH), p50 µs → ms:
- COLD: create 43 / **connect 613** / exec 5 / teardown 531
- RESTORE: create 50 / **connect 110** / exec 1 / teardown 531

Notes: `connect` dominates both paths. `teardown` = `shutdown()`'s fixed `SHUTDOWN_GRACE=500ms`
sleep (excluded from the headline time-to-ready numbers; bounds per-test throughput).

## Final result (full stack: EXP-1 + EXP-2 + EXP-3 + EXP-4)

Canonical re-run, same suite as the baseline (freq-pinned 2.2 GHz, warm-cache):

| Metric | baseline | final | improvement |
| --- | --- | --- | --- |
| CH cold boot → ready | 642 | **330** | **−49%** |
| CH warm restore → ready | 166 | **84** | **−49%** |
| FC cold boot → ready | 1019 | **776** | −24% |
| CH phase COLD connect | 613 | **284** | −54% |
| CH phase RESTORE connect | 110 | **36** | −67% |
| CH teardown (graceful `shutdown()`) | 531 | **283** | −47% |
| vsock exec RTT | 694 µs | 711 µs | ~flat |

Final cmdline lever is **`loglevel=6`** (see EXP-1): a first `quiet loglevel=3` cut CH cold to 287 ms
but emptied the serial log and failed `boot.rs`'s "Linux version" assertion; `loglevel=6` keeps a
debuggable serial log (+panic capture) at a ~43 ms cost. Validation: **`just ci` green**, **unit suite
242 passed / 0 failed**, **`just test-privileged` 232 passed / 0 failed** (clean re-run;
`boot::{cloud_hypervisor,firecracker}` pass). No invariant relaxed; every optimization has its
bug_risk noted below. The "buggy-fast → correct-slow" gap was mostly recoverable: the verbose serial
console (EXP-1) and a coarse guest accept poll (EXP-4) were the two biggest levers.

## Follow-up: tunable config knobs + native resync (design `docs/44-...`)

### Phase 1 — KernelVerbosity + Timeouts presets + shared cmdline builder (host-only) — KEEPER

`KernelVerbosity` (Quiet/Balanced/Verbose/Debug → `loglevel=3/6/7/8`) and a `Timeouts` struct with
`default()`/`low_latency()`/`throughput()` presets (all clamped to floors) on `VmConfig`; a single
`build_kernel_cmdline` shared by all 3 backends. Wired into connect/shutdown/api-poll; bench-vm gained
`--profile` / `--kernel-verbosity`. Unit 246/0; boot::{ch,fc,qemu} pass.

| Result | value |
| --- | --- |
| **QEMU cold boot** (shared builder gives QEMU its missing `loglevel=6`) | ~1400 → **996 ms** |
| **`throughput` profile teardown** (`shutdown_grace` 250→50 ms) | 283 → **96 ms** |
| **Logging VM-exit cost** (CH cold, `verbose` vs `balanced`) | 561 vs 330 → **+231 ms** |
| CH cold (regression check, default profile) | 333 ms (unchanged) |

**VM-exit finding (maintainer's question):** yes — kernel serial logging causes VM exits. `ttyS0` is a
legacy **PIO** 8250 UART, so each logged byte traps to the VMM; the +231 ms `verbose`-vs-`balanced`
delta is that exit cost. `KernelVerbosity` lets debugging/specific tests pay it without taxing every VM.
(`perf kvm stat` blocked by `perf_event_paranoid=4` here; the A/B is the evidence.)

**Pre-existing flakiness (not this change):** `snapshot_restore::cloud_hypervisor` /
`egress_proxy::qemu` agent-timeout under full-suite concurrency load (differ run-to-run; the test
passes **3/3 in isolation**). Worth a separate test-robustness look; orthogonal to these features.

### Phase 2 — native in-agent resync + guest cmdline-tunable timeouts (rootfs rebuild) — KEEPER

`Resync`/`ResyncAck` protocol pair replaces the 3 post-restore subprocess execs with one native
round-trip: clock via `rustix::time::clock_settime`, RNG via a pure-`std::io` 32-byte
`/dev/hwrng`→`/dev/urandom` copy, MAC via a `SIOCSIFHWADDR` ioctl in a new lean-agent `netif` module
(reusing the guest-tools logic — removes the multi-MB `ip` binary from the restore hot path). M-RESTORE-1
fail-loud contract preserved (`clock_error` → `Err` before clearing `restored`). Guest `ACCEPT_POLL`/
`REBIND_IDLE` now parsed from `vmcell_accept_poll_ms=`/`vmcell_rebind_idle_ms=` cmdline tokens (clamped
to floors), so the `Timeouts` presets tune the guest without a rootfs rebuild.

| Metric | pre-Phase-2 | Phase 2 | Δ |
| --- | --- | --- | --- |
| CH warm restore (default) | 84 | **60 ms** | −24 (−29%) |
| CH phase RESTORE `connect` | 36 | **16 ms** | −20 (native resync removed the 3 spawns) |
| CH cold (default) | 330 | 327 | ~0 (resync is restore-only) |
| CH cold (**low-latency** profile) | 327 | **309 ms** | −18 (guest `accept_poll=5ms` honored) |

Validation: unit 249/0 (incl. protocol round-trip, framing, `parse_ms` clamp, ifreq layout, clock
mapping, the 4 M-RESTORE-1 fail-loud tests); lean-agent gate clean (no reqwest/tokio/hyper in the
agent); `snapshot_restore::ch` passes in isolation and asserts the **native** MAC rotation to
`mac_math(new_vmid)` + clock resync (via `FakeClock`) + reseed. `boot::{ch,fc,qemu}` pass.

**Restore, full journey:** 166 (original) → 84 (perf pass) → **60 ms** (native resync) = **−64%**.

## Flake investigation (2026-07-02): the full-suite "Agent … timed out"

**Symptom.** Running the full privileged suite, ~1–3 VM tests intermittently fail with
`Timeout("Agent connection/exec timed out")`; the wedged guest logs `handle_connection error: failed
to fill whole buffer` (an EOF mid-frame — the CH hybrid-vsock control connection reset). Hits any VM
test (snapshot_restore, egress_proxy, host_endpoint, concurrency, put_file, benchmark); passes 3/3 in
isolation.

**Root cause: pre-existing / environmental — NOT a code regression.** Bisected by checking out the
pre-optimization baseline (`50811f9`, `ACCEPT_POLL=100ms`/`REBIND_IDLE=1s`), rebuilding its rootfs, and
running the suite 6×: it **also flakes** (2 clean, then intermittent failures) — so the perf pass did
not introduce it. It is an intermittent CH-vsock reset under repeated back-to-back boots; the rate
rises with host load (slower runs flake more). No leaks (netns=0, no orphaned VMMs/scopes; the 25 loop
devices are snapd, unrelated), ample memory. The historical "195/0" baseline was a single (lucky) run.

**Ruled out (each tested, reverted):**
- *Lib-test oversubscription* — the suite pulled the ~172 `kind(lib)` unit tests (not in `serial-host`)
  to run at num_cpus alongside the serial VM test. Scoping to `kind(test)` (justfile) removed them, but
  the flake persisted → not the (sole) cause. Kept anyway (correct: lib tests belong in `test-unit`;
  less load; faster suite 236→59 tests).
- *Guest listener re-bind resetting the active connection* — gated re-bind on "no active connection";
  the flake persisted, and the gate risks the design's "stale connection may never EOF" case → reverted.

**Fix: `nextest retries` + `kind(test)` scoping.** `retries = {backoff=exponential, count=3, delay=5s,
max-delay=20s}` on the `integration` profile: a transient reset is sidestepped by a fresh-VM retry
(with growing delays to outlast a load burst), while a genuine break still fails all 4 attempts, so
coverage is preserved. This is the standard, honest mitigation for a confirmed-intermittent
environmental integration flake (a real host run occasionally, not 40× back-to-back like this bisect
session, sees a lower base rate). Deeper CH-vsock reliability work is possible future work.

**2026-07-02 UPDATE — root cause found (AGENT-2).** The dominant cause was **not** environmental: it
was a PID-1 reaper race in the guest agent — `ReaperCoordinator::reserve()` running after the SIGCHLD
drain had already recorded a fast child's exit discarded that child's *own* status as "stale", parking
its waiter forever (host sees a 10 s exec timeout). Found while stabilizing the FC restore probe,
reproduced on pre-optimization code, fixed with an epoch-based `reserve(pid, epoch)` (red-checked).
Details: `docs/45-claude-perf-investigation.md` EXP-E #5; `docs/implementation-notes.md`. The retries
stay as defense-in-depth, but back-to-back suite runs should now flake far less.

## Experiments

### EXP-1 — Quieter guest kernel boot console (host cmdline; no rootfs rebuild) — KEEPER (as `loglevel=6`)

Change: CH + FC cmdline gain `loglevel=6 random.trust_cpu=on random.trust_bootloader=on`
(`vmm/cloud_hypervisor.rs:351`, `vmm/firecracker.rs:490`). The verbose printk to the byte-at-a-time
8250 UART is the single largest cold-boot tax; `loglevel=6` drops the `KERN_INFO` (6) probe flood
while keeping `NOTICE`/`WARN`/`ERR`.

| Metric | baseline | quiet loglevel=3 | **loglevel=6 (shipped)** |
| --- | --- | --- | --- |
| CH cold boot | 642 | 372 (−270) | **~415 est. isolated / 330 full-stack** |
| CH warm restore | 166 | 165 | ~0 (restore skips boot) |
| FC cold boot | 1019 | 835 (−184) | slightly higher |

**Correction:** the first attempt `quiet loglevel=3` (measured above) emptied the serial log — the
kernel banner "Linux version" (KERN_NOTICE 5) and everything ≥3 were suppressed, so `boot.rs`'s
`log_content.contains("Linux version")` assertion failed and `just test-privileged` regressed
(`boot::{cloud_hypervisor,firecracker}` fail; guests still booted — exec/snapshot/restore passed).
`loglevel=6` keeps the notice/warn/err lines (incl. the banner, oops, panic) so the serial log is
debuggable + panic-capturable, at ~43 ms cost vs `quiet`. Bug_risk resolved: **a too-quiet serial log
is itself a defect for a test framework** (no boot-failure diagnostics). Kept as `loglevel=6`.

### EXP-2 — Tighten host connect cadence (host-only; no rootfs rebuild) — KEEPER (small)

Change: `agent/mod.rs` backoff floor 50→20ms, cap 500→100ms, reset-to-floor once the UDS connects;
OK-read first-byte timeout 500→150ms. `cloud_hypervisor.rs` api-socket readiness poll 20→5ms.

| Metric | EXP-1 | EXP-2 | Δ |
| --- | --- | --- | --- |
| CH cold boot | 372 | **368** | −4 |
| CH warm restore | 165 | **159** | −6 |
| FC cold boot | 835 | 841 | +6 (noise) |

Phase-budget (p50): COLD connect 332 / teardown 528; RESTORE connect 113 / teardown 529.
Verdict: marginal — confirms the connect slack is GUEST-side (`ACCEPT_POLL`), not the host backoff,
on CH (UDS connects instantly). Kept for the worst-case robustness (bounded backoff + OK-read).

### EXP-4 — Guest accept cadence (rootfs rebuild): ACCEPT_POLL 100→20ms + REBIND_IDLE 1s→250ms

Stacks on EXP-1+EXP-2. `ACCEPT_POLL` is on the critical path (host waits for Ready between its OK
handshake and the guest's next `accept()`). `main.rs:375/377`. Rootfs rebuild = 41s.

| Metric | EXP-2 | EXP-4 | Δ |
| --- | --- | --- | --- |
| CH cold boot | 368 | **294** | −74 |
| CH warm restore | 159 | **88** | −71 (−45%) |
| FC cold boot | 841 | **757** | −84 |
| phase RESTORE connect | 113 | **29** | −84 |
| phase COLD connect | 332 | **255** | −77 |

Verdict: the biggest single win for restore (and a large cold-boot win). 70+ VM boots/restores in
the run all reached agent-ready + exec'd cleanly → the re-bind-after-restore + reconnect + resync
invariants still hold. Kept.

**Cumulative after EXP-1+2+4:** CH cold 642→294 (−54%), CH restore 166→88 (−47%), FC cold 1019→757.
Restore is now create-bound (51ms CH --restore+resume) > connect (29ms). Cold is guest-boot-bound.

### EXP-3 — Teardown: poll-for-exit + safe grace ceiling (host-only) — the "buggy-fast→correct-slow" teardown

`shutdown()` inserts a fixed `SHUTDOWN_GRACE=500ms` sleep (ORCH-7 added it for guest flush; the
comment defers a `try_wait` early-return as "out of scope"). Phase-budget teardown = ~529ms both
paths. Replace the fixed sleep with a poll for actual VMM exit, capped at a lower grace.

Change: new `VmInstance::has_exited()` (default `false`; CH/FC/QEMU do a non-blocking
`process.try_wait()`; fake returns `true`). `shutdown()` polls it every 20ms up to
`SHUTDOWN_GRACE`, now **250ms** (was 500). `orchestrator.rs:17,1056`, `vmm/mod.rs`, the 3 backends.

| Metric | before | EXP-3 | Δ |
| --- | --- | --- | --- |
| unit suite | — | 242 passed / 0 failed | green |
| CH teardown (phase) | 529 | **283** | −246 |
| CH cold / restore | 291 / 83 | 291 / 83 | unchanged |

Verdict: teardown halved. CH's process stays alive after `vm.shutdown` (has_exited never fires →
ceiling-bound at 250ms), so the win is the ceiling cut; the poll still helps FC/QEMU and realizes
ORCH-7's deferred design. Safe: ephemeral tmpfs/RO-erofs guests have no heavy flush; force-kill is
the guaranteed fallback; the fast `Drop` path (~27ms) is untouched. Kept. DEVIATION → impl-notes.
