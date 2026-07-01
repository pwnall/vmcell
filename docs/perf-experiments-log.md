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
