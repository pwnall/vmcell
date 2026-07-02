# 45 — Performance investigation: post-knobs latency opportunities (2026-07-01)

> **Status: COMPLETE (2026-07-02).** All five experiments landed and validated: `just ci`
> green (incl. semver-checks + the 205-config feature powerset), privileged suite **59/59**,
> unprivileged **2/2**. Headline wins: **FC warm restore unlocked at 24 ms p50** (the fastest
> restore tier; was N/A), CH restore 66→58 ms, throughput-profile e2e CH restore 161→120 ms /
> CH cold 405→361 ms, QEMU cold 1003→965 ms with **zero** dropped iterations (the AGENT-2
> reaper-race fix — the real cause of the historical "Agent … timed out" flake). Final matrix:
> `docs/benchmark-results.md` "Post-investigation matrix".
> Baseline for this pass = the 2026-07-01 profile-matrix re-run in `docs/benchmark-results.md`
> (HEAD `37c5067`): CH cold 318 ms / restore 66 ms (default), 290 / 54 (low_latency);
> FC cold 778; QEMU cold 1003; e2e (phase-budget TOTAL) CH 604/405 ms cold default/throughput,
> CH restore 359/161 ms; FC 1063/860; QEMU 1311/~1100.

Maintainer ask: re-run the benchmarks, then find and try improvements — particularly
**time-to-ready (resume + fresh boot) across all backends under the latency-tuned knobs**, and
**end-to-end latency across all backends under the throughput-tuned knobs**.

## Method

Multi-agent sweep over the design + codebase (8 read-only subsystem analysts: host-create path,
guest kernel boot, guest-agent init, host connect loop, restore path, teardown/e2e, FC/QEMU
backends, docs miner) → 59 raw suggestions → deduplicated to 18 → **each adversarially vetted**
(evidence re-read at the cited lines; cross-checked against `perf-experiments-log.md`,
`implementation-notes.md`, `44-claude-perf-config-design.md`, AGENTS.md contracts; win estimates
re-derived against the measured phase budgets). Verdicts: **4 pursue, 2 defer, 12 reject**.
The reject list is kept below — several plausible-sounding levers are mechanically refuted, and
that knowledge is worth not re-deriving.

## Opportunities pursued (experiments)

### EXP-A (OPP-1) — Unify the two hardcoded 20 ms readiness polls onto `timeouts.api_socket_poll`

- **What:** `qemu.rs:278` (vhost-device-vsock daemon socket wait) and `firecracker.rs:321`
  (T2 CPU-template probe socket wait) still poll at a literal 20 ms while every other readiness
  wait uses the profile-tuned `cfg.timeouts.api_socket_poll` (5 ms default / 2 ms low_latency).
  Design 44 §7 explicitly parked this divergence as "a cleanup, noted for later".
- **Mechanism:** removes ~7–8 ms of mean poll quantization per affected wait; makes the
  `low_latency` profile apply uniformly.
- **Expected:** QEMU cold create −5…15 ms (per VM); FC first-VM-per-process only (T2 probe is
  OnceLock-cached) — a uniformity cleanup there, not a p50 mover. No effect on CH.
- **Risk:** negligible (cadence within the existing 1 ms floor; fail-fast on early process exit
  unchanged). Hardening rider: clamp `interval_ms >= 1` inside `wait_for_socket` (pre-existing
  div-by-zero exposure via the pub `timeouts` field).
- **Measure:** QEMU phase-budget create-phase p50 (not total p50 — ~1% of a guest-boot-bound
  1003 ms path, and QEMU carries the known flake noise).

### EXP-B (OPP-3) — Kernel cmdline boot-probe trims (per-flag A/B): `i8042.nokbd i8042.noaux`, `pci=lastbus=0`, `tsc=reliable`

- **What:** skip boot-time probing that is dead work in a microVM. All flags go through the
  single shared `build_kernel_cmdline` (config.rs) → one-line, individually revertible A/Bs.
- **Vet corrections:** `no_timer_check` is auto-set under `CONFIG_KVM_GUEST=y` — guaranteed
  no-op, dropped. kvmclock already supplies the TSC frequency, so `tsc=reliable` likely ~0 and
  carries clock-watchdog risk — last, only if step 0 shows calibration cost. Step 0 = one
  verbose boot; `CONFIG_PRINTK_TIME=y` timestamps show which probes actually cost anything.
- **Expected (revised down by the vet):** 0–10 ms combined on the ~280 ms guest-boot-bound
  connect phase; led by the i8042 pair.
- **Risk:** `tsc=reliable` → validate M-RESTORE-1 clock resync; `pci=lastbus=0` CH/QEMU-only via
  `backend_extra` (FC is MMIO), must keep every virtio device enumerating (all on bus 0 today).
  No loglevel change → panic capture + "Linux version" banner unaffected.

### EXP-C (OPP-2) — Event-driven guest accept: poll(2) on the vsock listener instead of the sleep loop

- **What:** `serve_vsock` (guest agent `main.rs:486-511`) does non-blocking `accept` →
  `WouldBlock` → `sleep(accept_poll)` (20 ms default / 5 ms low_latency). A host connection
  landing mid-sleep pays a mean ~half-interval on **every** connect (cold and restore).
  Replace the sleep with a blocking `poll(POLLIN)` on the listener fd, timeout = remaining
  rebind-idle window → sub-millisecond wake on connection arrival.
- **Why credible:** same mechanism EXP-4 already proved (accept cadence 100→20 ms bought
  −74 ms cold / −71 ms restore); this removes the residual quantization *and* makes connect
  latency independent of the `guest_accept_poll` knob. Bonus: ~50 idle wakeups/s per idle
  guest (default profile) drop to ~4 — the dense-farm wakeup cost design 44 worried about.
- **Invariants preserved:** re-bind-after-restore via an Instant-based deadline (poll timeout =
  remaining window; timeout/POLLERR/HUP/poll-error → re-bind); EINTR re-polls with recomputed
  remaining (PID 1 takes SIGCHLD); spurious POLLIN must **not** reset the deadline; the
  `parse_ms` floor stays load-bearing on the bind-retry path. Lean-agent gate: rustix/libc
  already prod deps.
- **Expected:** cold connect −5…10 ms p50 (all backends), restore connect −2…8 ms; p95
  tightening larger. Rootfs rebuild (~41 s).

### EXP-D (OPP-5) — Teardown grace tuning: adaptive `has_exited` cadence + deadline placement

- **What:** `shutdown()` (orchestrator.rs:1043-1058) computes the grace deadline **after** the
  shutdown RPC returns and polls `has_exited` at a hardcoded 20 ms. With `throughput` grace
  = 50 ms the 20 ms grid exits at ~60 ms (~10 ms overshoot even when ceiling-bound), and FC —
  whose process genuinely exits in-window — pays up to 20 ms detection quantization.
- **Change:** deadline computed before the RPC, clamped post-RPC to ≥ now + one poll step
  (a stalled RPC must still yield ≥1 `has_exited` check — the ORCH-7 flush grace); poll step
  derived from the grace: ≤50 ms → 5 ms, ≤150 ms → 10 ms, else 20 ms (recordable deviation
  from design 44's "poll step stays 20 ms"; 10 wakeups in a 50 ms window is not a busy-spin).
- **Expected:** −5…15 ms on the 96 ms throughput-profile graceful teardown, all backends.
- **Tests:** driven-FakeVmm units — slow-RPC still gets a post-ack poll (RED on naive pre-RPC
  deadline); grace=50 exits by ~50 not ~60 ms (RED on fixed 20 ms step); ORCH-2/7 order test
  unchanged.

### EXP-E (OPP-18 probe) — Firecracker warm restore: re-validate the guest re-attach, flip the capability if green

- **What:** FC `snapshot_restore` is honestly `false` (E2: first post-restore exec dropped —
  guest vsock listener didn't re-attach). But `snapshot()`/`restore()` + the host-paths sidecar
  + the matrix test **already exist**; the guest rebind loop is now generic, faster
  (REBIND_IDLE 250 ms), cmdline-tunable, and the resync is native — **none of which existed
  when E2 was recorded**. The failure has never been re-tested since.
- **Why now:** the maintainer asked for *resume latency across all backends*; FC restore is the
  only missing row, and historical measurements (~128–138 ms, taken with the capability off)
  predate the accept-poll + native-resync wins — it should land well under that.
- **Probe:** locally flip `fc_capabilities().snapshot_restore` + invert the honesty test; run
  `snapshot_restore::firecracker` 3× isolated + once under suite load; if green, benchmark
  FC restore (default + low_latency) and keep the flip (with design §3.3/§16 + docs updates).
  If exec still drops: capture serial + agent logs, revert, record the FC-specific gap here.
- **UFFD lazy restore stays deferred** (new feature wiring — a userfaultfd page-server).

## Deferred (real, not now)

- **OPP-10 — parallelize virtiofsd share startup.** Sequential per-share loop is real
  (cloud_hypervisor.rs:392-402, qemu.rs:294-298), but: `try_join_all` is cancellation-unsafe
  (a dropped `VirtioFsDaemon::start` future between spawn and construction leaks the daemon
  process group — violates "ownership owns cleanup"); the win is invisible on every tracked
  benchmark (zero-share configs; snapshot tier is share-free by law); measuring needs new
  bench wiring (`--shares N`). The dominating cheap lever if shares matter later: the 20 ms
  socket poll in fs.rs:140-163 → 2–5 ms. Revisit with a `join_all`+owner-push design and a
  failure-injection zero-leak test that goes red on the `try_join_all` variant.
- **OPP-18b — FC UFFD lazy restore** (`backend_type: Uffd` + page-server process): separate
  design pass; only after the EXP-E flip stabilizes.

## Rejected (vetted and refuted — don't re-derive)

| # | Suggestion | Why rejected |
| --- | --- | --- |
| OPP-4 | Overlap prev-VM teardown with next-VM create in the bench harness | Accrues to no reported metric (latency samples exclude teardown; phase budgets don't shrink) and pipelining corrupts the harness's per-iteration isolation. A *library* affordance would be a feature, not a bench fix. |
| OPP-6 | inotify/event-driven host socket readiness | Misdiagnosis: EXP-2 already measured the host-side waits at −4/−6 ms total; the CH UDS connects instantly — the wait is guest-side. Ceiling ~0–2.5 ms, below the ±6 ms noise band. |
| OPP-7 | CH graceful shutdown via ACPI power-button | Statically refuted: the guest has no ACPI-button handler (PID-1 agent, no acpid; kernel button driver not wired to power off this init). CH stays ceiling-bound either way. A guest-agent vsock "shutdown" verb would be the real variant — separate feature. |
| OPP-8 | Kernel config trims (balloon off, ext4 off) | No balloon device is ever attached (registration ≈ µs, not a probe); ext4 is a used block-fallback tier. 0–2 ms, below the kernel-sweep noise floor. |
| OPP-9 | Defer agent optional init off the pre-listener path | ~1–3 ms cold only; exactly 0 on restore (agent `main()` doesn't run on restore — the snapshot resumes a running agent). Below noise. |
| OPP-11 | Background FC T2 probe at construction | Unimplementable as titled (probe needs `cfg.kernel`); OnceLock-cached → invisible in every canonical metric (warmup ≥ 1). |
| OPP-12 | `mitigations=off` opt-in lever | Host CPU is "Not affected" for the expensive mitigations and exposes that via ARCH_CAPABILITIES → guest already skips KPTI/VERW. ~0–3 ms here; risk without win. |
| OPP-13 | Parallelize setup_env legs (netns ∥ cgroup) | bench-vm runs `network_disabled()` → nothing to overlap; privileged-net upper bound ~0.5 ms. |
| OPP-14 | Batch rtnetlink round-trips in setup_tap | Same: network-disabled benches can't see it; ~0.5–1 ms on tap configs. |
| OPP-15 | Overlap vhost-vsock daemon start with QEMU spawn | Win double-counted with EXP-A; residual overlap ~2–8 ms, below QEMU's flake noise floor. |
| OPP-16 | Batch OK-line read + tighten low_latency backoff floors | Premise fabricated (floor rationale is idle-wakeup cost, not the byte read); ~1–1.5 ms, unmeasurable. |
| OPP-17 | Persistent QMP connection | Cold path issues exactly one QMP command (`cont`) — a cached connection saves ~0; ≤1–3 ms e2e. |

## Results

*(deltas are p50 vs the profile-matrix baseline above)*

| Experiment | Status | Result |
| --- | --- | --- |
| EXP-A readiness-poll unification | **KEEPER** | QEMU create phase **140→124 ms (−17)** (throughput-profile phase budget, n=14; the vhost-vsock daemon wait dominates the win). FC T2 probe: uniformity only (OnceLock-cached), as predicted. |
| EXP-B cmdline probe trims | **KEEPER (marginal)** | CH cold 318→312 (−6), FC cold 774 (−4): consistent direction, but at the ±6 ms noise floor — the step-0 probe (debug verbosity) overstated the production-loglevel win. Kept: zero-risk, mechanism directly evidenced by printk timestamps. |
| EXP-C event-driven guest accept | **KEEPER** | **CH restore connect phase 16.6→4.6 ms p50 (−72%)**; restore time-to-ready 66→**55 ms**, and the default profile now ties low-latency on restore (54 ms) — the `guest_accept_poll` knob no longer gates connect, as designed. Cold connect (phase budget) 280→266 ms; latency-mode cold within noise; FC cold flat (boot-bound). Also removes ~46 idle wakeups/s per idle guest. |
| EXP-D teardown grace tuning | **KEEPER (exceeded estimate)** | Throughput-profile graceful teardown: CH **95→56 ms**, FC 90→78, QEMU 106→92. **CH restore e2e 161→120 ms (−25%)**; CH cold e2e 405→361. Default profile also gains ~20 ms (285→265) from the deadline-before-RPC fix alone. The win beyond the predicted 5–15 ms is the RPC round-trip now spending the grace instead of extending it. |
| EXP-E FC restore probe | **KEEPER — capability unlocked** | `snapshot_restore::firecracker` passes **3/3 isolated, retries=0** (plus a 10/10 diagnostic loop); CH regression green. FC `snapshot_restore` now `true`. **FC warm restore: 24 ms p50 default / 23 ms low-latency (p95 33/28) — the fastest restore tier, beating CH's 58 ms**; FC restore e2e (throughput) **64 ms**. Bonus from the AGENT-2 reaper fix: QEMU latency runs now keep **20/20 iterations** (were 16–17/20) and QEMU cold improved to 965 ms p50. |

### EXP-E narrative — what was actually broken (none of it was the guest re-attach)

The historical E2 note blamed the guest vsock listener. Probing at HEAD found the guest side
fine (the generic re-bind + native resync cured it long ago) and instead surfaced, in sequence:

1. **Host cached-client bug (all backends, FC-visible).** `MicroVm::snapshot()` left the cached
   `agent_client` in place; FC severs established vsock connections across its
   pause/snapshot/resume cycle (CH keeps them), so the base VM's next exec died with
   `Connection dropped during exec` — block 1 of the test, before restore ever ran. Fix:
   the first-class `snapshot()` verb self-guards by invalidating the cache (one cheap
   reconnect; red-checked unit tests for both Ok and Err paths); all call sites migrated off
   `instance_mut().snapshot()`.
2. **Verbatim-rebind ENOENT.** FC's `PUT /snapshot/load` re-binds the snapshot's baked host
   vsock UDS path *verbatim* (no load-time override exists in v1.16); the ancestor VM's scratch
   dir was gone → `Load snapshot error … binding … No such file or directory`. Fix: `restore()`
   recreates the baked path's parent; the restored instance's `Drop` removes the resurrected
   dir; plus a **fail-loud liveness guard** (`reject_live_baked_vsock`): if a live listener
   still answers on the baked path (the snapshotted VM or a prior restore of the lineage),
   restore is rejected with a typed error instead of silently unlinking a live VM's transport.
3. **CH-shaped test assertions.** The matrix test asserted vsock-path rotation — a CH restore
   config-rewrite behavior FC cannot implement. Encoded honestly as a new capability
   `VmmCapabilities::restore_rotates_host_paths` (CH `true`, FC `false`, QEMU `false`); the
   test branches on it (FC asserts the real contract: verbatim path, functional reconnect).
   Consequence documented: an FC snapshot lineage is **single-use-at-a-time** (no concurrent
   restores of one lineage; restore-while-ancestor-alive rejected) — the §16
   single-snapshot-CoW gap already covers the multi-clone story for both backends.
4. **FC had no entropy device** — `reseed_applied` came back `false` (no `/dev/hwrng`). Fix:
   `create()` now attaches virtio-rng via `PUT /entropy`.
5. **AGENT-2: the "environmental" flake was a real PID-1 reaper race.** With 1–4 fixed, the
   probe still flaked ~30–40% with 10 s exec timeouts — reproduced on *pre-existing* code, so
   not introduced by this pass. Guest kernel-stack capture during a wedge proved it: the
   child had been reaped, but `ReaperCoordinator::reserve()` ran after the SIGCHLD drain had
   already recorded the fast child's exit and discarded the child's own status as "stale" —
   the waiter parked forever and the host timed out. Fix: `pre_spawn_epoch()` captured before
   `spawn`; `reserve(pid, epoch)` only discards statuses recorded ≤ epoch (red-checked; the
   residual µs window is documented). **This likely explains the historical full-suite
   "Agent … timed out" flake that `nextest retries` papered over** — the retries stay (other
   environmental factors remain), but the dominant cause is gone.

**EXP-B step-0 probe notes (why the original flags died):** one debug-verbosity CH boot with
printk timestamps showed `i8042.nokbd/noaux` targets a probe that never runs (single instant
"PNP: No PS/2 controller found" line), `pci=lastbus=0` targets a beyond-bus-0 scan that doesn't
exist (ACPI/ECAM already constrains to bus 0), and `tsc=reliable` targets calibration kvm-clock
already skips ("Calibrating delay loop (skipped)"). The probe instead surfaced the two flags
actually shipped: `cryptomgr.notests` (~9.7 ms silent gap at the crypto/keyring initcalls) and
`raid=noautodetect` (~2 ms md autodetect scan). Also noted for later: a ~22 ms unattributed
fs_initcall-region gap (worth an `initcall_debug` probe someday) and a ~5.7 ms cfg80211
regulatory.db double firmware-load failure (kernel-config-trim territory, not cmdline).
