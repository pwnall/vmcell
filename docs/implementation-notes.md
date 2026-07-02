# Implementation Notes

This is the running log of **justified deviations** from the design (per `AGENTS.md`): a place to
record a deliberate divergence, with its reason, at the moment it is made.

**The log is currently empty.** As of the v17 design rewrite (`docs/43-claude-design-v17.md`) every
prior entry has been reconciled into the design document — either folded into the body as the settled,
present-tense state of the system, or dropped as superseded / dated validation bookkeeping. The design
document now reflects the system *as built*, including the deviations that used to live here (for
example: the Firecracker snapshot/restore honest gate-off, the `ResourceUsage` net-counter omission,
the stringly per-subsystem `Error` payloads, the static-glibc guest agent, the `SUDO_UID`-not-`nobody`
virtiofsd choice, and the file-cap runner's inability to shrink its bounding set). See design §12
("The subtle parts") for the cross-cutting invariants and §15 ("Open decisions and known gaps") for
what remains forward work.

**When you make a new deviation,** add a short entry here — *what* you diverged from and *why* — and,
once it stabilizes, fold it into the design document and delete it from this log. Keep this file
small: a growing log means the design doc has drifted from the code.

---

## Performance pass (2026-07-01): cold-boot / restore latency recovery

Context: the correct-but-slower code (vs the earlier buggy-fast versions) carried recoverable latency
in a handful of conservative constants and one always-on grace sleep. This pass recovered it **without
relaxing an invariant** — every change preserves fail-loud, the desync flag, the mandatory post-restore
clock resync, the re-bind-after-restore behaviour, and ordered teardown. Full measured deltas live in
`docs/perf-experiments-log.md`; the settled numbers are folded into design §15 / `benchmark-results.md`.
The deliberate divergences worth flagging:

- **Guest kernel cmdline gained `loglevel=6 random.trust_cpu=on random.trust_bootloader=on`**
  (`vmm/cloud_hypervisor.rs`, `vmm/firecracker.rs`; design §8.3). *Why:* full-verbosity printk to the
  byte-at-a-time 8250 UART cost ~270 ms of CH cold boot (~180 ms FC). `loglevel=6` drops the
  `KERN_INFO` device-probe flood (the bulk of that cost) while keeping `NOTICE`/`WARN`/`ERR` — so the
  serial log stays **debuggable** and non-empty (an empty log broke the `boot.rs` "Linux version"
  assertion and would blind a boot-failure post-mortem) and panic capture is unaffected
  (`contains_panic` matches KERN_EMERG `"Kernel panic"`). A first attempt at `quiet loglevel=3` emptied
  the serial log — recoverable-but-too-aggressive; `loglevel=6` keeps all but ~43 ms of the win.
- **`shutdown()` no longer *always* sleeps the full grace; `SHUTDOWN_GRACE` 500 ms → 250 ms.** A new
  `VmInstance::has_exited()` (defaulted `false`; the three real backends do a non-blocking
  `process.try_wait()`) lets `shutdown()` return as soon as the guest actually powers off, capping at
  the grace — the `try_wait` early-return ORCH-7 explicitly deferred. The ceiling drop to 250 ms is the
  deliberate part: the guest SIGTERM handler is `sync()`+`reboot(RB_POWER_OFF)` over a tmpfs overlay +
  RO erofs root (no heavy writeback), so 250 ms is ample flush headroom and the force-kill stays the
  guaranteed fallback. The fast `Drop` teardown (~27 ms) is untouched. **Public-API note:** the
  defaulted `has_exited` is a non-breaking addition to the `VmInstance` trait (expect `cargo
  semver-checks` to report a minor addition).
- **Poll cadences tightened** (pure constants, no invariant): host connect backoff floor 50→20 ms /
  cap 500→100 ms + reset-to-floor once the UDS connects, and the OK-line read timeout 500→150 ms
  (`agent/mod.rs`); the CH api-socket readiness poll 20→5 ms (`vmm/cloud_hypervisor.rs`); and, in the
  guest agent, the accept-loop `ACCEPT_POLL` 100→20 ms and `REBIND_IDLE` 1 s→250 ms
  (`vmcell-guest-agent/src/main.rs`). `ACCEPT_POLL` was the dominant restore-reconnect cost (the host
  blocks for `Ready` between its completed CONNECT/OK handshake and the guest's next `accept()`); the
  smaller `REBIND_IDLE` only tightens the worst-case post-restore deaf window (re-binding is harmless
  during normal operation — accepted connections keep their own fds).

## Tunable config knobs + native resync (2026-07-01, design `docs/44-...`)

Follow-up making the above tunable and eliminating the last restore subprocess cost. No invariant
relaxed; every added knob clamps to a correctness floor; the M-RESTORE-1 fail-loud contract is intact.

- **`KernelVerbosity` knob + shared cmdline builder.** `VmConfig.kernel_verbosity`
  (Quiet/Balanced/Verbose/Debug → `loglevel=3/6/7/8`, default Balanced) replaces the hard-coded
  `loglevel=6`; the cmdline is now built once in `config::build_kernel_cmdline` shared by all 3
  backends. *Why:* the cmdline was triplicated and **QEMU's inline copy omitted `loglevel=` entirely**
  (paying the full 8250-UART VM-exit tax); centralizing fixed that — QEMU cold **~1400→996 ms**.
  Measured VM-exit cost of logging: CH cold `verbose` 561 vs `balanced` 330 = **+231 ms** (answers the
  "does logging cause VM exits" question — yes; `perf kvm stat` is blocked by `perf_event_paranoid=4`
  here, so the A/B is the evidence). `boot.rs` asserts the `"Linux version"` NOTICE banner, which
  prints at `Balanced`+.
- **`Timeouts` struct + presets.** All per-VM hot-path timings (connect backoff floor/cap, OK-read,
  api-socket poll, shutdown grace, guest accept/rebind polls) in one `Timeouts` on `VmConfig`, with
  `low_latency()` (tightens connect/accept, leaves teardown graceful) and `throughput()` (cuts
  `shutdown_grace` 250→50 ms) presets. Guest-side polls are emitted as `vmcell_accept_poll_ms=` /
  `vmcell_rebind_idle_ms=` cmdline tokens the agent parses (clamped) — so a preset tunes the guest with
  **no rootfs rebuild**. Measured: `throughput` teardown 283→**96 ms**; `low_latency` cold 327→**309 ms**.
- **Native in-agent resync** (replaces 3 post-restore subprocess execs). New `#[non_exhaustive]`
  protocol `Message::Resync { unix_secs, unix_nanos, mac }` + `Message::ResyncAck { clock_error,
  reseed_applied, mac_applied }`. The agent applies them natively: clock via
  `rustix::time::clock_settime` (added rustix `time` feature), RNG via a pure-`std::io` 32-byte
  `/dev/hwrng`→`/dev/urandom` copy, MAC via a `SIOCSIFHWADDR` ioctl in a new `netif` module in the
  **lean** `vmcell-guest-agent` lib (reusing the guest-tools logic — the lean-agent CI gate confirms no
  reqwest/tokio/hyper leaks in). The orchestrator's `maybe_resync_after_restore` sends one `resync`
  round-trip; `clock_error.is_some()` → typed `Err` **before** clearing `restored` (mandatory clock
  fail-loud, identical to the old non-zero-`date`-exit semantics); RNG/MAC best-effort with the ack
  reporting each. *Why worth the complexity (maintainer's trade):* removes 3 guest fork/execs incl. the
  **multi-MB reqwest-linked `ip` binary** page-in from the restore hot path — CH restore **84→60 ms**
  (restore `connect` phase 36→16 ms) — matched by new unit + integration coverage (protocol round-trip,
  framing, `parse_ms` clamp, ifreq layout, clock mapping, the 4 M-RESTORE-1 fail-loud tests, and the
  `snapshot_restore` integration asserting the native MAC/clock/reseed). **Public-API:** the two
  protocol variants + `AgentClient::resync`/`ResyncOutcome` + `KernelVerbosity`/`Timeouts` are additive
  (`cargo semver-checks` minor).
- **`ConsoleMode` knob (virtio-console vs UART).** `VmConfig.console_mode` (default `Uart`=`ttyS0`;
  opt-in `VirtioConsole`=`hvc0`) drives the cmdline `console=` token **and** the per-backend device
  wiring from one field (they can't desync). CH wires `console:{mode:File}` / QEMU wires
  `virtio-serial-pci`+`virtconsole`; the CH restore config-rewrite moves `console.file` in lockstep with
  `serial.file`. Capability `VmmCapabilities.virtio_console` (CH/QEMU true, **Firecracker false** →
  `VirtioConsole` rejected loud+early via `reject_unsupported_console` before the cmdline is built).
  Default is `Uart` because virtio-console (`hvc0`) exists only after virtio-pci probe → early-boot +
  pre-virtio **panic capture** (§12.10) is lost — a correctness floor kept safe-by-default; virtio is
  opt-in for guest-code tests. *Why:* UART is a per-byte PIO VM-exit; virtio-console batches it, so a
  test can run **verbose** kernel logging at ~the balanced-UART cost — **CH cold 558→299 ms (−46%)** with
  full logs (§15). Host-side only (guest kernel already has `CONFIG_VIRTIO_CONSOLE=y`); no rootfs rebuild.
- **Flake mitigation (not a code change to the product): `nextest retries` + `kind(test)` scoping.** The
  full privileged suite intermittently hit an environmental CH-vsock control-connection reset (`Agent …
  timed out`); bisected to the pre-optimization baseline (it flakes there too — not a regression). Fix:
  `retries={backoff=exponential,count=3,delay=5s,max-delay=20s}` on the integration profile (a fresh-VM
  retry sidesteps the transient reset; a real break still fails all attempts) + `-E 'kind(test)'` on the
  suites (keeps the ~172 lib unit tests off the VM suite — they run in `test-unit`). Detail:
  `docs/perf-experiments-log.md` "Flake investigation".
- **`shutdown()` grace poll step is adaptive, not the fixed 20 ms (2026-07-02, EXP-D/OPP-5 of
  `docs/45-claude-perf-investigation.md`).** Deliberate deviation from design 44's "the poll step stays
  20 ms" note: the `has_exited` cadence now derives from the configured grace (<= 50 ms → 5 ms,
  <= 150 ms → 10 ms, else 20 ms; the 5 ms floor is at most ~10 wakeups in a 50 ms window — not a
  busy-spin). *Why:* the `throughput` preset's 50 ms grace on a 20 ms grid exits at ~60 ms even when
  ceiling-bound, and an in-window guest exit pays up to 20 ms detection quantization. The same pass
  fixes deadline placement: the grace deadline is computed **before** `request_shutdown` (the RPC's
  round trip no longer silently extends the window) and clamped post-ack to >= one poll step — the RPC
  has no timeout (`vmm::unix_api_request`), so a stalled RPC would otherwise skip the poll loop and
  grant ~0 post-ack flush, the anti-pattern ORCH-7 exists to prevent. Pinned by new orchestrator unit
  tests (stalled-RPC still gets a post-ack poll; 50 ms grace returns in [50, 60) ms on a 5 ms step;
  ORCH-2/7 teardown-order test untouched).
- **Guest accept loop is event-driven, not a sleep loop (2026-07-02, EXP-C/OPP-2 of `docs/45-...`).**
  `serve_vsock` no longer does `accept` → `WouldBlock` → `sleep(accept_poll)` (a mean ~half-interval of
  added latency on every connect, cold and restore); it blocks in `poll(2)` on the listener fd for
  `POLLIN` with the **remaining re-bind idle window** as the timeout (rustix `event` feature on the
  existing dep — no new crate, lean-agent gate green), so a host connection wakes the agent
  sub-millisecond. The §9.2/§12.4 re-bind-after-restore semantics are **unchanged**: the idle window is
  a bounded, `Instant`-based deadline (`last accept or (re)bind + rebind_idle`); only a *real* accept
  restarts it — an `EINTR`'d poll (PID 1 takes SIGCHLD; poll is never auto-restarted) and a spurious
  `POLLIN`→`WouldBlock` wakeup re-poll with the recomputed remainder and do **not** reset the deadline,
  so a deaf post-restore listener still runs out the clock and re-binds. `POLLERR`/`POLLHUP`/`POLLNVAL`
  and non-`EINTR` poll errors are logged and treated as the deaf-listener case (re-bind, never exit).
  **Semantic change:** `Timeouts::guest_accept_poll` / `vmcell_accept_poll_ms` now paces only the
  bind-failure retry; its `parse_ms` 1 ms floor stays load-bearing there, and the poll timeout carries
  its own 1 ms floor (a sub-ms remainder must not truncate to a busy-spinning 0). Pinned by unit tests
  on the extracted pure policy (`next_deadline`/`remaining_idle`/`poll_timeout_ms`): each verified RED
  on its inverse (deadline reset on spurious wakeup / `Some(ZERO)` at the deadline / a dropped 1 ms
  floor).
- **The two residual hardcoded 20 ms readiness polls now use `timeouts.api_socket_poll` (2026-07-02,
  EXP-A/OPP-1 of `docs/45-...`).** The QEMU vhost-device-vsock daemon wait (`qemu.rs`) and the FC T2
  CPU-template probe wait (`firecracker.rs`) were the last `wait_for_socket` call sites on a literal
  20 ms while every sibling used the profile-tuned `api_socket_poll` (5 ms default / 2 ms low-latency)
  — the cadence divergence design 44 §7 parked as "a cleanup, noted for later". Pure cadence change
  within the existing 1 ms floor; fail-fast-on-early-exit unchanged. `wait_for_socket` also clamps its
  interval to >= 1 ms (the interval arrives via the pub `VmConfig.timeouts` field — a 0 would have
  divided by zero; pinned by a red-on-inverse unit test). Measured: QEMU cold create 140→124 ms p50.
- **Guest cmdline gained `cryptomgr.notests raid=noautodetect` (2026-07-02, EXP-B/OPP-3 of
  `docs/45-...`).** Chosen by a printk-timestamp probe (one debug-verbosity boot), which *disqualified*
  the fashionable microVM trims — `i8042.nokbd/noaux` (no PS/2 probe runs in this guest),
  `pci=lastbus=0` (ACPI/ECAM already stops at bus 0), `tsc=reliable` (kvm-clock already skips
  calibration) — and instead surfaced the built-in crypto self-tests (~10 ms) and the md RAID
  autodetect scan (~2 ms) as the only real cmdline-trimmable boot work. Self-tests are a boot-time QA
  pass, not a runtime dependency; no RAID device can exist. Measured: CH cold −6 ms / FC −4 ms p50 —
  at the noise floor, kept for the consistent cross-backend direction at zero risk. Cmdline-builder
  unit test pins both tokens.
- **Firecracker warm restore wired end-to-end: `snapshot_restore` flipped `true` (2026-07-02;
  deliberate deviation from design v17 §3.2/§3.3/§16, which record FC as gated off).** The historical
  E2 symptom — the first post-restore `exec` dropping — is cured by the guest agent's *generic*
  re-bind-after-restore loop plus two host-side fixes: (1) `MicroVm::snapshot()` invalidates the cached
  `AgentClient` after a successful backend snapshot (FC severs established vsock connections across its
  pause/snapshot/resume; CH keeps them alive — invalidating uniformly costs at most one cheap
  reconnect), and (2) FC `restore()` re-creates the baked vsock path's parent dir before
  `PUT /snapshot/load` (FC re-binds the snapshot's recorded host UDS path **verbatim** — no load-time
  override exists in v1.16 — and the ancestor VM's scratch dir is gone by then; `FcInstance::Drop`
  removes the resurrected dir). The verbatim re-bind is now a declared contract: new capability field
  `VmmCapabilities.restore_rotates_host_paths` (CH `true` via its restore config-rewrite, FC/QEMU
  `false`), consumed by the `snapshot_restore` integration test to assert each backend's REAL
  semantics — path rotation + rotated-vmid embedding on CH, path *equality* on FC — instead of
  encoding CH semantics for everyone. Consequence of `false`: a lineage's restores share one host
  vsock path, so FC `restore()` gained a fail-loud liveness guard (`reject_live_baked_vsock`: a
  100 ms `UnixStream::connect` probe; a live listener → typed `Error::Vmm` "still in use" instead of
  silently unlinking a live VM's socket; stale file → removed; missing parent → re-created; TOCTOU
  documented as a misuse guard, not a security boundary), and concurrent restores from one lineage
  stay unsupported (subsumed by the §16 single-snapshot-CoW gap). FC `create()` also now attaches the
  **entropy device** (virtio-rng → guest `/dev/hwrng`): CH always carries an rng device, but without
  the explicit `PUT /entropy` the FC guest has no hwrng, the post-restore reseed reports
  `reseed_applied: false`, and the restored VM replays frozen CSPRNG state. Validated on this KVM
  host: `snapshot_restore::firecracker` 10/10 in a diagnostic loop + 1+3/3 official runs, and
  `snapshot_restore::cloud_hypervisor` green (no CH regression from the shared test edits). Unit
  coverage: liveness-guard trio (live listener → typed Err, verified red on a probe-skipping guard;
  stale → cleared; missing → parent resurrected) and capability-honesty pins (FC
  `restore_rotates_host_paths=false`, CH `true`).
- **PID-1 reaper: reservation epoch is captured PRE-spawn (AGENT-2, 2026-07-02).** Root cause of the
  long-standing sporadic 10 s `Agent exec timed out` (~30% of `snapshot_restore::firecracker` runs
  once the rotation asserts stopped masking it; also the likely mechanism behind the historical
  CH-suite "environmental" flake that `nextest retries` papered over): an instant child (`head -c 32
  /dev/urandom` ≈ 1 ms) exits and is drained by the PID-1 reaper *between* `spawn` and
  `reaper.reserve(pid)` — on a 1-vcpu guest the child often runs to completion before the exec thread
  is rescheduled — and the old `reserve` unconditionally wiped any pre-existing status for the pid,
  including the child's OWN, stranding the waiter on the condvar forever (guest kernel stacks captured
  during a wedge confirmed: child reaped and gone, waiter futex-parked). Fix: `ReaperCoordinator::
  pre_spawn_epoch()` is captured before `Command::spawn`; `reserve(pid, epoch)` now discards only a
  status recorded **at or before** that epoch (a genuine previous occupant of the reused pid — its
  zombie was necessarily reaped-and-recorded, atomically under the drain lock, before the kernel could
  reuse the pid) and keeps a post-epoch status as the child's own for immediate delivery. Residual
  window recorded honestly in the doc-comment: a grandchild status recorded between epoch capture and
  the fork whose pid is instantly recycled to the new child would still be misattributed — that needs
  a full pid-space wrap inside a microseconds window. Pinned by
  `reserve_after_fast_child_already_drained_delivers_status` (verified red on the pre-fix wipe); the
  existing reuse/atomicity tests updated to the epoch API keep the stale-status guarantees green.
  Agent change ⇒ rootfs rebuilt (the closure hash folds agent sources).
