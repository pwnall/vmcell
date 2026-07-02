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
