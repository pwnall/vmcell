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
