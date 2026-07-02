# 44 — Tunable performance config + native in-agent resync (design)

Design for two maintainer-requested follow-ups to the 2026-07-01 latency pass (§15 /
`benchmark-results.md`):

1. **More configuration knobs** — the pass hard-coded perf-optimal constants (`loglevel=6`,
   `ACCEPT_POLL=20 ms`, `SHUTDOWN_GRACE=250 ms`, …). Different workloads want different points:
   debugging wants a verbose kernel log; a test farm wants throughput (fast whole-lifecycle);
   an interactive/latency-sensitive caller wants minimal time-to-output. So: make the kernel log
   level a per-VM knob, and gather **all timeouts into one struct** with two ready-made presets —
   one that optimizes **throughput** and one that optimizes **output latency (excluding teardown)**.
2. **Native in-agent resync** — replace the 3 post-restore subprocess spawns (`date` / `sh`+`head` /
   the multi-MB `ip`) with in-agent syscalls behind a protocol message. Worth the added complexity
   *because it is matched by added test coverage* (the maintainer's explicit trade).

Guiding principle unchanged: **recover latency without relaxing an invariant**, and every new knob
has a correctness floor so a bad value cannot wedge or busy-spin.

---

## 1. Kernel logging is a knob — and yes, it causes VM exits

**Finding (answers the maintainer's question).** Kernel serial logging **does** cause VM exits, and
it was the single largest cold-boot tax. All three backends select the legacy **8250/`ttyS0` UART**
(`console=ttyS0`) and sink its bytes to a per-VM `serial.log`. The 8250 is a legacy **PIO** device:
the guest writes each console byte to the THR I/O port (0x3F8), and **every such write VM-exits**
(`IO_INSTRUCTION`) to the VMM, which formats and appends to the log. Verbose boot = hundreds of
`KERN_INFO` device-probe lines × ~80 bytes × one exit per byte → the ~270 ms we removed with
`loglevel=6` (which drops the `KERN_INFO` flood while keeping `NOTICE`/`WARN`/`ERR` + panic lines).

**Measurement (to run in the pursue phase).** Count the serial-attributable exits directly:
`perf kvm stat record` around a single cold boot, then `perf kvm stat report --event=vmexit` and read
the `IO_INSTRUCTION` row; A/B `Quiet` vs `Verbose`. `perf_event_paranoid` is 4 on this host, so run it
under the delegated-scope / capability runner (as `scripts/run-bench.sh` does), not ad-hoc sudo. The
expected result: `IO_INSTRUCTION` exits scale with log volume and drop sharply from `Verbose`→`Default`.

**The knob.** Add a typed, `#[non_exhaustive]` enum to `VmConfig` (matches the `RestoreMode` style,
keeps it matchable/fail-loud), defaulting to the perf-optimal level:

```rust
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum KernelVerbosity {
    Quiet,            // loglevel=3 — err/crit only (fastest; empties a healthy log — not for boot.rs)
    #[default]
    Balanced,         // loglevel=6 — perf-optimal; keeps NOTICE banner + WARN/ERR + panic (shipped)
    Verbose,          // loglevel=7 — + the KERN_INFO device-probe flood (pays the UART tax)
    Debug,            // loglevel=8 + `ignore_loglevel` — everything, for a wedged-boot post-mortem
}
```

Only debugging / a test that asserts on a specific kernel line opts into `Verbose`/`Debug`; everyone
else keeps `Balanced` and does not pay the exit tax. `boot.rs` (asserts the `"Linux version"` NOTICE
banner) stays green under `Balanced` (already true) and any higher level. Panic capture is unaffected
at every level (`contains_panic` matches KERN_EMERG). **virtio-console (`hvc0`)** would batch bytes
(≈1 notify-exit per burst) and nearly erase the tax, but it only exists after virtio-pci enumeration —
too late for early boot / a pre-virtio panic — so `ttyS0` stays the early+panic console; a hybrid
`console=ttyS0 console=hvc0` is noted as future work, not in scope here.

## 2. One shared cmdline builder (fixes a real divergence)

The kernel cmdline is **triplicated inline** across the three backends
(`cloud_hypervisor.rs`, `firecracker.rs`, `qemu.rs`) — and it has **already diverged**: **QEMU's
cmdline has no `loglevel=` at all**, so QEMU guests silently pay the full verbose 8250 tax the pass
removed from CH/FC. This is exactly the "don't triplicate; extract" bug AGENTS.md targets. So the
verbosity knob ships **with** a single shared builder:

```rust
// config.rs
pub(crate) fn build_kernel_cmdline(cfg: &VmConfig, res: &Resources, backend_extra: &str) -> Result<String>
```

It emits, in one place: `console=ttyS0 loglevel=<N> random.trust_cpu=on random.trust_bootloader=on
root=/dev/vda rootfstype=<fs> ro <backend_extra> panic=1 init=… vmcell_vmid=<n> [ip=…]
[vmcell_share=…]* vmcell_accept_poll_ms=<a> vmcell_rebind_idle_ms=<r>`. `backend_extra` carries the
one genuine per-backend bit (FC's `noxsave` fpu guard). All three backends call it; QEMU gains
`loglevel` (a latent cold-boot win to measure) and the guest-tuning tokens (§4).

## 3. Unified `Timeouts` struct + two presets

The inventory found **31** timing constants. Not all belong in a per-VM struct — the internal
readiness/join/QMP timeouts are correctness-floor mechanics, not workload tunables. The struct holds
the ones that (a) sit on the per-test hot path and (b) a workload legitimately trades:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Timeouts {
    // --- host reconnect cadence (coupled with guest_accept_poll — see notes) ---
    pub connect_backoff_floor: Duration,  // 20ms  poll while the VMM vsock socket is absent
    pub connect_backoff_cap:   Duration,  // 100ms
    pub connect_ok_read:       Duration,  // 150ms per-byte OK-line read
    pub api_socket_poll:       Duration,  // 5ms   VMM control-socket readiness poll
    // --- teardown ---
    pub shutdown_grace:        Duration,  // 250ms graceful-shutdown() ceiling (NOT the Drop path)
    // --- guest-side, emitted on the cmdline (§4) ---
    pub guest_accept_poll:     Duration,  // 20ms  guest vsock accept poll
    pub guest_rebind_idle:     Duration,  // 250ms post-restore re-bind window
}
```

Failure ceilings that must **not** be workload-tuned stay as constants (documented as such): the
connect Ready-frame wait (2 s) and overall connect deadline (10 s) must exceed real boot-to-listening;
`DEFAULT_EXEC_TIMEOUT` (10 s) must exceed the slowest legit guest command *and* is the anti-leak kill
net; QMP/readiness/join timeouts are internal. The struct's setters **clamp to floors** (e.g.
`guest_accept_poll >= 1 ms`, `shutdown_grace >= 0` but the poll step stays 20 ms) so no preset or
caller can produce a busy-spin or a sub-viable window.

**Presets** (the two "instances" requested), plus the shipped balanced default:

| field | `default()` (shipped) | `low_latency()` (min time-to-output, teardown *excluded*) | `throughput()` (min whole-lifecycle incl. teardown) |
|---|---|---|---|
| connect_backoff_floor | 20 ms | **5 ms** | 10 ms |
| connect_backoff_cap | 100 ms | **40 ms** | 75 ms |
| connect_ok_read | 150 ms | 100 ms | 150 ms |
| api_socket_poll | 5 ms | **2 ms** | 3 ms |
| guest_accept_poll | 20 ms | **5 ms** | 10 ms |
| guest_rebind_idle | 250 ms | 150 ms | 200 ms |
| **shutdown_grace** | 250 ms | **250 ms (left graceful — teardown not optimized)** | **50 ms (fast teardown — the key lever)** |

Rationale: time-to-output is bounded by the *poll gap* between "guest ready" and "host noticed" — so
`low_latency` tightens every connect/accept cadence (host + guest) and leaves teardown alone (grace is
irrelevant to output latency). Throughput is bounded by the *whole* per-test wall-clock, whose largest
tunable is the graceful teardown grace — so `throughput` cuts `shutdown_grace` to 50 ms and keeps
connect cadences moderate (tight polls cost idle-CPU wakeups, which hurt a dense farm). Both are
measured in the pursue phase; expected: `low_latency` shaves ~15–25 ms off cold connect and restore
reconnect; `throughput` shaves ~200 ms off each graceful teardown. (A caller that already tears down
via `Drop`/RAII gets the ~27 ms fast path regardless — `throughput` helps the graceful-`shutdown()`
users.)

`VmConfig` gains `timeouts: Timeouts` (default `Timeouts::default()`) and `kernel_verbosity`; the
builder gains `.timeouts(Timeouts)` and `.kernel_verbosity(KernelVerbosity)`. The orchestrator/agent
read the host fields from `cfg.timeouts` instead of the hard-coded constants; the two guest fields are
emitted on the cmdline (§4).

## 4. Guest-side timeouts, tunable via the cmdline (no rootfs rebuild)

`ACCEPT_POLL` / `REBIND_IDLE` live in the guest agent binary, so they can't be host-set at runtime —
**unless passed on the kernel cmdline**, which the host already controls and the agent already parses
(`vmcell_share=`, `vmcell_vmid=`). Add two tokens in whole ms: `vmcell_accept_poll_ms=<u64>` and
`vmcell_rebind_idle_ms=<u64>`. The agent adds one `parse_ms` helper next to `parse_share_mounts`,
treating `/proc/cmdline` as **untrusted** and clamping into `[floor, ceil]` (absent/garbage → the
compiled default), and threads the two Durations into `serve_vsock` (replacing the `const`s). The host
emits them from `cfg.timeouts` in the shared builder (§2). This makes the whole `Timeouts` struct —
host and guest — a single per-VM knob with **no rootfs rebuild** to change a value.

## 5. Native in-agent resync

`maybe_resync_after_restore` fires **three** guest fork/execs today (each = a full `handle_exec`:
Exec→Stdout/Stderr→Exit frames + ~4 helper threads + reaper coordination):
`date -s @<secs>` (mandatory clock, fail-loud), `sh -c 'head -c 32 /dev/hwrng > /dev/urandom'`
(best-effort RNG), `ip link set eth0 address <mac>` (best-effort MAC — **spawns the multi-MB,
reqwest/rustls-linked guest-tools binary**, the dominant cost). Replace all three with one round-trip
of native in-agent work:

- **Protocol** (`vmcell-protocol`, enum already `#[non_exhaustive]`): two additive variants —
  `Resync { unix_secs: u64, unix_nanos: u32, mac: Option<[u8; 6]> }` (host→guest) and
  `ResyncAck { clock_error: Option<String>, reseed_applied: bool, mac_applied: bool }` (guest→host).
  One request, one ack, carrying the exact per-step outcomes today's three exit codes give.
- **Guest** (`handle_connection` gains a `Resync` arm → `handle_resync`): clock via
  `rustix::time::clock_settime(Realtime, Timespec{..})` (add the `time` feature to the agent's rustix;
  a `libc::clock_settime` fallback exists) — **mandatory**, on error fill `clock_error`, never `?`/panic
  (always send the ack); RNG via a pure-`std::io` 32-byte `/dev/hwrng`→`/dev/urandom` copy (byte-
  identical to the `>` redirect — mixes without crediting entropy); MAC via `SIOCSIFHWADDR`, **reusing
  the existing guest-tools `set_mac` ioctl** — extracted into a small `netif` module in the *lean*
  `vmcell_guest_agent` **library** crate (its deps are only rustix/libc/vsock/signal-hook, so the
  lean-agent CI assertion stays green — no reqwest leaks in). All best-effort steps report via the ack.
- **Host** (`agent/mod.rs`): `AgentClient::resync(unix_secs, unix_nanos, mac) -> Result<ResyncOutcome>`
  modeled on `put_file` (ensure_synced → timeout-wrapped send → await `ResyncAck` → `finish_request`).
  `orchestrator.rs` replaces the `GuestExec`/`exec_argv` seam with a `GuestResync` seam; the mandatory-
  clock-**fail-loud** + retry contract (M-RESTORE-1) is preserved: `ResyncAck.clock_error.is_some()` →
  return `Err`, leave `restored` set so the next `agent()` retries the whole resync; `reseed_applied`
  is recorded (keeps `restore_reseed_applied()` observability); MAC best-effort.

**Estimated win:** ~12–20 ms off the ~36 ms restore reconnect (removing 3 fork/execs, the double-fork
`sh`, and above all the multi-MB `ip` loader/relocation/static-init). Removes the guest-tools binary
from the *restore hot path* entirely (it stays in the rootfs for user execs).

## 6. Test coverage — the complexity mitigation

Every item names the buggy inverse it reddens on (AGENTS.md discipline). All but the last run in the
default (no-KVM) suite.

- **Protocol round-trip** — add `Resync`/`ResyncAck` to `test_serialization_all_variants` + the
  `arb_message` proptest (RED on a dropped/reordered field or a `secs↔nanos` swap).
- **Framing vs real codec** — frame `ResyncAck` with the guest `send_framed`, decode with the host
  `LengthDelimitedCodec`, and the reverse for `Resync` (RED on endianness/prefix/cap drift).
- **Clock timespec mapping** — pure `(secs,nanos)→Timespec` fn test (RED on a unit/overflow bug).
- **`netif::set_mac` ifreq layout** — unit-test the `ifreq` byte layout (`ARPHRD_ETHER` at 0..2, mac at
  2..8) the ioctl writes, so a field-offset regression reddens without a netns.
- **`KernelVerbosity::loglevel()` mapping** — Quiet=3/Balanced=6/Verbose=7/Debug=8 (RED on a swap).
- **`Timeouts` presets + clamps** — `low_latency` connect cadences < `default` < (looser); `throughput`
  `shutdown_grace` < `default`; every field ≥ its floor (RED on an un-clamped preset that busy-spins).
- **Shared cmdline builder** — asserts all three backends now emit `loglevel=`, the `vmcell_*_ms`
  tokens, and the FC `noxsave` extra (RED on the QEMU-loglevel-missing divergence returning).
- **Guest `parse_ms` clamp** — absent/garbage/overflow → default; in-range honored; below-floor clamped
  (RED on an un-clamped parse that lets `vmcell_accept_poll_ms=0` busy-spin PID 1).
- **Integration (privileged)** — the existing `snapshot_restore` matrix now drives the **native** path:
  assert `restore_reseed_applied() == Some(true)`, the clock advanced to host time, and (where the tap
  path allows) the MAC rotated — all with **zero** guest subprocess spawns for resync (a `FakeGuestResync`
  records the single `resync` call, replacing the 3-exec `FakeExec`). RED if resync silently no-ops or
  falls back to execs.

## 7. Rollout, defaults, scope

- **Back-compat:** `VmConfig` defaults to `KernelVerbosity::Balanced` + `Timeouts::default()` = today's
  shipped behavior, so existing callers are unchanged. New public surface (`KernelVerbosity`,
  `Timeouts`, `AgentClient::resync`, `ResyncOutcome`, protocol variants) → expect `cargo semver-checks`
  to report minor additions; the two protocol variants are additive on a `#[non_exhaustive]` enum.
- **Order of implementation (each measured/validated before the next):** (1) shared cmdline builder +
  `KernelVerbosity` (host-only; re-benchmark QEMU cold — free win — and confirm `boot.rs`); (2)
  `Timeouts` struct + presets + host wiring (host-only); (3) guest cmdline tuning (`parse_ms` + tokens)
  — one rootfs rebuild, jointly with (4); (4) native resync — same rootfs rebuild; re-benchmark restore.
- **Out of scope (noted for later):** virtio-console hybrid; unifying the internal readiness-poll
  interval divergence (CH 5 ms vs FC/QEMU 20 ms) — a cleanup, not a workload knob; making the smoltcp
  NAT pump cadence (5 ms, the guest-egress output-latency lever) part of `low_latency` — relevant only
  to networked guests, deferred until a networking-latency benchmark exists.

**Definition of done:** `just ci` green; the new unit tests red on their inverse; `just
test-privileged` green (incl. the native-resync `snapshot_restore` assertions and QEMU boot under the
shared cmdline); `benchmark-results.md` gains the QEMU-loglevel delta + the preset deltas + the native-
resync restore delta; deviations → `implementation-notes.md`; settled parts fold into design §4/§8/§9/§10.
