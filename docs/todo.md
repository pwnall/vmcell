## Designed, need implementing

* README covering CLI capabilities and benchmark results — PARTIAL: the CLI half is done (the
  README's "CLI (`vmcell`)" subcommand table, plus its "Privileged Test Runner" and downstream-
  contract sections); a benchmark-results summary is still pending — the README only links
  `docs/benchmark-results.md`, which is where every number lives.

## Need design

More difficult

* Observability: OTLP spans/metrics + per-step quotas + balloon/memory.high
  pressure + a typed, subscribable event stream [V:high/E:med]

## Designed and implemented

* Persistent interactive sessions: PTY + streaming stdin + multiplexed exec
  [V:high/E:med] — shipped in v26 (`docs/historical/62-claude-design-v26.md` §22): eight
  append-only channelized `Message` variants, a guest non-blocking dispatch loop
  with one per-connection writer + PTY/pipe/stdin/winsize sessions +
  connection-owns-its-sessions teardown, and a host `agent::session` multiplexer.
  Daemon streaming sessions + a raw-mode interactive CLI are §22.7 forward work.

* Multi-VM cluster topologies with a shared L2 segment [V:high/E:high] — shipped in v30 delta 8
  (design §6.5): `NetSegment` owns one netns + bridge per segment (ids `1..=MAX_SEGMENT_ID`, up to
  `MAX_SEGMENT_SLOT` members on `10.201.<s>.0/24`), members join through `NetConfig::Segment` —
  which carries no egress at all, is refused with `snapshotting`, and is privileged-capability-class
  only (probed via `CAP_NET_ADMIN` + a reachable `/var/run/netns`, never presumed). The namespace
  dies with the last `NetSegment` Arc holder; a member releases only its slot and tap, through the
  one ordered teardown helper. The host reaches a member's in-guest listener via
  `NetSegment::dial_tcp`. Live battery: `crates/vmcell/tests/segment.rs`.

## Need directional decision

Candidate capabilities surfaced by the vmcell rebrand (full detail + invariant
guardrails in `docs/historical/38-claude-design-v14.md` §16). Each is triaged; the decision
is which to pull forward. V/E = value/effort.

Adopt-now (cheap, high-value, extend an existing seam):

* Network fault injection: netem (L3/L4) + nft partition + L7 egress chaos [V:high/E:med] —
  PARTIAL: v30 delta 8 exposes the segment's namespace path and its bridge/tap names
  (`NetSegment::netns_path`/`bridge_name`) so a harness runs its own
  `nsenter --net=<path> tc qdisc … netem` — §6.5 exposes the *names*, not a typed impairment API —
  and `crates/vmcell/tests/segment.rs` drives a 50 ms delay leg plus a 100%-loss
  partition-and-heal leg. A typed impairment API, nft partition, and L7 egress chaos stay open.
* Declarative per-sandbox egress policy + full attempted-connection audit [V:high/E:med]
* Disk I/O fault injection [V:high/E:med] — PARTIAL: throttling (bandwidth+IOPS) done in v22
  (`BlockDevice::io_limit`, all backends); error/latency injection (QEMU-`blkdebug`) still open
* Deterministic clock control over vsock (set/freeze/forward-jump) [V:high/E:med]
* Egress + model cassettes: deterministic record/replay over the MITM proxy [V:high/E:med]
* Post-restore secrets injection (never persisted to snapshot/erofs) [V:high/E:med]
* Structured serial fault capture (panic/oops/KASAN/lockdep -> typed Error) [V:high/E:low] —
  PARTIAL: `SerialLog::contains_panic` is a boolean panic detector on the host, and v30 delta 4
  added `vmcell-artifact-validator`'s `classify`, which maps a boot serial log to a typed §5.4
  `ContractViolation` and renders it with the clause and the `CONFIG_*` symbols it names.
  oops/KASAN/lockdep → a typed `vmcell` `Error` stays open.

Design-now-build-later (forward work worth specifying):

* Hardware-profile matrix: CPUID feature masking + aarch64 second architecture [V:med/E:high]
* versioned control-plane API + warm-pool manager [V:high/E:high]
* Generic vsock<->TCP port-forward bridge (LLM transcript schema in a consumer) [V:high/E:med] —
  PARTIAL: v30 delta 7 shipped the dial primitives — `MicroVm::dial_vsock` (a raw host→guest byte
  stream to any guest AF_VSOCK port, no framing and no agent) and the `echo-server` guest-tools
  applet (`--vsock` / `--tcp`) as its in-guest counterpart; `NetSegment::dial_tcp` reaches a
  member's in-guest TCP listener from the host. A long-lived forwarder (a host listener relaying
  into a guest port, or the reverse) stays open — note a host half-close is not portable, so a
  forwarder must frame its own end-of-message (`VsockDial` carries the per-backend table).
* In-VM filesystem checkpoint/rollback (overlay-upper snapshots) [V:med/E:med]
* kcov/gcov/sanitizer coverage extraction over vsock [V:high/E:high]
* Kernel debugging & postmortem: gdbstub + crash-dump capture [V:med/E:high]
* Scale-to-zero invocation lifecycle + cold-start budget (serverless) [V:med/E:med]

Out-of-scope for the core by design (ship as consumer crates/examples on top):

* MCP server frontend (sandbox-as-tools)
* KUnit / kselftest / LTP runner with KTAP parsing
* Deterministic record/replay: rr-as-payload
* Per-invocation billing / usage metering (serverless)
* Per-tool-call run bundle (content-addressed output/egress/metrics capture)
