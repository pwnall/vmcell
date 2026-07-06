## Designed, need implementing

* README covering CLI capabilities and benchmark results — the README §5 (bless) and the
  new CLI verbs are documented, but a full CLI-capability + benchmark-results summary section
  is still pending.

## Need design

More difficult

* Observability: OTLP spans/metrics + per-step quotas + balloon/memory.high
  pressure + a typed, subscribable event stream [V:high/E:med]

## Designed and implemented

* Persistent interactive sessions: PTY + streaming stdin + multiplexed exec
  [V:high/E:med] — shipped in v26 (`docs/62-claude-design-v26.md` §22): eight
  append-only channelized `Message` variants, a guest non-blocking dispatch loop
  with one per-connection writer + PTY/pipe/stdin/winsize sessions +
  connection-owns-its-sessions teardown, and a host `agent::session` multiplexer.
  Daemon streaming sessions + a raw-mode interactive CLI are §22.7 forward work.

## Need directional decision

Candidate capabilities surfaced by the vmcell rebrand (full detail + invariant
guardrails in docs/38-claude-design-v14.md §16). Each is triaged; the decision
is which to pull forward. V/E = value/effort.

Adopt-now (cheap, high-value, extend an existing seam):

* Network fault injection: netem (L3/L4) + nft partition + L7 egress chaos [V:high/E:med]
* Declarative per-sandbox egress policy + full attempted-connection audit [V:high/E:med]
* Disk I/O fault injection [V:high/E:med] — PARTIAL: throttling (bandwidth+IOPS) done in v22
  (`BlockDevice::io_limit`, all backends); error/latency injection (QEMU-`blkdebug`) still open
* Deterministic clock control over vsock (set/freeze/forward-jump) [V:high/E:med]
* Egress + model cassettes: deterministic record/replay over the MITM proxy [V:high/E:med]
* Post-restore secrets injection (never persisted to snapshot/erofs) [V:high/E:med]
* Structured serial fault capture (panic/oops/KASAN/lockdep -> typed Error) [V:high/E:low]

Design-now-build-later (forward work worth specifying):

* Hardware-profile matrix: CPUID feature masking + aarch64 second architecture [V:med/E:high]
* versioned control-plane API + warm-pool manager [V:high/E:high]
* Generic vsock<->TCP port-forward bridge (LLM transcript schema in a consumer) [V:high/E:med]
* In-VM filesystem checkpoint/rollback (overlay-upper snapshots) [V:med/E:med]
* kcov/gcov/sanitizer coverage extraction over vsock [V:high/E:high]
* Multi-VM cluster topologies with a shared L2 segment [V:high/E:high]
* Kernel debugging & postmortem: gdbstub + crash-dump capture [V:med/E:high]
* Scale-to-zero invocation lifecycle + cold-start budget (serverless) [V:med/E:med]

Out-of-scope for the core by design (ship as consumer crates/examples on top):

* MCP server frontend (sandbox-as-tools)
* KUnit / kselftest / LTP runner with KTAP parsing
* Deterministic record/replay: rr-as-payload
* Per-invocation billing / usage metering (serverless)
* Per-tool-call run bundle (content-addressed output/egress/metrics capture)
