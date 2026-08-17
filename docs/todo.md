## Designed, need implementing

* README covering CLI capabilities and benchmark results — PARTIAL: the CLI half is done (the
  README's "CLI (`vmcell`)" subcommand table at `README.md:74`, plus "Privileged Test Runner" at
  `:331` and the downstream-contract section at `:94`); a benchmark-results summary is still pending —
  the README only links `docs/benchmark-results.md` (`:490`), which is where every number lives. Needs
  a directional call first: an embedded summary is in direct tension with AGENTS.md's
  pointer-over-figure rule, and the docs/90 pass **deleted** the README's one embedded matrix figure
  (the crosvm pass/total) for exactly that reason, replacing it with a pointer at the recipe that
  produces it (`:298-299`). The defensible shape is a pointer plus the *shape* of what is measured,
  never the numbers.

## Open from the docs/90 review pass

The code half of `docs/90-claude-opus-code-review.md` is landed and so is the design reissue it
directed; §11 of that document records the per-finding outcome, re-verified against commit `c34f9c2`.
What follows is what it left genuinely open.

**The design-document corrections section is retired**, not deferred: all nine body-sentence edits
(docs/90 C1, C3, C5, D6, D7, D9, D10, A2, E1) landed in the same commit as the code, and that §11
names the design line that carries each one. Do not reconstruct the list from the finding bodies —
they describe the pre-reissue tree by construction. One item in it was worse than stale: the C5 entry
asserted that `ValidationOptions` "still carries only `level`" and directed §17 to keep that gap
open, and acting on it would have **reversed a correct design sentence** — the field shipped
(`crates/vmcell-artifact-validator/src/lib.rs:300`, ledgered at that crate's `Cargo.toml:82`). Grep
before acting on any item below, and delete an item rather than re-verifying it later.

### Worked examples on the public API

Mostly landed, and gated: `just test-doc` compiles every `///` example (`just ci` and `ci.yml` both
invoke it). `README.md:29-62`, `crates/vmcell/src/lib.rs:21-53,60-99`, the `artifact` module's
`Pipeline` and `pack_rootfs_with_injection` pair (`crates/vmcell/src/artifact/mod.rs:20-56,69-99`),
`run_battery` (`crates/vmcell-artifact-validator/src/lib.rs:106-164`) and `DaemonClient`
(`crates/vmcell-daemon-client/src/lib.rs:15-53`) all carry compiled examples now. What is left:

* `Stage` — the one contract-surface item a consumer *implements* rather than calls — has a one-line
  doc and no example (`crates/vmcell/src/artifact/mod.rs:505-506`). It is the extension point most
  worth a worked shape: a `Stage` that names itself, computes a cache key over its inputs and publishes
  one artifact path. [docs/90 D11]
* Placement, cheaply: the `Pipeline` (`artifact/mod.rs:2691-2697`), `PackOptions`
  (`artifact/rootfs/mod.rs:200-209`) and `run_battery`
  (`vmcell-artifact-validator/src/conformance.rs:585-594`) examples live on the enclosing **module**,
  so a reader who lands on the item's own rustdoc page sees none. An intra-doc link from each item to
  its module example is the whole fix; a duplicated example would be a second copy to drift.
  [docs/90 D11]

### Shipped config knobs still never applied in a live boot

AGENTS rule 4's "cover it or record it" — recorded here rather than in prose so the list stays
countable. The rest of docs/90's T2 set is closed: `console_mode` boots under
`crates/vmcell/tests/nested_virt.rs`, the tuning channel is measured by
`crates/vmcell/tests/guest_tuning.rs` (a declared `guest_rebind_idle`, read back off PID 1's socket
inodes), and `ksm_mergeable`'s mandatory `shared=off` coupling is pinned KVM-free on the composed CH
memory payload (`ch_memory_payload_couples_ksm_mergeable_to_unshared_memory`).

* Both non-default `RestoreMode`s: shipped, documented, and applied in no integration test — the only
  caller outside `vmcell` is `crates/vmcell-bench/src/bin/bench-vm.rs:203-209`, and `bench-vm` is a
  tracked metric rather than a gate. The behavior it selects is one `--restore` argument
  (`crates/vmcell/src/vmm/cloud_hypervisor.rs:492-497`), so a unit pin on the composed argv is the
  cheap half and a live prefault leg the honest one. [docs/90 T2]
* `Timeouts::low_latency()` as a preset (`crates/vmcell/src/config.rs:423`): `guest_tuning.rs` boots a
  non-default profile by mutating one field, which is what removed the channel's unfalsifiability, but
  no test boots the preset itself — its values are only unit-asserted
  (`crates/vmcell/src/config.rs:3245-3258`). [docs/90 T2]
* `metrics_limits.rs`'s `io_max` refusal leg is written and asserted but its kernel-`ENODEV` arm is
  **dead on a default systemd user session**, which delegates `cpu memory pids` and not `io`. It runs
  the day the suite meets a host with `io` delegated; recorded at the leg
  (`crates/vmcell/tests/metrics_limits.rs:456-467,549`) so the gap is not mistaken for coverage.
  [docs/90 T1]

### Deliberately deferred — do not re-open as findings

* `artifact::Cache`'s inert parameter stays on `Pipeline::build` / `reset_to`. Its rustdoc now says
  what it is (no fields, no methods, nothing about a hit or a miss travels through the handle);
  dropping the parameter is a cheap ledgered pre-1.0 bump whenever someone wants it, not a defect.
  [docs/90 A1]
* vmcell-owned request/response types at the proxy-doubles seam: worth considering only if that surface
  grows. The re-exports are the shipped fix. [docs/90 E1]

### Operational

* The blessed runner on this host is **stale** and `scripts/review-preflight-priv.sh` says so —
  re-probed 2026-08-17 at `c34f9c2`: KVM OK, both file-capability copies present and `+ep`, and both
  the debug and the release copy older than `crates/vmcell-test-runner/src`,
  `crates/vmcell-privilege/src` and `Cargo.lock`, so the verdict is BLOCKED-ON-BLESS (exit 2), decided
  cargo-free from the `.blessed` content hash plus the runner's in-tree source closure. It needs one
  maintainer `just bless`; every privileged run before that executes an older binary than the tree
  under review — including the gate that asserts about the runner's own capability posture. This is
  not a static-only downgrade: the host is capable. [docs/90 G9]

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
  Daemon streaming sessions + a raw-mode interactive CLI are v26 §22.7 forward work.

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
