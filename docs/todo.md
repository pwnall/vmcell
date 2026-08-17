## Designed, need implementing

* README covering CLI capabilities and benchmark results — PARTIAL: the CLI half is done (the
  README's "CLI (`vmcell`)" subcommand table, plus its "Privileged Test Runner" and downstream-
  contract sections); a benchmark-results summary is still pending — the README only links
  `docs/benchmark-results.md`, which is where every number lives. Needs a directional call first:
  an embedded summary is in direct tension with AGENTS.md's pointer-over-figure rule, and the
  docs/90 pass **deleted** the README's one embedded matrix figure (29/29 crosvm) for exactly that
  reason. The defensible shape is a pointer plus the *shape* of what is measured, never the numbers.

## Open from the docs/90 review pass

The code half of `docs/90-claude-opus-code-review.md` is landed; §11 of that document records the
per-finding outcome. What follows is what it left genuinely open.

### Design-document corrections, for the next reissue

Every item below is a **body-sentence** edit inside an existing section of
`docs/83-claude-fable-design-v33.md`; none needs a heading to change, and none may be fixed by
renumbering one. `scripts/ban-dangling-design-ref.sh` resolves every `§<id>` and `Appendix <letter>`
under `crates/*/src` against those headings (2058 of them) and `scripts/check-docs-pointers.sh` does
the same for the root markdown, so moving a heading is a reissue-scale change with two red gates
attached.

**Grep before acting, and delete the item rather than re-verifying it later.** The design reissue was
in flight in the same pass that wrote this list, so an item may already read correctly — each one below
names the spelling to search for, which is the whole check.

* §10.4's contract list must name `pack_rootfs_with_injection` — the format-honoring inject+pack tail
  — beside `pack_erofs_with_injection`, which since delta 8 is the **erofs-only door** onto it and
  refuses any other `PackOptions::format` by name. The ledger entry is written
  (`crates/vmcell/Cargo.toml`, 0.19 → 0.20) and `README.md` lists it; the design line is the gap.
  [docs/90 C1]
* §10.4's "labelled rootfs/handler build entry points" and §10.5's "where selection lives" must name
  the shipped shape: the `RootfsStage::labelled` / `GuestToolsStage::labelled` constructors plus the
  `vmcell build --rootfs-label / --handler-label` verbs. `build_labelled_rootfs` and
  `build_labelled_handler` do not exist and are not going to — the constructors are the better shape,
  recorded in `docs/implementation-notes.md`. [docs/90 C3]
* §17's battery-budget entry must scope its closure to `ConformanceOptions.battery_budget` /
  `run_battery`, and keep `validate()`'s missing overall wall-clock budget **on** the register:
  `ValidationOptions` still carries only `level`, and a `Level::Full` run is bounded only by the sum
  of its per-check deadlines. [docs/90 C5]
* §9.3's annotation on `VmConfig::steward_placement`, and §18 delta 4's *What* line, must name **both**
  C8 methods. C8 is a two-method law precisely because availability (`steward_port()`) and
  snapshot-eligibility (`resync_reachable()`) differ exactly at `Service`; naming one is the spelling
  §13 defines as the law's violation. [docs/90 D6]
* §2.2's "every control RPC over the API socket is bounded at 5 s" needs its one-clause exception: the
  snapshot RPC's budget scales with guest RAM through `vmm::snapshot_request_timeout(mem_mib)`,
  deliberately, since a suspend image tracks guest RAM. [docs/90 D7]
* §15.4, §4.7's two mentions and delta 7's gate line name `test_pax_xattrs_are_not_preserved`. The
  shipped pair is `pax_xattrs_are_stripped_under_the_default_policy` /
  `pax_xattrs_are_preserved_under_the_preserve_policy`. [docs/90 D9]
* Two design sites still advertise `RootfsSource::Block` as a writable root (the §4.7 sentence is
  already recorded in `docs/implementation-notes.md`; widen that entry so the next reissue does not fix
  one and leave two). The authority is `RootfsSource::root_device_read_only` — one law, and the
  0.19 → 0.20 ledger entry states the behavior and the data-plane evidence for it. [docs/90 D10]
* §17's Cloud-Hypervisor-binary-resolver consolidation entry has a stale inventory: it named
  `harness::ch_bin()` and `bench-vm`'s workspace-root ascent and missed `vmcell-cli`'s copy. That copy
  is gone (it calls `vmcell::artifact::ch_binary_path()`) and the class is gated by
  `scripts/ban-ch-binary-resolver-copies.sh`, so the entry needs re-scoping to what is actually left.
  [docs/90 A2]
* §10.4 must list `vmcell::proxy::doubles`' `hudsucker` / `hyper` re-exports, so a version bump inside
  vmcell is ledgered rather than discovered by a consumer whose test double stops compiling —
  `cargo semver-checks` cannot see it, because the type aliases' shape does not change. [docs/90 E1]

### `docs/implementation-notes.md`

* The `tar2erofs`-does-not-preserve-PAX-xattrs entry is past its own retirement condition ("Retire if
  xattr passthrough is implemented" — delta 7 implemented it) and names a test delta 7 renamed. Retire
  it or rewrite it as the delta-7 pointer, and spot-check its neighbour for the same drift.
  [docs/90 D8]

### Worked examples on the public API

* Now safe to add and gated the moment they land: `just test-doc` compiles every `///` example
  (`just ci` and `ci.yml` both invoke it). `README.md` still carries **zero** Rust code blocks,
  `crates/vmcell/src/lib.rs`'s crate doc none, and the contract-surface entry points `Stage`,
  `Pipeline`, `pack_rootfs_with_injection`, `PackOptions` and `run_battery` none. The natural set is
  one example each for boot-and-exec, snapshot-and-restore via `Zygote`, a `Pipeline` assembly, and a
  `DaemonClient` round trip — the last on `vmcell-daemon-client`, whose `DaemonClient` is documented as
  "a typed Rust API matching the `vmcell` entry points" and shows none of them. [docs/90 D11]

### Shipped config knobs still never applied in a live boot

AGENTS rule 4's "cover it or record it" — recorded here rather than in prose so the list stays
countable. The rest of docs/90's T2 set is closed: `console_mode` boots under
`crates/vmcell/tests/nested_virt.rs`, the tuning channel is measured by
`crates/vmcell/tests/guest_tuning.rs`, and `ksm_mergeable`'s mandatory `shared=off` coupling is pinned
KVM-free on the composed CH memory payload.

* Both non-default `RestoreMode`s: shipped, documented, and applied in no integration test.
  `bench-vm` drives them, and `bench-vm` is a tracked metric rather than a gate. [docs/90 T2]
* `Timeouts::low_latency()` as a preset: `guest_tuning.rs` boots a non-default profile (which is what
  removed the channel's unfalsifiability), but never the preset itself, so its two values are still
  only unit-tested. [docs/90 T2]
* `metrics_limits.rs`'s `io_max` refusal leg is written and asserted but its kernel-`ENODEV` arm is
  **dead on a default systemd user session**, which delegates `cpu memory pids` and not `io`. It runs
  the day the suite meets a host with `io` delegated; recorded at the leg so the gap is not mistaken
  for coverage. [docs/90 T1]

### Deliberately deferred — do not re-open as findings

* `artifact::Cache`'s inert parameter stays on `Pipeline::build` / `reset_to`. Its rustdoc now says
  what it is (no fields, no methods, nothing about a hit or a miss travels through the handle);
  dropping the parameter is a cheap ledgered pre-1.0 bump whenever someone wants it, not a defect.
  [docs/90 A1]
* vmcell-owned request/response types at the proxy-doubles seam: worth considering only if that surface
  grows. The re-exports are the shipped fix. [docs/90 E1]

### Operational

* The blessed runner on this host is **stale** and `scripts/review-preflight-priv.sh` now says so
  (BLOCKED-ON-BLESS, decided cargo-free from the `.blessed` content hash plus the runner's in-tree
  source closure). It needs one maintainer `just bless`; every privileged run before that executes an
  older binary than the tree under review. [docs/90 G9]

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
