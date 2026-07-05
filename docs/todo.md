## Designed, need implementing

* README covering CLI capabilities and benchmark results — the README §5 (bless) and the
  new CLI verbs are documented, but a full CLI-capability + benchmark-results summary section
  is still pending.

### v15 design items — IMPLEMENTED (2026-06-30)

All five v15 "next design round" items below are implemented and validated against the full
static suite (clippy `-D warnings` clean, fmt clean, `nextest --all-features` 195 passed /
40 KVM-skipped, deny ok, ban gates, per-member lean checks). See
docs/implementation-notes.md "v15 implementation pass" for the per-item deviations. KVM host
suites were not re-run this pass (correct-by-construction; run `just bless` + `just
test-privileged` once after a runner rebuild to confirm).

### v22 design items — IMPLEMENTED (2026-07-05)

Both "Easy" items below are implemented (design `docs/59-claude-design-v23.md` §19) and validated on
the KVM host. `VmConfig` gained `extra_disks: Vec<BlockDevice>`, `extra_kernel_args: Vec<String>`
(append-only, one-predicate reserved-token guard), and `init: Option<PathBuf>` (genuine `init=`
override, control plane forgone fail-loud). **Pass 2** added disk-I/O fault injection
(`BlockDevice::io_limit`, bandwidth+IOPS throttling on all three backends) and the **daemon-API
exposure** (`CreateVmRequest.extra_disks`/`extra_kernel_args`; extra disks read-only + pinned;
`init` deliberately library-only). CLI `run`/`create` gained `--disk`/`--disk-rw`/`--append`.
KVM-validated (all green): `extra_block` (+ snapshot-composition) CH+FC+QEMU, `custom_init` CH,
`extra_block_io_throttle` CH+FC+QEMU, and the daemon `extra_disk_over_api` HTTP path. See
docs/implementation-notes.md "v22" for the justified deviations. **Forward work:** writable-
scratch-from-artifact over the daemon (copy-on-attach), and disk error/latency injection
(QEMU-`blkdebug`).

* Arbitrary extra virtio-blk devices + disk-I/O fault injection [V:high/E:med] — DONE
* Custom init + append-only boot-args passthrough [V:med/E:low] — DONE

## Need design

More difficult

* Single-snapshot copy-on-write clone + fork()/branch() with lineage handles
  (new injectable OverlayStore seam) [V:high/E:high]
* Privileged-window hardening: VMM seccomp + jailer-equivalent + setup-broker [V:high/E:high]
* Persistent interactive sessions: PTY + streaming stdin + multiplexed exec [V:high/E:med]
* Observability: OTLP spans/metrics + per-step quotas + balloon/memory.high
  pressure + a typed, subscribable event stream [V:high/E:med]

## Need directional decision

Candidate capabilities surfaced by the vmcell rebrand (full detail + invariant
guardrails in docs/38-claude-design-v14.md §16). Each is triaged; the decision
is which to pull forward. V/E = value/effort.

Adopt-now (cheap, high-value, extend an existing seam):

* Disk I/O fault injection [V:high/E:med] — PARTIAL: throttling (bandwidth+IOPS) done in v22
  (`BlockDevice::io_limit`, all backends); error/latency injection (QEMU-`blkdebug`) still open
* Deterministic clock control over vsock (set/freeze/forward-jump) [V:high/E:med]
* Egress + model cassettes: deterministic record/replay over the MITM proxy [V:high/E:med]
* Declarative per-sandbox egress policy + full attempted-connection audit [V:high/E:med]
* Post-restore secrets injection (never persisted to snapshot/erofs) [V:high/E:med]
* Structured serial fault capture (panic/oops/KASAN/lockdep -> typed Error) [V:high/E:low]
* Network fault injection: netem (L3/L4) + nft partition + L7 egress chaos [V:high/E:med]

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
