## Designed, need implementing

* README covering CLI capabilities and benchmark results

Designed in docs/39-claude-design-v15.md (the "next design round" items below; each
landed its honestly-easy core, with the not-easy parts deferred/rejected inline):

* `vmcell-test-runner` bless resilience (§12.8) — install the blessed runner to a
  stable path outside `target/` + idempotent content-hash stamp keyed on the RUNNER
  (never test binaries) + the confinement-root fix (anchor on the test binary's path,
  not `/proc/self/exe`) + a pure, unit-tested `CapState` transition. ALSO answers
  "switch to a workspace?" → yes (§10.1), but the stable-path install is the load-
  bearing churn fix; the workspace is the structural leanness boundary.
* Build/distribution hygiene: cargo-workspace split + content-hash bless stamp (§10.1,
  §12.8) [done in design]; reproducible bundle SCOPED DOWN to a digest-pinned fetch-
  and-verify manifest for our artifacts — vendoring the VMM binaries is REJECTED (QEMU
  GPL redistribution; size; fetch-verify already gives reproducibility).
* VM-as-a-handle lifecycle verbs (§10.2/§10.3): create/run/pause/resume/snapshot/stats/
  destroy unified across lib + CLI, taking a `--rootfs` (erofs) arg; pause/resume/
  snapshot promoted to first-class MicroVm methods. DEFERRED: list/rm + standalone exec
  (need the impd daemon's cross-process registry — collides with ordered-Drop); fork
  (the §16.2 CoW-clone item).
* Bring-your-own OCI image → `vmcell oci2erofs IMAGE@DIGEST` build-time utility (§8.2/
  §11); VM verbs take the resulting erofs. Fail loud on a libc6-less base; static-musl
  agent is an explicit `--agent-musl` opt-in, not a silent fallback.
* Per-test kernel config-fragment matrix (§8.3): base SHA + sorted KConfig fragment set,
  content-addressed. config-only fragments in scope; PREEMPT_RT (needs patched source)
  and KCOV extraction (needs guest tooling, §16.2) excluded; per-test API deferred.


## Need design

* Migrate all "best-effort" functionality (do something if the capabilties
  exist, move on otherwise) to failing on missing capabiltiies. Implementations
  must document the required capabilities. Callers must ensure they have the
  capabilities need to call into functionality. I am concerned about silent
  failures leading to missed errors.
* Resolve open questions based on benchmarks
* Ensure that the micro-VM execution primitive is reasonably general

## Need directional decision

Candidate capabilities surfaced by the vmcell rebrand (full detail + invariant
guardrails in docs/39-claude-design-v15.md §16). Each is triaged; the decision is
which to pull forward. V/E = value/effort. (v15 already pulled four §16.1 candidates
forward — lifecycle verbs, oci2erofs, the kernel-fragment matrix, and the workspace +
bless-stamp build hygiene — see "Designed, need implementing" above.)

Adopt-now (cheap, high-value, extend an existing seam):

* Deterministic clock control over vsock (set/freeze/forward-jump) [V:high/E:med]
* Custom init + append-only boot-args passthrough [V:med/E:low]
* Egress + model cassettes: deterministic record/replay over the MITM proxy [V:high/E:med]
* Declarative per-sandbox egress policy + full attempted-connection audit [V:high/E:med]
* Post-restore secrets injection (never persisted to snapshot/erofs) [V:high/E:med]
* Structured serial fault capture (panic/oops/KASAN/lockdep -> typed Error) [V:high/E:low]
* Network fault injection: netem (L3/L4) + nft partition + L7 egress chaos [V:high/E:med]
* Arbitrary extra virtio-blk devices + disk I/O fault injection [V:high/E:med]

Design-now-build-later (forward work worth specifying):

* Single-snapshot copy-on-write clone + fork()/branch() with lineage handles
  (new injectable OverlayStore seam) [V:high/E:high]
* vmcelld daemon + versioned control-plane API + warm-pool manager [V:high/E:high]
* Privileged-window hardening: VMM seccomp + jailer-equivalent + setup-broker [V:high/E:high]
* Generic vsock<->TCP port-forward bridge (LLM transcript schema in a consumer) [V:high/E:med]
* Observability: OTLP spans/metrics + per-step quotas + balloon/memory.high
  pressure + a typed, subscribable event stream [V:high/E:med]
* Persistent interactive sessions: PTY + streaming stdin + multiplexed exec [V:high/E:med]
* In-VM filesystem checkpoint/rollback (overlay-upper snapshots) [V:med/E:med]
* kcov/gcov/sanitizer coverage extraction over vsock [V:high/E:high]
* Multi-VM cluster topologies with a shared L2 segment [V:high/E:high]
* Kernel debugging & postmortem: gdbstub + crash-dump capture [V:med/E:high]
* Hardware-profile matrix: CPUID feature masking + aarch64 second architecture [V:med/E:high]
* Scale-to-zero invocation lifecycle + cold-start budget (serverless) [V:med/E:med]

Out-of-scope for the core by design (ship as consumer crates/examples on top):

* MCP server frontend (sandbox-as-tools)
* KUnit / kselftest / LTP runner with KTAP parsing
* Deterministic record/replay: rr-as-payload
* Per-invocation billing / usage metering (serverless)
* Per-tool-call run bundle (content-addressed output/egress/metrics capture)
