## Designed, need implementing

* README covering CLI capabilities and benchmark results

## Need design

* Introduce the term "unprivileged operation" instead of "rootless" (with KVM
  access, no additional caps), and its opposite as "privileged" (with
  capabilities). Explicitly spec tests for unprivileged and for privileged
  operation.
* Position as isolated test environment, useful for agentic harnesses and
  generic serverless
* Reconsider `imp-test-runner` design for testing privileged operations. We're
  blocked on me running `just bless` too often. Are there approaches that would
  be more resilient to code changes? Alternatively, can we design a more robust
  suite of tests for the `imp-test-runner` binary so that we don't have to get
  it rebuilt as often? Does the binary get rebuilt often because of unrelated
  changes, suggesting we should switch to a cargo workspace?
* Migrate all "best-effort" functionality (do something if the capabilties
  exist, move on otherwise) to failing on missing capabiltiies. Implementations
  must document the required capabilities. Callers must ensure they have the
  capabilities need to call into functionality. I am concerned about silent
  failures leading to missed errors.
* Resolve open questions based on benchmarks
* Ensure that the micro-VM execution primitive is reasonably general

## Need directional decision

Candidate capabilities surfaced by the vmcell rebrand (full detail + invariant
guardrails in docs/38-claude-design-v14.md §16). Each is triaged; the decision is
which to pull forward. V/E = value/effort.

Adopt-now (cheap, high-value, extend an existing seam):

* VM-as-a-handle lifecycle verbs (create/list/pause/resume/fork/destroy/stats)
  unified across lib + CLI + daemon API [V:high/E:med]
* Egress + model cassettes: deterministic record/replay over the MITM proxy [V:high/E:med]
* Declarative per-sandbox egress policy + full attempted-connection audit [V:high/E:med]
* Bring-your-own OCI image as an erofs rootfs source (per-sandbox) [V:high/E:med]
* Post-restore secrets injection (never persisted to snapshot/erofs) [V:high/E:med]
* Deterministic clock control over vsock (set/freeze/forward-jump) [V:high/E:med]
* Per-test kernel config-fragment matrix (extend the kernels registry) [V:high/E:med]
* Structured serial fault capture (panic/oops/KASAN/lockdep -> typed Error) [V:high/E:low]
* Network fault injection: netem (L3/L4) + nft partition + L7 egress chaos [V:high/E:med]
* Arbitrary extra virtio-blk devices + disk I/O fault injection [V:high/E:med]
* Custom init + append-only boot-args passthrough [V:med/E:low]
* Build/distribution hygiene: cargo-workspace split + content-hash bless stamp +
  reproducible bundle (also resolves the just-bless churn above) [V:high/E:med]

Design-now-build-later (forward work worth specifying):

* Single-snapshot copy-on-write clone + fork()/branch() with lineage handles
  (new injectable OverlayStore seam) [V:high/E:high]
* impd daemon + versioned control-plane API + warm-pool manager [V:high/E:high]
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
