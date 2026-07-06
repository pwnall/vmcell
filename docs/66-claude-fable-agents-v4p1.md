# AGENTS.md — vmcell

Deploy at the repository root as `AGENTS.md`. Terse by design; the reasoning lives in
`docs/53-claude-fable-code-review-rubric.md` (rubric v4) and `docs/47-claude-design-v18.md`
(design).

## What this is

vmcell runs each integration test in an isolated micro-VM. Cloud Hypervisor is the primary backend;
Firecracker and QEMU are secondary, behind one `Vmm` trait with a `VmmCapabilities` descriptor.
Crates (under `crates/`): `vmcell` (host lib), `vmcell-cli`, `vmcell-protocol`,
`vmcell-guest-agent` (PID 1 in-guest), `vmcell-test-runner` (privileged capability runner),
`vmcell-guest-tools`, plus the rootfs/kernel builders and the artifact validator. Two operating
modes:
**unprivileged** (KVM group only, smoltcp NAT) and **privileged** (three caps, netns/tap/nft, the
only snapshot-eligible mode).

## Read before changing anything

- `implementation-notes.md` — recorded, justified deviations. Do not "fix" entries listed there;
  record new justified deviations there instead of silently diverging. Retire an entry when it is
  empirically disproven.
- `docs/53-claude-fable-code-review-rubric.md` — every rule below is expanded there with its
  defect history.
- `docs/52` (gates implementation report) — doc↔code deviations recorded there with reasoning are
  settled; do not re-litigate them without new evidence.
- `docs/45-*.md` + `docs/benchmark-results.md` — measured perf levers. Do not re-derive refuted levers.
- `docs/47-claude-design-v18.md` — architecture; §12 lists cross-cutting invariants with owners.

## Non-negotiable rules

1. Every recurring defect class becomes a lint, a CI job, or a test that can go red. A fix for a
   defect a human found lands **with its gate**.
2. Every test and every gate must be able to fail. Write the red-on-inverse first; a gate whose
   self-test cannot fail is theater.
3. CI executes what it claims: filters select > 0 tests (`--no-tests=fail`), lean targets are built
   and clippied (a `cargo tree`-only check compiles nothing), accepted-red steps run last or
   non-gating so they never short-circuit other gates.
4. Enumerate what the suite structurally cannot reach — error branches, non-default configs and
   flows, defaults, window-filling payloads, security inverses — and cover it or record it.
5. Host-facing claims are validated by executing the suites. KVM capability is **probed**
   (preflight), never presumed absent — the box you are on usually qualifies, and the blessed
   runner lets you run the privileged suite unprivileged. Green static review proves little; a
   capability-flag change re-validates empirically, not in the descriptor.

## Writing code

- Teardown is ownership: dependents are declared before the resources they run inside (drop order
  = declaration order). `Drop` is the panic path, `shutdown()` the graceful one — same order, one
  shared helper, never two copies.
- Fail loud. No bare `let _ =` on a `Result` or on an accepted input. Every accepted input —
  config field, CLI flag, env var, feature gate — is honored or rejected at construction; a feature
  gate may remove a capability (`CapabilityUnavailable`), never silently change semantics.
- Suppressions: `#[expect(<lint>, reason = "…")]` on the **single statement** that needs it —
  never a fn, module, or crate scope (`clippy::allow_attributes*` deny plain and reason-less
  suppressions in production code). If a lint fires only under some feature or platform, scope with
  `cfg_attr` — or a reasoned `#[allow]` there. Route repeated legitimate sites through one helper
  (`exit_failure()`) so one suppression covers the class.
- Defaults get the strictest scrutiny: the default arm is the least-tested path. `Egress::Open`
  must actually forward.
- One law, one predicate. A cross-cutting invariant lives in exactly one function or const that
  every call site uses: `config_has_vhost_user_device` (§12.1), `MAX_FRAME_BYTES`
  (`vmcell-protocol`), `mac_math`/`ip_math`, the cache-key rules (§11.2). Never write a second
  copy of load-bearing logic — every duplicate so far has diverged.
- Recovery stays retryable: consume one-shot flags (`restored`, desync) only after the recovery
  succeeds. A transient failure must leave the next call able to retry, not a wedged cached client.
- Security checks anchor on trusted data (the runner's own `current_exe()`, never an argument),
  match normalized input (case, trailing dot, label boundary), and ship with a positive control.
- Handle counts. Partial `write`/`send_slice` returns are looped or errored, never discarded.
- Capability honesty (§7.2): `Unsupported`/`CapabilityUnavailable` for absent facilities, `Error`
  with errno for broken ones; `limits_enforced`/`*_read_ok` reflect empirically validated behavior.
- Helper daemons: spawn with `PR_SET_PDEATHSIG` + `CLOEXEC`; reap on every error path; a failed
  later spawn step reaps the earlier daemons.
- PID-1 discipline in the guest agent: never `exit`; reap children via the `ReaperCoordinator`
  epochs; signal handling per §12.6. A PID-1 panic aborts the guest, so the agent binary keeps the
  full deny family (`unwrap_used`, `panic`, `print_*`).
- Deadlines are `Instant`, propagated outer-bounds-inner. Concurrent startup is cancellation-safe:
  a failed sibling future must not leak the others' resources.
- Runtime files under `XDG_RUNTIME_DIR` (or the artifacts dir), never bare `/tmp` on shared hosts.
- Serial/console logs are persisted artifacts: no secrets in kernel cmdline or agent output.

## Unsafe, FFI, and the guest boundary

- Kernel ABI structs are `#[repr(C)]`, defined once, with `size_of`/offset asserts against the ABI —
  no inline byte-math reimplementations (the 18-byte `ifreq` wrote 22 bytes past a PID-1 stack).
- Every `unsafe` block holds **one** operation (`multiple_unsafe_ops_per_block` denies) with a
  `SAFETY:` comment proving that operation's obligation, not restating it.
- Guest- or network-derived lengths are validated against `MAX_FRAME_BYTES` before allocation or
  indexing; integer narrowing from the wire is `try_from`, never `as`.
- The guest framing round-trips against the real host codec, both directions, including over-cap
  rejection — KVM-free, so it always runs.

## Writing tests

- Before accepting a test, construct the buggy implementation it guards and confirm it goes red.
- Skips go through `require_cap!` only: it panics for cloud-hypervisor (primary) and records
  `SKIP <vmm> <capability>` to `VMCELL_SKIP_MANIFEST`. A `println!("SKIP") + return` is a green PASS.
- Never neuter the property under test (`-k` on a curl that exists to validate TLS).
- Assert positive identities, not inequality-with-prior: `post_mac == mac_math(new_vmid)`, the
  in-guest default route via `ip_math(new_vmid)` — branch on `restore_rotates_host_paths`.
- Assert on the data plane: an egress byte after restore, `memory.events oom_kill > 0`, a file
  `cat`-ed back in-guest — not proxy signals (vsock liveness, exit codes, `contains("html")`).
- Move window-filling and `> MAX_FRAME_BYTES` payloads in every data-plane test.
- Failure injection is a first-class suite member: mid-`start()`/`restore()` faults leave zero
  residue in the correct order; a transient resync recovers on the next call.
- A negative security result needs a positive control (the allowed path reaches the same target).
- Pure math in harnesses (percentiles) gets unit tests against known values; regenerate published
  tables when the harness changes.
- Residue checks assert the artifact existed before drop, then that it is gone.

## Running the privileged suites — probe, don't presume

- "Am I on a KVM host?" is answered by `scripts/review-preflight-priv.sh`, never by assumption.
  Hesitating instead of probing is the exact failure mode the preflight exists to remove.
- The blessed runner exists so that *you*, unprivileged, can run the privileged suite: nextest
  invokes `.vmcell-bin/release/vmcell-test-runner`, which holds the three file capabilities — no
  sudo, no root shell; cargo and the tests stay yours.
- Preflight green → run `just test-privileged` and the unprivileged suite yourself.
- Preflight failing only on blessing (runner missing, stale stamp, not `+ep`) → ask the maintainer
  to run `just bless` (one sudo), then rerun preflight and the suites. Never attempt the bless
  yourself; never silently skip.
- Only a genuinely absent facility (`/dev/kvm`, a missing backend binary) downgrades you to
  static-only — say so explicitly and mark every runtime claim unverified.

## Done means

- `just ci` green locally (it is the CI definition; both set `RUSTFLAGS=-D warnings`).
- For host-facing changes: both operating-mode suites green per the section above, all three
  backends, and the skip manifest reviewed.
- New public API: rustdoc complete (`missing_docs` denies), `cargo semver-checks` clean.
- The privileged runner is re-blessed after rebuilds (`just bless`; blessing is stripped on rewrite
  by design).

## Performance claims

- Benchmarks are tracked metrics, not gates; only relative invariants graduate to guards.
- Check the `docs/45` refuted-lever table before proposing a lever; only interleaved same-session
  deltas are evidence; name the budget a change must not regress.
- "Environmental" is a hypothesis, not a diagnosis: a flake explanation without a mechanism stays open.

## Docs and dependencies

- Docs state each fact once, in present tense, terse, with trade-offs stated honestly.
- Dependencies: permissive licenses only (cargo-deny allow-list enforces); `cargo deny` ignores
  carry a per-crate rationale; vendored patches (`vendor/vhost*`) keep exact `=` pins — a caret
  requirement silently drops the patch.
- Toolchain: `rust-toolchain.toml` pins 1.96.1 and the declared `rust-version` **equals** it (one
  `[workspace.package]` fact). An understated MSRV lets MSRV-aware resolvers re-resolve older
  consumers onto vulnerable dependency versions (the `time 0.3.45` class). Build `--locked`; never
  `cargo update` on an older toolchain.
- No unused dependencies (`cargo machete`; macro-only false positives get a per-crate ignore).
  Third-party GitHub Actions stay pinned to full commit SHAs; Dependabot moves the pins.
