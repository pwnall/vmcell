# AGENTS.md — vmcell

Deploy at the repository root as `AGENTS.md`. Terse by design; the reasoning lives in
`docs/68-claude-fable-code-review-rubric.md` (rubric v5) and `docs/67-claude-fable-design-v28.md`
(design).

## What this is

vmcell runs each integration test in an isolated micro-VM. Cloud Hypervisor is the primary backend
and the **only** one in the `vmcell` lib; Firecracker and QEMU are secondary and live in their own
crates (`vmcell-firecracker`, `vmcell-qemu`), each depending on `vmcell` for the one `Vmm` trait,
the `VmmCapabilities` descriptor, and the shared jail/seccomp/spawn/console/eligibility helpers —
`vmcell` has no production edge back (only a dev-dep, for the matrix tests). Crates (under
`crates/`): `vmcell` (host lib), `vmcell-firecracker` / `vmcell-qemu` (the secondary backends),
`vmcell-bench` (the cross-backend `bench-vm` harness, wiring all three backends), `vmcell-cli`,
`vmcell-protocol`, `vmcell-guest-agent` (PID 1 in-guest), `vmcell-test-runner` (privileged
capability runner), `vmcell-guest-tools`, the rootfs/kernel builders, `vmcell-privilege` (shared
cap/blessing predicates), and the control-plane tier: `vmcell-daemon` (lib), `vmcelld` (binary),
`vmcell-daemon-client`, `vmcelld-ctl`, and `vmcell-broker` (the privileged spawn helper). Two
operating modes: **unprivileged** (KVM group only, smoltcp NAT) and **privileged** (three caps,
netns/tap/nft, the only snapshot-eligible mode).

## Read before changing anything

- `implementation-notes.md` — recorded, justified deviations, and the as-built reconciliation of
  the **0.9→0.10 delta pass** (design §18). Do not "fix" entries listed there; record new justified
  deviations there instead of silently diverging. Retire an entry when it is empirically disproven.
- `docs/99-claude-fable-code-review-rubric-v9.md` — every rule below is expanded there with its
  defect history. Its **Retired rules** section lists two former demands v28 supersedes — don't
  re-open them. (`9` represents an arbitrary digit, use the newest version you find)
- `docs/benchmark-results.md` — measured perf levers.
- `docs/99-claude-fable-design-v99.md` — architecture; **§13** lists the cross-cutting invariants,
  lettered S/C/L/F/P/G, each with an owner and a gate; **Appendix A** records the load-bearing
  reversals (cite them, don't re-argue); **§17** is the open-gaps register.

## The delta register binds implementations, not the baseline

Design §18 directs **eleven changes that are specified but not yet built** (one breaking pass,
`vmcell` 0.9→0.10). Until it lands, the code legitimately matches validated 0.9 — a delta-item
divergence is a finding **only** in the change that claims to implement that delta. A change
implementing a delta lands **with the delta's named gate**, reconciles the result in
`implementation-notes.md`, and updates in-code `§` references per design Appendix E. Two design-doc
errata `docs/historical/70` (quality gates) is authoritative over: the §9.7 Rust-1.85/1.88 toolchain
note (the MSRV is 1.96.1, single-sourced) and the §15.2 phrasing that the broker excludes
tokio/rtnetlink (it excludes only the **web** stack — axum/hyper — and owns the engine).

## Non-negotiable rules

1. Every recurring defect class becomes a lint, a CI job, or a test that can go red. A fix for a
   defect a human found lands **with its gate**.
2. Every test and every gate must be able to fail. Write the red-on-inverse first; a gate whose
   self-test cannot fail is theater.
3. CI executes what it claims: filters select > 0 tests (`--no-tests=fail`), lean targets are built
   and clippied (a `cargo tree`-only check compiles nothing), accepted-red steps run last or
   non-gating so they never short-circuit other gates.
4. Enumerate what the suite structurally cannot reach — error branches, non-default configs and
   flows, defaults, window-filling payloads, security inverses, **and the effect classes your fakes
   are blind to** (`FakeVmm` never touches the filesystem — the lineage `create_dir_all` was
   invisible to every fake-driven test). Cover it or record it.
5. Host-facing claims are validated by executing the suites. KVM capability is **probed**
   (preflight), never presumed absent — the box you are on usually qualifies, and the blessed runner
   lets you run the privileged suite unprivileged. Green static review proves little; a
   capability-flag change re-validates empirically, not in the descriptor.

## Writing code

- Teardown is ownership, through **one** ordered helper (`teardown_post_instance`). `Drop` is the
  panic path, `shutdown()` the graceful one, `EnvSetup`'s explicit `Drop` the mid-`start()` error
  path (delta 7 — **not** field-declaration order any more), and the registry's
  `destroy`/`shutdown_all`/`Drop` — all the same order, one helper, never a second copy. A hard kill
  that skips `Drop` is reclaimed by the daemon's start-up sweep against an empty live set.
- Fail loud. No bare `let _ =` on a `Result` or on an accepted input. Every accepted input — config
  field, CLI flag, env var, feature gate — is honored or rejected at construction; a feature gate
  may remove a capability (`CapabilityUnavailable`), never silently change semantics. Where a field
  is meaningful on only one variant, **move it there** (delta 4 put `host_services_port` on
  `NetConfig::Unprivileged` so the invalid state is unrepresentable) instead of accept-then-reject.
- Injected seams travel as **one `HostEnv`** (`{cids, vmids, cgroups, clock, overlay}`, deltas 1–2):
  spawn entry points take `&HostEnv`, `agent()` takes no seam args, tests build
  `HostEnv::hermetic()`. Every CoW clone materializes through `env.overlay` (S4) — no second
  injection path.
- Suppressions: `#[expect(<lint>, reason = "…")]` on the **single statement** that needs it —
  never a fn, module, or crate scope (`clippy::allow_attributes*` deny plain and reason-less
  suppressions in production code). Feature/platform-conditional lints scope with `cfg_attr`. Route
  repeated legitimate sites through one helper (`exit_failure()`) so one suppression covers the
  class.
- Defaults get the strictest scrutiny: the default arm is the least-tested path. `Egress::Open`
  must actually forward.
- One law, one predicate. A cross-cutting invariant lives in exactly one function or const every
  call site uses: `config_has_vhost_user_device` (S1), `is_reserved_cmdline_arg` (F3), the
  `vmcell::naming` name/filter composers (F2), `resolve_artifact_path` (P3),
  `ensure_blessed_or_explain` (P1), `vmm_seccomp_args`/`apply_jail` (§12), `check_clone_eligible`,
  `MAX_FRAME_BYTES`/`MAX_BROKER_FRAME_BYTES`, `mac_math`/`ip_math`, the cache-key rules (F4). Never
  write a second copy — every duplicate so far has diverged.
- Recovery stays retryable: consume one-shot flags (`restored`, desync) only after the recovery
  succeeds; a transient failure leaves the next call able to retry, and a failed resync evicts the
  cached client so nothing wedges.
- Security checks anchor on trusted data (the runner's own `current_exe()`; the daemon's own
  `--artifacts-dir` via `resolve_artifact_path` — never a client-supplied path, never inline
  `dir.join(client)`), match normalized input (case, trailing dot, label boundary), and ship with a
  positive control.
- Capability, or untrusted-input parsing — never both in one process, and posture matches lifetime.
  The broker child holds the caps and never parses network input; the HTTP parent drops all caps
  before serving (P2). A transient privilege wrapper (the runner) drops-and-execs; a long-lived
  cap-holder (the daemon) retains and **refuses to start degraded** (P1).
- Handle counts. Partial `write`/`send_slice` returns are looped or errored, never discarded.
- Capability honesty (§7.2): `Unsupported`/`CapabilityUnavailable` for absent facilities, `Error`
  with errno for broken ones; `mem_limit_enforced` means exactly "memory controller delegated"
  (delta 3 — the deliberately narrow claim); `*_read_ok` reflect empirically validated behavior.
  The one start-up `HostCapabilities` descriptor (delta 8) is probed once and logged; per-op
  enforcement keeps its own authoritative fail-loud per-write check (it does not re-derive the
  descriptor per op, nor silently re-probe).
- Helper daemons and the broker child: spawn with `PR_SET_PDEATHSIG` + `CLOEXEC`; reap on every
  error path; a failed later spawn step reaps the earlier daemons.
- PID-1 discipline in the guest agent (C1): never `exit`; reap children via the `ReaperCoordinator`
  epochs; signal handling per §3.4. A PID-1 panic aborts the guest, so the agent binary keeps the
  full deny family (`unwrap_used`, `panic`, `print_*`).
- Deadlines are `Instant`, propagated outer-bounds-inner. Concurrent startup is cancellation-safe
  (`spawn_clones` is the shipped all-or-nothing pattern; `try_join_all` over daemon starts is the
  recorded rejection).
- Runtime files under `XDG_RUNTIME_DIR` (or the artifacts dir), never bare `/tmp` on shared hosts.
- Serial/console logs are persisted artifacts: no secrets in kernel cmdline, agent output, or logs
  — and no daemon API key in argv/env (perms-checked file only, P4).

## The daemon, the broker, and the jailer  *(new subsystems)*

- **Daemon HTTP (B12).** Every client-named artifact resolves through `resolve_artifact_path`
  (allowlist, anchored on `--artifacts-dir`); the store is create-only + atomic + digest-sidecar'd
  at upload (delta 10); auth wraps every route except `/healthz`+`/openapi.json` (perms-checked key
  file, constant-time compare, 401-absent/403-wrong); the served OpenAPI and the mounted routes are
  one parity-gated table (P5); `DaemonError` maps to status once, a config error is 400 not 500;
  DTOs are single-sourced (client links `default-features = false`). `restore_from` goes via CoW so
  the store snapshot stays re-restorable. Daemon extra disks are read-only and there's no `init=`
  over REST — both recorded, don't re-flag.
- **Broker (B13/P2).** Forked **before** the tokio runtime (fork-with-threads is unsafe);
  `PR_SET_PDEATHSIG=SIGKILL`; the parent drops all caps via `plan_broker_parent_drop` before
  serving; frames are length-bounded by `MAX_BROKER_FRAME_BYTES`. It reuses the real
  seams + `build_vmm_cmd` + `apply_jail` (a location, not a fork of the logic). The engine channel
  is **JSON** because the forwarded DTOs use `#[serde(skip_serializing_if)]`/`default` and postcard
  corrupts those (Appendix A reversal 10) — any presence-attribute type gets a round-trip test on
  the codec it ships over. The fat (engine-owning) broker is what ships; the thin broker +
  fd-passing is recorded §17.
- **Jailer (B13).** `apply_jail` is async-signal-safe between `fork` and `execve`; order is
  rlimits → dumpable → ambient-clear → `no_new_privs` → seccomp → `execve`. `clear_ambient_caps`
  defaults **false** with its at-site rationale (clearing it stripped the `CAP_NET_ADMIN` the VMM
  needs for tap setup — Appendix A reversal 9; default-on is blocked on fd-passing). `RLIMIT_CORE=0`
  + non-dumpable; `rlimit_fsize` is `None` on the snapshot path (a snapshot is a guest-RAM write).
  The VMM's own seccomp is explicit and typed (`VmmSeccomp`); QEMU **must** pass `-sandbox …` or it
  runs unconfined. The extra deny-list is `EPERM`, opt-in, off until live-validated per backend.
- **Seccomp deps.** `seccompiler` only; the libseccomp-wrapper crates are banned by name in
  `deny.toml` (their LGPL-2.1 C link is invisible to the license scan).

## Unsafe, FFI, and the guest boundary

- Kernel ABI structs are `#[repr(C)]`, defined once, with `size_of`/offset asserts against the ABI —
  no inline byte-math reimplementations (the 18-byte `ifreq` wrote 22 bytes past a PID-1 stack).
- Every `unsafe` block holds **one** operation (`multiple_unsafe_ops_per_block` denies) with a
  `SAFETY:` comment proving that operation's obligation (async-signal-safety in the jail child;
  pointer+size for an ioctl), not restating it.
- Guest- or network-derived lengths are validated against `MAX_FRAME_BYTES` (and the broker's
  `MAX_BROKER_FRAME_BYTES`) before allocation or indexing; integer narrowing from the wire is
  `try_from`, never `as`.
- The guest framing round-trips against the real host codec, both directions, including over-cap
  rejection — KVM-free, so it always runs.

## Writing tests

- Before accepting a test, construct the buggy implementation it guards and confirm it goes red.
- Skips go through `require_cap!` only: it panics for cloud-hypervisor (primary) and records
  `SKIP <vmm> <capability>` to `VMCELL_SKIP_MANIFEST`. A `println!("SKIP") + return` is a green PASS.
- Never neuter the property under test (`-k` on a curl that exists to validate TLS).
- Assert positive identities, not inequality-with-prior: `post_mac == mac_math(new_vmid)`, the
  in-guest default route via `ip_math(new_vmid)` — branch on `restore_rotates_host_paths`. Recompute
  expected resource names through `vmcell::naming`, never a test-local `format!`.
- Assert on the data plane: an egress byte after restore, `memory.events oom_kill > 0`, a file
  `cat`-ed back in-guest, a tmpfs marker surviving `restore_from` — not proxy signals (vsock
  liveness, exit codes, `contains("html")`).
- Move window-filling and `> MAX_FRAME_BYTES` payloads in every data-plane test; presence-attribute
  DTOs round-trip on the codec they actually ship over (the postcard trap).
- Failure injection is a first-class suite member: mid-`start()`/`restore()` faults leave zero
  residue in the recorded order; each `FakeVmm` fault-menu arm (delta 9) is driven; a transient
  resync recovers on the next call.
- For each recording fake, name the live test covering what it structurally cannot see (fs, network,
  process table) — "the fakes are green" is not evidence on those axes.
- A negative security result needs a positive control (the allowed path reaches the same target).
- Pure math in harnesses (percentiles) gets unit tests against known values; regenerate published
  tables when the harness changes.
- Residue checks assert the artifact existed before drop, then that it is gone.
- New batteries the suite must carry: the **zygote** fan-out (distinct vmid/`mac_math`/vsock, master
  `config.json` byte-identical, `Unsupported` on `n>1` non-rotating + single-clone control); the
  **session** set (zero cross-attribution, post-exit drop, connection-drop pgroup residue, PTY +
  pipe negative control); the **daemon** set (KVM-free auth/OpenAPI/name-validator/delete-in-use +
  the inverted-runner `vmcelld` KVM suite).

## Running the privileged suites — probe, don't presume

- "Am I on a KVM host?" is answered by `scripts/review-preflight-priv.sh`, never by assumption.
  Hesitating instead of probing is the exact failure mode the preflight exists to remove.
- The blessed runner exists so that *you*, unprivileged, can run the privileged suite: nextest
  invokes `.vmcell-bin/release/vmcell-test-runner`, which holds the three file capabilities — no
  sudo, no root shell; cargo and the tests stay yours. The daemon suite (`just test-daemon`) uses
  the same runner and delegated scope.
- Preflight green → run `just test-privileged`, the unprivileged suite, and `just test-daemon`
  yourself.
- Preflight failing only on blessing (runner missing, stale stamp, not `+ep`) → ask the maintainer
  to run `just bless` (one sudo), then rerun preflight and the suites. Never attempt the bless
  yourself; never silently skip.
- Only a genuinely absent facility (`/dev/kvm`, a missing backend binary) downgrades you to
  static-only — say so explicitly and mark every runtime claim unverified.

## Done means

- `just ci` green locally (it is the CI definition; both set `RUSTFLAGS=-D warnings`).
- For host-facing changes: both operating-mode suites green per the section above, all three
  backends, `just test-daemon` for daemon-touching changes, and the skip manifest reviewed.
- New public API: rustdoc complete (`missing_docs` denies), `cargo semver-checks` clean. A change
  implementing a delta-register item ships that item's named gate and reconciles
  `implementation-notes.md`.
- The privileged runner is re-blessed after rebuilds (`just bless`; blessing is stripped on rewrite
  by design).

## Performance claims

- Benchmarks are tracked metrics, not gates; only relative invariants graduate to guards.
- Check the `docs/historical/45` refuted-lever table before proposing a lever; only interleaved
  same-session deltas are evidence; name the budget a change must not regress.
- "Environmental" is a hypothesis, not a diagnosis: a flake explanation without a mechanism stays
  open. Tail figures from before 2026-07-03 use the broken `floor(n·q)` estimator — not comparable.

## Docs and dependencies

- Docs state each fact once, in present tense, terse, with trade-offs stated honestly.
- Dependencies: permissive licenses only (cargo-deny allow-list enforces); the libseccomp-wrapper
  crates are `[bans]`-denied by name (LGPL-2.1 C link invisible to the scan); `cargo deny` ignores
  carry a per-crate rationale; vendored patches (`vendor/vhost*`) keep exact `=` pins — a caret
  requirement silently drops the patch.
- Toolchain: `rust-toolchain.toml` pins 1.96.1 and the declared `rust-version` **equals** it (one
  `[workspace.package]` fact; this supersedes the design §9.7 pre-bump note). An understated MSRV
  lets MSRV-aware resolvers re-resolve older consumers onto vulnerable dependency versions (the
  `time 0.3.45` class). Build `--locked`; never `cargo update` on an older toolchain.
- No unused dependencies (`cargo machete`; macro-only false positives get a per-crate ignore).
  Third-party GitHub Actions stay pinned to full commit SHAs; Dependabot moves the pins.
