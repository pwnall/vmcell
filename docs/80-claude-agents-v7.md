# AGENTS.md — vmcell

Deploy at the repository root as `AGENTS.md`. Terse by design; the reasoning lives in
`docs/75-claude-fable-code-review-rubric-v6.md` (rubric v6) and `docs/79-claude-fable-design-v31.md`
(design v31).

## What this is

vmcell runs each integration test in an isolated micro-VM. Cloud Hypervisor is the primary backend
and the **only** one in the `vmcell` lib; Firecracker, QEMU, and crosvm are secondary and live in
their own crates (`vmcell-firecracker`, `vmcell-qemu`, `vmcell-crosvm`), each depending on `vmcell`
for the one `Vmm` trait, the `VmmCapabilities` descriptor, and the shared
jail/seccomp/spawn/console/eligibility helpers — `vmcell` has no production edge back (only
dev-deps, for the matrix tests). `vmcell-crosvm` (design §2.5) is **validated live** (via
`just test-crosvm`, including snapshot/restore), but the crosvm binary is absent on CI, so its live
matrix is that opt-in recipe, not `test-privileged`. Snapshot/restore is the **Firecracker
baked-CID pattern** (crosvm requires the baked vsock CID on restore, so `restore_rotates_host_paths`
is false — single-lineage, no concurrent fan-out); QEMU is on the **rotating** side (its restore
programs a fresh guest CID); virtio-fs/unpriv-net/disk-throttle stay honest-false on crosvm.
Crates (under `crates/`): `vmcell` (host lib), `vmcell-firecracker` / `vmcell-qemu` /
`vmcell-crosvm` (the secondary backends), `vmcell-artifact-validator` (the artifact conformance
kit — boots real VMs against the named check battery; downstream **contract surface**),
`vmcell-bench` (the cross-backend `bench-vm` harness, wiring all four backends), `vmcell-cli`,
`vmcell-protocol`, `vmcell-guest-agent` (PID 1 in-guest), `vmcell-test-runner` (privileged
capability runner), `vmcell-guest-tools`, the rootfs/kernel builders, `vmcell-privilege` (shared
cap/blessing predicates), and the control-plane tier: `vmcell-daemon` (lib), `vmcelld` (binary),
`vmcell-daemon-client`, `vmcelld-ctl`, and `vmcell-broker` (the privileged spawn helper). Two
operating modes: **unprivileged** (KVM group only, smoltcp NAT) and **privileged** (three caps,
netns/tap/nft, the only snapshot-eligible mode). Current version: `vmcell` 0.13.

## Read before changing anything

- `docs/implementation-notes.md` — recorded, justified deviations and the as-built reconciliations
  (the landed 0.9→0.10 pass, the docs/72 fixes, the backend/crosvm/QEMU-restore passes, the v30
  delta register, the docs/78 review pass). Do not "fix" entries listed there; record new justified
  deviations there instead of silently diverging. Retire an entry when it is empirically disproven.
- `docs/99-claude-fable-code-review-rubric-v9.md` — every rule below is expanded there with its
  defect history. Its **Retired & qualified rules** section lists former demands the design
  supersedes or scopes (incl. the exhaustive-contract-types qualification) — don't re-open them.
  (`9` represents an arbitrary digit, use the newest version you find.)
- `docs/99-claude-fable-automated-quality-v9.md` — the gate specifications (lint preambles, ban
  scripts, recipes, the delta-gate table, the coverage map); newest version wins, as above.
- `docs/99-claude-fable-code-review.md` — the newest standing code review and what it found; a
  finding it records is not a fresh discovery.
- `docs/benchmark-results.md` — measured perf levers; the 2026-07-17 matrix is canonical.
- `docs/99-claude-fable-design-v99.md` — architecture; **§13** lists the cross-cutting invariants,
  lettered S/C/L/F/P/G, each with an owner and a gate; **Appendix A** records the load-bearing
  reversals (cite them, don't re-argue); **§17** is the open-gaps register. **No standing errata**:
  a correction is folded into the body when the design is reissued.

## The delta register binds implementations, not the baseline

Design §18's register is the mechanism for directing changes that are **specified but not yet
built**. The v30 downstream-platform register (deltas 1–9) is **landed**; `vmcell` is 0.13 and the
code no longer legitimately differs from it. When a future register is open, these conventions
stand:

- Until an item lands, the code legitimately matches the last validated release — a delta-item
  divergence is a finding **only** in the change that claims to implement that delta.
- A change implementing a delta lands **with the delta's named gate** and reconciles the result in
  `docs/implementation-notes.md`.
- **Re-verify the delta's premise anchors before cutting.** Premises stated as shipped fact have
  been empirically false in every register so far (v28 had two; v30's delta-9 record claimed "every
  backend's `restore()` rejects a non-snapshotting config", and no backend's `restore()` reads
  `cfg.snapshotting` at all). A stale premise is a stop-and-check.
- Sketched names/signatures are advisory — the behavior and its gate bind; a shift is recorded,
  never silent. fs/process-touching deltas run their named live gate (the fakes are fs-blind). Any
  presence-attribute type round-trips on the codec it actually ships over.

## Non-negotiable rules

1. Every recurring defect class becomes a lint, a CI job, or a test that can go red. A fix for a
   defect a human found lands **with its gate**.
2. Every test and every gate must be able to fail. Write the red-on-inverse first; a gate whose
   self-test cannot fail is theater.
3. CI executes what it claims: filters select > 0 tests (`--no-tests=fail`), lean targets are built
   and clippied (a `cargo tree`-only check compiles nothing), accepted-red steps run last or
   non-gating so they never short-circuit other gates. A CI step that hand-copies a `just` recipe
   drifts from it — invoke the recipe (`run: just test-unprivileged`) so local ≡ CI by construction.
4. Enumerate what the suite structurally cannot reach — error branches, non-default configs and
   flows, defaults, window-filling payloads **in both directions**, security inverses, **and the
   effect classes your fakes are blind to** (`FakeVmm` never touches the filesystem — the lineage
   `create_dir_all` was invisible to every fake-driven test; no test moved bulk data *guest→host*
   through the NAT, which is why a ring-wrap panic shipped). Cover it or record it.
5. Host-facing claims are validated by executing the suites. KVM capability is **probed**
   (preflight), never presumed absent — the box you are on usually qualifies, and the blessed runner
   lets you run the privileged suite unprivileged. Green static review proves little; a
   capability-flag change re-validates empirically, not in the descriptor.

## Writing code

- Teardown is ownership, through **one** ordered helper (`teardown_post_instance`). `Drop` is the
  panic path, `shutdown()` the graceful one, `EnvSetup`'s explicit `Drop` the mid-`start()` error
  path, and the daemon registry's `destroy`/`shutdown_all` — all the same order, one helper, never
  a second copy. A segment member releases its *slot* through the same helper and never deletes the
  segment netns — that dies with the last `NetSegment` Arc holder. A hard kill that skips `Drop` is
  reclaimed by the daemon's start-up sweep against empty live sets (vmids **and** segids).
- Fail loud. No bare `let _ =` on a `Result` or on an accepted input. Every accepted input — config
  field, CLI flag, env var, feature gate, **pins-overlay key**, **a guest tool shim's argv** — is
  honored or rejected at construction; a feature gate may remove a capability
  (`CapabilityUnavailable`), never silently change semantics; the overlay parser rejects a top-level
  key matching no known pins namespace (a typo'd override must not silently resolve from the
  baseline); F3's reserved-cmdline law covers **aliases**, not just key-equal collisions (`rw`
  inverts the owned `ro`; `quiet`/`debug`/`ignore_loglevel` override `loglevel=`), because the
  emitted-token coverage gate structurally cannot discover an alias. Where a field is meaningful on
  only one variant, **move it there** so the invalid state is unrepresentable (`host_services_port`
  on `Unprivileged` only; `NetConfig::Segment` carries no egress at all).
- Injected seams travel as **one `HostEnv`** (`{cids, vmids, segids, cgroups, clock, overlay}` —
  grown by field, never by positional argument): spawn entry points take `&HostEnv`, `agent()`
  takes no *seam* args (its `timeout: Option<Duration>` is the per-call connect budget — a recorded
  deviation, don't re-drop it), tests build `HostEnv::hermetic()`. Every CoW clone materializes
  through `env.overlay` (S4) — no second injection path. A "probe" never writes into the directory
  it is probing: a zygote master is immutable, so `probe_reflink` works in a sibling scratch dir it
  proves is on the same filesystem.
- Suppressions: `#[expect(<lint>, reason = "…")]` on the **single statement** that needs it —
  never a fn, module, or crate scope (`clippy::allow_attributes*` deny plain and reason-less
  suppressions in production code). Feature/platform-conditional lints scope with `cfg_attr`. Route
  repeated legitimate sites through one helper (`exit_failure()`) so one suppression covers the
  class.
- Defaults get the strictest scrutiny: the default arm is the least-tested path. `Egress::Open`
  must actually forward what its mode admits — and is *not* arbitrary outbound.
- One law, one predicate. A cross-cutting invariant lives in exactly one function or const every
  call site uses: `config_has_vhost_user_device` (S1), `is_reserved_cmdline_arg` (F3), the
  `vmcell::naming` name/filter composers + `validate_resource_prefix` — `NetSegment::new` routes
  through it too (F2), `is_reserved_injection_path` (F5), `resolve_artifact_path` (P3),
  `ensure_blessed_or_explain` (P1), `vmm_seccomp_args`/`apply_jail` (§12), the one config-only
  snapshot/clone-eligibility predicate shared by `restore_inner` and `check_clone_eligible`,
  `RootfsSource::effective_image` (which file backs `/dev/vda`), `uses_in_kernel_vsock`,
  `net_uses_tap`, `net_sys::setns_net`, `reap_process_group`, the shared `build_kernel_cmdline`
  (§5.3), `segment_ip_math` beside `ip_math`/`mac_math`, the one vsock `CONNECT/OK` prologue
  (shared by `connect_framed` and `dial_vsock`), the one id-claim core (`flock` + `hard_link`)
  under both `VmidAllocator` and `SegmentIdAllocator`, `MAX_FRAME_BYTES`/`MAX_BROKER_FRAME_BYTES`
  and the `capped_debug` renderer beside them, `pcts`, and the cache-key rules (F4). Never write a
  second copy — every duplicate so far has diverged.
- Recovery stays retryable: consume one-shot flags (`restored`, desync) only after the recovery
  succeeds; a transient failure leaves the next call able to retry, and a failed resync evicts the
  cached client so nothing wedges.
- Security checks anchor on trusted data (the runner's own `current_exe()`; the daemon's own
  `--artifacts-dir` via `resolve_artifact_path` — never a client-supplied path, never inline
  `dir.join(client)`), match normalized input (case, trailing dot, label boundary), apply on **every**
  verb that names the resource (a suffix reserved at `create` but not at `info`/`delete` is not
  reserved), and ship with a positive control.
- Capability, or untrusted-input parsing — never both in one process, and posture matches lifetime.
  The broker child holds the caps and never parses network input; the HTTP parent drops all caps
  before serving (P2). A transient privilege wrapper (the runner) drops-and-execs; a long-lived
  cap-holder (the daemon) retains and **refuses to start degraded** (P1). A privilege *reduction*
  that fails is warned, never discarded — a silently wider bounding set is a silently weaker posture.
- Handle counts. Partial `write`/`send_slice` returns are looped or errored, never discarded, and a
  reader consumes only what the buffer it was handed actually contains: the guest→host NAT drain
  writes from **inside** smoltcp's `recv` closure, over the contiguous span, because `peek_slice`
  copies across the RX-ring wrap while `dequeue_many_with` asserts against the contiguous span.
- Capability honesty (§7.2): `Unsupported`/`CapabilityUnavailable` for absent facilities, `Error`
  with errno for broken ones (`ENOENT`/`EOPNOTSUPP` = absent facility → `Error::Cgroup`, not a
  delegation remediation); the typed-refusal feature string equals the `VmmCapabilities` field
  name; a deliberately narrow flag keeps its narrow name (`mem_limit_enforced`,
  `usb_host_passthrough`); `*_read_ok` reflect empirically validated behavior (§7.2 rule 3). The one
  start-up `HostCapabilities` descriptor is probed once and logged; per-op enforcement keeps its own
  authoritative fail-loud per-write check.
- Helper daemons and the broker child: spawn with `PR_SET_PDEATHSIG` + `CLOEXEC`; reap on every
  error path through the one reaper; a failed later spawn step reaps the earlier daemons. A
  cap-holding child that outlives a terminal signal is worse than one that dies: the broker child
  ignores INT/TERM (PDEATHSIG and the shutdown channel govern its lifetime) and `build_vmm_cmd`
  resets `SIG_DFL` in `pre_exec` so spawned VMMs keep normal behavior.
- PID-1 discipline in the guest agent (C1): never `exit`; reap children via the `ReaperCoordinator`
  epochs; signal handling per §3.4; **zero netlink and zero new guest code for segments** — members
  still learn their address from the kernel `ip=` token (C6). A PID-1 panic aborts the guest, so
  the agent binary keeps the full deny family (`unwrap_used`, `panic`, `print_*`). No blocking I/O
  on the dispatch path: a child that stops reading stdin must not wedge the connection past its
  teardown.
- Deadlines are `Instant`, propagated outer-bounds-inner, and bound the **whole** operation, not the
  gaps between its polls — a budget checked only between iterations does not bound a wedged
  connect, read, or write. Concurrent startup is cancellation-safe (`spawn_clones` is the shipped
  all-or-nothing pattern; `try_join_all` over daemon starts is the recorded rejection).
- Runtime files under `XDG_RUNTIME_DIR` (or the artifacts dir), never bare `/tmp` on shared hosts —
  the un-prefixed `/tmp/vmcell-vmid` / `/tmp/vmcell-segid` id-lock dirs are the recorded
  cross-process-rendezvous exception (deliberate, not swept, don't "fix").
- Serial/console logs are persisted artifacts: no secrets in kernel cmdline, agent output, or logs —
  and no daemon API key in argv/env (perms-checked file only, P4). A log line that renders a whole
  guest-controlled frame is a flood; render through `capped_debug`.

## The daemon, the broker, and the jailer

- **Daemon HTTP (B12).** Every client-named artifact resolves through `resolve_artifact_path`
  (allowlist, anchored on `--artifacts-dir`); the store is create-only + atomic + digest-sidecar'd
  at upload (a client name ending `.sha256` is reserved-rejected on **every** verb, not just
  `create`); a snapshot to an already-populated prefix is a 409, not a silent overwrite into a
  create-only store; auth wraps every route except `/healthz`+`/openapi.json` (perms-checked key
  file, constant-time compare, 401-absent/403-wrong, and `--allow-unauthenticated` warns per
  request); the served OpenAPI and the mounted routes are one parity-gated table (P5); `DaemonError`
  maps to status once, a config error is 400 not 500; DTOs are single-sourced (client links
  `default-features = false`). `restore_from` goes via CoW so the store snapshot stays
  re-restorable. Daemon extra disks are read-only and there's no `init=` over REST — both recorded,
  don't re-flag.
- **Broker (B13/P2).** Forked **before** the tokio runtime (fork-with-threads is unsafe);
  `PR_SET_PDEATHSIG=SIGKILL`; the parent drops all caps via `plan_broker_parent_drop` before
  serving; frames are length-bounded by `MAX_BROKER_FRAME_BYTES`, and a reply that cannot be
  serialized or exceeds the cap sends a typed `Err` frame — never nothing, which hangs the caller
  forever. It reuses the real seams + `build_vmm_cmd` + `apply_jail` (a location, not a fork of the
  logic). The engine channel is **JSON** because the forwarded DTOs use
  `#[serde(skip_serializing_if)]`/`default` and postcard corrupts those (Appendix A reversal 10) —
  any presence-attribute type gets a round-trip test on the codec it ships over. The broker's lean
  boundary is the web-**server** stack (`axum` + `vmcell-daemon` absent; `hyper` enters
  legitimately; it owns the engine). The fat (engine-owning) broker is what ships; the thin broker +
  fd-passing is recorded §17.
- **Jailer (B13).** `apply_jail` is async-signal-safe between `fork` and `execve` — and
  **allocation-free on every path, including the error paths** (`io::Error::from_raw_os_error`, not
  `format!`/`io::Error::new`, which can deadlock a child against the parent's allocator lock).
  Order is rlimits → dumpable → ambient-clear → `no_new_privs` → seccomp → `execve`.
  `clear_ambient_caps` defaults **false** with its at-site rationale (clearing it stripped the
  `CAP_NET_ADMIN` the VMM needs for tap setup — Appendix A reversal 9; default-on is blocked on
  fd-passing). `RLIMIT_CORE=0` + non-dumpable; `rlimit_fsize` is `None` on the snapshot path (a
  snapshot is a guest-RAM write). The VMM's own seccomp is explicit and typed (`VmmSeccomp`); QEMU
  **must** pass `-sandbox …` or it runs unconfined — asserted on the **composed argv**, not on a
  fragment; **crosvm always runs `--disable-sandbox`** (its multiprocess minijail is incompatible
  with single-process supervision — the live-validation reversal) and its `Enforcing` turns the
  Layer-2 deny-list **on** instead, through one pure `effective_jail_config` that is pinned both
  ways; `Log` is a typed `Unsupported` on FC, QEMU, **and** crosvm. The extra deny-list is `EPERM`,
  opt-in elsewhere, off until live-validated per backend.
- **Seccomp deps.** `seccompiler` only; the libseccomp-wrapper crates are banned by name in
  `deny.toml` (their LGPL-2.1 C link is invisible to the license scan).

## The downstream toolkit contract

vmcell has out-of-repo consumers; the contract surface is **one named list** (design §10.4): the
pins schema + overlay, `Stage`/`Pipeline`/`ResolvePinsStage`, the kernel build entry points + the
resolved-config sidecar, `pack_erofs_with_injection` + `ExtraFile`, the `VMCELL_*` env table, and
the `vmcell-artifact-validator` battery. Rules: a change to listed surface is a **deliberate,
ledgered version bump** (the `Cargo.toml` comment changelog), never discovered by a consumer's
build breaking; `semver-checks` covers `vmcell` *and* the validator; the out-of-tree
`examples/downstream-kernel/` workspace is the living consumer gate — **breaking its CI job is the
intended failure mode of contract drift**, and "fixing" the example to stay green instead of
versioning the contract inverts the gate. The `VMCELL_*` semantics are specified (`VMCELL_ROOTFS`
= full ensure no-op; `VMCELL_KERNEL` = path redirect that still requires existence; `VMCELL_PINS`
= the overlay; the `VMCELL_*_BIN` resolvers are the one way any harness finds a VMM binary —
`bench-vm` included; downstream getters fail loud naming the two-step route — a recorded deviation
from the FR's letter, cite it). vmcell ships **mechanisms, never consumer content** (G1): example
fragments are self-proving mechanism proofs (IKCONFIG); the generic `usbhost` capability-gate
fragment is the one defended exception shape and never carries a consumer's usbip/gadget closure.

## Unsafe, FFI, and the guest boundary

- Kernel ABI structs are `#[repr(C)]`, defined once, with `size_of`/offset asserts against the ABI —
  no inline byte-math reimplementations (the 18-byte `ifreq` wrote 22 bytes past a PID-1 stack).
  Where a second copy is deliberately kept (guest-tools beside the agent's `netif`), the deviation
  is **recorded** and the divergence guard pins fields and ioctl numbers, not just total size.
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
- Never neuter the property under test (`-k` on a curl that exists to validate TLS). The in-guest
  `curl` is vmcell's own shim on `/vmcell-tools` (first on PATH; the rootfs carries no GNU curl), so
  it **rejects** any flag it cannot honor — an accepted-but-ignored flag is the same hazard one step
  removed, and it silently voided a data-plane assertion before the shim was made fail-loud.
- Assert positive identities, not inequality-with-prior: `post_mac == mac_math(new_vmid)`, the
  in-guest default route via `ip_math(new_vmid)` — branch on `restore_rotates_host_paths`; where an
  `assert_ne!` is right (QEMU's rotated CID), **reserve the source value first** so it is
  non-vacuous. Recompute expected resource names through `vmcell::naming`, never a test-local
  `format!`.
- Assert on the data plane: an egress byte after restore, `memory.events oom_kill > 0`, a file
  `cat`-ed back in-guest, a tmpfs marker surviving `restore_from`, `/proc/config.gz` proving a
  fragment took — not proxy signals (vsock liveness, exit codes, `contains("html")`).
- Move window-filling and `> MAX_FRAME_BYTES` payloads in every data-plane test, **in both
  directions**; presence-attribute DTOs round-trip on the codec they actually ship over (the
  postcard trap).
- Failure injection is a first-class suite member: mid-`start()`/`restore()` faults leave zero
  residue in the recorded order; each `FakeVmm` fault-menu arm (incl. `fail_resume`) is driven; a
  transient resync recovers on the next call.
- For each recording fake, name the live test covering what it structurally cannot see (fs, network,
  process table) — "the fakes are green" is not evidence on those axes.
- A negative security result needs a positive control (the allowed path reaches the same target).
- Pure math in harnesses (percentiles) gets unit tests against known values; regenerate published
  tables when the harness changes.
- Residue checks assert the artifact existed before drop, then that it is gone — and a **test's own**
  fixtures are residue too: a fixture tree owns its cleanup on the panic path as well as the success
  path. A snapshot fixture that leaked ~129 MB per run filled the host tmpfs and reddened the daemon
  suite with `EDQUOT`, which reads as a product defect and is not one.
- Batteries the suite carries: the **zygote** fan-out (distinct vmid/`mac_math`/vsock — and, on
  QEMU, distinct guest CID; master `config.json` byte-identical; `Unsupported` on `n>1`
  non-rotating + single-clone control); the **session** set (zero cross-attribution, post-exit
  drop, connection-drop pgroup residue, PTY + pipe negative control); the **daemon** set (KVM-free
  auth/OpenAPI/name-validator/delete-in-use + the inverted-runner `vmcelld` KVM suite, incl. the
  group-SIGINT orphan leg and the broker-parent zero-capability assertion with the child as positive
  control); the **segment** set (two-VM bidirectional TCP, off-segment negative against both
  members with the on-segment positive control, host `dial_tcp`, netem delay *and* loss legs,
  last-holder residue, orphan-`seg` sweep); the **dial** set (echo + EOF both ways per endpoint
  arm, dead-port typed error, the echo-server-as-`init=` leg); the **injection** set (in-guest
  `cat`/`stat`, reserved/duplicate-dest rejects, cache-key invalidation); the **toolkit** set
  (overlay wins/falls-back/rejects-typos, resolved-config sidecar, classifier red-on-inverse, the
  example workspace's consumer loop); and the **NAT window** set (host→guest *and* guest→host
  window-filling transfers, digest-compared against a backpressuring peer).

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
  static-only — say so explicitly and mark every runtime claim unverified. The crosvm matrix is an
  **opt-in recipe** (`just test-crosvm`) because CI lacks the binary; its KVM-free honesty pins
  always run. `just test-usb-passthrough` is opt-in for the same reason: it needs a designated
  device (`VMCELL_TEST_USB_DEVICE`), and without one `test-privileged` records a capability skip.
- **Guest-side code is baked into `rootfs.erofs`.** A change to `vmcell-guest-agent` or
  `vmcell-guest-tools` means nothing to a live suite until the artifacts are rebuilt — and the
  rebuild is `vmcell build --kernel-source host-make`: the bare default is `prebuilt`, which
  silently **replaces** a locally built `vmlinux` with one lacking `CONFIG_KVM_INTEL` /
  `CONFIG_HW_RANDOM_VIRTIO` and reddens `nested_virt` and `snapshot_restore`.

## Done means

- `just ci` green locally (it is the CI definition; both set `RUSTFLAGS=-D warnings`).
- For host-facing changes: both operating-mode suites green per the section above, all backends the
  change touches, `just test-daemon` for daemon-touching changes, `just test-crosvm` for
  crosvm-touching ones, the example-workspace job for contract-touching changes, and the skip
  manifest reviewed.
- New public API: rustdoc complete (`missing_docs` denies), `cargo semver-checks` clean (both contract
  crates — the toolkit section above). A change implementing a delta-register item ships that item's
  named gate and reconciles `docs/implementation-notes.md`.
- The privileged runner is re-blessed after rebuilds (`just bless`; blessing is stripped on rewrite
  by design).

## Performance claims

- Benchmarks are tracked metrics, not gates; only relative invariants graduate to guards.
- Check the `docs/historical/45` refuted-lever table before proposing a lever; only interleaved
  same-session deltas are evidence; name the budget a change must not regress.
- "Environmental" is a hypothesis, not a diagnosis: a flake explanation without a mechanism stays
  open (the ~10% smoltcp bring-up flake is the recorded open instance, with its named fix owner —
  design §17). Tail figures from before 2026-07-03 use the broken `floor(n·q)` estimator — not
  comparable.

## Docs and dependencies

- Docs state each fact once, in present tense, terse, with trade-offs stated honestly. Counts and
  rosters quoted in docs (capability flags, crate lists, suite tallies) are checked against the
  tree, never from memory — stale counts were a recurring v5-era defect. Prefer a **pointer** to the
  recipe that produces a number over an embedded figure that goes stale silently.
- Dependencies: permissive licenses only (cargo-deny allow-list enforces); the libseccomp-wrapper
  crates are `[bans]`-denied by name (LGPL-2.1 C link invisible to the scan); `cargo deny` ignores
  carry a per-crate rationale; vendored patches (`vendor/vhost*`) keep exact `=` pins — a caret
  requirement silently drops the patch, and a **git-dep consumer must replicate the
  `[patch.crates-io]` stanza** (design §10.4; `scripts/check-vendored-vhost.sh` is the
  consumer-runnable check, and it distinguishes not-applicable from not-patched).
- Toolchain: `rust-toolchain.toml` pins 1.96.1 and the declared `rust-version` **equals** it (one
  `[workspace.package]` fact, sync-asserted). An understated MSRV lets MSRV-aware resolvers
  re-resolve older consumers onto vulnerable dependency versions (the `time 0.3.45` class). Build
  `--locked`; never `cargo update` on an older toolchain. A dep bump's **compiler-invisible
  behavior changes** (a TLS trust-anchor swap, a default-feature rename) are named in the bump's
  notes, not discovered later.
- No unused dependencies (`cargo machete`; macro-only false positives get a per-crate ignore).
  Third-party GitHub Actions stay pinned to full commit SHAs; Dependabot moves the pins.
