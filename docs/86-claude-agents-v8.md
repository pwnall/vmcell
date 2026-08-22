# AGENTS.md — vmcell

Deploy at the repository root as `AGENTS.md`. Terse by design; the reasoning lives in
`docs/84-claude-fable-code-review-rubric-v7.md` (rubric v7) and `docs/93-claude-opus-design-v34.md`
(design v34, the regression-harness pass; v33 is now `docs/historical/83-claude-fable-design-v33.md`).

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
`vmcell-protocol`, `vmcell-steward` (the in-guest control-plane process — a library plus a thin binary since v33
delta 5, running as PID 1 by default or as a service under somebody else's init; the v33 delta-1 rename of
`vmcell-guest-agent`, identifier-scoped: "agentic execution" domain text and this file's name keep
"agent"), `vmcell-test-runner` (privileged
capability runner), `vmcell-guest-tools`, the rootfs/kernel builders, `vmcell-privilege` (shared
cap/blessing predicates), and the control-plane tier: `vmcell-daemon` (lib), `vmcelld` (binary),
`vmcell-daemon-client`, `vmcelld-ctl`, and `vmcell-broker` (the privileged spawn helper). Two
operating modes: **unprivileged** (KVM group only, smoltcp NAT) and **privileged** (three caps,
netns/tap/nft, the only snapshot-eligible mode). Crate versions are **not quoted here** — the one
that used to be went stale inside a single review pass. Read the `version` from the crate's own
`Cargo.toml`; `vmcell`'s and `vmcell-artifact-validator`'s carry the ledgered comment changelog a
contract-surface bump must extend (see "The downstream toolkit contract").

## Read before changing anything

- `docs/implementation-notes.md` — recorded, justified deviations and the as-built reconciliations
  (the landed 0.9→0.10 pass, the docs/72 fixes, the backend/crosvm/QEMU-restore passes, the v30
  delta register, the docs/78 + docs/81 review passes, the v33 reissue record). Do not "fix" entries listed there; record new justified
  deviations there instead of silently diverging. Retire an entry when it is empirically disproven.
- `docs/99-claude-fable-code-review-rubric-v9.md` — every rule below is expanded there with its
  defect history. Its **Retired & qualified rules** section lists former demands the design
  supersedes or scopes (incl. the exhaustive-contract-types qualification) — don't re-open them.
  (`9` represents an arbitrary digit and `*` the authoring model — both vary across revisions; use the newest version you find.)
- `docs/historical/85-claude-fable-automated-quality-v5.md` — the gate specifications (lint
  preambles, ban scripts, recipes, the delta-gate table, the coverage map). **Retired**: there is no
  non-historical copy, so read it for rationale, never for a roster. The live roster is the `gates`
  recipe plus each script's own header.
- the newest non-historical `docs/*-code-review.md` (today `docs/90-claude-opus-code-review.md`) —
  the standing code review; a finding it records is not a fresh discovery. Earlier passes are
  retired under `docs/historical/`.
- `docs/benchmark-results.md` — measured perf levers; the 2026-07-17 matrix is canonical.
- `docs/99-claude-*-design-v99.md` — architecture; **§13** lists the cross-cutting invariants,
  lettered S/C/L/F/P/G, each with an owner and a gate; **Appendix A** records the load-bearing
  reversals (cite them, don't re-argue); **§17** is the open-gaps register. **No standing errata**:
  a correction is folded into the body when the design is reissued.

## The delta register binds implementations, not the baseline

Design §18's register is the mechanism for directing changes that are **specified but not yet
built**. The v30 downstream-platform register (deltas 1–9) is **landed**; the code no longer
legitimately differs from it. **The v33 register is CLOSED — all ten deltas landed** (design §18): 1 the steward
rename; 2 the feature vocabulary + intersection (R3, §7.4); 3 the two-directional conformance kit
(R4, §10.6); 4 steward placement (R1, §3.5); 5 the steward as a library / service mode (R5, §3.5);
6 the artifact registry — rootfs + handler kinds, lazy, digest-only (R2+R7, §10.5); 7 external
repacking + per-artifact xattr policy (R6, §4.2/§4.7); 8 the ext4 producer (separable); 9 the
systemd proof cell (opt-in capstone); 10 daemon placement exposure (separable). Deltas 2–7 land as
one breaking release; 1 lands first and alone. These conventions bind:

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
- **A gate binds the call sites, not just the extracted predicate.** Two of the six
  completeness-audit PARTIALs were invisible precisely because a green unit test stood beside an
  unchanged call site; a one-law delta names its call-site scan alongside its predicate tests.

## Non-negotiable rules

1. Every recurring defect class becomes a lint, a CI job, or a test that can go red. A fix for a
   defect a human found lands **with its gate**.
2. Every test and every gate must be able to fail. Write the red-on-inverse first; a gate whose
   self-test cannot fail is theater.
3. CI executes what it claims: filters select > 0 tests (`--no-tests=fail`), lean targets are built
   and clippied (a `cargo tree`-only check compiles nothing), accepted-red steps run last or
   non-gating so they never short-circuit other gates. A CI step that hand-copies a `just` recipe
   drifts from it — invoke the recipe (`run: just test-unprivileged`) so local ≡ CI by construction.
   That applies to the **gate roster** too: every ban/check script, every red-on-inverse self-test,
   and the `shellcheck` pass live in the one `gates` recipe, which both `just ci` and `ci.yml` call
   (`run: just gates`); a new script is added to that recipe and nowhere else. The hand-copy had
   already drifted three times, so `scripts/ban-ci-script-handcopy.sh` is the meta-gate: it runs
   first, fails if `ci.yml` names a `scripts/*.sh` directly, and asserts the recipe's roster equals
   the gate-shaped scripts on disk in **both** directions (orphan script *and* stale entry).
   `scripts/ban-recipe-body-handcopy.sh` closes the same class one level in — a restated recipe
   **body**: it reads bodies back through `just --show` (the recipe is the authority) and fails if
   the `ci` recipe or `ci.yml` contains all of another recipe's lines instead of calling it, matching
   interpolated lines as globs so an expanded copy is caught too. Both halves had shipped: ci.yml's
   inlined `test-unprivileged` command lost `--features qemu` (a backend's matrix legs stopped
   compiling in CI), and `ci` carried a verbatim copy of the `test-unit` body.
   Anything parsing `cargo` output belongs in a script, not a `run:` block: CI exports
   `CARGO_TERM_COLOR: always` and `just ci` does not, which silently killed three `cargo tree` bans
   — `ban-uncolored-cargo-parse.sh` is that class's gate.
4. Enumerate what the suite structurally cannot reach — error branches, non-default configs and
   flows, defaults, window-filling payloads **in both directions**, security inverses, **and the
   effect classes your fakes are blind to** (`FakeVmm` never touches the filesystem — the lineage
   `create_dir_all` was invisible to every fake-driven test; no test moved bulk data *guest→host*
   through the NAT, which is why a ring-wrap panic shipped). **A knob nobody boots is a claim nobody
   makes**: docs/90 found three of four `ResourceLimits` fields, four `VmConfig` knobs and a
   `ConsoleMode` variant with no live boot behind them. And a channel whose two ends default to the
   *same* value is unfalsifiable by construction — the guest's compiled cadence fallbacks equalled the
   host's emitted defaults, so deleting the guest's parser changed nothing any test could see. Cover
   it or record it.
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
  grown by field, never by positional argument): spawn entry points take `&HostEnv`, `steward()`
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
  and the `capped_debug` renderer beside them, `pcts`, and the cache-key rules (F4). The docs/81
  pass added six more, each because the duplicate form had already diverged:
  `vmm::reject_unadvertised_capabilities` (`nested_virt` / `lazy_restore`) beside its siblings
  `reject_unsupported_console` and `reject_usb_host_devices` — one shared refusal per capability
  field, keyed off the descriptor handed in, never a hardcoded `false` at the refusal site;
  `vmm::VMM_SOCKET_READY_TIMEOUT_MS`, the one VMM-control-socket readiness ceiling, which
  `register_and_await_ready`/`wait_for_vmm_socket` take as *no argument at all* so a per-backend
  literal is a compile error; `vmcell_protocol::GUEST_TOOLS_APPLETS`, the host↔guest applet roster
  the guest-tools dispatch table is `const`-asserted against element-wise and the rootfs injection
  manifest emits from; `VmmProcessGroup::is_reaped`, the read-only reaped flag (no setter, so no
  call site can re-arm a signal at a recycled pgid); `metrics::vm_slice_name` — now `pub` and
  re-exported as `naming::vm_slice_name` — the **full** cgroup slice name, of which
  `naming::cgroup_slice_name` is only the leaf, so no reader hand-formats the path; and
  `artifact::kernel::kernel_artifact_key`/`kernel_pin_key`, the kernel artifact-key and pin-key
  composers. The v33 pass adds, each directed with its call-site scan:
  `StewardPlacement::steward_port` + `StewardPlacement::resync_reachable` (C8 — **two methods for
  two questions**: availability vs snapshot-eligibility, which differ exactly at `Service`; the
  pre-v33 tree spelled availability three accidentally-equivalent ways, and `cfg.init` decides
  init *identity* only, at the one cmdline site); the `vmcell::feature` intersection's one
  computation site (F6 — unknown
  feature tokens are hard errors, and refusal feature strings are composed from `Feature::name()`,
  so substring matchers on refusal messages are banned); the registration-is-a-digest rule (F7 — a
  path is an override, `bundle` refuses unpinned); the one registry merge/collision/sort core
  shared by the kernel/rootfs/handler kinds; `XattrPolicy` as a parameter of the one inject+pack
  tail; and `STEWARD_VSOCK_PORT` single-sourced in `vmcell-protocol` (retiring the mirrored
  host/guest 5000s). The docs/90 pass adds seven more: `PackOptions::handler_key` /
  `artifact::handler::handler_artifact_key`, the one answer to "which handler artifact does this
  rootfs bake?" — the pack tail spelled the default key as a literal, so a labelled handler was
  published under `guest_tools-<label>`, read as absent, and the image shipped with **no** multicall
  binary and no applet symlinks at all while the build reported success (H1);
  `config::is_cmdline_unsafe_char`, the character law for every cmdline-encoded input (`init=`
  override, append-only arg, share tag, share `guest_path`) beside `is_reserved_cmdline_arg`, whose
  `normalize_cmdline_key` now folds the kernel's leading `"` as well as `-`, because one quote
  defeated every reserved key and was reachable from any authenticated REST client (M3);
  `net::tap::netns_path` / `netns_dir` over the one `NETNS_DIR`, now the only spelling of the
  `/var/run/netns` layout — the rustdoc claimed "exactly one place" while four production sites
  composed it inline, and nothing could see that claim age; `vmcell::artifact::ch_binary_path`, the
  one `VMCELL_CH_BIN` resolver (two byte-identical copies closed this pass, one of them in the CLI
  every VM-lifecycle verb went through — and §17's own consolidation register had named only two of
  the three);
  `orchestrator::control_plane_probe_budget`, where the **placement** picks the health-gate window
  (`Pid1` keeps the tuned constant, `Service` gets the caller's default connect budget, because that
  constant re-boots a slow-but-healthy systemd cell to exhaustion by its own health check — M2); in
  each backend that reports its own endpoint, the one `steward_endpoint` composer, so the endpoint
  baked at spawn carries the **declared** port (the trait default bakes `STEWARD_VSOCK_PORT` and only
  `MicroVm::steward` re-keys it, so QEMU's gate probed 5000 at a cell listening on 5100 and killed a
  healthy cell four times — M1); and `vmcell_protocol::STEWARD_ACCEPT_POLL` / `STEWARD_REBIND_IDLE`,
  the two kernel-cmdline cadence tokens each side reads — the host's emitted defaults and the guest's
  compiled fallbacks were four literals in two crates, so deleting the guest's parse block left every
  test in the tree green (G7). Never write a second copy — every duplicate so far has diverged. Where a law's drift is
  **not** a compile error it carries a grep-ban plus a red-on-inverse self-test —
  `ban-inline-setns.sh`, `ban-inline-netns-path.sh`, `ban-kernel-key-composers.sh`,
  `ban-handler-key-composers.sh`, `ban-readiness-timeout-literal.sh`, `ban-artifact-path-join.sh`,
  `ban-ch-binary-resolver-copies.sh`; `just gates` is the full roster — read it, never count from
  here. A new law of that shape earns one. Where an in-source scan already owns one crate, the shell
  gate is its **complement** rather than a second copy: it scans the other crates, **names its
  delegate**, and fails loud if that gate or the const it reads its needle out of is gone — and it
  bans the layout's **alias** (`/run/netns` reaches the same directory as `/var/run/netns`), F3's
  alias class one level out.
  A source-scanning ban treats a **zero-file scan** as `gate misconfigured` and exits non-zero, never
  a green `ok:` — the only way to open nothing is to have been pointed at nothing — and its self-test
  carries the empty-tree leg proving that arm. Write both with the script: eight bans wore a green
  verdict on an empty tree until a review pass swept it (docs/90 G4).
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
- PID-1 discipline in the steward (C1 — scoped to the `Pid1` placement): never `exit`; reap
  children via the `ReaperCoordinator` epochs; signal handling per §3.4; **zero netlink and zero
  new guest code for segments** — members still learn their address from the kernel `ip=` token
  (C6). A PID-1 panic aborts the guest, so the steward binary keeps the full deny family
  (`unwrap_used`, `panic`, `print_*`). In **service mode** (v33 §3.5) the fatality inverts by
  design: no filesystem assembly, a graceful SIGTERM shutdown, `PR_SET_CHILD_SUBREAPER` on — the
  placement parameterizes the contract, never forks the code. No blocking I/O
  on the dispatch path: a child that stops reading stdin must not wedge the connection past its
  teardown.
- Deadlines are `Instant`, propagated outer-bounds-inner, and bound the **whole** operation, not the
  gaps between its polls — a budget checked only between iterations does not bound a wedged
  connect, read, or write. Concurrent startup is cancellation-safe (`spawn_clones` is the shipped
  all-or-nothing pattern; `try_join_all` over daemon starts is the recorded rejection).
- Runtime files under `XDG_RUNTIME_DIR` (or the artifacts dir), never bare `/tmp` on shared hosts —
  the un-prefixed `/tmp/vmcell-vmid` / `/tmp/vmcell-segid` id-lock dirs are the recorded
  cross-process-rendezvous exception (deliberate, not swept, don't "fix").
- Serial/console logs are persisted artifacts: no secrets in kernel cmdline, steward output, or logs —
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
  re-restorable. A daemon extra disk is read-only by default and `writable: true` attaches a
  **private copy-on-attach clone** through `env.overlay.clone_file` — the store artifact is never
  attached writable, and the copy dies with the VM; the
  no-`init=`-over-REST rule is scoped by v33 delta 10 — `Service` placement + a custom init becomes
  expressible (it keeps the control plane, the rule's own rationale), while placement `None` stays
  unexpressible over REST.
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
pins schema + overlay — v33 adds the rootfs/handler registry namespaces (§10.5) —
`Stage`/`Pipeline`/`ResolvePinsStage`, the kernel/rootfs/handler build entry points + the
resolved-config and feature-manifest sidecars, `pack_rootfs_with_injection` (the format-selecting
tail, with `pack_erofs_with_injection` as its erofs-only door) + `ExtraFile` + `XattrPolicy` +
`RootfsFormat`, the labelled pack surface (`PackOptions`' `with_label` / `with_handler_label` /
`with_applets` / `with_xattrs` / `with_format`, beside `rootfs_filename` / `rootfs_artifact_key` /
`handler_artifact_key`), the `VMCELL_*` env table, and
the `vmcell-artifact-validator` battery (whose `CheckStatus` grows `Warn`/`Unverified` in v33 and
whose `ValidationOptions::run_budget` bounds a whole run — ledgered validator bumps). `Cache` survives
as a parameter of listed surface, a **documented inert placeholder**: dropping the argument is a break
a consumer is versioned through, not a tidy-up, and its gate reddens the moment the handle starts
carrying anything. Rules: a change to listed surface is a **deliberate,
ledgered version bump** (the `Cargo.toml` comment changelog), never discovered by a consumer's
build breaking. Three gates hold three different halves and none covers another's: `semver-checks`
covers `vmcell` *and* the validator and gates the version **number** against the signatures that
moved — silent by construction on an addition, and on any behavior change behind an unchanged
signature; `crates/vmcell/tests/contract_ledger.rs` gates the ledger's own **shape** (an unbroken
`# <from> → <to>:` chain ending at the version that crate publishes; it had a two-version hole at
its most breaking release, because no lint sees a missing comment); and the out-of-tree
`examples/downstream-kernel/` workspace gates the **guidance** by compiling against it —
**breaking its CI job is the intended failure mode of contract drift**, and "fixing" the example to
stay green instead of versioning the contract inverts the gate. What no gate supplies is the entry's
prose; write it for the consumer who is migrating, and read the edge in the manifest rather than a
version quoted here. Design §1.3's *other* designed-in extension point is deliberately **not** on
this list and needs its own care: `proxy::doubles`' `Matcher`/`Responder` are aliases over
third-party types, so that module re-exports `hudsucker` and `hyper` at the exact versions the
aliases are built from — a consumer names them through vmcell instead of pinning them out of
vmcell's `Cargo.lock`, and a doctest compiles the documented spelling. The `VMCELL_*` semantics are specified (`VMCELL_ROOTFS`
= full ensure no-op; `VMCELL_KERNEL` = path redirect that still requires existence; `VMCELL_PINS`
= the overlay; the `VMCELL_*_BIN` resolvers are the one way any harness finds a VMM binary —
`bench-vm` included; downstream getters fail loud naming the two-step route — a recorded deviation
from the FR's letter, cite it). vmcell ships **mechanisms, never consumer content** (G1): example
fragments are self-proving mechanism proofs (IKCONFIG); the generic `usbhost` capability-gate
fragment is the one defended exception shape and never carries a consumer's usbip/gadget closure.

## Unsafe, FFI, and the guest boundary

- Kernel ABI structs are `#[repr(C)]`, defined once, with `size_of`/offset asserts against the ABI —
  no inline byte-math reimplementations (the 18-byte `ifreq` wrote 22 bytes past a PID-1 stack).
  Where a second copy is deliberately kept (guest-tools beside the steward's `netif`), the deviation
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
  example workspace's consumer loop); the **NAT window** set (host→guest *and* guest→host
  window-filling transfers, digest-compared against a backpressuring peer); and the v33 sets
  (design §15.4): the **placement** set (the `Service{5000}`+`init: None` composition leg; the
  discriminating `Service`+custom-`init` refusal-identity leg — the arm that reddens on the
  `cfg.init` re-key; the `Service`-cell `snapshot()` typed refusal via `resync_reachable()`; the
  `None` fail-loud leg; the byte-identical-default cmdline pin; the C8 two-method call-site scan);
  the **service-steward** set (under `mini-init`: the orphan-`PPid` leg, red by removing the
  subreaper call — **not** the design's sketched double-fork *hang*, which does not reproduce
  because the steward only ever waits on its own direct child, see implementation-notes; both
  SIGTERM legs — service: C3 residue gone, clean exit, mini-init restarts it,
  guest stays up; `Pid1` powers off — plus the declared-port and rapid-failure-cap legs, and this
  otherwise-CH-only file's one **QEMU** member: the declared-port *health-gate* leg on the external
  `vhost-device-vsock` transport, the only shape `verify_control_plane` probes, whose whole assertion
  is that `start()` returns. Its serial
  assertions must be on `mini-init`'s `println!` output or on the kernel's own lines: the steward
  logs at `info` and the guest has no `RUST_LOG`, so `tracing_subscriber` keeps everything below
  `error` off the console); the **steward shutdown** set, KVM-free and in-crate (the service sweep
  kills a live one-shot `exec` child — its pgid used to live only in the connection thread's stack
  frame, so a `systemctl stop` mid-`exec` orphaned it under the real init; an unwinding connection
  thread still tears down its sessions' process groups *and* its in-flight one-shot children, C3; and
  the shutdown flag is checked at **both** `serve_vsock` loop levels, one leg each, since a flag set
  before the loop has bound anything is answered by the outer check and leaves the inner one
  unfailable); the **feature** set
  (two-sided provenance — the same artifact's removal names the rootfs on one backend and the
  backend on the other; misspelled-token hard error; `require()` refuses pre-boot); the
  **conformance** set (the four-leg present/absent × capable/incapable matrix, paired
  positive-control ids, the `Warn` lifecycle, roster gates on all three levels, the battery
  budget bounding the **whole** run typed, and the setup-failure leg: an absence-declaring artifact
  that cannot boot is `Unverified` — never the `Pass` a *verified* absence earns — with a source scan
  keeping the setup/measurement line where the shipped probe draws it, plus the KVM-free scan that
  each live leg's stated fake-blind axis is still what its probe answers); the **registry** set
  (same-digest-two-labels byte-identity + unmoved default key,
  laziness red on eager, corrupt-blob digest mismatch, bundle-refuses-unpinned, legacy-shape
  reject, the registered-`format: ext4` leg end to end — entry → the one inject+pack tail → the
  external producer, asserted on the ext4 superblock **bytes**, since an erofs image under an `.ext4`
  name satisfies every filename assertion — with the KVM-free seam twin in `oci::tests`, and the live
  handler leg: a registered handler's own `xattr` applet answers in-guest while an applet in vmcell's
  const but *not* in the entry's roster is absent, which is what proves the symlinks came from the
  registry entry); the **xattr** set (the `Preserve` twin + in-guest `xattr get` readback with the
  `Strip` negative control); the **ext4** set (pack → boot as `Block` → in-guest tree/xattr/device
  diff; version-probe typed refusal); the **limits** set (`cpu_max_pct` read back off `cpu.max` *and*
  measured under the un-throttled leg's own floor, `pids_max` proven by `pids.events`' `max` counter
  against a host co-tenant load, `io_max` refused loud with the same config minus the limit as the
  positive control); the **console** set (`VirtioConsole`: the active console pinned *and* a marker
  through `/dev/console` landing in the host `serial.log`); the **iops** set (two disks in one VM,
  `iflag=direct` so the cap binds operations rather than a coalesced readahead); the **confinement**
  set (a *running* CH's `NoNewPrivs` and loaded seccomp filter, with `JailConfig::disabled()` +
  `VmmSeccomp::Disabled` booted seconds later on the same host as the control, plus the ambient-set
  leg that asserts — never skips — that it runs blessed); and the **guest-tuning** set (a declared
  `rebind_idle` measured from the distinct `/proc/1/fd` socket inodes PID 1's re-bind loop creates,
  against a default-window twin differing in exactly that one variable, because the steward's own
  resolved-cadence log sits below the console's `error` filter).

## Running the privileged suites — probe, don't presume

- "Am I on a KVM host?" is answered by `scripts/review-preflight-priv.sh`, never by assumption.
  Hesitating instead of probing is the exact failure mode the preflight exists to remove.
- The blessed runner exists so that *you*, unprivileged, can run the privileged suite: nextest
  invokes `.vmcell-bin/debug/vmcell-test-runner` (the `runner` variable at the top of the
  `justfile`), which carries `BLESSED_FILE_CAPS` — the delivered `PRIVILEGED_CAPS` plus the
  **transient** `CAP_SETPCAP` the bounding-set shrink needs, dropped again before `exec`, so no test
  or VMM ever holds it. No sudo, no root shell; cargo and the tests stay yours. `just bless` also
  blesses a release copy, which no recipe invokes today. Every runner-wrapped recipe
  (`test-privileged`, `test-daemon`, `test-validator`, `test-bench`, `test-crosvm`,
  `test-usb-passthrough`, and v33's `test-systemd`) uses
  that same debug runner; `test-unprivileged` deliberately runs without it, which is what keeps the
  unprivileged path honest. `test-daemon` wraps itself in the delegated scope; every other live
  suite is wrapped at the call site (`systemd-run --user --scope -p Delegate=yes
  scripts/with-delegated-scope.sh just <recipe>`), the way `ci.yml` invokes them — the cgroup legs
  need a delegated subtree and fail without one.
- Preflight green → run `just test-privileged`, the unprivileged suite, `just test-daemon`, and
  `just test-validator` yourself.
- Preflight failing only on blessing (runner missing, stale stamp, not `+ep`) → **run `just bless`
  yourself**, then rerun preflight and the suites. Escalate to the maintainer *only* when it actually
  needs a `sudo` you cannot supply. That is safe to attempt blind because the recipe stages and swaps:
  `bless_one` blesses a temp copy and renames it into place, so a declined or non-interactive `sudo`
  leaves the existing blessing intact rather than replacing it with a cap-less binary — the failure
  mode is "still stale", never "silently un-capped". Never silently skip.
  Which arm you get is decided by the recipe's idempotence check, which hashes the freshly *built*
  runner against the stamp:
  - **Binary unchanged** → it re-dates the stamp and skips `setcap` entirely. **No sudo.** A
    `Cargo.lock` move that touches nothing in the runner's own closure is this arm, and so is any
    codegen-neutral edit — *for the release copy*.
  - **Binary changed** → `setcap`, which needs a sudo; a non-interactive shell fails with
    `sudo: a terminal is required to authenticate`. Ask the maintainer, quoting that.
  The two copies can legitimately disagree, and it is not a bug: `debug` carries DWARF line tables and
  `release` (cargo's default `debug = false`) carries none, so a comment-only edit above live code
  shifts the debug binary's bytes and leaves the release binary byte-identical. Expect "only the debug
  runner needed re-blessing" and do not report it as an anomaly. Never *promise* which arm you will
  hit before you have run it.
- Only a genuinely absent facility (`/dev/kvm`, a missing backend binary) downgrades you to
  static-only — say so explicitly and mark every runtime claim unverified. The crosvm matrix is an
  **opt-in recipe** (`just test-crosvm`) because CI lacks the binary; its KVM-free honesty pins
  always run. `just test-usb-passthrough` is opt-in for the same reason: it needs a designated
  device (`VMCELL_TEST_USB_DEVICE`), and without one `test-privileged` records a capability skip.
  v33's `just test-systemd` (the R1+R2+R5+R6+R7 proof cell) is opt-in for the same class of
  reason: it pulls a full-Debian image; its KVM-free halves run everywhere. The **ext4** batteries
  need no opt-in — `test-privileged` selects them — but they do need a `mkfs.ext4` new enough for the
  `-d <tarball>` form, so they ask `common::probe_ext4_or_record_skip`, the one law shared by
  `ext4_cell` / `ext4_producer` / `repack_outside_checkout`: it records
  `SKIP cloud-hypervisor ext4_producer` when the facility is genuinely absent or below
  `MIN_E2FSPROGS_VERSION`, and **panics** when the product's probe calls it broken rather than absent.
  `rootfs_registry`'s `format: ext4` leg reaches those same two outcomes from the other side — it asks
  the pack call and reads its typed `CapabilityUnavailable` as the absence, recording the same skip
  token and panicking on anything else — because pre-probing would skip past the erofs-only door that
  leg exists to assert.
  A green privileged run is therefore not by itself evidence the ext4 claim was verified — the skip
  manifest is the only thing that answers that. CI obtains the facility instead of living with the
  skip: `ci.yml` builds a pinned, checksum-verified e2fsprogs ahead of the suites, non-gating, so a
  failed install degrades to that recorded skip rather than a red job, and
  `ci_obtains_the_ext4_facility_rather_than_living_with_the_skip` is that step's gate.
  `just test-bench` is the
  one invocation that selects `vmcell-bench`'s three `#[ignore]`d live legs (fc, qemu, crosvm) — the
  composition root wiring every backend had no can-it-go-red proof anywhere before it. Its argument
  is a **features list** defaulting to `cloud-hypervisor,firecracker,qemu`, so the crosvm leg is
  never compiled where there is no binary; a list omitting `cloud-hypervisor` is rejected up front
  (`bench-vm`'s `required-features` would otherwise build no binary and fail inside a test). Only
  that crosvm leg is opt-in, through the explicit list — `just test-bench cloud-hypervisor,crosvm` —
  while the default list runs in CI's kvm job under a delegated scope, like `test-validator`.
- **Guest-side code is baked into `rootfs.erofs`.** A change to `vmcell-steward` or
  `vmcell-guest-tools` (any applet — `mini-init` and `xattr` included) means nothing to a live
  suite until the artifacts are rebuilt — and the
  rebuild is `vmcell build --kernel-source host-make`: the bare default is `prebuilt`, which
  silently **replaces** a locally built `vmlinux` with one lacking `CONFIG_KVM_INTEL` /
  `CONFIG_HW_RANDOM_VIRTIO` and reddens `nested_virt` and `snapshot_restore`.

## Done means

- `just ci` green locally (it is the CI definition — it calls the same `just gates` recipe `ci.yml`
  does; both set `RUSTFLAGS=-D warnings`). It also invokes `just test-doc`, the only gate that
  compiles the `///` examples (nextest cannot run doctests, so before it nothing did), which is what
  gates a doctest on the contract surface — and makes worked examples on the front door safe to add.
- For host-facing changes: both operating-mode suites green per the section above, all backends the
  change touches, `just test-daemon` for daemon-touching changes, `just test-crosvm` for
  crosvm-touching ones, `just test-validator` for changes to the artifact-conformance battery (its
  live legs are `#[ignore]`d and only that recipe selects them), `just test-bench` for changes to the
  `bench-vm` harness or a backend's wiring into it (same shape), the example-workspace job for
  contract-touching changes, the conformance kit's four-leg matrix for changes touching a declared
  feature, the registry byte-identity/unmoved-key gates for changes touching artifact identity,
  `just test-systemd` for changes touching the placement/registry composition (opt-in, the crosvm
  rule), and the skip manifest reviewed (`just skip-manifest-reset` before the
  sequence, `just skip-manifest-show` after, so the skips belong to this run) — that manifest is the
  only place an `ext4_producer` skip shows up, so an ext4 claim is unverified until it is read.
- New public API: rustdoc complete (`missing_docs` denies), `cargo semver-checks` clean (both contract
  crates — the toolkit section above). A change implementing a delta-register item ships that item's
  named gate and reconciles `docs/implementation-notes.md`.
- The privileged runner is re-blessed after rebuilds (`just bless`; blessing is stripped on rewrite
  by design). The recipe re-dates the blessed copy even when the rebuild is byte-identical, so
  running it actually clears the preflight's stale verdict instead of leaving the documented reviewer
  path wedged at BLOCKED-ON-BLESS; `scripts/test-bless-redates-blessed-copy.sh` is that behavioural
  gate — it drives the real recipe against the real preflight in a throwaway fixture tree, with no
  cargo, no sudo and no KVM.

## Performance claims

- Benchmarks are tracked metrics, not gates; only relative invariants graduate to guards.
- **"Did this regress?" is `just bench-ab`, never a diff against a recorded table.** Two prepared
  arms (`just bench-ab-prepare <ref> <label>`), interleaved on one host in one session, rank-tested
  over repeats — design §16. The recorded tables are absolute numbers *with their substrate*, and a
  substrate change voids the comparison in both directions: the 2026-08-21 pass ran on a different
  machine than every table in `docs/benchmark-results.md`. `bench-ab` verifies its controls by
  **digest** rather than by exported variable (an arm older than a `VMCELL_*` var silently ignores
  it — that is how two arms once booted two kernels for a whole matrix) and refuses rather than
  warns when one is violated.
- **A single p50 is not evidence.** Of six single-pass deltas ≥10% in that pass, five did not
  survive repeats and one reversed sign — after a mechanism hunt had run to completion against one
  of the phantoms. Below four repeats per arm `bench-ab` prints no verdict at all, and the verdict
  it does print keys off the **Holm-Bonferroni adjusted** p over the rows that can receive one
  (twenty uncorrected tests at 0.05 print a phantom 64% of the time), with the family size and the
  raw p both shown. Three more outcomes are deliberately not verdicts: `sample loss` (an arm whose
  percentiles are over a shrunken sample set — the surviving boots are the fast ones), and
  `no direction` for a compositional share or a metric outside the `vmcell_bench::metrics` roster.
  That roster is the one place a metric's direction lives, `bench-vm` refuses to emit a name it does
  not carry, and each arm's notes are surfaced with an asymmetry (one arm `cpufreq: NOT pinned`,
  the other not) called out loud.
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
- Every pointer resolves, and two gates say so: `scripts/check-docs-pointers.sh` over the root
  markdown plus `docs/*.md`, and `scripts/ban-dangling-design-ref.sh` over `crates/*/src`, where
  ~2000 `§`/`Appendix` references cite the design because nearly every law's rustdoc does. Both
  resolve against the **discovered newest** design document's real headings (one resolver,
  `scripts/design-headings.sh` — it makes no claim about the tree, so it is not gate-shaped and is
  not on the `gates` roster). So **do not renumber or delete a design heading**: those references
  are its call sites, and a renumbering is a change to all of them. A reference into another
  numbering must say which (`v30 §9.4`, `docs/78 §5`) and is skipped. The class shipped in a document
  the daemon hands to *clients* — the served OpenAPI's own description pointed consumers at a design
  section that does not exist.
- Dependencies: permissive licenses only (cargo-deny allow-list enforces); the libseccomp-wrapper
  crates are `[bans]`-denied by name (LGPL-2.1 C link invisible to the scan); `cargo deny` ignores
  carry a per-crate rationale; vendored patches (`vendor/vhost*`) keep exact `=` pins — a caret
  requirement silently drops the patch, and a **git-dep consumer must replicate the
  `[patch.crates-io]` stanza** (design §10.4; `scripts/check-vendored-vhost.sh` is the
  consumer-runnable check, and it distinguishes not-applicable from not-patched).
- Toolchain: `rust-toolchain.toml` pins 1.98.0 and the declared `rust-version` **equals** it (one
  `[workspace.package]` fact, asserted in one place — `scripts/check-msrv-sync.sh`, which replaced the
  mirrored inline `sed` comparisons in the `ci` recipe and in ci.yml, a pair that could have drifted in
  *strictness* silently). An understated MSRV lets MSRV-aware resolvers
  re-resolve older consumers onto vulnerable dependency versions (the `time 0.3.45` class). Build
  `--locked`; never `cargo update` on an older toolchain. A dep bump's **compiler-invisible
  behavior changes** (a TLS trust-anchor swap, a default-feature rename) are named in the bump's
  notes, not discovered later.
- No unused dependencies (`cargo machete`; macro-only false positives get a per-crate ignore).
  Third-party GitHub Actions stay pinned to full commit SHAs; Dependabot moves the pins.
