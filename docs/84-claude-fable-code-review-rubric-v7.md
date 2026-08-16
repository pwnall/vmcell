# vmcell — Code Review Rubric (v7)

*Distilled from eight Claude review passes (docs 13, 17, 26, 27, 34, 37, 40, 46), two Gemini passes
(25, 33), the doc↔code reconciliation that landed the automated gates (docs/52), the landed v28 and
v30 delta registers with their as-built records (`docs/implementation-notes.md`), the **docs/78 and
docs/81 review passes** — 93 + 76 verified findings against the landed v30 system, their fix waves,
the adversarial completeness audit, and the CI-repair pass — and the **v33 design**
(`docs/83-claude-fable-design-v33.md` — the serial-nexus consumer-platform pass) with its ten-delta
register (§18) and its new cross-cutting laws (C8, F6, F7). Its job is to stop the **classes** of
defect those sources found from recurring — not to re-list individual findings. This **v7 rubric**
supersedes v6 (`docs/75`, reissued to `docs/historical/`); v7 **re-bases every v30 "delta N"
reference on the landed state** (the v30 register's nine items are as-built rules now, cited as
"the v30 pass" — the same move v6 made for v28), absorbs the post-v6 defect history (the
gates-that-cannot-go-red cluster, the accepted-inputs-no-datapath-reads cluster, the
unbounded-control-edge cluster, the daemon-`Registry` cluster, the local≢CI-by-construction
cluster), adopts the **steward** vocabulary (v33 delta 1 renames the in-guest control-plane process
from "guest agent"; the rename is identifier-scoped — see "Retired & qualified rules"), and adds
Parts B17–B18 for the two surface families v33 introduces (steward placement + the service-mode
steward; the registry/features/conformance tier). Tagging: unmarked items carry over from v2
(reviews 13–34); **[37] [40] [46] [G]** mark items added or sharpened by that pass (G = the Gemini
passes); **[52]** the docs/52 reconciliation; **[28]** the v28 design and its landed pass; **[IN]**
items arising from the implementation-notes record between v28 and v30; **[30]** items arising from
the v30 design and its landed pass; **[81]** items arising from the docs/78 + docs/81 reviews, their
fix waves, the completeness audit, and the CI-repair pass; **[33]** items arising from the v33
design; **[BP]** best practices added on judgment, not yet matched to a surfaced defect.*

*The binding register is now **v33 §18: ten design changes specified but not yet built** — delta 1
(the steward rename) first and alone; deltas 2–7 (the feature vocabulary/intersection, the
two-directional conformance kit, steward placement, the steward-as-a-library/service mode, the
artifact registry with digest-only registration, external repacking + xattr policy) as one breaking
release; deltas 8–10 (the ext4 producer, the systemd proof cell, daemon placement exposure)
separable, with 9 the capstone that necessarily lands last. Rubric items tagged with a v33 delta
number bind the implementation of that pass; until an item lands, the code legitimately matches the
validated 0.14 state — flag divergence from a delta only in the change that claims to implement it.
The v33 §18 preamble's **five** register-authoring conventions govern how those changes are
reviewed: sketches advisory (behavior + gate bind); premises are verified anchors (v33's were
re-verified against HEAD by independent agents, and three of the requester's own premises were
corrected in the process — the count is the argument); fs/process-touching deltas name their live
gate up front; presence-attribute codecs round-trip on their real wire; and — promoted to a
convention by this pass — **a gate binds the call sites, not just the extracted predicate** [81].*

## Why this exists

Each rubric generation was built to kill the failure mode the previous one could not see:

- **v1 lesson (reviews 13–27):** the same defect families recurred because the test/lint/CI layer
  had no automated opinion on them; a human reviewer was the only thing between the bug and `main`,
  and a human reviewer is fallible five times running.
- **v2 lesson (review 34):** **a green CI can be a lie.** Skips counted as passes, filters selected
  zero tests, non-default build configs were never compiled, and "required" assertions passed on
  their own inverse.
- **v3 lesson (reviews 37, 40, 46):** with the v2 gates largely in place and the suites green,
  the surviving Criticals and Highs concentrated **on paths the suite structurally cannot reach**:
  mid-`start()` error branches, non-default configs and CLI flows, data-plane payloads large enough
  to hit backpressure, security assertions whose outcome is filter-independent, and the *default*
  value of an enum nobody tested. The second recurring source is **the second copy** of load-bearing
  logic — every duplicated helper eventually diverged, and the divergent copy is where the bug lived.
  Review 37 added a third: **static review alone is insufficient** — only actually executing the
  suites surfaced E1–E3, and only adversarial verification kept the findings honest.
- **v4 → v5 lesson (docs/52 + design v28):** the reviewed core stabilized while the system grew
  three privilege-sensitive subsystems — an authenticated HTTP control plane whose inputs name
  filesystem objects, a broker that splits capability from network parsing, and a jailer applied
  between `fork` and `exec` — each with defect classes (path traversal, timing-comparable secrets,
  postcard-corrupted presence attributes, ambient-cap stripping that broke the VMM it confined) the
  rubric had never named.
- **v5 → v6 lesson (the landed v28 pass + docs/72 + the backend/crosvm/QEMU passes + design v30):**
  **specifications drift from reality in both directions, and the drift is where reviews waste
  their time.** Premises stated as shipped fact were empirically false at implementation; sketched
  signatures could not survive contact; the design body accumulated stale claims and counts; and
  live validation kept reversing confident static reasoning. The v6 responses: premises carry
  verified anchors; sketches are advisory; counts are checked against the tree; and the first
  out-of-repo consumer made a *contract* reviewable.
- **v6 → v7 lesson (docs/78 + docs/81 + the fix waves + the completeness audit + the CI-repair
  pass):** **with the premise discipline in place, the surviving majors cluster in four shapes the
  gates themselves cannot see.** [81]
  1. **A gate that tests the extracted helper is not a gate on the claim.** Two of the completeness
     audit's six PARTIAL verdicts were invisible precisely because a green unit test stood beside an
     unchanged call site (`start_paced` with zero production callers; the M6 live gate that a
     comment *claimed* existed). crosvm's only seccomp confinement could be deleted — one token,
     `effective_jail_config(cfg)` → `&cfg.jail` — with its pure test, `just ci`, and the whole live
     `test-crosvm` matrix green (docs/81 M11); the P5 OpenAPI parity gate compared the document to
     the table it was generated from and never to the router (M10); `ban-legacy-terms.sh` printed
     `scanned: … justfile` while scanning zero bytes of it (M13). The response: **call-site
     binding** — a source scan, a fold-the-consumer-from-the-table construction, or a plan type
     whose defeat is a compile error (`LaunchPlan::jail` private) — is now a register convention
     and a Part D gate meta-rule.
  2. **Accepted inputs that no datapath reads.** `Egress::Blocked` was a third spelling of `Open` —
     rustdoc promising "all egress blocked" over an arm nothing matched — and
     `nested_virt`/`RestoreMode::Lazy` were accepted on backends advertising `false`. The landed
     resolution is a template: `Blocked` was **honored, not rejected** (two new predicates,
     `privileged_egress_rules` and `nat_egress_plan`, each `match`ing **exhaustively** so a future
     variant is a compile error rather than a fall-through into the most permissive arm — which is
     exactly how the defect happened), and the unadvertised-capability class got one shared law
     (`reject_unadvertised_capabilities`, called from `create()` **and** `restore()` on all four
     backends, keyed off the descriptor handed in — never a hardcoded `false` at the refusal site).
  3. **Unbounded waits at control-plane edges, and deadlines that bound the gaps instead of the
     operation.** crosvm bounded one of its seven control ops; the guest-RAM-proportional
     `vm.snapshot` RPC rode a fixed 5 s ceiling and could leave the VM **paused** on timeout;
     `connect_framed`'s deadline was checked between attempts while the attempt itself was
     unbounded. The landed shapes are the rule: a named ceiling a backend **cannot re-spell as a
     literal** (`vmm::VMM_SOCKET_READY_TIMEOUT_MS` is taken as *no argument at all* —
     `register_and_await_ready` lost its `timeout_ms` parameter so a per-backend literal is a
     compile error), and a budget **sized by what it bounds** (`snapshot_request_timeout(mem_mib)`,
     adopted as `max(own_floor, shared_predicate)` where a backend has a floor of its own — QEMU's
     iterative migration keeps its 120 s floor and the predicate takes over at the multi-GiB
     crossover it exists for).
  4. **The youngest owning-lifetime code carries the densest defects.** The daemon `Registry` held
     four of docs/81's thirteen majors, three reproduced by a running probe: a state
     (`Snapshotting`) unobservable because it was set and cleared under the same held lock —
     head-of-line blocking `GET /v1/vms` for every VM; a snapshot prefix deletable mid-write because
     `VmSlot::pins` didn't cover it (and the readback error was swallowed into `files: []` — HTTP
     200 for a snapshot that no longer existed); `ShutdownAll` returning while detached dispatch
     tasks still ran, orphaning a VMM booting inside the launch-to-insert window. Review the
     newest owning code the way v5 reviewed the privileged window: stricter, with running probes.
  Plus a fifth, meta: **local ≢ CI by construction is a class, not an incident.** [81]
  `CARGO_TERM_COLOR: always` silently disarmed every pattern that parses `cargo tree` (28 matches
  uncolored, 0 colored) — six copies of lean-tree bans passed for seven weeks while proving
  nothing; the fuzz workflow's nightly toolchain was silently outranked by `rust-toolchain.toml`
  for 41 runs; the integration job named a self-hosted runner that was never registered, so the
  whole live matrix was CI-invisible for the repo's entire history. The fixes are producer-side
  (`--color never` on the invocation, not an ANSI-tolerant regex; `RUSTUP_TOOLCHAIN` env override
  plus a one-second nightly assertion that names the cause) and structural (`just ci` calls the
  same `just gates` recipe `ci.yml` does; `ban-ci-script-handcopy.sh` is the meta-gate that runs
  first and asserts the roster in both directions; `ban-uncolored-cargo-parse.sh` is the class
  gate). And a sixth, small but new: **a vocabulary rename needs an identifier-scoped ban** [33] —
  ban the retired identifiers, never the bare word, or the gate reddens the domain text and the
  repo's own tooling files.

So this rubric is written to be *enforced*, not just consulted. **Five** governing rules:

1. **If a checklist item below reaches human review, the gate that should have caught it is
   missing.** File the missing gate (Part D), don't just fix the instance.
2. **For every test: "Write the buggy implementation. Does this test go red?"** If no, the test is
   theater. v7 sharpening [81]: apply the same question to the gate's *scope* — "rewrite the call
   site to bypass the extracted helper; does anything go red?" A green predicate test beside an
   unbound call site is the completeness audit's recurring shape.
3. **A test CI never executes is not a test; a config CI never builds is not covered.** Skips are
   visible and durable; a zero-selection filter is a failure; non-default feature configs compile
   under a *blocking* gate. v7 sharpening [81]: **a gate whose passing output is identical to its
   not-running output is not a gate** — measure the not-running output once (the M13 justfile scan,
   the colored `cargo tree`, the validator's own compiled-and-never-selected smoke suite were all
   exactly this).
4. **Enumerate what the suite structurally cannot reach. [37][40][46]** For every subsystem, ask:
   which error branches, payload sizes, flow variants, feature configs, and defaults does no test
   drive — **and which side effects the fakes structurally cannot see** (a `FakeVmm` never touches
   the filesystem; no fake sees a process table or a systemd boot [33]). Failure-injection,
   window-filling payloads **in both directions** [81], per-flow-variant coverage, and
   default-value tests are first-class requirements.
5. **Host-facing claims are validated by execution, not reading. [37]** A review of (or fix to)
   host-facing code is not done until the suites actually ran on a KVM-capable host (Part E) —
   capability is **probed** (the preflight), never presumed absent. Both review passes this rubric
   absorbs ran every suite before reading a line, and both found live-only defects static reviewers
   could not see.

### Retired & qualified rules  *(v5–v6, extended in v7)* [28][IN][81][33]

Rules superseded or scoped by explicit, landed design decisions. Recorded here so a reviewer citing
an old rubric does not re-open them:

- **"Drop order = declaration order, stated in a load-bearing comment" (v4 A4/B1).** Replaced by
  the explicit `EnvSetup` `Drop` calling the one ordered helper (`teardown_post_instance`) — one
  law, two callers, pinned by a drop-order recording gate (design §9.4). Load-bearing teardown
  encoded only in field declaration order is a review reject.
- **"`limits_enforced` reflects ALL requested controllers" (v4 B2).** Resolved the other way: the
  field is `mem_limit_enforced` and deliberately means only "the memory controller is delegated"
  (design §7.1). The *narrow-name-for-narrow-claim* doctrine is generative: `usb_host_passthrough`
  (v30) and the v33 `Feature` roster (a variant claims exactly what a §10.6 check validates — §7.4)
  are the same move [30][33].
- **"`#[non_exhaustive]` on every growable public type" (v5 B8) — QUALIFIED, not blanket.** [IN]
  Five shared VMM-contract types are deliberately **exhaustive** (`VmmCapabilities`,
  `PerVmResources`, `RootfsSource`, `ConsoleMode`, `VsockTransport`) so a new field/variant is a
  compile error in every backend crate; safe because every crate is `publish = false`. The rule:
  non-exhaustive for types that grow *toward callers*, exhaustive for contract types that grow
  *toward implementors*. v33 extends the family: `Feature` and `CheckStatus`'s new variants follow
  the same doctrine (a new `Feature` must force every declarer's stance — §7.4) [33]. Corollary:
  `NetConfig` **is** `#[non_exhaustive]`, so a new variant threads its per-backend obligation
  through an exhaustive channel instead (`PerVmResources`).
- **"`Egress::Blocked` is dead — implement, reject, or remove" — RESOLVED: honored.** [81] The
  docs/81 M1 decision is recorded: `Blocked` emits the accepts-nothing ruleset on the privileged
  path (`PrivilegedEgressRules::Blocked`, an exhaustive-match arm in the orchestrator) and registers
  no forward port + `NatEgressPolicy::Deny` on the NAT path; `build()` additionally rejects the
  unhonorable `Blocked` + `host_services_port` pair. A reviewer proposing rejection-or-removal
  re-litigates a settled decision; the residual to know: `VmConfig` fields are `pub`, so `build()`
  binds the *builder* — the datapath predicates are the defense in depth, deliberately.
- **"No `init=` over REST" — QUALIFIED to "no steward-less cells over REST".** [33] The rule's own
  rationale ("the daemon owns VMs through the control plane") permits exactly the placement that
  keeps the control plane: v33 delta 10 exposes `init` + `steward_placement: Service{port}` over
  REST; `StewardPlacement::None` stays unexpressible there. Flagging `init` in a `CreateVmRequest`
  as the old violation re-opens the qualified rule.
- **The steward rename is identifier-scoped (v33 delta 1).** [33] The retired identifiers
  (`vmcell-guest-agent`, `AgentClient`, `MicroVm::agent()`, `Error::Agent`, `boot.agent_ready`,
  `--agent-musl`, …) are banned by the extended legacy-terms gate; the bare word "agent"
  legitimately survives in the agentic-execution domain text (§1.1), `AGENTS.md` (repo tooling
  convention), historical finding IDs (`AGENT-2`), and external names (Kata's `agent-ctl`). A
  reviewer flagging those survivals — or proposing to widen the ban to the bare word — re-opens a
  settled scoping (design §17).

### Enforcement legend

`lint` compiler/clippy deny (fails the build) · `CI` a CI job · `test` a test that must fail on the
buggy impl · `review` human/agent judgment, no mechanical gate yet.

---

## Part A — Cross-cutting principles

The generative rules. Most Part B checks are corollaries; when a new situation isn't covered,
reason from these.

1. **Fail loud, typed, and early.** No swallowed `Result` (`let _ =` without a justifying comment —
   docs/81 found the class again in the *readback* position: a `read_dir(..).unwrap_or_default()`
   turned a deleted-mid-write snapshot into HTTP 200 `files: []` [81]), no `Ok(())` on a failed or
   unsupported branch, no panics on any path a guest or the network can drive. An error is
   *visible*, *typed* (matchable, not `Error::Other(String)`), and *prompt* (checked before a long
   timeout masks it). Sharpenings: **a semantic result is part of the contract** [40]; **errors are
   errno-precise** (`EINVAL` → `Error::Cgroup`; permission errnos → `CapabilityUnavailable`; an
   absent facility (`ENOENT`/`EOPNOTSUPP`) → `Error::Cgroup`, because "enable delegation" is the
   wrong remediation [IN]), the split unit-tested against each inverse [46]; **a returned count is
   part of the result** (`Ok(n)` where `n < requested` is not success) [46]; and **an I/O failure
   is never re-reported as a domain condition** — `FsIdClaim` collapsing `EACCES` into "No
   available VMIDs" sends the operator chasing phantom capacity [81].

2. **Every accepted input is honored or rejected — silent degradation is the default bug.** A
   *requested functional* op that cannot be performed returns a typed error, never a
   logged-and-ignored no-op returning `Ok`. Three categories, and a review places every host-facing
   op in one: *functional* (fail loud) · *observational* (may degrade, surfacing what was
   unavailable via `*_read_ok` flags) · *explicitly-listed best-effort* (the §16 benchmark knobs).
   The test: *if a caller's assertion can be wrong because the op silently did nothing, it is
   functional.* The rule covers **every accepted input**: a config field dropped with a bare
   `let _ =`, an enum variant with no code path behind it (`Egress::Blocked` — found again by two
   independent docs/81 reviewers, resolved by **honoring** it through exhaustive-match predicates
   [81]), a capability-shaped knob a backend silently ignores (`nested_virt`/`RestoreMode::Lazy` on
   an advertising-`false` backend — closed by the one shared `reject_unadvertised_capabilities`
   [81]), a guest shim's argv (the `curl`/`ip` applets — rejection *is* the faithful emulation
   [81]), a pins-overlay key, and a CLI flag whose unknown value selects the default. **A `#[cfg]`
   feature gate never silently changes semantics** [40]. **Defaults get the strictest scrutiny**
   [46]. Where a field is meaningful on only one variant, **move it there so the invalid state is
   unrepresentable** [28][30] — but weigh the consumer surface: the docs/81 `Blocked`+port pair was
   left representable-but-rejected because making it unrepresentable meant breaking every consumer
   of a shared public enum for one pair; the boundary check + at-site rationale is the recorded
   trade [81]. v33 instances to hold: `StewardPlacement`'s one contradictory pair (`Pid1` + custom
   `init`) is rejected at `build()`; a feature token matching no `Feature` variant is a hard error
   naming it — **absence is the silent direction**, so a typo may never read as "unsupported"
   (F6) [33].

3. **Capabilities are declared, probed, reported — once — and the report is pinned; a cell's set is
   an intersection with provenance.** Backends report `VmmCapabilities` (nine fields — the count is
   checked against the struct, never quoted from memory); the host is probed into the one
   `HostCapabilities` descriptor; and — v33 — an **artifact** declares through its registry entry +
   feature-manifest sidecar, with the cell's effective set computed at exactly one intersection
   site and every removal carrying `Removal { feature, by, reason }` provenance (law F6, §7.4)
   [33]. A backend's typed refusal names the capability with a **feature string equal to the
   `VmmCapabilities` field name** — v33 promotes the comment norm to a type law: the string is
   `Feature::name()` by construction, and the substring matchers the prose strings bred
   (`feature.contains("vhost-user")` and its five siblings) are banned as
   assertion-weaker-than-the-comment [33][81]. Every advertised flag is **live** and **empirically
   backed** [37]; every flag on every backend has a **capability-honesty pin** [46]; accessors are
   honest across state transitions [46]; a transient probe failure is never cached as a permanent
   negative [40]; and the refusal predicate keys off the descriptor **handed in**, never a
   hardcoded `false` at the refusal site — so flipping a flag flips its refusal with it [81].

4. **Ownership owns cleanup — on panic, on post-acquire failure, and on every spawned helper.**
   Every acquired host resource is released in reverse dependency order, and that path runs on
   panic. **The teardown order lives in one named helper** (`teardown_post_instance`) that every
   path calls [40][28]; a segment member releases its *slot* and never deletes the segment netns
   [30]; helper daemons spawn through `helper_daemon_pre_exec` (`setpgid` then
   `PR_SET_PDEATHSIG(SIGKILL)`, with the getppid re-check for the fork-window race) [81]; a
   displaced host resource is restored by the one who displaced it (the USB interface→driver map,
   captured before spawn, re-bound after reap, bounded-retry because usbfs release is asynchronous
   — and `UsbHostClaim` deliberately has **no `Drop`**: the restore must run *after* the reap and
   *before* `kill()` returns, so the ordering lives visibly at the call site — the recorded
   exception, cite it) [81]. The hard-kill path is reclaimed by the start-up sweep against empty
   live sets — which is **prefix-ownership**, not liveness (the sweep is cross-process
   liveness-blind; sharing a prefix between concurrent owners is outside the model) [81]. Cleanup
   is idempotent [37]; ids are released **after** the resources named by them (`vmid` before the
   scratch dir named after it was the docs/81 m2 ordering bug) [81]; and shutdown paths **drain
   their detached work before returning** — `ShutdownAll` returning while dispatch tasks still ran
   orphaned a VMM booting inside the launch-to-insert window (bounded drain, over-deadline jobs
   named in a warning) [81].

5. **One law, one predicate.** A contract enforced at multiple boundaries is implemented as **a
   single shared predicate** each boundary calls, pinned by its own unit test — per-backend copies
   *demonstrably* diverge. The census now includes: `config_has_vhost_user_device` (S1),
   `is_reserved_cmdline_arg` (F3 — alias-aware, dash/underscore-normalized [81]), the
   `vmcell::naming` composers + `validate_resource_prefix` (F2), `resolve_artifact_path` (P3),
   `ensure_blessed_or_explain` (P1), `vmm_seccomp_args` + `apply_jail` (§12.2–§12.3), the one
   config-only eligibility predicate `clone_ineligible_feature` wrapped (never restated) by
   `check_clone_eligible` [81], `uses_in_kernel_vsock`, `RootfsSource::effective_image`,
   `net_uses_tap`, `net_sys::setns_net`, `reap_process_group`, the shared `build_kernel_cmdline`,
   `segment_ip_math` beside `ip_math`/`mac_math`, the one vsock `CONNECT/OK` prologue, the one
   id-claim core (`flock` + `hard_link`), `MAX_FRAME_BYTES`/`MAX_BROKER_FRAME_BYTES` + the
   `capped_debug` renderer, `pcts`, the cache-key rules (F4), `is_reserved_injection_path` (F5) —
   plus the docs/81-pass additions, each because the duplicate had already diverged [81]:
   `vmm::reject_unadvertised_capabilities` (one shared law; per-backend wrappers whose only job is
   binding their own name once), `vmm::VMM_SOCKET_READY_TIMEOUT_MS` (taken as **no argument at
   all**, so a per-backend literal is a compile error), `vmcell_protocol::GUEST_TOOLS_APPLETS`
   (const-asserted element-wise against the dispatch table; the manifest emits from it),
   `VmmProcessGroup::is_reaped` (read-only — no setter, so no call site can re-arm a signal at a
   recycled pgid), `metrics::vm_slice_name` (**pub**, re-exported as `naming::vm_slice_name` — the
   full slice name, of which `cgroup_slice_name` is only the leaf), and
   `kernel_artifact_key`/`kernel_pin_key` (exported; the builder calls them instead of
   byte-duplicating) — and the v33 laws [33]: `StewardPlacement::steward_port()` +
   `StewardPlacement::resync_reachable()` (law C8, **two methods for two questions** — availability
   and snapshot-eligibility differ exactly at `Service`, which has a port but no measured
   post-restore resync, so `steward_port()` alone cannot guard `snapshot()`; the pre-v33 tree
   spelled availability **three accidentally-equivalent ways**: raw `cfg.init` in `start()`, the
   retained `control_plane_disabled` field, and `cfg.init` again in the eligibility predicate),
   the `Feature` intersection's
   one computation site (F6), the registry digest rule (F7), the registry merge/collision/sort
   core shared across all three artifact kinds, `XattrPolicy` on the one pack tail, and
   `STEWARD_VSOCK_PORT` single-sourced in `vmcell-protocol` (retiring the host/guest mirrored-const
   pair). Where a law's drift is **not** a compile error it carries a grep-ban plus a
   red-on-inverse self-test (`ban-inline-setns.sh`, `ban-kernel-key-composers.sh`,
   `ban-readiness-timeout-literal.sh`, `ban-artifact-path-join.sh`; `just gates` is the roster);
   a new law of that shape earns one [81]. Standing consolidation targets, recorded not urgent:
   `bench-vm`'s workspace-root ascent and `harness::ch_bin()` (design §17).

6. **Validate at the boundary; return, don't assert; symmetric paths get symmetric handling.**
   Out-of-range values return `Err`; an `.expect()` on a guest-controlled index is a guest-drivable
   panic; if TX degrades gracefully, RX must too. **A cross-cutting protocol invariant lives in one
   shared helper every request method routes through** [37][46] — and the desync/eviction pair must
   close the loop: a desynced cached client that nothing evicts wedges every later call on that VM
   (`agent()` — now `steward()` — checks `is_desynced()` and reconnects-or-evicts before handing
   the cached handle back; the race is real, not theoretical: host and guest wait the same duration
   and the host's timer can fire first on a correctly-behaving exec) [81].

7. **Determinism is tested, not assumed.** Anything feeding a cache key or claiming reproducibility
   has a test pinning a golden value on a **real** stage. Hash the **full source closure** [37];
   fold **content on every flow variant** [46]; key concatenation is **injective** [37];
   **directory outputs** are first-class [40]; fold only **consumed** inputs [40]. v33 additions
   [33]: an artifact-property change (xattr policy) is an identity change and re-packs with a
   `STAGE_VERSION` bump (the v20 precedent); a claimed byte-determinism gets a **pack-twice
   byte-identity gate** (the erofs packer's determinism was a recorded design claim with no in-tree
   gate until delta 7 adds one); and the registry's empty-change property is pinned — a second
   label at the same digest must not move the default's key.

8. **Verify everything you ingest — and parse it fallibly.** Digest-pinned pulls; verification
   failure is a hard stop; fetch once, verify, use those bytes [46]; malformed input is an error,
   not an empty default [37]; unknown input classes fail loud [37][46]. v33 promotes the
   discipline to a law (F7): **a registration is a digest; a path is an override, never a
   registration** — a `source` is a fetch instruction verified against the authoritative digest
   before use, the dev path-override marks provenance `unpinned` and is refused by `bundle`, and
   the gate is the corrupt-one-byte test, because a digest stored and never checked has passing
   output identical to its not-running output [33].

9. **A seam you can't fake is a unit you can't test — and a fake must be *faithful*, *driven*,
   *failure-injectable*, and *honest about its blind spots*.** Side effects go behind injectable
   traits with a real impl and a recording fake; the process-wide set travels as **one `HostEnv`**.
   Four fake pathologies: **over-promise** [37][40]; **wrong layer** [46]; **no fault injection**
   (the `FakeVmm` fault menu, each arm driven) [46][28]; **structural blindness** — enumerate what
   the fake *cannot* see and name the live test covering exactly that [28]. Two sharpenings [81]:
   `HostEnv::hermetic()` is hermetic in its **allocators, not its host effects** (it wires the real
   cgroup seam by design — 15 shipping call sites depend on real confinement; unit tests use the
   `#[cfg(test)] for_unit_tests()` constructor, and `hermetic()` is `#[cfg(not(test))]` so naming
   it in a lib unit test is a compile error, not a green-here/red-in-CI landmine); and a shared
   fake that four crates hand-rolled is exported once behind a **non-default `test-support`
   feature** with a production-ban script as the backstop (feature unification is the hazard, not
   `cargo build`).

10. **Assert on the plane the property lives on. [46]** Control-plane green does not prove the data
    plane. A networking property needs an **egress byte**; a restore property needs the restored VM
    to move real traffic; a data-pump property needs **payloads that fill the window — in both
    directions** (the guest→host direction shipped a ring-wrap panic because every test moved tiny
    payloads host→guest; the B1 fix writes from inside smoltcp's `recv` closure over the contiguous
    span, and the upload gate digest-compares against a backpressuring sink) [81]. v33 instances:
    a placement property needs the health gate to have *run* (not merely not-errored); an xattr
    property needs the in-guest `getxattr` readback with the `Strip` twin as the negative control;
    a subreaper property needs a double-forking payload's exit code to actually arrive [33].

11. **Mandatory recovery stays retryable. [37][46]** Consume one-shot flags only after the work
    succeeds; on failure, evict/invalidate so the next call retries; test the
    transient-failure-then-recovery sequence. And **a recovery path that cannot recover is worse
    than none** [81]: the QEMU control-plane re-spawn burned its whole retry budget against a NAT
    socket the first VMM's exit had unlinked (the vhost listener `Drop` unlinks the path; the
    re-spawn comment claimed "recreates on the SAME per-VM resources", which is exactly why the NAT
    was overlooked) — a re-spawn must re-create, or re-accept on, every resource whose lifetime the
    failed instance ended.

12. **Security checks anchor on trusted data and prove the negative. [37][40][46]** Anchor on the
    runner's own canonicalized location / the daemon's own `--artifacts-dir`; normalize before
    comparing; a negative result carries a **positive control**; the test configuration must not
    neuter the property. v33 extends the positive-control rule structurally: an absence probe and
    its positive control are **one paired check id** in the conformance kit, so the control cannot
    be deleted without the roster gate reddening (§10.6) [33]. And a reserved-name rule holds on
    **every verb** — the `.sha256` reservation held on four verbs and not the fifth
    (`Registry::snapshot` picked the weaker validator), so the rule is **folded into the one
    validator** so no caller can choose (the docs/81 M3 shape: one authenticated request
    permanently broke uploads of the shadowed name) [81].

13. **One process may hold capability or parse untrusted input — never both; and posture matches
    lifetime. [28]** The broker split (P2); posture follows lifetime (P1); secrets never sit in
    process-visible surfaces (P4). Verified live now, not just designed [81]: the daemon suite
    asserts the serving parent's `CapEff/CapPrm/CapInh/CapAmb` all zero with the still-capable
    broker child as the positive control; the broker child ignores INT/TERM (PDEATHSIG + the
    shutdown channel govern it) and `build_vmm_cmd` resets `SIG_DFL` in `pre_exec` so spawned VMMs
    keep normal signal behavior; the bounding-set shrink stopped being a warned no-op via the
    **transient** `CAP_SETPCAP` file cap — in `BLESSED_FILE_CAPS`, never in `PRIVILEGED_CAPS`,
    dropped out of its own bounding set mid-transition, gated live by a `CapBnd` **equality**
    assertion [81].

---

## Part B — Review checklist

### B1 · Resource lifecycle & teardown  *(Critical in every pass)*

- [ ] `MicroVm`'s `Drop` performs the full ordered teardown — **VMM process group → virtiofsd →
      netns / cgroup / overlay / sockets / scratch dir** — exercised by a panic-residue test that
      asserts the **full order** via recording fakes. The drop-order gate must cover the tail it
      claims: built with `vmid: None, cid: None, tmp_dir: None`, it no-ops the last three steps and
      proves nothing about them (docs/81 m20) [81]. `test`
- [ ] **All teardown paths route through the one ordered helper** (`teardown_post_instance`):
      `shutdown()`, `Drop`, the `EnvSetup` explicit `Drop`, and the registry's
      `destroy`/`shutdown_all` (the registry itself has **no** `Drop` impl — the third path is the
      contained `MicroVm`s dropping; writing one would be a second copy). Ids release **after** the
      resources named by them (the vmid-before-scratch-dir window let a same-process reallocation
      have its fresh directory deleted by the departing VM [81]). The triplicated
      `reaped`-flag/pgid teardown dance is consolidated through `reap_process_group` +
      `VmmProcessGroup::is_reaped` (read-only — no setter re-arms a recycled pgid) [81].
      [40][46][28][81] `test` `review`
- [ ] Process teardown uses a **group kill that waits**, pgid cached at spawn. Applies to all
      backends *and every helper daemon they spawn*; helpers spawn through
      `helper_daemon_pre_exec` (`setpgid` → `PR_SET_PDEATHSIG(SIGKILL)` → the `getppid` fork-window
      re-check), gated on the **behavior**, not the flag (`pdeath_signal` is per-task and `clone`
      zeroes it) [81]. `review` `test`
- [ ] **Each spawned helper has its own RAII guard before subsequent fallible steps** [37][40];
      **shutdown paths drain detached work before returning** — bounded, with over-deadline jobs
      named — and a `create` in flight during shutdown is either covered by the drain or excluded
      by a lock spanning its launch-to-insert window (docs/81 M4) [81]. `test`
- [ ] **A displaced host resource is restored by the displacer**: the USB interface→driver map is
      captured **before** the spawn (the sysfs symlink is gone once the VMM claims the device) and
      re-bound after the reap by the one helper both `kill()` and `Drop` call, bounded-retry
      (usbfs release is asynchronous — a bind at t=0 fails; one 100 ms later succeeds), warn-never-
      fatal, restore-what-we-displaced-never-make-it-work (a deliberately-unbound device stays
      unbound). `UsbHostClaim`'s missing `Drop` is the recorded exception to teardown-is-ownership
      — cite it, don't "fix" it [81]. `test` `review`
- [ ] Per-VM scratch dirs are owned (`VmTempDir` dropped last); residue assertions cover the
      **directory**; the per-clone CoW copy lives inside the scratch dir (S3). **A test's own
      fixtures are residue too**: fixture trees own their cleanup on the panic path (`TempTree`,
      with the driven unwind leg) — the snapshot fixture that leaked ~129 MB per run filled the
      host tmpfs and reddened the daemon suite with `EDQUOT`, which reads as a product defect and
      is not one [81]. `test`
- [ ] Spawned-forever workers hold a shutdown signal + `JoinHandle`; `Drop` signals and joins
      within a timeout [46]. A worker's *listener lifetime* is part of the contract: the vhost
      listener's `Drop` unlinks its socket path, so a supervisor that re-spawns against "the same
      resources" must know which resources died with the worker (docs/81 M2) [81]. `test`
- [ ] `request_shutdown()` is followed by a bounded grace-poll, then the SIGKILL fallback — and
      **every control op on the path to the force-kill is itself bounded** (a wedged `powerbtn`
      must not delay the unconditional `kill()` behind it — the crosvm one-of-seven lesson) [81].
      `review` `test`
- [ ] `sweep_orphans()` reaps hard-crash residue per class against **its own id space**; the daemon
      start-up sweep passes both sets empty — a **prefix-ownership** argument, not a liveness one
      (the sweep is cross-process liveness-blind and discards the pid embedded in scratch names;
      same-prefix concurrent owners are outside the model — the recorded scope, don't over-claim
      it) [28][81]. `review` `test`
- [ ] **Guest/network-driven in-flight state is bounded and reclaimed at every accumulation
      point** [37][40][28]; log renders of guest-controlled frames go through `capped_debug`
      (an uncapped `{:?}` printed ~16 MiB onto the persisted serial artifact) [81]. `test`
- [ ] Reclaim predicates are tested with the resource **live** [37]; concurrent-startup patterns
      are cancellation-safe (`spawn_clones` all-or-nothing; `try_join_all` over daemon starts is
      the recorded rejection) [BP][28]. `review` `test`

### B2 · Failure visibility

- [ ] No `.unwrap()` in non-test code; `.expect("invariant: …")` never on guest-/network-driven
      paths. PID-1-and-service discipline for the steward: under `Pid1` it never exits on a
      recoverable condition (the **four**-mount fatal core set — tmpfs `/mnt`, overlay, `/proc`,
      `/dev`; the in-code "exactly three" comment understated its own code and is corrected by v33
      delta 5 [33]); under `Service` the SIGTERM policy inverts to a graceful shutdown **by
      declared mode, never by accident** — and a detached thread's panic is an exit C1 cannot see
      (the `std::thread::spawn`-on-`EAGAIN` listener death, docs/81 m12: the control plane dies
      with no kernel panic and no supervisor) [81][33]. `lint` `review`
- [ ] The reaper does not steal an exec'd child's exit status: the `ReaperCoordinator` epoch
      discipline stays pinned, **placement-independent** — the reservation/epoch machinery is
      pid-reuse correctness for children the steward spawned itself and carries into service mode
      intact; what changes with placement is only the orphan bound's necessity
      (`PR_SET_CHILD_SUBREAPER` under `Service`) [40][33]. `test`
- [ ] No `Ok(())`/printed success on a failed or unsupported branch — including the **readback**
      position: a swallowed `read_dir` after a successful write reported a deleted artifact as
      created (docs/81 M8's second half, the one that made the first invisible) [81]. `review`
- [ ] Every `let _ = result;` carries a justifying comment [46]; the recorded 11-site cluster is
      10 best-effort teardown sites + one commented probe discard — a **load-bearing** swallow
      hiding among best-effort ones is the docs/78 `usage_readable` shape [81]. `review`
- [ ] Error **detection** is correct, not inverted or loose [37][46]; shims are exit-code-faithful;
      **an unknown flag is exit-2 naming the offender — rejection is the faithful emulation**
      (the `curl`/`ip` applet rule; an accepted-but-ignored flag silently voids the property a
      test asserts through the shim) [81]. `test`
- [ ] A remote exec's **exit code is checked** [40]; readiness signaling propagates build failures;
      every VMM control RPC is bounded — **by a ceiling the backend cannot re-spell**
      (`VMM_SOCKET_READY_TIMEOUT_MS` is not a parameter) and **by a budget sized to the operation**
      (`snapshot_request_timeout(mem_mib)`; a fixed constant on a guest-RAM-proportional write is
      the docs/81 M6 bug, and its timeout path must leave the VM **resumed**, not paused) [G][46][81].
      `review` `test`
- [ ] **A requested capability-dependent op fails loud** with the §7.2 errno split; per-op checks
      read the one `HostCapabilities` descriptor; enforcement keeps its own per-write typed check
      [46][28]. A configured limit is **proven binding** (`memory.events oom_kill > 0`) [37]. `test`
- [ ] Unknown/unhandled protocol variants are logged, never silently dropped into a desync [40];
      an undecodable request gets a reply (the serve-nothing arm wedges the caller) [81]. `review`
- [ ] Logging via `tracing`; serial/proxy logs cap retention; **no secrets in argv/env/logs** (P4);
      and diagnostics that never fire are defects too — the TPROXY `log prefix` that netfilter
      suppresses in a non-init netns promised a diagnostic that never existed (fix the doc or the
      sysctl, never leave the promise) [81]. `lint` `review`

### B3 · Capability & input contracts

- [ ] Typed `Error::Unsupported { vmm, feature }` for every capability gap; the feature string is
      **`Feature::name()` by construction** once v33 delta 2 lands — composed from a `Removal`,
      never hand-spelled; until then N-VMM-1 (string == field name) binds new sites [33]. Advertised
      capabilities are live, empirically validated, and **pinned per-flag per-backend** (nine
      fields — landed; the count is checked against the struct [81]); the three seccomp-`Log`
      unsupporteds stay pinned as typed errors. A deliberately narrow flag keeps its narrow name
      [30]. **The unadvertised-capability class routes through the one shared
      `reject_unadvertised_capabilities`**, called from `create()` **and** `restore()` on every
      backend, keyed off the descriptor handed in [81]. `test`
- [ ] `restore()`/`snapshot()` self-guard on `capabilities()` *and* `config_has_vhost_user_device`
      (S1) — **all four backends**, never per-backend copies; restore-boundary re-checks go through
      the one config-only `clone_ineligible_feature` (which `check_clone_eligible` **wraps, never
      restates** — the open-coded copy had already drifted and fanned out a custom-init config
      N clones before refusing) [37][40][46][81]. `test`
- [ ] `create()` rejects configs the backend can't honor — the primary backend is not exempt [40].
      `test`
- [ ] `VmConfigBuilder::build()` returns `Result` and rejects, with a negative test each: the v6
      roster (shares, snapshotting exclusions, vcpus/mem floors, vmid range, extra-disk rules,
      `resource_prefix`, reserved cmdline args **including aliases and dash/underscore
      respellings** — the kernel normalizes `-`↔`_` in parameter names, so `kvm_intel.nested=1`
      must be as reserved as `kvm-intel.nested=1` [81]) plus v33 [33]: `Pid1` placement + a custom
      `init` (contradiction); `snapshotting` + any non-`Pid1` placement; `Blocked` +
      `host_services_port` (the landed pair-reject [81]); the registry's legacy-singleton `rootfs`
      shape (loud migration error, never silent reinterpretation). Boundary checks bind the
      *builder* — `pub` fields mean datapath predicates stay the defense in depth (recorded) [81].
      `#[must_use]` on builder methods. `test`
- [ ] **No dead variants or flags advertised as live** — implement, reject typed, or remove; the
      `Egress::Blocked` resolution (honor, exhaustive-match) is the settled template [46][81].
      `review` `test`
- [ ] Accessors stay honest across state transitions [46]; **states are observable** — a state set
      and cleared under the same held lock can never be seen, and its documented 409 can never
      fire (`VmState::Snapshotting`, docs/81 M9: carry it in an atomic read without the per-VM
      handle lock; ops on one VM must not head-of-line-block `list` for all) [81]. `review` `test`
- [ ] The workload runs only **after** cgroup placement [46]; out-of-range values return `Err` at
      a validation boundary [review].

### B4 · Determinism, caching & provenance

- [ ] Cache keys: stable hasher; deterministic input order; content and identity that travel —
      including fallback arms [40]; per-stage version + pinned SHA; injective concatenation (F4).
      `test`
- [ ] The rootfs key folds the full source closure of everything baked in — steward closure,
      guest-tools content, baked CA, per-flow-variant bytes (`--steward-musl` folds content, never
      the path) [37][46]; the snapshot key folds the pinned CH identity; **an artifact-property
      change (xattr policy) is an identity change** with its `STAGE_VERSION` bump [33]. `test`
- [ ] Validity is content-addressed; re-hash on every use; directory outputs first-class [40];
      **the registry's digest rule (F7)**: a `source` fetch verifies against the authoritative
      digest before use — gated by the corrupt-one-byte test; the dev path-override marks
      provenance `unpinned` and `bundle` refuses it [33]. `bundle` digests are **blake3** (the
      cache's `hash_file` law); a registry `source.archive_sha256` is sha256 like
      `kernel_prebuilt`'s — two hash roles, named, never conflated [33]. `test`
- [ ] Stale intermediates verify-or-purge; pulls digest-pinned; the layer list parses from the
      digest-verified bytes [46]; mmdebstrap keeps its in-guest signing chain. `test` `review`
- [ ] Decode paths are complete and fixture-tested (gzip/zstd, whiteouts, device nodes,
      hardlinks, unknown-entry-fails-loud) [40][46]. `test`
- [ ] CA hygiene: minted once per artifacts dir, process-global cache, atomic write, `0600` —
      **and cross-process serialization**: `CaManager::new_in` takes the `.ca.lock` `flock` for
      the whole generate-or-load (the process mutex serializes threads; the flock serializes the
      per-test *processes* nextest spawns — the two-rename publish window reddened two unrelated
      cache tests before it was closed at the source; the gate asserts the mechanism, not the
      timing) [40][81]. The pack tail writes the published CA under the same lock (the m15
      truncate window) [81]. `review` `test`
- [ ] **The injection-identity fold covers every injected thing** — extra files as sorted
      `(dest, mode, content-hash)` triples; the reserved-path law (F5) derives from the manifest
      and normalizes before comparing; the resolved-config and feature-manifest sidecars are
      content-addressed with their artifacts [30][33]. **Claimed byte-determinism carries a
      pack-twice gate** (delta 7 adds the missing one) [33]. `test`
- [ ] The daemon store's digest is computed once at upload, sidecar-served, atomic-renamed [28];
      the `.sha256` reservation is **one predicate folded into `validate_artifact_name`** so no
      verb can pick a weaker validator (the M3 lesson: `snapshot` did, and one authenticated
      request permanently broke uploads of the shadowed name) [81]. `test`

### B5 · Pipeline staging

- [ ] Stage 0 loads committed pins; pin ingestion fallible; no hardcoded fallbacks; image+digest
      pair atomically [37]. `test` `review`
- [ ] **The pins overlay is stricter than the baseline** [30]: an overlay top-level key matching no
      known namespace is a hard error naming it; a referenced-but-unresolvable key stays a hard
      error; the stage key folds both files; a missing fragment folds a distinct marker. v33 grows
      the namespace roster by `rootfs` (map shape) and `handlers` — added to
      `KNOWN_PINS_NAMESPACES` **and** `flatten_pins_namespace` together, with the legacy-singleton
      reject [33]. `test`
- [ ] `StageInputs`/`StageOutputs` carry real data; cache-hit runs merge skipped stages' pins [G];
      stage names and artifact keys unique [37]; `reset_to` removes the named stage's and later
      outputs **including registered sibling artifacts** (the config sidecar — docs/81 m29's
      shape: parse the stage's recorded artifact list, keep `Pipeline` kind-agnostic) [37][81].
      `test`
- [ ] Artifacts under the one resolved `artifacts_dir()`; a missing upstream is `Error::Artifact`;
      **caches sit on cache-shaped paths** — an OCI blob cache sited on a per-run temp output dir
      dies with the run and silently re-pulls every build (docs/81 m16) [81]. `review`
- [ ] Record/replay seams for every fetch path (`OciPuller`) [40]; **selection is lazy** [33]: a
      registered artifact is not built until selected — `build-kernels <label>…`/`--all`, the
      rootfs/handler kinds selection-driven from birth; the laziness gate is
      register-an-unselected-label-and-assert-no-build, red on eager. `test`

### B6 · Concurrency & injected state

- [ ] IDs, time, and I/O from injected seams; the process-wide subset travels as one `HostEnv`
      (grown by field); `hermetic()` is allocator-hermetic, **not** host-effect-hermetic — unit
      tests use `for_unit_tests()`, and the cgroup seam is the only one swapped there (overlay and
      clock stay real deliberately: the fs-blindness and resync-clock lessons) [28][81].
      `CI(grep)` `review` `test`
- [ ] Every CoW clone materializes through `env.overlay` (S4); `probe_cow_support` routes through
      the seam **on every wrapper** (`Zygote` gained `probe_cow_support_in`; `Lineage`'s
      hardcoded-store bypass was the docs/81 d4 finding), and the probe is side-effect-free
      against the **immutable master** — it probes a sibling scratch dir it proves is on the same
      filesystem [28][81]. `test`
- [ ] Cross-process coordination is seamed, atomic, tested; rename-based claiming is the
      known-wrong shape (the H1 `flock`+`hard_link` core, one implementation, two id spaces);
      an I/O failure in the claim path is an error, never "exhausted" [46][IN][30][81]. `test`
- [ ] Allocators: release on the actual instance; reuse-by-design asserted as "valid live", never
      `assert_ne!`; the release proptest asserts actual reuse [40]. `test`
- [ ] `/30`/MAC math centralized; the **six** NAT silent-wedge invariants (§6.2) each pinned —
      including the guest→host contiguous-span drain (the write happens **inside** the `recv`
      closure; `peek_slice`+`dequeue_many_with` pairing panics on any ring-wrapping upload — B1,
      found only when a window-filling upload gate existed) [46][81]. `test`
- [ ] Socket namespace origination is explicit [46]; **`setns` has one home** (`net_sys::setns_net`
      + the `vmm` pre_exec site; `ban-inline-setns.sh` is the gate; a `setns` inside a dependency
      is invisible to it — the pooled-worker hazard stays a recorded watch item) [81]. `review`
- [ ] Lineage identity cross-family-safe (S5) [28]; the broker engine channel multiplexes without
      head-of-line blocking, **fails in-flight requests on EOF** (the drain is the only thing
      standing between a dead broker and every request hanging — it has its own gate now), and
      `call` carries a per-call deadline so a *stalled* broker is bounded too [28][81]. `test`
- [ ] Deadlines are `Instant`, propagated outer-bounds-inner, and **bound the whole operation, not
      the gaps between its polls** — a budget checked only between iterations does not bound a
      wedged connect, read, or write (`connect_framed`'s per-attempt bound; QEMU's
      `drive_migration` wrapped whole; crosvm's `CROSVM_CONTROL_BUDGET` with `kill_on_drop`)
      [BP][81]. `review` `test`
- [ ] Side-effecting fakes carry assertions and failure injection; each `FakeVmm` fault arm driven
      [46][28]. `test`

### B7 · Module boundaries & duplication

- [ ] **The second copy is where the bug lives.** The census and its history live in A5; review
      additions here: a kernel-ABI struct kept deliberately duplicated (guest-tools ↔ `netif`)
      carries the recorded deviation **and** the divergence guard pinning fields and ioctl numbers
      against `libc`, not just total size — retire the entry when the shared crate lands [81].
      `review`
- [ ] **The broker is a location, not a fork of the logic** (P2) [28]. `review`
- [ ] No hand-rolled HTTP/packet parsing where a parser exists [G]; module responsibilities match
      the design; benchmarks exercise the production helper, not a strawman [40]. `review`
- [ ] **Command and posture travel together**: a backend's argv and its jail spec compose in one
      plan type (`LaunchPlan` / `CrosvmLaunchPlan`) whose jail half is private — the two-line
      defeat is a compile error, and the source scan pins the call-site count per backend
      (crosvm's plan is deliberately its own type: its `Enforcing` flips the Layer-2 deny-list,
      which the shared type has no place for — cite, don't unify) [81]. `test` `review`

### B8 · Public-API hygiene

- [ ] `#[non_exhaustive]` per the qualified rule; `cargo semver-checks` over **both** contract
      crates; every bump gets its ledger entry — **and semver-checks has known blind spots the
      ledger must cover by hand**: return-type changes and 0.x minor breaks are invisible to it
      (the `Netlink::setup_tap` lesson: a dead `Result<Option<tun_tap::Iface>>` forced every
      out-of-tree seam implementor onto an unre-exported dep; the fix was breaking and
      semver-blind, hand-ledgered) [28][30][81]. `CI` `review`
- [ ] `Error` posture per §9.5; `DaemonError` mirrors it; no always-zero fields; no `pub` escape
      hatches around self-guards; multi-value returns become named structs [46][28]. `review`
- [ ] Docs: `#![deny(missing_docs)]`; `# Errors`/`# Panics` accurate; `cargo doc` gated [46].
      **Comments are load-bearing and audited like code** [40][46]: a comment **claiming coverage
      that does not exist** is the worst instance of the class (the M6 stdin-flood comment named a
      live gate that had never been written — found by the completeness audit); a security-relevant
      non-default posture carries its at-site rationale; reworks sweep the comments they
      invalidate [81]. `review`
- [ ] Per-module `#![forbid(unsafe_code)]` on I/O-free modules [lint]; dead code removed or
      justified. `review`

### B9 · The privileged window  *(`vmcell-test-runner`, `vmcell-steward`, `vmcell-privilege`, the `vmcelld` cap-holder, `vmcell-broker`)*

- [ ] The runner checks the **effective** set; remediation says `setcap … +ep`; **one blessing
      predicate, two callers** (P1); posture matches lifetime; the transition is a pure ordered
      **step list** (`PrivilegePlan::steps` — a struct has no sequence, so while the plan was only
      a struct the promised ordering test had nothing to assert against), uid-drop **before**
      ambient-raise, bounding shrink before the raise [40][28][81]. `test` `review`
- [ ] **The blessed file set is `BLESSED_FILE_CAPS` = the three delivered caps + transient
      `CAP_SETPCAP`** — SETPCAP exists only for `PR_CAPBSET_DROP`, drops itself in step 3, is
      absent from `inheritable_add`/`ambient_raise`/`final_caps`, and the live gate asserts
      `CapBnd` **equals** the delivered set (asserting the plan would be theater — a correct plan
      whose syscalls all fail is precisely the state that shipped). `setcap_arg` is the one
      composer; the copy-drift gate **walks the tree** over an exact file→count roster (the
      hand-listed pair claimed "every copy" while the design's own copy drifted for a release)
      [81]. `test`
- [ ] Path confinement anchors on the runner's own canonicalized location, adversarial fixtures
      tested [37][40][28]; `just bless` stages-then-setcaps-then-renames so a declined sudo never
      destroys a working blessing [81]. `test` `review`
- [ ] Dependency-thin (runner + `vmcell-privilege`: `rustix`+`capctl`+`libc`); the steward's lean
      ban is `tokio|hyper|rtnetlink` and **must survive the delta-5 library split** [33]; the
      broker's boundary is the web-**server** stack (`axum` + `vmcell-daemon` absent; `hyper`
      legitimate); the lean checks live in **one** `check-lean-tree.sh` both `just` and CI call,
      with `--color never` at the producer and a self-test that exports `CARGO_TERM_COLOR=always`
      (the six inline copies passed for seven weeks proving nothing) [28][IN][81]. `CI` `test`
- [ ] virtiofsd posture per §4.5; readiness paced by the caller's profile through the shared
      `wait_for_socket` (the unpaced `start` is a `#[deprecated]` shim awaiting the next ledgered
      bump — deprecation under `-D warnings` is what keeps it from becoming the accidental twin)
      [G][40][81]. `review`

### B10 · Unsafe, FFI & the guest-facing boundary

- [ ] **One audited definition per kernel struct**, size- and offset-asserted against `libc`; a
      deliberate second copy carries the recorded deviation + the field-by-field pin [81]. `test`
- [ ] `// SAFETY:` proves the actual obligation; `apply_jail` is async-signal-safe **and
      allocation-free on every path including error paths** (`io::Error::from_raw_os_error`,
      never `format!`/`io::Error::new` — a child racing the parent's allocator lock deadlocks
      `create()`) [28][81]. `review`
- [ ] Counts are handled; guest-derived lengths validated before allocation; wire narrowing is
      `try_from`; presence-dependent serde needs a self-describing codec, **round-tripped on the
      codec it actually ships over with `Some`/`None` asymmetric** — v33 delta 10's DTO fields are
      the next instance and their gate says so [28][33]. `test`
- [ ] Interop tested cross-implementation (guest framing vs the real host codec, both directions,
      over-cap) [40]; **pre-send caps match pre-receive caps** — the one-shot path's missing
      pre-send `MAX_FRAME_BYTES` check surfaced as an opaque desync while the session path checked
      (symmetric paths, symmetric handling) [81]. `test`
- [ ] **Fuzz the decode surfaces** — the roster is fifteen targets with a count law (`cargo fuzz
      list` == `[[bin]]` count == file count, asserted by the workflow) and the nightly job runs a
      **genuinely nightly** toolchain (`RUSTUP_TOOLCHAIN` outranks the pinned file; the one-second
      `rustc -vV` assertion names the cause — 41 runs fuzzed nothing before it) [28][81]. `CI`
- [ ] [BP] Miri on unsafe-adjacent pure units where no ioctl blocks it. `CI` `review`

### B11 · Lint-suppression hygiene  [52]

- [ ] Narrowest scope (`#[expect]` on the statement, never fn/module/crate); `#[expect]` over
      `#[allow]` (with the `cfg_attr` exception for config-conditional lints); every suppression
      carries `reason = "…"`; repeated legitimate sites collapse into one helper. A shared test
      fixture whose lock-unwraps trip production lints routes them through **one** helper carrying
      a single `#[expect]` — the `test-support` precedent [81]. `lint` `review`

### B12 · The daemon HTTP surface  [28]

- [ ] **One name validator, allowlist, anchored on the daemon's own dir** (P3) — and every
      name-shaped rule is **folded into it** so no verb can choose a weaker validator (the
      `.sha256` reservation now lives inside `validate_artifact_name`; `Registry::snapshot`
      picking the weaker one was M3) [81]. `test` `CI(grep)`
- [ ] **Authenticated by default** (P4): the unauthenticated set is exactly `/healthz` +
      `/openapi.json`; perms-checked key file; constant-time compare **with a gate that a plain
      `==` fails** (the shipped "timing test" hashed both inputs to fixed width first — a `==`
      passed it unchanged; docs/81 m21) [81]; `--allow-unauthenticated` warns per request. `test`
- [ ] **The router is a fold over `API_ROUTES`** (P5) — parity is structural, not asserted: the
      previous gate compared the document to the table it was generated from and stayed green
      through exactly the drift it claimed to catch (M10). The residual gates hold what
      construction cannot: exactly two `.route(` mount sites, every row resolves to a handler, the
      open set is exactly the two meta routes, every `$ref` resolves in a document required to
      contain at least one (the ErrorBody schema — its `error` enum rendered from
      `ErrorKind::ALL`, never a second literal list) [81]. `test`
- [ ] One `DaemonError`, mapped once; `Error::Config` → 400; the client surfaces matchable
      conditions. `test` `review`
- [ ] **The store is create-only and atomic**; snapshot prefixes are part of the create-only
      namespace (`create_dir`, `EEXIST` *is* the check); **a resource is pinned for the duration
      of the operation that writes it** — `VmSlot::pins` covers the snapshot prefix via a
      `SnapshotPin` RAII cleared on every exit path, so delete-in-use excludes a mid-write
      snapshot (M8) [28][81]. `test`
- [ ] **The registry is seam-driven and correctly locked**: per-VM handle mutexes; immutable
      identity read lock-free; **states observable without the handle lock** (M9); ids opaque and
      never reused; "ready" derived from `MicroVm::start` returning. `test` `review`
- [ ] `restore_from` restores via CoW; snapshots land in the store; the tmpfs-marker end-to-end
      pin. `test`
- [ ] Recorded divergences are design, not drift — don't re-flag: daemon extra disks read-only;
      **steward-less cells unexpressible over REST** (the v33-qualified form — `Service`+init is
      legal per delta 10) [33]. `review`
- [ ] `--resource-prefix` threads to both the launcher and the sweep (F2). `test`

### B13 · Privilege-hardening layers  [28]

- [ ] `VmmSeccomp` explicit and typed per backend (CH explicit flag; FC built-in/`--no-seccomp`;
      QEMU `-sandbox` **asserted on the composed argv** — the fragment-vs-composed hole was M11's
      sibling; crosvm always `--disable-sandbox` with `Enforcing` flipping the Layer-2 deny-list,
      the live-validation reversal); the three `Log` unsupporteds typed. **The flip's call site is
      gated, not just the pure function** — `effective_jail_config` could be bypassed with one
      token while every gate stayed green; the plan-type + source-scan pair is the fix (M11)
      [IN][81]. `test`
- [ ] `apply_jail` async-signal-safe, allocation-free, fixed order (rlimits → dumpable →
      ambient-clear → NNP → seccomp → execve); post-apply state gated by the three routes (status
      stand-in, `PR_GET_DUMPABLE` fork-probe, the privileged ambient leg) [28][81]. `test` `review`
- [ ] `clear_ambient_caps` defaults `false` with the at-site reversal rationale; default-on blocked
      on fd-passing [28]. `review` `test`
- [ ] Core-dump/fsize limits match the threat model (P4); the extra deny-list is `EPERM`, opt-in
      until live-validated per backend — **21 syscalls, parsed from the design §12.3 roster by
      discovery** (the gate errors rather than reading an empty table; the version that pinned a
      copy of the const stayed green while the const silently lacked `process_vm_readv`) [81].
      `review` `test`
- [ ] The broker topology exact (P2): forked before the runtime; PDEATHSIG; the child **ignores
      INT/TERM** (a terminal Ctrl-C reaches the foreground group; at default disposition it killed
      the cap-holder before its ordered teardown — M9 of docs/78) and `build_vmm_cmd` resets
      `SIG_DFL` in `pre_exec` (an ignored disposition survives `execve`); the parent's cap-drop is
      **asserted live** (`/proc/<pid>/status` all-zero with the child as positive control — P2 had
      no red-able gate until then) [28][81]. `test` `review`
- [ ] Seccomp crates banned by name in `deny.toml` (§12.5). `CI`

### B14 · Sessions, cloning & lineage  [28]

- [ ] One writer per connection (C4); channelized session I/O with exactly one `SessionExit` (C5);
      a connection owns its sessions (C3) — **including under stdin pressure**: session stdin
      writes go through a per-session writer thread, never inline in the dispatch loop (a full
      64 KiB pipe parked the whole connection, `CloseSession` was never dispatched, and on host
      disconnect `teardown_sessions` never ran — C3 broken at the one moment it matters; the
      512 KiB flood leg is the named live gate the fix's comment once falsely claimed existed)
      [81]. `test`
- [ ] `SessionMux`'s registry is **closable in one critical section** — `open()` after the reader's
      terminal step is the documented typed error, never a handle whose `recv()` waits forever for
      a router that no longer exists [81]; the writer is a channel to a sole-owner task (the
      recorded shape — both satisfy C4; the mutex sketch is superseded). `test`
- [ ] PTY is a real controlling terminal with the pipe negative control (C7). `test`
- [ ] The master is immutable (S3); the fan-out gate is `restore_rotates_host_paths` (never a
      bespoke flag); restore-transport mechanics are per-backend recorded law — cite, don't
      re-derive [IN]. `test` `review`
- [ ] Lineage re-validates through the same predicate; a branch is a flat snapshot, never a chain
      (§8.6); **snapshot destinations are create-only through one law** (`prepare_snapshot_dest`:
      create-with-parents, accept-empty, refuse-populated — the library's `create_dir_all`-then-
      overwrite was m4) [28][81]. `test` `review`
- [ ] Filesystem side effects on the lineage path need the live suite (fake blindness) [28]. `test`

### B15 · The downstream toolkit contract  [30]

- [ ] **The contract surface is one named list** (design §10.4) — v33 grows it: the rootfs/handler
      registry namespaces, the labelled build entry points, the feature-manifest sidecar, the
      `XattrPolicy` parameter, and the kit's new `CheckStatus` variants are contract, each a
      ledgered bump [33]. `semver-checks` covers both contract crates; the CLI half is gated by
      the example workspace invoking the exact documented commands. `CI` `review`
- [ ] The `VMCELL_*` env semantics are specified, not discovered; the harness getters' two
      behaviors are pinned from the consumer position; overrides stay overrides (F7 governs
      registrations, not `VMCELL_KERNEL`/`VMCELL_ROOTFS`) [30][33]. `test` `review`
- [ ] **The example workspace is the living consumer gate** — breaking it is the intended failure
      mode of contract drift; "fixing" the example to stay green inverts the gate. Its packing leg
      is no longer argument-parsing-only: delta 7's from-outside-a-checkout pack (with `--tools` +
      `--steward-musl`) closes the "no rootfs was ever packed from the consumer position" honesty
      note [30][33]. `CI` `review`
- [ ] Validation failures name the missing contract clause; the classifier keys on the emitters'
      real text; `BootKind::{Fresh, Restored}` selects the renderer (a restored VM's empty console
      is deliberately not "not a direct-boot kernel" — docs/81 m9) [30][81]. `test`
- [ ] Git-dep guidance is load-bearing documentation (the patch-stanza replication, the
      downstream-runnable vendor script with both legs and the not-applicable third way) [30]. `CI`

### B16 · VM-to-VM segments & the raw vsock dial  [30]

- [ ] A segment is where taps live, not a new datapath; the exhaustive channel is
      `PerVmResources::segment`; `assert_tap_wiring_matches` joins the two channels. `test` `review`
- [ ] Segment addressing is disjoint pure math; zero new guest code (C6); MACs are `mac_math(vmid)`
      on **every arm of every backend** (the deterministic-L2-collision premise failure). `test`
- [ ] Segment lifetime is Arc-structural; the sweep's `-seg-` class keys against its own id space.
      `test`
- [ ] Fault injection ships as names, not a typed API (the recorded rtnetlink blocker); gates
      include a loss/partition leg, not only delay. `review` `test`
- [ ] The raw dial reuses the one prologue and deliberately not the boot-retry loop; its caveats
      are contract (no post-restore re-bind service for user listeners; baked endpoints on
      non-rotating backends; **half-close is not portable** — drain first, the four-backend table
      is the recorded evidence). `test` `review`

### B17 · Steward placement & the service-mode steward  *(new in v7)* [33]

v33 deltas 4–5 (design §3.5). The defining property: **control-plane availability is the declared
placement, read through one predicate** (law C8) — and the review's job is to keep the predicate
from re-fragmenting into the three accidental spellings it replaced.

- [ ] **Two methods, one enum, call-site-bound**: `StewardPlacement::steward_port()` is the only
      spelling of "is a steward expected, and where" (`steward()`, `connect_sessions()`, the
      control-plane health gate), and `StewardPlacement::resync_reachable()` is the only spelling
      of "may this cell snapshot/clone" (`snapshot()`'s guard, the eligibility predicate's
      placement arm) — two methods because `Service{5000}` and `Pid1` are indistinguishable
      through the port, and an eligibility site reading `steward_port()` is the law's violation
      (the near-miss the design's own review caught). `cfg.init` decides init *identity* only, at
      the cmdline builder plus its two validation sites (`validate_init_path`, the reserved-key
      membership). The gate is the C8 **two-method call-site source scan** — the predicates' unit
      tests alone are not the claim (governing rule 2's v7 sharpening). A new consumer of either
      fact that re-derives from `cfg.init` is this rubric's hardest reject. `test` `CI(scan)` `review`
- [ ] **The fail-loud law kept its teeth and gained its first negative case**: placement `None`
      answers `steward()`/`connect_sessions()` with the typed error immediately (never blocking
      out the connect budget) — and `Service` must **not** take that arm. Before v33 no
      configuration existed in which a custom `init=` and a reachable steward coexisted, so the
      guard had only ever been shown to *fire*, never to *discriminate*; the amendment strengthens
      the law. The fail-first is attributed precisely (the design's review caught the near-trap):
      with `init: None` the buggy and correct predicates agree everywhere, so the discriminating
      leg is `Service` + a **custom `init`** (legal — only `Pid1`+init is the contradiction), whose
      assertion is **refusal identity**: `steward()` proceeds to the transport and times out the
      connect budget, never returns the placement refusal — re-keying any site back onto
      `cfg.init.is_some()` turns that leg red on the wrong error. A `Service` cell's `snapshot()`
      must return the typed placement refusal (`resync_reachable()`). `test`
- [ ] **The health-gate re-key is the site most likely to be missed**: `verify_control_plane` and
      its bounded re-spawn loop run whenever `steward_port()` is `Some` — correct-for-`None`
      rationale (re-spawn to exhaustion against a listener that never comes) does not cover
      `Service`, where a wedged `vhost-device-vsock` bring-up is precisely what the probe catches.
      The delta-4 gate's third assertion is that the gate *ran* (not merely didn't error). `test`
- [ ] **The placement matrix validates at `build()`**: `Pid1` + custom `init` rejected
      (contradiction — the kernel cannot start the steward as PID 1 if `init=` names something
      else); `Service{port}` + `init: None` **legal** — the deliberately-allowed gate combination
      that makes the predicate half verifiable before the service-mode steward exists (the kernel
      starts the steward as PID 1 *and* the host treats it as a service; the steward listens on
      the declared port either way); `snapshotting` ⇒ `Pid1` (for `None` the S2 resync is
      structurally unreachable; for `Service` its post-restore reachability is unmeasured — §17's
      recorded residual, strictly narrower than the pre-v33 rejection, don't re-litigate). `test`
- [ ] **The default is byte-identical**: `Pid1` + `init: None` emits the same cmdline and takes
      the same code path everywhere — the pay-for-what-you-use floor, pinned (a cell that never
      names a placement cannot tell v33 landed). The port moves to **one shared
      `STEWARD_VSOCK_PORT` in `vmcell-protocol`** (both sides re-export; the mirrored-const pair
      retired); a non-default `Service` port rides the existing trusted channel as
      `vmcell_steward_port=` (F3's `vmcell_` prefix already reserves it against caller spoofing),
      parsed clamped-and-untrusted in **both** modes. `test`
- [ ] **`dial_vsock` stays unkeyed** and its wire-driving gate stays green verbatim — the
      placement work must not touch the one path that already made this decision. `test`
- [ ] **Service mode's contract inversions are parameters, never forks** (design §3.5): filesystem
      assembly (`Pid1` only — re-running `pivot_root` in service mode is destructive); the SIGTERM
      policy (PowerOff under `Pid1`; graceful shutdown under `Service` — `systemctl stop` must not
      power off the machine, and `restart` must return); **`PR_SET_CHILD_SUBREAPER` under
      `Service`** — the silent regression: without it a double-forking payload reparents to the
      real init, which reaps it, and `wait_for(pid)` blocks forever on a status never recorded —
      the host sees a hung exec, not an error. Gates: the double-fork exec leg **red-on-inverse by
      removing the prctl call** (the test hangs, bounded by its harness timeout, instead of
      returning the exit code); both SIGTERM legs (service: guest stays up, next exec works; the
      `Pid1` twin *does* power off — a SIGTERM policy that never powers off is the same
      assertion-free shape one placement over); the reservation/epoch suite green **unmoved**
      (pid-reuse correctness is placement-independent). Mode selection is `getpid() == 1` —
      unforgeable and flagless; a proposal to add a mode flag re-argues the recorded choice. `test`
- [ ] **The library split survives the lean gate**: `cargo tree -e no-dev` on the steward crate
      stays free of `tokio|hyper|rtnetlink` after the whole steward moves behind `StewardOptions`
      — the split is the delta, the lean boundary is the invariant. The tracing seam
      (`Install | AlreadyInstalled`) exists so a service under a journal or a host-side unit test
      can decline the global subscriber. `CI` `test`
- [ ] **`mini-init` is gate infrastructure, defended — cite, don't re-litigate** (G1): the
      smallest generic init that starts the steward as a child (mount the core set, spawn, reap,
      **restart the steward on exit** — what makes the service SIGTERM leg satisfiable at all —
      with a rapid-failure cap that powers off fail-loud instead of crash-looping); it exists because live-validating `Service` requires an init that
      is not the steward and neither the pinned base nor CI has one. It is an applet, so
      `GUEST_TOOLS_APPLETS`, the injection manifest, and their pins move together — and **the
      change means nothing to a live suite until the rootfs is rebuilt with
      `--kernel-source host-make`** (the recorded operational trap: a warm rootfs runs the old
      binary and the suite reports on code that is not under test; the bare `vmcell build`
      default is `prebuilt`, which also swaps the kernel and reddens `nested_virt`). `review` `test`

### B18 · The registry, features & the two-directional kit  *(new in v7)* [33]

v33 deltas 2–3 and 6–8 (design §7.4, §10.5, §10.6, §4.7). The defect mode across all of them is
the same: **a declaration is a claim, and an unchecked claim is a fact a consumer builds a fixture
on** — so every rule here is about keeping declarations measurable and removals attributable.

- [ ] **The intersection is an intersection, proven two-sided**: declare a rootfs no-snapshot,
      run it on a `snapshot_restore: true` backend — `why_absent` must name the **rootfs**; run
      the same artifact on an advertising-`false` backend — the removal must name the **backend**.
      The pair together is the only assertion that distinguishes an intersection from a rename of
      the backend flags. One computation site (F6), call-site-scanned; per-op enforcement keeps
      its own authoritative typed refusal (the descriptor is queryable, never a replacement —
      §7.2's standing rule). `test` `CI(scan)`
- [ ] **Unknown feature tokens are hard errors naming the token** at every declaration surface
      (pins entry, feature-manifest sidecar) — absence is the silent direction; the fail-first
      proof is that removing the strict parse turns the typo'd-declaration case green, which is
      the whole hazard. A sidecar-less artifact contributes the **baseline declaration** (the
      canonical artifacts *are* the baseline — stated, not silent); a sidecar, when present, is
      authoritative. `test`
- [ ] **`require(Feature)` refuses pre-boot** with the removal's provenance in the error —
      resolved at `MicroVm::start` (where backend + artifacts exist), never at the first use-site
      call; `build()` stays backend-blind (its config-internal validation unchanged). `test`
- [ ] **Feature strings compose from `Feature::name()`; substring matchers are banned.** The
      evidence for the ban is the retired census: `feature.contains("vhost-user")` (three
      backends), `.contains("custom init")` (four sites), `.contains("segment")`,
      `.contains("USB")`, `.contains("read-only")`, `.contains("boot after restore")` (three),
      `.contains("in-kernel vsock")` (two) — each an assertion strictly weaker than the comment
      above it. Tests match on `Feature::name()`; a new `.contains(` on a feature string is a
      review reject and a sweep-test hit. `test` `review`
- [ ] **Registration is a digest (F7)**: the corrupt-one-byte gate is the whole assertion; the
      dev path-override marks `unpinned` and `bundle` refuses it; `VMCELL_KERNEL`/`VMCELL_ROOTFS`
      keep their override semantics untouched. `test`
- [ ] **The registry extends the kernel shape, sharing the core**: `rootfs_artifact_key` and the
      handler laws mirror `kernel_artifact_key`/`kernel_pin_key` (exported one-law composers) and
      share the merge/collision/sort core — three kind parameterizations of one resolution law,
      never three copies. The legacy-singleton `rootfs` shape is rejected **naming the
      migration** (two accepted shapes for one namespace is parser ambiguity waiting for a
      third); `KNOWN_PINS_NAMESPACES` and `flatten_pins_namespace` grow together. `test` `review`
- [ ] **Laziness is gated red-on-eager**: register a `debian-latest` label, assert a build that
      selects nothing does not build it; register a second label at the **same digest** as
      `default`, assert byte-identical outputs **and** the default's cache key unmoved (the
      empty-change property — the only assertion that catches a registry change quietly re-keying
      every existing artifact). `build-kernels`' default flip to selection-driven is a ledgered
      CLI behavior change with the CI `--all` updated in the same commit. `test`
- [ ] **Handlers land through the injection tail under the existing laws**: the default entry
      names today's workspace build (behavior byte-identical, now data); `GUEST_TOOLS_APPLETS`
      const-asserts the **default** handler only — a labelled handler's roster comes from its
      strict-parsed registry entry; `is_reserved_injection_path` is unchanged (registering more
      artifacts extends nothing about what a consumer may shadow — F5). `test`
- [ ] **`Warn` and `Unverified` have exact semantics**: a present feature that fails is `Fail`; an
      absent one that works is `Warn` (under-claiming is a documentation defect — reddening it
      pushes declarers toward over-claiming, the wrong incentive); a `Warn` **not** in
      `expected_warnings` promotes to `Fail` (a new under-claim must be triaged; without the
      lifecycle, warnings accumulate until nobody reads them — the same terminal state as not
      emitting them); `Unverified` carries *why* and is never counted as a pass (the
      `KconfigValues::get` `None`-vs-`Some(No)` distinction, one level up); `Skip` is untouched
      and still never a pass. `Warn`s route through the classifier like `Fail`s. `test`
- [ ] **Every absence probe is one paired check id with its positive control** — the same probe
      against a declaring artifact must report "works", and deleting the control reddens the
      roster gate (an absence probe without one is a constant that certifies everything). The
      four-leg matrix per decidable feature is the acceptance shape; the live example that
      motivates it: the `usbhost` sidecar was byte-identical to the unlabelled one — the fragment
      was a no-op against the baseline, and a presence-only predicate passed while the fragment
      contributed nothing (re-measure the byte-identity before leaning on it: it is recorded from
      the requester's box and unverifiable on a clean checkout). `test`
- [ ] **The roster gates extend to all three levels via the mechanism, not a waiver**: every check
      records-or-skips its id on every path including pre-handshake failures (the shape Full's
      arms already had), making Core/Extended enumerable against a `fail_create` fake — the
      recorded blocker fixed rather than accepted. `battery_budget` bounds the whole battery
      (per-check deadlines stay); the gate is a stalled fake check tripping the budget typed, not
      hanging. `test`
- [ ] **Xattr policy is per-artifact, both directions gated**: default `Strip` byte-identical
      (cache key unmoved); the `Preserve` twin of `test_pax_xattrs_are_not_preserved`; the live
      leg reads `security.capability` back **in-guest** through the read-only `xattr` applet with
      the `Strip` twin as the negative control; a policy change re-packs (identity fold +
      `STAGE_VERSION`). vmcell's own injections carry no xattrs under either policy. The strip
      rationale's premise ("everything runs as root, capabilities are moot") is *scoped*, not
      reversed — it stays true of the minimal base and the policy exists because it is false of a
      full distro image. `test`
- [ ] **The ext4 producer prefers the crate route and validates the fallback**: a permissive
      pure-Rust ext4 writer is adopted if it passes the mount-and-diff gate (pack → boot as
      `Block` → in-guest tree/xattr/device-node diff against the tar manifest); the fallback is
      external `mkfs.ext4 -d <tarball>` — validated at specification time (e2fsprogs 1.47.2,
      unprivileged, root ownership + `security.capability` + device nodes preserved), with two
      pinned sharp edges: **parent directories must be present in the tar** (no implicit
      synthesis — loud error) and the version gate (≥ 1.47.1 with libarchive) probes fail-loud,
      never mis-builds. Either route sits behind the one Stage so the swap is not a contract
      change; e2fsprogs is a GPL-2 *binary*, spawned never linked (the QEMU/nft carve-out shape,
      recorded). The producer adds an artifact; **the erofs root does not move**. `test` `review`

---

## Part C — Tests that actually test  *(the meta-rubric)*

Every test must be able to **fail**. Before accepting one, construct the buggy implementation it
nominally guards and confirm it goes red; confirm CI actually runs it; and ask what the test
*structurally cannot reach* (rule 4).

**Test smells — reject on sight:**

- [ ] **Skip == pass, in any costume.** A `println!("SKIP") + return`; a zero-selection filter; a
      hand-rolled per-backend skip. Skips go through `require_cap!`, which panics for the primary
      backend and records to the durable `VMCELL_SKIP_MANIFEST`. **Do not conflate nextest's
      `N skipped` summary (deselected tests) with the capability-skip count** — the two sit one
      line apart in the same output, and conflating them is how a published tally went stale
      [46][81].
- [ ] **Asserts nothing / dead fake / self-fulfilling / zero-test crate** [37][46].
- [ ] **The gate tests the extracted helper, not the claim.** [81] The v7 addition, and the
      completeness audit's recurring shape: a pure test beside an unchanged (or bypassable) call
      site — `start_paced` with zero production callers; `effective_jail_config` deletable with
      every gate green; the parity gate comparing a document to its own source table. Demand the
      call-site scan, the fold-the-consumer-from-the-table construction, or the
      private-field plan type.
- [ ] **Fake-blind side effects** [28]: enumerate what the fake cannot observe and name the live
      test — now including the **process table and init behavior** (no fake sees a subreaper bit
      or a systemd boot; deltas 5 and 9 name their live legs) [33].
- [ ] **Filter-independent outcome; missing positive control** [40] — and in the conformance kit
      the control is *structural*: a paired check id whose deletion reddens the roster [33].
- [ ] **The test config neuters the property** (`-k` on the TLS probe) [46].
- [ ] **Loose "or" / proxy-signal assertions**; **coincidental pass / wrong identity** (assert
      positive identities — `post_mac == mac_math(new_vmid)`; where `assert_ne!` is right,
      reserve the source value first) [37][IN].
- [ ] **Vacuous residue checks** (assert existed-before, gone-after; recompute names through
      `vmcell::naming`) [46][28].
- [ ] **Tests the opposite of its name / enshrines a bug** [46][40]; **a comment claiming coverage
      that does not exist** is the same defect in prose — verify the named leg exists [81].
- [ ] **Easy-variant-only state coverage** [37][40]; **mock where round-trip is required;
      same-implementation interop; wrong-codec round-trips** [40][28].
- [ ] **Tiny-payload data-plane tests — in either direction.** Window-filling and
      `>MAX_FRAME_BYTES` payloads move both ways; the guest→host gap is how the ring-wrap panic
      shipped [46][81].
- [ ] **String stand-ins; determinism via a trivial stage; harness strawmen; untested stats
      helpers** (`pcts` nearest-rank with known values; regenerate published tables when the
      harness changes) [40][46][28].
- [ ] **An assertion strictly weaker than the comment above it** — `contains(X)` where the
      comment names the full property; substring feature matchers are the canonical instance,
      banned by B18 [81][33].

**Positive requirements:**

- [ ] Serial execution via the nextest workspace-glob `serial-host` group
      (`package(~vmcell) & kind(test) & !binary(proptests)` — positive selection so new members
      auto-join); nextest pinned so `--no-tests=fail` holds; `#[ignore = "reason"]` with reasons.
      `CI`
- [ ] **Capability honesty machinery**: `require_cap!`; a per-flag honesty pin for every
      `VmmCapabilities` field on every backend (nine — checked against the struct); the three
      seccomp-`Log` pins; the skip manifest measured against a **reset** manifest so the count is
      attributable [46][28][81]. `test`
- [ ] **Failure injection is a first-class suite member**: mid-`start()`/`restore()` faults with
      zero residue; each `FakeVmm` fault arm; helper-daemon spawn-step failures; transient
      resync/transport failure then recovery [37][40][46][28]. `test`
- [ ] **Data-plane assertions** per A10, both directions [46][81]. `test`
- [ ] The standing batteries: snapshot/restore (S2, transport-real per-backend identity); the
      zygote set; the session set (now incl. the stdin-flood leg and the C3-under-pressure
      residue leg [81]); the daemon set (incl. the group-SIGINT orphan leg and the
      broker-parent zero-capability assertion with the child as positive control [81]); the
      segment set; the dial set; the injection set; the toolkit set; the NAT window set (both
      directions [81]); and the **v33 batteries** (design §15.4) [33] — the placement set (the
      three never-before-satisfiable assertions; the `None` fail-loud leg with the `Service`
      negative arm; the byte-identical-default pin; the C8 scan), the service-steward set (the
      subreaper red-on-inverse; both SIGTERM legs), the feature set (two-sided provenance;
      misspelled-token; pre-boot `require`), the conformance set (the four-leg matrix; paired
      controls; the `Warn` lifecycle; the budget), the registry set (same-digest byte-identity +
      unmoved key; laziness red-on-eager; corrupt-blob; bundle-refuses-unpinned; legacy-shape
      reject), the xattr set (both twins + in-guest readback), the ext4 set (mount-and-diff;
      version probe), and the opt-in systemd proof cell (deliberately reddened once at landing).
      `test`
- [ ] Ingest fixture set (device node, zstd, whiteout, hardlink, unknown-type-loud) [40][46];
      guest framing vs the real host codec [40]; cross-process allocator tests [46]; [BP]
      property tests on the stateful protocols. `test`

---

## Part D — Required automated gates

Each item turns a defect *family* into a build failure. **If a Part B/C item reached a human, the
matching gate here is missing — add it.**

**Crate-root lints** (unchanged from v6's two sanctioned variants; the roster note: the steward
crate keeps the full deny family — a PID-1 panic aborts the guest — and the rename does not change
its class [33]):

```rust
#![deny(missing_docs, unsafe_op_in_unsafe_fn, rustdoc::broken_intra_doc_links)]
#![deny(unreachable_pub)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::missing_safety_doc,
        clippy::missing_errors_doc, clippy::missing_panics_doc,
        clippy::multiple_unsafe_ops_per_block)]
#![cfg_attr(not(test), deny(
    clippy::unwrap_used, clippy::panic, clippy::unreachable,
    clippy::todo, clippy::unimplemented,
    clippy::indexing_slicing,
    clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro,
    clippy::allow_attributes, clippy::allow_attributes_without_reason,  // B11
))]
```

**Crate classes [28][IN][33]:** *full family* — the library crates, the steward binary
(`vmcell-steward` post-delta-1), and `vmcelld`. *Print-by-contract binaries* (`vmcell-cli`,
`vmcell-guest-tools`, `vmcell-test-runner`, `vmcelld-ctl`, `bench-vm`) drop the two `print_*`
denies with the rationale in the crate doc. *Wire crates* (`vmcell-protocol`, the steward) add the
cast denies (`not(test)`-scoped — the recorded deviation). Per-module `#![forbid(unsafe_code)]` on
I/O-free modules.

**Gate meta-rules** (the C-GATE-1 lesson, extended [37][40][81]):

1. **Every gate is reachable.** Accepted-red steps run last or non-gating; in the `justfile` the
   same.
2. **Gates have red-on-inverse self-tests covering every rule they claim.** One MUST-flag fixture
   per keyword/rule — and one MUST-PASS fixture per deliberate exemption (the rename ban's
   `AGENTS.md`/"agentic" survivals) [33].
3. **`just ci` and CI are the same thing, by construction.** CI invokes the recipes
   (`run: just test-unprivileged`), and the **gate roster lives in the one `gates` recipe** both
   `just ci` and `ci.yml` call — `scripts/ban-ci-script-handcopy.sh` is the meta-gate: it runs
   first, fails if `ci.yml` names a `scripts/*.sh` directly, and asserts the recipe's roster
   equals the gate-shaped scripts on disk in **both** directions (orphan script *and* stale
   entry). The hand-copy had already drifted three times [81].
4. **A gate binds the call sites, not just the extracted predicate.** [81] When a fix extracts a
   predicate, the gate covers the callers: a source scan (the `virtiofs_pacing_gate` /
   `jail_composition_gate` shape), a construction that folds the consumer from the table (the P5
   router), or a plan type whose defeat is a compile error (`LaunchPlan::jail` private). A pure
   test beside an unchanged call site is theater.
5. **Anything parsing `cargo` output lives in a script with `--color never` at the producer, and
   its self-test exports `CARGO_TERM_COLOR=always`.** [81] CI exports the variable and `just ci`
   does not, which silently killed three `cargo tree` bans for seven weeks;
   `scripts/ban-uncolored-cargo-parse.sh` is the class gate. A gate's not-running output is
   measured once (meta-rule for rule 3 of the governing five).

**CI jobs** (all required; the ban/check scripts and their self-tests live in the `gates` recipe —
the recipe is the roster, per meta-rule 3; new scripts join it and nowhere else):

| Gate | Catches |
|---|---|
| `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` | lint families; format drift |
| Build **and** clippy each lean target — a `cargo tree`-only check compiles nothing | non-default-build breaks |
| Blocking builds of the shipped reduced-host feature configs; the feature powerset (last, blocking) [40] | feature-gated semantic drift |
| **`check-lean-tree.sh --all`** (one law, both callers): steward + runner + `vmcell-privilege` ∌ `tokio|hyper|rtnetlink`; **`check-broker-lean.sh`**: broker ∌ `axum` + `vmcell-daemon`, three-way split (absent / present / cargo-could-not-answer) with the daemon as positive control [81] | privileged-window re-coupling; a negative gate that cannot fail |
| `cargo deny check` (license allow-list; the six seccomp-adjacent `[bans]`) | metadata-masked copyleft links |
| `cargo semver-checks` — `-p vmcell` **and** `-p vmcell-artifact-validator`; the ledger covers what semver-checks cannot see (return types, 0.x minors) [30][81] | unannounced contract breaks |
| The example-workspace CI job — now including the delta-7 consumer-position pack leg [30][33] | downstream-contract drift |
| `cargo doc` (deny broken links) [46] | doc-build rot |
| `cargo nextest run` with per-test timeouts; retries scoped to the VM profile with the honest stanza | hangs; retry-masked rot |
| The `--ignored` integration matrix on the **GitHub-hosted** KVM runner (every live suite wrapped in a delegated scope — a hosted runner's own cgroup is not delegated; the udev device-widening step asserts every node it writes, no `\|\| true` [81]) + `just test-daemon` | the suite being CI-invisible (it was, for the repo's whole history) |
| Skip-manifest surfaced (count + contents, against a reset manifest) [46][81] | skips accumulating invisibly |
| The grep-ban roster with both-direction self-tests: `ban-global-state`, `ban-agent-ip-shellout`, **`ban-legacy-terms` (extended with the steward-rename identifiers + file-count reporting — a roster that resolves to nothing may not print a reassuring message [81][33])**, `ban-artifact-path-join`, `ban-inline-setns`, `ban-kernel-key-composers`, `ban-readiness-timeout-literal`, `ban-test-support-in-production`, `ban-uncolored-cargo-parse`, + the C8/F6 **call-site scans** as they land [33] | one-law drift where drift is not a compile error |
| `check-vendored-vhost.sh` (both ways, three-way split) [30] | the carried patch evaporating |
| `check-agents-md-sync.sh` (byte-equality, newest-doc discovery) [81] | the deployed AGENTS.md drifting from its source doc |
| `--locked` everywhere; toolchain honesty (one MSRV fact, sync-asserted) [52] | MSRV drift (the `time 0.3.45` class) |
| Nightly `cargo-fuzz` over the fifteen decode targets, **on an asserted-nightly toolchain** (`RUSTUP_TOOLCHAIN` + the `rustc -vV` guard; target-count law) [28][81] | parser panics; a fuzz job that fuzzes nothing |
| `shellcheck` over `scripts/`, `git-pre-commit`, the example scripts [BP] | quoting bugs in the scripts that gate everything else |
| `actionlint` (release-pinned, `fallback: none` — install-action does not carry it) + `zizmor`; actions SHA-pinned; a `self-hosted-runner.labels` whitelist for labels no job uses is a gate switched off [BP][81] | workflow bugs; supply chain; disarmed runner-label checks |
| `cargo machete`; `typos` [BP] | unused deps; doc rot |

**Gates that land with the v33 delta pass [33]** (each delta's named gate, per design §18; the
KVM-free halves summarized — the live legs are §15.4's batteries): the extended legacy-terms
fixtures (1); the F6 provenance pair + misspelled-token + computation-site scan + the
no-hand-spelled-feature-string sweep (2); the four-leg conformance matrix + paired-control roster
gates on all three levels + the battery-budget wall-clock test (3); the placement matrix (incl. the discriminating `Service`+custom-`init` refusal-identity leg and
the `Service`-cell `snapshot()` refusal) + the byte-identical-default pin + the C8 two-method
call-site scan (4);
the subreaper red-on-inverse + both SIGTERM legs + the lean-tree survival + the applet/manifest
pins (5); the same-digest/unmoved-key + laziness-red-on-eager + corrupt-blob + bundle-refuses +
legacy-shape gates (6); the xattr twins + in-guest readback + `--tools` both ways + the pack-twice
determinism gate (7); the mount-and-diff + version-probe + parent-dirs pins (8); the proof cell
itself, deliberately reddened once (9); the asymmetric JSON round-trip + `None`-rejected-400 with
the `Service` positive control (10).

---

## Part E — Running a review  *(the process that made 37/40/46 — and 78/81 — trustworthy)*

- **Phase 0 preflight, block-and-ask.** `scripts/review-preflight-priv.sh` answers "am I on a KVM
  host"; a failure whose remediation is `just bless` is block-and-ask, not a static-only downgrade.
  Only a genuinely absent facility downgrades to static-only, with every runtime claim marked
  unverified. [37]
- **Run the suites at HEAD before reading code** — `just ci`, both operating-mode suites,
  `just test-daemon`, `just test-validator`, plus opt-in `test-crosvm`/`test-usb-passthrough`/
  `test-systemd` where their preconditions resolve (probe, don't presume); reset the skip manifest
  first and review it after, so the skips belong to this run [28][81]. The review reports what
  green *does not prove*.
- **Ground in `implementation-notes.md` first.** Recorded, justified deviations are not
  re-reported; newly-found justified deviations are recorded there; entries empirically disproven
  are retired. The design's Appendix A reversals, §17 recorded gaps, **and the §17 v33-residuals
  list** (Service+snapshotting rejected-until-measured; the opt-in systemd cell; the narrow
  `Feature` roster; the ext4 crate-vs-tool resolution; placement-`None` unexpressible over REST;
  the identifier-scoped rename ban) carry do-not-re-flag standing until their retire condition
  fires [28][30][33]. Where a config doc proposes something stricter than this rubric, the rubric
  is the tie-breaker.
- **The delta register binds implementations, not the baseline.** [28][30][33] Until a v33 item
  lands, the code legitimately matches validated 0.14 — a delta divergence is a finding only in
  the change claiming to implement it. A change implementing a delta lands with the delta's named
  gate, reconciles the as-built result in `implementation-notes.md`, and follows the five §18
  register conventions — **re-verify the premise anchors before cutting** (every register so far
  has had at least one false shipped-fact premise; v33's were agent-verified against HEAD and
  still expire as the tree moves), and treat a stale premise as a stop-and-check.
- **Adversarial verification for every Critical/High**: an independent agent tries to refute each
  finding — three lenses (correctness; does the test actually stay green; is it already
  justified) — with a decisive empirical check where one exists. The docs/81 pass added the
  **running probe** as the strongest verifier move (three Registry majors were proven by driving
  the live object, not by reading it) and produced two refutations worth keeping (the CA-lock
  deadlock that wasn't; the out-of-tree-backend "blocker" that is a documented decision) — record
  refutations so they are not re-raised [81].
- **Every finding carries** `file:line`, the category, the red test it lacks, and a direction.
  Expect a residual error rate; confirm cited lines before fixing.
- **Perf findings cite measured evidence.** The `docs/historical/45` refuted-lever table; only
  interleaved same-session deltas; "environmental" is a hypothesis, not a diagnosis — a flake
  explanation without a mechanism stays open, and the project has now withdrawn a recorded
  mechanism that the tree contradicted (the NAT lazy-bind claim) — verify a mechanism against the
  tree before recording it [46][28][81]. Tails before 2026-07-03 are on the broken estimator.
- **A fix to host-facing code is not done** until the suites re-ran green on a KVM-capable host,
  and any capability-flag change re-validates empirically [37].

---

## One-line summary

Make every recurring defect class fail a **lint, a CI job, or a test that can actually go red** —
and treat any item that reaches human review as evidence a gate is missing. The v7
highest-leverage targets: **gates that bind the call sites, not the extracted predicate** (the
completeness-audit lesson — meta-rule 4, B13, C), **accepted inputs with a datapath behind every
variant** (A2 — honor or reject, exhaustively matched), **deadlines that bound the whole operation,
sized by what they bound** (B6 — named ceilings a backend cannot re-spell), **the youngest owning
code reviewed with running probes** (B12 — observable states, pinned-during-write resources,
drained shutdowns), **local ≡ CI by construction** (meta-rules 3 and 5 — one recipe roster, one
producer-side color fix), **one predicate for control-plane availability and one vocabulary for
features** (B17/B18 — C8's call-site scan, F6's two-sided provenance, F7's corrupt-one-byte
proof), and **declarations kept measurable in both directions** (B18 — paired positive controls,
the `Warn` lifecycle, absence probes that can go red) — all validated by actually executing the
suites (rule 5 + Part E), grounded in the design's settled reversals, the implementation notes'
verified premises, and the §17 residuals lists rather than re-litigating any of them.
