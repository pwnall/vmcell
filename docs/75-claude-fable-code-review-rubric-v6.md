# vmcell — Code Review Rubric (v6)

*Distilled from eight Claude review passes (docs 13, 17, 26, 27, 34, 37, 40, 46), two Gemini passes
(25, 33), the doc↔code reconciliation that landed the automated gates (docs/52), the v28 design
restructure with its (now fully landed) delta register, the post-v28 implementation record
(`docs/implementation-notes.md`: the 0.9 → 0.10 pass as built, the docs/72 review-fix pass, the
backend extraction, the QEMU suspend/resume pass, the two crosvm passes), and the **v30 design**
(`docs/74-claude-fable-design-v30.md` — the downstream-platform pass) with its nine-delta register
(§18) and recorded reversals (Appendix A). Its job is to stop the **classes** of defect those
sources found from recurring — not to re-list individual findings. This **v6 rubric** supersedes v5
(`docs/69`, reissued to `docs/historical/`); v6 **re-bases every "delta N" reference on the landed
state** (the v28 register's eleven items are as-built rules now, cited as "the v28 pass"), absorbs
the post-v5 defect history (the H1 dual-claim race, the postcard-adjacent session-mux encode gap,
the errno-classification refinement, the crosvm seccomp reversal, the QEMU one-QMP-connection and
`file:`-URI rules), adds Parts B15–B16 for the two surfaces v30 introduces (the downstream toolkit
contract; VM-to-VM segments and the raw vsock dial), and qualifies one v5 rule the backend
extraction reversed (see "Retired & qualified rules"). Tagging: unmarked items carry over from v2
(reviews 13–34); **[37] [40] [46] [G]** mark items added or sharpened by that pass (G = the Gemini
passes); **[52]** the docs/52 reconciliation; **[28]** the v28 design and its landed pass; **[IN]**
items arising from the implementation-notes record between v28 and v30 (the as-built deviations,
docs/72 fixes, backend extraction, QEMU restore, crosvm); **[30]** items arising from the v30
design; **[BP]** best practices added on judgment, not yet matched to a surfaced defect.*

*The binding register is now **v30 §18: nine design changes specified but not yet built** — deltas
1–8 as one breaking pass (`vmcell` 0.12 → 0.13), delta 9 (`usb_host_passthrough`) separable and
deliberately last. Rubric items tagged with a v30 delta number bind the implementation of that
pass; until it lands, the code legitimately matches the validated 0.12 state — flag divergence from
a delta only in the change that claims to implement it. The v30 §18 preamble's four
register-authoring conventions (sketches advisory; premises are verified anchors; fs-touching
deltas name their live gate; presence-attribute codecs round-trip on their real wire) govern how
those changes are reviewed.*

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
  logic — every duplicated helper eventually diverged, and the divergent copy is where the bug lived
  (the 18-byte inline `ifreq`, the per-backend vhost-user guards, the QMP parse, the
  `shutdown()`-vs-`Drop` order). Review 37 added a third: **static review alone is insufficient** —
  only actually executing the suites surfaced E1–E3, and only adversarial verification kept the
  findings honest.
- **v4 → v5 lesson (docs/52 + design v28):** the reviewed core stabilized while the system grew
  three privilege-sensitive subsystems — an authenticated HTTP control plane whose inputs name
  filesystem objects, a broker that splits capability from network parsing, and a jailer applied
  between `fork` and `exec` — each with defect classes (path traversal, timing-comparable secrets,
  postcard-corrupted presence attributes, ambient-cap stripping that broke the VMM it confined) the
  rubric had never named. And two rubric rules turned out to be on the wrong side of a design
  decision the restructure made explicit; a rubric that silently disagrees with the design is the
  doc-level second copy, so v5 retires them visibly rather than letting reviewers re-litigate.
- **v5 → v6 lesson (the landed v28 pass + docs/72 + the backend/crosvm/QEMU passes + design v30):**
  **specifications drift from reality in both directions, and the drift is where reviews waste
  their time.** Two v28 delta premises were empirically false at implementation ("no consumer" had
  ~18 woven sites, ~10 of them rejection tests; "none is known to use it" had five); two sketched signatures could not survive contact
  (`clone_into`'s trait collision, `agent()`'s dropped timeout); the design body itself accumulated
  stale claims a later doc had to erratum (the MSRV note, the broker leanness phrasing) and stale
  counts ("all seven flags", "the two `Log` unsupporteds"); and live validation kept reversing
  confident static reasoning (crosvm's sandbox, the baked restore CID, the ambient-caps default —
  each caught only by running). The v6 responses: **premises carry verified anchors** and a stale
  premise is a stop-and-check; **sketches are advisory, behavior + gate bind**, with the shift
  reconciled in the implementation notes; **counts and rosters in review prose are checked against
  the tree**, never quoted from memory; and the system's first out-of-repo consumer makes a new
  surface class reviewable — a *contract* (pins overlay, env variables, the validator battery, an
  example workspace) whose defect mode is not a bug but a silent promise-break to a workspace that
  cannot see your diff.

So this rubric is written to be *enforced*, not just consulted. **Five** governing rules:

1. **If a checklist item below reaches human review, the gate that should have caught it is
   missing.** File the missing gate (Part D), don't just fix the instance.
2. **For every test: "Write the buggy implementation. Does this test go red?"** If no, the test is
   theater.
3. **A test CI never executes is not a test; a config CI never builds is not covered.** Skips are
   visible and durable; a zero-selection filter is a failure; non-default feature configs compile
   under a *blocking* gate.
4. **Enumerate what the suite structurally cannot reach. [37][40][46]** For every subsystem, ask:
   which error branches, payload sizes, flow variants, feature configs, and defaults does no test
   drive — **and which side effects the fakes structurally cannot see** (a `FakeVmm` never touches
   the filesystem, so a missing `create_dir_all` on the lineage snapshot path was invisible to every
   fake-driven test and caught only live [28]). Failure-injection, window-filling payloads,
   per-flow-variant coverage, and default-value tests are first-class requirements, not
   nice-to-haves.
5. **Host-facing claims are validated by execution, not reading. [37]** A review of (or fix to)
   host-facing code is not done until the suites actually ran on a KVM-capable host (Part E) —
   capability is **probed** (the preflight), never presumed absent: the box you are on usually
   qualifies, and the blessed runner exists precisely so an unprivileged reviewer can execute the
   privileged suite. Review 37's empirical pass found two Highs and a leak that seventeen static
   sub-reviewers could not see.

### Retired & qualified rules  *(v5, extended in v6)* [28][IN]

Rules superseded or scoped by explicit, landed design decisions. Recorded here so a reviewer citing
an old rubric does not re-open them:

- **"Drop order = declaration order, stated in a load-bearing comment" (v4 A4/B1).** The v28 pass's
  delta 7 (landed) replaced implicit field-order teardown on the error path: `EnvSetup` has an
  **explicit `Drop`** that calls the same ordered helper (`teardown_post_instance`) the success
  path uses — one law, two callers, pinned by a drop-order recording gate. Load-bearing teardown
  encoded only in field declaration order is a review reject, not a documented pattern: it was
  correct but invisible and reshuffle-fragile (design §9.4).
- **"`limits_enforced` reflects ALL requested controllers, not just memory" (v4 B2).** The v28
  pass's delta 3 (landed) resolved this the other way: the field is **renamed
  `mem_limit_enforced`** and deliberately means only "the memory controller is delegated" — the one
  controller whose silent absence lets the cap not fire; the read path holds only the cgroup name,
  so a whole-`ResourceLimits` guarantee was never implementable there (design §7.1). The fix was
  making the name tell the truth, not widening the claim. This *narrow-name-for-narrow-claim*
  doctrine is now generative: v30's `usb_host_passthrough` (not a generic `host_device` flag) is
  the same move (design §2.1) [30].
- **"`#[non_exhaustive]` on every growable public type" (v5 B8) — QUALIFIED, not blanket.** [IN]
  The backend extraction deliberately made five shared VMM-contract types **exhaustive**
  (`VmmCapabilities`, `PerVmResources`, `RootfsSource`, `ConsoleMode`, `VsockTransport`): every
  out-of-tree backend must construct or exhaustively match them, so a new field/variant is a
  **compile error in every backend crate** — the intended fail-loud — where `#[non_exhaustive]`
  would let it slip through as an unhandled default. Safe because every crate is `publish = false`
  (no external consumer relies on non-exhaustiveness); the cost is a version bump per new field
  (the 0.11→0.12 `disk_io_throttle` precedent; v30 delta 9 repeats it). The rule now reads:
  non-exhaustive for types that grow *toward callers*, exhaustive for contract types that grow
  *toward implementors* — and flipping either direction is a recorded design decision, not a style
  fix. Corollary (v30 §6.2): `NetConfig` **is** `#[non_exhaustive]`, so a new variant is *not* a
  compile error out-of-tree — a change adding one must thread its per-backend obligation through an
  exhaustive channel instead (v30 threads segments through `PerVmResources`) [30].

### Enforcement legend

`lint` compiler/clippy deny (fails the build) · `CI` a CI job · `test` a test that must fail on the
buggy impl · `review` human/agent judgment, no mechanical gate yet.

---

## Part A — Cross-cutting principles

The generative rules. Most Part B checks are corollaries; when a new situation isn't covered,
reason from these.

1. **Fail loud, typed, and early.** No swallowed `Result` (`let _ =` without a justifying comment),
   no `Ok(())` on a failed or unsupported branch, no panics on any path a guest or the network can
   drive. An error is *visible*, *typed* (matchable, not `Error::Other(String)`), and *prompt*
   (checked before a long timeout masks it). Three sharpenings: **a semantic result is part of the
   contract** — an exec's non-zero exit code is a failure even when the transport succeeded [40];
   **errors are errno-precise** — the kernel refusing a *value* (`EINVAL`) is `Error::Cgroup`, a
   permission errno (`EACCES`/`EPERM`/`EROFS`) is `CapabilityUnavailable`, an **absent facility**
   (`ENOENT`/`EOPNOTSUPP` — e.g. `memory.swap.max` on a kernel without swap accounting) is
   `Error::Cgroup` too, because "enable delegation" is the *wrong remediation* when the controller
   is delegated and the host simply lacks the file [IN], and the split is a pure function
   unit-tested against each inverse [46]; and **a returned count is part of the result** —
   `Ok(n)` where `n < requested` (a short write, a partial `send_slice` enqueue) is not success;
   handle the remainder or fail [46].

2. **Every accepted input is honored or rejected — silent degradation is the default bug.** A
   *requested functional* op that cannot be performed returns a typed error
   (`Error::CapabilityUnavailable { op, needed }` / `Error::Unsupported { vmm, feature }`), never a
   logged-and-ignored no-op returning `Ok`. Three categories, and a review places every host-facing
   op in one: *functional* (fail loud) · *observational* — a read — (may degrade, surfacing what was
   unavailable via `*_read_ok` / `mem_limit_enforced` flags) · *explicitly-listed best-effort* (the
   §16 benchmark knobs; visible `warn!`, never silent). The test: *if a caller's assertion can be
   wrong because the op silently did nothing, it is functional.* Generalized by 37/40/46: the rule
   covers **every accepted input** — a config field dropped with a bare `let _ =`
   (`Privileged { host_services_port }` [46]), an enum variant with no code path behind it
   (`Egress::Open ≡ Blocked` [46]), a request field the far end never reads (`ExecRequest.timeout`
   in the guest [G]), a restore mode hardcoded away (`RestoreMode::Lazy` on FC [37]), and a CLI flag
   whose unknown value silently selects the default [46]. **A `#[cfg]` feature gate never silently
   changes semantics** — a feature-gated arm of a functional op that no-ops (`create_slice` under
   `not(metrics)` [40]) is this bug in build-config form; features gate availability (compile error
   or typed error), never behavior. **Defaults get the strictest scrutiny** — a dead default is
   worse than a dead option, because every caller inherits it [46]. And where a field is meaningful
   on only one variant, **move it there so the invalid state is unrepresentable** instead of
   accepting-then-rejecting it at `build()` — the landed v28 pass moved `host_services_port` into
   `NetConfig::Unprivileged` (its delta 4) and deleted the now-unreachable negative test; v30's
   `NetConfig::Segment` repeats the move by *omitting* `egress`/`host_services_port` entirely
   (design §6.2); the compiler is the strongest validator [28][30].

3. **Capabilities are declared, probed, and reported — once — and the report is pinned.** Backends
   report `VmmCapabilities`; the host environment is probed into the **one start-up
   `HostCapabilities` descriptor** (effective caps, KVM group, netns-dir reachability, delegated
   controllers, non-threaded `domain` scope — the v28 delta 8, landed; design §7.2) that mode
   selection, the daemon's main, and per-op checks all *read* — scattered per-op re-probes are the
   descriptor's second copy and diverge (as built, per-op *enforcement* keeps its own authoritative
   per-write typed check; the descriptor is the queryable source, not a replacement — the recorded
   Delta-8 reconciliation) [28][IN]. A backend's typed refusal names the capability it lacks with a
   **feature string equal to the `VmmCapabilities` field name** (`Unsupported { vmm, feature }`),
   pinned per backend — a prose-y feature string is ungreppable and drifts [IN]. A requested mode's missing prerequisites fail loud up front, never
   mid-run. Sharpenings: every advertised flag is **live** (a `lazy_restore: true` with no plumbing
   is a lie [37]) and **empirically backed** (FC advertised `snapshot_restore` while the path failed
   end-to-end until validated on a real host [37]); every flag on every backend has a
   **capability-honesty pin test** so a silent regression to `false` cannot turn a scenario into a
   green no-op [46]; accessors are honest (`guest_cid()` must not report the fresh allocator CID
   while the restored guest keeps its baked one [46]); and **a transient probe failure is never
   cached as a permanent negative capability** — distinguish "unsupported" from "probe failed", and
   log the latter [40].

4. **Ownership owns cleanup — on panic, on post-acquire failure, and on every spawned helper.**
   Every acquired host resource (VMM process *group*, virtiofsd, auxiliary daemons, netns, cgroup,
   overlay, sockets, scratch dirs, CID, VMID, threads/runtimes) is released in reverse dependency
   order, and that path runs on panic. A resource acquired before a later fallible step is owned by
   an RAII guard *before* that step — and this applies to **each** spawned process individually:
   reaping the primary VMM's group while dropping the un-guarded second daemon orphans it (the
   `vhost-device-vsock` leak [37]). **The teardown order lives in one named helper**
   (`teardown_post_instance`) that every path calls: `shutdown()`, `Drop`, the `EnvSetup` explicit
   `Drop` on mid-`start()` failure (the v28 delta 7 — the retired declaration-order pattern), and
   every daemon-registry variant (`destroy` / `shutdown_all` / registry `Drop`) — two
   hand-maintained orders diverge [40][28]. v30 extends the family, not the copy-count: a segment
   member's teardown releases its *slot* through the same helper and **never deletes the segment
   netns** — the netns dies with the last `NetSegment` Arc holder, making the
   never-delete-a-netns-under-a-live-VMM hazard structural (design §6.5) [30]. A drop-order recording gate asserts the success and error paths emit
   the identical sequence. The hard-kill path that skips every `Drop` is reclaimed by the start-up
   orphan sweep against an **empty** live set (design §11.4) [28]. Cleanup ops are idempotent (no
   spurious re-delete WARNs masking real failures [37]).

5. **One law, one predicate.** A contract enforced at multiple boundaries (snapshot-eligibility at
   `build()` / `orchestrator::restore()` / backend self-guards) is implemented as **a single shared
   predicate** each boundary calls, pinned by its own unit test — per-backend copies *demonstrably*
   diverge (the FC copy never grew the virtio-fs-rootfs term the CH copy carried [37][40]). A method
   whose correctness depends on "the caller checked first" is a latent bug: check inside, return
   `Error::Unsupported`. The same for config: validate in `build()` — including documented
   incompatibilities (`ksm_mergeable ⊥ vhost-user` [37]) — with a negative test per rejected case.
   The census of one-law functions now includes `config_has_vhost_user_device` (law S1, §8.1),
   `is_reserved_cmdline_arg` (F3, §5.3), the `vmcell::naming` name/filter composers +
   `validate_resource_prefix` — which `NetSegment::new` must route through too (F2, §9.3/§6.5) —
   `resolve_artifact_path` (P3, §11.3), `ensure_blessed_or_explain` (P1, §11.2),
   `vmm_seccomp_args` + `apply_jail` (§12.2–§12.3), `check_clone_eligible` (§8.5),
   `uses_in_kernel_vsock` (§2.4) [IN], `MAX_FRAME_BYTES` and `MAX_BROKER_FRAME_BYTES`, the
   cache-key rules (F4, §10.2), the shared `build_kernel_cmdline` and the `pcts` percentile
   estimator (whose python-heredoc second copy in a perf script was a confirmed live divergence,
   removed by moving the script into the bench crate [IN]) — and, with v30:
   `is_reserved_injection_path` (F5, §4.2), `net_uses_tap` (§6.2), `segment_ip_math` beside
   `ip_math` (§6.5), the extracted vsock `CONNECT/OK` prologue shared by `connect_framed` and
   `dial_vsock` (§3.2), and the one id-claim core (`flock` + `hard_link`) both `VmidAllocator` and
   `SegmentIdAllocator` use (§6.5) [30]. Standing consolidation target, recorded not urgent:
   `harness::ch_bin()` duplicates `vmcell::artifact::ch_binary_path()` (v30 §17) [30].

6. **Validate at the boundary; return, don't assert; symmetric paths get symmetric handling.**
   Library code reachable from a test, the API, or the wire takes untrusted-shaped input:
   out-of-range values return `Err`; `assert!` on an input path takes down the runner; an
   `.expect()` on a guest-controlled descriptor index is a guest-drivable panic, and if TX degrades
   gracefully, RX must too. Sharpening [37][46]: **a cross-cutting protocol invariant lives in one
   shared helper every request method routes through** — `exec()` honoring the desync flag while
   `put_file()` bypasses it lets a stale frame be read as the wrong reply; one method participating
   in a protocol its sibling ignores is the per-method copy of principle 5.

7. **Determinism is tested, not assumed.** Anything feeding a cache key or claiming reproducibility
   has a test pinning a golden value, identical across processes/checkouts, exercised on a **real**
   stage. Inputs are hashed in deterministic order, as content (not absolute paths), with a stage
   version and pinned SHA. Sharpenings: hash the **full source closure** a binary compiles from, not
   its entry file [37]; fold **content on every flow variant** that supplies the input — the
   `--agent-musl` path folding a path string while the default path folds content is a per-variant
   cache-poisoning hole [46]; key concatenation is **injective** (length-prefix or delimit fields;
   `"ab"+"c"` must not collide with `"a"+"bc"`) [37]; **directory outputs** are first-class (hash
   via a deterministic sorted walk; `reset_to` removes them) — a `hash_file`-on-a-directory `EISDIR`
   landing in a `warn!` arm silently exempts the most expensive stage from caching *and* tamper
   verification [40]; and fold only **consumed** inputs (over-invalidation is safe but wasteful —
   an acceptable trade only when recorded) [40].

8. **Verify everything you ingest — and parse it fallibly.** Every downloaded artifact is checked
   against a pinned hash before use; pulls are digest-pinned; verification failure is a hard stop; a
   stale cached intermediate is verify-or-purge. Sharpenings: **fetch once, verify, and use those
   same bytes** — parsing the layer list from a second, unverified manifest fetch is a registry
   TOCTOU [46]; **malformed input is an error, not an empty default** — `parse_pins_json` degrading
   a garbled file to an empty map fails later with a misleading "missing pin" [37]; **unknown
   input classes fail loud** — an unrecognized OCI media type or tar entry type silently skipped
   (`_ => continue`) is data loss waiting for a hardlink-heavy base [37][46]; and half-specified
   fallbacks are rejected (an image and its digest default together or not at all [37]).

9. **A seam you can't fake is a unit you can't test — and a fake must be *faithful*, *driven*,
   *failure-injectable*, and *honest about its blind spots*.** No module-global mutable state for
   IDs, time, or I/O; side effects go behind small injectable traits with a real impl and a
   recording fake, and the process-wide set travels as **one `HostEnv` bundle** (the v28 deltas
   1–2, landed; v30 grows it by `segids` — the documented growth-by-field mode) so a
   test builds `HostEnv::hermetic()` and substitutes field-by-field. Four fake pathologies:
   **over-promise** — `FakeCgroupFs` enforcing delegation regardless of feature while the real
   non-`metrics` impl no-ops means no test can see the real bug; a fake is never *stronger* than the
   real impl on the property under test [37][40]; **wrong layer** — `FakeGuestResync` bypassing the
   desync layer hides the wedge that layer causes; the fake sits at the same seam the real path
   traverses [46]; **no fault injection** — a `FakeVmm` that records but cannot be told to fail
   leaves every error path untestable — resolved by the v28 pass's `FakeVmm` fault menu (fail
   `create`/`boot`/`restore`/`resume` at a chosen step, delay readiness, wedge the control socket),
   and each fault arm gets a driving test [46][28]; **structural blindness** — a fake elides whole effect
   classes (the filesystem, for `FakeVmm`), so enumerate what it *cannot* see and ensure a live
   test covers exactly that (the lineage `create_dir_all`, Appendix A reversal 11) [28].

10. **Assert on the plane the property lives on. [46]** Control-plane green does not prove the data
    plane: all 59 privileged tests passed with post-restore guest networking dead, because
    `snapshot_restore.rs` asserted only over vsock. A networking property needs an **egress byte**;
    a restore property needs the *restored* VM to move real traffic; a proxy property needs a real
    upstream (or an explicit doubles-only contract test); a data-pump property needs **payloads that
    fill the window** — the NAT byte-drop survived every test because tests moved tiny payloads.

11. **Mandatory recovery stays retryable. [37][46]** A one-shot flag consumed *before* the work it
    guards succeeds converts a transient failure into a permanent silent skip (`restored` cleared
    before the resync ran [37]) or a permanent wedge (the desynced client cached with nothing ever
    calling `reconnect()` [46]). Consume state only after success; on failure, evict/invalidate so
    the next call retries; and test the transient-failure-then-recovery sequence, not just the happy
    path.

12. **Security checks anchor on trusted data and prove the negative. [37][40][46]** A
    containment/authorization check anchored on attacker-influenced data is vacuous — a
    caller-supplied path always contains its own `target/` ancestor; anchor on the runner's *own*
    canonicalized location and test with adversarial fixtures (`..`, symlinks, foreign `target/`
    dirs) [40]. The daemon's instance of the same law: every client-supplied artifact name resolves
    through the one allowlist validator anchored on the daemon's own `--artifacts-dir`
    (`resolve_artifact_path`, law P3) — never `dir.join(client_string)` at a call site [28].
    Security matchers **normalize** before comparing (lowercase, strip the FQDN trailing dot — the
    deny-list was bypassable by `EXAMPLE.NET.` [37]). A security assertion carries a **positive
    control**: a blocked attempt against a black-hole address fails filter-independently; prove the
    same target succeeds via the allowed path and is blocked via the filtered one [40]. And the
    test configuration must not neuter the property under test — passing `-k` everywhere disabled
    exactly the TLS validation whose failure the probe mishandled [46].

13. **One process may hold capability or parse untrusted input — never both; and posture matches
    lifetime. [28]** The broker split (law P2, §12.4): the HTTP-serving parent drops **all** caps
    before serving; the cap-holding broker child never parses network input (its socketpair frames
    are length-bounded by one constant and come only from the parent). Posture follows lifetime
    (law P1): a *transient* privilege wrapper (the runner) drops-and-execs so caps live across one
    `exec`; a *long-lived* privileged server (`vmcelld`'s cap-holder) verifies the effective-set
    precondition, **retains** its caps, and **refuses to start degraded** — never a daemon that
    comes up without `CAP_NET_ADMIN` and fails every privileged create at first use. Secrets never
    sit in process-visible surfaces (law P4): keys arrive via perms-checked files, never argv/env;
    `RLIMIT_CORE=0` + non-dumpable keep guest RAM out of core dumps.

---

## Part B — Review checklist

### B1 · Resource lifecycle & teardown  *(Critical in every pass)*

- [ ] `MicroVm`'s `Drop` performs the full ordered teardown — **VMM process group → virtiofsd →
      netns / cgroup / overlay / sockets / scratch dir** — exercised by a panic-residue test that
      asserts the **full order** via recording fakes, not merely that *a* drop happened. `test`
- [ ] **All teardown paths route through the one ordered helper** (`teardown_post_instance`):
      `shutdown()`, `Drop`, the `EnvSetup` explicit `Drop` on mid-`start()`/`restore()` failure
      (v28 delta 7), and the registry's `destroy`/`shutdown_all`/`Drop` — two hand-maintained orders
      diverge (`shutdown()` deleted the netns before the in-netns proxy while `Drop` was correct
      [40]). The drop-order recording gate asserts success and error paths emit the identical
      sequence; a mid-`start()`/`restore()` failure-injection test asserts zero residue. Encoding a
      load-bearing teardown sequence only in struct-field declaration order is a reject (the
      retired v4 pattern). [40][46][28] `test` `review`
- [ ] Process teardown uses a **group kill that waits** (`kill -9 -<pgid>`, pgid cached at spawn,
      then reap), not `start_kill()` and not `Child::id()` after an await (returns `None`, so
      `kill(-pid)` no-ops). Applies to all backends *and every helper daemon they spawn*. `review`
- [ ] **Each spawned helper has its own RAII guard before subsequent fallible steps** — reaping the
      primary VMM's group on an error path while dropping the un-guarded vsock/fs daemon orphans it
      (H-QEMU-1); transient probe VMs (the FC T2 probe) are reaped through the same shared helpers,
      not a hand-rolled non-reaping loop. [37][40] `review` `test`
- [ ] `Drop` releases **both** CID and VMID to their allocators; a unit test builds a `MicroVm`,
      drops it, and asserts the same ids re-allocate (the drop-order test with `cid: None` no-ops
      the release path and proves nothing). [40] `test`
- [ ] Per-VM scratch dirs are owned (a `VmTempDir` guard dropped last), and the residue assertion
      covers the **directory**, not only the socket inside it — 36 `/tmp` dirs leaked under a green
      residue test that checked the socket alone. The per-clone CoW copy lives *inside* the scratch
      dir so the same teardown reclaims it — a clone dir outside the owned tree is an unreclaimed
      leak by construction (S3, §8.4). [37][28] `test`
- [ ] Spawned-forever workers (smoltcp NAT, proxy, runtimes) hold a shutdown signal + `JoinHandle`;
      `Drop` signals and joins **within a timeout**. A worker blocked pre-connection (an `accept()`
      that never checked its kill-eventfd) deadlocks the join. [46] `test`
- [ ] Cleanup is **idempotent**: an explicit `delete()` followed by `Drop` must not re-delete and
      log a spurious WARN that trains readers to ignore real teardown failures. [37] `review`
- [ ] `request_shutdown()` is followed by a bounded grace-poll (`has_exited()`), then the SIGKILL
      fallback — never an immediate unconditional `kill()`; the grace deadline is computed
      **before** the shutdown RPC so the round trip spends the grace instead of extending it
      (§9.4). [28] `review`
- [ ] `sweep_orphans()` (injectable `OrphanScanner`; non-live vmids only; netns → cgroup → scratch
      order) reaps hard-crash residue; **the daemon runs it at start-up with an empty live set**
      before owning any VM (its own hard-kill counterpart, §11.4); sweep filters come from
      `vmcell::naming` so a produced name can never outrun its filter (F2); the fully-automatic
      periodic sweeper is a recorded §17 gap — keep it visible, don't re-justify it per review.
      [28] `review` `test`
- [ ] **Guest/network-driven in-flight state is bounded and reclaimed — at every accumulation
      point.** The smoltcp pool cap, the PID-1 reaper status map, **the proxy request log** (an
      unbounded `Vec<String>` fed by guest requests is the same DoS in a different subsystem [40]),
      **allocations sized from guest input** (`vec![0; desc.len()]` up to 4 GiB from a descriptor
      [37]), and the daemon's upload path (size-capped by `--max-artifact-bytes`, streamed to a
      temp file, never buffered unbounded [28]) — cap, ring-buffer, or clamp each, and assert the
      bound after a flood. The host-side per-session queue is the *recorded* unbounded trade
      (host-trusted; §17) — visible, not re-flagged. `test`
- [ ] Reclaim predicates are tested with the resource **live**: the pool test using only
      `stream = None` missed that a closed mapping with `stream = Some` counted live forever,
      self-inflicting the DoS the cap was built to prevent. On any transition to closed/error,
      *every* branch releases the associated resource (`take()` + shutdown), not just the branch the
      happy path exercises. [37] `test`
- [ ] Concurrent-startup patterns are cancellation-safe: `try_join_all` over daemon starts leaks the
      already-started process groups when one future fails and the rest are dropped — the recorded
      OPP-10 rejection; a replacement needs a `join_all`+owner-push design plus a zero-leak
      failure-injection test. `Zygote::spawn_clones` is the shipped positive pattern: concurrent,
      **all-or-nothing**, tearing down the already-up clones in the documented order on first error
      (§8.4). [BP][28] `review` `test`
- [ ] [BP] Helper daemons set `PR_SET_PDEATHSIG(SIGKILL)` in `pre_exec` (belt to the sweeper's
      suspenders: a SIGKILLed orchestrator can't run `Drop`) — the broker child does the same so no
      orphaned cap-holder survives its parent (§12.4) — and host-side fds are `CLOEXEC` so spawned
      VMMs don't inherit sockets/locks that outlive teardown. [28] `review`

### B2 · Failure visibility

- [ ] No `.unwrap()` in non-test code. `.expect("invariant: …")` is the only escape hatch and is
      **not** permitted on guest-/network-driven paths (smoltcp packet loop, both TX and RX vring
      ops, PID-1 dispatch, proxy, in-process FUSE queue dispatch, the daemon's request handlers and
      the broker's frame loop [28]) — those degrade gracefully. `clippy::expect_used` is not
      currently denied, which is how a production `expect()` survived in `exit_event` — deny it
      with per-site `#[expect]` + invariant reasons, or grep-ban it in the guest-driven modules.
      [46] `lint` `review`
- [ ] PID-1 never exits on a recoverable condition — including the **primary signal path**: a
      SIGTERM handler that `break`s out of `main` kernel-panics the guest just as surely as the
      fallback path it contradicts. Loop or power off (law C1, §3.4). Fatality is consistent with
      the documented core-mount policy (a `/sys` `create_dir_all` should not be fatal while the
      `/sys` *mount* is tolerated). [40] `review`
- [ ] The reaper does not steal an exec'd child's exit status (false `127`): the
      `ReaperCoordinator` pre-spawn epoch discipline (AGENT-2) stays pinned by its red-on-inverse
      unit test, and the record/reserve critical-section gap under pid reuse stays a *recorded*
      deferral, re-checked when touched. [40] `test`
- [ ] No `Ok(())`/printed success on a failed or unsupported branch: a QMP `{"error":…}` swallowed,
      a `snapshot()` that resumes-and-returns-Ok on failure, a CLI verb that prints success while
      doing nothing, a **mandatory sidecar written best-effort** (an FC snapshot "succeeding"
      without the sidecar its own `restore()` hard-requires is an unrestorable artifact reported as
      restorable [37]). **Removed** CLI verbs (`exec`/`ls`/`rm`/`destroy`, the v28 delta 11) print
      the `vmcelld-ctl` redirect and exit non-zero, pinned by a table-driven test asserting each
      message names the **exact** `vmcelld-ctl` verb that exists (`destroy` → `rm`; a bare
      `contains("vmcelld-ctl")` let a wrong-verb redirect ship green [IN]) — a verb that vanishes
      from `--help` with no message is a support trap. [28] `review` `test`
- [ ] Every `let _ = result;` carries a justifying comment — the `host_services_port` silent no-op
      shipped behind a bare, uncommented discard, found independently by three review clusters.
      [46] `review`
- [ ] Error **detection** is correct, not inverted or loose: any-error-as-success probes (the FC T2
      probe; guest-tools `probe_connect` returning true on *any* proxy reply, mapping TLS failures
      and timeouts to exit 0 [46]); bare `ends_with` domain matching; `contains("\"error\"")` QMP
      sniffing; a single-line QMP read capturing an async `{"event":…}` as the command reply [37].
      Shims that emulate a tool are **exit-code-faithful** to it (curl's 60/28/56). `test`
- [ ] A remote exec's **exit code is checked**, not just its transport: `?`-propagating the send
      while `warn!`-ing a non-zero exit swallows a persistently failing mandatory step (the clock
      resync). [40] `review`
- [ ] Readiness signaling propagates build failures: a startup channel that sends `Ok(port)` before
      (or regardless of whether) the underlying builder succeeded converts an immediate config error
      into a mysterious timeout. Polling loops check `process.try_wait()` and surface
      stderr/serial context; every VMM control RPC is bounded (5 s) so a wedged API socket is a
      typed `Error::Timeout`, not a hang. [G][46] `review` `test`
- [ ] **A requested capability-dependent op fails loud** (`CapabilityUnavailable { op, needed }`),
      with the §7.2 errno split (`EINVAL` → `Error::Cgroup`; permission errnos →
      `CapabilityUnavailable`) unit-tested both ways. `mem_limit_enforced` means exactly
      "memory-controller delegated" — the deliberate v28 delta-3 narrowing (see Retired rules); the
      `CgroupFs`-fake enforcement tests pin the memory-controller-only meaning (implementation-notes,
      Delta 3 — there is no doc-test; name the real gate). Per-op checks *read* the start-up `HostCapabilities` descriptor
      (v28 delta 8; the descriptor is queryable, per-write enforcement keeps its own typed check —
      the recorded reconciliation), never re-probe. Best-effort is only the listed §16 knobs, with
      a visible `warn!`. [46][28][IN] `test`
- [ ] A **configured limit is proven binding, not just readable**: `memory.max` read back correctly
      on all three backends while shmem-backed guest RAM sailed past it — the enforcement test sets
      guest RAM *above* the cap and asserts the cgroup `memory.events oom_kill > 0` (which is why
      `create_slice` writes `memory.swap.max=0` + `memory.oom.group=1`). Configuration readback is
      not enforcement. [37] `test`
- [ ] Unknown/unhandled protocol variants are logged (and the connection policy decided), never
      silently dropped into a desync. [40] `review`
- [ ] Logging goes through `tracing` at the right level; no `println!`/`eprintln!` in production
      code; mutex poisoning handled deliberately. [BP] Serial logs and proxy logs may contain guest
      data — cap retention, and never log the CA private key, the daemon API key, or other secrets
      (law P4). `lint` `review`

### B3 · Capability & input contracts

- [ ] Typed `Error::Unsupported { vmm, feature }` for every capability gap; law rejections at the
      orchestrator boundary use it too (an `Error::Config` there breaks callers matching
      `Unsupported` [40]). Advertised capabilities are live, empirically validated, and **pinned
      per-flag per-backend** (every `VmmCapabilities` field — eight today, nine once v30 delta 9
      lands; the count is checked against the struct, never quoted from memory — four of the
      original seven had no honesty pin, so a flag regressing to `false` would green-out its whole
      scenario [46]); the **three** seccomp-`Log` unsupporteds (FC, QEMU, crosvm) are pinned as
      typed errors, never a silently substituted mode (§12.2) [28][IN]. A deliberately narrow flag
      keeps its narrow name (`usb_host_passthrough`, not `host_device_passthrough` — the flag
      claims exactly what is validated; the flag+config+typed-refusal *pattern* is what
      generalizes) [30]. `test`
- [ ] `restore()`/`snapshot()` self-guard on `capabilities()` *and* on the absence of any
      vhost-user device via the **single shared predicate** `config_has_vhost_user_device` (law S1,
      §8.1) — never per-backend copies (they diverged [37][40][46]) — returning `Err(Unsupported)`,
      with the shared-predicate unit test plus a negative test at each of the three boundaries, and
      the "extra virtio-blk does **not** flip the predicate" test (a false positive wrongly
      disqualifies snapshot, §4.6) [28]. `test`
- [ ] `create()` rejects configs the backend can't honor instead of silently building a broken VM —
      and the **primary backend is not exempt**: CH and QEMU built a kernel-panicking VM for a
      `VirtioFs` rootfs while only FC rejected it. [40] (`RootfsSource::VirtioFs` was deleted by
      the v28 pass — whose "no consumer" premise turned out to cover ~18 woven sites, the recorded
      premise-verification lesson [IN]; the enum is now deliberately exhaustive post-extraction, so
      re-adding is a compile-visible change.) `test`
- [ ] `VmConfigBuilder::build()` returns `Result` and rejects, with a negative test each: duplicate
      share tags and tag/`guest_path` containing `:`/whitespace or non-absolute paths (§4.5);
      snapshotting + {**any** data share, unprivileged net, **a custom `init`** (§5.3)}; documented
      incompatibilities (`ksm_mergeable` + any vhost-user device [37]); `vcpus == 0`; `mem_mib`
      below floor; out-of-range vmid; empty/non-absolute extra-disk paths, duplicate extra-disk
      images, an `io_limit` that limits nothing or caps at `0` (§4.6); a `resource_prefix` outside
      `[A-Za-z0-9]{1,6}` (§9.3); an `extra_kernel_args` entry hitting `is_reserved_cmdline_arg`
      (F3). `host_services_port` on the privileged variant is **unrepresentable** since the v28
      pass — the type does the validator's job. v30 adds, each with its negative test:
      `snapshotting` + {`NetConfig::Segment`, any `usb_host_devices`}; a segment member whose
      `resource_prefix` differs from its segment's; duplicate `UsbHostDevice`s. (The `ExtraFile`
      dest rejections live at the *pack tail*, not `build()` — B4/B5; `ExtraFile` is a rootfs
      pack-time parameter, never a `VmConfig` field.) [46][28][30]
      `#[must_use]` on builder methods. `test`
- [ ] **No dead variants or flags advertised as live**: an `Egress::Open` default with no code path
      admitting egress; a wire feature bit (`VIRTIO_NET_F_CTRL_VQ`) with no backing queue/handler;
      a `RestoreMode` a backend ignores — implement, reject typed, or remove (the v28 pass removed
      `VirtioFs`; the pattern generalizes — and v30 applies it to the CLI: `--kernel-source
      prebuilt` with a label/fragments **silently dropped both**; it becomes a typed error, delta
      3). [37][40][46][28][30] `review` `test`
- [ ] Accessors stay honest across state transitions (`guest_cid()` after restore reports the CID
      the guest actually has). [46] `review`
- [ ] The workload runs only **after** cgroup placement: spawn paused (QEMU `-S`; CH/FC
      create-then-boot), `add_task`, then start — `boot()` as a no-op `cont` on an already-running
      guest is both a contract lie and a cgroup escape window. [46] `review`
- [ ] Out-of-range values return `Err` at a validation boundary, not `assert!` inside `create()`. `review`

### B4 · Determinism, caching & provenance

- [ ] Cache keys: stable hasher (`blake3`/`sha2`); deterministic input order (`BTreeMap`, never
      `HashMap` iteration); content and identity that travel, never absolute `PathBuf`s — including
      in **fallback arms** (an `unwrap_or_default()` or a path-string fold on the error path
      collapses distinct states into one key [40]); a per-stage version constant + pinned SHA;
      **injective field concatenation** (delimit or length-prefix [37]) (law F4, §10.2). `test`
- [ ] The rootfs key folds the **full source closure** of everything baked in: the guest agent's
      source closure (not just the bin wrapper — editing `agent/mod.rs` must re-bake [37]), the
      guest-tools content, the baked CA cert content, and — on **every flow variant** — the actual
      bytes: the `--agent-musl` path folds the injected binary's `hash_file`, never its path [46].
      The snapshot key folds the pinned CH build identity (no cross-version snapshot compat), and
      deliberately *not* virtiofsd (law S1 — a snapshot-eligible VM runs none). An end-to-end "edit
      agent source → rootfs key changes" test pins the class. `test`
- [ ] Keys fold only **consumed** inputs — a kernel rebuild spuriously invalidating the OCI rootfs
      is safe-but-wasteful; acceptable only when recorded as the intended trade. [40] `review`
- [ ] Validity is content-addressed: a tampered artifact with an intact `.cache_key` sidecar is
      rejected; re-hash on every use including the cached-OCI-blob hit path; **directory outputs**
      hash via a deterministic sorted walk and are cache/tamper/reset-first-class — an `EISDIR`
      falling into a `warn!` arm silently exempted the most expensive stage from all three. [40] `test`
- [ ] Stale intermediates verify-or-purge; downloads verify against pins before use; pulls are
      digest-pinned (tag fallback is an error); the layer list parses from the **digest-verified
      manifest bytes**, never a second unverified fetch [46]; mmdebstrap keeps apt gpg verification
      + the `snapshot.debian.org` timestamp pin, with the trust root recorded (the base image's own
      keyring, pinned transitively by digest). `test` `review`
- [ ] Decode paths are complete **and fixture-tested**: gzip *and* zstd layers, whiteouts, device
      nodes via `makedev`, **hardlinks** (silently dropped by a `_ => continue` until a real Trixie
      entry hit it [46]) — a fixture tar per class, and an unknown entry/media type fails loud
      rather than skipping. [40][46] `test`
- [ ] CA hygiene as designed: minted once **per artifacts dir**, process-global cache returning the
      parsed authority (per-`authority()` re-signing breaks the guest trust chain), atomic write,
      `0600`, generate-or-load serialized under the cache lock (the concurrent-first-mint TOCTOU
      [40]); per-deployment minting is the *recorded* deviation from per-run hygiene — don't
      re-flag it. `review`
- [ ] **The rootfs injection-identity fold covers every injected thing — extra files included**
      (v30 delta 6): `fold_rootfs_injection_identity` gains each `ExtraFile` as a sorted
      `(dest, mode, content-hash)` triple — content that travels, never the `src` path — and **both**
      rootfs stages bump `STAGE_VERSION` (the recorded v20 precedent: an identity-fold change
      without the bump serves stale cached images). The **pack tail** rejects, typed
      `Error::Artifact` and red-on-inverse: an `ExtraFile` dest that is non-absolute,
      trailing-slash, non-UTF-8, duplicated, or hits `is_reserved_injection_path` (F5) — the
      injection tail is the validation boundary, since `ExtraFile` never passes through
      `VmConfig`. The resolved-config sidecar
      (`vmlinux[-<label>].config`, v30 delta 3) is content-addressed alongside its kernel. [30] `test`
- [ ] **The daemon store's digest is computed once, at upload** (the v28 delta 10): bytes stream through
      the hasher to a same-dir temp file, atomic-rename into place, `<name>.sha256` sidecar written;
      `list` serves the sidecar (O(entries), never a per-list re-hash of the store) and excludes
      sidecars from output; the store test asserts the sidecar matches a streamed re-hash. This is
      *serving*, not *validity*: the daemon owns the dir, so the sidecar is a cache of its own
      write — the pipeline's tamper-reject rule above is unchanged. [28] `test`

### B5 · Pipeline staging

- [ ] Stage 0 loads the committed `pins.json` and propagates it via `StageOutputs` — honestly
      documented as a lock (live resolution is recorded §17 forward work); pin ingestion is
      fallible (malformed JSON is an error, not an empty map [37]); a missing pin is an error —
      **no hardcoded image/digest fallbacks**, and image+digest pair atomically (a half-specified
      pin set yielding a mismatched reference is worse than a missing one [37]). `test` `review`
- [ ] **The pins overlay is stricter than the baseline** (v30 delta 1, §10.2): the downstream
      overlay merges key-level over the **embedded** committed baseline; an overlay top-level key
      matching no known pins namespace is a hard error naming it — a typo'd *override* would
      otherwise silently resolve from the baseline, the accept-then-ignore class on a surface whose
      whole purpose is overriding (the baseline file keeps its own ignore-unknown semantics — it is
      vmcell-committed, not caller input); a *referenced*-but-unresolvable fragment/label stays a
      hard error naming the key; the stage `cache_key` folds **both** files' content; and a missing
      fragment folds a **distinct marker** in the key, never empty bytes (two stages differing only
      in an unresolvable fragment must not share a key until `run()` fails — v30 delta 3). [30] `test`
- [ ] `StageInputs`/`StageOutputs` carry real data; **cache-hit runs merge skipped stages'
      `outputs.pins` into downstream inputs** (the fully-cached-run state-loss bug [G]); no env-var
      side channels. `test`
- [ ] Stage names and artifact keys are unique — parameterized stages (multi-kernel labels) derive
      `name()` from the label or the `Artifacts` map silently collapses. [37] `review`
- [ ] Output paths are declared by each `Stage` (with output *kind* — file vs directory [40]);
      `Pipeline::build` returns artifact locations; `reset_to(stage)` removes that stage's and all
      later outputs (directories included), errors on an unknown name, and **propagates removal
      failures** (a `let _ = remove_file` reports success while the stale artifact survives to be
      served [37]). `test`
- [ ] Artifacts live under the one resolved `artifacts_dir()` (workspace-root-anchored); a missing
      upstream is `Error::Artifact`, never a `/tmp` fallback boot. `review`
- [ ] Record/replay seams exist for **every** fetch path — the `OciPuller` trait with the
      recording/replaying fake drives pull + cache-hit re-verify + tamper tests with no network;
      a hardcoded client construction anywhere reopens the gap. [40] `test`

### B6 · Concurrency & injected state

- [ ] IDs, time, and I/O come from injected seams (`CidAllocator`, `VmidAllocator`, `Clock`,
      `CgroupFs`, `Netlink`, `NftApplier`, `SerialLog`, `OciPuller`, `GuestResync`, `OverlayStore`,
      `OrphanScanner`, the daemon's `VmLauncher`/`VmHandle`) — never module-global statics; no
      "wrapper around a global static" pretending to be injectable. **The process-wide subset
      travels as one `HostEnv`** (`{cids, vmids, segids, cgroups, clock, overlay}` — the v28
      deltas 1–2, grown by v30's `segids`): spawn entry points take `&HostEnv`, `agent()` takes no
      *seam* arguments (its retained `timeout: Option<Duration>` is the per-call connect **budget**,
      the recorded as-built deviation — re-dropping it re-ships the boot flakiness the 60–180 s
      validator windows exist for [IN]), the per-clone `make_cgroups` closures are retired, and
      tests build `HostEnv::hermetic()` substituting recording fakes field-by-field — a spawn path
      taking a seam positionally outside the bundle is the argument sprawl returning. [28][IN][30]
      `CI(grep)` `review` `test`
- [ ] **Every CoW clone materializes through `env.overlay`** (law S4; the v28 delta 2): `restore_cow`'s
      standalone store parameter and `Zygote::with_overlay_store` are retired — a second injection
      path is a store that drifts from the one the rest of the process uses. The
      `RecordingOverlayStore` fan-out test asserts the store came from the env and targeted N
      distinct private dsts. [28] `test`
- [ ] **Cross-process coordination is seamed, atomic, and tested — and rename-based claiming is a
      known-wrong shape.** The shared id lock dir is injectable (`shared_at`); the whole
      read → liveness → (re)claim sequence is serialized by an **exclusive `flock` on a per-id
      coordination file**, with the claim itself an atomic **`hard_link` of a pid-bearing temp
      file** — the H1 fix: a rename-first "steal" still dual-claims (a stealer removing a lock
      momentarily frees the path for a third racer, whose fresh claim the rename-back clobbers —
      empirically **three winners** in the race gate), and only a coordination lock across the
      decision is correct; the kernel releases the flock on holder death so a crashed coordinator
      cannot wedge the id [IN]. Reclaim tolerates corrupt/empty locks; the exactly-one-winner race
      gate (8 racers × 200 trials on a seeded dead lock) is red on the pre-fix shapes. v30
      generalizes the claim core for `SegmentIdAllocator` — **one implementation, two id spaces,
      the race gate re-parameterized**, never a second copy (§6.5) [30]. The un-prefixed bare-`/tmp`
      lock dirs (`/tmp/vmcell-vmid`, `/tmp/vmcell-segid`) are the recorded cross-process-rendezvous
      exception — deliberate, not swept, don't "fix". [46][IN][30] `test`
- [ ] [BP] On multi-user hosts, predictable names under world-writable `/tmp` are squattable
      (denial-of-service on the lock dir) — prefer `$XDG_RUNTIME_DIR`/per-uid dirs; the
      dev-workstation scope is a recorded trade, kept visible.
- [ ] Allocators: `release()` operates on the actual instance; reserved CIDs skipped; wrap without
      colliding with live/reserved ids; **CID reuse on sequential restore is by design** (assert
      "valid live CID", never `assert_ne!`); allocator tests stay hermetic; the release proptest
      asserts a freed value is actually *reused* (a no-op `release()` still hands out fresh unique
      ids [40]). `test`
- [ ] `/30`/MAC math centralized and unit-tested; the host NAT MAC pinned outside
      `mac_math(1..=254)`; the five smoltcp silent-wedge invariants (§6.2) each pinned by the test
      that reddens on its inverse — including the window-filling `host_read_budget` test (C-NET-1). `test`
- [ ] **Socket namespace origination is explicit**: a proxy binding inside the VM netns re-enters
      the host root netns before creating upstream/DNS sockets (a socket's netns is fixed at
      `socket()` time); the re-entry failure aborts startup loud. Any thread that `setns()`s
      documents what it creates while inside. [46] `review` `test`
- [ ] **Lineage identity is cross-family-safe** (law S5): `is_ancestor_of` checks the two nodes
      share a `LineageAllocator` (`Arc::ptr_eq`) *before* consulting ancestry — ids from distinct
      allocators (each starts at `L1`) must never false-positive; the cross-allocator unit test
      pins it. [28] `test`
- [ ] **The broker engine channel multiplexes without head-of-line blocking**: each forwarded
      request carries a `u64` id matched to a per-id oneshot, so concurrent client requests to
      different VMs pipeline over the one channel; a reply for an unknown/expired id is logged and
      dropped, never delivered to the wrong waiter. [28] `test`
- [ ] [BP] Deadlines and durations use `Instant`, never `SystemTime` arithmetic (the allocator
      seeded from `SystemTime::now()` bypassing the injected `Clock` [40] is the smell); wall-clock
      time appears only where wall-clock is the point (the resync payload). Outer timeouts bound
      inner retries — no retry loop can exceed its caller's deadline. `review`
- [ ] Side-effecting fakes carry assertions (rendered ruleset, netlink order, exact limit-file
      contents) and support **failure injection** — the M-VMM-6 seam-enrichment gap is resolved by
      the v28 `FakeVmm` fault menu; each scripted fault arm (failed
      `create`/`boot`/`restore`/`resume` at a chosen step, delayed readiness, wedged control
      socket) has a driving test asserting the retry/timeout behavior *and* ordered zero-residue
      teardown — the `fail_resume` arm reaches a post-instance-built teardown path `fail_restore`
      cannot [IN]. [46][28] `test`

### B7 · Module boundaries & duplication

- [ ] **The second copy is where the bug lives.** Logic existing in ≥2 copies is extracted and
      unit-tested once; the evidence: the inline 18-byte `ifreq` duplicating the audited `netif`
      struct (an OOB write onto PID 1's stack [46]); per-backend vhost-user guards (diverged
      [37][40]); the triplicated spawn/`add_task`/readiness sequence (QEMU already wrapped errors
      differently [40]); the QMP/JSON-error parse; the `/proc/self/cgroup` sibling-placement parse
      (triplicated across src + two test files, pure and untested [46]); `shutdown()` vs `Drop`
      ordering [40]; the seven hard-coded `vmcell-*` prefix literals that `vmcell::naming` collapsed
      into one name/filter composer (law F2 — a produced name that outruns its sweep filter is a
      silent leak [28]); the runner-private blessing predicate the daemon would have re-implemented,
      extracted to `vmcell-privilege` with its red-on-inverse tests guarding both callers
      (§11.2 [28]). `review`
- [ ] **The broker is a location, not a fork of the logic**: it reuses the exact `Netlink` /
      `NftApplier` / `CgroupFs` / `OrphanScanner` seams plus `build_vmm_cmd` + `apply_jail` — a
      broker-local copy of network/cgroup/spawn/jail logic is this rule's violation in
      cross-process form (law P2, §12.4). [28] `review`
- [ ] No hand-rolled HTTP (numeric status parse, looped reads) or hand-rolled packet sniffing
      (`packet.get(14)`) where a parser exists. [G] `review`
- [ ] Module responsibilities match the design: cgroup logic lives in `metrics.rs` behind
      `CgroupFs`; test-only behavior is never baked into production handlers. `review`
- [ ] **Benchmarks exercise the production helper, not a strawman** — a bench `black_box`-ing a
      hand-rolled `format!("10.200.{}.1", …)` guards a metric a real `/30` regression can't move.
      [40] `review`

### B8 · Public-API hygiene

- [ ] `#[non_exhaustive]` on growable public types — **with a constructor/builder/`Default`**, or
      external implementors can't name them at all [46] — scoped by the exhaustive-contract-types
      qualification in "Retired & qualified rules" [IN]; `cargo semver-checks` in CI, now covering
      **both** contract crates (`-p vmcell` and `-p vmcell-artifact-validator` — the validator is
      downstream contract surface, v30 §10.4) [30]. The v30 register's deltas 1–8 land as **one**
      0.12 → 0.13 breaking pass (delta 9 separable, explicitly last), not a trickle of point
      breaks (§18); every bump gets its entry in the `crates/vmcell/Cargo.toml` comment ledger
      [28][30]. `CI` `review`
- [ ] `Error` has per-subsystem variants; feature-gated `#[from]` sources are themselves
      `#[cfg]`-gated; the deliberate stringly-payload posture is recorded — flag only where a real
      typed source exists. `DaemonError` mirrors the posture: no catch-all beyond `Internal`, each
      variant carrying its HTTP status in one `IntoResponse` (B12). [28] `review`
- [ ] No always-zero / never-read public fields. *Resolved for the original instance*: the
      `ResourceUsage` net counters were **not** added — cgroup v2 has no per-cgroup network
      accounting, so the fields would be the always-zero lie; the netns-scoped usage type is
      recorded §17 forward work (design §7.1). The rule stands for the next candidate field. [46][28] `review`
- [ ] **No `pub` escape hatches around self-guards** — *resolved by the v28 pass*: `instance_mut()`
      is `pub(crate)`; a public raw-instance accessor let a caller invoke backend `snapshot()`
      directly, bypassing the cached-client invalidation the `MicroVm` wrapper enforces. The
      delta's "none is known to use it" premise was empirically false — five test sites called it,
      reconciled by adding the safe `MicroVm::kill()` they actually wanted (the
      premise-verification lesson) [IN]. The rule generalizes: raw-handle escape hatches around an
      invariant-enforcing wrapper are `pub(crate)` at most. [46][28] `review`
- [ ] Multi-value returns with adjacent same-typed fields (the 8-tuple with two swap-prone
      `Option<u32>` pgids) become structs with named fields. [46] `review`
- [ ] Docs: `#![deny(missing_docs)]`; `# Errors`/`# Panics` accurate to the code (not describing
      checks never performed, nor errors never returned); `cargo doc` gated in CI (five broken
      intra-doc links hard-failed doc builds with nothing catching it [46]). `lint` `CI`
- [ ] **Comments are load-bearing and audited like code**: a `SAFETY` comment must prove the actual
      obligation (async-signal-safety, not kill semantics); a "correctly-sized" claim on a
      wrong-sized struct and a "stronger defense-in-depth" claim on a weakened check are defects in
      themselves; **a security-relevant non-default posture carries its at-site rationale**
      (`clear_ambient_caps: false` cites the restore-with-tap EPERM reversal so nobody "hardens" it
      back on without the fd-passing prerequisite [28]); reworks sweep the comments and design/§17
      entries they invalidate (the subprocess-era resync docs, the "environmental" retry stanza,
      the stale grace-window gap). [40][46] `review`
- [ ] Per-module `#![forbid(unsafe_code)]` on I/O-free modules; dead code removed or justified. `lint` `review`

### B9 · The privileged window  *(`vmcell-test-runner`, `vmcell-guest-agent`, `vmcell-privilege`, the `vmcelld` cap-holder, `vmcell-broker`)*

Every dependency and instruction here executes with elevated capability; the review is stricter.

- [ ] The runner checks the **effective** set and the printed remediation says `setcap … +ep`
      (a `+p`-only blessing leaves caps un-raised). `test`
- [ ] **One blessing predicate, two callers** (law P1): `ensure_blessed_or_explain` +
      `blessing_remediation` live in `vmcell-privilege`; the runner imports them, the daemon calls
      them at start-up — the red-on-inverse tests moved with the code and guard both. Copying the
      predicate back into a caller is the B7 violation on security-critical logic. [28] `test` `review`
- [ ] **Posture matches lifetime** (A13): the runner is transient (file-caps → ambient raise →
      uid drop → `execvp`; caps live across one `exec`); the daemon's cap-holder is long-lived
      (verify effective set, **retain** — no uid drop, no ambient raise, no bounding shrink, no
      exec — and **refuse to start degraded**, printing the `setcap` remediation). A long-lived
      server that drops-and-execs, or a transient wrapper that retains, is a posture inversion.
      [28] `test` `review`
- [ ] The privilege-transition sequence is a **pure function** (`plan_privilege_transition`)
      unit-tested against each buggy inverse — including the setuid form's security-critical
      **uid-before-ambient** ordering and the P/E trim — so ordering is verified before a bless,
      not only by running the suite. Only the thin syscall layer stays integration-only. The
      broker parent's cap drop follows the same pattern (`plan_broker_parent_drop`, pure, with the
      bounding-shrink-is-a-warned-no-op-sans-`CAP_SETPCAP` case). [40][28] `test`
- [ ] **Path confinement anchors on the runner's own trusted location** — canonicalized
      `current_exe()` → the `.vmcell-bin` ancestor → `<workspace>/target` — then rejects `..` on
      the raw argument, canonicalizes, and confirms descent. Anchoring on the *argument's* own
      `target/` ancestor is inert (every path contains its own ancestors) — a local
      privilege-escalation surface that shipped with a comment calling it stronger. Adversarial
      fixtures (`/home/attacker/target/debug/evil`, `..`, symlinks) are unit-tested. The daemon's
      analogous anchor-on-trusted-data check is `resolve_artifact_path` (B12) — same law,
      different boundary. [37][40][28] `test`
- [ ] `just bless` installs to the stable out-of-`target/` copy, `chmod 0700` (the enforced
      execute boundary; `0750`+group is the documented shared-host alternative), idempotent via a
      content-hash stamp keyed on the **runner only** — never on test binaries. [40] `review`
- [ ] Dependency-thin: `rustix`+`capctl`+`libc` for the runner **and `vmcell-privilege`** (the
      `libc` rationale recorded); **no tracing/logging stack initialized at full privilege** (the
      copy-pasted `tracing-subscriber` dep [37]); the standing set is exactly
      `CAP_NET_ADMIN`+`CAP_SYS_ADMIN`+`CAP_DAC_OVERRIDE`; `merge_preserved_groups` keeps the kvm
      gid iff held, never invents it (the setuid form otherwise drops `/dev/kvm` access [37]).
      **The broker's lean boundary is the web-server stack**: it links `vmcell`'s
      net-privileged/metrics subset + `vmcell-privilege` and legitimately runs the engine
      (tokio, rtnetlink) — its tree assertion bans `axum` + the `vmcell-daemon` crate, the
      HTTP-server stack that must never share a process with the caps; `hyper` enters
      **legitimately** via the proxy/HTTP-client subset, so asserting its absence reddens the
      clean tree (design §15.2 states the as-built boundary in the body — no standing erratum;
      matches the Part D lean-tree row). [28][IN] `CI` `test`
- [ ] Honest limitations stay surfaced: no `CAP_SETPCAP` → bounding-drop is a warned no-op on the
      file-cap path; the runner is a dev-workstation convenience, not a multi-tenant boundary. `review`
- [ ] virtiofsd runs `--sandbox namespace` with the recorded uid posture (`SUDO_UID`, `nobody`
      refused; the per-share service-uid allocator is a §17 gap); `--readonly` enforced for RO
      shares — the in-process backend *refuses* RO fail-loud (typed, not stringly) until it can
      enforce it. [G][40] `review`

### B10 · Unsafe, FFI & the guest-facing boundary

Everything crossing the vsock/virtio/ioctl boundary — and the broker socketpair — is
attacker-influenced or ABI-critical.

- [ ] **One audited definition per kernel struct.** Every `#[repr(C)]` passed to an ioctl/syscall
      lives in one module (`netif`/`net_sys`), size- and offset-asserted against `libc` (a
      `const`-asserted `size_of`, offset tests) — the inline 18-byte `ifreq` against the kernel's
      40 bytes was a 22-byte OOB write onto PID 1's stack on every boot, green because the bytes
      landed in padding. Re-declaring inline is banned. `test` `lint(grep)`
- [ ] `// SAFETY:` comments prove the **actual** obligation of the block (async-signal-safety in
      `pre_exec` — the `apply_jail` child runs only direct syscalls, no allocation, no locks,
      between `fork` and `execve`; pointer validity + size for an ioctl), and a false safety claim
      is a defect. [28] `review`
- [ ] **Counts are handled**: `send_slice`/`write` returning fewer bytes than offered retains and
      re-enqueues the remainder (C-NET-1 silently corrupted host→guest streams under
      backpressure); reads into guest-visible buffers are bounded by the receiver's real free
      capacity (`host_read_budget`). `test`
- [ ] Guest-derived lengths/indices are validated before use: descriptor indices checked before
      `add_used` (the guest-drivable RX panic), allocation sizes clamped to MTU/frame caps,
      wire-length prefixes capped by `MAX_FRAME_BYTES` — defined **once** in `vmcell-protocol` and
      enforced identically on both ends (the host codec defaulted to 8 MiB against the guest's 16
      [37]). The broker socketpair has the same shape: length-prefixed frames bounded by the one
      `MAX_BROKER_FRAME_BYTES` constant, validated before allocation — an unbounded peer-supplied
      length is a DoS/overflow even from a "trusted" parent, which is exactly the process that
      parses network input (P2). [28] `test`
- [ ] **Presence-dependent serde needs a self-describing codec** (Appendix A reversal 10): a DTO
      using `#[serde(skip_serializing_if)]` / `#[serde(default)]` silently corrupts round-trips
      under postcard's positional encoding — a skipped field shifts every later field. The engine
      channel is JSON for exactly this; the broker's own attribute-free control enum stays
      framed-binary. Rule: any type carrying presence attributes gets a round-trip test **on the
      codec it actually ships over**, with `Some`/`None` populated asymmetrically. [28] `test`
- [ ] **Interop is tested cross-implementation**: the guest's hand-rolled `send_framed`/
      `read_framed` round-trips against the host's real `LengthDelimitedCodec` in a KVM-free unit
      test (both directions + an over-cap reject) — a suite that uses the same codec on both ends
      tests nothing about the hand-rolled side. [40] `test`
- [ ] [BP] **Fuzz the decode surfaces**: `cargo-fuzz` targets for the protocol codec + framing, the
      QMP reply reader, the HTTP status parser, the tar/OCI ingestion path, and the broker frame
      decode. These are exactly the parsers guest/network/cross-privilege bytes reach; a nightly
      non-blocking fuzz job is cheap relative to one missed frame-parse panic. [28] `CI`
- [ ] [BP] Run the unsafe-adjacent pure units under **Miri** where no ioctl blocks it (the
      virtqueue ring handling, the framing, the reaper), and keep integer conversions from the wire
      checked (`try_from`, not `as`). `CI` `review`

### B11 · Lint-suppression hygiene  [52]

The Part D gates are only as strong as the suppressions they tolerate. Applies to every workspace
member, the daemon tier and broker included.

- [ ] **Narrowest possible scope.** `#[allow(...)]`/`#[expect(...)]` sits on the single statement
      or expression that needs it — never a function, module, or crate (the sanctioned crate-root
      policy blocks in Part D are the sole exception). A fn-level
      `#[allow(clippy::disallowed_methods)]` licenses every future call in that body; the
      statement-level attribute licenses exactly one. `lint` `review`
- [ ] **`#[expect]` over `#[allow]`** (the attribute — unrelated to `Result::expect`). An
      expectation whose lint stops firing is itself a warning (`unfulfilled_lint_expectation`), so
      under `-D warnings` a stale suppression self-reports instead of silently outliving its
      reason. Machine-enforced: `clippy::allow_attributes` denies plain `#[allow]` in non-test
      code. Honest exception: a lint that fires only in some feature/platform configs turns
      `#[expect]` red in the configs where it doesn't fire — scope it with
      `#[cfg_attr(<the firing cfg>, expect(...))]`, or fall back to a reasoned `#[allow]` there. `lint`
- [ ] **Every suppression carries `reason = "..."`** stating why the lint is wrong *here* —
      machine-enforced by `clippy::allow_attributes_without_reason`. `lint`
- [ ] **Repeated legitimate sites collapse into one helper.** Eight error-exits routed through a
      single `exit_failure() -> !` carry one suppressed `process::exit` instead of eight scattered
      ones — one place to audit, one reason to keep true. [52] `review`

### B12 · The daemon HTTP surface  *(new in v5: `vmcell-daemon`, `vmcelld`, the client)* [28]

Every input here is network-supplied and several name filesystem objects; the review treats it as
the runner's confinement check writ large.

- [ ] **One name validator, allowlist, anchored on the daemon's own dir** (law P3):
      `resolve_artifact_path(dir, name)` is the *only* function turning a client string into a
      path — every store op **and** every VM-API artifact reference (`kernel`, `rootfs`,
      `restore_from`, each extra disk) routes through it. Accept rule is an allowlist (non-empty,
      ≤255 bytes, every byte in `[A-Za-z0-9._-]`, not `.`/`..`, no leading `-` or `.`), so
      traversal and subdirectories are unrepresentable — a denylist of bad substrings is the
      divergence trap. Red-on-inverse battery: `..`, `a/b`, `/abs`, `-rf`, `.hidden`, empty,
      >255 bytes, NUL — each rejects; positive control: `vmlinux-6.12` joins to exactly
      `<dir>/<name>`. Grep gate: `dir.join(` on a client string outside the validator is a
      review reject and a ban-script hit. `list` surfaces only validator-passing direct children
      (a stray subdir or out-of-band name never appears as a usable artifact); sidecars are
      internal, never listed. `test` `CI(grep)`
- [ ] **Authenticated by default; opt-out is the exception list** (law P4): one middleware layer
      wraps every route; the unauthenticated set is exactly `/healthz` + `/openapi.json`, asserted
      by the parity gate — a new route is authenticated without anyone remembering to add it. The
      key loads from `--api-key-file`, **perms-checked** (group/other-readable → refuse), never
      argv or env (no `ps`/log leak); comparison is **constant-time**, with a shape test guarding
      a future `==` regression; **absent** credentials → 401 + `WWW-Authenticate: Bearer`,
      **wrong** → 403; no key file → refuse to start, unless `--allow-unauthenticated` (loopback
      dev bind, logged loudly at every request). `test`
- [ ] **The served OpenAPI and the mounted routes are one table** (law P5): `openapi_document()`
      builds from the same route table the router mounts; the KVM-free parity gate asserts every
      mounted `(method, path)` is documented, every documented one is mounted, every named
      component schema exists, and every non-meta operation carries the security requirement.
      Deriving the doc separately (macro or hand-file) is the doc-level second copy. `test`
- [ ] **One `DaemonError`, matchable, mapped once**: each variant carries its status in one
      `IntoResponse` (404/409×3/400×2/401/403/501/413/500); a config-validation failure
      (`Error::Config`) maps to **400**, not 500 — a client error is not a server bug; the body is
      the documented `{error, message}` component, `Display` never a `Debug` struct dump; the
      client library surfaces the same conditions as a matchable enum (`ClientError::AlreadyExists`
      from a 409, not an opaque status). `test` `review`
- [ ] **The store is create-only and atomic**: `PUT` over an existing name is a typed
      `AlreadyExists` 409, never a silent overwrite; bytes stream through the hasher to a
      **same-dir temp file** then atomic-rename (a crash never leaves a half-written artifact
      under its final name); uploads past `--max-artifact-bytes` are 413, not disk-fill; `DELETE`
      of an artifact a live VM pins — including extra disks — is a typed `InUse` 409, checked
      against the registry before unlink. `test`
- [ ] **DTOs are single-sourced and feature-split**: the DTOs + the name predicate compile
      unconditionally in `vmcell-daemon`; the whole server stack (axum, handlers, registry, auth,
      the `vmcell` host stack) sits behind the default-on `server` feature; the client depends
      with `default-features = false` and links **only** the wire types — a required field added
      to a DTO is a client compile error, never silent skew. A client-side redeclaration of a DTO
      is the B7 violation on the wire. `CI` `review`
- [ ] **The registry is seam-driven and correctly locked**: logic (id minting, state machine,
      ordered teardown, artifact pinning) is unit-tested against recording `VmLauncher`/`VmHandle`
      fakes with no KVM; each `VmSlot` holds its handle behind its **own** async mutex (ops on one
      VM serialize on its single vsock channel; ops on different VMs run concurrently); immutable
      identity (id, vmid, pinned names) reads lock-free for the delete-in-use guard. The public
      **id** is opaque and server-minted (readable counter + mixed suffix), never the vmid, never
      reused in-process. "Ready" is derived from `MicroVm::start` returning with the agent up —
      never a hopeful label. `test` `review`
- [ ] **`restore_from` restores via CoW** (`restore_cow`), so the named store snapshot stays
      byte-intact and re-restorable (S3 across the network boundary); `create` then drives the
      mandatory post-restore resync; `snapshot` writes **into the store** under the prefix and
      returns names — the store is the one exchange surface, no out-of-band paths. The end-to-end
      pin: a tmpfs marker written pre-`snapshot` survives `restore_from` into a fresh VM. `test`
- [ ] **Recorded divergences from the library are design, not drift** — don't re-flag: daemon
      extra disks are **read-only** (the store is create-only/immutable; a writable disk backed by
      a shared artifact lets one VM mutate what another reads — copy-on-attach scratch is §17),
      and there is **no `init=` over REST** (the daemon owns VMs through the control plane a
      custom init replaces). `review`
- [ ] **`--resource-prefix` threads to both the launcher and the sweep** (law F2): the daemon's
      VMs are named with it and the start-up sweep reclaims exactly those names — two daemons with
      distinct prefixes never sweep each other (the `acme`-vs-`vmcell` KVM validation: plant both
      orphan families, assert only the matching one is reclaimed). `test`

### B13 · Privilege-hardening layers  *(new in v5: `vmm::seccomp`, `vmm::jail`, `vmcell-broker`)* [28]

Three independent layers (design §12); each is reviewed as if the others were bypassed.

- [ ] **The VMM's own seccomp state is explicit and typed** (`VmmSeccomp`, §12.2): CH gets
      `--seccomp true|log|false` **explicitly** (visible in argv, never implicit); FC `Enforcing`
      is the built-in (no flag), `Disabled` emits `--no-seccomp`, `Log` is a typed
      `Unsupported` — never silently substituted; QEMU `Enforcing` **must** pass
      `-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny` — QEMU
      runs completely unconfined without `-sandbox`, the hole the earlier path shipped;
      `spawn=deny` is the load-bearing clause. **crosvm's arm is the live-validation reversal**
      [IN]: its own sandbox is a *multiprocess* minijail (`pivot_root` into `/var/empty`,
      per-device forked children) that is structurally incompatible with the single-process
      supervision model — first boot died on it — so crosvm **always** runs `--disable-sandbox`,
      and `Enforcing` keeps the never-unconfined-by-default invariant by turning the **Layer-2
      jailer deny-list on** instead (`Crosvm::create` sets `seccomp_deny_list = true`); `Log` is a
      typed `Unsupported` there too. `Disabled` exists for diagnosing a suspected seccomp failure
      and is a loud explicit opt-out, never a fallback when a filter fails to apply.
      `vmm_seccomp_args` is unit-tested per backend, including non-empty sandbox-enabling
      `Enforcing` output for the backends with their own filter, crosvm's
      `--disable-sandbox`+deny-list pairing, and the **three** typed `Log` errors. `test`
- [ ] **`apply_jail` is async-signal-safe with a fixed, load-bearing order**: between `fork` and
      `execve` the child runs only direct syscalls (no allocation, no locks); order is
      rlimits → dumpable → ambient-clear → `no_new_privs` → seccomp → `execve` — NNP must precede
      the filter (installing without it needs `CAP_SYS_ADMIN`, defeating the point) and the filter
      installs last so the setup syscalls aren't filtered. The pure jail plan is unit-tested; the
      `/proc/self/status` stand-in gate asserts the post-apply caps/NNP/dumpable state matches the
      spec. `test` `review`
- [ ] **`clear_ambient_caps` defaults `false`, and the at-site rationale is load-bearing**
      (Appendix A reversal 9): clearing the ambient set stripped the `CAP_NET_ADMIN` the VMM
      itself needs at boot (CH `TapSetMac`, FC tap-reopen) — every restore-with-tap test went red
      `EPERM` while cold boot stayed green. Default-on is a real hardening increment **blocked on
      fd-passing tap creation** (§17); flipping the default without that prerequisite re-ships the
      regression. `review` `test`
- [ ] **Core-dump and file-size limits match the threat model** (law P4): `rlimit_core Some(0)` +
      `non_dumpable` — a VMM core would contain guest RAM; `rlimit_fsize` is `None` on the
      snapshot path — a snapshot **is** a guest-RAM-sized write, and a cap there turns
      `snapshot()` into a mid-write kill. `review`
- [ ] **The extra seccomp deny-list is `EPERM`, opt-in, and stays opt-in until live-validated**:
      denied syscalls return `EPERM` (a probing VMM degrades; `SIGSYS` kills it mysteriously);
      the list is `None` by default and flips on per backend only after a live run of each
      (§17) — a review that proposes default-on re-derives the recorded sequencing. `review`
- [ ] **Why-not-chroot/uid-drop is recorded — don't re-derive**: the host connects to the VMM's
      API socket and the guest vsock UDS (a chroot hides them), and cross-uid
      `pidfd_send_signal` needs `CAP_KILL` (teardown breaks); the jailer
      chroot/`pivot_root`/uid-drop increment is §17 with fd-passing as its prerequisite. `review`
- [ ] **The broker topology is exact** (law P2, §12.4): forked **before** the tokio runtime starts
      (fork-with-threads is unsafe; only async-signal-safe code in the child until `exec`);
      `PR_SET_PDEATHSIG=SIGKILL` so no orphaned cap-holder survives its parent; the parent drops
      **all** caps via the pure `plan_broker_parent_drop` before serving HTTP; frames are
      length-prefixed and bounded by `MAX_BROKER_FRAME_BYTES` (B10); `--no-setup-broker` is the
      recorded weaker fallback, not the default. The shipped shape is the **fat** broker (the
      cap-holding child owns the `Registry`; the parent forwards over the JSON `VmEngine`
      channel); the **thin** broker + fd-passing is the recorded §17 end-state — a review
      proposing either direction cites that record instead of re-arguing it. `test` `review`
- [ ] **Seccomp crates are banned by name, not by license metadata** (§12.5): `seccompiler` only
      (Apache-2.0/BSD-3, the compiler CH and FC themselves use); `libseccomp`, `libseccomp-sys`,
      `seccomp-sys`, `syscallz`, `seccomp`, and `birdcage` carry permissive Rust metadata over an **LGPL-2.1 C
      link that cargo-deny's license scan cannot see** — the one place in the dependency strategy
      where an explicit `deny.toml [bans]` entry substitutes for the allow-list. `CI`

### B14 · Sessions, cloning & lineage  *(new in v5)* [28]

The interactive control plane (laws C3–C7, §3) and the fan-out tier (laws S3–S5, §8.4–§8.6).

- [ ] **One writer per connection, both ends** (C4): a single task owns writes to a given vsock
      connection; concurrent sessions queue frames to that writer, never write directly. Gate: two
      window-filling, self-identifying concurrent streams show zero cross-attribution. `test`
- [ ] **Session I/O is channelized with exactly one terminal `SessionExit`** (C5): stdout/stderr
      are tagged frames; a spawn failure is `SessionStderr` + `SessionExit(127)`, never a hang or
      a bare error; frames arriving after a session's exit are **dropped**, never misattributed to
      a live session. The demux interleave + post-exit-drop unit test runs over a tokio duplex,
      KVM-free. `test`
- [ ] **A connection owns its sessions** (C3): when a control connection's dispatch loop ends, every
      process group it spawned is `kill(-pgid, SIGKILL)`'d — no guest process outlives the
      connection that created it. The KVM residue test: spawn `sh -c 'echo $$; sleep 600'`, drop
      the connection, assert the pgroup is gone. `test`
- [ ] **A PTY session is a real controlling terminal** (C7): `setsid` + `TIOCSCTTY`; in-guest
      `isatty` is true (`test -t 0 && stty size`); host `Winsize` changes forward as `SIGWINCH`
      with a resize assertion; a **pipe session is the negative control** (same battery, `isatty`
      false) so the assertion can't pass vacuously. Per-session backpressure is the recorded
      unbounded host-trusted trade (§17) — visible, not re-flagged. `test`
- [ ] **The master is immutable; every clone restores from a private CoW copy** (S3): the copy is
      minted in the orchestrator **before** the backend is called, so no code path can restore
      directly from the master (the in-place `config.json` rewrite makes a shared dir a race);
      extends to every lineage branch node. The fan-out test asserts the master `config.json` is
      **byte-identical** after N concurrent clones. `test`
- [ ] **The concurrent-fan-out gate is the existing capability, not a bespoke flag**:
      `spawn_clones(n > 1)` on a backend with `restore_rotates_host_paths: false` is a typed
      `Unsupported` (two FC clones would fight over one baked vsock path; two crosvm clones over
      one baked **CID** — the AF_VSOCK form of the same fact [IN]); a **single** clone works
      everywhere; the suite branches per backend on the same flag the warm tier declares — a
      second fan-out boolean is a second source of truth for one fact. QEMU is on the *rotating*
      side: its restore programs a fresh allocator-unique guest CID (a device property, not
      migration state), with the kernel's `EADDRINUSE` at realize as the fail-loud backstop [IN]. `test`
- [ ] **Restore-transport mechanics are per-backend law, recorded — cite, don't re-derive** [IN]:
      QEMU snapshots over **one** QMP connection (no per-poll `qmp_capabilities` re-handshake),
      migrates to a **`file:` URI** (never `exec:` — its own `-sandbox …,spawn=deny` would kill
      it), restores with **`-incoming defer`** + `migrate-incoming` polled to completion (a bare
      `-incoming` races `cont` into an `inmigrate` runstate); QEMU and FC `create()` attach
      **virtio-rng** so the post-restore reseed can apply (`reseed_applied: false` = frozen
      correlated CSPRNG across clones); crosvm requires a **full** suspend before snapshot and
      `resume --full` after (`--suspended` freezes devices *and* vCPUs; its default xhci is not
      `Suspendable`, which is why `--no-usb` is unconditional). Each fact is pinned by a KVM-free
      arg-builder/codec assertion. `test` `review`
- [ ] **Lineage re-validates through the same predicate** (`check_clone_eligible`) at
      `branch`/`fork_from_vm` construction — a typed error before any snapshot or copy is minted;
      `fork_many` *is* `spawn_clones`, so the gate above applies with no second copy. Generation
      strictly increments; ancestry is `parent.ancestry ++ [parent.id]`; cross-family safety per
      B6 (S5). `test`
- [ ] **A branch is a flat, complete snapshot — never a backing chain** (§8.6): restore stays O(1)
      in lineage depth; depth costs disk (one guest-RAM image per retained branch point), reported
      honestly. A qcow2/overlay backing-chain proposal re-derives a rejected design — cite §8.6,
      don't re-argue. `review`
- [ ] **Filesystem side effects on the lineage path need the live suite** (Appendix A reversal 11):
      the missing `create_dir_all` in `branch`/`fork_from_vm` was invisible to `FakeVmm` (which
      never touches the filesystem) — the fake-blindness rule (A9) applied concretely. `test` `review`

### B15 · The downstream toolkit contract  *(new in v6: pins overlay, env contract, the validator, the example workspace)* [30]

The system's first out-of-repo consumer makes a *contract* reviewable. The defect mode here is not
a crash but a **silent promise-break to a workspace that cannot see your diff** — so every rule
below is about keeping the promise observable.

- [ ] **The contract surface is one named list** (design §10.4): the pins schema + overlay
      semantics, `Stage`/`Pipeline`/`ResolvePinsStage`/`StageInputs`/`StageOutputs`/`CacheKey` +
      the hash helpers, the kernel build entry points + the resolved-config sidecar,
      `pack_erofs_with_injection` + `ExtraFile`, the `VMCELL_*` env table, and the
      `vmcell-artifact-validator` battery + `KconfigValues`. A breaking (or behavior-visible)
      change to anything on the list is a
      **deliberate, ledgered version bump** (the `Cargo.toml` comment changelog), never discovered
      by a consumer's compile or runtime failure. `semver-checks` covers both contract crates; the
      CLI half (flags are invisible to semver-checks) is gated by the example workspace invoking
      the exact documented commands. `CI` `review`
- [ ] **The `VMCELL_*` env semantics are specified, not discovered** (§10.4): `VMCELL_KERNEL` is a
      path redirect that still requires existence; `VMCELL_ROOTFS` is the **full**
      ensure-bootstrap no-op (not a rootfs-only skip); `VMCELL_PINS` is the overlay;
      `VMCELL_ARTIFACTS_DIR` relocates the cache with freshness intact. In a consumer workspace
      the harness getters either return the named override paths or **fail loud naming the
      two-step route** — never a silent attempt to run the workspace bootstrap against the cargo
      checkout (`ensure_test_artifacts` structurally cannot build downstream: its fingerprint
      hashes the guest-agent source closure out of the vmcell tree). This substitution for the
      FR's letter is a *recorded deviation* — reviewers cite it, not re-litigate it. `test` `review`
- [ ] **The example workspace is the living consumer gate** (v30 delta 5): out-of-tree, its own
      pins overlay, a neutral self-proving fragment (`IKCONFIG` → `/proc/config.gz` on the data
      plane), the resolved-config assertion, the validator battery, the harness-getter contract
      legs, and the vendor-assertion positive control — built and run by CI on every push, KVM leg
      on the self-hosted runner. **Breaking the example job is the intended failure mode of
      contract drift**; a change that "fixes" the example to keep it green instead of versioning
      the contract is the violation. Consumer content never enters vmcell — example fragments are
      mechanism proofs (the generality law G1; the one recorded exception shape: a generic
      capability-gate fragment like `usbhost`, defended in place, never carrying the consumer's
      usbip/gadget closure). `CI` `review`
- [ ] **Validation failures name the missing contract clause** (v30 delta 4): the serial-log
      classifier maps the known signatures (`VFS: Unable to mount root fs` → root-fs symbols;
      vsock `EAFNOSUPPORT` → `CONFIG_VSOCKETS`; no banner → not a direct-boot `vmlinux`) into the
      failing check's message; an *unclassified* boot failure still reports the named check, the
      expired deadline, and the serial tail with a §5.4 checklist pointer — new signatures grow
      the classifier, never the timeout path. Every check deadline is an `Instant`,
      outer-bounds-inner: "fails loudly, not by hanging" holds by construction. The classifier is
      pure, red-on-inverse on canned logs. `test`
- [ ] **Git-dep guidance is load-bearing documentation**: the `[patch.crates-io]` replication
      stanza (cargo honors patch sections only from the consumer's workspace root — a plain git
      dep silently drops the vendored `SET_VRING_ENABLE` fix on the QEMU-unprivileged path),
      scoped to when it applies; the downstream-runnable `check-vendored-vhost.sh` with both a
      green positive control and a red inverse leg; the per-workspace bless note. A rejected
      alternative is recorded (the build-probe cfg detection — complexity traded away because the
      unpatched failure is loud-but-cryptic, not silent): cite it, don't re-propose it. `CI` `review`

### B16 · VM-to-VM segments & the raw vsock dial  *(new in v6)* [30]

The shared-L2 tier (design §6.5) and the agent-independent byte channel (§3.2). Both reuse existing
machinery by design — the review checks that the reuse stayed reuse.

- [ ] **A segment is where taps live, not a new datapath**: one netns per segment holding one
      bridge; member taps created there and enslaved; the VMM enters via the same `build_vmm_cmd`
      pre-exec `setns`; device wiring routes through the one `net_uses_tap(cfg)` predicate so
      `Privileged` and `Segment` take the identical tap arm. A backend re-deriving the mode from
      an ad-hoc `NetConfig` match is the second copy (and, because `NetConfig` is
      `#[non_exhaustive]`, a *silent* one out-of-tree — the fail-loud channel is the exhaustive
      `PerVmResources::segment` field every backend must acknowledge to compile). `test` `review`
- [ ] **Segment addressing is disjoint pure math**: `segment_ip_math` on `10.201.<s>/24` (the
      per-VM `/30`s fully consume `10.200/16`); slot free-list bounded at 253 with
      claim/free/exhaustion tests; the guest still learns its address from the kernel `ip=` token —
      **zero new guest code, zero netlink in PID 1** (law C6 untouched); MACs stay `mac_math(vmid)`
      (host-unique vmids ⇒ bridge-unique MACs, outside the NAT's reserved image). `test`
- [ ] **Segment lifetime is Arc-structural** (B1 extension): members hold the segment handle; the
      netns/bridge die with the last holder; member teardown releases its slot through the ordered
      helper and never touches the netns. The sweep gains the `-seg-` class **with its own live-id
      space** — keying a segment netns against live *vmids* is the wrong-id-space bug; the daemon
      start-up sweep passes both sets empty. `NetSegment::new` routes its prefix through the one
      `validate_resource_prefix` (F2 lockstep + IFNAMSIZ safety); `build()` rejects a member whose
      prefix differs from its segment's. `test`
- [ ] **Segment fault injection ships as names, not a typed API** — a recorded simplicity cut, not
      an oversight: the rtnetlink stack in use types no netem options, so the mechanism is stable
      accessors (`netns_path()`, tap/bridge names) a harness drives `tc` against; the typed
      impairment API is §17 forward work behind hand-assembled `TcMessage`s. A review proposing
      "just add the typed API" re-derives the recorded blocker. Gates include a **loss/partition**
      leg, not only delay (a bridge that silently healed a partition would pass a delay-only
      gate). `review` `test`
- [ ] **The raw dial reuses the one prologue and deliberately not the boot-retry loop** (§3.2):
      the `CONNECT/OK` prologue is extracted from `connect_framed` into the single shared fn
      (fixing the recorded no-backoff `CONNECT`-write retry in passing); `dial_vsock` interprets
      refusal signals **fail-fast typed** — hybrid EOF-without-`OK` is a no-listener error naming
      the port; the AF_VSOCK arm surfaces the kernel's connect error; the accept-and-hang daemon
      shape runs out the bounded per-byte read — because the retry loop exists to outwait a
      *booting agent*, which is not this caller's situation. `VsockDial` is a public newtype
      (ControlStream stays `pub(crate)`, non-generic, unwind-safety preserved). `test`
- [ ] **The dial's documented caveats are contract**: it bypasses the custom-init guard (sound
      because the vsock *device* is attached unconditionally on every backend — anchored per
      backend, validated live by the echo-server-as-`init=` leg); a user listener gets **no**
      post-restore re-bind service (only the agent re-binds after the device is re-created) — dial
      afresh after a restore; on non-rotating backends the endpoint is the baked path/CID. `test` `review`

---

## Part C — Tests that actually test  *(the meta-rubric)*

Every test must be able to **fail**. Before accepting one, construct the buggy implementation it
nominally guards and confirm it goes red; confirm CI actually runs it; and ask what the test
*structurally cannot reach* (rule 4). The suites passed green over two Criticals and most of review
46's Highs — not because assertions were weak, but because no test drove the input that breaks the
code.

**Test smells — reject on sight:**

- [ ] **Skip == pass, in any costume.** A `println!("SKIP") + return` is a green PASS under nextest
      [46]; a recipe whose filter selects zero tests; a hand-rolled per-backend skip bypassing the
      harness (`shares_ro_rw` [37]); the CH/primary path exempted inside one test while
      `require_cap!` protects the others [40]. Skips go through the one harness macro, which panics
      for the primary backend and records `SKIP <vmm> <capability>` to the **durable run-scoped
      manifest** (`VMCELL_SKIP_MANIFEST`) — a passing test's stdout is captured and discarded, so
      only a manifest survives. [46]
- [ ] **Asserts nothing / dead fake / self-fulfilling.** Result discarded; assertion commented out;
      the injected fake never consulted on the path under test; the fake bypasses the layer whose
      bug it would reveal (`FakeGuestResync` skipping the desync layer [46]); the test performs the
      behavior itself and asserts a trivial outcome; **the pure seam extracted for testability with
      zero tests** (the reaper had none while being the recurring defect class [37]); **a whole
      crate with zero tests** (guest-tools — which is how the exit-0-on-everything probe shipped
      [46]).
- [ ] **Fake-blind side effects.** [28] The fake elides a whole effect class — `FakeVmm` never
      touches the filesystem, so the lineage `create_dir_all` bug was structurally invisible to
      every fake-driven test (Appendix A reversal 11). For each recording fake, enumerate what it
      *cannot* observe (fs, network, process table) and name the live test that covers exactly
      that; "the fakes are green" is not evidence on those axes.
- [ ] **Filter-independent outcome.** A security assertion whose result is the same with the filter
      deleted: `curl` at a black-hole address fails for unreachability whether or not any nft rule
      exists. A negative result needs a **positive control** — the same target reachable via the
      allowed path, blocked via the filtered one — or a host-observable counter. [40]
- [ ] **The test config neuters the property.** `-k` on every egress `curl` disables exactly the
      TLS validation whose failure path is under test. [46]
- [ ] **Loose "or" / proxy-signal assertions.** OOM accepting `137 || 1 || -1`; guest-RAM self-OOM
      masquerading as a cgroup OOM (set guest RAM *above* the cap; assert
      `memory.events oom_kill > 0`); body checks via `contains("html")`; exit-code-only where the
      body is the property.
- [ ] **Coincidental pass / wrong identity.** Two `/dev/urandom` reads differing; the clock
      advancing after a sleep; and **inequality against a prior value of a pure function of vmid**
      — MAC/vsock-path `assert_ne!(old, new)` is flaky when the vmid recycles *and* passes when
      rotation never ran but a different vmid was handed out. Assert the positive identity:
      `post_mac == mac_math(new_vmid)`, route via `ip_math(new_vmid)`, branching on
      `restore_rotates_host_paths` per backend — and where an `assert_ne!` is the right shape (the
      QEMU rotated-CID assert), **reserve the source value first** so the inequality is
      non-vacuous (the allocator could otherwise hand the restore the very CID being compared
      against [IN]). [37]
- [ ] **Vacuous residue checks.** Asserting non-existence of a `format!`-recomputed path with no
      pre-drop existence check — silently vacuous the day the naming drifts (and naming now has one
      home, `vmcell::naming` — recompute through it, never a test-local `format!` [28]). Assert
      the artifact existed before drop, then that it's gone. [46]
- [ ] **Tests the opposite of its name / enshrines a bug.** `tampered_digest_aborts` corrupting the
      sidecar and asserting a rebuild; a name like `concurrency` that boots VMs strictly
      sequentially [46]; `test_reset_to_propagates_remove_error` **locking in** the EISDIR
      misbehavior it should have exposed [40] — a test can canonize a defect; check what behavior
      the assertion actually blesses.
- [ ] **Easy-variant-only state coverage.** The reclaim test using only `stream = None` while the
      leak lives in the `stream = Some` transition [37]; unit-testing `reclaim_and_has_room` while
      no test drives the real SYN loop that must call it [40]. Enumerate the state × resource
      matrix; test the transitions that release things.
- [ ] **Mock where round-trip is required; same-implementation interop.** `put_file` asserted
      against a UDS mock instead of `cat` in the guest; the guest's hand-rolled framing "covered" by
      tests running the host codec on both ends [40]; a presence-attribute DTO "round-tripped" on a
      codec it never ships over (test on the wire's actual codec — the postcard trap [28]).
- [ ] **Tiny-payload data-plane tests.** Every NAT/proxy test moving payloads far below the window
      masks backpressure bugs (C-NET-1); include window-filling and `>MAX_FRAME` payloads. [46]
- [ ] **String stand-ins; determinism via a trivial stage; harness strawmen.** `format!` paths
      instead of real socket paths; a `DummyStage` where the real stage's cache bugs live; a bench
      measuring a reimplementation [40]; **untested stats helpers** — the `floor(n·q)` percentile
      made every published p95 at N=20 the sample max (the corrected estimator is nearest-rank
      `ceil(q·n) − 1`, and tails published before 2026-07-03 are not comparable [28]); pure math in
      the bench harness gets unit tests against known values, and published tables are regenerated
      when the harness changes. [46]

**Positive requirements:**

- [ ] Serial execution via the nextest `serial-host` group — **positively selecting every
      `vmcell-*` member's integration binaries** (`package(~vmcell) & kind(test) &
      !binary(proptests)`) so the daemon suite and any new member auto-join; the mild cost
      (serializing a few cheap KVM-free integration tests) buys the auto-inclusion the negative
      selector loses [28]; `#[ignore = "reason"]` with the reason string; nextest pinned ≥ 0.9.85
      so `--no-tests=fail` holds; the two operating-mode suites separately invoked with visible
      hard preconditions. `CI`
- [ ] **Capability honesty machinery**: `require_cap!` panics for the primary backend, records to
      the durable skip manifest for others; a per-flag honesty pin exists for **every**
      `VmmCapabilities` field on every backend (eight today, nine with v30 delta 9), plus the three
      seccomp-`Log` typed unsupporteds (FC, QEMU, crosvm) as separate non-descriptor pins.
      [46][28][IN] `test`
- [ ] **Failure injection is a first-class suite member**: mid-`start()`/`restore()` failures
      (assert zero residue + the recorded drop order via the drop-order gate); each `FakeVmm`
      fault-menu arm driven (the v28 menu, `fail_resume` included); a forced spawn-step failure after each helper daemon starts
      (assert the helper is reaped); a transient resync/transport failure followed by recovery on
      the next `agent()` call. [37][40][46][28] `test`
- [ ] **Data-plane assertions**: an egress byte after restore (the rotated `/30`'s default route
      observed in-guest *and* traffic moves); window-filling NAT transfers; a real upstream through
      the privileged Filtered proxy where CI has internet, else the doubles-only contract stated in
      the test. [46] `test`
- [ ] Required integration assertions stay specific: snapshot reconnect (guest re-bind + per-backend
      host-path branch) + valid live CID + `mac_math(new_vmid)`/route identity + FakeClock-driven
      first-call resync + reseed captured without the test reseeding; the **zygote battery** — N
      concurrent clones with distinct vmid / `mac_math(vmid)` MAC / vsock paths, master
      `config.json` byte-identical, `Unsupported` on `n > 1` non-rotating with the single-clone
      positive control, `RecordingOverlayStore` distinct private dsts [28]; the **session
      battery** — zero cross-attribution, post-exit drop, connection-drop pgroup residue, PTY +
      pipe negative control [28]; the **daemon battery** — the KVM-free gates (auth 200/403/401,
      OpenAPI parity, the name-validator inverse battery, delete-in-use) always run, plus the
      inverted-runner `vmcelld` KVM suite (the test binary holds the caps, spawns `vmcelld` in a
      systemd-delegated scope, drives create → exec → snapshot → `restore_from` → destroy, asserts
      the tmpfs marker survives) [28]; HTTPS interception logged + `CONNECT` falls through +
      label-boundary **and normalized** (case, trailing dot) block observed and recorded;
      ordered-Drop-on-panic zero residue including the scratch **directory**; N-VM concurrency
      actually concurrent; the pipeline tamper/cache-hit/determinism trio on real stages;
      `put_file` round-trip read back in-guest; the structural zero-netlink gate plus the
      behavioral grep (an agent shelling out to `ip` adds no crate and passes the tree gate [40]);
      and the **v30 batteries** [30] — the **segment set** (two-VM bidirectional TCP via the
      `echo-server` applet, an off-segment VM's dial to **both** members refused against the same
      targets that just accepted, host `dial_tcp`, the netem delay *and* loss/partition legs,
      last-holder netns residue, the orphan-`seg` sweep with foreign-prefix isolation); the
      **dial set** (echo + EOF both directions per endpoint arm, dead-port typed error within the
      bound, the echo-server-as-`init=` custom-init leg); the **injection set** (in-guest
      `cat`/`stat` of an injected file before first exec, reserved/duplicate-dest rejects,
      cache-key invalidation); and the **toolkit set** (overlay wins/falls-back/rejects-typos,
      resolved-config sidecar assertable, classifier red-on-inverse on canned logs, the example
      workspace's full consumer loop incl. the harness-getter contract legs). `test`
- [ ] Ingest fixture set: device node, zstd layer, whiteout, **hardlink**, unknown entry type →
      loud error. [40][46] `test`
- [ ] Guest framing A↔B round-trip vs the real host codec, both directions, over-cap reject —
      KVM-free. [40] `test`
- [ ] Cross-process `VmidAllocator` tests: claim, crashed-owner reclaim, corrupt/empty lock,
      dual-claim race. [46] `test`
- [ ] [BP] Property tests on the stateful protocols — operation sequences over the handshake FSM,
      desync flag, and reaper (proptest strategies over interleavings), not only single-shot cases. `test`

---

## Part D — Required automated gates

Each item turns a defect *family* into a build failure. **If a Part B/C item reached a human, the
matching gate here is missing — add it.**

**Crate-root lints** (every crate root; two sanctioned variants [52]):

```rust
#![deny(missing_docs, unsafe_op_in_unsafe_fn, rustdoc::broken_intra_doc_links)]
#![deny(unreachable_pub)]                                    // API surface honesty
#![deny(clippy::undocumented_unsafe_blocks, clippy::missing_safety_doc,
        clippy::missing_errors_doc, clippy::missing_panics_doc,
        clippy::multiple_unsafe_ops_per_block)]              // one obligation per SAFETY
#![cfg_attr(not(test), deny(
    clippy::unwrap_used, clippy::panic, clippy::unreachable,
    clippy::todo, clippy::unimplemented,
    clippy::indexing_slicing,
    clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro,
    clippy::allow_attributes, clippy::allow_attributes_without_reason,  // B11
))]
// Under evaluation after M-HOST-6: cfg_attr(not(test), deny(clippy::expect_used)) with per-site
// #[expect]s carrying "invariant:" reasons — at minimum grep-ban `.expect(` in guest-driven modules.
```

**Crate classes [28][IN]:** *full family* — the library crates (`vmcell`, `vmcell-protocol`, the
two builders, the three extracted backends `vmcell-firecracker`/`vmcell-qemu`/`vmcell-crosvm`,
`vmcell-artifact-validator`, `vmcell-privilege`, `vmcell-daemon`, `vmcell-daemon-client`,
`vmcell-broker`), the PID-1 agent binary (a PID-1 panic aborts the guest, so
`unwrap_used`/`panic` are load-bearing there), and `vmcelld` (a daemon logs via `tracing`, never
stdout). *Print-by-contract binaries* (`vmcell-cli`, `vmcell-guest-tools`, `vmcell-test-runner`,
`vmcelld-ctl`, `vmcell-bench`'s `bench-vm`) drop the two `print_*`
denies with the rationale in the crate doc. *Wire crates* (`vmcell-protocol`, the guest agent) add
`#![deny(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap)]` —
the B10 `try_from`-not-`as` rule as a lint. Plus per-module `#![forbid(unsafe_code)]` on the
I/O-free modules; crates with real FFI drop it and rely on the unsafe-audit lints, saying why in
the crate doc. [52]

**Gate meta-rules** (the C-GATE-1 lesson [37][40]):

1. **Every gate is reachable.** An accepted-red step (the feature powerset while the collapse was
   pending) runs `continue-on-error: true` or **last** — never as a short-circuit that silently
   disables `cargo deny`, `semver-checks`, the lean builds, and the ban script behind an "expected"
   red. In the `justfile`, same: known-debt steps go last or non-gating.
2. **Gates have red-on-inverse self-tests covering every rule they claim.** The ban-script
   self-test's fixtures covered only `Atomic*`; deleting `OnceLock|Mutex|Lazy` from the scanner
   left every fixture green — a gate that can't fail is theater, same as a test. One MUST-flag
   fixture per keyword/rule — the new `dir.join(` ban included. [40][28]
3. **`just ci` and CI are the same thing, asserted.** Same `-D warnings` mechanism (RUSTFLAGS),
   same steps, same nextest filters including the `kind(test)` predicate — CI drifted to running
   ~172 lib tests concurrently with the serial VM suite [46]. Either generate both from one source
   or add an equality-check job.

**CI jobs** (all required):

| Gate | Catches |
|---|---|
| `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` | the lint families; format drift |
| Build **and** clippy each lean target (`agent`, `test-runner`, `guest-tools`, `vmcell-privilege`, `vmcell-broker`) — a `cargo tree`-only check never compiles the target | an un-`cfg`'d `#[from]`/re-export breaking a non-default build |
| **Blocking builds of the shipped reduced-host feature configs** (e.g. `--no-default-features --features cloud-hypervisor[,metrics]`; the daemon client with `default-features = false` [28]) [40] | the CFG-1 class: a feature-gated arm silently changing semantics in a config only the non-blocking powerset compiles |
| Lean-target tree assertions: `agent` + `test-runner` + `vmcell-privilege` ∌ `tokio`/`hyper`/`rtnetlink`; **`vmcell-broker` ∌ `axum` + `vmcell-daemon`** — the as-built boundary: it owns the engine, and `hyper` enters legitimately via the proxy/HTTP-client subset, so asserting hyper's absence reddens the clean tree (the recorded v3-gate reconciliation; design v30 §15.2 now states this in the body — no standing erratum) [28][IN]; guest-tools exempt, recorded | privileged-window/guest binaries re-coupling to the host or web-server stack |
| `cargo deny check`; every `ignore` carries a **per-crate** rationale [37]; **`[bans]` names the libseccomp-wrapper crates** (`libseccomp`, `libseccomp-sys`, `seccomp-sys`, `syscallz`, `seccomp`) plus the `birdcage` alternative-sandbox ban — their LGPL-2.1 C link (or sandbox duplication) is invisible to the license scan (§12.5); the roster matches the six landed `deny.toml` entries [28][IN] | GPL/unvetted crates; silently defeated advisories; metadata-masked copyleft links |
| `cargo semver-checks` — `-p vmcell` **and `-p vmcell-artifact-validator`** (v30: the validator is contract surface) | unannounced API breaks (the v30 §18 deltas 1–8 land as one announced 0.13 pass; delta 9 separable) |
| [30] **The example-workspace CI job** (`examples/downstream-kernel/`): builds the out-of-tree consumer, runs the documented CLI invocations, the pins-overlay loop, the validator battery, the harness-getter contract legs, and the vendor-assertion positive control; KVM leg on the self-hosted runner | downstream-contract drift shipping invisibly — the surface class semver-checks and unit tests structurally cannot see |
| **`cargo doc` (deny broken intra-doc links)** [46] | a hard-failing doc build nothing notices |
| `cargo nextest run` with per-test timeouts; retries scoped to the VM integration profile only, with the honest stanza comment (retries are the residual-environment backstop, not a diagnosis — AGENT-2 taught that [46]) | hangs; retry-masked rot |
| The `--ignored` integration matrix on a KVM runner, selecting > 0 tests, **compiled with `--features firecracker,qemu`** [37], **plus the `just test-daemon` suite** (the inverted-runner `vmcelld` battery) [28] | the suite being CI-invisible; FC/QEMU never executing; the daemon tier untested end-to-end |
| Skip-manifest surfaced in CI output (count + contents) [46] | capability skips accumulating invisibly |
| Global-state grep ban (alias-aware, multi-line-aware, with the per-keyword self-test fixtures) [40] | un-fakeable global state returning |
| **Artifact-path grep ban**: `dir.join(` / `artifacts_dir.join(` on a client string outside `resolve_artifact_path`, with MUST-flag and MUST-pass fixtures (meta-rule 2) [28] | a handler bypassing the one name validator (P3) |
| **Vendored-patch assertion**: `cargo tree` proves `vhost`/`vhost-user-backend` resolve from `vendor/` with exact `=` pins — a caret bump silently drops the carried patch with only a cargo warning [46]; v30 adds the **downstream-runnable** form (`scripts/check-vendored-vhost.sh`, path-independent) with a green positive control in the example workspace and a red stanza-dropped inverse [30] | the QEMU-unprivileged patch evaporating — in this workspace or a consumer's |
| **Agent-ip-shellout grep ban** (`ban-agent-ip-shellout.sh` + self-test) — the C6 behavioral grep beside the structural zero-netlink tree assertion [40][IN] | an agent shelling out to `ip`, which adds no crate and passes the tree gate |
| **Legacy-terms grep ban** (`ban-legacy-terms.sh` + self-test) — the as-built vocabulary gate alongside the global-state, agent-ip, and artifact-path bans [IN] | retired terminology re-entering docs/code after a rename |
| [BP] `cargo build --locked` / `--frozen` in CI | lockfile drift; unreviewed dep bumps |
| [BP] Nightly non-blocking `cargo-fuzz` on the decode surfaces (B10), the broker frame decode included [28] | guest/network/cross-privilege-reachable parser panics |
| [52] Suppression-hygiene lints in every preamble (`clippy::allow_attributes`, `allow_attributes_without_reason`) | fn/module-scope or reason-less suppressions; stale `#[allow]`s outliving the lint they silence (B11) |
| [52] **Toolchain honesty**: `rust-toolchain.toml` is the single toolchain source; `rust-version` lives once in `[workspace.package]` and **equals the tested floor (1.96.1)**, sync-asserted in `ci` (v30 §9.7 states 1.96.1 single-sourced in the body — the docs/historical/70 pre-bump erratum is folded in; no standing erratum [28][IN]) | declared-vs-effective MSRV drift — an understated `rust-version` lets an MSRV-aware resolver re-resolve older consumers onto the *vulnerable* dependency versions the lockfile pins were bumped past (the `time 0.3.45` class) |
| [BP] `shellcheck scripts/*.sh` — the ban scripts, preflight, and bless path are load-bearing, security-adjacent bash | quoting/word-split bugs in the scripts that gate everything else |
| [BP] `actionlint` + `zizmor` over `.github/workflows/`; third-party actions **pinned to full commit SHAs**, Dependabot moves the pins | workflow typos and shell bugs in `run:` blocks; script-injection, over-broad permissions, unpinned-action supply chain — the suites run on a **self-hosted KVM runner**, where a compromised action is lateral movement onto the host |
| [BP] `cargo machete` (per-crate `[package.metadata.cargo-machete]` ignores for macro-only false positives) | unused dependencies silently enlarging the audited, licensed, advisory-scanned surface |
| [BP] `typos` with a project `_typos.toml` | doc rot in a repo whose docs are a first-class artifact |

**Gates that landed with the 0.10 pass [28]** are standing suite members now (drop-order recording;
the `HostEnv::hermetic()` seam re-parameterization; the `CgroupFs`-fake `mem_limit_enforced`
enforcement tests; the
`HostCapabilities` fake-host descriptor test; the `FakeVmm` fault-arm tests; the
sidecar-matches-streamed-rehash store test; the table-driven CLI redirect test) — regressions there
are ordinary reds, not delta reviews.

**Gates that land with the v30 delta pass [30]** (each delta's named gate, per design v30 §18): the
overlay tests — wins / falls-back / referenced-absent-fails-naming-the-key /
**misspelled-override-key-rejected** — plus the overlay-edit key-invalidation test (1); the
vendor-script both-ways legs + the semver-checks `-p vmcell-artifact-validator` extension (2); the
resolved-config-sidecar presence + fragment-symbol assertion, the prebuilt-with-label typed reject,
the sorted-label and missing-fragment-marker unit tests (3); the serial-classifier red-on-inverse
battery on canned logs (4); the example-workspace CI job itself, deliberately reddened once during
landing (5); the injection-layer reserved/duplicate-dest rejects + the live in-guest `cat`/`stat`
leg + the identity-fold cache test (6); the extracted-prologue mock-handshake test + the dead-port
typed-error leg + the custom-init dial leg (7); the §6.5 segment battery — KVM-free math/naming/
allocator-race/slot tests plus the live two-VM/negative/netem/`dial_tcp`/residue/sweep legs (8);
the ninth honesty pin + the USB argv golden + both `build()` rejections + the opt-in
`test-usb-passthrough` live leg (9).

---

## Part E — Running a review  *(the process that made 37/40/46 trustworthy)*

- **Phase 0 preflight, block-and-ask.** A privileged-aware review starts by verifying the suites
  can actually run (`scripts/review-preflight-priv.sh`: runner blessed, KVM + backends present,
  delegated scope available). "This may not be a KVM host" is a question the script answers, not a
  reason to skip it — run it first. A failure whose printed remediation is `just bless` is
  **block-and-ask**: request the one-sudo bless from the maintainer, then rerun — it is not a
  static-only downgrade. Only a genuinely absent facility (`/dev/kvm`, a missing backend binary)
  downgrades the review to **static-only**, with every runtime claim marked unverified. Review 37's
  empirical pass found a non-binding memory cap, a broken FC restore, and a `/tmp` leak that
  seventeen static sub-reviewers missed. [37]
- **Run the suites at HEAD before reading code**, all three CI backends (`fail-fast=false`) plus the
  opt-in `just test-crosvm` where `$VMCELL_CROSVM_BIN` resolves (probe for the binary, don't presume
  its absence) — and for
  daemon-touching changes, `just test-daemon` alongside the two operating-mode suites [28]; the
  review reports what green *does not prove* (review 46's framing), not just what's red.
- **Ground in `implementation-notes.md` first.** Recorded, justified deviations are not
  re-reported; newly-found *justified* deviations are recorded there (per the maintainer's standing
  request), not listed as defects; the do-not-re-report list is maintained and **retired** when
  empirically disproven (the "CH restore is a known gap" entry outlived the fix [37]). Doc↔code
  reconciliation reports (docs/52) carry the same standing, and so do the design's **Appendix A
  reversals and §17 recorded gaps** (v30) — a settled reversal (MMIO-not-PCI, JSON-not-postcard,
  `clear_ambient_caps` default-off, flat-snapshot-not-chain, crosvm's `--disable-sandbox` +
  Layer-2 confinement, the baked FC/crosvm restore identities vs QEMU's rotated CID [IN]) is
  cited, not re-litigated, unless refuted with new evidence [28]. The implementation notes'
  **accepted limitations** carry the same do-not-re-flag standing until their retire condition
  fires: PAX-xattr non-preservation and the opaque-whiteout marker-first assumption (each pinned
  by its own test), daemon read-only extra disks, no `init=` over REST, the host-trusted unbounded
  session queue, the un-prefixed id-lock rendezvous dirs [IN]. Where a config doc proposes
  something *stricter than this rubric*, the rubric is the tie-breaker (the `temp_dir` non-ban
  [52]).
- **The delta register binds implementations, not the baseline.** [28][30] Until the v30 pass
  lands, the code legitimately matches validated 0.12 — a delta-item divergence is a finding only
  in the change claiming to implement that delta. A change implementing a delta lands **with the
  delta's named gate** (Part D), reconciles the as-built result in `implementation-notes.md`, and
  follows the v30 §18 register conventions: **re-verify the delta's premise anchors before
  cutting** (two v28 premises were empirically false — treat a stale premise as a stop-and-check),
  and a sketched name/signature may shift for a recorded reason — the behavior and its gate are
  what bind.
- **Adversarial verification for every Critical/High**: an independent agent re-derives the claim
  from the cited source and tries to refute it — three lenses (correctness; does the test actually
  stay green; is it already justified) — with a decisive empirical check where one exists (the
  `size_of` probe, the percentile reproduction). Majority-refute drops the finding; verification
  downgrades are recorded **with the reachability argument** ("unreachable in a supported flow" is
  a severity fact, not an excuse to omit). [37][46]
- **Every finding carries** `file:line`, the category, **the red test it lacks**, and a direction —
  independently re-checkable. Expect a residual error rate in a review this size: confirm the cited
  lines before fixing.
- **Perf findings cite measured evidence.** Check the `docs/historical/45` refuted-lever table before
  proposing (don't re-derive OPP-4…17); only interleaved same-session deltas are trustworthy;
  changes touching a measured path name the budget they must not regress. "Environmental" is a
  hypothesis, not a diagnosis — a flake explanation without a mechanism stays open. Tail figures
  published before 2026-07-03 are on the broken `floor(n·q)` estimator and are not comparable. [46][28]
- **A fix to host-facing code is not done** until the suites re-ran green on a KVM-capable host —
  probed, not presumed (AGENTS.md rule), and any capability-flag change re-validates empirically,
  not just in the descriptor. [37]

---

## One-line summary

Make every recurring defect class fail a **lint, a CI job, or a test that can actually go red** —
and treat any item that reaches human review as evidence a gate is missing. The v6
highest-leverage targets: **paths the suite structurally cannot reach** (failure injection,
window-filling payloads, non-default flows and defaults, the effect classes your fakes are blind
to — rule 4 + Part C), **one shared predicate/helper for every law** (A5/B7 — the second copy is
where the bug lives, and the census now spans naming, blessing, jail, the artifact-name validator,
the vsock prologue, the id-claim core, and the injection reserved-path list), **capability-or-
parsing, never both, with posture matching lifetime** (A13 + B12/B13), **the downstream contract
kept observable** (B15 — a promise-break to a workspace that cannot see your diff is the new
silent-failure class, and the example workspace is its gate), **reuse that stays reuse** (B16 —
segments and the raw dial are locations of existing machinery, not new datapaths), **faithful,
failure-injectable, blind-spot-honest fakes** (A9), **data-plane assertions** (A10), and **gates
that are reachable and can themselves fail** (Part D meta-rules) — all validated by actually
executing the suites (rule 5 + Part E), grounded in the design's settled reversals and the
implementation notes' verified premises rather than re-litigating either.
