# vmcell — Code Review Rubric (v4)

*Distilled from eight Claude review passes (docs 13, 17, 26, 27, 34, 37, 40, 46), two Gemini passes
(25, 33), and the doc↔code reconciliation that landed the automated gates (docs/52). Its job is to
stop the **classes** of defect those reviews found from recurring — not to re-list individual
findings. This **v4 rubric** supersedes v3 (`docs/50-claude-fable-code-review-rubric.md`); v4 adds
lint-suppression hygiene (B11), new tooling gates in Part D, and reconciliation-report grounding in
Part E. Tagging: unmarked items carry over from v2 (reviews 13–34); **[37] [40] [46] [G]** mark
items added or sharpened by that pass (G = the Gemini passes); **[52]** marks items arising from the
docs/52 reconciliation; **[BP]** marks best practices added on judgment for this problem domain, not
yet matched to a surfaced defect.*

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
   drive? Failure-injection, window-filling payloads, per-flow-variant coverage, and
   default-value tests are first-class requirements, not nice-to-haves.
5. **Host-facing claims are validated by execution, not reading. [37]** A review of (or fix to)
   host-facing code is not done until the suites actually ran on a KVM-capable host (Part E) —
   capability is **probed** (the preflight), never presumed absent: the box you are on usually
   qualifies, and the blessed runner exists precisely so an unprivileged reviewer can execute the
   privileged suite. Review 37's empirical pass found two Highs and a leak that seventeen static
   sub-reviewers could not see.

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
   permission errno (`EACCES`/`EPERM`/`EROFS`) is `CapabilityUnavailable`, and the split is a pure
   function unit-tested against both inverses [46]; and **a returned count is part of the result** —
   `Ok(n)` where `n < requested` (a short write, a partial `send_slice` enqueue) is not success;
   handle the remainder or fail [46].

2. **Every accepted input is honored or rejected — silent degradation is the default bug.** A
   *requested functional* op that cannot be performed returns a typed error
   (`Error::CapabilityUnavailable { op, needed }` / `Error::Unsupported { vmm, feature }`), never a
   logged-and-ignored no-op returning `Ok`. Three categories, and a review places every host-facing
   op in one: *functional* (fail loud) · *observational* — a read — (may degrade, surfacing what was
   unavailable via `*_read_ok` / `limits_enforced` flags) · *explicitly-listed best-effort* (the §15
   benchmark knobs; visible `warn!`, never silent). The test: *if a caller's assertion can be wrong
   because the op silently did nothing, it is functional.* Generalized by 37/40/46: the rule covers
   **every accepted input** — a config field dropped with a bare `let _ =`
   (`Privileged { host_services_port }` [46]), an enum variant with no code path behind it
   (`Egress::Open ≡ Blocked` [46]), a request field the far end never reads (`ExecRequest.timeout`
   in the guest [G]), a restore mode hardcoded away (`RestoreMode::Lazy` on FC [37]), and a CLI flag
   whose unknown value silently selects the default [46]. **A `#[cfg]` feature gate never silently
   changes semantics** — a feature-gated arm of a functional op that no-ops (`create_slice` under
   `not(metrics)` [40]) is this bug in build-config form; features gate availability (compile error
   or typed error), never behavior. **Defaults get the strictest scrutiny** — a dead default is
   worse than a dead option, because every caller inherits it [46].

3. **Capabilities are declared, probed, and reported — and the report is pinned.** Backends report
   `VmmCapabilities`; the host environment is probed (effective caps, delegated controllers, KVM
   group, netns-dir writability) and a requested mode's missing prerequisites fail loud up front,
   never mid-run. Sharpenings: every advertised flag is **live** (a `lazy_restore: true` with no
   plumbing is a lie [37]) and **empirically backed** (FC advertised `snapshot_restore` while the
   path failed end-to-end until validated on a real host [37]); every flag on every backend has a
   **capability-honesty pin test** so a silent regression to `false` cannot turn a scenario into a
   green no-op [46]; accessors are honest (`guest_cid()` must not report the fresh allocator CID
   while the restored guest keeps its baked one [46]); and **a transient probe failure is never
   cached as a permanent negative capability** — distinguish "unsupported" from "probe failed", and
   log the latter [40].

4. **Ownership owns cleanup — on panic, on post-acquire failure, and on every spawned helper.**
   Every acquired host resource (VMM process *group*, virtiofsd, auxiliary daemons, netns, cgroup,
   overlay, sockets, scratch dirs, CID, VMID, threads/runtimes) is released by `Drop` in reverse
   dependency order, and that path runs on panic. A resource acquired before a later fallible step
   is owned by an RAII guard *before* that step — and this applies to **each** spawned process
   individually: reaping the primary VMM's group while dropping the un-guarded second daemon orphans
   it (the `vhost-device-vsock` leak [37]). `shutdown()` and `Drop` route through **one shared
   ordered-teardown helper** — two hand-maintained orders diverge [40]. Where teardown is implicit
   (struct-field drop order, e.g. `EnvSetup`), the order is load-bearing: dependents are declared
   before the resources they run inside (drop order = declaration order) with a comment saying so,
   and a mid-`start()` failure-injection test pins it [46]. Cleanup ops are idempotent (no spurious re-delete WARNs masking real failures [37]).

5. **One law, one predicate.** A contract enforced at multiple boundaries (snapshot-eligibility at
   `build()` / `orchestrator::restore()` / backend self-guards) is implemented as **a single shared
   predicate** each boundary calls, pinned by its own unit test — per-backend copies *demonstrably*
   diverge (the FC copy never grew the virtio-fs-rootfs term the CH copy carried [37][40]). A method
   whose correctness depends on "the caller checked first" is a latent bug: check inside, return
   `Error::Unsupported`. The same for config: validate in `build()` — including documented
   incompatibilities (`ksm_mergeable ⊥ vhost-user` [37]) — with a negative test per rejected case.

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

9. **A seam you can't fake is a unit you can't test — and a fake must be *faithful*, *driven*, and
   *failure-injectable*.** No module-global mutable state for IDs, time, or I/O; side effects go
   behind small injectable traits with a real impl and a recording fake. Three fake pathologies from
   37/40/46: **over-promise** — `FakeCgroupFs` enforcing delegation regardless of feature while the
   real non-`metrics` impl no-ops means no test can see the real bug; a fake is never *stronger*
   than the real impl on the property under test [37][40]; **wrong layer** — `FakeGuestResync`
   bypassing the desync layer hides the wedge that layer causes; the fake sits at the same seam the
   real path traverses [46]; **no fault injection** — a `FakeVmm` that records but cannot be told to
   fail leaves every error path untestable [46].

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
    dirs) [40]. Security matchers **normalize** before comparing (lowercase, strip the FQDN trailing
    dot — the deny-list was bypassable by `EXAMPLE.NET.` [37]). A security assertion carries a
    **positive control**: a blocked attempt against a black-hole address fails filter-independently;
    prove the same target succeeds via the allowed path and is blocked via the filtered one [40].
    And the test configuration must not neuter the property under test — passing `-k` everywhere
    disabled exactly the TLS validation whose failure the probe mishandled [46].

---

## Part B — Review checklist

### B1 · Resource lifecycle & teardown  *(Critical in every pass)*

- [ ] `MicroVm`'s `Drop` performs the full ordered teardown — **VMM process group → virtiofsd →
      netns / cgroup / overlay / sockets / scratch dir** — exercised by a panic-residue test that
      asserts the **full order** via recording fakes, not merely that *a* drop happened. `test`
- [ ] `shutdown()` and `Drop` share **one** ordered-teardown helper; two hand-maintained orders
      diverge (`shutdown()` deleted the netns before the in-netns proxy while `Drop` was correct).
      [40] `review` `test`
- [ ] Where teardown is implicit struct-field drop order (`EnvSetup`), dependents are declared
      before the resources they run inside — drop order = declaration order, stated in a
      load-bearing comment — and a **mid-`start()`/`restore()` failure-injection test** asserts zero
      residue on the error paths, not only on panic. [46] `test`
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
- [ ] Per-VM scratch dirs are owned (a `VmTempDir`/`tempfile::TempDir` guard dropped last), and the
      residue assertion covers the **directory**, not only the socket inside it — 36 `/tmp` dirs
      leaked under a green residue test that checked the socket alone. [37] `test`
- [ ] Spawned-forever workers (smoltcp NAT, proxy, runtimes) hold a shutdown signal + `JoinHandle`;
      `Drop` signals and joins **within a timeout**. A worker blocked pre-connection (an `accept()`
      that never checked its kill-eventfd) deadlocks the join. [46] `test`
- [ ] Cleanup is **idempotent**: an explicit `delete()` followed by `Drop` must not re-delete and
      log a spurious WARN that trains readers to ignore real teardown failures. [37] `review`
- [ ] `request_shutdown()` is followed by a bounded grace-poll (`has_exited()`), then the SIGKILL
      fallback — never an immediate unconditional `kill()`. `review`
- [ ] `sweep_orphans()` (injectable `OrphanScanner`; non-live vmids only; netns → cgroup → scratch
      order) reaps hard-crash residue; the fully-automatic periodic sweeper is a recorded §16 gap —
      keep it visible, don't re-justify it per review. `review`
- [ ] **Guest/network-driven in-flight state is bounded and reclaimed — at every accumulation
      point.** The smoltcp pool cap, the PID-1 reaper status map, **the proxy request log** (an
      unbounded `Vec<String>` fed by guest requests is the same DoS in a different subsystem [40]),
      and **allocations sized from guest input** (`vec![0; desc.len()]` up to 4 GiB from a
      descriptor [37]) — cap, ring-buffer, or clamp each, and assert the bound after a flood. `test`
- [ ] Reclaim predicates are tested with the resource **live**: the pool test using only
      `stream = None` missed that a closed mapping with `stream = Some` counted live forever,
      self-inflicting the DoS the cap was built to prevent. On any transition to closed/error,
      *every* branch releases the associated resource (`take()` + shutdown), not just the branch the
      happy path exercises. [37] `test`
- [ ] Concurrent-startup patterns are cancellation-safe: `try_join_all` over daemon starts leaks the
      already-started process groups when one future fails and the rest are dropped — the recorded
      OPP-10 rejection; a replacement needs a `join_all`+owner-push design plus a zero-leak
      failure-injection test. [BP] `review`
- [ ] [BP] Helper daemons set `PR_SET_PDEATHSIG(SIGKILL)` in `pre_exec` (belt to the sweeper's
      suspenders: a SIGKILLed orchestrator can't run `Drop`), and host-side fds are `CLOEXEC` so
      spawned VMMs don't inherit sockets/locks that outlive teardown. `review`

### B2 · Failure visibility

- [ ] No `.unwrap()` in non-test code. `.expect("invariant: …")` is the only escape hatch and is
      **not** permitted on guest-/network-driven paths (smoltcp packet loop, both TX and RX vring
      ops, PID-1 dispatch, proxy, in-process FUSE queue dispatch) — those degrade gracefully.
      `clippy::expect_used` is not currently denied, which is how a production `expect()` survived
      in `exit_event` — deny it with per-site `#[allow]` + invariant comments, or grep-ban it in the
      guest-driven modules. [46] `lint` `review`
- [ ] PID-1 never exits on a recoverable condition — including the **primary signal path**: a
      SIGTERM handler that `break`s out of `main` kernel-panics the guest just as surely as the
      fallback path it contradicts. Loop or power off. Fatality is consistent with the documented
      core-mount policy (a `/sys` `create_dir_all` should not be fatal while the `/sys` *mount* is
      tolerated). [40] `review`
- [ ] The reaper does not steal an exec'd child's exit status (false `127`): the
      `ReaperCoordinator` pre-spawn epoch discipline (AGENT-2) stays pinned by its red-on-inverse
      unit test, and the record/reserve critical-section gap under pid reuse stays a *recorded*
      deferral, re-checked when touched. [40] `test`
- [ ] No `Ok(())`/printed success on a failed or unsupported branch: a QMP `{"error":…}` swallowed,
      a `snapshot()` that resumes-and-returns-Ok on failure, a CLI verb that prints success while
      doing nothing, a **mandatory sidecar written best-effort** (an FC snapshot "succeeding"
      without the sidecar its own `restore()` hard-requires is an unrestorable artifact reported as
      restorable [37]). Deferred CLI verbs (`exec`/`ls`/`rm`/`destroy`) fail loud with a typed
      error. `review` `test`
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
      `CapabilityUnavailable`) unit-tested both ways, and `limits_enforced` reflecting **all**
      requested controllers, not just memory. Best-effort is only the listed §15 knobs, with a
      visible `warn!`. [46] `test`
- [ ] A **configured limit is proven binding, not just readable**: `memory.max` read back correctly
      on all three backends while shmem-backed guest RAM sailed past it — the enforcement test sets
      guest RAM *above* the cap and asserts the cgroup `memory.events oom_kill > 0` (which is why
      `create_slice` writes `memory.swap.max=0` + `memory.oom.group=1`). Configuration readback is
      not enforcement. [37] `test`
- [ ] Unknown/unhandled protocol variants are logged (and the connection policy decided), never
      silently dropped into a desync. [40] `review`
- [ ] Logging goes through `tracing` at the right level; no `println!`/`eprintln!` in production
      code; mutex poisoning handled deliberately. [BP] Serial logs and proxy logs may contain guest
      data — cap retention, and never log the CA private key or other secrets. `lint` `review`

### B3 · Capability & input contracts

- [ ] Typed `Error::Unsupported { vmm, feature }` for every capability gap; law rejections at the
      orchestrator boundary use it too (an `Error::Config` there breaks callers matching
      `Unsupported` [40]). Advertised capabilities are live, empirically validated, and **pinned
      per-flag per-backend** (all seven `VmmCapabilities` flags — four of seven had no honesty pin,
      so a flag regressing to `false` would green-out its whole scenario [46]). `test`
- [ ] `restore()`/`snapshot()` self-guard on `capabilities()` *and* on the absence of any
      vhost-user device via the **single shared predicate** `config_has_vhost_user_device` — never
      per-backend copies (they diverged [37][40][46]) — returning `Err(Unsupported)`, with the
      shared-predicate unit test plus a negative test at each of the three boundaries. `test`
- [ ] `create()` rejects configs the backend can't honor instead of silently building a broken VM —
      and the **primary backend is not exempt**: CH and QEMU built a kernel-panicking VM for a
      `VirtioFs` rootfs while only FC rejected it. [40] `test`
- [ ] `VmConfigBuilder::build()` returns `Result` and rejects, with a negative test each: duplicate
      share tags; snapshotting + {virtio-fs rootfs, **any** data share, unprivileged net};
      documented incompatibilities (`ksm_mergeable` + any vhost-user device [37]);
      `Privileged { host_services_port: Some(_) }` until wired [46]; `vcpus == 0`; `mem_mib` below
      floor; out-of-range vmid. `#[must_use]` on builder methods. `test`
- [ ] **No dead variants or flags advertised as live**: an `Egress::Open` default with no code path
      admitting egress; a wire feature bit (`VIRTIO_NET_F_CTRL_VQ`) with no backing queue/handler;
      a `RestoreMode` a backend ignores — implement, reject typed, or remove. [37][40][46] `review` `test`
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
      **injective field concatenation** (delimit or length-prefix [37]). `test`
- [ ] The rootfs key folds the **full source closure** of everything baked in: the guest agent's
      source closure (not just the bin wrapper — editing `agent/mod.rs` must re-bake [37]), the
      guest-tools content, the baked CA cert content, and — on **every flow variant** — the actual
      bytes: the `--agent-musl` path folds the injected binary's `hash_file`, never its path [46].
      The snapshot key folds the pinned CH build identity (no cross-version snapshot compat), and
      deliberately *not* virtiofsd (§12.1). An end-to-end "edit agent source → rootfs key changes"
      test pins the class. `test`
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

### B5 · Pipeline staging

- [ ] Stage 0 loads the committed `pins.json` and propagates it via `StageOutputs` — honestly
      documented as a lock (live resolution is recorded §16 forward work); pin ingestion is
      fallible (malformed JSON is an error, not an empty map [37]); a missing pin is an error —
      **no hardcoded image/digest fallbacks**, and image+digest pair atomically (a half-specified
      pin set yielding a mismatched reference is worse than a missing one [37]). `test` `review`
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
      `CgroupFs`, `Netlink`, `NftApplier`, `SerialLog`, `OciPuller`, `GuestResync`) — never
      module-global statics; no "wrapper around a global static" pretending to be injectable.
      `CI(grep)` `review`
- [ ] **Cross-process coordination is seamed, atomic, and tested.** The shared vmid lock dir is
      injectable (`shared_at`), the claim writes pid content atomically (within the `create_new`
      open, or temp+rename — a crash between create and write leaves an unparseable lock the
      "crashed-owner reclaim" never recovers), reclaim tolerates corrupt/empty locks, the
      liveness-check-then-remove race is closed or tolerated by design, and all of it has tests —
      the hardcoded `/tmp` path had zero. [46] `test`
- [ ] [BP] On multi-user hosts, predictable names under world-writable `/tmp` are squattable
      (denial-of-service on the lock dir) — prefer `$XDG_RUNTIME_DIR`/per-uid dirs; the
      dev-workstation scope is a recorded trade, kept visible.
- [ ] Allocators: `release()` operates on the actual instance; reserved CIDs skipped; wrap without
      colliding with live/reserved ids; **CID reuse on sequential restore is by design** (assert
      "valid live CID", never `assert_ne!`); allocator tests stay hermetic; the release proptest
      asserts a freed value is actually *reused* (a no-op `release()` still hands out fresh unique
      ids [40]). `test`
- [ ] `/30`/MAC math centralized and unit-tested; the host NAT MAC pinned outside
      `mac_math(1..=254)`; the five smoltcp silent-wedge invariants (§12.8) each pinned by the test
      that reddens on its inverse — including the window-filling `host_read_budget` test (C-NET-1). `test`
- [ ] **Socket namespace origination is explicit**: a proxy binding inside the VM netns re-enters
      the host root netns before creating upstream/DNS sockets (a socket's netns is fixed at
      `socket()` time); the re-entry failure aborts startup loud. Any thread that `setns()`s
      documents what it creates while inside. [46] `review` `test`
- [ ] [BP] Deadlines and durations use `Instant`, never `SystemTime` arithmetic (the allocator
      seeded from `SystemTime::now()` bypassing the injected `Clock` [40] is the smell); wall-clock
      time appears only where wall-clock is the point (the resync payload). Outer timeouts bound
      inner retries — no retry loop can exceed its caller's deadline. `review`
- [ ] Side-effecting fakes carry assertions (rendered ruleset, netlink order, exact limit-file
      contents) and support **failure injection** (M-VMM-6 is the recorded open seam-enrichment). `test`

### B7 · Module boundaries & duplication

- [ ] **The second copy is where the bug lives.** Logic existing in ≥2 copies is extracted and
      unit-tested once; the evidence: the inline 18-byte `ifreq` duplicating the audited `netif`
      struct (an OOB write onto PID 1's stack [46]); per-backend vhost-user guards (diverged
      [37][40]); the triplicated spawn/`add_task`/readiness sequence (QEMU already wrapped errors
      differently [40]); the QMP/JSON-error parse; the `/proc/self/cgroup` sibling-placement parse
      (triplicated across src + two test files, pure and untested [46]); `shutdown()` vs `Drop`
      ordering [40]. `review`
- [ ] No hand-rolled HTTP (numeric status parse, looped reads) or hand-rolled packet sniffing
      (`packet.get(14)`) where a parser exists. [G] `review`
- [ ] Module responsibilities match the design: cgroup logic lives in `metrics.rs` behind
      `CgroupFs`; test-only behavior is never baked into production handlers. `review`
- [ ] **Benchmarks exercise the production helper, not a strawman** — a bench `black_box`-ing a
      hand-rolled `format!("10.200.{}.1", …)` guards a metric a real `/30` regression can't move.
      [40] `review`

### B8 · Public-API hygiene

- [ ] `#[non_exhaustive]` on growable public types — **with a constructor/builder/`Default`**, or
      external implementors can't name them at all [46]; `cargo semver-checks` in CI. `CI` `review`
- [ ] `Error` has per-subsystem variants; feature-gated `#[from]` sources are themselves
      `#[cfg]`-gated; the deliberate stringly-payload posture is recorded — flag only where a real
      typed source exists. `review`
- [ ] No always-zero / never-read public fields (`ResourceUsage` net counters: populate or delete;
      the netns-read architecture gap is recorded §16 — the lying field is not). `review`
- [ ] **No `pub` escape hatches around self-guards**: `pub instance_mut()` lets a caller invoke
      backend `snapshot()` directly, bypassing the cached-client invalidation the `MicroVm` wrapper
      exists to enforce. Encapsulation is part of the invariant. [46] `review`
- [ ] Multi-value returns with adjacent same-typed fields (the 8-tuple with two swap-prone
      `Option<u32>` pgids) become structs with named fields. [46] `review`
- [ ] Docs: `#![deny(missing_docs)]`; `# Errors`/`# Panics` accurate to the code (not describing
      checks never performed, nor errors never returned); `cargo doc` gated in CI (five broken
      intra-doc links hard-failed doc builds with nothing catching it [46]). `lint` `CI`
- [ ] **Comments are load-bearing and audited like code**: a `SAFETY` comment must prove the actual
      obligation (async-signal-safety, not kill semantics); a "correctly-sized" claim on a
      wrong-sized struct and a "stronger defense-in-depth" claim on a weakened check are defects in
      themselves; reworks sweep the comments and design/§16 entries they invalidate (the subprocess-
      era resync docs, the "environmental" retry stanza, the stale grace-window gap). [40][46] `review`
- [ ] Per-module `#![forbid(unsafe_code)]` on I/O-free modules; dead code removed or justified. `lint` `review`

### B9 · The privileged window  *(`vmcell-test-runner`, `vmcell-guest-agent`)*

Every dependency and instruction here executes with elevated capability; the review is stricter.

- [ ] The runner checks the **effective** set and the printed remediation says `setcap … +ep`
      (a `+p`-only blessing leaves caps un-raised). `test`
- [ ] The privilege-transition sequence is a **pure function** (`plan_privilege_transition`)
      unit-tested against each buggy inverse — including the setuid form's security-critical
      **uid-before-ambient** ordering and the P/E trim — so ordering is verified before a bless,
      not only by running the suite. Only the thin syscall layer stays integration-only. [40] `test`
- [ ] **Path confinement anchors on the runner's own trusted location** — canonicalized
      `current_exe()` → the `.vmcell-bin` ancestor → `<workspace>/target` — then rejects `..` on
      the raw argument, canonicalizes, and confirms descent. Anchoring on the *argument's* own
      `target/` ancestor is inert (every path contains its own ancestors) — a local
      privilege-escalation surface that shipped with a comment calling it stronger. Adversarial
      fixtures (`/home/attacker/target/debug/evil`, `..`, symlinks) are unit-tested. [37][40] `test`
- [ ] `just bless` installs to the stable out-of-`target/` copy, `chmod 0700` (the enforced
      execute boundary; `0750`+group is the documented shared-host alternative), idempotent via a
      content-hash stamp keyed on the **runner only** — never on test binaries. [40] `review`
- [ ] Dependency-thin (`rustix`+`capctl`+`libc`, the `libc` rationale recorded); **no
      tracing/logging stack initialized at full privilege** (the copy-pasted `tracing-subscriber`
      dep [37]); the standing set is exactly `CAP_NET_ADMIN`+`CAP_SYS_ADMIN`+`CAP_DAC_OVERRIDE`;
      `merge_preserved_groups` keeps the kvm gid iff held, never invents it (the setuid form
      otherwise drops `/dev/kvm` access [37]). `CI` `test`
- [ ] Honest limitations stay surfaced: no `CAP_SETPCAP` → bounding-drop is a warned no-op on the
      file-cap path; the runner is a dev-workstation convenience, not a multi-tenant boundary. `review`
- [ ] virtiofsd runs `--sandbox namespace` with the recorded uid posture (`SUDO_UID`, `nobody`
      refused; the per-share service-uid allocator is a §16 gap); `--readonly` enforced for RO
      shares — the in-process backend *refuses* RO fail-loud (typed, not stringly) until it can
      enforce it. [G][40] `review`

### B10 · Unsafe, FFI & the guest-facing boundary  *(new in v3)* [46]

Everything crossing the vsock/virtio/ioctl boundary is attacker-influenced or ABI-critical.

- [ ] **One audited definition per kernel struct.** Every `#[repr(C)]` passed to an ioctl/syscall
      lives in one module (`netif`/`net_sys`), size- and offset-asserted against `libc` (a
      `const`-asserted `size_of`, offset tests) — the inline 18-byte `ifreq` against the kernel's
      40 bytes was a 22-byte OOB write onto PID 1's stack on every boot, green because the bytes
      landed in padding. Re-declaring inline is banned. `test` `lint(grep)`
- [ ] `// SAFETY:` comments prove the **actual** obligation of the block (async-signal-safety in
      `pre_exec`; pointer validity + size for an ioctl), and a false safety claim is a defect. `review`
- [ ] **Counts are handled**: `send_slice`/`write` returning fewer bytes than offered retains and
      re-enqueues the remainder (C-NET-1 silently corrupted host→guest streams under
      backpressure); reads into guest-visible buffers are bounded by the receiver's real free
      capacity (`host_read_budget`). `test`
- [ ] Guest-derived lengths/indices are validated before use: descriptor indices checked before
      `add_used` (the guest-drivable RX panic), allocation sizes clamped to MTU/frame caps,
      wire-length prefixes capped by `MAX_FRAME_BYTES` — which is defined **once** in
      `vmcell-protocol` and enforced identically on both ends (the host codec defaulted to 8 MiB
      against the guest's 16 [37]). `test`
- [ ] **Interop is tested cross-implementation**: the guest's hand-rolled `send_framed`/
      `read_framed` round-trips against the host's real `LengthDelimitedCodec` in a KVM-free unit
      test (both directions + an over-cap reject) — a suite that uses the same codec on both ends
      tests nothing about the hand-rolled side. [40] `test`
- [ ] [BP] **Fuzz the decode surfaces**: `cargo-fuzz` targets for the protocol codec + framing, the
      QMP reply reader, the HTTP status parser, and the tar/OCI ingestion path. These are exactly
      the parsers guest/network bytes reach; a nightly non-blocking fuzz job is cheap relative to
      one missed frame-parse panic. `CI`
- [ ] [BP] Run the unsafe-adjacent pure units under **Miri** where no ioctl blocks it (the
      virtqueue ring handling, the framing, the reaper), and keep integer conversions from the wire
      checked (`try_from`, not `as`). `CI` `review`

### B11 · Lint-suppression hygiene  *(new in v4)* [52]

The Part D gates are only as strong as the suppressions they tolerate.

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
      `restore_rotates_host_paths` per backend. [37]
- [ ] **Vacuous residue checks.** Asserting non-existence of a `format!`-recomputed path with no
      pre-drop existence check — silently vacuous the day the naming drifts. Assert the artifact
      existed before drop, then that it's gone. [46]
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
      tests running the host codec on both ends [40].
- [ ] **Tiny-payload data-plane tests.** Every NAT/proxy test moving payloads far below the window
      masks backpressure bugs (C-NET-1); include window-filling and `>MAX_FRAME` payloads. [46]
- [ ] **String stand-ins; determinism via a trivial stage; harness strawmen.** `format!` paths
      instead of real socket paths; a `DummyStage` where the real stage's cache bugs live; a bench
      measuring a reimplementation [40]; **untested stats helpers** — the `floor(n·q)` percentile
      made every published p95 at N=20 the sample max; pure math in the bench harness gets unit
      tests against known values, and published tables are regenerated when the harness changes.
      [46]

**Positive requirements:**

- [ ] Serial execution via the nextest `serial-host` group (positively selecting every vmcell
      integration binary so new tests auto-join); `#[ignore = "reason"]` with the reason string;
      nextest pinned ≥ 0.9.85 so `--no-tests=fail` holds; the two operating-mode suites separately
      invoked with visible hard preconditions. `CI`
- [ ] **Capability honesty machinery**: `require_cap!` panics for the primary backend, records to
      the durable skip manifest for others; a per-flag honesty pin exists for **all seven**
      `VmmCapabilities` flags on every backend. [46] `test`
- [ ] **Failure injection is a first-class suite member**: mid-`start()`/`restore()` failures
      (assert zero residue + correct implicit drop order); a forced spawn-step failure after each
      helper daemon starts (assert the helper is reaped); a transient resync/transport failure
      followed by recovery on the next `agent()` call. [37][40][46] `test`
- [ ] **Data-plane assertions**: an egress byte after restore (the rotated `/30`'s default route
      observed in-guest *and* traffic moves); window-filling NAT transfers; a real upstream through
      the privileged Filtered proxy where CI has internet, else the doubles-only contract stated in
      the test. [46] `test`
- [ ] Required integration assertions stay specific: snapshot reconnect (guest re-bind + per-backend
      host-path branch) + valid live CID + `mac_math(new_vmid)`/route identity + FakeClock-driven
      first-call resync + reseed captured without the test reseeding; HTTPS interception logged +
      `CONNECT` falls through + label-boundary **and normalized** (case, trailing dot) block
      observed and recorded; ordered-Drop-on-panic zero residue including the scratch **directory**;
      N-VM concurrency actually concurrent; the pipeline tamper/cache-hit/determinism trio on real
      stages; `put_file` round-trip read back in-guest; the structural zero-netlink gate plus the
      behavioral grep (an agent shelling out to `ip` adds no crate and passes the tree gate [40]). `test`
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
#![deny(unreachable_pub)]                                    // v4: API surface honesty
#![deny(clippy::undocumented_unsafe_blocks, clippy::missing_safety_doc,
        clippy::missing_errors_doc, clippy::missing_panics_doc,
        clippy::multiple_unsafe_ops_per_block)]              // v4: one obligation per SAFETY
#![cfg_attr(not(test), deny(
    clippy::unwrap_used, clippy::panic, clippy::unreachable,
    clippy::todo, clippy::unimplemented,
    clippy::indexing_slicing,
    clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro,
    clippy::allow_attributes, clippy::allow_attributes_without_reason,  // v4: B11
))]
// Under evaluation after M-HOST-6: cfg_attr(not(test), deny(clippy::expect_used)) with per-site
// #[expect]s carrying "invariant:" reasons — at minimum grep-ban `.expect(` in guest-driven modules.
```

**Print-by-contract binaries** (`vmcell-cli`, `vmcell-guest-tools`, `vmcell-test-runner`) drop the
two `print_*` denies with the rationale in the crate doc; the PID-1 agent binary keeps the full
family — a PID-1 panic aborts the guest, so `unwrap_used`/`panic` are load-bearing there. [52]
**Wire crates** (`vmcell-protocol`, the guest agent) add
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
   fixture per keyword/rule. [40]
3. **`just ci` and CI are the same thing, asserted.** Same `-D warnings` mechanism (RUSTFLAGS),
   same steps, same nextest filters including the `kind(test)` predicate — CI drifted to running
   ~172 lib tests concurrently with the serial VM suite [46]. Either generate both from one source
   or add an equality-check job.

**CI jobs** (all required):

| Gate | Catches |
|---|---|
| `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` | the lint families; format drift |
| Build **and** clippy each lean target (`agent`, `test-runner`, `guest-tools`) — a `cargo tree`-only check never compiles the target | an un-`cfg`'d `#[from]`/re-export breaking a non-default build |
| **Blocking builds of the shipped reduced-host feature configs** (e.g. `--no-default-features --features cloud-hypervisor[,metrics]`) [40] | the CFG-1 class: a feature-gated arm silently changing semantics in a config only the non-blocking powerset compiles |
| Lean-target tree assertion (∌ `tokio`/`hyper`/`rtnetlink` for agent + test-runner; guest-tools exempt, recorded) | privileged-window/guest binaries re-coupling to the host stack |
| `cargo deny check`; every `ignore` carries a **per-crate** rationale — sixteen identical boilerplate RUSTSEC ignores is the bulk-suppression pattern recurring [37] | GPL/unvetted crates; silently defeated advisories |
| `cargo semver-checks` | unannounced API breaks |
| **`cargo doc` (deny broken intra-doc links)** [46] | a hard-failing doc build nothing notices |
| `cargo nextest run` with per-test timeouts; retries scoped to the VM integration profile only, with the honest stanza comment (retries are the residual-environment backstop, not a diagnosis — AGENT-2 taught that [46]) | hangs; retry-masked rot |
| The `--ignored` integration matrix on a KVM runner, selecting > 0 tests, **compiled with `--features firecracker,qemu`** — default-features CI compiles the secondary backends out entirely [37] | the suite being CI-invisible; FC/QEMU never executing |
| Skip-manifest surfaced in CI output (count + contents) [46] | capability skips accumulating invisibly |
| Global-state grep ban (alias-aware, multi-line-aware, with the per-keyword self-test fixtures) [40] | un-fakeable global state returning |
| **Vendored-patch assertion**: `cargo tree` proves `vhost`/`vhost-user-backend` resolve from `vendor/` with exact `=` pins — a caret bump silently drops the carried patch with only a cargo warning [46] | the QEMU-unprivileged patch evaporating |
| [BP] `cargo build --locked` / `--frozen` in CI | lockfile drift; unreviewed dep bumps |
| [BP] Nightly non-blocking `cargo-fuzz` on the decode surfaces (B10) | guest/network-reachable parser panics |
| [52] Suppression-hygiene lints in every preamble (`clippy::allow_attributes`, `allow_attributes_without_reason`) | fn/module-scope or reason-less suppressions; stale `#[allow]`s outliving the lint they silence (B11) |
| [52] **Toolchain honesty**: `rust-toolchain.toml` is the single toolchain source; `rust-version` lives once in `[workspace.package]` and **equals the tested floor (1.96.1)**, sync-asserted in `ci` | declared-vs-effective MSRV drift — an understated `rust-version` lets an MSRV-aware resolver re-resolve older consumers onto the *vulnerable* dependency versions the lockfile pins were bumped past (the `time 0.3.45` RUSTSEC class) |
| [BP] `shellcheck scripts/*.sh` — the ban scripts, preflight, and bless path are load-bearing, security-adjacent bash | quoting/word-split bugs in the scripts that gate everything else |
| [BP] `actionlint` + `zizmor` over `.github/workflows/`; third-party actions **pinned to full commit SHAs**, Dependabot moves the pins | workflow typos and shell bugs in `run:` blocks; script-injection, over-broad permissions, unpinned-action supply chain — the suites run on a **self-hosted KVM runner**, where a compromised action is lateral movement onto the host |
| [BP] `cargo machete` (per-crate `[package.metadata.cargo-machete]` ignores for macro-only false positives) | unused dependencies silently enlarging the audited, licensed, advisory-scanned surface |
| [BP] `typos` with a project `_typos.toml` | doc rot in a repo whose docs are a first-class artifact |

---

## Part E — Running a review  *(new in v3; the process that made 37/40/46 trustworthy)*

- **Phase 0 preflight, block-and-ask.** A privileged-aware review starts by verifying the suites
  can actually run (`scripts/review-preflight-priv.sh`: runner blessed, KVM + backends present,
  delegated scope available). "This may not be a KVM host" is a question the script answers, not a
  reason to skip it — run it first. A failure whose printed remediation is `just bless` is
  **block-and-ask**: request the one-sudo bless from the maintainer, then rerun — it is not a
  static-only downgrade. Only a genuinely absent facility (`/dev/kvm`, a missing backend binary)
  downgrades the review to **static-only**, with every runtime claim marked unverified. Review 37's
  empirical pass found a
  non-binding memory cap, a broken FC restore, and a `/tmp` leak that seventeen static sub-reviewers
  missed. [37]
- **Run the suites at HEAD before reading code**, all three backends, `fail-fast=false`; the review
  reports what green *does not prove* (review 46's framing), not just what's red.
- **Ground in `implementation-notes.md` first.** Recorded, justified deviations are not
  re-reported; newly-found *justified* deviations are recorded there (per the maintainer's standing
  request), not listed as defects; the do-not-re-report list is maintained and **retired** when
  empirically disproven (the "CH restore is a known gap" entry outlived the fix [37]). Doc↔code
  reconciliation reports (docs/52) carry the same standing: a deviation recorded there with its
  reasoning is settled unless refuted with evidence — and where a config doc proposes something
  *stricter than this rubric*, the rubric is the tie-breaker (the `temp_dir` non-ban [52]). [52]
- **Adversarial verification for every Critical/High**: an independent agent re-derives the claim
  from the cited source and tries to refute it — three lenses (correctness; does the test actually
  stay green; is it already justified) — with a decisive empirical check where one exists (the
  `size_of` probe, the percentile reproduction). Majority-refute drops the finding; verification
  downgrades are recorded **with the reachability argument** ("unreachable in a supported flow" is
  a severity fact, not an excuse to omit). [37][46]
- **Every finding carries** `file:line`, the category, **the red test it lacks**, and a direction —
  independently re-checkable. Expect a residual error rate in a review this size: confirm the cited
  lines before fixing.
- **Perf findings cite measured evidence.** Check the `docs/45` refuted-lever table before
  proposing (don't re-derive OPP-4…17); only interleaved same-session deltas are trustworthy;
  changes touching a measured path name the budget they must not regress. "Environmental" is a
  hypothesis, not a diagnosis — a flake explanation without a mechanism stays open. [46]
- **A fix to host-facing code is not done** until the suites re-ran green on a KVM-capable host —
  probed, not presumed (AGENTS.md
  rule), and any capability-flag change re-validates empirically, not just in the descriptor. [37]

---

## One-line summary

Make every recurring defect class fail a **lint, a CI job, or a test that can actually go red** —
and treat any item that reaches human review as evidence a gate is missing. The v3 highest-leverage
targets, from what survived the v2 gates: **paths the suite structurally cannot reach** (failure
injection, window-filling payloads, non-default flows and defaults — rule 4 + Part C), **one shared
predicate/helper for every law and every protocol invariant** (A5/A6/B7 — the second copy is where
the bug lives), **faithful, failure-injectable fakes** (A9), **data-plane assertions** (A10),
**suppressions that stay narrow, reasoned, and self-reporting** (B11), and **gates that are
reachable and can themselves fail** (Part D meta-rules) — all validated by actually executing the
suites (rule 5 + Part E).
