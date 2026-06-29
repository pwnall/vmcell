# Imp Testing — Code Review Rubric (v2)

*Distilled from five implementation/review passes (reviews 13, 17, 26, 27, and **34**) against the
v6 → v13 design. Its job is to stop the **classes** of defect those reviews found from recurring —
not to re-list individual findings. This is the **v2 rubric**, revised after review 34 to close the
gaps that let review 34's defect classes exist in the first place; it supersedes the v1 rubric
(`docs/28-claude-code-review-rubric.md`).*

## Why this exists

The same defect families showed up in pass after pass even as the design tightened. The reviews
diagnosed the cause precisely: **the test/lint/CI layer had no automated opinion on any of them**, so
the as-built suite passed green and a human reviewer was the only thing standing between the bug and
`main`. A human reviewer is fallible five times running.

Review 34 added a sharper diagnosis still: **a green local build is necessary but not sufficient, and
a green CI run can be a lie.** Its two headline patterns are the ones this v2 rubric is built to kill:

- **Green-CI-that-masks-a-broken-non-default-config.** A single un-`cfg`'d `#[from]` error variant broke
  *every* build that excluded the default backends — the guest agent and the privileged runner — while
  `--all-features` (and therefore the naive CI) stayed green. The gate that should have caught it
  (`cargo hack` powerset) was *also* red for an unrelated reason and so was being ignored, and the
  lean-agent gate was `cargo tree`-only and **never built the agent**.
- **A path with no test that can actually fail is a path that has never run.** The privileged-tap and
  warm-restore paths had "tests," but every run died early (netns permission, vsock reconnect) and the
  failure was invisible — so a *chain* of latent bugs sat undiscovered until someone forced the path to
  execute end-to-end. Several "required integration assertions" passed on their own inverse.

So this rubric is written to be *enforced*, not just *consulted*. **Three** governing rules:

1. **If a checklist item below reaches human review, the gate that should have caught it is missing.**
   File the missing gate (Part D), don't just fix the instance.
2. **The one question that matters for every test: "Write the buggy implementation. Does this test go
   red?"** If the answer is no, the test is theater — one of the green-but-blind tests that let every
   other bug survive.
3. **(New, from review 34) A test that CI never *executes* is not a test, and a config CI never *builds*
   is not covered.** "Green" must mean *the path actually ran on a capable runner* (not skipped, not
   filtered to zero, not behind an `--ignored` job nobody runs) and *the non-default build configs
   actually compiled*. Skip-with-reason is fine; skip-as-pass and build-as-`--all-features`-only are not.

### Enforcement legend

`lint` compiler/clippy deny (fails the build) · `CI` a CI job · `test` a test that must fail on the
buggy impl · `review` human/agent judgment, no mechanical gate yet. **(new in v2)** entries marked
**[34]** were added or sharpened after review 34.

---

## Part A — Cross-cutting principles

The generative rules. Most specific checks in Part B are corollaries; when a new situation isn't
covered, reason from these.

1. **Fail loud, typed, and early.** No swallowed `Result` (`let _ =` without a justifying comment), no
   `Ok(())` on a failure or unsupported branch, no panics on any path a guest or the network can drive.
   An error must be *visible* (surfaced or logged), *typed* (matchable, not `Error::Other(String)`), and
   *prompt* (checked before a long timeout masks it).

2. **Best-effort is the rare, *declared* exception — silent degradation is the default bug. [34]** A
   *requested functional* operation that cannot be performed because a capability is missing must return
   a **typed error** (`Error::CapabilityUnavailable { op, needed }` or equivalent), not a logged-and-
   ignored no-op that returns `Ok` (a cgroup limit that silently doesn't apply, a bounding-set drop that
   silently no-ops). Three categories, and a review must place every host-facing op in one: *functional*
   (must fail loud) · *observational* — a read — (may degrade, but must surface what was unavailable via
   an explicit flag, e.g. `limits_enforced`) · *explicitly-listed best-effort* — a non-functional knob
   like a benchmark's CPU-freq pin (may no-op, but with a **visible** `warn!`, never silent). The test:
   *if a caller's assertion can be wrong because the op silently did nothing, it is functional.*

3. **Capabilities are declared, probed, and reported — for the host as well as the backend. [34]** Just
   as a backend reports `VmmCapabilities` so callers never invoke an unsupported op, the host environment
   is probed (`HostCapabilities`: caps held — the *effective* set, not permitted — controllers delegated,
   group access, namespace-dir writability) and the operating mode is *selected from what the host
   offers*, failing loud up front when a requested mode's prerequisites are absent — never discovered
   half-way through a run.

4. **Ownership owns cleanup — including on a *post-acquire failure*, not just on panic. [34]** Every
   acquired host resource (VMM process *group*, virtiofsd, netns, cgroup, overlay, sockets, CID, VMID,
   threads/runtimes) is released by `Drop`, in reverse dependency order, and that path runs on panic.
   **And** a resource acquired before a later fallible step must be owned by an RAII guard *before* that
   step runs — the classic leak is "spawn the VMM, then `add_task()?`/`wait_for_socket()?` *before*
   building the instance whose `Drop` reaps it," so the `?` leaks a live VMM. `shutdown()` getting the
   order right does not count — the panic and early-return paths are `Drop`/guards.

5. **Contracts self-guard.** A method whose correctness depends on "the caller checked `capabilities()`
   first" is a latent bug. Check the precondition *inside* and return `Error::Unsupported`. The same
   applies to config: validate in `build()`, don't trust the call site. **A law must be enforced at
   *every* boundary it can be violated at, not the first one. [34]** (The snapshot-eligibility law was
   guarded for a virtio-fs *rootfs* but not a *data share*, so the share slipped past `build()`, past
   `orchestrator::restore()`, and the backend then attached the forbidden vhost-user device.)

6. **Validate at the boundary; return, don't assert.** Library code reachable from a test or API takes
   untrusted-shaped input. Out-of-range values return `Err`; `assert!`/`panic!` on an input path takes
   down the whole runner. **Symmetric paths get symmetric handling [34]:** if one direction of a
   guest-driven loop (a virtqueue TX) handles an error gracefully, the mirror direction (RX) must too —
   an `.expect()` on a guest-controlled descriptor index is a guest-drivable panic.

7. **Determinism is tested, not assumed.** Anything that feeds a cache key or claims reproducibility
   (`cache_key`, pins, built images) must have a test pinning a golden value and asserting it is
   identical across processes/checkouts. "It hashes the inputs" is not enough if the inputs are absolute
   paths, **hashed in `HashMap` iteration order [34]**, missing a stage version, or exercised only by a
   trivial constant stage.

8. **Verify everything you ingest.** The project's provenance discipline (pinned digests, signing
   chains) is a property of *bytes on the wire*, not just crate licenses. Every downloaded artifact is
   checked against a pinned hash before use; pulls are digest-pinned, not tag-pinned; the verification
   failure is a hard stop. **Treat any externally-supplied (incl. LLM-supplied) hash/digest as
   unverified until checked against the upstream signed source [34]** — a wrong pinned SHA must be
   *rejected by the pipeline*, and a stale cached intermediate must *invalidate (verify-or-purge)*, not
   error.

9. **A seam you can't fake is a unit you can't test.** No module-global mutable state for IDs, time, or
   I/O. Side effects go behind small injectable traits with a real impl and a recording fake. The
   absence of the fake is the *direct cause* of a bug being review-only. **And the fake must be
   *driven*, not merely *exist* [34]** — a `FakeVmm`/`FakeClock`/recording fake that the code path under
   test never consults is dead, and any assertion "guarded" by it is theater (§Part C).

---

## Part B — Review checklist

### B1 · Resource lifecycle & teardown  *(Critical in every pass)*

- [ ] `TestVm::Drop` performs the full ordered teardown: **VMM process group → virtiofsd →
      netns / cgroup / overlay / sockets**, and is exercised by a panic-residue test that asserts the
      **full order** (recording fakes), not merely that *a* drop happened. `review` `test`
- [ ] Process teardown uses a **group kill that waits** (`kill -9 -<pgid>`, pgid cached at spawn, then
      reap), not `start_kill()` (leader-only, non-blocking) and not `Child::id()` after the child has
      been awaited elsewhere (it returns `None`, so `kill(-pid)` no-ops) — otherwise `ip netns exec`
      wrappers, child VMMs, and zombies survive. Applies to all three backends. `review`
- [ ] `Drop` releases **both** CID and VMID back to their allocators (not just VMID). `review`
- [ ] **A resource acquired before a later fallible step is owned by a guard before that step. [34]**
      Spawn-then-`add_task()?`/`wait_for_socket()?` reaps the VMM on the `?` (a shared
      `reap_process_group` helper); CID/VMID/netns/**cgroup** all have RAII guards (the cgroup slice
      had none — a construction-failure leak). `review` `test`
- [ ] Spawned-forever workers (smoltcp NAT, egress proxy, tokio runtimes) hold a shutdown signal and a
      `JoinHandle`; `Drop` signals and the worker joins **within a timeout** (an unbounded join hangs
      teardown forever). Transient/probe resources (the Firecracker T2-probe microVM + its socket) are
      reaped too, not left to a non-reaping `Drop`. `test`
- [ ] `request_shutdown()` is not immediately followed by an unconditional `kill()` — wait for exit
      (bounded) before the SIGKILL fallback, or the guest never flushes. `review`
- [ ] A **periodic sweeper + orphan registry** reaps anything a hard crash left behind (leaked
      `/var/run/netns/imp-net-*` collide with later vmids), and the lifecycle test asserts against the
      registry. A one-shot reaper invoked by a test is a start, not the sweeper. `review` `test`
- [ ] **Guest/network-driven *in-flight* state is bounded and reclaimed. [34]** The smoltcp per-port
      socket/port-map pool (~512 KiB per distinct dst port) and the PID-1 reaper status map must not grow
      host memory without bound — cap the pool, reclaim idle/closed mappings, prune the status map. A
      flood of distinct destination ports is a guest-drivable memory DoS otherwise (review NET-5); assert
      the pool stays capped after N distinct ports. `test`

### B2 · Failure visibility

- [ ] No `.unwrap()` in non-test code. `.expect("invariant: …")` is the only escape hatch and is
      **not** permitted on remotely/guest-driven hot paths (smoltcp packet loop, **both TX *and* RX**
      vring ops [34], PID-1 exec, proxy) — those degrade gracefully (log + continue/close). `lint` `review`
- [ ] PID-1 (`imp-guest-agent`) does not `.expect`/panic on a **recoverable** condition; a panic here
      kernel-panics the guest. Recoverable = logged-and-skipped (a missing optional virtio-fs share
      tag; a loopback ioctl failure); only the genuinely-unrecoverable core mounts (overlay/`/proc`/
      `/dev`) are fatal. The reaper must not steal the exec'd child's exit status (false `127`). `review`
- [ ] No `Ok(())` (or printed-success) on a branch that failed or is unsupported: QEMU
      `boot()/resume()/pause()` swallowing a QMP `{"error":…}`; `snapshot()` resuming-and-returning-Ok
      on a failed snapshot; a **CLI subcommand that prints success while doing nothing [34]**; stubs
      (`put_file`, `reset_to`) returning `Ok(())`. A not-yet-implemented op returns a typed error +
      non-zero exit. `review`
- [ ] Every `let _ = result;` carries a comment justifying why the error is safe to drop. Default
      stance: surface it, or at minimum `tracing::warn!`. `review`
- [ ] Error **detection** logic is correct, not inverted or loose: a probe treating *any* error as
      success (FC T2), a domain filter using bare `ends_with` (over-blocks siblings — match label
      boundaries), an HTTP parse matching only `200`. `test`
- [ ] Polling/readiness loops fail fast and legibly: check `process.try_wait()` so an immediately-dead
      VMM reports the real cause; on timeout return an error with context (read stderr/serial), never
      silently fall through to "success". `review`
- [ ] **A *requested* capability-dependent op fails loud; it does not silently no-op. [34]** A cgroup
      limit on an undelegated controller, a bounding-set drop without `CAP_SETPCAP`, an in-process FUSE
      RO not enforced — each is `CapabilityUnavailable` (or a surfaced flag for *reads*), not a
      swallowed error. Benchmark-only knobs (`cpufreq`, KSM) are the listed best-effort exception and
      `warn!` *visibly*. `review` `test`
- [ ] Logging goes through `tracing` at the right level — no `println!`/`eprintln!` in production code;
      no normal startup logged at `error!`. `lint`
- [ ] Mutex poisoning is handled deliberately (`parking_lot`, or `into_inner()` *with* a comment that
      recovering the state is sound), not by `.lock().unwrap()` cascades. `review`

### B3 · Capability & input contracts

- [ ] A typed `Error::Unsupported { vmm, feature }` exists and is returned for every capability gap —
      never a panic, never a stringly `Error::Vmm("…does not support…")`. Advertised capabilities are
      **live, not dead flags [34]**: `lazy_restore: true` with no `prefault` plumbing is a lie the
      "no dead protocol/feature variants" rule forbids. `lint` `review`
- [ ] `restore()` and `snapshot()` **self-guard** on `capabilities().snapshot_restore` *and* on the
      absence of any vhost-user device, returning `Err(Unsupported)` rather than running the migrate
      sequence and trusting callers. `test`
- [ ] `create()` rejects configs the backend can't honor instead of silently building a broken VM
      (Firecracker given a vhost-user socket → error, not boot netless). `test`
- [ ] **Snapshot-eligibility law is enforced in code at *every* boundary, for *every* vhost-user
      device. [34]** A snapshot-eligible VM has *no* vhost-user device — virtio-fs **rootfs**, virtio-fs
      **data share** (not just the rootfs!), `NetConfig::Unprivileged` (vhost-user-net), or an external
      vhost-user-vsock. Rejected at `config::build()`, re-checked at `orchestrator::restore()`, and
      self-guarded in the backend `restore()`/`snapshot()` — **with a negative test at each boundary.**
      `restore()` taking `&VmConfig` is to reconstruct the *non-vhost-user* topology only; it must not
      attach virtiofsd on that path. `test`
- [ ] `VmConfigBuilder::build()` returns `Result` and rejects, **with a negative test for each [34]**:
      duplicate share tags; snapshotting + {virtio-fs rootfs, **any data share**, unprivileged net};
      `vcpus == 0`; `mem_mib` below floor; empty kernel path; out-of-range vmid. `#[must_use]` on builder
      methods. `test`
- [ ] Out-of-range values (vmid past the address-scheme ceiling) return `Err` at a validation boundary —
      not `assert!` inside `create()`. `review`

### B4 · Determinism, caching & provenance

- [ ] Cache keys use a **stable** hasher (`blake3`/`sha2`), never `DefaultHasher`. `review`
- [ ] Cache-key inputs are hashed in a **deterministic order** (sorted / `BTreeMap`), **never `HashMap`
      iteration order [34]** (which varies across processes → spurious cache miss → forced expensive
      rebuild). `test`
- [ ] Cache keys hash **content and identity that travel**, not absolute `PathBuf`s under `target/`
      (two checkouts must agree), embed a **stage version**, the pinned source **SHA**, and the content
      of *every* upstream input that affects the output — e.g. `guest_agent_src_hash` and the
      guest-tools content fold into the **rootfs** key (a stale agent baked into the rootfs is the
      tell). `test`
- [ ] Cache validity is **content-addressed**, not existence-based: a tampered artifact with an intact
      `.cache_key` sidecar is rejected (re-hash on every use, including a **cached OCI blob on the
      cache-hit path [34]**, not only on first fetch). `test`
- [ ] **A stale intermediate invalidates (verify-or-purge), and a stale artifact is never silently
      booted. [34]** A cached kernel tarball whose hash ≠ the pin purges and re-fetches (not errors);
      the harness fails loud (or auto-builds) when an artifact is older than the sources it depends on. `test`
- [ ] Every downloaded artifact (kernel tarball, OCI blobs, builder base) is verified against its pinned
      hash before use; mismatch is a hard stop. Image pulls are **digest-pinned**; a tag fallback is an
      error. mmdebstrap enforces apt gpg + a `snapshot.debian.org` timestamp pin. `test` `review`
- [ ] Decode paths are complete: OCI gzip **and** zstd (a zstd layer must not yield an empty rootfs);
      device-node `rdev` uses `makedev`, not `(major<<8)|minor`. `review`
- [ ] Security-sensitive files: the MITM CA is generated once and the parsed authority cached (no
      re-self-signing per `authority()` call — but note `hudsucker` reconstructing a `Certificate` from
      the *same* loaded params/key is the cache-once pattern, **not** the re-sign bug), written
      atomically, `0600`, and **from the one artifacts dir the rootfs CA was baked from [34]** (a
      per-pid `/tmp` CA that doesn't match the baked-in CA breaks the guest trust chain). `review`

### B5 · Pipeline staging

- [ ] Stage 0 isolates all non-determinism. Either it **live-resolves pins** (tag→digest, snapshot
      timestamp) into a lock, **or** the committed `pins.json`/`pins.lock` *is* the lock and Stage 0
      loads-and-propagates it through `StageOutputs` — **honestly documented as which [34]**; a
      `ResolvePinsStage` that neither resolves nor is documented as a lock is a stage that silently does
      nothing. `review`
- [ ] `StageInputs`/`StageOutputs` actually carry data; downstream stages consume upstream outputs (no
      empty structs, no reading paths from `IMP_KERNEL`/`IMP_ROOTFS` env vars). `test`
- [ ] A stage's declared inputs cover *everything* that affects its output (the guest-agent binary and
      the guest-tools helper are cached inputs with their own content in the rootfs key, not a
      `cargo build` side effect the key ignores). `review`
- [ ] Output paths are declared by each `Stage`, not synthesized by the pipeline from hardcoded
      `if name == "kernel"` matches; `Pipeline::build` returns artifact locations, not an empty
      `Artifacts {}`. An artifact registered only on the warm path is lost on a cold build. `review`
- [ ] The snapshot stage boots the **erofs** rootfs, not a hardcoded `RootfsSource::Block`. `review`
- [ ] `reset_to(stage)` removes that stage's and all later outputs and **errors on an unknown stage
      name**; a test asserts `reset_to(rootfs)` rebuilds rootfs+snapshot but not the kernel. `test`
- [ ] No `/tmp/vmlinux`-style fallback paths masking a missing upstream — a missing dependency is an
      error; artifacts live under one resolved dir (`artifacts_dir()`), not three divergent defaults. `review`
- [ ] Record/replay seam (requirement 7) splits network access into record and replay for **every**
      fetch path — including an **injectable OCI pull seam** so OCI record/replay + tamper tests can run
      (a hardcoded `oci_client::Client` can't be faked). `review`

### B6 · Concurrency & injected state

- [ ] IDs and time come from **injected allocators** (`CidAllocator`, vmid allocator, `Clock`,
      `CgroupFs`, `CpuFreqSysfs`) — never module-global `static AtomicU32`/`Mutex`/`OnceLock`/`Lazy`. A
      "wrapper around a global static" (`CPU_TEMPLATE`, `CA_CACHE`) that pretends to be injectable is the
      same bug. `CI`(grep) `review`
- [ ] `release()` operates on the *actual* allocator instance, not a freshly-created one; allocators
      track the in-use set, skip reserved CIDs (0/1/2), and wrap without colliding with live/reserved
      IDs. **CID reuse on a *sequential* restore is by design** — the uniqueness contract is over *live*
      clones, so assert "valid live CID," not `assert_ne!(old, new)`. [34] `test`
- [ ] VMID→octet mapping (`(vmid % 254) + 1`) is applied at **every** use site, consistently;
      centralize the `/30` host-IP math in one unit-tested helper. **The host NAT MAC is pinned outside
      the `mac_math(vmid)` range [34]** (the v12 pin collided at vmid 254) — assert no `mac_math(1..=254)`
      equals it. Allocator unit tests stay **hermetic** (a cross-process `/tmp` lock file must not make
      two `new()` instances collide globally). `test`
- [ ] Side-effecting subsystems sit behind injectable traits — `Netlink`, `NftApplier`, `CgroupFs`,
      `SerialLog`, `Clock` — each with a recording fake that **carries assertions** (the rendered
      ruleset / netlink order / limit-file contents), not a fake that exists and asserts nothing. `review` `test`

### B7 · Module boundaries & duplication

- [ ] Logic that exists in three copies is extracted: the cgroup `stats()` reader, the spawn/`netns
      exec`/readiness boilerplate, the HTTP-over-Unix client, **and a shared QMP/JSON-`error` parser
      [34]** are each one helper across CH/FC/QEMU — duplication is where per-backend divergence bugs
      (cgroup escape logged for CH but silent for QEMU) live. `review`
- [ ] No hand-rolled HTTP: a real client parses status codes numerically and loops the read — not a
      single 4096-byte read matched by `starts_with("HTTP/1.1 200")`. `review`
- [ ] Module responsibilities match the design: cgroup creation/reading/limits live in `metrics.rs`
      behind `CgroupFs`, not scattered across the orchestrator and a backend. `review`
- [ ] Test-only logic is not baked into production handlers (no hardcoded `example.net` block — use the
      configurable deny list, which records blocked requests). `review`

### B8 · Public-API hygiene

- [ ] `#[non_exhaustive]` on every public struct/enum likely to grow (configs, requests/outcomes,
      stages, `Error`, `NetConfig`, `RestoreMode`). `cargo semver-checks` catches the resulting break. `CI` `review`
- [ ] `#[must_use]` on constructors and builder methods returning `Self`. `review`
- [ ] `Error` has per-subsystem variants with typed sources and `#[from]` (not `String` payloads and
      `Error::Other`); unused typed variants are wired up or removed. **A `#[from]` variant for a
      feature-gated dep is itself `#[cfg]`-gated [34]** (an un-gated `Hyper(#[from] hyper::Error)` breaks
      the lean `agent`/`test-runner` builds). `review` `CI`
- [ ] No **always-zero / never-read public fields [34]** — `ResourceUsage`'s io/net counters left at 0
      are the same lie as a missing field: populate them or delete them. `review`
- [ ] Every public item is documented (`#![deny(missing_docs)]`); `Result`-fns have `# Errors`,
      panicking fns `# Panics` (and a doc must not claim a panic that cannot occur), `unsafe` blocks a
      real `// SAFETY:`. `lint` `review`
- [ ] Per-module `#![forbid(unsafe_code)]` on the I/O-free modules (`config`, `agent::protocol`,
      `artifact` cache_key, `net` /30 math); the one genuinely-needed ioctl spot lives in a separate
      module (`net_sys`) so `net` stays forbid-unsafe. `lint`
- [ ] No leaked internals (`pub` on `Pipeline.stages`, backend instance fields). `review`
- [ ] Dead code removed or justified: unreachable protocol variants (`Hello`, no-op `Ping`), `restored`
      fields never read, a **dead second setuid block [34]** obscuring the real privilege-drop ordering. `review`

### B9 · The privileged window  *(new in v2 — `imp-test-runner`, `imp-guest-agent`)* [34]

Every dependency and instruction here executes with elevated capability; the review is stricter.

- [ ] The runner checks the **effective** capability set (not permitted), and the blessing message it
      prints matches — `setcap … +ep`, **not** `+p` (a `+p`-only blessing leaves caps un-raised and the
      check still fails, so the printed remediation is unfollowable). `review`
- [ ] Privilege-drop ordering is correct and singular: drop the **bounding** set (needs `CAP_SETPCAP`
      raised *first*, else it silently no-ops — surface the failure or document best-effort) **before**
      raising **ambient**; for the setuid form, change uid *before* raising ambient; trim `P`/`E` after.
      One drop path — no dead second block. `review`
- [ ] The runner is **dependency-thin** (`rustix`+`capctl` only) and inits **no tracing/logging stack at
      full privilege**; the build that blesses it passes `--features test-runner` (blessing the wrong
      binary is a silent no-op). `review` `CI`
- [ ] The runner's standing capability set is **exactly what the suites need and no more** — currently
      `CAP_NET_ADMIN`+`CAP_SYS_ADMIN`+`CAP_DAC_OVERRIDE` (the third for `/var/run/netns` creation and
      kernfs knob writes); KVM is the `kvm` *group*, not a capability. `review`
- [ ] CA hygiene and virtiofsd sandboxing per B4/§design: generate-once cached authority, atomic
      `0600`, per-run-scoped; virtiofsd `--sandbox namespace` + dedicated uid, `--readonly` enforced for
      RO shares (not mounted rw with a warning). `review`

---

## Part C — Tests that actually test  *(the meta-rubric; this is why the rest recurred)*

Every test must be able to **fail**. Before accepting a test, construct the buggy implementation it
nominally guards and confirm the test goes red. **And confirm CI actually *runs* it (Part D) — an
`#[ignore]`d path no job exercises, or a filter that selects zero tests, is the same as no test. [34]**

**Test smells — reject on sight:**

- [ ] **Skip == pass, at *test* and *recipe* level. [34]** A test that `return`s green when KVM/artifacts
      are absent; **and** a recipe whose nextest filter matches no test name and exits "0 tests run"
      (the unprivileged suite ran *nothing* for a release because `test(rootless)` matched no test).
      Skip *visibly* (skip-with-reason); a zero-selection filter is a CI **failure**, not a pass.
- [ ] **Asserts nothing.** Discards the result, `println!`s instead of asserting, or has the assertion
      commented out. A prop test that computes-and-drops asserts nothing. A `bench`-coverage test whose
      assertion is commented out is theater.
- [ ] **Dead fake / wrong target / self-fulfilling. [34]** The injected fake is never consulted on the
      path under test (a `FakeClock` read only on a later call where `restored==false`, so the
      clock-resync assertion can never hold); the assertion targets a path the code never uses (a
      panic-residue check on `/sys/fs/cgroup/imp-vm-{vmid}` when the real slice is nested under the
      delegated parent); the order is asserted by `.contains("drop")` / a count instead of a sequence;
      or the test *performs the behavior itself* then asserts a trivial outcome (runs its own RNG reseed
      and asserts `code==0`, so deleting the orchestrator's reseed leaves it green). Assert the actual
      rotate/reseed/resync, driven through the code under test.
- [ ] **Loose "or" assertions.** OOM accepting `137 || 1 || -1` (code 1 is generic failure); **a guest-RAM
      OOM masquerading as a `memory.max` OOM [34]** (guest RAM ≤ the cap → the guest's own OOM gives 137
      regardless of the cgroup cap, so the cap can be deleted and the test stays green — set guest RAM
      *above* the cap and assert a cgroup `memory.events oom_kill > 0`); block-detection on "stdout
      contains 403". Assert the *specific* signal.
- [ ] **Coincidental pass.** Two `/dev/urandom` reads differing (true without reseeding); the clock
      advancing after a host sleep (true on a plain resume). Isolate the actual behavior.
- [ ] **Tests the opposite of its name.** A `tampered_digest_aborts` test that corrupts the `.cache_key`
      sidecar and asserts a *rebuild* (corrupt the *artifact bytes*, sidecar intact, and assert abort).
- [ ] **Mock where round-trip is required.** `put_file` asserting bytes reached a UDS mock instead of
      reading the file back *in the guest*. (A pure codec/handshake mock is fine *as such* — classify it
      honestly; it does not stand in for the round-trip.)
- [ ] **String stand-ins for real artifacts.** Path-injectivity comparing `format!("imp-vm-{vmid}")`
      strings instead of real socket paths, never varying `pid`; `/30` math doing `ends_with(".2/30")`
      instead of asserting octets and rejecting overflow at vmid ∈ {0,1,254,255}.
- [ ] **Determinism tested only via a trivial stage. [34]** A `DummyStage` with a constant key cannot
      catch the real `RootfsStage`/`SnapshotStage` cache-key bugs (HashMap order, path-hashing, missing
      stage version) — exercise a **real** stage with a golden cross-process key, and add an end-to-end
      "changing the guest-agent source re-bakes the rootfs" test.

**Positive requirements:**

- [ ] Serial execution comes from the `nextest` `serial-host` group, not ad-hoc `#[serial_test::serial]`.
      `#[ignore]` is only for genuine KVM/privilege needs; pure mock/codec tests run in the default suite.
- [ ] The integration suite is split into the **two named operating modes [34]** — an **unprivileged**
      suite (KVM-group, no caps) and a **privileged** suite (the runner's three caps) — each invoked
      separately, each with its prerequisites as a **visible hard precondition** (skip-with-reason on a
      missing cap / undelegated controller, never skip-as-pass). The privileged suite needs a
      non-threaded `domain` cgroup scope and a delegated leaf for limit tests.
- [ ] The `FakeVmm` is a **recording** fake that is actually **driven**: a backend-agnostic test
      exercises allocation order, retry/timeout, restore-vs-cold-boot selection, and ordered teardown
      with no KVM. "Exists but unused" is the recurring failure.
- [ ] Injected fakes carry assertions: the `Netlink` fake records **zero** calls (zero-netlink-in-PID-1,
      at boot *and* on restore — the restore path does **not** re-run `ip addr` in the guest; only a
      device-layer MAC `ioctl` is allowed); the `CgroupFs` fake asserts exact limit-file contents and
      that a requested limit on an undelegated controller fails loud.
- [ ] The per-VMM matrix consults `capabilities()` and emits **skip-with-reason** for unsupported
      scenarios — and the CH/primary path is *not* exempted (a CH regression hard-fails, only a truly
      unsupported case skips).
- [ ] Required integration assertions are present and specific: snapshot reconnect (incl. the guest
      **re-bind** + host-path rewrite, not just "restore succeeds") + rotate (live CID, in-guest MAC) +
      reseed + resync (FakeClock driven on the *first* post-restore call); HTTPS interception logged +
      `CONNECT` falls through + filter-block observed **and recorded** + intended-destination observed;
      ordered-Drop-on-panic zero residue (computed paths, all resource classes); N-VM concurrency with
      distinct CID/VMID/socket paths; the build-pipeline tamper/cache-hit/determinism trio on **real**
      stages; the zero-netlink assertion.
- [ ] No dead scratch tests in `src/` that are never compiled (`mod` not declared).

---

## Part D — Required automated gates (the infrastructure that makes B & C real)

The reviews show review-alone fails. Each item turns a defect *family* into a build failure. **If a
Part B/C item reached a human, the matching gate here is missing — add it.**

**Crate-root lints** (`lib.rs`):

```rust
#![deny(missing_docs, unsafe_op_in_unsafe_fn, rustdoc::broken_intra_doc_links)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::missing_safety_doc,
        clippy::missing_errors_doc, clippy::missing_panics_doc)]
#![cfg_attr(not(test), deny(
    clippy::unwrap_used, clippy::panic, clippy::unreachable,
    clippy::todo, clippy::unimplemented,        // no silent Ok(()) stubs either — see B2
    clippy::indexing_slicing,                   // forces bounded reads (.get())
    clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro,
))]
```
Plus per-module `#![forbid(unsafe_code)]` on the I/O-free modules.

**CI jobs** (all required; **`-D warnings` must be set the same way locally and in CI [34]** — a local
`just ci` weaker than CI means "green locally" doesn't mean "green in CI"):

| Gate | Catches |
|---|---|
| `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` | the lint families; format drift |
| **Build *and* clippy each build target [34]** — `host` (default), and `--no-default-features --features {agent,test-runner,guest-tools}` | a `#[from]`/re-export not `#[cfg]`-gated breaking a non-default config; a lean binary that fails to compile. **This replaces the feature powerset** once the feature matrix is collapsed to one host feature + the lean targets; the powerset never exercised real partial-*host* combos and stayed red on debt. A `cargo tree`-only check is **insufficient** — it never builds the target (how the broken agent build slipped past). |
| Lean-target tree assertion — `cargo tree -e no-dev --no-default-features --features agent` (and `test-runner`, `guest-tools`) ∌ `tokio`/`hyper`/`rtnetlink` | the privileged-window/guest binaries re-coupling to the host stack — *in addition to* building them |
| `cargo deny check` (allow-only licenses + advisories + sources); **each `ignore` carries a real per-crate rationale [34]** (no bulk-suppression, no duplicate or stale-but-unremoved entries) | GPL/unvetted crates; advisories silently defeated |
| `cargo semver-checks` | the `#[non_exhaustive]`-omission breakage |
| `cargo nextest run` with a **per-test timeout** | a hang (virtiofsd socket-wait, `cgroup` write) becoming a stuck job instead of a failure |
| **The `--ignored` integration matrix on a KVM runner — and it must select > 0 tests [34]** | the entire suite being CI-invisible (skip==pass); a filter matching no test name exiting "0 tests run" as a pass; the privileged/restore paths never actually executing |
| grep banning new module-global mutable state — `static …: Atomic…`/`static mut`/**`OnceLock`/`OnceCell`/`Lazy`/`Mutex` module-globals [34]** outside the allocator module (per-line allow comments, not blanket file exemptions) | re-introduction of un-fakeable global state (B6) |

---

## One-line summary

Make every recurring defect class fail a **lint, a CI job, or a test that can actually go red** — and
treat any item that reaches human review as evidence a gate is missing. The highest-leverage targets,
Critical across the passes, are **ordered teardown that runs on panic *and post-acquire failure*** (B1),
**fail-loud on a missing capability** (A2/B2), and **tests that can fail *and that CI actually runs***
(Part C + the build-every-target / select->0-is-failure gates in Part D).
