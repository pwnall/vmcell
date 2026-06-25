# Imp Testing — Code Review Rubric

*Distilled from four implementation/review passes (reviews 13, 17, 26, 27) against the
v6 → v11p1 design. Its job is to stop the **classes** of defect those reviews found from
recurring — not to re-list individual findings.*

## Why this exists

The same defect families showed up in all four passes even as the design tightened. The
reviews diagnosed the cause precisely: **the test/lint/CI layer had no automated opinion on
any of them**, so the as-built suite passed green and a human reviewer was the only thing
standing between the bug and `main`. A human reviewer is fallible four times running.

So this rubric is written to be *enforced*, not just *consulted*. Two governing rules:

1. **If a checklist item below reaches human review, the gate that should have caught it is
   missing.** File the missing gate (Part D), don't just fix the instance.
2. **The one question that matters for every test: "Write the buggy implementation. Does this
   test go red?"** If the answer is no, the test is theater — it is one of the green-but-blind
   tests that let every other bug survive.

### Enforcement legend

`lint` compiler/clippy deny (fails the build) · `CI` a CI job · `test` a test that must fail
on the buggy impl · `review` human/agent judgment, no mechanical gate yet.

---

## Part A — Cross-cutting principles

The generative rules. Most specific checks in Part B are corollaries; when a new situation
isn't covered, reason from these.

1. **Fail loud, typed, and early.** No swallowed `Result` (`let _ =` without a justifying
   comment), no `Ok(())` on a failure or unsupported branch, no panics on any path a guest or
   the network can drive. An error must be *visible* (surfaced or logged), *typed* (matchable,
   not `Error::Other(String)`), and *prompt* (checked before a long timeout masks it).

2. **Ownership owns cleanup.** Every acquired host resource (VMM process *group*, virtiofsd,
   netns, cgroup, overlay, sockets, CID, VMID, threads/runtimes) is released by `Drop`, in
   reverse dependency order, **and that path runs on panic**. `shutdown()` getting the order
   right does not count — the panic path is `Drop`.

3. **Contracts self-guard.** A method whose correctness depends on "the caller checked
   `capabilities()` first" is a latent bug. Check the precondition *inside* and return
   `Error::Unsupported`. The same applies to config: validate in `build()`, don't trust the
   call site.

4. **Validate at the boundary; return, don't assert.** Library code reachable from a test or
   API takes untrusted-shaped input. Out-of-range values return `Err`; `assert!`/`panic!` on an
   input path takes down the whole runner.

5. **Determinism is tested, not assumed.** Anything that feeds a cache key or claims
   reproducibility (`cache_key`, pins, built images) must have a test pinning a golden value and
   asserting it is identical across processes/checkouts. "It hashes the inputs" is not enough if
   the inputs are absolute paths or the hasher isn't stable.

6. **Verify everything you ingest.** The project's provenance discipline (pinned digests,
   signing chains) is a property of *bytes on the wire*, not just crate licenses. Every
   downloaded artifact is checked against a pinned hash before use; pulls are digest-pinned, not
   tag-pinned; the verification failure is a hard stop.

7. **A seam you can't fake is a unit you can't test.** No module-global mutable state for IDs,
   time, or I/O. Side effects go behind small injectable traits with a real impl and a recording
   fake. The absence of the fake is the *direct cause* of a bug being review-only.

---

## Part B — Review checklist

### B1 · Resource lifecycle & teardown  *(Critical in every pass)*

- [ ] `TestVm::Drop` performs the full ordered teardown: **VMM process group → virtiofsd →
      netns / cgroup / overlay / sockets**, and is exercised by a panic-residue test. `review` `test`
- [ ] Process teardown uses a **group kill that waits** (`kill -9 -<pgid>` then reap), not
      `start_kill()` (leader-only, non-blocking) — otherwise `ip netns exec` wrappers, child
      VMMs, and zombies survive. Applies to all three backends. `review`
- [ ] `Drop` releases **both** CID and VMID back to their allocators (not just VMID). Pool
      exhaustion over a long run is the tell. `review`
- [ ] Spawned-forever workers (smoltcp NAT, egress proxy, tokio runtimes) hold a shutdown
      signal and a `JoinHandle`; `Drop` signals and the worker joins within a timeout. `test`
- [ ] `request_shutdown()` is not immediately followed by an unconditional `kill()` — wait for
      exit (bounded) before the SIGKILL fallback, or the guest never flushes. `review`
- [ ] Transient/probe resources are cleaned up: the Firecracker T2-probe socket is removed and
      the probe microVM is reaped, not left to a non-reaping `Drop`. `review`
- [ ] A **periodic sweeper + orphan registry** reaps anything a hard crash left behind, and the
      lifecycle test asserts against the registry. `review` `test`

### B2 · Failure visibility

- [ ] No `.unwrap()` in non-test code. `.expect("invariant: …")` is the only escape hatch and is
      **not** permitted on remotely/guest-driven hot paths (smoltcp packet loop, vring ops, PID-1
      exec, proxy) — those degrade gracefully (log + continue/close). `lint` `review`
- [ ] PID-1 (`imp-guest-agent`) does not `.expect`/panic on recoverable conditions; a panic here
      kernel-panics the guest. Boot-time self-check probes vsock/virtio-fs and emits a clear
      diagnostic *before* binding. `review`
- [ ] No `Ok(())` returned on a branch that failed or is unsupported: QEMU `boot()` swallowing
      `cont`; `snapshot()` resuming-and-returning-Ok when the snapshot call failed; netns-open
      failure binding the default namespace; stubs (`put_file`, `reset_to`) returning `Ok(())`. `review`
- [ ] Every `let _ = result;` carries a comment justifying why the error is safe to drop. Default
      stance: surface it, or at minimum `tracing::warn!`. `review`
- [ ] Error **detection** logic is correct, not inverted or loose: a probe that treats *any*
      error as success (FC T2) and a domain filter using bare `ends_with` (blocks sibling domains)
      are both this class. `test`
- [ ] Polling/readiness loops fail fast and legibly: check `process.try_wait()` so an
      immediately-dead VMM reports the real cause, and on timeout return an error with context
      (read stderr), never silently fall through to "success". `review`
- [ ] Logging goes through `tracing` at the right level — no `println!`/`eprintln!` in
      production code; no normal startup logged at `error!`. `lint`
- [ ] Mutex poisoning is handled deliberately (`parking_lot`, or `into_inner()` *with* a comment
      that recovering the state is sound), not by `.lock().unwrap()` cascades. `review`

### B3 · Capability & input contracts

- [ ] A typed `Error::Unsupported { vmm, feature }` exists and is returned for every capability
      gap — never a panic, never a stringly-typed `Error::Vmm("…does not support…")`. `lint` `review`
- [ ] `restore()` and `snapshot()` **self-guard** on `capabilities().snapshot_restore` and
      return `Err(Unsupported)` when false, rather than running the migrate sequence and trusting
      callers. `test`
- [ ] `create()` rejects configs the backend can't honor instead of silently building a broken
      VM (e.g. Firecracker given a rootless vhost-user socket → must error, not boot netless). `test`
- [ ] **Snapshot-eligibility law is enforced in code, not just docs:** a snapshot-eligible VM
      has *no* vhost-user device attached. `restore()` rejects `NetConfig::Rootless` and a
      virtio-fs *rootfs*; the snapshot tier does not attach virtiofsd. `test`
- [ ] `VmConfigBuilder::build()` returns `Result` and rejects: duplicate share tags,
      virtio-fs-rootfs + snapshot, `vcpus == 0`, `mem_mib == 0`/below floor, empty kernel path,
      out-of-range vmid. Negative tests exist for each. `test`
- [ ] Out-of-range values (vmid past the address-scheme ceiling) return `Err` at a validation
      boundary — not `assert!` inside `create()`. `review`

### B4 · Determinism, caching & provenance

- [ ] Cache keys use a **stable** hasher (`blake3`/`sha2`), never `DefaultHasher` (not portable
      across Rust versions). `review`
- [ ] Cache keys hash **content and identity that travel**, not absolute `PathBuf`s under
      `target_dir` (two checkouts must agree), and they embed a **stage version** and the pinned
      source **SHA** (re-pointing a pin at new bytes must invalidate). `test`
- [ ] Cache validity is **content-addressed**, not existence-based: a tampered artifact with an
      intact `.cache_key` sidecar must be rejected, not silently accepted. `test`
- [ ] Every downloaded artifact (kernel tarball, OCI layer blobs, builder base) is verified
      against its pinned hash before use; mismatch is a hard stop. `test`
- [ ] Image pulls are **digest-pinned**; a tag fallback is an error, not a silent degradation.
      mmdebstrap enforces apt gpg verification and a `snapshot.debian.org` timestamp pin. `review`
- [ ] Decode paths are complete: OCI layer handling covers gzip **and** zstd (a zstd layer must
      not silently yield an empty rootfs); device-node `rdev` uses `makedev`, not `(major<<8)|minor`. `review`
- [ ] Security-sensitive files are written safely: the MITM CA is generated once and the parsed
      authority cached (no re-self-signing per `authority()` call, which breaks the guest trust
      chain), written atomically (temp-then-rename), `0600`, and per-run-scoped (not a shared
      `/tmp` path two suites race on). `review`

### B5 · Pipeline staging

- [ ] Stage 0 **resolves pins** (OCI digest, Debian snapshot timestamp, kernel version, tool
      tags) into a committed `pins.lock` — inside the pipeline, not read from a static file outside
      it. `review`
- [ ] `StageInputs`/`StageOutputs` actually carry data; downstream stages consume upstream
      outputs (no empty structs, no reading paths from `IMP_KERNEL`/`IMP_ROOTFS` env vars). `test`
- [ ] A stage's declared inputs cover *everything* that affects its output — e.g. the guest-agent
      binary is a cached input artifact with its own key, not a `cargo build` side-effect of
      `RootfsStage::run()` that the rootfs key ignores. `review`
- [ ] Output paths are declared by each `Stage` impl, not synthesized by the pipeline from
      hardcoded `if name == "kernel"` string matches. `Pipeline::build` returns artifact locations,
      not an empty `Artifacts {}`. `review`
- [ ] The snapshot stage boots the **erofs** rootfs (the density argument depends on it), not a
      hardcoded `RootfsSource::Block`. `review`
- [ ] `reset_to(stage)` removes that stage's and all later stages' outputs and **errors on an
      unknown stage name**; a test asserts `reset_to(rootfs)` rebuilds rootfs+snapshot but not the
      kernel. `test`
- [ ] No `/tmp/vmlinux`-style fallback paths that mask a missing upstream artifact — a missing
      dependency is an error (as mmdebstrap already does). `review`
- [ ] Record/replay seam (requirement 7) splits network access into record and replay steps for
      every fetch path. `review`

### B6 · Concurrency & injected state

- [ ] IDs and time come from **injected allocators** (`CidAllocator`, vmid allocator, `Clock`) —
      never module-global `static AtomicU32`/`Mutex<Vec>`. A "wrapper around a global static" that
      pretends to be injectable is the same bug. `CI`(grep) `review`
- [ ] `release()` operates on the *actual* allocator instance/state, not a freshly-created one
      (the no-op-release bug); allocators track the in-use set, skip reserved CIDs (0/1/2), and
      wrap without colliding with live or reserved IDs. `test`
- [ ] VMID→octet mapping (`(vmid % 254) + 1`) is applied **at every use site** and consistently
      (no `%254` in one path, `%256` in another). Centralize the `/30` host-IP math in one
      unit-tested helper. `test`
- [ ] Side-effecting subsystems sit behind injectable traits — `Netlink`, `NftApplier`,
      `CgroupFs`, `SerialLog`, `Clock` — each with a recording fake, so orchestration can assert
      "the right rules/limits/handshake were requested" without touching the host. `review` `test`

### B7 · Module boundaries & duplication

- [ ] Logic that exists in three copies is extracted: the cgroup `stats()` reader, the
      spawn/`netns exec`/readiness-poll boilerplate, and the HTTP-over-Unix client are each one
      shared helper across CH/FC/QEMU — duplication is where the per-backend divergence bugs (cgroup
      escape logged for CH but not QEMU, etc.) live. `review`
- [ ] No hand-rolled HTTP: a real client parses status codes numerically and loops the read —
      not a single 4096-byte read matched by `starts_with("HTTP/1.1 200")` that misses
      201/202/chunked/large responses. `review`
- [ ] Module responsibilities match the design: cgroup creation/reading/limits live in
      `metrics.rs`, not scattered across the orchestrator and a backend. `review`
- [ ] Test-only logic is not baked into production handlers (no hardcoded `example.net` block —
      use the configurable deny list). `review`

### B8 · Public-API hygiene

- [ ] `#[non_exhaustive]` on every public struct/enum likely to grow (configs, requests/outcomes,
      stages, `Error`). `cargo semver-checks` catches the resulting break if omitted. `CI` `review`
- [ ] `#[must_use]` on constructors and builder methods returning `Self`. `review`
- [ ] `Error` has per-subsystem variants with typed sources and `#[from]` (not `String` payloads
      and `Error::Other` everywhere); unused typed variants are wired up or removed. `review`
- [ ] Every public item is documented (`#![deny(missing_docs)]`, not `warn`); `Result`-returning
      fns have `# Errors`, panicking fns `# Panics`, `unsafe` blocks a real `// SAFETY:` that states
      the actual preconditions (not "thread isolation"). `lint` `review`
- [ ] Per-module `#![forbid(unsafe_code)]` on the I/O-free modules (`config`, `agent::protocol`,
      `artifact` cache_key, `net` /30 math); `#![deny(unsafe_op_in_unsafe_fn,
      rustdoc::broken_intra_doc_links)]` at the crate root. `lint`
- [ ] No leaked internals (`pub` on `Pipeline.stages`, `ChInstance` fields); `Debug` on all public
      types and it actually prints fields. `review`
- [ ] Dead code removed or justified: unreachable protocol variants (`Hello`, no-op `Ping`),
      `restored` fields never read, debug `-trace` flags / `println!` left on the command line. `review`
- [ ] Native `async fn` in traits where `dyn` isn't required; `#[async_trait]` only where
      object-safety forces it, and documented as such. `review`

---

## Part C — Tests that actually test  *(the meta-rubric; this is why the rest recurred)*

Every test must be able to **fail**. Before accepting a test, construct the buggy
implementation it nominally guards and confirm the test goes red. Reject any test exhibiting
the smells below.

**Test smells — reject on sight:**

- [ ] **Skip == pass.** A test that `return`s green when `/tmp/imp-artifacts/*` (or KVM) is
      absent makes a misconfigured environment indistinguishable from success. Must skip *visibly*
      (`#[ignore]` / explicit skip-with-reason), and CI must run the `--ignored` suite on a capable
      runner so the skip isn't permanent.
- [ ] **Asserts nothing.** Discards the result (`let _ = alloc...`), `println!`s instead of
      asserting, or has the assertion commented out. A prop test that computes and drops its value
      asserts nothing.
- [ ] **Loose "or" assertions.** OOM-kill accepting `137 || -119 || 1 || -1` (code 1 is generic
      failure → passes with no OOM); block-detection passing on stdout-or-stderr-contains-403; CPU
      load accepting any non-zero (a missing binary passes). Assert the *specific* signal: exit 137 /
      a cgroup OOM event / the specific log line.
- [ ] **Coincidental pass.** Asserting two `/dev/urandom` reads differ (true without reseeding) or
      that the clock advanced after a host sleep (true on a plain resume) does not isolate the
      rotate/reseed/resync behavior. Pin the behavior, not a side effect that holds anyway.
- [ ] **Tests the opposite of its name.** A `tampered_digest_aborts` test that corrupts the
      `.cache_key` sidecar and asserts a *rebuild* verifies nothing about tamper-abort.
- [ ] **Mock where round-trip is required.** `put_file` asserting bytes reached a UDS mock (a
      guest-side `Ok(())` no-op still passes) instead of reading the file back in the guest.
- [ ] **String stand-ins for real artifacts.** Path-injectivity comparing `format!("imp-vm-{vmid}")`
      strings instead of the actual per-VM socket paths, and never varying `pid`; `/30` math doing
      `ends_with(".2/30")` instead of asserting octets and rejecting overflow at vmid ∈ {0,1,254,255}.

**Positive requirements:**

- [ ] `#[serial_test::serial]` on every test that touches global host state (netns, cgroups, nft)
      **and** on unit tests that contend on a process-global allocator — otherwise `--ignored`
      parallel runs flake. `test`
- [ ] `#[ignore]` reserved for genuine KVM/privilege needs; pure mock/codec tests run in the
      default `cargo test`, never hidden behind `--ignored`. `test`
- [ ] The `FakeVmm` is a **recording** fake and is actually driven: a backend-agnostic test
      exercises allocation order, retry/timeout, restore-vs-cold-boot selection, and ordered
      teardown with no KVM. "Exists but unused" is the recurring failure. `test`
- [ ] Injected fakes carry assertions: the `Netlink` fake records **zero** calls (the
      agent-free / zero-netlink-in-PID-1 contract); `restore()` does not re-run `ip link/addr` in
      the guest. `test`
- [ ] The per-VMM matrix consults `capabilities()` and emits **skip-with-reason** for
      unsupported scenarios — and the CH/primary path is *not* exempted from the check, so a CH
      regression skips-with-reason only when truly unsupported and otherwise hard-fails. `test`
- [ ] Required integration assertions are present, not happy-path-only: snapshot reconnect +
      rotate/reseed/resync; HTTPS interception logged + `CONNECT` falls through + filter-block
      observed + intended-destination observed; ordered-Drop-on-panic zero residue; N-VM
      concurrency with distinct CID/VMID/socket paths; the build-pipeline tamper/cache-hit/
      determinism trio. `test`
- [ ] No dead scratch tests in `src/` that are never compiled (`mod` not declared). `review`

---

## Part D — Required automated gates (the infrastructure that makes B & C real)

The reviews show review-alone fails. Each item below turns a defect *family* into a build
failure. **If a Part B/C item reached a human, the matching gate here is missing — add it.**

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

**CI jobs** (all required; the gaps below were all flagged as still-missing in pass 6):

| Gate | Catches |
|---|---|
| `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` | the lint families above; format drift (it currently fails) |
| `cargo hack --feature-powerset --depth 2 clippy --all-targets` | deps imported unconditionally under a feature gate (the `cgroups-rs`/`blake3` class) |
| lean-agent assert: `cargo tree -e no-dev --no-default-features --features agent` ∌ `tokio`/`hyper`/`rtnetlink` | guest PID-1 binary re-coupling to the host stack |
| `cargo deny check` with an allow-only license list + advisories + sources; **each `ignore` carries a rationale** | GPL/unvetted crates; bulk-suppressed advisories defeating the gate |
| `cargo semver-checks` | the `#[non_exhaustive]`-omission breakage |
| `cargo nextest run` with a **per-test timeout** | a hang (virtiofsd socket-wait, `cgroups add_task`) becoming a stuck CI job instead of a failure |
| a CI job running the **`--ignored` integration matrix** on a KVM-capable runner | the entire §12.4 suite being CI-invisible (skip == pass) |
| grep banning new `static …: Atomic…` / `static mut` outside the allocator module | re-introduction of global mutable ID state (B6) |

---

## One-line summary

Make every recurring defect class fail a **lint, a CI job, or a test that can actually go
red** — and treat any item that reaches human review as evidence that one of those gates is
missing. The two highest-leverage targets, Critical in all four passes, are **ordered
teardown that runs on panic** (B1) and **tests that can fail** (Part C).
