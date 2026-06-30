# AGENTS.md — vmcell

Operating instructions for any agent (or human) changing this crate. The CI gates
(`just ci`, the lint header, `deny.toml`, `nextest.toml`) catch a fixed set of defect
*families*; this file is the rest — the contracts, system invariants, and test discipline
that no gate can enforce. **A green `just ci` is necessary but not sufficient: the as-built
suite passed green for four separate broken implementations.** What kept the bugs in was
the absence of tests that could fail. Closing that is your job, not the gates'.

Source of truth for the architecture is `docs/<design>.md`; the explained checklist is the
review rubric; recorded, justified deviations live in `implementation-notes.md`.

## Prime directives

- **Fail loud, typed, early.** No swallowed `Result`, no `Ok(())` on a failed or unsupported
  branch, no panic on any path a guest or the network can drive. Errors are visible, matchable
  (not `Error::Other(String)`), and checked before a timeout can mask them.
- **Ownership owns cleanup — on panic.** Every host resource is released by `Drop`, in reverse
  dependency order, and that path must run when a test panics. `shutdown()` being correct does
  not count; the panic path is `Drop`.
- **Contracts self-guard.** A method whose correctness depends on "the caller checked first" is
  a latent bug. Check the precondition inside and return `Error::Unsupported` / `Err`.
- **Verify everything you ingest** (digests, signatures) and **test everything you claim is
  deterministic** (cache keys, pins, built images). Neither is assumable.
- **A seam you can't fake is a unit you can't test.** No module-global mutable state; side
  effects go behind injectable traits with recording fakes.
- **Record deviations.** Any deliberate divergence from the design goes in
  `implementation-notes.md` with its reason, not silently into the code.

## Validate every change (use the automation)

1. **Inner loop, while iterating:** `just test-unit` (unit + codec + property tests; no KVM).
2. **Before you call a change done:** `just ci` — runs fmt, clippy `-D warnings`, the
   feature-powerset clippy, `cargo deny`, the global-state ban, and the unit suite. It must be
   clean. If it flags something, fix the cause; don't suppress.
3. **If you touched anything host-facing** (VMM lifecycle, netns/tap/nft, cgroups, virtiofsd,
   snapshot, the agent, the pipeline), the unit suite does **not** cover it. On a KVM-capable
   Linux host run `just test-unprivileged` and `just test-privileged` (the latter needs `just bless`
   once after the runner rebuilds). If you cannot run them in this environment, **say so
   explicitly in your change summary** and make the tests correct by construction — never
   report a host-dependent change as validated on unit tests alone. That misreport is the
   "skip == pass" failure in human form.
4. **Public-API changes** will trip `cargo semver-checks` on the PR; expect it and update the
   surface deliberately.
5. **The rule that matters most:** for every behavior you add or fix, write the buggy version
   in your head and confirm a test goes **red** on it. If no test would catch the inverse of
   your change, the change is unverified regardless of step 2.

## What the gates already catch — don't re-police by hand

`.unwrap()`/`panic!`/`println!`/`dbg!` in production · missing doc/`# Errors`/`# Panics`/
`# Safety` · `DefaultHasher` in a cache key · a dep used unconditionally under a feature gate ·
non-permissive licenses and un-rationalized advisory ignores · a `#[non_exhaustive]` omission
that breaks the API · new module-global `static … Atomic…` · a re-introduced legacy term
(`ban-legacy-terms.sh` keeps `rootless`/`TestVm`/`imp_testing`/`imp-*` and the old `IMP_*` env vars
out of non-historical code — design v14 §10.7) · format drift · a hang (it becomes
a timeout). Everything below is what no gate sees.

## System contracts & invariants (read before touching the relevant subsystem)

These are not inferable from the code; violating them passes compilation and often passes a
naive test.

- **Snapshot-eligibility law.** A snapshot-eligible VM has **no vhost-user device attached** —
  not virtio-fs (virtiofsd), not the unprivileged `vhost-user-net` NAT, not an external
  `vhost-device-vsock`. Consequence: the snapshot tier runs the **privileged (tap) network
  path and a non-vhost-user vsock**. `restore()`/`snapshot()` must reject `NetConfig::Unprivileged`
  and a virtio-fs *rootfs*, and must not attach virtiofsd. Enforce in code, not just docs.
- **Capability descriptor is the contract.** Backends diverge (Firecracker has no virtio-fs, no
  vhost-user-net, no nesting). An unsupported op returns `Error::Unsupported { vmm, feature }`,
  **never a panic, never a stringly-typed `Error::Vmm`**. `restore()`/`snapshot()`/`create()`
  self-check `capabilities()` and degrade or error — they do not assume CH semantics.
- **Teardown order.** `MicroVm::Drop` tears down **VMM process group → virtiofsd → netns /
  cgroup / overlay / sockets**, force-killing the process *group* with a wait
  (`kill -9 -<pgid>` then reap) — not `start_kill()` (leader-only, non-blocking), which orphans
  `ip netns exec` wrappers and leaves zombies. Removing a netns while the VMM still holds
  interfaces in it hangs or leaks; reap first. Release **both CID and VMID** in `Drop`.
- **Zero-netlink in PID 1.** `vmcell-guest-agent` does **no** `ip link/addr/route`; the kernel
  `ip=` cmdline (with `CONFIG_IP_PNP=y`, virtio-net present) configures `eth0`. The restore
  path must not re-run `ip` inside the guest either. A `Netlink` fake must be assertable to
  zero calls.
- **PID-1 reaper vs. waiter.** A single `waitpid(WNOHANG)` reaper must not steal the exec'd
  child's exit status from the dedicated `child.wait()` — that race reports false exit `127`
  for a command that succeeded. Coordinate them.
- **VMID → octet mapping.** Apply `(vmid % 254) + 1` at **every** use site, consistently (no
  `%254` in one path and `%256` in another), and centralize the `/30` host-IP math in one
  unit-tested helper. Out-of-range vmid returns `Err` at a validation boundary, not `assert!`
  inside `create()`.
- **Cache keys are reproducible.** Hash content and **identity that travels** — never absolute
  `PathBuf`s under `target_dir` — and embed a **stage version** and the pinned source **SHA**.
  Cache validity is **content-addressed** (hash the output), not existence-of-file. A tampered
  artifact with an intact `.cache_key` must be rejected.
- **Pipeline staging.** Stage 0 **resolves pins** into a committed `pins.lock` inside the
  pipeline. Stages pass real data via `StageInputs`/`StageOutputs` (not empty structs, not
  `VMCELL_KERNEL`/`VMCELL_ROOTFS` env vars). The snapshot stage boots the **erofs** rootfs, not
  `Block`. Anything a stage's output depends on (incl. the guest-agent binary) is a cached
  input, not a `run()` side effect. No `/tmp/vmlinux`-style fallback paths that hide a missing
  upstream artifact — missing input is an error. `reset_to(stage)` errors on an unknown name.
- **Provenance is a hard stop.** Every download (kernel tarball, OCI blobs, builder base) is
  verified against its pinned hash before use. Pulls are **digest-pinned**, never tag-fallback.
  mmdebstrap enforces apt gpg verification and a `snapshot.debian.org` timestamp pin. Decode
  paths are complete (OCI gzip **and** zstd; `makedev`, not `(major<<8)|minor`).

## Authoring rules the gates don't catch

- **Failure handling.** Reject silent `Ok(())` stubs (clippy catches `todo!()` but not a no-op
  `Ok(())`). Every `let _ = result;` carries a comment justifying the discard, else surface or
  `tracing::warn!`. Error *detection* must be correct: no "any error → success" probes, no
  bare `host.ends_with(blocked)` (over-blocks sibling domains — match label boundaries).
  Readiness/poll loops check `process.try_wait()` and fail fast with the real cause; never fall
  through a timeout to "success". Handle mutex poison deliberately (`parking_lot`, or
  `into_inner()` with a comment that recovery is sound).
- **`config::build()` returns `Result`** and rejects duplicate share tags, virtio-fs-rootfs +
  snapshot, `vcpus == 0`, `mem_mib` below floor, empty kernel path, out-of-range vmid — with a
  negative test for each.
- **Build the injectable seams.** `Netlink`, `NftApplier`, `CgroupFs`, `SerialLog`, `Clock` are
  small traits with a real impl and a recording fake. Use `rtnetlink`, not the `ip` CLI. IDs and
  time come from injected allocators; `release()` operates on the real instance (the no-op-release
  bug), skips reserved CIDs (0/1/2), and wraps without colliding with live IDs.
- **Don't triplicate; extract.** The cgroup `stats()` reader, the spawn/`netns exec`/readiness
  boilerplate, and the HTTP-over-Unix client are **one shared helper** across CH/FC/QEMU —
  duplication is where per-backend divergence bugs hide (a cgroup escape logged for CH but
  silent for QEMU). No hand-rolled HTTP (parse status numerically, loop the read — not a single
  4096-byte read prefix-matched). Cgroup logic lives in `metrics.rs`. No test-only logic in a
  production handler (no hardcoded `example.net` block).
- **Error type.** Per-subsystem variants with typed sources and `#[from]`, not `String`
  payloads and `Error::Other` everywhere. Wire up or delete unused variants. `#[non_exhaustive]`
  on growable public types; `#[must_use]` on constructors/builders; no `pub` leaking internals
  (`Pipeline.stages`, backend instance fields); no dead protocol variants advertised as live
  (`Hello`, no-op `Ping`).
- **Security in the privileged window** (`vmcell-test-runner`): check the **effective** set, not
  permitted; **drop the bounding set before raising ambient**; trim `P`/`E` after; for the
  setuid form, change uid *before* raising ambient. CA hygiene: generate once and cache the
  parsed authority (re-self-signing per `authority()` call breaks the guest trust chain), write
  atomically (temp-then-rename), `0600`, per-run-scoped path. virtiofsd: `--sandbox namespace`
  + a dedicated uid; enforce `read_only` for RO shares (don't mount rw and warn).

## Test discipline (why bugs survived four passes)

Every test must be able to fail. Before accepting one, construct the buggy impl it guards and
confirm it goes red. Reject these smells:

- **skip == pass** — a `return` on missing artifacts/KVM makes misconfiguration look like
  success. Skip *visibly* and ensure CI runs the `--ignored` suite.
- **asserts nothing** — discards the result, only `println!`s, or has the assertion commented out.
- **loose `or`** — OOM accepting `137 || 1 || -1` (code 1 is generic failure); block-detection on
  "stdout or stderr contains 403". Assert the *specific* signal (exit 137 / a cgroup OOM event /
  the exact log line).
- **coincidental pass** — two `/dev/urandom` reads differing (true without reseeding); the clock
  advancing after a host sleep (true on a plain resume). Isolate the actual rotate/reseed/resync.
- **tests the opposite of its name** — a "tamper aborts" test that corrupts the `.cache_key`
  sidecar and asserts a rebuild.
- **mock where round-trip is required** — `put_file` asserting bytes reached a UDS mock instead
  of reading the file back in the guest.
- **string stand-ins** — path-injectivity comparing `format!("vmcell-vm-{vmid}")` strings instead of
  real socket paths, never varying `pid`; `/30` math doing `ends_with(".2/30")` instead of
  asserting octets and rejecting overflow at vmid ∈ {0,1,254,255}.

Positive requirements: serial execution comes from the `nextest.toml` `serial-host` group, not
ad-hoc `#[serial_test::serial]`. `#[ignore]` is only for genuine KVM/privilege needs — pure
mock/codec tests run in the default suite. The `FakeVmm` must *record* and be *driven*: a
backend-agnostic test exercises allocation order, retry/timeout, restore-vs-cold-boot selection,
and ordered teardown with no KVM. The per-backend matrix consults `capabilities()` and emits one
consistent skip-with-reason — the primary (CH) path is never exempted from the check. Required
integration assertions exist and are specific: snapshot reconnect + rotate/reseed/resync; HTTPS
intercept logged + `CONNECT` falls through + filter-block observed + intended-destination
observed; ordered-Drop-on-panic zero residue; N-VM concurrency with distinct CID/VMID/socket
paths; the build-pipeline tamper / cache-hit / determinism trio; the zero-netlink assertion. Use
the `vmm_matrix_test!` + `require_cap!` + `start_vm` harness in `tests/common/mod.rs` so this is
mechanical.

## Dependencies & licenses

Permissive only (MIT / Apache-2.0 / BSD / ISC / Zlib) for anything **linked**; copyleft tolerated
only for an external **binary** (QEMU) when it unlocks a fallback. `cargo deny` is the source of
truth — confirm a new crate's license via the gate, not its label (the `rustables`-mislabeled-as-MIT
precedent). GPL source is **documentation-only**: read it to understand behavior, never copy it
into this MIT/Apache codebase. Keep the privileged-window binaries (`vmcell-guest-agent`,
`vmcell-test-runner`) dependency-thin — every dep there executes with elevated capability — and keep
the agent off the host async stack (the lean-agent CI assertion enforces this).

## Definition of done

- [ ] `just ci` is clean (cause fixed, not suppressed).
- [ ] Host-facing change: `just test-unprivileged` + `just test-privileged` run on a KVM host, **or** the
      summary states they were not run and why, with the tests correct by construction.
- [ ] The new/changed behavior has a test that fails on its inverse (incl. the panic path for any
      resource you acquire, and a negative test for any validation you add).
- [ ] No new contract/invariant above is violated; if you deliberately diverge from the design,
      it's recorded in `implementation-notes.md` with a reason.
- [ ] Public-API change: `cargo semver-checks` reviewed, surface updated intentionally.

## Pointers

· `docs/99-claude-design-v99.md` — architecture & the decision record (authoritative).
  (`9` represents an arbitrary digit, use the latest version you find)
· `docs/99-claude-code-review-rubric.md` the review rubric — the explained version of everything above.
· `docs/historical/99-claude-automated-quality.md` — the gates and how to deploy them.
· `implementation-notes.md` — the running log of justified deviations; add to it.
