# vmcell — Design Document (v16)

*A **micro-VM runner for isolated environments** — create a fresh micro-VM, run a command in it over a typed control channel, give it shares / host-endpoints / logged egress, observe and cap its resource use, optionally snapshot/restore it for speed, and tear it down with no residue — driven entirely from a single Rust library. **vmcell** exposes that loop as a general, workload-agnostic primitive with **three co-equal application domains**: **low-level systems testing** (a real kernel, the full syscall surface, and nested virt, per test), **agentic execution / agent harnesses** (untrusted AI-agent tool calls and code execution in disposable, observable, fast-to-restore sandboxes), and **generic serverless / ephemeral-function execution** (snapshot a warmed runtime once, restore per invocation in ~tens of ms, discard). Its origin and still most-demanding consumer is end-to-end integration testing and evaluation of the **Imp** agentic harness — the project's former name was "Imp Testing." The three guarantees it delivers — isolation, hermeticity, fidelity (§1.2) — are exactly what all three domains need.*

> **Name (proposed).** This revision renames the project from *Imp Testing* to **`vmcell`**. The name is a proposal and is trivially swappable — it is a single-token rename across this one doc plus the crate/bin identifiers. The crate, CLI, and helpers become `vmcell` / `vmcell-guest-agent` / `vmcell-test-runner` / `vmcell-guest-tools`; the public VM handle becomes **`MicroVm`** (was `TestVm`). Throughout this document, **"Imp"** still refers to the agentic *harness* that is the origin consumer — never to this runner.

**What changed in v16 (the experimental-conclusions audit pass).** No new subsystem — this revision *corrects recorded conclusions* that were re-tested live on the committed pins (QEMU **10.2.1**, Cloud Hypervisor **v52**, Firecracker **v1.16.0**, guest kernel **6.12.94**) on a KVM host, because several v15/impl-notes conclusions were drawn while the code was buggy and turned out to have wrong *reasons* or to be outright stale. Full method, evidence, and per-experiment verdicts: `docs/41-experimental-conclusions-audit.md`. Of six re-run "we can't / we must" conclusions only one held cleanly; the corrections here are the rest. **(1) The `microvm`-rejection *reason* is corrected (§3 "Fallback VMM", §4 QEMU).** The recorded story — *"`microvm`'s `virtio-net-device` (MMIO) falls back to the legacy 10-byte virtio-net header and breaks networking"* — is unsupported: header size is **feature-negotiated** (`VIRTIO_NET_F_MRG_RXBUF`/`VIRTIO_F_VERSION_1`), not transport-governed, and `microvm` never even reaches virtio-net probe. The real reason `microvm` is unusable here is that **QEMU 10.2.1's `microvm` cannot boot these PVH kernels to userspace** — a deterministic early-boot spurious `#DE` in `start_kernel`, reproduced across ~24 machine/CPU/timer/IRQ permutations incl. pure-TCG, and **`-M microvm,pcie=on` with the same PCI devices `q35` uses fails identically.** `q35` stays; only the justification changes. **(2) QEMU snapshot gains a validated privileged tier (§3.3, §4 QEMU, §9, A.3 #5).** The "privileged kernel-`vhost-vsock` → likely, unvalidated" recovery path is now **validated in its load-bearing halves**: QEMU 10.2 source has **no migration blocker** on the in-kernel `vhost-vsock-pci` device (unlike the external vhost-user-vsock daemon), and migrate-to-file → `-incoming` restore was verified live on the real `vmlinux`+erofs. So "QEMU is snapshot-ineligible in *all* configs" becomes "ineligible over the unprivileged external-`vhost-device-vsock` path; **eligible in the privileged in-kernel-vhost-vsock config**" — a capability, pending the live agent-reconnect run + wiring `snapshot()`/`restore()` (still `Unsupported`). **(3) The vendored `vhost`/`vhost-user-backend` patch is confirmed, not "lowest-confidence" (§10.4).** A live vhost-user message trace confirms QEMU sends `SET_VRING_ENABLE` **before** `SET_FEATURES` (CH sends features first) and our backend negotiates `PROTOCOL_FEATURES` correctly — the fork addresses a genuine QEMU ordering quirk, not a masked backend bug; upstream 0.22/0.16 still enforce the guard. **(4) The Firecracker-PCI-snapshot claim is overturned (A.3 #1).** FC **v1.16.0** ships stable PCI + snapshot: `--enable-pci` + Full snapshot **create *and* restore both succeed** (no `MicroVMStoppedWithError`) — the v15 justification was version-stale (true in FC's ~1.10–1.12 experimental-PCI era). FC still runs MMIO by default, but for maturity/shared-`vmlinux` reasons, not "PCI cannot snapshot." **(5) The FC extended-FPU guard is corrected and de-over-applied (§3.2, §9, A.3 #3; code fix).** `noxsave` was hard-coded into the FC boot-args **unconditionally** — even alongside the T2 template, needlessly disabling guest AVX2 the template leaves usable. It is now **gated to `template.is_none()`** (design §138's fallback-only intent; the always-on impl-notes deviation is superseded). Live: the `restore_fpregs_from_fpstate` panic does **not** reproduce for reachable AVX2/YMM state on FC v1.16.0 with *no* guard, and FC **rejects** the T2 template on modern Intel client hybrids (Lunar Lake) — so the T2 leg is inoperative there. (The AVX-512/ZMM trigger is untestable on this CPU; `noxsave` is retained as the no-template fallback.) **(6) The `passt`-rejection *reason* is corrected (Appendix B, Exp 5).** `passt` is **not** CH-incompatible via its seccomp: passt's seccomp *allows* `accept4` (it survives with `EACCES`, not a `SIGSYS` kill). The `accept4`→`EACCES`→`epoll`-`EBADF` cascade is the host **AppArmor** `passt` profile's stale coarse `network unix stream` rule vs Ubuntu 26.04's af_unix fine-grained mediation — **not CH-specific** (a `socat` client reproduces it) and avoidable by flipping the vhost-user socket direction. smoltcp stays (better design regardless), but the recorded justification was wrong. **(7) Minor corrections.** §8.3's config-omission narrative is order-dependent — for `kvm_guest.config`-*alone* the first failure is the **erofs root-mount panic** (boot never reaches userspace), not `EAFNOSUPPORT` at vsock, which needs an intermediate config; and the symbol is `CONFIG_VIRTIO_VSOCKETS_COMMON`, not `CONFIG_VSOCKETS_COMMON`. §13.6: the pipeline's `mmdebstrap` source builds `--variant=apt` (≈129 MB → OCI **−38.7%**), not `--variant=minbase` (≈120 MB → −34%). **Code landed alongside this revision:** the FC `noxsave` gating and a `tests/host_endpoint.rs` `Drop`-guard fix (a leaked `http.server` child on the panic path); both validated by `just ci`, `just test-privileged` (232 pass), `just test-unprivileged` (17 pass). **What v16 does *not* change:** every corrected decision (keep `q35`, keep the fork, keep smoltcp, run FC in MMIO) still stands — only the *reasons* and two now-invalidated impossibility claims are fixed, plus the newly-validated QEMU privileged-snapshot tier.

---

**What changed in v15 (the easy-extensions + capability-runner-resilience pass).** Five revisions, all from the maintainer's `todo.md` "next design round," each ground-truthed against the v14 code and adversarially triaged for "is this *actually* easy?" — three of the four candidate tags survived, one was pushed back, and two sub-items were demoted to deferred-but-designed. **(1) The capability runner's blessing now survives iterating on the rest of the code (§12.8 — the headline ask).** Three composing fixes make `just bless` durable: the blessed binary is **installed to a stable path outside `target/`** (so cargo's churn — the process-wide `RUSTFLAGS=-D warnings` re-fingerprint, feature-set toggles, profile changes — never rewrites and re-strips it), `just bless` becomes **idempotent via a content-hash *stamp* keyed on the *runner* binary** (re-`setcap` runs only when the runner actually changed), and the runner's privilege-transition logic is **extracted to a pure, unit-tested `CapState` function** so the runner rarely *needs* to change at all. A latent **confinement-root bug** that would have silently broken the stable-path install is fixed in the same pass: the runner derived its target-dir confinement root from its *own* path (`/proc/self/exe`), which has no `target/` ancestor once the runner moves out of `target/` — v15 re-sources it from the **test binary's** (already-canonicalized) path. **The runner deliberately does *not* hash, pin, or allowlist test-binary content** — it is a generic privilege-injector; the security boundary is *who may execute the runner* plus path-confinement, not test-binary identity, and pinning test-binary hashes would re-introduce exactly the per-iteration churn this pass removes. **(2) The single package is promoted to a cargo workspace (§10.1/§10.5/§12.2).** A `vmcell` library crate, a tiny shared `vmcell-protocol` crate, and member crates for the three lean privileged-window / guest binaries (`vmcell-test-runner`, `vmcell-guest-agent`, `vmcell-guest-tools`), so library churn no longer rebuilds the blessed runner (a *structural* leanness boundary, stronger than v13's feature gate) — the concrete answer to the todo's "should we switch to a workspace? **yes**." (Workspace members still share `target/` and `RUSTFLAGS`, so the stable-path install of #1 remains the load-bearing durability fix; #1 and #2 compose.) **(3) VM-management verbs take a `rootfs` argument, and `vmcell` ships an `oci2erofs` utility (§8.2/§10.2/§11) — the maintainer's clarification.** OCI stays a **build-time source only**: a new `vmcell oci2erofs IMAGE@DIGEST -o rootfs.erofs` utility runs the existing rootfs pipeline against any digest-pinned base image (verify-every-blob → whiteouts → inject agent/CA/guest-tools → erofs), and the lifecycle verbs consume the resulting **erofs path** — so the runtime stays erofs-only and the single-shared-erofs + snapshot/density story is untouched. Bring-your-own images that omit `libc6` **fail loud before packing** (the glibc agent would die at PID 1); a static-musl agent is an **explicit `--agent-musl` opt-in**, never a silent fallback (which would violate the §7.1 fail-loud contract). **(4) Lifecycle verbs are unified across lib + CLI — the easy subset committed, the daemon-coupled subset deferred (§10.2/§10.3).** `create`/`run` (synchronous create→exec→teardown), `stats`, `snapshot`, and `destroy` are committed, taking `--kernel`/`--rootfs`; this also makes `pause`/`resume`/`snapshot` **first-class `MicroVm` methods** (today they sit on the `VmInstance` trait, reachable only via `instance_mut()` — a deliberate, `cargo-semver-checks`-visible promotion, the one library change this item needs). **Pushed back to the `impd` daemon (§16.2):** `list`/`rm` and a standalone `exec`, because a meaningful cross-invocation registry requires VMs to *outlive their creating process*, which collides head-on with the load-bearing ordered-`Drop`-owns-cleanup invariant. **`fork` stays deferred (§16.2):** efficient copy-on-write fork is E:high, and even a correctness-only snapshot-copy-then-restore fork depends on the same per-backend single-use config-rewrite the CoW item must generalize. **(5) The kernels registry grows a config-fragment matrix (§8.3).** A kernel can be requested as a base SHA + an ordered set of named KConfig fragments (KASAN/KCOV/LOCKDEP/`slub_debug`/a driver), content-addressed per (base SHA + **sorted** fragment set + stage version); the *mechanism* is a small extension of the existing `KernelStage` cache key + config-append + `pins.json`. Committed with scoping: config-only fragments are in scope, the merge fails loud on `olddefconfig` error, build-time blow-up is bounded by the cache (a cold KASAN build is ~45–90 min → CI batches and a nightly full matrix), and the genuinely-not-a-fragment cases are excluded — **PREEMPT_RT needs a patched source** (a separate registry source, not a fragment) and **KCOV *extraction* needs guest tooling** (the §16.2 item) — with the per-test invocation API left as forward work. **What v15 does *not* change:** no subsystem, no invariant, and no hot-path mechanism — every revision extends an existing seam (the capability runner, the four-target build, the rootfs pipeline, the `MicroVm`/`VmInstance` handle, the `KernelStage` registry) and is gated on the §3.3 snapshot law, the zero-netlink contract, the fail-loud contract, the lean-privileged-window boundary, and keep-the-primitive-general. The **reproducible-bundle** idea from the §16.1 candidate is scoped down to a **digest-pinned fetch-and-verify manifest** for *our* artifacts (kernel/erofs/CA/`pins.json`); **vendoring the VMM binaries is explicitly rejected** — QEMU is GPL (redistribution is a legal question the "external binary, not linked" carve-out does not cover), CH/FC are 100+ MB per release, and fetch-and-verify-by-digest already delivers the reproducibility, with an offline-everything image left to a consumer `Dockerfile` (a productization layer, §1.3).

---

**What changed in v14 (the rebrand + terminology pass).** Four classes of revision, all from the maintainer's `todo.md`. **(1) Rebrand (§1).** The project is renamed *Imp Testing* → **vmcell** and repositioned from a single-purpose test platform to a **general micro-VM runner for isolated environments** with three co-equal application domains (low-level systems testing · agentic execution / agent harnesses · generic serverless). The crate, CLI, and helper binaries rename accordingly, and the public handle is renamed from the testing-specific `TestVm` to the neutral **`MicroVm`** — a deliberate, `cargo-semver-checks`-visible public-API change (§10.2). **(2) Terminology canonicalized (§6.4, §10.7).** v13's *prose* already said *unprivileged*/*privileged*; v14 makes it canonical *in the API, tests, and tooling*: `NetConfig::Rootless` → `NetConfig::Unprivileged`, the `*_rootless` test functions → `*_unprivileged`, the `just test-rootless` / `test-priv` recipes → `test-unprivileged` / `test-privileged`, and the nextest `test(rootless)` filter → `test(unprivileged)`. §10.7 is the exact rename spec. **(3) Explicit per-mode test specs (§12.4).** Each operating mode is a first-class, separately-invoked suite whose prerequisites are a visible hard precondition; §12.4 now spells out exactly what the **unprivileged suite** and the **privileged suite** must each assert, plus a strengthened unit-test spec for the capability runner itself (§12.8) to cut its rebuild/bless churn. **(4) New capabilities surfaced by the rebrand (§16).** A catalog of candidate features the three domains motivate — VM-as-a-handle lifecycle + a daemon/API, single-snapshot copy-on-write clones, warm pools, fault injection, kernel-matrix testing, an in-guest model-proxy bridge, and more — is collected and adversarially triaged against the design's invariants. The fail-loud capability contract (§7) and the capability-runner resilience / cargo-workspace question (§10.1, §12.8) are also advanced. **The architecture itself does not change** (Appendix A): beyond the mechanical renames, v14 adds new *specification* sections — §10.7, the §12.4 per-mode test specs, the §12.8 churn-reduction block, and the §16 catalog — but no new subsystem; the rest of Parts II–IV is carried forward from v13.

**What changed in v13 (since v12p2).** Three classes of revision: (1) **the §13 benchmark suite ran on the committed pin** (Linux 6.12.94, CH v52 / FC v1.16 / QEMU 10.2.1), so most §14 contested facts and §15 open questions are now *settled with measured numbers* (`docs/benchmark-results.md` is the canonical results doc); several research-era hypotheses **inverted** (OCI base is *smaller* than mmdebstrap-minbase; static-musl is *larger* than glibc; the guest kernel version is *not* a material hot-path lever). (2) **Implementation lessons** folded into the body: the snapshot-eligibility law is now enforced *in code at three boundaries* (§3.3); snapshot/restore needed concrete host-side fixes (CH `config.json` path rewrite, FC vsock-UDS sidecar, a guest vsock **re-bind** after restore — §9.2); a small in-rootfs Rust **guest-tools** helper replaces missing `iproute2`/`curl` (§5.3); the artifact dir and cache keys were consolidated and content-addressed (§11). (3) **Maintainer design directives** (`todo.md`): the project now speaks of **unprivileged operation** (KVM-group access, *no* extra Linux capabilities) and **privileged operation** (the capability runner holds `CAP_NET_ADMIN`/`CAP_SYS_ADMIN`/`CAP_DAC_OVERRIDE`) — replacing the older "rootless" wording (§6.4); host-facing operations move from **silent best-effort degradation to fail-loud on a missing capability** (§7); and the cargo feature matrix collapses to **four build targets** (one host feature + three lean targets, §10.5).

**How to read this document.** Parts I–III describe the system **as it currently is** — the architecture, each subsystem, the test and benchmark strategy, and the open items. Facts that were once contested, reversed, or arrived at across multiple implementation passes are stated here in their settled, present-tense form. **Part IV is the history**: the implementation-pass ledger (what each pass confirmed or overturned), the substitution experiments, prior art, and the build roadmap. Where a current design choice is non-obvious — why erofs and not ext4, why Firecracker runs in MMIO mode, why the snapshot tier excludes unprivileged networking — the body points to the appendix that explains how it was reached. Measured numbers are real and recorded inline (§13) and in `docs/benchmark-results.md`; the substrate they were measured on is recorded with them. The few facts still awaiting confirmation against the exact pinned versions are called out as such in §14.

---

## Part I — Orientation

## 1. Purpose, scope, and non-goals

### 1.1 What this builds

A Rust library (plus a thin CLI binary) that, on a Linux/x86_64 host with KVM, can:

1. Build the VM artifacts (kernel, root filesystem, proxy CA) reproducibly.
2. Create, configure, start, stop, and destroy micro-VMs programmatically.
3. Give each VM read-only and read-write shared directories with independent permissions.
4. Let host-side code stand up private HTTP (and other) servers the VM can reach.
5. Route all VM web egress through a transparent, logging/filtering Rust proxy.
6. Drive the VM's "console" over a vsock control channel (exec, stream I/O, exit code).
7. Monitor and cap each VM's CPU / RAM / disk-I/O / net-I/O.
8. Optionally expose nested virtualization so a guest (the harness under test, or any workload) can run its own VMs.

**The execution primitive is general; the three domains are consumers of it.** Strip capabilities 3–5 (shares, host endpoints, egress proxy) and what remains — create → restore-or-cold-boot → `exec` over vsock → observe/cap → ordered teardown — is a self-contained, workload-agnostic **micro-VM execution primitive**. It is exposed as such: nothing in `vmm`/`agent`/`orchestrator`/`metrics` is testing-specific (or agent-specific, or serverless-specific), the artifact pipeline produces a generic Debian rootfs, and the **`MicroVm`** handle — renamed in v14 from the testing-specific `TestVm` (§10.2) — is a thin owner over the primitive. Integration testing for Imp drives every capability and so remains the most demanding consumer, but the same primitive serves **low-level systems testing** (a real kernel + full syscall surface + nested virt), **agentic-harness sandboxing** (run an untrusted agent's tool calls in a disposable VM with logged egress), and **generic serverless / ephemeral-function execution** (snapshot a warmed runtime once, restore per invocation in ~tens of ms, discard). Keeping the primitive general is a hard design constraint, not an afterthought (§15); the capabilities each domain additionally *wants* — and how to add them without leaking consumer policy into the core — are catalogued and triaged in **§16**.

### 1.2 The three guarantees

The runner exists to deliver three properties, by construction rather than by cleanup. They are stated in testing terms but hold for any consumer (substitute "invocation"/"job" for "test"):

1. **Isolation** — a misbehaving harness, model, or workload cannot disrupt the host.
2. **Hermeticity** — no state leaks between runs; each starts from an identical, fresh VM, and teardown is structural (the VM is discarded, not reset).
3. **Fidelity** — the in-VM environment matches a real end-user Linux system, including full-host-access use cases (nested virt, full syscall surface).

### 1.3 Non-goals: the evaluation methodology layer

Scoring, juries, dashboards, multi-juror adversarial evaluation, MCTS rollback engines, stateful API simulation, and CI soft-failure statistics are **out of scope**. This library is the *substrate* such a layer sits on. Two connection points are designed in now because they map onto hard requirements:

- The transparent egress proxy (capability 5) is the natural home for **record/replay "cassettes"** and **Rust test doubles** for web services.
- The vsock control plane (capability 6) is the natural transport for an **in-guest model-proxy bridge** (the agent talks to `localhost:PORT`, the harness forwards over vsock and records the transcript) if Imp evaluations later need it.

Everything beyond those hooks belongs to a separate crate that depends on this one. The same boundary applies to the other consumers in §1.1: a serverless scheduler (warm-pool management, invocation routing, billing) or an agent-sandboxing frontend (policy, tool-call mediation) is a *layer on top of* this primitive, not part of it. This library's job is to make one isolated VM cheap, fast, observable, and leak-free; orchestrating many of them for a particular product is the caller's.

---

## 2. System at a glance

```
┌──────────────────────── Host: Linux + KVM (nested=1 if needed) ───────────────────────┐
│                                                                                        │
│  vmcell orchestrator  (Rust, tokio)                                               │
│   ├─ Vmm trait:  create / boot / request_shutdown / kill / snapshot / restore / stats  │
│   │     └─ impls:  CloudHypervisor (default) · Firecracker (dense) · Qemu (fallback)   │
│   ├─ per-test:  cgroup v2 slice  →  {netns + tap (/30)  |  smoltcp vhost-user NAT}      │
│   ├─ AgentClient (tokio-vsock / AF_UNIX, retry+handshake)   ⇄   vmcell-guest-agent (PID 1) │
│   ├─ virtiofsd × N  (vmcell-in ro · vmcell-bin ro · vmcell-out rw)                               │
│   ├─ EgressProxy (hyper+rustls):  {nft TPROXY | smoltcp L4}  →  log/filter/doubles → WAN│
│   └─ Metrics:  read memory.peak / cpu.stat / io.stat from the slice                     │
│                                                                                        │
│   artifact cache:  vmlinux  ·  erofs rootfs (RO, shared)  ·  warm snapshot  ·  proxy CA │
└────────────────────────────────────────────────────────────────────────────────────────┘
        │ restore (ms) or cold-boot                          ▲ vsock: Ready/Exec/IO/Exit
        ▼                                                     │
  ┌──────────────────────── micro-VM (per test, ephemeral) ───────────────────────┐
  │ kernel: direct boot, virtio + vsock + virtio-fs + (opt) KVM built-in, no initramfs │
  │ PID 1: vmcell-guest-agent  (mounts /sys /proc + shares, sets up tmpfs overlay,     │
  │        installs proxy CA, reaps children, serves the vsock protocol)            │
  │ root: /dev/vda = erofs (RO, shared)  +  tmpfs overlay for writes                │
  │ mounts: /in (virtiofs ro) · /opt/imp (virtiofs ro) · /out (virtiofs rw)         │
  │ net: eth0 → default route → host proxy   [optional] /dev/kvm → inner VMs        │
  └─────────────────────────────────────────────────────────────────────────────────┘
```

### Per-test lifecycle

1. **Acquire artifacts** from the cache (kernel, erofs rootfs, snapshot, CA) — built once, reused.
2. **Allocate per-test resources:** a cgroup v2 slice, networking (netns+tap on a fresh `/30`, or an in-process smoltcp NAT), and a unique vsock **CID**. The erofs base is mounted read-only and shared — *no per-VM disk copy*; the only writable state is the tmpfs overlay.
3. **Start the VM:** either **restore** a warm "agent-ready" snapshot (the fast path: `--restore` → `resume`, never `create`/`boot`) or **cold-boot** (opt-in for tests that mutate global state the snapshot would have baked in). On restore, **rotate identity** (vsock CID, MAC/IP, reseed entropy via virtio-rng) and **resync the guest clock** (§9).
4. **Bind shares (cold / general path):** point `vmcell-in` / `vmcell-out` virtiofsd at this test's input/output dirs; `vmcell-bin` is shared read-only across all tests so its pages stay hot. *On the snapshot/restore tier there are no virtio-fs shares* (virtiofsd is a vhost-user device, §3.3); read-only data there is served as an extra erofs/block image.
5. **Connect + drive over vsock:** the host `AgentClient` retries the vsock handshake until the guest's `Ready` frame arrives (bounded by a timeout), while tailing the serial log so a boot panic fails fast instead of retrying to no avail. Then `Exec` the entrypoint; stream stdout/stderr/exit. On the restore path the connection is **re-established, not reused** (§4).
6. **Collect results:** outputs from the host `vmcell-out` dir; `memory.peak`/`cpu.stat`/`io.stat` from the slice; the proxy's request log.
7. **Tear down (ordered):** force-kill the **VMM process group first**, then the virtiofsd processes, *then* remove the tap/netns/cgroup/overlay/sockets. Removing a netns while the VMM still holds interfaces or threads in it can hang or leak; reaping the process first makes teardown a clean kernel operation. Discard is structural — that *is* the no-leakage guarantee.

### Decisions summary (bottom line up front)

| Concern | Decision |
|---|---|
| **Primary VMM** | **Cloud Hypervisor (CH)**, run as a subprocess over its REST `--api-socket`. Rust/rust-vmm, Apache-2.0/BSD-3. Meets every functional capability; the feature-complete default. |
| **Secondary VMM** | **Firecracker** behind the same trait, for the dense/snapshot tier. Runs in **MMIO mode**, snapshots with UFFD lazy restore. **Fastest warm restore of the three** (≈128 ms p50, beating CH's ≈169 ms — §13) though slowest cold boot. No virtio-fs, no vhost-user-net (so no unprivileged net mode), no nested virt. |
| **Fallback VMM** | **QEMU `q35`** (not `microvm`) as a documented escape hatch and the most-proven nester; full feature set. Snapshot is ineligible over the unprivileged external-`vhost-device-vsock` path but **validated-eligible in the privileged in-kernel `vhost-vsock` config** (no QEMU-10.2 migration blocker; migrate→restore verified live — §3), pending the live agent-reconnect run + wiring `snapshot()`/`restore()` (still `Unsupported`). C/GPL **binary**, used as an external tool, not linked. |
| **Control plane** | **virtio-vsock + a Rust guest agent as PID 1** (dynamic-glibc by default), framed postcard protocol (`Ready`/`Exec`/`Stdout`/`Stderr`/`Exit`/`PutFile`). Host connects with a retry/handshake loop and reconnects after restore. Serial console wired to a per-VM log for panic capture and fast-fail. SSH only as a human debugging fallback. |
| **Shared dirs** | **virtio-fs, one `virtiofsd` per share**, `--readonly` for inputs/binaries, rw for output; `--memory shared=on`; `cache=never`. |
| **Root filesystem** | **erofs read-only image over `virtio-blk`**, shared by all concurrent VMs with **no per-VM copy**; per-VM writes go to a **tmpfs `overlayfs` upper**. erofs has no journal → no recovery writes, no concurrent-mount corruption, and it composes with snapshot (a plain block device, not vhost-user). |
| **Host-served endpoints** | Per-VM **network namespace + tap + `/30`** (privileged) *or* an **in-process smoltcp + vhost-user-net NAT** (unprivileged). Host test servers reachable, not exposed beyond the VM. Mode chosen via `NetConfig`. |
| **Transparent proxy** | **nftables `TPROXY`** (privileged) or **L4 interception in the smoltcp NAT** (unprivileged) → a **Rust MITM proxy** (`hyper`+`rustls`, or `hudsucker`) with logging, filtering, pluggable **test doubles**, CA baked into the guest trust store. |
| **Monitoring / limits** | One **cgroup v2 slice per VMM (and per virtiofsd) process**; read `memory.peak`/`memory.current`/`cpu.stat`/`io.stat`; enforce `memory.max`/`cpu.max`/`pids.max`/`io.max`. Enforcement needs a **delegated** cgroup subtree; the orchestrator **probes delegation and fails loud** when a *requested* limit can't be enforced — no silent no-op (§7). |
| **Operating modes** | **Two, named and tested separately** (§6.4, §12.4): **unprivileged operation** (KVM-group access, *no* extra Linux capabilities; userspace smoltcp NAT) and **privileged operation** (the §12.8 capability runner grants `CAP_NET_ADMIN`+`CAP_SYS_ADMIN`+`CAP_DAC_OVERRIDE`; netns+tap). A mode's prerequisites are probed up front and **enforced fail-loud**, never discovered mid-run. |
| **Guest tooling** | A tiny in-Rust multicall **`vmcell-guest-tools`** (`ip`/`curl`/`kvm-ok`, doing the *real* operations) **baked into the erofs**, supplying the few tools the minimal Debian base omits without bloating the rootfs or weakening assertions (§5.3). |
| **Guest OS** | Minimal **Debian Trixie (13, kernel 6.12 LTS)** rootfs, from one of two sources feeding the same erofs packer: **OCI pull** by digest (default — host-native, in-Rust, no Docker/containerd), or **`mmdebstrap` inside a builder micro-VM** for the full apt signing chain. |
| **Guest kernel** | **Direct kernel boot** of a custom-minimal `vmlinux` from **Debian kernel source** with an **explicit config fragment** (§8) — virtio (PCI + MMIO) + vsock + virtio-fs + erofs/overlay + optional KVM, all built-in, no initramfs. No project-specific patches. |
| **Speed lever** | **Warm snapshot + restore** off the erofs rootfs, with a tmpfs overlay per test; cold-boot opt-in. Measured **≈3.7× faster than cold boot on CH and ≈8× on Firecracker** on the pinned substrate (§13); CH **lazy restore ≈1.5× faster than eager (≈82 ms)**. |
| **Density levers** | `cache=never` + shared erofs RO base (one host-cached copy for all guests) + **virtio-balloon / free-page-reporting**, plus opt-in **KSM** (`ksm_mergeable`: CH `mergeable=on,shared=off` — deduped ≈394 MiB / ~84% across 8 identical guests, but mutually exclusive with vhost-user paths; §13). **Not DAX** (unavailable in CH, §14). |
| **Dependency posture** | Prefer in-crate Rust over external tools; permissive licenses only (MIT/Apache/BSD); copyleft tolerated only for *binaries* (QEMU, `nft`). Vet with `cargo-deny` on every build. |
| **Build layout** (v15) | A **cargo workspace**: `vmcell` library + a shared `vmcell-protocol` crate + three lean member crates (`vmcell-test-runner`, `vmcell-guest-agent`, `vmcell-guest-tools`). Leanness is a *structural per-member property* (§10.1, §12.2), stronger than the v13 feature gate. `[patch.crates-io]` (vhost fork) at the workspace root. |
| **Privileged-test bless** (v15) | Durable across code iteration: the blessed runner is a **copy installed to a stable path outside `target/`** (immune to cargo's `RUSTFLAGS`/feature re-fingerprint), `just bless` is **idempotent via a content-hash stamp keyed on the runner** (never test binaries), confinement is anchored on the **test binary's** path, and the privilege transition is a **pure, unit-tested `CapState` function** (§12.8). |
| **VM lifecycle verbs** (v15) | Unified `create`/`run`/`pause`/`resume`/`snapshot`/`stats`/`destroy` across lib + CLI, taking a `--kernel`/`--rootfs` (erofs) argument; `pause`/`resume`/`snapshot` promoted to first-class `MicroVm` methods (§10.2). `vmcell oci2erofs IMAGE@DIGEST` converts any digest-pinned OCI image to an erofs (build-time; §8.2). `list`/`rm`/standalone `exec` (cross-process registry) deferred to the `impd` daemon; `fork` to the CoW-clone item (§16.2). |

---

## Part II — The system, subsystem by subsystem

## 3. VMM backends and the `Vmm` trait

### 3.1 Why a trait plus a capability descriptor

The lifecycle is modeled as a narrow, well-typed contract — `capabilities()` plus `create` / `boot` / `request_shutdown` / `kill` / `snapshot` / `restore` / `stats` — so the finicky, subprocess-supervising, occasionally-`unsafe` VMM glue stays behind a boundary and the orchestrator stays idiomatic and unit-testable (a `FakeVmm` implements the same trait, §10.6). The three backends genuinely diverge — Firecracker has no virtio-fs, no vhost-user-net, and no nested virt — so the contract is **general with a capability descriptor**, not CH-shaped. Each method documents the *behavior*; the backend-specific mechanism stays inside the impl; a backend reports what it supports via `capabilities()`, so an unsupported op returns `Error::Unsupported { vmm, feature }` and the orchestrator (and the test/bench matrix) degrades gracefully rather than assuming CH semantics everywhere. The orchestrator selects a backend per tier from `capabilities()`; the test and benchmark harnesses **skip — never fail** — scenarios a backend cannot run (§12.4 / §13).

Every field of `VmmCapabilities` is a property of the *pinned* VMM build and must be re-confirmed against it (§14), not hard-coded from memory. The same "report, don't assume" discipline is applied to the **host environment** so the orchestrator selects an operating mode (§6.4) from what the host actually offers — capabilities held, controllers delegated, KVM-group access — and fails loud when a requested mode's prerequisites are missing, rather than discovering it mid-run. (Today this is realized by **per-op capability checks** — `Error::CapabilityUnavailable` gated on `cgroup.subtree_control`, the per-backend `VmmCapabilities`, and the §6.4 mode probes; consolidating them into one unified, start-up `HostCapabilities` descriptor, §7.1, is forward work, §15.)

### 3.2 The three backends

**Cloud Hypervisor (CH) — the default.** The feature-complete backend: snapshot/restore via `--restore`+`resume`, virtio-fs shares, vhost-user-net (so the unprivileged smoltcp NAT), and nested virt. Controlled over a hand-written thin REST client (`hyper`/`hyperlocal` over the Unix `--api-socket`, with `serde` types from CH's in-repo OpenAPI YAML). Cold boot ≈635 ms; warm restore ≈169 ms (CH default ≈ lazy; eager ≈258 ms — §13). The lifecycle has two distinct paths: cold = `vm.create` → `vm.boot`; warm = launch with `--restore` → `vm.resume` (**never** `create`/`boot` — CH returns `500 "VM is already created"`). `snapshot` must `vm.pause` first, then snapshot, then `vm.resume` (or stay paused if the VM is about to be killed). **Restore-path `config.json` rewrite (observed, v13):** CH `--restore` rebuilds every device from the snapshot's `config.json`, which records the *original* instance's now-defunct temp-dir paths for the **vsock socket** and **serial file**, and CH exposes **no** restore-time override for them (`RestoreConfig` = `source_url`/`prefault`/`memory_restore_mode`/`net_fds`/`resume` only). So the spawn step must rewrite `<snapshot>/config.json`'s `vsock.socket` and `serial.file` to this restore's freshly-minted paths *before* launching, or the host connects to a socket CH never bound and the serial log stays empty. In-place rewrite suffices for a single-use snapshot; restoring many clones from one snapshot needs a copy-on-write of the snapshot dir first (§9). CH is supervised and pinned as an external release binary — it is **not** cargo-installable and has no embeddable library crate; only its REST *client* is a crate.

**Firecracker — the dense/snapshot tier.** Its draw is **density (low memory overhead) + snapshot**, and it has the **fastest warm restore of the three** (≈128 ms p50, vs CH's ≈169 ms — §13), the metric the per-test hot path actually uses — even though it has the slowest cold boot (≈1022 ms). Implemented the same way as CH: a hand-written `hyper`-over-Unix client (not `firecracker-rs-sdk`), with the binary managed as an external pre-compiled download (it needs its containerized `tools/devtool` build, so `cargo install` is not an option). Its device model is deliberately minimal — virtio-{net,block,vsock,balloon,rng,pmem} — so it **cannot do virtio-fs, vhost-user-net, or nested virt**; the orchestrator reads this off `capabilities()` and the test/bench matrix skips those scenarios. Two Firecracker-specific facts:

- **It runs in native MMIO mode** (no `--enable-pci`). The guest kernel ships both virtio-pci (for CH) and virtio-mmio (§8), so one `vmlinux` serves CH over PCI and Firecracker over MMIO. It defaults to MMIO for backend maturity and the shared `vmlinux`, **not** because PCI blocks snapshot: the old "no snapshot under PCI" claim is version-stale — FC **v1.16.0** supports `--enable-pci` + snapshot create *and* restore (A.3 #1). Its restore sequencing differs from CH's — pause/resume is `PATCH /vm` (not `PUT`); restore is a fresh process + `POST /snapshot/load {resume_vm:false}`; drives and vsock may **not** be (re)configured around load. `resume_vm:false` is deliberate: restore returns the VM *paused* and the orchestrator calls `resume()` explicitly, so both backends share the trait's "restore returns paused, caller resumes" shape. The cost is one extra round-trip and a failed-`resume()` zombie risk, reaped by the ordered `Drop`. **Restore-path host-socket fix (observed, v13):** `POST /snapshot/load` rebinds the host vsock Unix socket **verbatim from the path baked in at snapshot time** with no load-time override, so restoring under a fresh sandbox dir both collides with the stale socket (`EADDRINUSE`) and points the agent at the wrong path. `snapshot()` therefore persists the host vsock/serial paths in an `vmcell_host_paths.json` sidecar; `restore()` reads it (failing loud on a missing/corrupt sidecar, **without leaking the VMM**), unlinks the stale socket, and adopts the snapshot's paths so the agent dials the exact UDS Firecracker re-creates. (Sequential restores from one snapshot work; concurrent clones need a copy-on-write of the snapshot dir — the same caveat CH carries, §9.)
- **Extended-FPU restore is constrained at the CPU layer.** Firecracker restore can panic in `restore_fpregs_from_fpstate` when the guest `glibc` dispatches to aggressive AVX/extended-FPU paths (the saved XSAVE area mismatches on restore). The fix is a static **`T2` CPU template** on the `MachineConfig` (masking `avx512_vnni` and the other extended-state CPUID bits) plus **`noxsave`** on the guest kernel command line **as a no-template fallback — `noxsave` is gated to `template.is_none()` in code, since applying it alongside T2 needlessly disables the guest AVX2 the template leaves usable.** Two FC-v1.16.0 caveats: FC **rejects** the T2 template on modern Intel client hybrids (e.g. Lunar Lake), so the T2 leg is inoperative there; and the `restore_fpregs_from_fpstate` panic does **not** reproduce for reachable AVX2/YMM state on FC v1.16.0 (the AVX-512/ZMM trigger is untestable on such a host), so `noxsave` is retained only as that no-template fallback. This keeps the `trixie` base — the bug is a Firecracker extended-state limitation that any modern-`glibc` base triggers, so the durable fix lives in CPUID, not the OS version (history and the rejected `bookworm` downgrade are in Appendix A). The trade-off to record: `noxsave` is broader than the template — it disables guest AVX/AVX2 as well as AVX-512 (SSE2 floor), whereas the template leaves AVX2 usable. That is a **test-fidelity** cost: software that dispatches to AVX/AVX2 runs its scalar/SSE2 paths inside a Firecracker VM, so SIMD-correctness-sensitive tests belong on the **CH tier** (full vector ISA, no `noxsave`), with Firecracker reserved for density/snapshot workloads.

**QEMU `q35` — the fallback and most-proven nester.** Full feature set (virtio-fs, vhost-user-net, nesting). Use **`q35` with `virtio-net-pci`**, not `microvm`: the virtio-net header size is **feature-negotiated** (`VIRTIO_NET_F_MRG_RXBUF`/`VIRTIO_F_VERSION_1`), not transport-governed, and `microvm` never even reaches virtio-net probe — QEMU 10.2.1's `microvm` cannot boot these PVH kernels to userspace (a deterministic early-boot spurious `#DE` in `start_kernel`, reproduced ~24 ways incl. pure-TCG), and `-M microvm,pcie=on` with the same PCI devices `q35` uses fails identically. Snapshot is ineligible over the **unprivileged** external `vhost-device-vsock` path — a stateless vhost-user backend that cannot migrate, so QEMU is snapshot-ineligible over the vsock control plane the unprivileged harness uses (§3.3) — but **validated-eligible in the privileged in-kernel `vhost-vsock` config**: QEMU 10.2 source has no migration blocker on `vhost-vsock-pci`, and migrate→restore was verified live on the real `vmlinux`+erofs (§3.3/§9), pending the live agent-reconnect run + wiring `snapshot()`/`restore()` (both still `Unsupported` in code). Wiring the unprivileged smoltcp NAT to QEMU also requires a `[patch.crates-io]` fork of `vhost-user-backend` + `vhost` to relax a `PROTOCOL_FEATURES` check (confirmed by live trace — §10.4). Cold boot ≈1405 ms.

### 3.3 The snapshot-eligibility law

Every snapshot finding across the project reduces to one rule:

> **A VM is snapshot-eligible only if no vhost-user device is attached to it — and, for Firecracker, only under MMIO.**

Any external vhost-user backend is, by construction, a separate stateless process the VMM cannot migrate, so it severs the snapshot. The practical consequence: **the warm-snapshot tier is {CH, Firecracker} on the privileged/tap network path with a non-vhost-user vsock transport** — plus a validated-but-unwired **QEMU privileged tier** (in-kernel `vhost-vsock`; §3.3 table / A.3 #5). (The "for Firecracker, only under MMIO" clause above is the design default + historical constraint — FC v1.16 can also PCI-snapshot, A.3 #1.) Any feature that requires a vhost-user device — the unprivileged NAT (vhost-user-net) **or virtio-fs *data* shares (virtiofsd), not only a virtio-fs *rootfs*** — is mutually exclusive with snapshot on the same VM. CH's base control-plane vsock is safe because it is CH's *userspace* implementation, not vhost-user; Firecracker's built-in vsock is likewise migratable.

**"Attached" means *any* virtiofsd, not just the rootfs one.** This is the precise point an earlier pass got wrong (it guarded a virtio-fs *rootfs* + snapshot but let a data `Share` through to the backend, which then attached `virtiofsd` to a VM it was about to snapshot — code review 34, finding C1). A read-only data share is *still* a vhost-user device; there is no "small enough to be safe" exception. The rule is over the **device class**, not the share's role or access mode.

**Enforced in code, at three boundaries — not just documented.** The law is a hard stop checked independently at each layer so no single missed check can let a vhost-user device onto a snapshot-eligible VM:

1. **`config::build()`** rejects `snapshotting == true` combined with a virtio-fs *rootfs*, **any** virtio-fs data `Share`, or `NetConfig::Unprivileged` — returning a typed validation `Err`, with a negative test per case (§12.3). This is the primary gate: an invalid combination never becomes a `VmConfig`.
2. **`orchestrator::restore()`** re-checks the same predicate against the `cfg` it is handed (defense in depth — a config constructed by other means still can't reach a backend) and returns `Error::Unsupported` rather than wiring up daemons.
3. **Backend `restore()` / `snapshot()`** self-guard on `capabilities().snapshot_restore` *and* on the absence of any vhost-user device in `cfg`, returning `Error::Unsupported { vmm, feature }` — never a panic, never a stringly `Error::Vmm`. A backend never assumes "the caller already checked."

Because boundary 1 rejects the combination outright, the old empirical question "*can* a virtio-fs data share be re-attached to a snapshotted VM?" is **answered by construction**: the public API can never attach a vhost-user device to a snapshot-eligible VM, so CH's runtime refusal is unreachable. The standing fallback for read-only data in the snapshot tier is to **serve it as an additional erofs/block image**, whose cost is the extra image's page cache, not guest anonymous RAM (§13.6). (The `restore()`/`snapshot()` signatures take `&VmConfig` so they can reconstruct the *non-vhost-user* device topology — rootfs/block args, tap/net wiring — from the config; this is **not** a license to attach virtiofsd on that path, the subtle conflation finding C1 flagged.)

| Backend + config | Snapshot-eligible? | Why |
|---|---|---|
| **CH** + erofs-block rootfs + userspace vsock + tap net | **Yes** | no vhost-user device in the path; the validated default snapshot tier |
| **CH** + a virtio-fs **data** share attached | **No** | `virtiofsd` is a vhost-user device — serve RO data as an extra erofs/block image in the snapshot tier instead |
| **CH** or **QEMU** + unprivileged smoltcp NAT (vhost-user-net) | **No** | the NAT is a vhost-user-net backend — unprivileged mode is not the snapshot path |
| **Firecracker** + MMIO + built-in vsock + tap net | **Yes** | native MMIO snapshot; vsock/balloon/rng/block are built-in, not vhost-user — plus the §3.2 extended-FPU CPU-template guard |
| **QEMU** + unprivileged external `vhost-device-vsock` | **No** | the external vsock daemon is a stateless vhost-user backend that cannot migrate |
| **QEMU** + privileged kernel-`vhost-vsock` | **Validated (source + migrate/restore); pending backend wiring** | no vhost-user device in the vsock path; QEMU 10.2 has no migration blocker on in-kernel `vhost-vsock-pci` and migrate→restore was verified live — backend `snapshot()`/`restore()` not yet wired |

The orchestrator reads this off `capabilities()` and the test/bench matrix skips the impossible combinations rather than discovering them at runtime.

### 3.4 Capability matrix

To re-confirm against the pinned builds (§14):

| Capability | CH | Firecracker | QEMU |
|---|---|---|---|
| `snapshot_restore` | ✓ (PCI) | ✓ (MMIO) | ✗ over unprivileged vhost-user-vsock; ✓ possible in the privileged in-kernel `vhost-vsock` config (validated, unwired) |
| `lazy_restore` (demand-paged) | ✓ (`memory_restore_mode`) | ✓ (UFFD) | — |
| `virtio_fs_shares` | ✓ | ✗ (block-only) | ✓ |
| `unprivileged_vhost_user_net` | ✓ | ✗ | ✓ |
| `nested_virt` | ✓ | ✗ | ✓ |
| cold boot (p50, §13) | ≈635 ms | ≈1022 ms | ≈1405 ms |
| warm restore (p50, §13) | ≈169 ms | ≈128 ms | N/A |

The cold-boot/restore inversion pins each backend's role precisely: **Firecracker is slower to cold-boot but fastest to restore**, so it earns the density+snapshot tier (the hot path); **CH stays the feature-complete default and cold-boot leader**; **QEMU is the fallback** for the awkward cases.

---

## 4. Control plane: vsock and the guest agent

### 4.1 The protocol

`agent::protocol` defines a small length-prefixed, `serde`+`postcard`-framed message enum (host and guest standardize on postcard's length-delimited framing): `Ready`, `Exec{argv,env,cwd,timeout}`, `Stdout(bytes)`, `Stderr(bytes)`, `Exit(i32)`, `PutFile`. The enum is `#[non_exhaustive]`. **No `Hello`, no `Ping`** — earlier drafts listed them, but a dead variant and a no-op variant are both the "dead protocol advertised as live" smell the review rubric bans, so they are omitted; `#[non_exhaustive]` makes re-adding either non-breaking if a real use appears. The guest sends `Ready` as the **first frame** after `accept`, and the host blocks for it (this is the handshake the restore path re-runs, §4.2). This module is the *only* code shared between the host and the guest agent, keeping "all functionality in one library crate" essentially true while the guest binary stays thin.

### 4.2 The host: `AgentClient`

`connect` opens the host-side vsock endpoint and performs the **readiness handshake**, retrying with backoff until the guest is listening and has sent `Ready`, OR a timeout elapses, OR the serial log shows a kernel panic (fail fast). The transport is uniform across all three backends: CH and Firecracker expose a host AF_UNIX socket with the **Firecracker-style hybrid-vsock handshake** (the host writes `CONNECT <port>\n`, expects `OK <port>\n`); the QEMU backend uses vhost-user-vsock so `vsock_path()` stays a Unix path and the handshake is identical. CH (and Firecracker) accept the Unix-socket connection *before* the guest has booted and bound, so the retry belongs at the handshake level, not around a single `connect()`.

Two invariants the protocol depends on:

- **Read the `OK <port>\n` line with exact 1-byte reads, never a buffered reader.** The framed protocol follows immediately on the *same* stream, so a `BufReader` that reads the line pre-fetches the first framed payload into its buffer, which is then silently discarded when the reader is dropped before handing the raw stream to the codec — manifesting as a mysterious connection timeout. Read exactly up to the `\n`, then pass the unbuffered stream to the codec.
- **`reconnect` after restore is not a no-op, and the guest LISTEN socket does *not* always survive.** All restorable backends reset the vsock device on restore, so the prior connection is dead (the guest sees EOF): CH re-creates the host socket; Firecracker closes open connections and bumps the `guest_cid`. The old client must be dropped and a new connection opened to the new endpoint. **The v12-era assumption that the guest's bound LISTEN socket simply survives is wrong on CH (observed, v13):** after CH `--restore` re-creates the vhost-vsock device, the pre-snapshot `VsockListener` goes *deaf* — it yields no new connections — so the guest must **re-`bind`** to re-attach to the live device. Two guest-side properties make reconnect work (detailed in §4.3 and §9.2): the agent serves each connection on **its own thread** (so a stale pre-snapshot connection whose blocking read never EOFs parks instead of wedging the accept loop), and it re-`bind`s its listener after a bounded idle period. `AgentClient::reconnect` then retries until the fresh listener accepts.

`exec` runs a command, streams stdout/stderr, and returns the exit status. Its timeout is **per-request** (`ExecRequest.timeout`), defaulting to **10 s** for ordinary commands and set long only for the builder-VM `apt`/`mmdebstrap` call — never a single global constant, which would force every test exec to wait minutes before failing.

### 4.3 The guest: `vmcell-guest-agent` as PID 1

The agent runs as the `init=` target (`init=/sbin/vmcell-guest-agent`). Because it executes as PID 1 on an already-mounted rootfs that ships `libc6` (any Debian base), the default build is **dynamically linked against the rootfs glibc** — no extra toolchain. A fully static `musl` build is optional (for a rootfs-independent agent) but needs `musl-tools`, which is not installable without root in some CI environments (the size, RSS, and startup implications of the choice are benchmarked in §13.3). Its PID-1 contract is larger than "serve the protocol," and missing any of it is painful to debug:

- mount `proc`, `sys`, `devtmpfs`, the virtio-fs tags, and set up the **tmpfs `overlayfs`** over the read-only erofs root;
- install the proxy CA into the trust store and bring up loopback. **The guest address is set by the kernel `ip=` boot parameter** (`CONFIG_IP_PNP=y`, §8), in both privileged tap and unprivileged smoltcp modes, so PID 1 needs **no netlink**. Agent-side network bring-up survives only as a guarded, last-resort fallback;
- **reap zombies** (`SIGCHLD`/`waitpid`) — PID 1 is the universal reaper; skip this and the guest fills with defunct processes. The reaper and the dedicated `child.wait()` for the exec'd command must be coordinated so the reaper does not steal the child's exit status (which would report a false `127` for a command that succeeded);
- **never exit on a recoverable condition** — if PID 1 returns, the kernel panics with `Attempted to kill init`. The genuinely-unrecoverable core mounts (overlay / `/proc` / `/dev`) stay fatal; *everything else is logged and the agent continues*. Two such conditions were live regressions (observed, v13): a **virtio-fs tag that is not attached** — shares are optional, and the exec-only / benchmark path attaches none, so a `virtio-fs: tag <vmcell-in> not found` must be logged and skipped, **not** `return Err`'d into a kernel panic — and a **loopback bring-up ioctl failure**, which is cosmetic on the data path and must log-and-continue rather than propagate out of `main`;
- **fork** the test command as a child (not `exec` into it) so the agent stays PID 1 and retains the control channel and reaping duty;
- a **boot-time self-check** probing for the device nodes / FS support it depends on (open `AF_VSOCK`, virtio-fs), emitting a clear diagnostic before binding so a missing-kernel-symbol regression fails legibly instead of as a raw errno panic;
- **serve connections in a loop, re-binding after restore:** the host reconnects on the vsock device the VMM re-creates during restore. The agent serves each connection on **its own thread** (a stale pre-snapshot connection, whose blocking read may never EOF, parks instead of blocking the accept loop), runs a **non-blocking accept loop**, and **re-`bind`s its listener after a bounded idle period** (`REBIND_IDLE`) — because on CH the pre-snapshot bound listener goes deaf once the vhost-vsock device is re-created (§4.2, §9.2). Re-bind is harmless in normal operation (it only fires on idle) and is what lets `AgentClient::reconnect` succeed post-restore.

The serial console is wired to a per-VM log for panic capture and fast-fail; SSH is a human-only debugging fallback, never the control plane.

---

## 5. Root filesystem and shared directories

### 5.1 The erofs read-only base + tmpfs overlay

The rootfs is a **single read-only erofs image over `virtio-blk`**, shared by all concurrent VMs with **no per-VM copy**; per-VM writes go to a **tmpfs `overlayfs` upper**. This one artifact serves every path — cold boot, concurrent shared mounts, and the snapshot tier — because erofs over virtio-blk is read-only, shareable, and snapshot-eligible (it is a plain block device, not vhost-user). erofs has **no journal**, which removes two failure modes an earlier ext4-clone-per-VM design hit: journal-recovery panics on read-only mounts, and concurrent-mount corruption. It is also a density lever: the host page cache holds a single copy of the image for all concurrent guests (the partial recovery of the page-cache-sharing benefit DAX would have provided, which is unavailable, §14).

If a writable *disk* overlay is ever needed (rare, given the tmpfs overlay), use reflink/qcow2-backing rather than a full copy — minding that `FICLONE` works on **XFS or Btrfs**, not ext4, where it silently degrades to a full copy. Using **virtiofs as an overlayfs lowerdir** is a known sharp edge (historically needs redirect_dir/metacopy) and is avoided — another reason the RO base is erofs, not a virtio-fs mount.

### 5.2 virtio-fs data / binary / output shares

Shared directories use **virtio-fs, one `virtiofsd` per `Share`**, each on its own Unix socket, with `--readonly` for `ReadOnly` shares (the flag is `--readonly`, *not* `--read-only`, which aborts the daemon) and a `--sandbox namespace` + dedicated uid so a daemon can reach only its one directory. The orchestrator emits the `--fs tag=…,socket=…` config and ensures `--memory shared=on`; cache policy defaults to `never` for density. **Share tags are caller-defined, not built-ins** (keeping the primitive general, §1.1): a consumer names whatever mount tags it wants on each `Share`, and the guest mounts exactly those — *the agent does not hardcode a tag list*. The mechanism (implemented): for every `Share` in `VmConfig`, the orchestrator appends one **`vmcell_share=<tag>:<guest_path>:<ro|rw>`** token to the guest kernel command line (`config::push_share_args`, consistent with the `ip=` cmdline pattern, §6/§8.4); the guest agent reads `/proc/cmdline`, mounts each `tag` at its **`guest_path`** over virtio-fs, and applies a read-only mount for `ro` shares. The mount point is **caller-controlled**: `guest_path` defaults to `/<tag>` and `Share::with_guest_path` overrides it (e.g. tag `data` mounted at `/srv/data`), decoupling the mount point from the tag for generic workloads. `build()` rejects a tag or `guest_path` containing `:`/whitespace, a non-absolute `guest_path`, or a duplicate tag/`guest_path` — a negative test per case — and the agent's pure cmdline parser is unit-tested (a malformed token is dropped, never mounted read-write a share the host declared read-only). The conventional default tags vmcell ships in its own builder/tests are `vmcell-in` (ro, per-test input), `vmcell-bin` (ro, shared across tests so its pages stay hot — e.g. the Imp consumer's binaries arrive here, so a new build does not invalidate the rootfs), and `vmcell-out` (rw, per-test output), but they are **examples, not requirements**: another consumer (a systems-testing fixture, a serverless function) supplies its own tags via `VmConfig`.

**Subprocess-supervision invariant:** a misconfigured `virtiofsd` exits immediately, but if the orchestrator only polls for the socket file, CH hangs forever waiting for the vhost-user socket — so the supervisor must surface the child's exit/stderr *and* bound the socket-wait with a timeout.

**Snapshot interaction:** attaching virtiofsd (a vhost-user device) makes a VM snapshot-ineligible (§3.3), and that is now **enforced by construction** — `config::build()` rejects `snapshotting` combined with any virtio-fs share, so the snapshot tier *never* attaches virtiofsd. Read-only data needed in the snapshot tier is served as an **additional erofs/block image** instead (its cost is the extra image's page cache, not guest RAM — §13.6). An in-process `fuse-backend-rs` alternative (Appendix B, Exp 1) is gated behind `experiment-fuse` with the daemon as the fallback; it does **not** yet enforce read-only, an open correctness gap (§15).

### 5.3 The in-rootfs guest-tools helper

The minimal Debian base (whether the OCI slim image or a lean `mmdebstrap` set) **omits `iproute2`, `curl`, and `cpu-checker`** — tools a handful of integration tests and the restore-path MAC rotation need. Rather than bloat the rootfs with distro packages or weaken the tests, the harness ships a small **Rust multicall binary, `vmcell-guest-tools`** (built from `src/bin/vmcell-guest-tools.rs`), providing:

- `ip` — read-only interface/route/neighbour state from sysfs/procfs, plus `link set <dev> address <mac>` via the `SIOCSIFHWADDR` ioctl (the one write the restore path uses; see §9.2), and accepts `ip addr`/`ip route` *write* forms as no-ops so an orchestrator `&&`-chain succeeds without touching the boot-time `ip=` address;
- `curl` — real HTTP/HTTPS via `reqwest`, honoring the proxy env vars and `-k`/`--resolve`/`--max-time` (and surfacing a proxy's `CONNECT` 403 the way curl does, which the egress-block test asserts on);
- `kvm-ok` — a real `/dev/kvm` probe for the nested-virt test.

Two properties keep it honest. **It performs the *real* operations** (genuine HTTP, real `/dev/kvm`, real procfs reads), so it is *not* a weakening of any assertion — it is the "prefer in-crate Rust over external tools" requirement applied to the guest side. And it is **baked into the erofs image**, not delivered over a share: `virtiofsd` cannot enter its `--sandbox namespace` without privilege, so a share would fail in the *unprivileged* suite; the erofs root is served over virtio-blk in both modes. A `GuestToolsStage` builds the helper and the rootfs packer injects it at `/vmcell-tools/vmcell-guest-tools` with `ip`/`curl`/`kvm-ok` symlinks; the agent prepends `/vmcell-tools` to the exec `PATH`. The rootfs cache key folds the helper's content (§11.2), so a helper change re-bakes the rootfs. It is gated behind a `guest-tools` build that compiles standalone (a lean target like the agent).

---

## 6. Networking and egress

### 6.1 Two modes, chosen by `NetConfig`

**Privileged (`tap`).** A per-VM network namespace, a `veth`/tap pair, and a `/30` (`10.200.<vmid>.0/30`, host `.1`, guest `.2`) via `rtnetlink`. Full L2 fidelity; needs `CAP_NET_ADMIN`. This is the default for fidelity-sensitive tests and the only network path eligible for the snapshot tier (§3.3).

**Unprivileged (`userspace`).** An in-process **smoltcp** TCP/IP stack behind a `vhost-user-backend` vhost-user-net device — no tap, no `CAP_NET_ADMIN`. Lower-fidelity (a userspace stack), so it is reserved for deployability rather than fidelity-sensitive tests, and it cannot be snapshotted (vhost-user-net, §3.3). Four invariants make it work, worth encoding because each one wedges the link silently:

1. smoltcp silently drops a broadcast frame whose *source* MAC equals the interface MAC, so the host NAT MAC must not collide with the guest's vmid-derived MAC. **Correction (observed, v13):** the v12 pin `02:00:00:00:00:fe` is *itself* `mac_math(254)`, so it collides for the allocatable vmid 254 (review finding NET-2 — the recorded "avoids collisions" rationale was wrong at that one vmid). Pin the host MAC **outside the range `mac_math` can emit** — a nonzero high octet such as `02:00:00:01:00:00` — and back it with a unit test asserting no `mac_math(vmid)` over `1..=254` equals the host MAC;
2. iterate the virtio RX descriptor chain **only when the NAT actually has packets queued** for the guest — iterating `vring.iter()` consumes/advances `avail_idx`, so polling it while empty discards the guest's RX buffers and permanently wedges the link;
3. call `enable_notification()` on the TX queue inside the `handle_event` loop so the guest knows to kick the eventfd for the next packet;
4. size the smoltcp socket pool for concurrent *and* keep-alive connections (≈16 sockets per forwarded port), not one-per-port — a single `TcpSocket` per port means an HTTP keep-alive connection holds the only slot and the next connection gets `Connection refused`.

(`passt` was the first choice but is out; smoltcp is better regardless — in-process, no external dep, no LSM/seccomp entanglement. **Correction (v16, audit E5):** the recorded reason — "passt's C seccomp filter drops the `accept4` CH's vhost-user connection needs, no opt-out — CH-incompatible" — was **wrong**. passt's own seccomp *allows* `accept4` (it survives with `EACCES`, not a `SIGSYS` kill); the `accept4`→`EACCES`→`epoll`-`EBADF` cascade is the host **AppArmor** `passt` profile's stale coarse `network unix stream` rule vs Ubuntu 26.04's af_unix fine-grained mediation — **not CH-specific** (a plain `socat` client reproduces it) and avoidable by flipping the vhost-user socket direction (CH `vhost_mode=server` + passt `-F`); Appendix B, Exp 5.)

The `/30` math is a pure function and unit-tested; the netlink calls, the `nft` invocation, and the smoltcp NAT's packet loop are the side-effecting part.

### 6.2 Host-served endpoints

A host test server bound to the per-VM gateway/host address is reachable from the guest and not exposed to other systems. Per-test server config and dynamically-assigned ports are configured *after* the server is listening. Arbitrary TCP/UDP works. vsock is available as an alternate, IP-stack-free host↔guest channel.

### 6.3 The transparent egress proxy

A `hyper`-based MITM proxy (`hudsucker` supplies the whole MITM stack — `hyper`+`rustls`+`rcgen`, Apache/MIT). For HTTP it splices/logs; for HTTPS it terminates TLS with an on-the-fly cert minted by an in-memory CA (`rcgen`) and re-originates upstream. The CA is baked into the guest trust store, so HTTPS interception works in both networking modes. `doubles` lets a test register `(Matcher, Responder)` pairs (and, for the eval layer, record/replay cassettes). HTTPS test doubles must **ignore `hyper::Method::CONNECT`** — matching on the `CONNECT` itself breaks the tunnel and yields a TLS "unexpected eof."

The proxy *process* is mode-independent; how traffic is *steered into it* is not, so the module exposes one proxy with two front-ends:

- **Privileged:** an nftables **`TPROXY`** ruleset (`tproxy to :<port> meta mark set 1 accept`, plus `drop`/`log`), rendered in Rust and applied via the external `nft -f -` binary — no permissive pure-Rust nftables crate covers the `tproxy`/`socket` expressions (§10.4). TPROXY carries the original destination *in the socket* (no conntrack lookup), preserves the original source, and handles **UDP** (transparent QUIC/HTTP-3 on udp/443). The assertion that matters, and what the test checks, is that the proxy observes the guest's intended destination.
- **Unprivileged:** egress interception at **L4 inside the smoltcp NAT** (cleaner than a privileged front-end, since there is no tap for nftables).

### 6.4 Operating modes: unprivileged vs privileged

The harness runs in one of **two named operating modes**, and the distinction is first-class — it governs the network datapath, the cgroup-delegation story, how tests are split into suites (§12.4), and (with §7) which operations may degrade vs must fail loud. The vocabulary is deliberate and replaces the older "rootless" wording, which over-implied "zero privilege":

- **Unprivileged operation** — the process holds **KVM-group access only** (`/dev/kvm` via the `kvm` group, granted once with `usermod -aG kvm $USER`) and **no extra Linux capabilities**. Networking is the in-process **smoltcp** userspace NAT (no tap, no netns); cgroup limits use whatever a `systemd-run --user` delegation provides. This is the deployable, no-elevation mode. KVM access is a *group membership*, not a capability — so "unprivileged" here means "no `CAP_*`," not "no access to anything."
- **Privileged operation** — the process holds **`CAP_NET_ADMIN`** (tap, rtnetlink, nft/TPROXY), **`CAP_SYS_ADMIN`** (per-test netns + `setns`), and **`CAP_DAC_OVERRIDE`**. Networking is the full **netns + tap + `/30`** path with L2 fidelity; it is the only mode eligible for the snapshot tier (§3.3) and the default for fidelity-sensitive tests. The caps are granted to the test binary alone via the **capability runner** `vmcell-test-runner` (§12.8), leaving cargo/rustc unprivileged and outputs dev-owned — *not* `sudo -E cargo test`, which runs the whole toolchain as root, taints `target/` with root-owned artifacts, and shifts cargo's environment (`sudo -E` or a dedicated root job remains the CI-only fallback).

**`CAP_DAC_OVERRIDE` is required and was missing from the v12 two-cap set (observed, v13).** The privileged tap path could never actually create a netns under the two-cap runner: `netns_rs::NetNs::new` must create `/var/run/netns/<name>`, a `root:root 0755` directory the dev-uid process can't write — `EPERM` — which masked the entire downstream tap path until fixed. `CAP_DAC_OVERRIDE` (added to the blessed set) also unblocks the benchmark-only sysfs/procfs knob writes (CPU-frequency pinning, KSM tuning — §13), since those `root:root` *kernfs* files honour `DAC_OVERRIDE` (whereas `drop_caches`, a procfs sysctl special-cased on `euid==0`, does not). So the blessed set is **three** caps: `cap_net_admin,cap_sys_admin,cap_dac_override`.

**Mode selection is probed and fail-loud, not discovered mid-run (§7).** Before a privileged-mode run the harness verifies it actually holds the three caps and that `/var/run/netns` is reachable; an unprivileged-mode run verifies KVM-group access. A requested mode whose prerequisites are absent **errors up front with the exact remediation**, rather than half-running and failing opaquely deep in a test. The two modes are exercised by **two named test suites** (§12.4), kept separate so the unprivileged path stays honestly exercised rather than always shadowed by the privileged one.

**Two host-environment caveats.** (1) The privileged tap path needs the harness in a **non-threaded `domain` cgroup scope** and, for limit enforcement, in a delegated leaf (§7) — run it under `systemd-run --user --scope -p Delegate=yes`. (2) Modern Ubuntu blocks the unprivileged-userns escape hatch by default (`kernel.apparmor_restrict_unprivileged_userns=1`) while Debian Trixie does not necessarily, so the host distro affects whether unprivileged mode gets off the ground. **Cleanup:** a killed privileged run can leak `/var/run/netns/vmcell-net-*` (occasionally colliding with a later vmid); `net::cleanup_orphan_netns(prefix)` (the rubric-B1 sweeper, run through the capability runner) reaps these — a periodic background sweeper is still partial (§15).

---

## 7. Monitoring, limits, and the fail-loud capability contract

One **cgroup v2 slice per VMM (and per virtiofsd) process**, with `ResourceLimits` applied and `memory.peak`/`memory.current`/`cpu.stat`/`io.stat` plus net counters read back. Peak comes for free from `memory.peak`; average is computed from periodic `cpu.stat`/`io.stat` deltas. The mapping is direct: `mem_max_mib`→`memory.max`, `cpu_max_pct`→`cpu.max`, `pids_max`→`pids.max`, `io_max`→`io.max`. All four `io.stat`/net counters in `ResourceUsage` must be **actually read**, not left as always-zero fields (a real defect the review caught — an unread counter is the same lie as a missing one).

### 7.1 The fail-loud capability contract

The v12 stance — "unprivileged delegation degrades gracefully" — was, in practice, an invitation to **silent no-ops**: a caller asks for a 256 MiB cap, the controller isn't delegated, the write fails, and the VM runs *unlimited* while the call returns `Ok`. The maintainer's directive (`todo.md`) reverses the default: **a missing capability fails loud unless the operation is explicitly classified as best-effort.** Three rules make this precise and uniform across the host-facing subsystems (cgroups here, netns/tap in §6.4, the sysfs knobs in §13):

1. **Every host-facing operation declares the OS capabilities it requires** — in its doc-comment and, where it gates a mode, in a queryable descriptor. This is the host-side analog of the per-backend `VmmCapabilities` (§3.1): just as a backend reports what it supports so callers never invoke an unsupported op, the orchestrator probes a **`HostCapabilities`** descriptor once at start-up — caps held (effective set, not permitted), cgroup controllers delegated to the per-VM cgroup's parent `subtree_control`, KVM-group access, `/var/run/netns` writability, whether the scope is a non-threaded `domain` — and selects the operating mode from it. **Status (v14):** the contract is realized today by *per-op* checks (a functional op returns `Error::CapabilityUnavailable` after testing the specific capability it needs — e.g. the controller's presence in `subtree_control`); consolidating those into a single queryable `HostCapabilities` descriptor probed once at start-up is the design target and remains forward work (§15).
2. **A *requested functional* operation that needs an absent capability returns a typed error, not `Ok`.** Asking for a resource *limit* that cannot be enforced is `Err(Error::CapabilityUnavailable { op, needed })` (matchable, carrying the exact missing capability and the remediation), surfaced before the VM is handed back — never a logged-and-ignored no-op. The orchestrator probes delegation up front, so the failure is at the boundary, not discovered after a test has run unbounded.
3. **Observation degrades; enforcement does not.** Reading a metric is inherently best-effort (you report what the kernel exposes), so *reads* fall back — e.g. read `memory.current`/`memory.peak` straight from sysfs when a controller's higher-level interface is absent — and surface what was unavailable through explicit booleans on `ResourceUsage` (`limits_enforced`, and per-metric availability) that the caller can assert on. The distinction is **requested-vs-observed**: a limit the caller *set* is functional (rule 2); a counter the caller *read* is observational (this rule).

A narrow, **explicitly-listed** best-effort tier remains for genuinely non-functional knobs — the §13 benchmark levers (CPU-frequency pinning, KSM acceleration) **must not** abort a run when they can't engage, since "benchmarks are tracked metrics, not gates" (§13.7). Those degrade to a **visible, unmissable `warn!`** (never silent) and a no-op guard. The dividing line is the test: *if a caller's assertion can be wrong because the operation silently did nothing, it is functional and must fail loud; if the only consequence is a less-controlled measurement, it is best-effort and warns.*

### 7.2 cgroup delegation mechanics

Limit enforcement under either operating mode runs into cgroup-v2 delegation edges, and they compound. The cgroup side effects sit behind an **injected `CgroupFs` trait** with a real impl (`DefaultCgroupFs`) and a recording fake — so sibling-placement, the controller-enable sequence, and the limit-file contents are unit-testable with no `/sys` writes (this seam was the one open testability gap in v12 §15; it is now closed).

- **Create the slice directly, not via a builder.** `DefaultCgroupFs::create_slice` `mkdir`s the per-VM cgroup and applies limits with **direct sysfs writes** — it does *not* use `cgroups-rs`'s `CgroupBuilder`, whose V2 path manipulates `subtree_control` and leaves the new cgroup rejecting `cgroup.procs` writes (`EOPNOTSUPP`) under common systemd layouts. The orchestrator reads `/proc/self/cgroup` to locate the runner's systemd-delegated slice (`Delegate=yes`) and places the VM cgroup relative to it. `delete_slice` is a direct `rmdir`.
- **The "no internal processes" rule** bites: a cgroup may hold processes *or* enable controllers for children, not both — and the harness process is itself internal — so the VM cgroup must be a **sibling** of the harness (move the harness into a `…/supervisor` leaf and place VM cgroups beside it; the orchestrator strips a `/supervisor` suffix when computing the path), not a child.
- **Write the PID directly** via `std::fs::write(cgroup/"cgroup.procs", pid)` — `cgroups-rs`'s `add_task()` raises a `CgroupMode` error on deeply nested unprivileged cgroups and can hang.
- **The scope must be a non-threaded `domain` cgroup (observed, v13).** A *threaded* scope — e.g. a GNOME-terminal `*-spawn-*.scope` whose `cgroup.type` is `domain threaded` — rejects `cgroup.procs` on its children regardless of `CAP_SYS_ADMIN`, because threaded subtrees move *threads* via `cgroup.threads`. Run the suites from a plain `domain` scope (`systemd-run --user --scope -p Delegate=yes …`).
- **Controller delegation is the gating capability.** Where the `memory`/`cpu` controllers aren't in the parent's `subtree_control`, a limit write fails `Operation not supported`. Per §7.1: a *requested* `memory.max` then fails loud (`CapabilityUnavailable`), and the limit-dependent test gates on controller availability as a **visible** precondition (skip-with-reason, never skip-as-pass); *reads* fall back to sysfs and set `limits_enforced=false`. Hard enforcement needs the privileged path or a confirmed `systemd-run --user -p MemoryMax=` delegation.

---

## 8. Guest OS and kernel

### 8.1 The base: Debian Trixie

The guest is a minimal **Debian Trixie (13, kernel 6.12 LTS)** rootfs. Debian 13 carries security support to 2028. The agent bypasses distro init (`init=/sbin/vmcell-guest-agent`), so a larger userland does not grow the boot working set.

### 8.2 Two rootfs sources, one erofs packer

Both sources produce a merged rootfs **tar**, which feeds a **shared tail**: inject `vmcell-guest-agent` + the proxy CA + the tmpfs/overlay scaffolding, then stream the tree through `am-fs-erofs` in memory (the `mkfs.erofs` binary is the fallback). The in-memory pack avoids creating device nodes or root-owned files on the host, so it runs **unprivileged**.

- **Default — OCI pull (host-native, in-Rust).** Resolve a Debian base image to a **manifest digest** (pin the digest, never the tag), pull manifest + config + layers with `oci-client` (no Docker/containerd daemon), verify every blob against its `sha256` digest, decompress each layer (`flate2`/`zstd`), and apply them in order honoring **OCI whiteout semantics** (`.wh.<name>` deletions and `.wh..wh..opq` opaque-dir markers) to produce the merged tar. The guest never sees OCI — this is OCI strictly as a *build-time source* feeding the erofs packer, so direct-kernel boot, snapshot/restore, and shared-RO-erofs density are unchanged. The only new linked crate is `oci-client` (Apache-2.0).
- **Full apt chain — `mmdebstrap` inside a builder micro-VM.** Build a builder rootfs via the OCI source (stock `debian:trixie-slim` + the agent), boot it on this project's own CH stack, then over the vsock agent run `apt-get install mmdebstrap` followed by `mmdebstrap` against the pinned snapshot — emitting the target rootfs as a tar on the `vmcell-out` rw share, which feeds the shared inject+pack tail. Because `mmdebstrap` runs as root inside a controlled guest, apt performs the full `InRelease`/`Release.gpg` chain verification in-guest (refuse-on-mismatch), Debian fidelity and `snapshot.debian.org` timestamp-reproducibility are preserved, and **`mmdebstrap`, `apt`, `gpg`, and the shell all leave the host entirely**.

The **bootstrap chain is acyclic and terminates**: kernel + OCI-built builder rootfs → builder VM → in-guest `mmdebstrap` → target tar → erofs. The OCI source needs no VM, so the recursion bottoms out there. The builder-VM boot is a build-time cost paid once per pin and cached; it does **not** touch per-test running time or VM density. The trade between the two sources is provenance vs convenience: the OCI default's digest pin is *integrity, not authenticity* unless a cosign/sigstore signature is also verified; the in-VM `mmdebstrap` source keeps the full apt signing chain for images that need it. Choose per profile and book the signing-chain drop as the explicit cost when using the OCI default (the resolution is detailed in Appendix B, Exp 4). **The size sub-argument for the builder VM inverted (observed, v13, §13.6):** the earlier hypothesis was that `mmdebstrap --variant=minbase` yields a *smaller* image; measured, the official OCI slim base is **~34% smaller apples-to-apples** (≈79 MB vs ≈120 MB trixie erofs; ~52% vs the cross-release ≈165 MB bookworm-minbase), because the official image carries `dpkg path-exclude` rules stripping `/usr/share/locale`/`doc`/man that a plain `mmdebstrap minbase` retains. So the in-VM `mmdebstrap` source now earns its keep on **provenance** (the full apt signing chain) and on **provisioning packages the slim base omits** (the `iproute2`/`curl` gap §5.3 also addresses via the guest-tools helper) — **not** on size, unless it adds those excludes.

**Bring-your-own base image — the `oci2erofs` utility (v15, `todo.md` #3).** The OCI source above is hardwired to the `pins.json` Debian base; v15 exposes the *same* source as a standalone utility so a caller can convert **any digest-pinned OCI image** into a vmcell-ready erofs rootfs: `vmcell oci2erofs IMAGE@sha256:DIGEST -o rootfs.erofs` (digest-pinned only — a tag is rejected, the §11.2 provenance hard stop). Per the maintainer's clarification, **this is build-time only and the VM-management verbs take the resulting erofs as their `rootfs` argument** (§10.2): OCI never becomes a runtime `RootfsSource` variant, so direct-kernel boot, snapshot/restore, and shared-RO-erofs density are unchanged — the guest still boots one read-only erofs over virtio-blk. Crucially, `oci2erofs` runs the **full existing rootfs pipeline**, not a stripped-down one: the shared inject+pack tail *requires* the `vmcell-guest-agent` (its absence is a hard error, not a silent skip), so the utility builds/reuses the agent + proxy CA + guest-tools and injects them exactly as the default source does — `oci2erofs` is `vmcell build`'s rootfs stage with the base image parameterized, content-addressed and cached per (image digest + injected-content + stage version), **not** a new code path that could drift from the default. Two honest constraints: (1) an arbitrary base may **omit the `libc6` the dynamic-glibc agent links against**, which would boot to a dead PID 1 — so the packer **scans the merged tar for `/lib64/libc.so.6` (or `/lib/*/libc.so.6`) in a single pass and fails loud before packing** with an actionable message, rather than emitting a rootfs that boots-and-dies (a silent-corruption class the §11.2 rules forbid); (2) a static-musl agent for `libc6`-less or non-glibc bases (Alpine, distroless-static) is an **explicit `--agent-musl PATH` opt-in**, never an automatic fallback — silently swapping the agent toolchain would violate the §7.1 fail-loud contract, and the musl agent build is not yet a reliably-available target (§13.3), so v15 commits the fail-loud check and leaves musl provisioning to the caller. The injectable OCI record/replay seam (§15) is still forward work; it is not required for the utility (the digest pin + blob cache give reproducibility), only for the requirement-7 record/replay tamper tests.

### 8.3 The guest-kernel config fragment

Direct-boot a custom-minimal `vmlinux` built from **Debian kernel source** with an explicit `microvm` fragment — **not** `kvm_guest.config` alone, which omits vsock, virtio-fs, and erofs and causes real boot failures. Which failure surfaces *first* is order-dependent: for `kvm_guest.config`-*alone* boot dies at the **erofs root-mount panic** (`VFS: Unable to mount root fs`) before it ever reaches userspace, so vsock is never exercised; the `EAFNOSUPPORT`-at-vsock symptom only appears on an *intermediate* config (erofs present, vsock absent). Everything the guest needs is built **in** (`=y`, no modules → no initramfs, nothing to probe):

```text
# Transport — CH uses virtio-pci; ALSO build virtio-mmio so Firecracker runs in
# MMIO mode and snapshots (one vmlinux serves CH over PCI and Firecracker over MMIO;
# FC defaults to MMIO (mature transport + shared vmlinux); FC v1.16 can also PCI-snapshot but MMIO stays its default — §3.2/A.3 #1)
CONFIG_PCI=y  CONFIG_VIRTIO=y  CONFIG_VIRTIO_PCI=y  CONFIG_VIRTIO_MMIO=y
# Core paravirtual devices
CONFIG_VIRTIO_BLK=y  CONFIG_VIRTIO_NET=y  CONFIG_VIRTIO_CONSOLE=y
CONFIG_HW_RANDOM_VIRTIO=y          # virtio-rng — also feeds the snapshot entropy reseed
CONFIG_VIRTIO_BALLOON=y            # density lever
CONFIG_IP_PNP=y                    # guest IP via kernel `ip=` cmdline → PID 1 needs no netlink
# vsock control plane  — MISSING from kvm_guest.config (EAFNOSUPPORT at vsock once erofs is present)
CONFIG_VSOCKETS=y  CONFIG_VIRTIO_VSOCKETS=y
# virtio-fs shared dirs — ALSO MISSING; the same failure waits here without these
CONFIG_FUSE_FS=y  CONFIG_VIRTIO_FS=y
# Filesystems: erofs RO root + tmpfs overlay (+ ext4 only if you keep a block fallback)
CONFIG_EROFS_FS=y  CONFIG_EROFS_FS_ZIP=y   # match the erofs builder's compressor; see note
CONFIG_OVERLAY_FS=y  CONFIG_TMPFS=y  CONFIG_EXT4_FS=y
# Console / early boot
CONFIG_SERIAL_8250=y  CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_DEVTMPFS=y  CONFIG_DEVTMPFS_MOUNT=y
# Paravirt clock (helps clock stability across pause/restore)
CONFIG_PARAVIRT=y  CONFIG_KVM_GUEST=y
# Nested virt: guest exposes /dev/kvm to inner VMs
CONFIG_KVM=y  CONFIG_KVM_INTEL=y          # or CONFIG_KVM_AMD=y
CONFIG_VHOST_VSOCK=y                       # only needed so an *inner* (L2) VM can use vsock
```

Two precisions:

- **`CONFIG_VHOST_VSOCK` is host-side.** It is *not* required in the guest for the base control plane — CH's vsock is a userspace implementation, so the base guest needs only `VSOCKETS` + `VIRTIO_VSOCKETS`. It earns its place in the *guest* kernel only for nested virt, when the L1 guest acts as host to an inner L2 VM that wants vsock.
- **erofs compression must match.** If the erofs builder compresses with lz4/zstd, the kernel needs the matching decompressor (`CONFIG_EROFS_FS_ZIP` for lz4; `…_ZIP_ZSTD`/`…_ZIP_LZMA`/`…_ZIP_DEFLATE` as applicable) or the mount fails. Building uncompressed sidesteps the dependency at a size/page-cache cost (the production packer ships **uncompressed**, §13.6).

**Pinned version and build toolchain (observed, v13).** The committed kernel is **Linux 6.12.94** (the Trixie-aligned 6.12 LTS line; §6 distribution-alignment), bumped from the v12-era 6.6.9. The bump also fixes a **from-scratch build break under modern toolchains**: gcc-15 defaults to C23, where `false`/`bool` are keywords, and `drivers/firmware/efi/libstub` is compiled without `-std=gnu11`, so a 6.6.9 build failed `cannot use keyword 'false' as enumeration constant`. 6.12.94 carries the `-std=gnu11` EFI-stub fix; independently, **cloud-hypervisor boots via PVH and never uses the EFI stub**, so `CONFIG_EFI_STUB=n` (or `KCFLAGS=-std=gnu11`) is a clean alternative. The 6.12.94 `vmlinux` is validated building *and booting* on a gcc-15.2.0 host.

**Kernel version is a tracked benchmark dimension, not just a pin.** `pins.json` carries a `kernels` registry (`<label> → {source_url, source_sha256}`, currently `6.6.143` and `6.12.94`) alongside the default `kernel`; `vmcell build-kernels` builds each to `vmlinux-<label>` (own build dir + cache sidecar; the on-disk filename sanitizes `.`→`-` so `with_extension` can't eat a dotted patch version), and `bench-vm --kernel <label>` sweeps the §13 suite per kernel. The erofs is **kernel-independent** (Debian userspace + injected agent), so one rootfs boots under any kernel. **Finding (§13):** an interleaved 6.6.143-vs-6.12.94 sweep shows the guest kernel version is **not a material hot-path lever** (warm restore within ~2%), settling the earlier cross-session "~2× slower" scare as host-load noise — the payoff of making kernel a dimension was *disproving* a wrong difference, not finding one.

**The config-fragment matrix (v15, `todo.md` #4).** v14's registry sweeps kernel *versions*; v15 extends the *same* `KernelStage` to sweep kernel *config variants* off one base source. A kernel is requested as **(base label, an ordered set of named KConfig fragments)** — e.g. `6.12.94 + [KASAN, LOCKDEP]`. `pins.json` gains a `kernel_fragments` registry mapping each name to a KConfig string (`KASAN → "CONFIG_KASAN=y\nCONFIG_KASAN_OUTLINE=y\n"`, `KCOV`, `LOCKDEP`, `SLUB_DEBUG`, a driver/tuning toggle); the build appends the requested fragments to the base `microvm_config` **in sorted-by-name order** before `make olddefconfig`, and the cache key folds the base SHA, the **sorted** fragment set, and a bumped stage-version constant. The mechanism is small — it extends the existing `KernelStage::cache_key` blake3 fold and the post-defconfig config-append, both already present — and is committed with the following scoping, because the *mechanism* being easy does not make the *matrix* free:

- **Determinism by sorted order.** Fragments are canonicalized to sorted order at hash time, so `[KASAN, LOCKDEP]` and `[LOCKDEP, KASAN]` resolve to the *same* `vmlinux-<base>-<fragment-hash>` — the §11.2 determinism invariant, not caller-order-dependent (KConfig is last-value-wins, so applied order would otherwise matter when two fragments touch the same key).
- **Fail loud on an unbuildable combo.** A non-zero `make olddefconfig` (unresolvable dependency, parse error) is an `Error::Artifact`, never a panic and never a silently-truncated config — incompatible combos are caught at build time, not at boot. *Caveat (documented, not silently handled):* `olddefconfig` resolves a *syntactically* valid merge even when two fragments are *semantically* at odds (it can drop a conflicting value), so a known-incompatible-pairs compatibility note + negative tests guard the cases `olddefconfig` would wave through.
- **Build-time blow-up is bounded by the cache, not free.** A cold KASAN/KCOV kernel build is ~45–90 min (vs ~15 for a baseline), and N bases × M combos multiplies; the content-addressed cache makes re-runs free, but a developer iterating fragments pays cold builds. CI therefore **batches tests by kernel label** and runs only a curated subset (base + one heavy + one light fragment) on the per-commit gate, leaving the full matrix to a nightly/release job — a deliberate bound, logged so the coverage gap is visible, not a silent truncation.
- **Strictly a pipeline concern (keep-general).** `KernelStage` is the only touch; `VmConfig`/agent/VMM see only a `kernel: PathBuf` that happens to be a fragment-built `vmlinux`. **Out of scope by construction:** **PREEMPT_RT** is *not* a config fragment — it needs an rt-*patched* source, so it would be a separate `kernels`-registry source, not an overlay; and **KCOV coverage *extraction*** needs a guest-side helper driving the kcov ioctl (the §16.2 item) — the fragment turns the kernel *capability* on, but reading the data out is a consumer layer. The **per-test invocation API** (how a test names "6.12.94 + KASAN") is left as forward work; v15 commits the build seam, not the test-harness ergonomics.

### 8.4 The kernel command line

```text
console=ttyS0 root=/dev/vda rootfstype=erofs ro
ip=10.200.<vmid>.2::10.200.<vmid>.1:255.255.255.252::eth0:off
init=/sbin/vmcell-guest-agent
```

The `ip=` parameter (enabled by `CONFIG_IP_PNP=y`) sets the guest address at boot — consumed by the kernel's IP-PNP late-initcall, not an initramfs — so PID 1 needs no netlink in either networking mode (the unprivileged smoltcp NAT uses a matching subnet). Nested virt adds `kvm-intel.nested=1` on the guest cmdline (and the host KVM module needs `nested=1`). If a block-ext4 fallback rootfs is ever used, add `rootflags=noload` so the ext4 driver mounts strictly read-only without journal recovery — recovery is a write and panics on a read-only device; erofs has no journal, so the default path needs no such flag.

---

## 9. Snapshot, restore, and density

### 9.1 The warm-snapshot path

The per-test speed lever is **warm snapshot + restore**: boot the erofs-rootfs base to "agent-ready," snapshot once, and per-test restore + add a tmpfs overlay. This skips kernel boot on the hot path and is measured at **≈3.7× faster than cold boot on CH and ≈8× on Firecracker** (§13). The erofs RO base needs **no per-test copy** (it is shared read-only), and the only writable per-test state is a tmpfs overlay. The snapshot tier is {CH, Firecracker} today — plus a validated-but-unwired QEMU privileged tier (§3.3) — on the privileged/tap path with a non-vhost-user vsock and **no virtio-fs data shares** (§3.3 — read-only data is served as an extra erofs/block image there, not virtiofsd). The mechanics: snapshot = `pause`→snapshot→(`resume` or stay paused for immediate kill); restore returns a **paused** instance the caller `resume()`s — never `boot()`/`create()`. The on-disk size of a suspend image **tracks guest RAM exactly** and is flat in rootfs size (a 256 MiB-RAM guest writes an ≈256 MiB memory file whether the rootfs is slim or fat — measured, §13.6), so an N-snapshot warm pool costs ≈N×guest-RAM on disk; restoring **many clones from one snapshot** therefore needs a copy-on-write of the snapshot dir first (the in-place `config.json`/sidecar rewrites of §3.2 are single-use).

### 9.2 Restore correctness

A restored snapshot resumes at the exact instruction it was taken, so restored clones share whatever state was frozen in. Things must be refreshed on **every** restore, not just at first boot. The resync fires once, on the **first post-restore `agent()` call** (the orchestrator tracks restored-ness), after the vsock reconnect succeeds:

- **Identity (CID) — uniqueness among *live* clones, not a forced numeric change.** The vsock CID must be unique across *concurrently running* restored clones so they don't collide. It is **not** required to differ from a torn-down original: the `CidAllocator` hands out the lowest free CID and **reuses freed CIDs by design** (a contract four tests assert via `Drop` returning the CID). So the correct check on a *sequential* restore is "the restored guest has a valid, live CID," **not** `assert_ne!(original_cid, restored_cid)` — the latter is over-specified and fails precisely because reuse is correct (a real test-correctness fix, v13). Concurrency-uniqueness is what the allocator's property test pins.
- **Identity (MAC) — rotated at the device layer, *not* via netlink; the IP is left alone.** MAC rotation is the one in-guest identity change the snapshot path performs, via a single `ip link set eth0 address <mac>` (the `SIOCSIFHWADDR` ioctl implemented by the guest-tools helper §5.3) — a device-layer write, consistent with the zero-netlink-in-PID-1 contract (§4.3). **The IP address is deliberately *not* rotated on restore.** The v11-era attempt to re-run `ip addr flush dev eth0 && ip addr add …` inside the guest was wrong (review DESIGN-DIVERGENCE-2): `ip addr flush` drops the IP-PNP default route, breaking post-restore egress to non-local destinations, and it re-introduces exactly the in-guest netlink the design forbids. The guest keeps the address the kernel `ip=` cmdline set; `ip addr`/`ip route` *write* forms are accepted as no-ops by the helper so an orchestrator `&&`-chain still succeeds. No test exercises a post-restore IP change, so this is a clean simplification, not a gap.
- **Entropy** — reseed via virtio-rng (rotate the RNG state / surface a VMGenID-style change). An unreseeded `getrandom()` can stall first use by seconds, and because every clone resumes at the same frozen instant, RNG reuse is otherwise silent and correlated.
- **Clock** — a snapshot resumed much later resumes with a stale wall clock. kvm-clock keeps the *monotonic* source sane, but the RTC/wall clock is frozen at the snapshot instant. The guest **cannot fix this from inside**: `hwclock --hctosys` reads the *restored* RTC (the old snapshot time) and sets the system clock *backwards*; and a restored snapshot may have networking disabled, so there is no in-guest NTP either. The resync is therefore **host-driven and mandatory for any time-sensitive test**: immediately after the post-restore vsock reconnect, the host reads `SystemTime::now()` and pushes it to the agent, which sets the clock (e.g. `date -s`). For purely ephemeral tests a stale clock is cosmetic; for anything that asserts on timestamps it is not.

**The post-restore vsock reconnect itself is mandatory and was the hardest restore bug to close (§4.2).** It is not a no-op, and on CH it is not merely "reuse the surviving listener": CH `--restore` rebuilds devices from the snapshot's `config.json` (so the spawn step must rewrite the now-defunct vsock/serial paths first, §3.2) **and** re-creates the vhost-vsock device, leaving the guest's pre-snapshot bound listener deaf — so the guest agent must serve connections thread-per-connection and **re-`bind`** after a bounded idle (§4.3) for the host's `reconnect` to land. Firecracker needs the analogous host-UDS sidecar fix (§3.2).

### 9.3 Density levers

RAM is the binding limit on parallelism. With DAX unavailable in CH (§14), density rests on:

- **`cache=never`** on virtio-fs shares (minimal footprint).
- **The shared erofs RO base** — one host-cached copy of the image for all concurrent guests (§5.1).
- **virtio-balloon / free-page-reporting** for reclaim under host pressure.
- **KSM — opt-in, and a no-op by default on CH (observed, v13).** CH backs guest RAM with a **shared memfd** (`shared=on` → it lands in the VMM's `RssShmem`), and KSM only merges **private-anonymous** pages, so global KSM deduplicates **0** of default-config guest RAM. The lever is therefore an explicit `VmConfig::ksm_mergeable` that sets CH's `mergeable=on` **and** `shared=off` together (the coupling is mandatory). Measured, it then deduplicates **≈394 MiB / ~84%** across 8 identical 256 MiB guests — a large win for N-identical-guest workloads. The cost is that `shared=off` is **mutually exclusive with every vhost-user path** (the unprivileged NAT, virtio-fs shares), plus KSM scan CPU — so it stays **off by default** and is selected per workload.

**Measured footprint (§13.3), replacing the v12 "128–256 MiB/guest, re-benchmark" placeholder:** each CH guest demand-pages **≈58 MiB of its 256 MiB** (the guest userland, not the ≈1 MiB VMM `RssAnon` overhead, dominates; the agent PID 1 is ≈2.4 MiB), and the marginal RAM per added guest is dead-linear at ≈57–58 MiB. So the RAM-tier ceiling is ≈13 GiB / 58 MiB ≈ **~230 idle guests** (≈**52** if each faults in its full 256 MiB under load). The next limits after RAM are typically one-virtiofsd-per-VM (mitigated by the in-process `fuse-backend-rs` experiment), tap/netns/nft (or the in-process NAT's per-VM threads) scaling, and host FD/PID limits. Each lever's effectiveness is a tracked number (§13.5).

---

## 10. The Rust library (`vmcell`)

This section covers the crate layout, the public API surface, each module's responsibility, the in-crate-vs-external-tool decision per capability, and the accommodations that make the orchestrator unit-testable.

### 10.1 Crate and workspace layout

A Cargo **workspace** (2024 edition), promoted in v15 from the single v14 package (`todo.md` #2). The workspace root is a pure `[workspace]` (no root `[package]`); its members are the `vmcell` **library**, a tiny shared **`vmcell-protocol`** crate (the framed postcard wire enum, the *only* code the host and the guest agent share), and three lean **binary member crates** for the privileged-window / guest binaries — `vmcell-test-runner`, `vmcell-guest-agent`, `vmcell-guest-tools` — each with its own `Cargo.toml`, dependency closure, and lint header. The `vmcell` library (with the `vmcell` CLI and `bench-vm`) stays one package compiled with the single `host` feature (§10.5). **Why a workspace (the durable answer to the re-bless churn, §12.8):** a member crate's build fingerprint depends only on its own (tiny) source + deps, so the §12.2 lean-tree assertion becomes a *structural per-member property* and no host module can leak into the runner by construction. Extracting `vmcell-protocol` is what lets `vmcell-guest-agent` be a standalone member without a dependency edge on the whole library; `vmcell-test-runner` already imports no library code (`rustix`/`capctl`/`libc` only), so it is a clean lift. The workspace is *not*, by itself, the fix for the re-bless pain — members share `target/` and `RUSTFLAGS`, so the **stable-path install + content-hash stamp** of §12.8 remain load-bearing and compose with the split. The `[patch.crates-io]` vhost fork (§10.5) moves to the workspace root. The pre-v15 single-package tree below maps onto the workspace one-to-one (`src/lib.rs` → `crates/vmcell/src/lib.rs`, `src/bin/vmcell-test-runner.rs` → `crates/vmcell-test-runner/src/main.rs`, `src/agent/protocol.rs` → `crates/vmcell-protocol/src/lib.rs`, etc.); it is kept here as the module map:

```
vmcell/
├─ Cargo.toml                 # edition = "2024"; [lib] + [[bin]] targets
├─ deny.toml                  # cargo-deny: permissive-license allow-list, advisory DB
├─ rustfmt.toml               # clippy is config-via-CI
├─ README.md                  # external tools + install, CLI usage, benchmark-results summary
├─ src/
│  ├─ lib.rs                  # re-exports the public API; crate docs
│  ├─ config.rs               # VmConfig, Share, NetConfig, ResourceLimits, NestedVirt …
│  ├─ vmm/
│  │  ├─ mod.rs               # `Vmm` + `VmInstance` traits, shared types, Cid allocator
│  │  ├─ cloud_hypervisor.rs  # subprocess supervisor + REST client (primary)
│  │  ├─ firecracker.rs       # optional dense backend (feature = "firecracker")
│  │  └─ qemu.rs              # optional fallback (feature = "qemu")
│  ├─ agent/
│  │  ├─ mod.rs               # AgentClient (host side, tokio-vsock/AF_UNIX, retry/handshake)
│  │  └─ protocol.rs          # framed wire protocol (shared by host + guest agent)
│  ├─ fs.rs                   # virtiofsd supervision: one per share, perms, tags, sockets
│  ├─ net/
│  │  ├─ mod.rs               # NetConfig dispatch: privileged vs unprivileged
│  │  ├─ tap.rs               # netns + tap + /30 addressing (rtnetlink); nft TPROXY emission
│  │  └─ userspace.rs         # unprivileged: smoltcp + vhost-user-backend NAT (L4 interception)
│  ├─ proxy/
│  │  ├─ mod.rs               # EgressProxy: listen, log, filter, dispatch
│  │  ├─ tls.rs               # MITM CA, on-the-fly cert minting (rcgen/rustls)
│  │  └─ doubles.rs           # test-double + record/replay (cassette) hooks
│  ├─ metrics.rs              # CgroupFs trait (injected: real + recording fake) + slice mgmt + peak/avg
│  │                          #   readers; create_slice writes sysfs directly (NOT cgroups-rs builder, §7.2)
│  ├─ cpufreq.rs              # benchmark-only: CpuFreqSysfs seam; pin governor/turbo, RAII restore-on-drop
│  ├─ net_sys.rs              # the ONE unsafe ioctl spot net/ can't host (TUNSETPERSIST); net is forbid-unsafe
│  ├─ artifact/
│  │  ├─ mod.rs               # Stage trait, Pipeline, cache, record/replay, signing; artifacts_dir() helper
│  │  ├─ kernel.rs            # vmlinux build stage (+ config fragment, §8); version-aware (multi-kernel registry)
│  │  ├─ tar2erofs.rs         # in-memory tar→erofs (am-fs-erofs Node tree) + OCI whiteout application
│  │  ├─ rootfs/
│  │  │  ├─ mod.rs            # rootfs build stage: source dispatch, shared agent+CA+guest-tools inject, erofs pack
│  │  │  ├─ oci.rs            # default source: pull by digest, verify blobs, apply layers (whiteouts) → tar
│  │  │  ├─ guest_tools.rs    # GuestToolsStage: build vmcell-guest-tools, inject into the rootfs (§5.3)
│  │  │  └─ mmdebstrap_vm.rs  # full-apt source: drive `mmdebstrap` inside a builder micro-VM, collect tar
│  │  └─ snapshot.rs          # warm-snapshot build stage
│  ├─ orchestrator.rs         # MicroVm handle tying it together; ordered Drop teardown; sweeper
│  └─ error.rs                # crate Error/Result (thiserror)
├─ src/bin/
│  ├─ vmcell.rs          # CLI wrapping the lib (clap): build, build-kernels, oci2erofs, run, create,
│  │                     #   snapshot, stats, destroy (v15); ls/rm deferred to the impd daemon (§16.2)
│  ├─ vmcell-guest-agent.rs      # guest PID 1 (dynamic-glibc default; static-musl optional)
│  ├─ vmcell-guest-tools.rs      # guest multicall: real ip/curl/kvm-ok, baked into the rootfs (§5.3)
│  ├─ vmcell-test-runner.rs      # privileged-test cap runner (§12.8): file-caps → ambient caps → exec as dev uid
│  └─ bench-vm.rs             # macro/VM-level benchmark harness (§13); shares the cap runner
└─ tests/                     # one integration test per capability / VM operation
   ├─ boot.rs                 ├─ exec_vsock.rs        ├─ shares_ro_rw.rs
   ├─ host_endpoint.rs        ├─ egress_proxy.rs      ├─ metrics_limits.rs
   ├─ nested_virt.rs          ├─ snapshot_restore.rs  └─ lifecycle.rs
```

`vmcell-guest-agent` and `vmcell-test-runner` are deliberately thin, and in v15 *structurally* so as workspace members. The agent shares only the small **`vmcell-protocol`** crate (the framed wire enum) with the host — no other library edge. The cap runner must be **blessed** once with privileges (file caps or setuid), and that blessing is stripped whenever the file is rewritten; it depends only on `rustix` + `capctl` + `libc`, pulls in no async runtime and **not** the `vmcell` library, so neither library churn nor a host-dep bump recompiles it. Library churn was never the *dependency-edge* reason the runner re-emitted (it has no such edge) — the re-emit came from cargo's `RUSTFLAGS`/feature **fingerprint** churn over a shared `target/`, which §12.8 neutralizes by `setcap`-ing a copy installed to a stable path *outside* `target/` (with an idempotent content-hash stamp). Keeping the runner tiny is also a security property — every dependency is code that runs inside the privileged window.

### 10.2 Public API surface

Types are `#[non_exhaustive]` where future fields are likely; builders keep call sites stable. Async is via native `async fn` in traits; `#[async_trait]` only where `dyn Vmm` object-safety is required.

```rust
// ---- config.rs ------------------------------------------------------------
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct VmConfig {
    pub vcpus: u8,
    pub mem_mib: u32,
    pub kernel: PathBuf,        // vmlinux (direct kernel boot)
    pub rootfs: RootfsSource,   // Erofs { image } (default) | Block { image, overlay } | VirtioFs { dir }
                                // Erofs/Block are virtio-blk → all backends; VirtioFs rootfs needs capabilities().virtio_fs_shares
    pub shares: Vec<Share>,     // virtio-fs mounts; need capabilities().virtio_fs_shares — Firecracker passes
                                // inputs as block devices or skips share-dependent scenarios
    pub net: NetConfig,
    pub nested_virt: bool,      // build/boot guest kernel with KVM exposed; needs capabilities().nested_virt (not Firecracker)
    pub snapshotting: bool,     // this VM will be snapshot/restored → build() REJECTS it with ANY vhost-user
                                // device (virtio-fs rootfs OR any Share OR NetConfig::Unprivileged) — the §3.3 law
    pub restore_mode: RestoreMode, // Default | Eager | Lazy → CH --restore prefault=on|off (§9.2, §13); #[non_exhaustive]
    pub ksm_mergeable: bool,    // opt-in KSM: CH mergeable=on + shared=off; mutually exclusive with vhost-user paths (§9.3)
    pub limits: ResourceLimits, // cgroup caps; a *requested* limit that can't be enforced fails loud (§7.1)
}
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub enum RestoreMode { #[default] Default, Eager, Lazy } // Lazy (userfaultfd) resumes ~1.5× faster (≈82 ms); cost reappears as first-touch faults (§13)
impl VmConfig { pub fn builder(kernel: impl Into<PathBuf>) -> VmConfigBuilder { /* … */ } }

#[derive(Clone, Debug)]
pub struct Share {
    pub tag: String,            // guest mount tag, e.g. "vmcell-in" (caller-defined)
    pub host_path: PathBuf,
    pub access: Access,         // ReadOnly | ReadWrite
    pub cache: CachePolicy,     // Never (default) | Auto | Always
    pub guest_path: PathBuf,    // in-guest mount point; default "/<tag>", set via Share::with_guest_path (§5.2)
}
pub enum Access { ReadOnly, ReadWrite }

#[derive(Clone, Debug)]
pub enum NetConfig {
    /// Full L2 fidelity; needs CAP_NET_ADMIN (capability runner / privileged CI).
    Privileged { egress: Egress, host_services: bool },
    /// Unprivileged via an in-process smoltcp NAT; egress interception at L4 inside the NAT.
    /// Needs capabilities().unprivileged_vhost_user_net (not Firecracker).
    Unprivileged   { egress: Egress, host_services: bool },
    None,
}
pub enum Egress { Filtered(ProxyConfig), Blocked, Open }

#[derive(Clone, Debug, Default)]
pub struct ResourceLimits {     // None => unlimited; maps to cgroup v2 keys
    pub mem_max_mib: Option<u32>,    // memory.max
    pub cpu_max_pct: Option<u32>,    // cpu.max
    pub pids_max:    Option<u32>,    // pids.max
    pub io_max:      Option<IoMax>,  // io.max
}

// ---- vmm/mod.rs -----------------------------------------------------------
pub trait Vmm: Send + Sync {
    type Instance: VmInstance;

    /// What this backend supports. Callers MUST consult this before invoking an optional op or
    /// configuring an optional device; the orchestrator selects a backend per tier from it, and the
    /// test/bench harness SKIPS — does not fail — scenarios a backend can't run. Reported, not assumed.
    fn capabilities(&self) -> VmmCapabilities;

    /// Cold path: spawn + configure the backend (does not start the guest yet) → boot().
    async fn create(&self, cfg: &VmConfig, res: &PerVmResources) -> Result<Self::Instance>;

    /// Warm path: restore from a snapshot. Returns a PAUSED instance — the caller continues with
    /// resume(), NEVER boot()/create(). Returns Error::Unsupported when capabilities().snapshot_restore
    /// is false OR cfg carries any vhost-user device (the §3.3 law; also rejected at config::build()
    /// and orchestrator::restore()). Takes cfg to reconstruct the NON-vhost-user device topology —
    /// the rootfs/block args and the tap/net wiring — which lives in the config, not the snapshot file.
    /// It must NOT attach virtiofsd on this path: a snapshot-eligible VM has no virtio-fs daemon (the
    /// subtle conflation review 34 C1 flagged). The MECHANISM is backend-specific and kept out of this
    /// contract: CH launches a new process with --restore (rewriting the snapshot config.json's now-
    /// defunct vsock/serial paths first, §3.2) then needs an explicit vm.resume; Firecracker (MMIO)
    /// POSTs /snapshot/load {resume_vm:false} (leaving the VM paused, symmetric with CH), reads its
    /// vmcell_host_paths.json sidecar and unlinks the stale vsock UDS so the bind succeeds (§3.2);
    /// QEMU reports snapshot_restore:false over the unprivileged vsock path; ✓ possible in the privileged
    /// in-kernel-vhost-vsock config (validated, unwired). All restorable backends reset the
    /// vsock device on restore, and on CH the guest must re-bind its listener — see AgentClient::reconnect.
    async fn restore(&self, snapshot: &Path, cfg: &VmConfig, res: &PerVmResources) -> Result<Self::Instance>;
}

/// Backend capability descriptor. Each field is a property of the PINNED VMM build and must be
/// re-confirmed against it, not hard-coded. An optional op invoked on a backend that lacks it
/// returns Error::Unsupported { vmm, feature } rather than panicking.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct VmmCapabilities {
    pub snapshot_restore: bool,         // CH ✓; Firecracker ✓ via MMIO; QEMU ✗ over unprivileged vsock, ✓ possible privileged in-kernel-vhost-vsock (validated, unwired).
    pub lazy_restore: bool,             // demand-paged restore: CH memory_restore_mode, Firecracker UFFD.
    pub virtio_fs_shares: bool,         // CH, QEMU. NOT Firecracker (block-only).
    pub unprivileged_vhost_user_net: bool,  // smoltcp NAT via vhost-user-net: CH, QEMU. NOT Firecracker.
    pub nested_virt: bool,              // expose /dev/kvm to the guest: CH, QEMU. NOT Firecracker.
}

pub trait VmInstance: Send {
    async fn boot(&mut self) -> Result<()>;            // cold start (after create)
    async fn pause(&mut self) -> Result<()>;           // REQUIRED before snapshot
    async fn resume(&mut self) -> Result<()>;          // after snapshot, and after restore
    async fn request_shutdown(&mut self) -> Result<()>;// graceful (ACPI)
    async fn kill(&mut self) -> Result<()>;            // force-terminate VMM process group
    /// Pauses internally, writes the snapshot, then resumes (or stays paused for immediate kill).
    async fn snapshot(&mut self, dir: &Path) -> Result<()>;
    async fn stats(&self) -> Result<ResourceUsage>;    // live counters
    fn vsock_path(&self) -> &Path;                     // AF_UNIX endpoint (changes across restore)
    fn guest_cid(&self) -> u32;                        // unique per running VM (>= 3)
    fn serial_log(&self) -> &Path;                     // per-VM panic/early-boot log
}

// ---- agent/mod.rs ---------------------------------------------------------
pub struct AgentClient { /* tokio-vsock connection */ }
impl AgentClient {
    /// Opens the host-side vsock endpoint and performs the readiness handshake, retrying until the
    /// guest sends `Ready`, OR timeout, OR the serial log shows a panic (fail fast). Read the
    /// `OK <port>\n` line with EXACT 1-byte reads, never a BufReader (which pre-fetches and discards
    /// the first framed payload); then hand the unbuffered stream to the codec.
    pub async fn connect(vsock_path: &Path, port: u32, timeout: Duration, serial_log: &Path) -> Result<Self>;
    /// Re-establish after a snapshot restore. Backends reset the vsock device on restore (the guest
    /// sees EOF), and on CH the guest's pre-snapshot listener goes *deaf* once the vhost-vsock device
    /// is re-created, so the guest **re-`bind`s** its listener (§4.2/§9.2) and this retries until the
    /// fresh listener accepts — fast, but NOT a no-op, and NOT merely "reuse the surviving socket".
    pub async fn reconnect(vsock_path: &Path, port: u32) -> Result<Self>;
    pub async fn exec(&mut self, cmd: ExecRequest) -> Result<ExecOutcome>;
    pub async fn put_file(&mut self, dst: &str, bytes: &[u8]) -> Result<()>;
}
pub struct ExecRequest {
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<String>,
    /// Per-exec timeout. MUST be per-request: a normal test command wants a short fail-fast (default
    /// 10 s), but the in-VM `mmdebstrap` source runs apt for minutes. None => a sane bounded default,
    /// never unbounded.
    pub timeout: Option<Duration>,
}
pub struct ExecOutcome { pub code: i32, pub stdout: Vec<u8>, pub stderr: Vec<u8> }

// ---- proxy/mod.rs ---------------------------------------------------------
pub struct EgressProxy { /* … */ }
impl EgressProxy {
    pub async fn start(cfg: ProxyConfig) -> Result<Self>;
    pub fn ca_cert_pem(&self) -> &[u8];                // baked into the rootfs trust store
    pub fn requests(&self) -> RequestLog;              // observed requests, for assertions
    pub fn install_double(&self, m: Matcher, r: Responder); // "great extra"
    pub fn record_to(&self, cassette: &Path);          // record/replay (eval-layer hook)
}

// ---- metrics.rs -----------------------------------------------------------
#[derive(Clone, Debug)]
pub struct ResourceUsage {
    pub mem_peak_mib: u64,  pub mem_current_mib: u64,
    pub cpu_usec: u64,      pub io_read_bytes: u64, pub io_write_bytes: u64,
    pub net_rx_bytes: u64,  pub net_tx_bytes: u64,
    pub limits_enforced: bool,  // false when the cgroup controller wasn't delegated (unprivileged, §7)
}

// ---- orchestrator.rs ------------------------------------------------------
/// The handle most tests hold. Owns all per-VM resources; Drop force-cleans in order.
pub struct MicroVm<V: Vmm> { /* instance, cgroup, net, virtiofsd procs, cid, overlay */ }
impl<V: Vmm> MicroVm<V> {
    pub async fn start(vmm: &V, cfg: VmConfig, ids: Arc<VmidAllocator>) -> Result<Self>; // create; allocator INJECTED, shared
    pub fn vmid(&self) -> u32;                          // cheap Copy metadata
    pub fn proxy(&self) -> &EgressProxyHandle;
    pub async fn agent(&mut self) -> Result<&mut AgentClient>;
    pub async fn usage(&self) -> Result<ResourceUsage>; // stats
    // ---- v15: unified lifecycle verbs, promoted to first-class MicroVm methods ----
    // pause/resume/snapshot lived on the VmInstance trait (reachable only via instance_mut()); v15 lifts them
    // to MicroVm so the library, CLI, and (future) daemon share ONE verb surface. This is a deliberate,
    // cargo-semver-checks-visible public-API addition (§10.2/§16.1). They forward to the instance, preserving
    // the existing pause→snapshot→resume internals; snapshot() is snapshot-eligible-only and returns
    // Error::Unsupported on a vhost-user VM (the §3.3 law, already enforced at config::build()).
    pub async fn pause(&mut self) -> Result<()>;
    pub async fn resume(&mut self) -> Result<()>;
    pub async fn snapshot(&mut self, dir: &Path) -> Result<()>;
    pub async fn shutdown(self) -> Result<()>;          // destroy: graceful, then verify gone (Drop force-cleans)
    // DEFERRED, not in v15 (kept here as the contract the daemon will satisfy):
    //   • fork() — snapshot a live VM, restore a divergent clone. Even a correctness-only full-snapshot-copy
    //     fork needs the per-backend single-use config.json/sidecar rewrite generalized; the efficient CoW
    //     form is the §16.2 OverlayStore item (E:high). Snapshot-eligible tier only.
    //   • list()/rm() — a meaningful cross-invocation registry needs VMs to OUTLIVE their creator, which
    //     collides with MicroVm's ordered-Drop-owns-cleanup invariant; that is the impd daemon (§16.2),
    //     not a MicroVm method. Within one process, the caller already holds its handles.
    // NOTE: agent() borrows all of MicroVm mutably for the lifetime of the returned ref, so read the
    // cheap immutable metadata (vmid/proxy) into locals BEFORE calling agent(), or hand the agent
    // handle out disjointly. vmid()/proxy() stay &self/Copy so the read-first pattern is always available.
}
impl<V: Vmm> Drop for MicroVm<V> { /* kill VMM proc-group → virtiofsd → tap/netns/cgroup/overlay/sockets */ }

// ---- artifact/mod.rs ------------------------------------------------------
pub trait Stage {
    fn name(&self) -> &str;
    fn cache_key(&self, inputs: &StageInputs) -> CacheKey;  // pure
    async fn run(&self, inputs: &StageInputs, out: &Path) -> Result<StageOutputs>;
}
pub struct Pipeline { stages: Vec<Box<dyn Stage>> }
impl Pipeline {
    pub async fn build(&self, cache: &Cache) -> Result<Artifacts>; // skip stages whose outputs exist
    pub fn reset_to(&self, stage: &str, cache: &Cache) -> Result<()>; // remove later outputs
}
```

A process-global concern lives in `vmm/mod.rs`: the **CID and VMID allocators must be process-global** — a single shared instance per test-runner process, not one per test. Under `cargo test`'s in-process parallelism, per-test allocators hand concurrent tests identical IDs, colliding on temp-dir paths and socket names. The fix is one global `Mutex`-guarded free-list per ID type, still *injectable* (`Arc<…>`) for unit testing. The VMID is substituted into an IPv4 octet (`10.200.<vmid>.{1,2}`), so it is mapped into `1..=254` via `(n % 254) + 1` — a raw atomic could exceed 255 and synthesize invalid addresses. **This caps a single host/process at ≈254 concurrent VMs on one `/16`**; beyond that the address scheme must widen to a second octet (a real ceiling against the §13 density target).

### 10.3 Module responsibilities

- **`config`** — Pure data + builders. No I/O, so trivially unit-tested: builder defaults; and `build()` returns `Result` and **rejects, each with its own negative test** (§12.3): duplicate share tags; `snapshotting` combined with a virtio-fs *rootfs*, **any** virtio-fs data `Share`, or `NetConfig::Unprivileged` (the §3.3 law, all three vhost-user cases — not just the rootfs); `vcpus == 0`; `mem_mib` below the floor; an empty kernel path; an out-of-range vmid. Builder chain methods are `#[must_use]`. Not a bare struct.
- **`vmm`** — The trait boundary and backends (§3). `cloud_hypervisor` owns process spawning, the REST payload, lifecycle calls, counters, and snapshot/restore. `firecracker`/`qemu` are feature-gated, implement the same traits, and differ in mechanism and what `capabilities()` reports. A backend invoked for an op it does not advertise returns `Error::Unsupported`, never a panic.
- **`agent`** — `protocol` is the shared framed enum; `mod` is the host client with the hybrid-vsock handshake, retry, and serial-panic watch (§4). The guest side in `src/bin/vmcell-guest-agent.rs` runs as PID 1 (§4.3).
- **`fs`** — virtiofsd supervision: one per share, perms, tags, sockets, the socket-wait timeout, and the snapshot caveat (§5.2). The in-process `fuse-backend-rs` alternative lives here behind `experiment-fuse`.
- **`net`** — Two implementations behind `NetConfig` (§6): `tap` (privileged netns+tap+`/30` via rtnetlink, nft TPROXY emission) and `userspace` (unprivileged smoltcp + vhost-user-backend NAT with L4 interception). Pure parts (the `/30` math, the nft-ruleset render) are unit-tested; the netlink calls, the `nft` invocation, and the packet loop are the side-effecting part.
- **`proxy`** — The `hyper`/`hudsucker` MITM proxy with logging, filtering, and doubles; one proxy, two front-ends (§6.3).
- **`metrics`** — The per-VM cgroup v2 slice, limit application, and peak/avg readout behind the injected `CgroupFs` seam (real impl writes sysfs directly; recording fake for unit tests). Per §7.1: a *requested* limit that can't be enforced **fails loud** (`Error::CapabilityUnavailable`); *reads* fall back to sysfs and surface `limits_enforced=false`. cgroup logic lives here, not scattered across the orchestrator and a backend.
- **`artifact`** — The staged build pipeline (§11): a `Stage` trait with a pure `cache_key`, a `Pipeline::build` that skips stages whose outputs exist, and `reset_to` for invalidation. The rootfs stage has two interchangeable sources feeding one shared inject+pack tail (§8.2). The in-VM `mmdebstrap` path is the one place the pipeline depends on the runtime (it boots a builder VM via this crate's own machinery); the dependency edge is acyclic because the builder VM's rootfs comes from the OCI source, which needs no VM.
- **`orchestrator`** — `MicroVm` composes everything and owns **ordered** `Drop` teardown (VMM proc-group → virtiofsd → tap/netns/cgroup/overlay/sockets), so a panicking test cannot leak host resources and the netns isn't torn down under a live process; a periodic sweeper reaps anything orphaned by a hard crash.
- **`error`** — One `Error` enum (`thiserror`) with variants per subsystem; `Result<T> = std::result::Result<T, Error>`.
- **`bin/vmcell`** — `clap`-based CLI: `build` / `build-kernels` / `run` / `exec` / `ls` / `rm` / `stats`. The library API is the product surface; `build`/`build-kernels` are implemented. Any subcommand still pending argument design (§15) **returns a typed "not implemented" error and a non-zero exit — it must never print success while doing nothing** (a stub that returns `Ok(())` and prints OK is the silent-no-op failure the fail-loud directive forbids, §7.1). The **README documents the CLI subcommands/capabilities** (`build`/`build-kernels`/`run`/`exec`/`ls`/`rm`/`stats`) and **summarizes the benchmark results** (§13 / `docs/benchmark-results.md`), per the requirements — not just external tools + install.

### 10.4 Dependency strategy

Implementation avenues are ranked — *best:* our own well-documented Rust; *great:* a permissive crate; *good:* a binary with a programmable interface; *okay:* an external tool — and copyleft/restrictive licenses are forbidden for anything *linked*. Much that a naive implementation would shell out to is instead a linked, permissive crate kept inside Cargo under `cargo-deny`'s license gate:

| Capability | Naive OS tool | Crate (linked) |
|---|---|---|
| netns / tap / addrs / routes | `iproute2` (`ip`) | `rtnetlink` + `netns-rs` + `tun-tap` |
| detached PGP verify (now in-guest) | `gpgv` / `gpg` | `pgp` (rPGP) |
| fetch in record step | `curl` / `wget` | `reqwest` (rustls) |
| reflink overlay clone | `cp --reflink` | `reflink-copy` (FICLONE) |
| verify SHA256 digests | `sha256sum` | `sha2` |
| MITM CA + leaf cert minting | `openssl` | `rcgen` + `rustls` |
| cgroup v2 peak/avg reads | parse `/sys` by hand | `cgroups-rs` + `procfs` (reads only; slice create + limit writes go **direct to sysfs**, §7.2) |
| guest `ip`/`curl`/`kvm-ok` | `iproute2` / `curl` / `cpu-checker` | in-crate `vmcell-guest-tools` (`reqwest` + ioctls), baked into the rootfs (§5.3) |
| vsock control channel | `socat`/`ncat` | `tokio-vsock` (host), `vsock` (agent) |
| unprivileged guest networking | `passt` (rejected — Exp 5) | `smoltcp` + `vhost-user-backend` |
| pull + unpack a Debian base | `skopeo` / `docker` | `oci-client` + `tar` + `flate2`/`zstd` |
| build the erofs image | `mkfs.erofs` | `am-fs-erofs` (tar→erofs in memory) |

**Cargo-installable binaries, run as subprocesses (not linked).** `virtiofsd` is `cargo install virtiofsd` (a rust-vmm binary, Apache-2.0 AND BSD-3), so shared-directory support needs no OS package. Dev tooling is the rest: `cargo install cargo-deny`, `rustup component add rustfmt clippy`.

**Irreducibly external — OS packages, release binaries, or kernel features.** The README's external-tools section: **`cloud-hypervisor`** (pinned release binary — not cargo-installable, no embeddable crate), **`mmdebstrap`** (no longer a host dependency — runs *inside* a builder VM, §8.2), **`erofs-utils`** (`mkfs.erofs`, now an optional fallback), the **kernel build toolchain** (`gcc`/`clang`, `make`, `flex`, `bison`, `bc`, `libelf-dev`, `libssl-dev`, `cpio`), **`nftables`** (`nft`, applies the privileged TPROXY ruleset), **`qemu-system-x86`** (fallback VMM only), and **KVM** (`/dev/kvm`; host `nested=1` for nested virt).

**Four build targets, not a feature powerset (v13).** Implementation experience retired the v12 fine-grained host feature matrix in favour of **one host feature** plus three lean targets (§10.5):

1. **`host`** (default) — the library + `vmcell` CLI + `bench-vm`, with *all* host functionality compiled together (all three VMM backends, both net paths, proxy, metrics, pipeline, CLI). No internal host feature splits.
2. **`agent`** — the guest PID-1, built `--no-default-features --features agent`, compiling only `serde`/`postcard`/`thiserror` + `vsock`/`rustix`/`signal-hook` — no tokio, hyper, or netlink (the CI lean-agent `cargo tree` assertion enforces this).
3. **`test-runner`** — the capability runner, `rustix` + `capctl` only, never the lib.
4. **`guest-tools`** — the in-rootfs helper (§5.3), `reqwest` + `rustix`; a guest binary, not the host stack.

The leanness that matters — the two privileged-window binaries and the guest tools must not drag in the host async stack — is preserved and **gated by building each target and asserting its dependency tree**, which is stronger than the v12 powerset clippy that only ever exercised partial *host* combos no deployment uses (§12.2). **v15 makes this structural (§10.1):** the four "targets" become workspace member crates (the `vmcell` library carrying the `host` feature, plus `vmcell-test-runner` / `vmcell-guest-agent` / `vmcell-guest-tools`, with the shared wire enum factored into a `vmcell-protocol` crate so the agent member needs no library edge), the `[features]` here stay as written *within* the library crate, and the `[patch.crates-io]` block below moves to the workspace root. The required-features `[[bin]]` gating of the manifest below is the pre-v15 single-package realization; the workspace promotes each `[[bin]]` to a member crate without changing the dependency sets.

Caveats that shaped the choices:

- **nftables has no permissive pure-Rust path today.** `rustables` (the obvious pure-netlink crate) relicensed to **GPL-3.0-or-later** at 0.8, so it is disqualified by the copyleft prohibition and `cargo-deny` would reject it. `nftables-rs` still needs the `nft` binary + `libnftables`; `nftnl-rs` is FFI to C `libnftnl`; the pure-Rust crates are unverified for the TPROXY/`socket` expressions. Since the ruleset is small, fixed, and security-critical, the design renders it in Rust and applies it via `nft -f -` — correctness over purity (a pure-Rust replacement is a future experiment, Appendix B, Exp 2).
- **A carried `[patch.crates-io]` fork of `vhost-user-backend` + `vhost`** is in the tree, needed *only* to attach the unprivileged smoltcp NAT to QEMU (not CH), where a strict vhost-user `PROTOCOL_FEATURES` check rejects `SET_VRING_ENABLE` arriving before `SET_FEATURES`. **The need is confirmed by a live vhost-user message trace:** QEMU sends `SET_VRING_ENABLE` **before** `SET_FEATURES` (CH sends features first), our backend negotiates `PROTOCOL_FEATURES` correctly, and upstream 0.22/0.16 still enforce the guard — so the fork addresses a genuine QEMU ordering quirk, not a masked backend bug. It is permissively licensed (rust-vmm, Apache-2.0), so `cargo-deny` is satisfied; a patched dependency still carries a maintenance/reproducibility cost, so pin the fork to an exact rev, prefer a narrow upstream-tracking patch, and re-evaluate at each bump. **The patch is genuinely droppable only if the QEMU-unprivileged tier is dropped** (CH-unprivileged needs no fork). The `[patch.crates-io]` block must be carried in both the in-doc manifest and the standalone `Cargo.toml` artifact.
- **`oci-client` is Apache-2.0** (the rename of the older `oci-distribution`); its default TLS is rustls, so pin `default-features = false, features = ["rustls-tls"]` to keep OpenSSL out. **`am-fs-erofs` is obscure — confirm its license and maintenance via `cargo-deny`** before it stays in the default path, keeping `mkfs.erofs` as the fallback.
- **`lzma-rs` (pure Rust) vs `xz2` (links `liblzma`).** Debian kernel tarballs are `.tar.xz`. The sketch uses `lzma-rs` to keep it in-Cargo at a speed cost.
- **Trust `cargo-deny`, not hand-written license labels.** An earlier draft mislabeled `rustables` MIT/Apache when it is GPL-3.0-or-later — exactly the class of error the `cargo-deny` allow-list (run on every CI build) exists to catch. The license notes here are guidance; the gate is the source of truth.

**License gate:** `cargo-deny` enforces an allow-list (MIT/Apache-2.0/BSD-3/ISC/Zlib/0BSD/Unicode-3.0) for all *linked* crates and fails the build on copyleft or non-OSI licenses. Build-time tools (`mmdebstrap`, the `mkfs.erofs` fallback, the kernel toolchain), the `nft` binary, and the QEMU fallback are external executables, not linked, so their copyleft status is acceptable.

### 10.5 The `Cargo.toml`

This manifest realizes §10.4 as the **pre-v15 single-package** layout — one package (2024 edition) with the library, the CLI binary, the macro-bench harness, and the three lean targets (thin agent, cap runner, guest-tools). v15 promotes it to a workspace (§10.1) that maps onto this manifest one-to-one — each `[[bin]]` becomes a member crate with the *same* dependency set, the `[features]` below stay inside the library crate, and `[patch.crates-io]` moves to the workspace root — so the manifest below remains the authoritative dependency/feature reference. v13's feature set collapses to **one `host` feature** (all host subsystems together) plus the three lean targets — see the `[features]` block below and the rationale in §10.4. Heavy host crates stay `optional = true` only so the lean targets can exclude them via `required-features`; the host build pulls the whole set. Versions are conservative floors — resolve exact pins with `cargo add` and gate the set through `cargo-deny`. Lines flagged `VERIFY` are where a crate may not cover the exact need; the OS-tool fallback is named in §10.4.

```toml
[package]
name = "vmcell"
version = "0.0.0"
edition = "2024"
rust-version = "1.85"          # 2024-edition baseline; bump to match your toolchain
license = "MIT OR Apache-2.0"
description = "vmcell: a micro-VM runner for isolated environments (systems testing, agent sandboxes, ephemeral functions)"
publish = false

[lib]
name = "vmcell"
path = "src/lib.rs"

[[bin]]
name = "vmcell"
path = "src/bin/vmcell.rs"
required-features = ["host"]    # the full host library + CLI (the single collapsed host feature)

# Guest PID-1 agent. DEFAULT build: dynamically linked against the rootfs glibc on the host gnu
# target. OPTIONAL fully static build (needs musl-tools, may be unavailable without root in CI):
#   cargo build --release --bin vmcell-guest-agent --no-default-features --features agent \
#       --target x86_64-unknown-linux-musl
[[bin]]
name = "vmcell-guest-agent"
path = "src/bin/vmcell-guest-agent.rs"
required-features = ["agent"]

# Privileged-test capability runner (§12.8). Blessed once
# (`setcap cap_net_admin,cap_sys_admin,cap_dac_override+ep`); blessing is stripped on every rebuild,
# so it must almost never rebuild — depends only on rustix + capctl, NOT the vmcell lib, so
# library churn never recompiles it.
[[bin]]
name = "vmcell-test-runner"
path = "src/bin/vmcell-test-runner.rs"
required-features = ["test-runner"]

# Guest-side multicall helper (§5.3): real ip/curl/kvm-ok, baked into the rootfs erofs.
# Cross-compiled for the guest; its own lean feature, not the host stack.
[[bin]]
name = "vmcell-guest-tools"
path = "src/bin/vmcell-guest-tools.rs"
required-features = ["guest-tools"]

# Micro-benchmark target (§13): criterion harness for pure/IO-light hot-path code.
[[bench]]
name = "micro"
harness = false
required-features = ["host"]

# Macro/VM-level benchmark harness (§13): boots real VMs. A bin (not a [[bench]]) because it needs
# KVM/root; runs on the gated CI job, NOT under `cargo bench`. Emits latency distributions.
[[bin]]
name = "bench-vm"
path = "src/bin/bench-vm.rs"
required-features = ["host"]

[dependencies]

# ---- unconditional shared core (lib + guest agent) ----
serde      = { version = "1", features = ["derive"] }
postcard   = { version = "1", features = ["use-std"] }   # compact framed vsock messages
thiserror  = "2"

# ---- host common (tokio stack + shared host utilities) ----
tokio              = { version = "1", optional = true, features = ["rt-multi-thread", "macros", "io-util", "net", "process", "sync", "time", "signal"] }
futures            = { version = "0.3", optional = true }
bytes              = { version = "1", optional = true }
tracing            = { version = "0.1", optional = true }
tracing-subscriber = { version = "0.3", optional = true, features = ["env-filter"] }
tokio-vsock        = { version = "0.7", optional = true }   # async AF_VSOCK (host side)
nix                = { version = "0.29", optional = true, features = ["mount", "sched", "process", "signal", "user"] }
uuid               = { version = "1", optional = true, features = ["v4"] }   # identity rotation on restore
which              = { version = "6", optional = true }

# ---- Cloud Hypervisor / Firecracker REST clients over --api-socket ----
hyper          = { version = "1", optional = true, features = ["client", "http1"] }
hyper-util     = { version = "0.1", optional = true, features = ["client", "client-legacy", "tokio"] }
http-body-util = { version = "0.1", optional = true }
hyperlocal     = { version = "0.9", optional = true }   # Unix-socket connector for hyper 1.x
serde_json     = { version = "1", optional = true }

# ---- QEMU fallback backend: QMP + guest-agent ----
qapi = { version = "0.14", optional = true, features = ["qmp", "qga", "tokio-stream"] }

# ---- privileged networking: netns + tap ----
rtnetlink = { version = "0.14", optional = true }   # links/addrs/routes via netlink (pure Rust)
netns-rs  = { version = "0.1", optional = true }    # create/enter network namespaces
tun-tap   = { version = "0.1", optional = true }    # /dev/net/tun ioctl: create + persist the tap
ipnet     = { version = "2", optional = true }      # /30 subnet arithmetic
# nftables: NO permissive pure-Rust crate covers TPROXY. The ruleset is applied via the external
# `nft` binary (see §10.4). No crate dependency here.

# ---- unprivileged networking: in-process smoltcp NAT ----
smoltcp            = { version = "0.11", optional = true, default-features = false, features = ["std", "medium-ethernet", "proto-ipv4", "socket-tcp", "socket-udp"] }
vhost-user-backend = { version = "0.17", optional = true }   # vhost-user-net backend in-process

# ---- transparent egress proxy ----
rustls         = { version = "0.23", optional = true }
tokio-rustls   = { version = "0.26", optional = true }
rcgen          = { version = "0.13", optional = true }   # mint the MITM CA + per-host leaf certs
rustls-pemfile = { version = "2", optional = true }
hudsucker      = { version = "0.23", optional = true }   # all-in-one MITM stack (preferred)

# ---- monitoring + limits ----
cgroups-rs = { version = "0.3", optional = true }   # cgroup v2 slices; read memory.peak / cpu.stat / io.stat
procfs     = { version = "0.16", optional = true }  # per-process / net-iface counters fallback

# ---- artifact build pipeline ----
reqwest      = { version = "0.12", optional = true, default-features = false, features = ["rustls-tls", "stream"] }
pgp          = { version = "0.14", optional = true }   # rPGP: verify Debian InRelease / Release.gpg in pure Rust
sha2         = { version = "0.10", optional = true }   # verify Debian SHA256 digests
blake3       = { version = "1", optional = true }      # fast internal content-addressed cache keys
tar          = { version = "0.4", optional = true }    # parse OCI layer tars + the merged rootfs tar
oci-client   = { version = "0.16", optional = true, default-features = false, features = ["rustls-tls"] } # pull pinned Debian image by digest; Apache-2.0
am-fs-erofs  = { version = "0.1", optional = true }    # build erofs in memory from a tar stream — VERIFY license; mkfs.erofs fallback
flate2       = { version = "1", optional = true }      # gzip — kernel/source tarballs AND gzip OCI layers
lzma-rs      = { version = "0.3", optional = true }    # pure-Rust xz (kernel tarballs) — see §10.4 vs xz2
zstd         = { version = "0.13", optional = true }   # zstd OCI layers; bundles libzstd via cc
reflink-copy = { version = "0.1", optional = true }    # FICLONE — XFS/Btrfs only (see §5.1)
walkdir      = { version = "2", optional = true }
toml         = { version = "0.8", optional = true }    # config files (pins.json is JSON, parsed via serde_json)
tempfile     = { version = "3", optional = true }
# NOTE: the mmdebstrap-in-a-builder-VM source needs NO new crates — it drives the existing VMM +
# AgentClient + Share machinery, then reuses am-fs-erofs.

# ---- CLI ----
clap   = { version = "4", optional = true, features = ["derive"] }
anyhow = { version = "1", optional = true }            # ergonomic top-level errors in the binary only

# ---- guest agent only — kept minimal; dynamic-glibc by default, static-musl optional ----
vsock       = { version = "0.5", optional = true }     # sync AF_VSOCK; avoids pulling tokio into the agent
rustix      = { version = "0.38", optional = true, features = ["fs", "mount", "process"] } # libc-free syscalls
signal-hook = { version = "0.3", optional = true }     # SIGCHLD reaping as PID 1

# ---- privileged-test capability runner only — minimal, blessed once (§12.8) ----
capctl      = { version = "0.2", optional = true }     # capset/capget + ambient set + bounding drop; MIT/Apache

# ---- in-process virtio-fs experiment (Appendix B, Exp 1, underway) ----
fuse-backend-rs = { version = "0.12", optional = true }   # vhost-user-fs + passthrough; virtiofsd remains the fallback

[dev-dependencies]
axum         = "0.7"   # spin up host-side HTTP test servers (capability 4)
assert_cmd   = "2"     # exercise the vmcell CLI end to end
predicates   = "3"
serial_test  = "3"     # serialize tests that touch global host resources (netns / cgroups / nft)
tempfile     = "3"
tracing-test = "0.2"
proptest     = "1"     # property tests: path-injectivity, codec round-trip, /30 math, cache-key stability
criterion    = { version = "0.5", features = ["html_reports"] }  # MICRO-benchmarks only; macro benches use bench-vm
# loom (concurrency model-checker for the allocators) is opt-in under #[cfg(loom)].

[build-dependencies]
progenitor = { version = "0.8", optional = true }   # optional: typed CH REST client from OpenAPI YAML

[features]
default = ["host"]

# ── ONE host feature: the full library + CLI, every subsystem compiled together. ──
# v13 COLLAPSES the v12 fine-grained matrix (cloud-hypervisor/firecracker/qemu /
# net-privileged/net-unprivileged / proxy / metrics / pipeline / cli / host-common
# + a dozen dep passthroughs) into this single feature (§10.5). Rationale, from
# implementation experience: no real deployment uses a *partial* host build; the
# fine-grained split was the direct source of the feature-gating build breaks (an
# un-`cfg`'d `#[from]` error variant broke `--features agent`/`test-runner`; modules
# gated on `host-common` rather than their own feature made single-feature combos
# fail to compile and kept the `cargo hack` powerset gate permanently red); and
# merging costs nothing, since `default` already compiled the whole set. The only
# splits that earn their keep — the two lean privileged-window binaries and the
# guest-side tools — remain, because those are real, enforced leanness boundaries.
host = [
    "dep:tokio", "dep:futures", "dep:bytes", "dep:tracing", "dep:tracing-subscriber",
    "dep:tokio-vsock", "dep:nix", "dep:uuid", "dep:which",
    "dep:hyper", "dep:hyper-util", "dep:http-body-util", "dep:hyperlocal", "dep:serde_json", # CH + Firecracker REST
    "dep:qapi",                                                                              # QEMU QMP
    "dep:rtnetlink", "dep:netns-rs", "dep:tun-tap", "dep:ipnet",                             # privileged net (tap/netns/30)
    "dep:smoltcp", "dep:vhost-user-backend",                                                 # unprivileged net (smoltcp NAT)
    "dep:rustls", "dep:tokio-rustls", "dep:rcgen", "dep:rustls-pemfile", "dep:hudsucker",    # egress MITM proxy
    "dep:cgroups-rs", "dep:procfs",                                                          # metrics reads (create_slice writes sysfs directly, §7.2)
    "dep:reqwest", "dep:pgp", "dep:sha2", "dep:blake3", "dep:tar", "dep:oci-client",         # artifact pipeline
    "dep:am-fs-erofs", "dep:flate2", "dep:lzma-rs", "dep:zstd",
    "dep:reflink-copy", "dep:walkdir", "dep:toml", "dep:tempfile",
    "dep:rustix",                                                                            # net_sys ioctls (TUNSETPERSIST, §10.1)
    "dep:clap", "dep:anyhow",                                                                # CLI
]

# ── Lean guest PID-1 agent — NO host/async stack (the CI lean-agent assertion enforces this). ──
agent = ["dep:vsock", "dep:rustix", "dep:signal-hook"]

# ── Lean privilege-delegation runner — only syscalls + caps; never links the vmcell lib. ──
test-runner = ["dep:rustix", "dep:capctl"]

# ── Guest-side multicall helper baked into the rootfs (§5.3): real ip/curl/kvm-ok. ──
# A *guest* binary cross-compiled into the rootfs. Needs reqwest for genuine HTTP, so it is
# leaner than the host but not as lean as `agent`; it is NOT the host stack (own lean target).
guest-tools = ["dep:reqwest", "dep:rustix"]

experiment-fuse = ["host", "dep:fuse-backend-rs"]
codegen = ["dep:progenitor"]

# ---- carried patch: QEMU-unprivileged vhost-user only ----
# Relaxes a PROTOCOL_FEATURES check on SET_VRING_ENABLE that QEMU sends before SET_FEATURES finalizes.
# NOT needed for CH-unprivileged — drop it if the QEMU-unprivileged tier isn't required. Pin to an exact rev.
# cargo-deny still applies (rust-vmm, Apache-2.0). Keep in sync with the standalone Cargo.toml.
[patch.crates-io]
# vhost-user-backend = { git = "https://github.com/<fork>/vhost", rev = "<pinned-sha>" }
# vhost              = { git = "https://github.com/<fork>/vhost", rev = "<pinned-sha>" }
```

### 10.6 Architectural accommodations for testability

Four accommodations make the orchestrator unit-testable without KVM or root. **They are load-bearing, not optional** — an implementation that skipped them (calling `ip`/`nft` and reading sysfs directly with no trait boundary, using module-global `static AtomicU32` counters) is precisely why a class of correctness bugs was review-only: with no fake, no unit test could assert allocator wraparound, cgroup sibling-placement, or the zero-netlink contract.

1. **The `Vmm`/`VmInstance` trait seam.** A `FakeVmm` implements both traits in memory, letting the orchestrator's logic (allocation order, ordered `Drop` cleanup, retry/timeout, snapshot-vs-cold-boot selection, CID allocation) be unit-tested with no KVM, root, or subprocess.
2. **Pure/imperative split.** The genuinely-testable pure functions are isolated from I/O: nft-rule rendering, `/30` arithmetic, the CH REST payload builder, the vsock handshake state machine, cgroup-path construction, the artifact `cache_key`, and the protocol codec. The thin I/O wrappers around them are exercised by integration tests.
3. **Injectable side-effect traits** — `Netlink`, `NftApplier`, `CgroupFs`, `SerialLog`, `Clock` — each with a real implementation and a recording fake, so `net`/`metrics`/`agent` orchestration can assert "the right rules/limits/handshake were requested" without touching the host.
4. **Deterministic IDs and clocks** are injected (a `vmid`/`cid` allocator, a `Clock`), never module-global mutable statics, so tests are reproducible.

The rule that follows: **a subsystem that cannot be unit-tested against a fake is, by this design, not done** (§12.5).

### 10.7 The v14 rename spec (mechanical, exhaustive)

The terminology and rebrand decisions above are only real once the *code, tests, and tooling* match the prose — v13 renamed in prose but left `NetConfig::Rootless`, `TestVm`, and `imp_testing` in the code. This subsection is the exact, auditable rename checklist. Three independent renames, each landing as one intentional change:

**A. `rootless` → `unprivileged` (the operating-mode vocabulary, §6.4).**
- `NetConfig::Rootless { .. }` → `NetConfig::Unprivileged { .. }` in `config.rs` (the public enum, §10.2) — a breaking API change, surfaced by `cargo-semver-checks` (§12.2). Every match site updates with it: `config.rs::build()` validation (the §3.3 snapshot-law and `ksm_mergeable` rejections), `orchestrator.rs`, `net/mod.rs` dispatch, the three `vmm/*.rs` backends, `proxy/mod.rs`.
- Test functions `test_*_rootless*` → `test_*_unprivileged*` (`test_egress_proxy_rootless` → `test_egress_proxy_unprivileged`; `test_lifecycle_rootless_smoltcp` → `test_lifecycle_unprivileged_smoltcp`), plus the in-code comments and `#[ignore = "…"]` reasons that say "rootless".
- **The suite split keys on the test name.** `just test-rootless` (nextest filter `test(rootless) | test(smoltcp)`) → `just test-unprivileged` (`test(unprivileged) | test(smoltcp)`), and `just test-priv` (`not (test(rootless) | test(smoltcp))`) → `just test-privileged` (`not (test(unprivileged) | test(smoltcp))`). Renaming the test functions and the filter **must happen together**, or a suite silently selects zero tests — which §12.4 makes a *CI failure*, not a pass. (`smoltcp` stays in the unprivileged filter: the unprivileged datapath *is* the smoltcp NAT, §6.)
- README §6 recipe names + prose, and the AGENTS.md recipe references. A single canonical historical note ("formerly *rootless*") is kept in §6.4 so the lineage stays searchable.

**B. `TestVm` → `MicroVm` (the neutral handle, §1.1).** Rename the public struct, its `impl`/`Drop`, and every use across lib/CLI/tests/benches in `orchestrator.rs`. This is the generality rename: the handle owns the *primitive*, which is not testing-specific. Breaking API change, surfaced by `cargo-semver-checks`. (Renaming a public type is breaking **regardless of `#[non_exhaustive]`** — v13's claim that this rename was "non-breaking under `#[non_exhaustive]`" was wrong; it is breaking and deliberate.)

**C. Project/crate → `vmcell`.** Package/lib `imp-testing`/`imp_testing` → `vmcell`; binaries `imp-testing` → `vmcell` (CLI), `imp-guest-agent` → `vmcell-guest-agent`, `imp-test-runner` → `vmcell-test-runner`, `imp-guest-tools` → `vmcell-guest-tools`; env vars `IMP_ARTIFACTS_DIR`/`IMP_KERNEL`/`IMP_ROOTFS` → `VMCELL_*`; internal name prefixes `imp-vm-*` / `imp-net-*` / `imp_host_paths.json` / `/imp-tools` → `vmcell-*`. Update the lean-binary CI assertions (§12.2) and `just bless` (§12.8) to the new binary names. **Share tags (revised in this pass):** the old hardcoded `imp-in`/`imp-bin`/`imp-out` tags are renamed to `vmcell-in`/`vmcell-bin`/`vmcell-out` **and** made fully caller-defined — the guest agent no longer mounts a fixed list; it mounts whatever `VmConfig.shares` specifies, decoded from the `vmcell_share=` cmdline tokens (§5.2). The internal `vmcell_vmid=` cmdline param (was `imp_vmid=`) and the test helper `clean_vmcell_netns` (was `clean_imp_netns`) rename with the rest. **What does *not* rename:** every **`Imp`** reference to the origin agentic *harness* — it is a consumer of the runner, not the runner.

The crate is `version = "0.0.0"`, `publish = false`, so the breaking parts (A, B) cost only internal call-site churn, not ecosystem breakage; bundle A/B/C into one commit. A grep gate (`scripts/ban-legacy-terms.sh`, modeled on the existing `ban-global-state.sh`) keeps `rootless` / `TestVm` / `imp_testing` from creeping back into non-historical code — the same "turn the rule into a gate" discipline as §12.2.

---

## 11. Artifact build pipeline

Maps onto the VM-artifact-production requirements: staged, pinned, deterministic, cacheable, resettable, minimal external access, record/replay, signing-chain verified. Exposed both as the library `artifact::Pipeline` API and as `vmcell build [--reset-to STAGE]` on the CLI. v15 adds `vmcell oci2erofs IMAGE@DIGEST -o rootfs.erofs` (§8.2), which drives the *same* rootfs stage against a caller-supplied digest-pinned base image and emits a single erofs the VM-management verbs (§10.2) consume via their `--rootfs` argument — a build-time utility, not a runtime source, so the erofs-only runtime is preserved. Its cache key is **input-based** (the image digest + the injected agent/CA/tools content + the stage version), which is correct per the §11.2 rules below (hash *identity that travels*, not the output path) and lets the cache decide to skip *before* a build, while artifact **validity** is still content-addressed (a tampered erofs with an intact `.cache_key` is rejected).

### 11.1 Artifacts produced

1. **`vmlinux`** (per arch, and per kernel label): one custom-minimal kernel, direct-boot, drivers built in, optional KVM-for-nesting. Host-side, shared by all VMs; rebuilt only when the config fragment or pinned source changes. The `kernels` registry (§8.3) builds `vmlinux-<label>` alternates for the benchmark sweep off the same fragment.
2. **Root filesystem** (per profile): a **single read-only erofs image** packed in memory by `am-fs-erofs` from a merged rootfs **tar**, from one of two interchangeable sources sharing the inject+pack tail (§8.2). The shared tail injects `vmcell-guest-agent`, the proxy CA, the **`vmcell-guest-tools` helper** (§5.3), and the tmpfs/overlay scaffolding. That one artifact serves cold boot, concurrent shared mounts, and the snapshot tier, and is **kernel-independent** (one rootfs boots under any `vmlinux-<label>`). Imp's own binaries are *not* baked in — they arrive over the `vmcell-bin` virtio-fs share, so a new Imp build does not invalidate the rootfs.
3. **Warm snapshot** (per VMM + profile): boot the erofs-rootfs base to "agent-ready," snapshot. Per-test = restore + tmpfs overlay. The Firecracker snapshot profile applies the `T2` CPU template (where the host CPU accepts it) + the `noxsave` extended-FPU guard as a no-template fallback (§3.2).
4. **Proxy CA cert**: minted once, baked into the rootfs trust store.

All four live under **one artifacts directory** — `vmcell::artifact::artifacts_dir()` = `$VMCELL_ARTIFACTS_DIR` or the default `target/vmcell-artifacts` (per-checkout, gitignored), from which `kernel_path()`/`rootfs_path()` derive (still overridable by `$VMCELL_KERNEL`/`$VMCELL_ROOTFS`). v12 had **three** divergent defaults (CLI wrote `target/vmcell-artifacts`, the harness read `/tmp/vmcell-artifacts`, the CA defaulted to `/tmp/vmcell-artifacts-<pid>`); the consolidation also closed a latent correctness bug — the proxy now loads the **same CA** the build baked into the rootfs, so the authority it presents matches the guest trust store. There are **no `/tmp/vmlinux`-style fallbacks**: a missing upstream artifact is an `Error::Artifact`, never a silent boot from a world-writable path.

### 11.2 Stage model

- **Stage 0 — the pin lock (the only non-deterministic input, isolated here).** The minimal pin set: the **OCI base-image manifest digest** (a `sha256:…` digest, never a tag), the Debian package-repo **snapshot timestamp** (`snapshot.debian.org`, used by the in-VM `mmdebstrap` source), the kernel source version/SHA (plus a `kernels` registry of alternates for the multi-kernel sweep, §8.3), and the CH/virtiofsd release tags. **As built (observed, v13):** these live in a **committed `pins.json`** that *is* the lock; `ResolvePinsStage` **loads it once and propagates the values through `StageOutputs`** so downstream stages read pins from memory, not files-on-the-fly. This makes stages 1..n purely deterministic, which is the load-bearing property. *Live* tag→digest and `snapshot.debian.org`-timestamp resolution (so Stage 0 can refresh the lock itself) is **forward work**, called out as such — the committed lock is the honest current state, not a stage that silently does nothing. Whichever form, Stage 0 is the *only* place non-determinism is allowed.
- **Stages 1..n — deterministic given inputs.** Each stage's output is fully determined by its inputs + pins. Examples: fetch+verify kernel source; configure+compile `vmlinux`; then the rootfs source-of-record (OCI: pull+verify the pinned image → apply layers/whiteouts → merged tar; or in-VM: build the builder rootfs via OCI → boot the builder VM → run `mmdebstrap` at the pinned snapshot → collect the target tar — this stage **depends on the compiled `vmlinux`**, so the kernel stage is ordered before it). Both paths converge on the shared tail: inject `vmcell-guest-agent` + CA → erofs pack → boot+snapshot.
- **Caching — five rules, each its own failure mode (the review found a bug in most).** Each stage has a pure `cache_key`; `Pipeline::build` skips a stage whose **output content** matches that key. The key composition is exact:
  1. **Stable hasher** — `blake3` (or `sha2`), never `DefaultHasher` (not portable across Rust versions).
  2. **Deterministic input order** — hash inputs in a fixed order (sorted keys / `BTreeMap`), **never** in `HashMap` iteration order; otherwise the key varies across processes and forces a spurious, expensive rebuild.
  3. **Content and identity that travel, not local paths** — hash the **content hashes of upstream artifacts**, never absolute `PathBuf`s under `target/` (two checkouts must agree). The rootfs key folds `guest_agent_src_hash` *and* the guest-tools content (§5.3), so rebuilding either correctly invalidates the rootfs (a stale agent baked into the rootfs was a real handshake-timeout bug).
  4. **Embed a per-stage version constant and the pinned source SHA** — a build-logic change with unchanged pins, or re-pointing a pin at new bytes, must invalidate the key.
  5. **Validity is content-addressed, not existence-based** — a tampered artifact with an intact `.cache_key` sidecar is **rejected**, not silently reused; re-hash on every use (including a cached OCI blob, whose digest must be re-verified on the cache-hit path, not only when first fetched). The kernel-tarball cache is **verify-or-purge**: a cached tarball whose hash ≠ the pin purges the build dir and re-fetches (a stale intermediate must invalidate, not error), then a still-mismatch is a provenance hard stop.

  `reset_to(stage)` removes that stage's and all later stages' outputs and **errors on an unknown stage name**.
- **Minimize external access + record/replay.** Network-touching stages split into a **record** step (populate an on-demand cache keyed to the pins) and a **replay** step (build purely from the cache), so iteration and CI hit the network at most once per pin. For the OCI source, **cache the pulled blobs by digest** so a later registry deletion/overwrite doesn't break a rebuild (registry retention is the OCI path's reproducibility weak point). For the in-VM `mmdebstrap` source, apt fetch happens inside the builder VM; its egress can run through this project's own egress proxy with a record/replay cassette.
- **Signing-chain verification — two forms, honest about what each gives.** The in-VM `mmdebstrap` source verifies the Debian `InRelease`/`Release` + `Release.gpg` chain against the pinned archive keyring *inside the guest* before using any package — full provenance, **refuse-on-mismatch**. The OCI source's `sha256` **digest pin is an integrity hard-stop** but is *integrity, not authenticity*; to also get provenance, optionally verify a **cosign/sigstore** signature (a different trust root than apt's keyring, and not every base image is signed). In all cases a mismatch is a hard stop, not a warning.

---

## Part III — Quality, performance, and risk

## 12. Testing strategy and quality gates

The principle: the test/lint/CI layer should **force** robustness rather than rely on review to catch it. Each class of defect that a review found — correctness bugs (no `Drop` teardown, temp-dir collisions, a non-portable cache hash), robustness gaps (`.unwrap()` on the hot path, undocumented `unsafe`, thread/FD leaks), API-guideline violations — becomes an automated gate, ordered **cheapest-and-broadest first**, so the next implementation cannot merge them and review is freed to find genuinely new problems. The highest-value gates cost *zero per-test authoring* (crate-level lints, a feature-matrix build, doctests, `cargo-deny`); the hand-written unit/integration tests are the next layer; the injectable seams (§10.6) are what make that layer possible.

### 12.1 Compiler- and lint-enforced gates

The crate root carries a deny-list that turns defect classes into compile errors with no test written:

```rust
// lib.rs
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
)]
#![cfg_attr(not(test), deny(
    clippy::unwrap_used,                      // hot-path panics in proxy/agent/smoltcp.
                                              // `.expect("invariant: …")` is the permitted escape hatch.
    clippy::panic, clippy::unreachable,
    clippy::todo, clippy::unimplemented,      // a todo!() is loud; a silent Ok(()) no-op is not
    clippy::indexing_slicing,                 // forces .get()/bounded reads
    clippy::print_stdout, clippy::print_stderr, // forces `tracing` instead of println!/eprintln!
    clippy::dbg_macro,
))]
```

The `not(test)` gating is the load-bearing trick: tests may `unwrap` freely; production paths may not. Two structural rules accompany it:

- **Contain `unsafe` with per-module `#![forbid(unsafe_code)]`.** The I/O-free modules — `config`, `agent::protocol`, `artifact` (`cache_key`), and the `/30` math in `net` — forbid `unsafe` outright, so it survives only in the four places that genuinely need it (`vmm` subprocess glue, `proxy::setns`, the `net::userspace` virtqueue ring handling, the guest agent's syscalls). A stray `unsafe` is a compile error, not a review note.
- **CI backstop:** `RUSTFLAGS="-D warnings"` with `cargo clippy --all-targets --all-features`. Anything left at `warn` still fails CI. `cargo fmt --check` is a separate required step.

### 12.2 Build-matrix and dependency gates

These catch defects that `--all-features` hides:

- **Build *and clippy* every target — the four-target gate (v13, replacing the feature powerset; v15 makes it per-member).** With the feature matrix collapsed to one host feature plus three lean targets (§10.5), there are no partial *host* combos for a powerset to exercise, so the gate is: a CI job that **builds and `clippy`s each of `host` / `agent` / `test-runner` / `guest-tools`** (`cargo clippy --no-default-features --features <t>` for each lean one; default for `host`). This is *stronger* than the v12 `cargo hack` powerset for the failure that actually bit: an un-`cfg`'d `#[from]` error variant in the shared `error.rs` that broke `--features agent`/`--features test-runner`. **Critically, the v12 lean-agent gate was `cargo tree`-only (graph analysis) and never *built* the agent target**, so the broken agent build slipped through (review GATES-4); v13 *compiles* each lean target. **v15 (with the workspace split, §10.1) turns this into a per-member structural property** — each lean binary is its own crate, so building the member *is* the lean build, and a host module cannot leak into it by construction rather than by a feature-gate that a future edit might loosen. The per-member CI matrix must stay in lockstep (a missing member gate is itself a silent regression vector — a CI template/macro keeps the four in sync).
- **Lean-target invariants, asserted on the built tree.** For `agent` and `test-runner` (and `guest-tools`), `cargo tree -e no-dev` must **not** contain `tokio`/`hyper`/`rtnetlink` (the host async stack) — guarding the §10.4 leanness promise against accidental re-coupling, *in addition to* the build above (the tree check alone is insufficient). Under the workspace split this `cargo tree` runs **per member crate**, a tighter boundary than the v13 feature-gated whole-package check.
- **`cargo-deny` is the license/advisory source of truth.** `cargo deny check` (licenses, advisories, bans, sources) on every build. The open `am-fs-erofs` license question is resolved by this gate, not by reading a label. A `deny.toml` skeleton (allow-only):

```toml
[licenses]
allow = ["MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception",
         "BSD-3-Clause", "BSD-2-Clause", "ISC", "Zlib", "0BSD", "Unicode-3.0"]
[bans]
multiple-versions = "warn"
wildcards = "deny"
[advisories]
yanked = "deny"
[sources]
unknown-registry = "deny"
unknown-git = "deny"
```

- **Public-API gate.** `cargo semver-checks` on every PR turns the *consequence* of a missing `#[non_exhaustive]` (a breaking field addition) into a CI failure.

### 12.3 Unit tests — pure functions and injected seams

Each row is a pure function or seam; none need KVM or root, so they run under a plain `cargo test`. `proptest` carries the invariants marked *[prop]*.

| Unit under test | Assertion |
|---|---|
| `config::VmConfigBuilder::build()` | returns `Result`; **a negative test per rejection**: duplicate share tags, snapshotting + {virtio-fs rootfs, any data `Share`, `NetConfig::Unprivileged`} (all three vhost-user cases, §3.3), `vcpus==0`, `mem_mib` below floor, empty kernel path, out-of-range vmid. Builder methods `#[must_use]` |
| per-VM path construction | injective in `(pid, vmid)` *[prop]* — distinct vmids never share `api.sock`/`vsock.sock`/`serial.log` |
| `/30` address math | guest/host/mask correct for `vmid ∈ {0,1,254,255}`; a vmid that would overflow an IPv4 octet is rejected *[prop]* |
| `CidAllocator` | skips reserved 0/1/2; wraps without emitting a live or reserved CID; tracks the in-use set; thread-storm contention test |
| vmid allocator | wrap at 254 consults the in-use set, not just a counter |
| `agent::protocol` codec | round-trips through the `LengthDelimitedCodec` framing, incl. partial buffers and oversized-frame rejection *[prop]* |
| vsock handshake FSM | `Connection refused → OK` retry; **EOF → return to `accept`** (restore survival); serial-log panic → fast-fail |
| CH REST request/response | golden-JSON payload; parser handles chunked, `>4096`-byte, and `201/202/204` responses *[prop on status]* |
| nft ruleset render | golden-text test; asserts the steering form preserves the destination |
| cgroup-path construction | pure: nests under `/proc/self/cgroup`, places the VM cgroup as a *sibling* of the runner (strips `/supervisor`) |
| `CgroupFs` fake | recording fake asserts exact limit-file contents per `ResourceLimits` (fails on an inverted MiB→bytes / cpu-quota formula); a *requested* limit on an undelegated controller returns `CapabilityUnavailable`, not `Ok` (§7.1) |
| `cpufreq` pin/restore | `CpuFreqSysfs` recording fake: pins every online CPU, disables turbo, and **restores exactly what it changed on Drop incl. panic** — each test fails on the inverse (a forgotten CPU, a restored constant, turbo left off, a CPU it never touched) |
| `Netlink`/`NftApplier`/smoltcp fakes | the recording fakes **assert** the rendered ruleset / netlink-call order (not "exist but assert nothing"); a host-NAT-MAC test asserts no `mac_math(1..=254)` collides with the host MAC (§6.1) |
| `artifact::cache_key` | golden digest pinned to a stable hash, **identical across processes** (not `DefaultHasher`); inputs hashed in **deterministic order** (not `HashMap` iteration); hashes **upstream content**, not absolute paths; folds `guest_agent_src_hash` + a **stage-version** constant. Exercised against a **real stage** (`RootfsStage`/`SnapshotStage`), not a constant `DummyStage` |
| `Error` | `Display` + `From` per variant; `#[non_exhaustive]` compile-guard |
| `SmoltcpProcess` / `EgressProxy` shutdown | a cancellation signal joins the worker within a timeout; `Drop` triggers it |
| `Drop` order | against `FakeVmm`: teardown runs VMM-proc-group → virtiofsd → netns/cgroup/overlay/sockets, and **still runs on `panic!`** |

### 12.4 Integration tests — real environment, default-skipped, per-VMM

**Gating, and the two operating-mode suites.** Tests needing KVM or capabilities are `#[ignore]` by default (CI runs them with `--ignored` on a capable runner) via the `nextest` `serial-host` group for anything touching global host state — not ad-hoc `#[serial]`. A laptop `cargo test` runs only the §12.3 unit tests and doctests and stays green. The integration suite is split into the **two named operating modes** (§6.4), and each is a *first-class, separately-invoked* suite (todo directive): an **unprivileged suite** (`just test-unprivileged` — KVM-group access, smoltcp net, no caps) and a **privileged suite** (`just test-privileged` — the §12.8 runner's three caps, tap/netns). A suite's prerequisites are a **visible, hard precondition**: a missing capability or an undelegated controller is a *skip-with-reason*, **never** a silent green; and a recipe whose test filter **selects zero tests is a CI failure**, not a pass — which is exactly why §10.7 renames the test functions and the nextest filter **together** (rename one without the other and the suite silently selects nothing; the v12 `test(rootless)` filter shipped before any test carried that name and exited "0 tests run" — the recipe-level skip==pass the review caught). Run under **`cargo nextest` with a per-test timeout** so a hang (virtiofsd-socket-wait, `cgroup` write) fails as a timeout, not a stuck job. The CLI gets `assert_cmd`/`predicates` smoke tests.

**Per-operating-mode test specification (the §6.4 directive, made explicit).** The two suites are not merely a filter convenience: each exercises a *different host datapath and capability set*, so each has its own fail-loud prerequisite probe (§7.1) and its own required assertions. The assertion *details* (each written to fail on its inverse) are listed by file just below; this block says **which mode owns which test and what its prerequisite is**.

- **Unprivileged suite (`just test-unprivileged`).** *Prerequisite probe (fail-loud, §7.1):* the suite confirms **KVM-group access** to `/dev/kvm` and that the backend reports `unprivileged_vhost_user_net` (CH/QEMU; Firecracker skips-with-reason — no vhost-user-net for the NAT to attach to, §3.4). It runs with **no `CAP_*` held**, proving the no-elevation path works end-to-end:
  - *smoltcp NAT datapath* (`test_lifecycle_unprivileged_smoltcp`): boot under `NetConfig::Unprivileged`; `eth0` comes up over the in-process NAT via kernel `ip=` (**zero in-guest netlink**, §4.3/§6.1); an `exec` over the unprivileged vsock succeeds; on teardown the NAT's vhost-user socket is **unlinked** (no residue).
  - *unprivileged egress* (`test_egress_proxy_unprivileged`): the full HTTPS-intercept / test-double / **filter-block-observed-and-logged** / intended-destination assertions (same as the privileged egress test), but through **L4 interception inside the smoltcp NAT** (§6.3) — proving the proxy contract holds *without* nft/TPROXY.
  - *fail-loud-from-below negative*: with no caps held, requesting a privileged-only op (constructing `NetConfig::Privileged`, creating a netns, or setting an un-delegatable limit) returns the typed `Error::CapabilityUnavailable`/`Unsupported` — **not** a panic and **not** a silent degrade to "ran unlimited / ran without isolation" (§7.1).
  - *metrics under `--user` delegation*: a *requested* limit that can't be enforced **fails loud**; *reads* fall back to sysfs and report `limits_enforced=false` (§7.1).
- **Privileged suite (`just test-privileged`, via the §12.8 capability runner).** *Prerequisite probe (fail-loud, §7.1):* the suite confirms the **three caps in the *effective* set** (`CAP_NET_ADMIN`/`CAP_SYS_ADMIN`/`CAP_DAC_OVERRIDE`), `/var/run/netns` writability, and a **non-threaded `domain` cgroup scope** with the needed controllers delegated (§6.4/§7.2). It asserts the full-fidelity path:
  - *tap/netns datapath* (`host_endpoint.rs`): a host server on the per-VM `/30` gateway is reachable from the guest and **not** exposed outside the netns; raw TCP works.
  - *privileged egress* (`egress_proxy.rs`): nft **TPROXY** steering; HTTPS logged; double answers; **filter-block observed by the guest and recorded**; proxy observes the **intended destination**; a real `CONNECT` falls through.
  - *enforced limits* (`metrics_limits.rs`): `memory.max` **OOM-kills** a runaway allocator (assert `memory.events oom_kill>0`, not exit 137); `limits_enforced=true`.
  - *snapshot/restore* (`snapshot_restore.rs`, CH+FC): the tap path is the **only** snapshot-eligible network path (§3.3), so all restore assertions (severed-vsock reconnect, live CID, rotated MAC, first-call clock resync, RNG reseed-without-self-reseed) live here.
  - *ordered Drop on panic* (`lifecycle.rs`): zero residue + full teardown order via recording fakes.
  - *the gateway covers itself (v15: now off the privileged path)*: the capability runner's **path confinement** (now anchored on the **test-binary's** path, not the runner's — the §12.8 fix that lets the runner live outside `target/`), **`+ep` remediation message, and `kvm`-group-preservation logic are unit-tested**; v15 additionally extracts the privilege-drop sequence (inheritable → bounding-drop → ambient-raise → trim → uid) into a **pure `plan_privilege_transition(CapState, need, euid)`** that is unit-tested against each buggy inverse — including the security-critical **setuid-form uid-before-ambient ordering** — so the runner's logic is verified *before* a bless, not only by running the privileged suite (§12.8 #3). Only the thin `set_current()`/`setresuid`/`exec` syscalls remain integration-only.
- **Mode-independent** (the default unit suite or either integration suite, since they don't depend on the network datapath): boot / exec / `put_file` round-trip / concurrency / the `FakeVmm`-driven orchestrator test / the **zero-netlink** assertion / the build-pipeline trio.

The required assertions go beyond the happy path, and each is written to **fail on its own inverse** (the rubric's governing question) — the v12 versions of the first three were *theatrical*, passing on their inverse, which the review caught:

- `snapshot_restore.rs`: the host **reconnects the severed vsock** (not merely "restore succeeds"). Identity: the restored VM has a **valid, *live* CID** (not `assert_ne!(old, new)` — CIDs are reused by design on a sequential restore, §9.2) and a **rotated MAC observed in-guest** (read back via the guest-tools `ip`). **Clock resync** is driven by an injected `FakeClock` consulted on the **first** post-restore `agent()` call (the v12 test injected a `FakeClock` read only on a *later* call where `restored==false`, so it was never consulted — dead). **RNG reseed** captures pre/post entropy *without the test issuing its own reseed* (the v12 test ran the reseed itself and asserted only `code==0`, so deleting the orchestrator's reseed left it green).
- `egress_proxy.rs`: **HTTPS** interception is logged; a registered **test double** answers; a **filter rule blocks a domain and the guest sees the block** (and the **block is recorded** in the request log — denials are the most security-relevant events); the proxy observes the guest's **intended destination** (assert on the *observed destination*, not the steering mechanism); a **real `CONNECT`** falls through. The HTTPS double **ignores `Method::CONNECT`**; the domain match is **label-boundary** (a sibling domain is *not* over-blocked — unit-tested).
- `metrics_limits.rs`: `memory.max` **OOM-kills** a runaway allocator — set **`mem_mib(512)` + `mem_max_mib(256)`** and assert a **cgroup `memory.events` `oom_kill > 0`**, not just a guest exit 137 (with guest RAM ≥ the cap the guest's *own* OOM produces 137 regardless of `memory.max`, so the v12 test passed with the cap deleted). Controller delegation is a **hard precondition** (visible skip if absent), and **average CPU** is computed over a busy loop.
- `lifecycle.rs`: **ordered `Drop` teardown on `panic`** leaves zero residue — assert against the **computed** per-VM cgroup path (nested under the delegated slice, not a top-level `/sys/fs/cgroup/vmcell-vm-{vmid}` the code never uses) **and** netns/tap/overlay/temp-dir/CID/VMID; and assert the **full teardown order** (VMM-group → virtiofsd → netns/cgroup/overlay) via **recording fakes**, on both normal drop and panic — not merely that *a* `drop` event was recorded (`.contains("drop")` asserts no ordering).
- `concurrency.rs`: N VMs in one process with **no CID/VMID/socket-path collision** (distinct real socket *paths*, varying `pid`, not `format!` string stand-ins).
- `put_file` **round-trip** (write via `put_file`, then `cat` the file back *in the guest* — not a UDS-mock assertion); agent **zero-netlink** assertion (the injected `Netlink` fake records **zero** calls — `ip=` configures `eth0`, and on restore the only in-guest `ip` write is the MAC rotation via the `SIOCSIFHWADDR` ioctl — *not* netlink — so the fake still records zero, §9.2); a **`FakeVmm`-driven** orchestrator test that *exercises* allocation order, retry/timeout, and restore-vs-cold-boot selection with no KVM (the fake must be **driven**, not merely "exist").

**Per-VMM matrix.** Every scenario is parameterized over the backend. Before running a case, the harness consults `capabilities()` and emits an explicit **skip-with-reason** for any backend that can't support it — so an unsupported feature surfaces as a visible, attributed gap, never a silent green. Applicability: boot / exec / lifecycle / metrics / `put_file` / concurrency and the **privileged** (tap) `egress_proxy`/`host_endpoint` paths run on **all three**; `snapshot_restore.rs` runs on **CH and Firecracker** (QEMU skips — snapshot-ineligible in unprivileged+vsock); `shares_ro_rw.rs` (virtio-fs) and the **nested-virt** class run on **CH/QEMU only** (Firecracker block-only, no nesting); the **unprivileged** (smoltcp) suite runs on **CH/QEMU only** (Firecracker has no vhost-user-net for the NAT to attach to). A backend silently *failing* a scenario it claims to support — rather than skipping one it doesn't — is itself the bug this matrix catches.

**Build-pipeline tests** (exercise the **real** `RootfsStage`/`SnapshotStage`/`KernelStage`, not a constant `DummyStage` — a trivial stage cannot catch the cache-key bugs §11.2 guards): a **tamper aborts** by corrupting the *artifact bytes* (with an intact `.cache_key` sidecar) and asserting the build **rejects** it — *not* corrupting the sidecar and asserting a rebuild (that "tampered_digest_aborts" inversion verifies nothing); a **warm-cache second build performs zero network fetches and skips stages**; a cached **OCI blob is re-verified on the hit path**; `reset_to(rootfs)` **rebuilds rootfs+snapshot but not the kernel**, and `reset_to(unknown-name)` **errors**; **determinism** — identical pins yield a byte-identical erofs and an identical `cache_key` across processes; and an **end-to-end invalidation** test asserts that changing the **guest-agent source re-bakes `rootfs.erofs`** (the stale-agent-baked-into-rootfs class that cost real debugging time). The harness **fails loud when an artifact is older than the sources it depends on** (or auto-`build`s first), rather than silently booting a stale rootfs.

### 12.5 The injectable seams are load-bearing

§10.6 lists four testability accommodations. The design treats them as requirements with teeth: side-effecting subsystems are written against a small trait (`Netlink`, `NftApplier`, `CgroupFs`, `SerialLog`, `Clock`), each with a real impl and a recording fake; IDs and time come from injected allocators, never module-global mutable statics (an optional CI grep bans new `static mut` / `static …: Atomic…` outside the allocator module). The lints make sloppy code fail to compile; the seams make correct code unit-testable. A subsystem that cannot be unit-tested against a fake is not done.

### 12.6 What stays review-or-benchmark

Stated so these are not mistaken for covered: syscall/FFI `unsafe` is not Miri-checkable (run Miri on the pure-logic `unsafe` only — allocator atomics, the virtqueue ring arithmetic, the codec; `setns`/`mount(2)`/vhost ioctls are integration-tested and SAFETY-reviewed); mutex-poisoning cascade is only partly testable (the real fix is `lock().unwrap_or_else(|e| e.into_inner())` or `parking_lot`); performance/density are **tracked metrics, not gates** (§13); the `#[non_exhaustive]` omission itself stays a review item (semver-checks catches the resulting break).

### 12.7 Defect → guard index

| Defect | Guard | Type |
|---|---|---|
| No `Drop` teardown; leak on panic | `FakeVmm` Drop-order unit test + `lifecycle.rs` panic-residue test | unit + integ |
| Temp-dir collision on PID-only path | path-injectivity prop test + `concurrency.rs` | unit + integ |
| Dependency unconditional under a gate | `cargo hack` feature powerset | CI matrix |
| `.unwrap()`/`panic` on hot path | `deny(clippy::unwrap_used, …)` under `not(test)` | lint |
| `DefaultHasher` cache key | golden-digest + cross-process `cache_key` test | unit |
| Undocumented `unsafe` | `deny(undocumented_unsafe_blocks)` + `unsafe_op_in_unsafe_fn` | lint |
| `println!` logging, swallowed errors | `deny(clippy::print_stdout, print_stderr)` → forces `tracing` | lint |
| `warn(missing_docs)` let items pass | `deny(missing_docs)` + `-D warnings` in CI | lint + CI |
| Missing `restore()`; cold/warm conflation | `Vmm::restore` in the trait + `FakeVmm` restore-path test | API + unit |
| Missing `reconnect()`; severed vsock | handshake-FSM EOF→accept unit test + `snapshot_restore.rs` | unit + integ |
| `build()` doesn't validate | `config::build()` validation tests | unit |
| CID/VMID wraparound, not injectable | allocator unit + contention tests | unit |
| Thread/FD leak; no shutdown | cancellation+`Drop` join test | unit |
| Fragile 4096-byte HTTP parse | response-parser tests (chunked/large/2xx) | unit |
| Steering preserves destination | golden-render + observed-destination integ assertion | unit + integ |
| Agent does its own networking | zero-netlink assertion via `Netlink` fake | unit |
| `put_file()` silent no-op | round-trip integ test + `deny(clippy::unimplemented/todo)` | integ + lint |
| Pipeline stubs (`reset_to`, stage I/O) | cache-hit / `reset_to` / determinism tests | integ |
| `cargo test` fails off a capable host | `#[ignore]` + `serial-host` group; split unprivileged/privileged suites; nextest timeout | test cfg |
| Silent no-op on a missing capability | `HostCapabilities` probe + typed `CapabilityUnavailable` on requested ops; `CgroupFs`-fake test | unit + review |
| Snapshot law unenforced for a data share | reject at `build()` + `restore()` + backend self-guard; a negative test at each | unit + integ |
| Cache key varies by `HashMap` order / hashes abs paths | cross-process golden key on a **real** stage; sorted inputs; content-of-upstream | unit |
| Theatrical restore assertion (dead `FakeClock`, self-reseed) | `FakeClock` drives the *first* post-restore call; capture pre/post entropy without self-reseed | integ |
| Recipe/test filter selects 0 tests (skip==pass) | CI fails on "0 tests run"; named suites with visible skip-with-reason | CI |
| Lean binary re-couples to host stack | build+clippy each of the 4 targets + `cargo tree` lean assertion | CI |
| Guest-drivable panic (RX vring `.expect`) | mirror the defensive TX handling on RX; smoltcp loop has no `.expect` on guest-shaped input | review + test |
| Stale artifact silently booted | guest-agent-change re-bakes rootfs (e2e); harness fails loud if artifact older than its sources | integ |

### 12.8 Privileged tests without `sudo -E`: the capability runner

**The problem.** `sudo -E cargo test` runs the *entire* toolchain as root — rustc, build scripts, nextest, the test binaries — so `target/` fills with root-owned artifacts the next unprivileged `cargo build` cannot overwrite, and cargo's cache/env shift. It is also maximally broad: everything gets full root when the privileged tests need only three capabilities — **`CAP_NET_ADMIN`** (tap, rtnetlink, nft/TPROXY), **`CAP_SYS_ADMIN`** (per-test netns + `setns`), and **`CAP_DAC_OVERRIDE`**. The third was missing from the v12 two-cap set and was load-bearing (observed, v13): `netns_rs::NetNs::new` must create `/var/run/netns/<name>`, a `root:root 0755` dir the dev-uid process can't write, so the *entire* tap path failed at `EPERM` until `DAC_OVERRIDE` was added; it also enables the benchmark-only sysfs/kernfs knob writes (CPU-frequency pinning, KSM — §13), which honour `DAC_OVERRIDE` (whereas `drop_caches`, a procfs sysctl special-cased on `euid==0`, does not). KVM access is *not* a capability — `/dev/kvm` is governed by the `kvm` group, granted once with `usermod -aG kvm $USER`.

**The mechanism.** `vmcell-test-runner` is registered as the cargo/nextest **target runner** for the privileged suite, so nextest invokes `vmcell-test-runner <test-bin> <args…>` instead of executing the test binary directly. cargo and rustc stay **unprivileged**; only the test binary is wrapped. The helper holds exactly `CAP_NET_ADMIN`+`CAP_SYS_ADMIN`+`CAP_DAC_OVERRIDE`, injects them into the test process via the **ambient** capability set, and execs the test **as the invoking developer's uid/gid** — so test-created files are dev-owned and the test runs with three capabilities, not full root. It stays **dependency-thin (`rustix` + `capctl` + `libc` — see the precision note below) and initializes no tracing/logging stack at full privilege** — diagnostics, if any, come after the privilege drop. (`bench-vm` reuses the same runner.)

**Blessing it — one-time, redone only when the helper itself rebuilds.** Two forms, least-privilege first:

- *File capabilities (preferred).* `sudo setcap cap_net_admin,cap_sys_admin,cap_dac_override+ep target/<profile>/vmcell-test-runner`. The helper then holds *only* those three caps, never full root, and already runs as the dev uid. Use **`+ep`** (Permitted **and** Effective), not `+p`: the runner's precondition checks its **effective** set, so a `+p`-only blessing leaves the caps un-raised and the check still fails — the printed remediation must therefore say `+ep` too (a v12 message printed `+p` and was unfollowable, review finding). (Requires a filesystem with security xattrs, not mounted `nosuid`.)
- *setuid-root (fallback).* `sudo chown root:$(id -gn) … && sudo chmod 4750 …`. Use **4750 with the developer's group**, not `4755`: a world-executable setuid-root binary that hands out `CAP_SYS_ADMIN` is a local privilege-escalation on a shared box. It momentarily grants all capabilities on exec, so it must `prctl(PR_SET_KEEPCAPS,1)`, drop to the dev uid (`setresgid`/`setgroups`/`setresuid`) *before* raising ambient, and trim `P`/`E` to the three caps. The file-cap form needs none of that dance because it never changed uid. (There is **one** privilege-drop path — no dead second setuid block to obscure the security-critical ordering, a v12 cleanup the review flagged.)

Both blessings are **stripped whenever the file is rewritten** (writing the file clears the setuid bit and file caps alike) — a *security feature*: re-blessing is a deliberate root action, so a rebuilt or tampered helper silently loses its powers instead of running modified code with privilege. The cost is the maintainer's standing pain — `just bless` bit far more often than "only when the helper changed," because *cargo rewrites the binary for reasons unrelated to the helper's source* (the v15 root-cause analysis and the durable fix are the churn block below; v15 **commits** that fix rather than carrying it as forward work). The hand-off, file-cap form — note the confinement root is taken from the **exec target**, not from the runner's own path (the v15 fix that makes the stable-path install of churn-fix #1 actually work):

```rust
// vmcell-test-runner — sketch (rustix + capctl + libc); no async, no lib, no tracing stack
let need = [Cap::CAP_NET_ADMIN, Cap::CAP_SYS_ADMIN, Cap::CAP_DAC_OVERRIDE];
ensure_blessed_or_explain(&need)?;                 // checks the EFFECTIVE set; else print `+ep` fix, exit non-zero
let target = argv.get(1).ok_or(Usage)?;
let target = canonicalize_reject_dotdot(target)?;  // reject `..` on the RAW input first, then canonicalize
confine_under_target_dir_of(&target)?;             // v15: confinement root = the nearest `target/` ancestor of the
                                                   // TEST BINARY (always under target/), NOT of /proc/self/exe — the
                                                   // runner now lives at a stable path OUTSIDE target/ (churn-fix #1),
                                                   // so anchoring on its own path would refuse every test (the bug v15 fixes)
let next = plan_privilege_transition(CapState::get_current()?, &need, geteuid());  // PURE — unit-tested (churn-fix #3)
apply_privilege_transition(next)?;                 // the thin syscall edge: setresuid/setgroups, set_current, ambient::raise
Command::new(&target).args(&argv[2..]).exec();     // execve; ambient set survives into the test binary
```

**Fail loud, print the fix.** On startup the helper checks its **effective** set holds `need` (or `geteuid()==0` for the setuid form); if not — almost always because it was just rebuilt — it exits non-zero and prints the exact `setcap … +ep` command, with the path resolved from `/proc/self/exe`. A `just bless` recipe wraps it (and **must build with `--features test-runner`** — a v12 `bless` that omitted the feature built the wrong binary, review finding), so the dev loop is *rebuild → `just bless` → run*. The helper never invokes `sudo` itself (circular) — it only prints.

**Threat model.** This is a **developer-workstation** convenience, explicitly **not** for multi-tenant or production hosts. `CAP_SYS_ADMIN` is root-equivalent in blast radius, so the privilege boundary is *who may execute the helper*: restrict it to the developer's group, keep its code minimal, drop the bounding set. The `ensure_under_cargo_target_dir` check is defense-in-depth, not the boundary. If test processes must hold **zero** standing privilege, the heavier alternative is a small **setup broker** (a privileged daemon that creates netns/tap/nft on request and passes back fds) — more secure, more machinery, a separate design. CI runners that are single-tenant and ephemeral can keep a dedicated root job.

**Reducing re-bless churn — the maintainer's standing pain, fixed in v15 (`todo.md` #2).** The dev loop was *rebuild → `just bless` → run*, and the re-bless step bit far more often than "only when the helper itself changes." **Root cause: writing the binary file strips its caps, and `target/<profile>/vmcell-test-runner` is rewritten by churn unrelated to the helper's own source.** Three distinct triggers, all observed (impl-notes): (a) **`RUSTFLAGS` differences** — a plain build vs `just ci`'s process-wide `RUSTFLAGS=-D warnings` re-fingerprints *every* target, the runner included, and re-emits the file; (b) **feature-set toggles** — `cargo nextest run --all-features` (the unit suite) builds the runner `[[bin]]` because `--all-features` turns on `test-runner`, whereas `just bless` builds it under `--features test-runner`, and the two fingerprints differ; (c) **profile/toolchain changes**. Note the runner already has **no `lib.rs` edge** (it imports only `rustix`/`capctl`/`libc`, never `vmcell::`), so library churn does *not* rebuild it via a dependency edge — the churn is fingerprint/feature-driven, not dependency-driven, which is why the workspace split alone (#4 below) does **not** fix it and the stable-path install (#1) is load-bearing. v15 **commits** four composing changes, the first three of which together end the pain without the structural #4:

1. **Decouple the blessed artifact from `target/` — the load-bearing fix.** `just bless` builds the runner once, **installs a copy to a stable path outside the cargo target tree** — a gitignored, project-local `./.vmcell-bin/vmcell-test-runner` (project-local, not `$CARGO_HOME/bin`, so two checkouts can't fight over one blessed binary) — and `setcap`s *that copy*; the nextest target-runner (`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER`) points at the stable path. Cargo's churn in `target/` then never touches the blessed binary, so re-bless is needed only on a deliberate reinstall. This is robust to *all* the unrelated rebuild triggers above, **including the `RUSTFLAGS` re-fingerprint that a workspace alone cannot fix**.
   - **The confinement-root fix this requires (a latent bug in the v14 plan).** Moving the runner out of `target/` would have *silently broken every test*: `ensure_under_cargo_target_dir()` derived its confinement root from the runner's own `/proc/self/exe` by walking to the nearest `target/` ancestor — and a runner at `./.vmcell-bin/` has no such ancestor, so the check fails closed for every exec. v15 re-sources the confinement root from the **exec target's** path: the test binary nextest hands the runner is *always* under `target/`, so its nearest `target/` ancestor is the real cargo target dir. `confine_under_target_dir_of(target)` canonicalizes the target (rejecting `..` on the raw input first, fail-closed on a non-existent path), finds *its* `target/` ancestor, and confirms descent — a *stronger* defense-in-depth than anchoring on the runner's location, and the precondition that the install-to-stable-path fix is even functional.
2. **Make `just bless` idempotent with a content-hash *stamp* keyed on the *runner* (never on test binaries).** `just bless` records `sha256(./.vmcell-bin/vmcell-test-runner)` in a sibling `.blessed` stamp (per profile); on re-run it skips the `sudo setcap` when the hash is unchanged, so re-blessing is a transparent no-op until the runner genuinely changes — `setcap` is idempotent and cheap, so the stamp gates the *prompt-for-sudo*, not correctness. **The stamp hashes the runner binary, and nothing else.** The runner **must not hash, pin, or allowlist the content of the *test* binaries it execs** — it is a generic privilege-injector, the security boundary is *who may execute the runner* (group-restriction) plus the path-confinement of #1, and test-binary *identity* is explicitly out of scope. Pinning test-binary hashes would re-introduce precisely the per-iteration churn this whole block removes (every code edit changes a test binary), while adding no security the confinement + exec-permission boundary doesn't already provide. This is a hard design rule, not an omission.
3. **Test the privilege transition as pure logic, so the runner rarely *needs* changing (the "more robust test suite" ask — the deepest fix).** The runner already unit-tests its pure helpers — `blessing_remediation` (`+ep`, not `+p`), the path-descendant confinement (`..` rejected before canonicalization, sibling-prefix rejected), and `merge_preserved_groups` (kvm-gid preserved iff held, never invented/duplicated). The remaining untested sliver was `main()`'s capability-state sequence (inheritable-add → bounding-drop → ambient-raise → permitted/effective trim) and the uid drop, untested only because they mutate the live process. v15 extracts that sequence into a **pure `plan_privilege_transition(current: CapState, need, euid) -> Plan`** — computing the next `CapState`, the bounding-drop set, and the uid/group plan from in-memory inputs — and unit-tests every step against its buggy inverse: a forgotten ambient-raise; a bounding set left wide; an inheritable not added; **the security-critical setuid-form ordering (uid drop *before* ambient raise)** that a later refactor could silently invert. Only the thin `apply_privilege_transition` (`setresuid`/`setgroups`/`set_current`/`ambient::raise`) and the final `exec` stay integration-only. With the logic covered *off* the privileged path, runner edits are verified *before* a bless — the privileged suite stops being the iteration loop for runner logic, which is the structural reason the runner now rarely changes (and so rarely needs re-blessing) at all. The §12.4 privileged-suite bullet that listed this as "forward work" is updated to "covered."
4. **Promote the privileged-window binaries to cargo *workspace member crates* (structural — committed; see §10.1).** A `vmcell` library crate, a tiny shared `vmcell-protocol` crate, and member crates `vmcell-test-runner` / `vmcell-guest-agent` / `vmcell-guest-tools`, each with its own `Cargo.toml`, dependency closure, and lint header, turns the §12.2 lean-tree assertion into a **per-member structural property** instead of a feature-gated whole-package check, and guarantees by construction that no host module can leak into the runner. It does **not**, on its own, stop the `RUSTFLAGS`/feature re-fingerprint (members share `target/` and `RUSTFLAGS`), so #1 remains the durable fix and #4 composes with it — the answer to the todo's "should we switch to a cargo workspace?" is **yes**, for the structural leanness boundary, with #1–#3 as the part that actually ends the re-bless churn.

**Dependency precision (deviation recorded).** The runner is **not** `rustix`+`capctl` *only*: the setuid-root fallback's group/uid drop uses `libc` (`getgrnam`, `getgroups`, `setgroups`, `setresgid`, `setresuid`), which rustix/capctl don't cover — three deps, all permissive, still no async/host stack. The §12.2 lean-tree assertion bans `tokio`/`hyper`/`rtnetlink`, none of which `libc` pulls, so the leanness property holds; §10.4's doc and the binary's doc-comment should read `rustix` + `capctl` + `libc`.

**Setup broker — promoted for the non-testing domains.** The capability runner wraps *test binaries* invoked by `cargo nextest`; that model does **not** fit the **agentic** and **serverless** domains, where many short-lived VMs are created by a long-running service. Those consumers want the **setup broker** (a small privileged daemon that creates netns/tap/nft on request and hands back fds). v14 keeps the capability runner as the *testing*-domain answer and promotes the setup broker from "heavier alternative" to the **recommended privilege boundary for the daemon/API mode** (§16) — one audited privileged surface serving an unprivileged service, which is both more secure and more operable than blessing a binary.

---

## 13. Performance: measured results and the benchmark plan

The design rests on performance assertions; this section is the instrument that settles each. Two framing rules carry it. First, **benchmarks are tracked metrics, not pass/fail gates** — absolute boot/restore/density numbers are hardware-bound, so a fixed threshold would be a lie on a different box; the exception is the few *relative* invariants in §13.7. Second, **a number is meaningless without its substrate**: every result records the pinned CH/virtiofsd/kernel build from `pins.json`, the host CPU/RAM/storage, and the THP/KSM/`memory_restore_mode` settings. A milestone's performance claims are not "settled" until its benchmark has run on the pinned substrate.

### 13.1 Measured numbers

**Micro (criterion, 100 samples, in-process):**

| Benchmark | What it measures | p50 |
|---|---|---|
| `protocol_encode` | `postcard` length-delimited encode of `Message::Exec` | ≈56 ns |
| `protocol_decode` | `postcard` length-delimited decode | ≈83 ns |
| `cache_key_generation` | hashing struct variants + configs for the artifact cache key | ≈218 ns |
| `math_30_ipv4_parse` | `/30` host-IP parse (`10.200.<vmid>.1`) | ≈29 ns |
| `in_memory_tar2erofs_empty` | erofs node-tree pack of an empty tar stream, in-memory | ≈1.23 µs |

The control-plane codec and the per-VM address/cache math are tens-to-hundreds of nanoseconds — far below anything that gates a multi-second VM lifecycle.

The full suite **has now run** on the committed pin (the v12 entries here were research-era estimates). The canonical, current-config numbers live in `docs/benchmark-results.md`; the highlights below are tagged with their substrate. **Substrate:** Intel Core Ultra 7 258V (Lunar Lake, 8c/8t), 30 GiB RAM, ext4-on-NVMe (`/tmp` is tmpfs); CH v52.0.0 / FC v1.16.0 / QEMU 10.2.1 / virtiofsd 1.13.3; guest kernel 6.12.94; THP `madvise`, KSM on; **freq-pinned to the sustained 2.2 GHz base** (turbo off), which is the *representative dense-operation clock* — when many VMs keep all cores busy, turbo can't engage. Two honest caveats: **"cold" is warm-cache** (`drop_caches` is special-cased on `euid==0` and tmpfs pages are immune, so true cold isn't reachable on this host), and the box is shared/loaded — so quote **central tendency, not tails/SLAs**.

**Macro — cold boot to agent-`Ready`** (N=20; warm-cache; mem 256 MiB):

| Backend | Cold p50 / p95 / max |
|---|---|
| **Cloud Hypervisor** | **≈635 / 669 / 669 ms** |
| **Firecracker** | **≈1022 / 1038 / 1038 ms** |
| **QEMU** (`q35`) | **≈1405 / 1732 / 1732 ms** |

**Macro — warm restore to agent response** (`MicroVm::restore` → vsock reconnect → agent replies; N=20):

| Backend | Warm restore p50 / p95 / max |
|---|---|
| **Firecracker** | **≈128 / 138 / 138 ms** |
| **Cloud Hypervisor** | **≈169 / 179 / 179 ms** (default ≈ lazy; eager ≈258) |
| **QEMU** (`q35`) | **N/A** (snapshot-ineligible in unprivileged+vsock, §3.3) |

Reading these together:

- **The restore numbers validate the snapshot tier and invert the cold-boot ordering for the metric that matters.** Restore is **≈3.7× faster than cold boot on CH (635→169 ms) and ≈8× on Firecracker (1022→128 ms)** — the empirical justification for restore-over-cold-boot on the per-test path. And **Firecracker *wins* restore (≈128 ms) over CH (≈169 ms)** — the reverse of cold boot — so it earns the **density + snapshot tier** while CH stays the feature-complete default and cold-boot leader. (The absolute ms are higher than v12's research-era 324/47 because cold is warm-cache, the host is shared, and the clock is pinned to the 2.2 GHz *base* not a 4.7 GHz turbo burst; the **relative** warm-vs-cold and cross-backend invariants — the load-bearing claims — reproduced.)
- **CH lazy restore (`prefault=off`, userfaultfd) is ≈1.5× faster than eager** (lazy ≈176 / eager ≈258 ms freq-pinned — ≈82 ms; default ≈169), settling the §14 #3 userfaultfd question — but the win **understates lazy's true cost**, which reappears as in-guest first-touch page faults *during execution*, so "lazy wins" is for time-to-resume, not necessarily time-to-first-useful-work.
- **The optimistic vendor cold-boot figures remain refuted.** Cold boot is ≈79–89% guest-kernel-boot + agent-startup wait (the `connect` phase, §13.4); the multi-`PUT`/REST config is ≈1 ms, so chasing the REST path won't move it.

The footprint, suspend-size, datapath, image-size, and musl-vs-glibc benchmarks that v12 listed as "defined but not yet run" are **now measured** — §13.3/§13.4/§13.6 below carry the results, and `docs/benchmark-results.md` is the canonical table.

### 13.2 Harness, method, and noise discipline

Two tiers. **Micro (in-process, no KVM) — `criterion`:** the pure and IO-light hot-path code (the codec, `cache_key`, the `/30` math, the in-memory tar→erofs pack, a loopback vsock round-trip). criterion's sample-many-iterations model is correct here and only here. **Macro (full-system, KVM + sometimes root, default-skipped) — the `bench-vm` custom harness:** everything that boots a VM (cold-boot, restore, idle RSS, density ceiling, datapath throughput), on the same gated CI runner as the integration suite — **not** under `cargo bench` — recording a full latency **distribution**, not a sampled mean. On a dev box its privileged runs go through the §12.8 capability runner. `bench-vm` is itself under CI (`tests/benchmark.rs` runs it with `--iterations 1 --warmup 0` across every compiled-in backend so the benchmark code path stays green).

The discipline that makes macro numbers honest: report distributions (p50/p95/p99/max — boot and restore are tail-heavy); treat cold vs warm as a deliberate axis (drop the page cache before cold runs, warm it before warm runs, since page-cache sharing is itself under measurement); control the noise floor (pin harness and VMM to disjoint cpusets, fix CPU frequency, record the storage backend); never fold one-time build costs into per-test; and treat the VMM as a primary axis — each macro benchmark runs against each compiled-in backend that supports the feature, skip-not-fail for unsupported, so the cross-backend comparison is itself a result.

### 13.3 The contested-fact benchmarks

Each contested or asserted performance claim, the benchmark that settles it, and the misreading it guards against:

| Claim | Benchmark | Metric(s) | Misreading it guards against |
|---|---|---|---|
| **Shared-erofs page-cache density** | Boot 1→N guests off the shared base, fixed workload | host **file-backed pages attributable to the image** as N grows; **marginal host RSS per added guest** | reading total host `used` (conflates anonymous guest RAM with shared file cache) |
| **Demand-paged boot working set** | same boot, slim base vs a deliberately fatter base | **pages faulted in during boot** and **boot latency**, vs total image size | assuming on-disk image size ≈ RAM/time cost; untouched files are never paged |
| **userfaultfd lazy restore** | restore the same snapshot, eager vs lazy (CH `memory_restore_mode` vs Firecracker UFFD) | **restore→resume latency**, **post-resume RSS**, **time-to-first-useful-work** | quoting resume latency alone — lazy restore moves cost to first-touch faults |
| **Cold-boot latency** | `create→boot→agent Ready` on the real stack | latency distribution, **console-on/off as an explicit axis** | comparing a console-off vendor figure against a console-on local run |
| **Restore latency, per-test critical path** | `restore→resume→reconnect→Ready` incl. identity rotation + RNG reseed + clock resync | distribution of the *complete* warm-start path | timing `resume` but omitting the mandatory reconnect+rotate+reseed |
| **Guest RAM footprint** (idle, under-load, restored) | park a booted/restored VM idle, then run a representative test workload, 1→N guests | **anonymous RSS** (the figure that bounds the RAM tier) split from **shared file-backed pages** (which don't), at idle / under-load / post-restore, each **pre- and post-KSM/balloon**; **marginal RAM per added guest** | reading total host `used`, or an idle-only / pre-balloon-pre-KSM snapshot — under-load *anonymous* RAM is what sets the density ceiling, and the agent runtime (glibc vs musl, below) is part of it |
| **Guest-agent toolchain: musl vs glibc** | build `vmcell-guest-agent` both ways (dynamic-glibc default, static-musl) and boot each | **agent on-disk size**, **agent RSS contribution**, **fork→`Ready` startup latency**, and **rootfs-independence** (does it boot on a base without `libc6`?) | assuming "static musl ⇒ strictly better" — musl trades a larger binary and a different `malloc`/perf profile for portability; on the boot path the startup/RSS delta may be negligible, making the real axis CI-toolchain availability + rootfs-independence, not speed |
| **Density ceiling + start throughput** | ramp concurrent VMs per RAM tier to first OOM; separately, sustained starts/sec | **max concurrent VMs per RAM tier**; **sustained start rate** under teardown pressure | a peak instantaneous rate vs a sustained rate while teardown competes |
| **Snapshot ↔ virtio-fs-data composition** | attempt restore with a virtio-fs *data* share attached | **boolean composes/fails**; if it fails, the **fallback cost** (RO data as an extra erofs/block image) | treating this as pure correctness — the fallback has a real density cost |
| **OCI-vs-mmdebstrap hot-path parity** | run the boot/restore/density benches against the *same* erofs built from each source | **delta** (expected ≈ 0) | assuming the source can affect the hot path — it must not, since both produce the same erofs |
| **Snapshot-size independence** | snapshot the same workload on slim vs fat rootfs | **snapshot artifact size** and **restore latency** vs rootfs size (expected ~flat) | assuming a bigger rootfs ⇒ a bigger/slower snapshot |

Three rows are backend-shaped (must include Firecracker as well as CH, since those settle the disputed *Firecracker* figures): cold-boot, density/throughput, guest RAM footprint. The lazy-restore row is **CH and Firecracker** (two different lazy-restore mechanisms). The snapshot↔virtio-fs-data probe is **CH/QEMU only** (Firecracker has no virtio-fs to compose with snapshot). The musl-vs-glibc row is **not** backend-shaped — the agent build is identical across backends — so it runs on the default backend (CH) only.

**Settled results (v13; canonical numbers in `docs/benchmark-results.md`).** Most of these ran and several *inverted* their hypothesis:

- **Shared-erofs density / footprint** — each CH guest demand-pages **≈58 MiB** (host `RssShmem` via memfd, *not* `RssAnon` as v12 assumed), dead-linear per added guest; ceiling ≈230 idle / ≈52 if each faults its full 256 MiB. Agent PID 1 is ≈2.4 MiB.
- **userfaultfd lazy restore** — **confirmed**: lazy ≈1.5× faster than eager (≈82 ms; and now actually plumbed via `restore_mode`; it was a *dead advertised capability* in v12 — `lazy_restore: true` with no `prefault` wiring, the exact "dead flag" the rubric bans, fixed).
- **KSM** — default dedup is **0** (CH shared memfd isn't `MADV_MERGEABLE`); the opt-in `ksm_mergeable` lever (mergeable=on, shared=off) deduplicates **≈394 MiB / ~84%** across 8 identical guests (§9.3).
- **Snapshot ↔ virtio-fs-data composition** — **answered by construction**: `config::build()` rejects it (§3.3), so the empirical CH-refusal is unreachable; RO data in the snapshot tier is served as an extra erofs/block image.
- **OCI-vs-mmdebstrap hot-path parity** — both produce the same erofs, so the hot path is source-independent (delta ≈ 0, by design); the *size* delta inverted (OCI smaller, §13.6).
- **musl vs glibc** — static-musl is **~6.2% *larger*** (it static-links libc/libgcc rather than borrowing the rootfs `libc.so.6`); the real axis is toolchain-availability + rootfs-independence, **not** size, so glibc-dynamic stays the default (§13.3 confirmed the hypothesis).
- **Snapshot-size independence** — **confirmed**: suspend size tracks guest RAM exactly and is flat in rootfs size (§13.6).
- **Kernel version** — **not a material hot-path lever** (interleaved 6.6.143 vs 6.12.94 within ~2%, §8.3).

### 13.4 Per-test critical-path budget

The number density and throughput ultimately reduce to. Instrument one test end-to-end as `tracing` spans — acquire artifacts → allocate {slice, net, CID} → start {restore | cold-boot} → vsock connect + handshake → exec → collect → ordered teardown — and report the **distribution per phase**, so a regression is localized to the phase that moved. Two budgets: the **restore path** (the hot path) and the **cold-boot path** (opt-in). Teardown is on the budget on purpose: the reap-VMM-first ordering trades a little teardown latency for the no-leak guarantee, so that cost is measured, not assumed-free. **This budget is now instrumented (v13), closing the v12 "highest-value remaining instrumentation" gap.** Measured shares (CH, canonical `docs/benchmark-results.md`): **cold** is ~**89%** the `connect` phase (guest-kernel-boot + agent-startup wait), ~6% create/spawn, ~4% teardown, ~1% exec — which is exactly *why* the restore tier exists, to delete that phase. **Restore** is dominated by the same `connect` phase — **reconnect + RNG/clock resync ~58% (≈115 ms, the single largest phase)** — then restore+resume ~27% (≈54 ms), **teardown ~14% (a real ≈27 ms**, confirming "teardown is on the budget on purpose"), and exec ~1%. The datapath floor is sub-millisecond (vsock exec round-trip p50 ≈0.7 ms incl. in-guest fork/exec/reap), so `exec` responsiveness is never the bottleneck.

### 13.5 Density, datapath, and build-time

- **Density levers as tracked numbers (§9.3):** KSM dedup ratio (`pages_shared`/`pages_sharing`) and its CPU cost; balloon/free-page-reporting pages reclaimed and reclaim latency; the shared-erofs image-attributable-pages figure; idle and marginal RSS per guest. The per-RAM-tier ceiling is their joint product.
- **Datapath:** vsock frame round-trip latency and IO-streaming throughput (gates `exec` responsiveness); virtio-fs per-share throughput with attention to `vmcell-bin` (its page-cache hit behaviour is a density lever); egress-proxy overhead privileged (tap+TPROXY) vs unprivileged (smoltcp L4, CH/QEMU only), putting a cost number next to the fidelity/convenience trade; the reflink overlay cliff (conditional — only if a writable disk overlay is used).
- **Build-time (offline), paid once per pin, never folded into per-test:** erofs build wall-clock OCI vs `mmdebstrap`-in-VM (as a *whole-pipeline* number including the builder-VM boot); source/blob cache cold vs warm; `am-fs-erofs` pack throughput; builder-VM amortization (build-time-per-pin ÷ tests-per-pin).

### 13.6 Artifact and state sizes on disk

The density story has a disk side as well as the RAM side above; two on-disk sizes are tracked per pin. Both are *static* byte measurements (not latency distributions), recorded with the same substrate tag.

- **Rootfs image size — OCI slim base vs a minimal `mmdebstrap` build (§8.2, Appendix B Exp 4).** The measurement that decides whether the more complex builder-VM source earns its keep. Both sources feed the *same* `am-fs-erofs` packer and the *same* shared tail (agent + CA + scaffolding injected identically), so the size difference reduces to the **base rootfs content**. Measure the **packed erofs image** (the artifact that actually boots) two ways: the OCI `debian:trixie-slim` pull, versus an `mmdebstrap` build restricted to the packages the harness actually needs (a `minbase`-class minimal-but-still-boots variant — the agent runs as PID 1 over a shell, so the working set is small). Also record the merged tar and the erofs under each candidate compressor (uncompressed vs lz4/zstd — a size/page-cache trade, §8.3). The hypothesis is that `mmdebstrap` yields the **smaller** image: a slim *image* still ships apt, `perl-base`, and other defaults the harness never touches, whereas `mmdebstrap` includes only what is asked for. If that size win is real, it is the **second** benefit that justifies the builder VM (the first being the full apt signing chain, §8.2), so this number — not an assumption — is what the cost/benefit of the `mmdebstrap` path turns on. **What the size is and isn't:** it is a *disk, one-time-cache-warm, and cold-boot-working-set* cost, **not** a per-test RAM or latency cost — erofs over virtio-blk is demand-paged and shared, so a fatter image never pages in its unused files and does not slow an individual test (the §13.3 demand-paged-working-set row). A smaller `mmdebstrap` image therefore buys host disk, a cheaper first-boot cache warm, and snapshot-pool headroom — which, with one shared erofs copy serving all guests, compound at high density — rather than per-test speed. **Result (v13) — the hypothesis INVERTED:** the OCI slim base packs to **≈79.2 MB uncompressed erofs** vs mmdebstrap-minbase **≈165 MB** (bookworm) / **≈120 MB** (trixie, apples-to-apples) — the OCI base is **~34% smaller apples-to-apples (trixie, 79 vs 120 MB)** — and ~52% vs the cross-release mmdebstrap-minbase-bookworm 165 MB — because the official Debian image carries `dpkg path-exclude` rules stripping `/usr/share/locale` (~32 MB), `/usr/share/doc`, and man pages that a plain `mmdebstrap minbase` keeps. So the builder-VM source earns its keep on **provenance** (and on provisioning tools the slim base omits, §5.3), **not** size — unless it adds those excludes. **Variant note (v16):** the −34% figure is measured against `mmdebstrap --variant=minbase` (≈120 MB), but the pipeline's *actual* `RootfsBuildSource::Mmdebstrap` builds `--variant=apt --include=curl,ca-certificates` (measured **≈129 MB**), not minbase, so the pipeline's real OCI advantage is **−38.7%** — larger than the −34% against minbase. (The packer ships **uncompressed** on both paths — an lz4/zstd size opportunity; zstd would roughly halve on-disk size — OCI ≈45 MB — at the cost of host page-cache duplication + per-read guest decompress, a runtime trade not taken for a short-lived rootfs.)
- **VM suspend-state size on disk, per backend (§9.1).** Measure the bytes a single snapshot writes: for **Cloud Hypervisor**, the snapshot directory (config JSON + device/`vmm` state + the **guest-memory file**, which dominates); for **Firecracker**, the **memory-snapshot file** + the vmstate file. Report the total and the memory-file share, and — the load-bearing point — measure it **against guest RAM size and against rootfs image size**: the expectation is that suspend size tracks **guest RAM**, not the rootfs (snapshots capture RAM, not the read-only disk), so a 256 MiB-RAM guest writes an ≈256 MiB-class memory file whether the rootfs is slim or fat. This is the *absolute-size* companion to the §13.3 snapshot-size-**independence** row (which asserts the size is flat in rootfs size): together they state *how big* a suspend image is and *what it does (not) scale with*. It also sizes the **snapshot pool on disk** — N pooled warm bases cost ≈N × the per-snapshot memory file, which is the disk-capacity ceiling on how many can be kept resident, and the reason sparse-snapshot (`SEEK_DATA`/`SEEK_HOLE`, §14) and zero-page handling matter for pool density. **Result (v13) — confirmed:** suspend size tracks guest RAM *exactly* (256 MiB→268.5 MB total, the memory file 100% of it + ~52 KiB CH / ~14 KiB FC of vmstate; 512→536.9 MB) and is **flat in rootfs size** (the full injected rootfs — ≈79 MB base + agent/tools/CA ≈ 85 MiB — contributes nothing). The memory files are **dense** (no holes), so sparse-snapshot is the lever that would shrink an N-snapshot warm pool from ≈N×mem to its touched-pages footprint.

### 13.7 Tracked metric vs regression guard

Most of §13 is observational; a minority graduates to a guard. **Stays observational (no threshold):** absolute cold-boot/restore ms, density ceiling, start throughput, guest RAM footprint, absolute rootfs image size, absolute suspend-state size, the musl-vs-glibc agent deltas (size/RSS/startup), and the **kernel-version sweep** (a tracked dimension via the `kernels` registry, §8.3 — it informs the pin, found no material hot-path effect, and never gates) — all either hardware-bound or base/pin-dependent, so they trend across pins and inform the per-tier and agent-build defaults but never gate. **Becomes a regression guard once a baseline is pinned** — the *relative* invariants, portable across hardware because they are deltas or ratios: OCI-vs-`mmdebstrap` hot-path parity (delta ≈ 0); boot working set flat in image size; snapshot size flat in rootfs size (and tracking guest RAM); per-test critical-path **phase shares** (a phase doubling its share is a regression even when absolute ms move with hardware). Each guard is **per-backend**. **Cross-backend selection is a tracked output, not a guard:** the backend-per-tier default is informed by the cross-VMM numbers but re-read per pin, since relative VMM performance shifts with kernel/hardware/pinned builds.

---

## 14. Contested facts to re-verify per pin

These load-bearing facts came from mid-2026 research inputs that conflicted on several points (CH was at v52.0 and Kata 4.0 in preview at research time). The design does **not** hard-depend on the optimistic reading of any of them. **In v13 the §13 suite has run on the pinned substrate, so #1–#4 below are now settled (marked inline); #5–#7 remain re-verify-per-pin guidance.** Each was confirmed against the exact CH v52.0.0 / virtiofsd 1.13.3 / kernel 6.12.94 in the lock; a future pin bump re-runs the §13 suite to re-settle them.

1. **virtio-fs DAX is UNAVAILABLE in Cloud Hypervisor — confirmed (v13).** CH `docs/fs.md` states DAX "is not available in Cloud Hypervisor"; it was deprecated in CH v24.0, and the pinned v52 has it gone. **Consequence:** host page-cache sharing for read-only data cannot come from virtio-fs DAX; it is recovered by serving the read-only base over erofs/virtio-blk (one host-cached copy for all guests — measured: guest RAM is `RssShmem`, ≈58 MiB/guest, §13.3), with per-share virtio-fs at `cache=never`. Not a load-bearing assumption; if DAX ever returns it is an opt-in extra.
2. **Snapshot/restore and virtio-fs do not compose — SETTLED by construction (v13).** CH refuses to snapshot a VM with vhost-user devices attached. This is the §3.3 law, now **enforced at `config::build()`** (snapshotting + any virtio-fs rootfs/share/unprivileged-net is rejected), so the empirical "can a *data* share re-attach to a snapshotted VM?" question is **unreachable through the public API** — answered by construction. The snapshot tier serves read-only data via additional erofs/block images.
3. **userfaultfd lazy/demand-paged restore in CH** (`prefault=on|off`) — **CONFIRMED and now plumbed (v13).** It was a *dead advertised capability* in v12 (`lazy_restore: true` with no `prefault` wiring); v13 threads `RestoreMode` → `--restore …,prefault=on|off` and measures **lazy ≈1.5× faster than eager** (≈82 ms; §13.1/§13.3). (Sparse snapshot via `SEEK_DATA`/`SEEK_HOLE`, SEV-SNP, iommufd, and the `QcowDiskAsync` io_uring backend remain confirmed; sparse-snapshot is the un-taken pool-density lever, §13.6.)
4. **Boot-time numbers are workload-dependent — measured, optimistic figures refuted (v13).** Firecracker's "≈125 ms to `/sbin/init`" and "≤5 MiB overhead" are real AWS figures but measured with the serial console disabled and a minimal kernel/rootfs; "150 µVMs/s/host" is benchmark-specific. §13.1 measures the real stack (cold boot is ~79–89% guest-kernel-boot + agent-startup), and with snapshot/restore the cold numbers fall off the per-test critical path anyway. Do not quote a single boot number as authoritative across substrates — only the *relative* invariants travel.
5. **Nested-virt enablement.** There is **no** `--cpu nested=on` CH flag. Nesting is enabled on the **host** KVM module (`kvm-intel nested=1` / `kvm-amd nested=1`), the **guest kernel** must have KVM built in, and CH passes `kvm-intel.nested=1` on the **guest** cmdline. On AMD, once an L1 has started an L2 guest, that L1 should no longer be migrated/snapshotted.
6. **Do not depend on `herolib-virt`.** It is an obscure single-author crate whose CH module merely shells out to the `cloud-hypervisor` binary. Use first-party `ch-remote` + a thin hand-written REST client, or the unofficial-but-cleaner `cloud-hypervisor-client` (0.3.x, MIT OR Apache-2.0).
7. **Security hygiene.** CVE-2026-45782 (a virtio-block use-after-free) is fixed in CH ≥ v51.2 / v52.0 — the pinned **v52.0.0 carries it**. CH does not guarantee snapshot/restore compatibility across versions, so a snapshot pool must pin one exact CH (and virtiofsd) build.

---

## 15. Risks and open decisions

**Resolved since v12 (recorded so they aren't re-litigated):**

- **The snapshot ↔ virtio-fs-data fork — RESOLVED by construction.** v12's highest-risk open item. `config::build()` now rejects snapshotting with any vhost-user device (§3.3), so the empirical "does a data share re-attach?" question is moot; the standing fallback (RO data as an extra erofs/block image) is the decision. Snapshot/restore itself works end-to-end on CH and Firecracker after the v13 host-path fixes (§3.2, §9.2).
- **The `CgroupFs` testability seam — EXTRACTED.** It is now an injected `Box<dyn CgroupFs>` with a real impl and a recording fake (§7.2, §10.6); the cgroup-limit path is unit-tested against the fake. This closes the one v12 item that violated a load-bearing design invariant.
- **Full per-test critical-path instrumentation — DONE.** §13.4 now reports per-phase distributions for both cold and restore paths, including teardown and the resync phases.

**Still open:**

- **The v14 rename is specified but unexecuted.** §10.7. The code still carries `NetConfig::Rootless`, `TestVm`, and the `imp-testing`/`imp_testing` names; §10.7 is the migration checklist (rootless→unprivileged, `TestVm`→`MicroVm`, project→`vmcell`), and the end-to-end validation recorded in Appendix A/D ran under the *current* (`rootless`/`priv`, `TestVm`) names — so "the unprivileged and privileged suites pass" there refers to today's `just test-rootless`/`test-priv`. Executing the rename — renaming the recipes and the `test(rootless)` nextest filter in lockstep with the test functions (§12.4) so neither suite selects zero tests — is forward work.

- **In-process `fuse-backend-rs` does not enforce read-only.** Appendix B, Exp 1. An upstream-library constraint, gated behind `experiment-fuse` with `virtiofsd --readonly` as the enforced-RO fallback. Must close (or enforce RO in the passthrough) before the experiment graduates, since silent write-through on a share declared read-only would violate the `fs` contract.
- **QEMU snapshot: unprivileged path ineligible; privileged path validated but unwired.** §3.2. `snapshot_restore: false` over the unprivileged external-`vhost-device-vsock` path. The privileged in-kernel-`vhost-vsock` path is now **validated** (v16 audit: no QEMU-10.2 migration blocker + migrate→restore verified live); remaining work is the live agent-reconnect run + wiring `snapshot()`/`restore()` and flipping the capability for that config only.
- **Single-snapshot CoW for many clones.** §3.2/§9.1. The CH `config.json` and FC sidecar path rewrites are single-use (in-place); restoring N clones from one snapshot needs a copy-on-write of the snapshot dir first — forward work the warm-pool density story depends on (with sparse-snapshot, §13.6).
- **Live pin resolution.** §11.2. `ResolvePinsStage` loads a committed `pins.json` rather than live-resolving tag→digest / `snapshot.debian.org` timestamps; making Stage 0 refresh the lock itself is forward work. Relatedly, the **OCI fetch lacks an injectable record/replay seam** (a concrete `oci_client::Client` today), so requirement-7 record/replay + tamper tests can't yet run for OCI.
- **The fail-loud capability migration is the standing directive; the op-by-op classification is the remaining work.** §7.1, `todo.md` #3. The principle and the three rules are specified, and the functional core is **built**: `Error::CapabilityUnavailable` exists and `metrics` returns it (rather than `warn`-and-`Ok`) when a requested limit's controller isn't in the parent's `subtree_control`, with `limits_enforced` surfaced on `ResourceUsage`. v14 makes fail-loud the **default for every host-facing op** (best-effort is the explicitly-listed exception, not the fallback): each op declares its required capabilities in its doc-comment, callers check the specific capability before invoking, and a *requested* op whose capability is absent returns typed `Error::CapabilityUnavailable`/`Unsupported` — never a silent `Ok`. The per-mode suites now **test this from both sides** (§12.4): the unprivileged suite asserts a privileged-only request fails loud rather than silently degrading, and the privileged suite asserts limits are actually enforced (`limits_enforced=true`). The remaining work is the mechanical op-by-op audit (which functional ops fail loud vs the explicitly-listed best-effort §13 knobs), threading the typed surface through every call site, and consolidating today's scattered per-op checks into the single start-up `HostCapabilities` descriptor §7.1 describes (still unbuilt).
- **The cargo feature-matrix collapse is done; the workspace split + durable bless are SPECIFIED-AND-COMMITTED in v15 (implementation pending).** §10.1, §10.5, §12.8, `todo.md` #2. The legacy `cargo hack` powerset gate stays red on partial-host-combo debt only until the modules finish re-gating onto the single `host` feature; the four-target build gate (§12.2) is the replacement, becoming a **per-member structural property** once the workspace lands. v15 commits the **cargo workspace** (a `vmcell` lib + a shared `vmcell-protocol` crate + the three lean member crates, §10.1) and the **durable re-bless fix** (§12.8): install the blessed runner to a stable path *outside* `target/`, an idempotent content-hash *stamp* keyed on the runner (never test binaries), the **confinement-root fix** that makes the stable-path install functional, and the **pure `CapState` transition** tests. The remaining work is mechanical (move sources into `crates/`, per-member lint headers, migrate the CI lean-tree checks to per-member). The workspace alone does *not* fix the re-bless churn — the stable-path install does (the `RUSTFLAGS`/feature re-fingerprint hits shared `target/`); they compose.
- **A periodic background orphan-sweeper is still partial.** §6.4. `net::cleanup_orphan_netns` reaps leaked `/var/run/netns/vmcell-net-*` when invoked, but a leaked netns can still collide with a later vmid between runs; a periodic sweeper + orphan registry (rubric B1) is not yet automatic.
- **The rootfs source is a two-method fork with a pipeline→runtime dependency edge.** §8.2. The in-VM `mmdebstrap` source can only run once the runtime is solid (kernel + agent + CH + an `vmcell-out` share + builder egress), and a runtime regression can block a rootfs rebuild. Keep the OCI source self-sufficient so first boot never depends on the VM stack it is trying to build.
- **OCI reproducibility hinges on three things.** §11.2. Pin the manifest digest, never a tag; cache pulled blobs by digest (registry retention is the weak point); confirm `am-fs-erofs` output is byte-stable (fixed mtimes, deterministic inode/dirent ordering). If any fails, neither source produces a byte-identical image and the determinism tests catch it.
- **The carried `vhost-user-backend`/`vhost` patch** is a maintenance/reproducibility cost; drop it if QEMU-unprivileged is not required. §10.4.
- **The CLI subcommands are partial, but the v15 set is specified.** §10.2/§10.3. `build`/`build-kernels` work today; v15 specifies `oci2erofs` (§8.2) and the live-handle lifecycle verbs `create`/`run`/`snapshot`/`stats`/`destroy` taking `--kernel`/`--rootfs` (§10.2). `ls`/`rm` and a standalone `exec` remain **deliberately unimplemented** pending the `impd` daemon (§16.2) — they require a cross-process registry that the single-process `MicroVm` ownership model cannot provide. Any still-pending subcommand must **fail loud** (non-zero `Error::Unsupported`), never print success.
- **The ≈254-concurrent-VM ceiling per `/16`.** §10.2. Beyond that, widen the address scheme to a second octet.
- **Keep the execution primitive general (ongoing design constraint, §1.1).** All three domains — systems testing, agent-sandboxing, serverless — are co-equal consumers, so no domain-specific assumption may leak into `vmm`/`agent`/`orchestrator`/`metrics`; the `MicroVm` handle is a thin owner over the primitive (renamed from `TestVm` in v14, §10.2). Reviewing each addition for primitive-generality is the standing guard, and §16 triages every candidate capability against it (a feature only one domain needs, that would push policy into the core, is out-of-scope by design).
- **Cross-version snapshot fragility** (pin one exact CH+virtiofsd build for any snapshot pool) and **x86_64 as the primary arch** (aarch64 is a supported second target, not a free rebuild — kernel configs and snapshot artifacts differ).

*Maintenance note:* the standalone `Cargo.toml` artifact and the handoff notes want syncing — the `[patch.crates-io]` block (§10.5), the collapsed feature set (§10.5), and the `restore(&VmConfig)` / `resume_vm:false` / TPROXY / three-cap-runner decisions should propagate to both.

---

## 16. Rebrand roadmap: candidate capabilities the three domains want

The rebrand (§1) reframes vmcell from a test platform into a general micro-VM runner, which surfaces a backlog of capabilities each of the three domains — systems testing, agentic harnesses, serverless — would use. This section is the **triaged catalog**. Every candidate was vetted against the hard invariants (the §3.3 snapshot-eligibility law, zero-netlink-in-PID-1 §4.3, the fail-loud capability contract §7, permissive-license-only §10.4, lean privileged-window binaries §10.5, and above all **keep-the-primitive-general** §1.1/§15). The governing rule is the one §1.3 already draws for the eval layer: **a capability the *core* can offer workload-agnostically goes in the library; a capability that is one domain's *policy* ships as a thin consumer crate on top.** These are **candidates, not commitments** — the §13 numbers and the §15 open items gate the order; each entry names the v13 hook it builds on and the invariant it must respect, because *how* it is added is what keeps the primitive general. **v15 pulled four §16.1 candidates forward into committed design** — the uniform lifecycle verbs (easy subset; §10.2), the BYO-OCI `oci2erofs` utility (§8.2), the kernel config-fragment matrix (§8.3), and the workspace-split + content-hash-bless-stamp build hygiene (§10.1/§12.8) — each landing only its honestly-easy core, with the not-easy parts (cross-process `list`/`rm` and `fork`, PREEMPT_RT, KCOV extraction, VMM-binary vendoring, the per-test kernel-matrix API) explicitly deferred or rejected and marked inline below. (Each entry's tag marks its primary consumer; **serverless** has few *dedicated* entries because its core loop — snapshot a warmed runtime once, restore-per-invocation via copy-on-write, discard — is delivered by the cross-cutting **single-snapshot CoW clone/`fork`**, the **`impd` warm-pool/daemon**, and **BYO-OCI-image** items, with the serverless-first lifecycle and metering pieces called out explicitly in §16.2 and §16.3 so the third domain is represented, not folded away.) Three tiers.

### 16.1 Adopt-now — cheap, high-value, extend an existing seam

- **Uniform VM-as-a-handle lifecycle verbs** (cross-cutting, V:high/E:med) — **ADOPTED IN v15 (easy subset; §10.2/§10.3), with `list`/`rm`/`fork` deferred.** Unify `create` / `pause` / `resume` / `snapshot` / `stats` / `destroy` identically across the library and CLI; the same verbs serve a test fixture, a serverless invocation, and an agent branch-exploration (*the single strongest reinforcement of keep-primitive-general*). *What v15 committed:* the live-handle verbs, taking a `--kernel`/`--rootfs` (erofs) argument, and the **semver-visible promotion of `pause`/`resume`/`snapshot` from the `VmInstance` trait to first-class `MicroVm` methods** (the one real library change — they were reachable only via `instance_mut()`). `create`==`start`, `destroy`==`shutdown`, `stats`==`usage` were already on `MicroVm`. *What v15 deferred, and why (the honest push-back):* `list`/`rm` and a standalone `exec` need a **cross-invocation VM registry**, i.e. VMs that outlive their creating process — which collides head-on with the load-bearing ordered-`Drop`-owns-cleanup invariant (`MicroVm::Drop` tears the VM down when the process exits). That is the `impd` daemon (§16.2), not a `MicroVm` method; within one process the caller already holds its handles. `fork` is deferred to the §16.2 CoW-clone item: even a correctness-only full-snapshot-copy fork depends on generalizing the per-backend single-use `config.json`/sidecar rewrite, and the efficient form is E:high. *Builds on:* `VmInstance` (pause/resume/snapshot/kill) + `MicroVm`. *Guardrail:* `fork` == snapshot+restore, so a forkable VM obeys the §3.3 law (reject `Unprivileged`/virtio-fs-rootfs/data-`Share`); `ls`/`rm` will act on a real registry — never the `Ok(())`-stub fake-success §7.1 bans; `Error::Unsupported` (not panic) on a backend lacking `fork`.
- **Egress + model cassettes — deterministic record/replay** (cross-cutting, V:high/E:med) — elevate the proxy's `record_to(cassette)` + `(Matcher, Responder)` doubles into a first-class deterministic-replay mode: record all guest egress on a golden run, replay byte-stable later for gradeable, hermetic, no-live-API evals (the origin consumer's core need) and CI regression of agent trajectories. *Builds on:* `EgressProxy` `doubles.rs` + `RequestLog` + the MITM CA already in the guest trust store. *Guardrail:* normalize nondeterminism (timestamps, nonces, streaming order) so matching isn't a coincidental/flaky pass — assert the *specific* replayed signal, never loose `contains`; HTTPS doubles still ignore `Method::CONNECT`; cassette mechanism is core, scoring stays out.
- **Declarative per-sandbox egress policy + full attempted-connection audit** (cross-cutting, V:high/E:med) — default-deny allowlist-by-domain as *data*, enforced at the MITM proxy, with every attempted connection audited (including the guest's intended destination, and explicit logging of metadata/`169.254.169.254` and RFC1918 lateral-movement attempts). The central security control for the agentic domain, defense-in-depth for the rest. *Builds on:* the privileged nft-TPROXY and unprivileged smoltcp-L4 front-ends + the `RequestLog`. *Guardrail:* match on DNS **label boundaries** (the rubric bans `host.ends_with(blocked)`); policy-as-data is core, a specific org policy is the caller's; no test-only hardcoded blocks in the production handler; the unprivileged path must reach destination-fidelity parity or *report reduced fidelity*, never silently pass.
- **Bring-your-own OCI image as an erofs rootfs source** (cross-cutting, V:high/E:med) — **ADOPTED IN v15 as the build-time `oci2erofs` utility (§8.2/§11), reframed per the maintainer's clarification.** A caller names any digest-pinned OCI image; `vmcell oci2erofs IMAGE@DIGEST -o rootfs.erofs` pulls by digest, verifies every blob, applies whiteouts, injects agent+CA+guest-tools, and packs a content-addressed erofs — and the VM-management verbs consume the resulting **erofs via their `--rootfs` argument**. The on-ramp every competitor offers, without breaking the single-shared-erofs + snapshot story (OCI is **never** a runtime `RootfsSource`). *Builds on:* `artifact/rootfs/oci.rs` + the tar2erofs packer + the shared inject tail — the utility runs the **full** rootfs stage (the inject tail hard-requires the agent), parameterized by the base image, not a separate minimal path. *Guardrail:* digest-pinned only (provenance hard stop, §11.2), cache keyed on **inputs** (image digest + injected content + stage version — correct per §11.2; "keyed on the output" in the v14 draft was imprecise), validity content-addressed; arbitrary images may omit the `libc6` the glibc agent needs → **fail loud before packing** (single-pass `/lib64/libc.so.6` scan), with a static-musl agent as an **explicit `--agent-musl` opt-in, not an automatic fallback** (silent toolchain-swap would violate §7.1); keep rejecting OCI-as-runtime-overlay (snapshot/density); the still-missing injectable OCI record/replay seam (§15) is not required for the utility.
- **Post-restore secrets injection** (agentic, V:high/E:med) — inject per-task secrets into a freshly restored/forked clone over vsock at resume time (tmpfs/env, `0600`), with a hard contract that *the snapshot is taken before injection* so secrets never enter the on-disk memory file or the shared erofs. *Builds on:* `put_file` + `ExecRequest.env` + the restore-ordering already tracked. *Guardrail:* enforce snapshot-before-inject in code (a snapshot *after* injection leaks the secret into the ~guest-RAM memory file); secrets never hit the serial log; a generic secret-sink is core, a KMS/Vault backend is a consumer; fail loud on a missing/unreachable secret.
- **Deterministic clock control over vsock** (cross-cutting, V:high/E:med) — promote the mandatory post-restore clock resync (§9.2) into a first-class set / freeze / forward-jump API for reproducible expiry/timeout/cron/TTL tests and forks resumed at a controlled instant. *Builds on:* the host-driven resync on first post-restore `agent()` + the injected `Clock`. *Guardrail:* advertise only the deliverable (wall-clock set + forward jump are honest; freezing/scaling `CLOCK_MONOTONIC` is *not* deliverable at the VMM layer — fence it as a documented limitation, no dead capability); bound backward jumps; add the protocol message only when the agent implements it.
- **Per-test kernel config-fragment matrix** (systems-testing, V:high/E:med) — **ADOPTED IN v15 (build seam; §8.3), with PREEMPT_RT and KCOV-extraction excluded and the per-test API deferred.** Extend the `kernels` registry so a test requests a kernel built from a base SHA + an overlay of KConfig fragments (KASAN, KCOV-config, lockdep, `slub_debug`, a driver), content-addressed per (base SHA + **sorted** fragment set + stage version); the matrix harness sweeps one test body across labels. The literal extension of v13's "kernel is a tracked dimension." *Builds on:* the multi-kernel registry + version-aware `artifact/kernel.rs`. *Guardrail:* hash the fragment set in **sorted** order, fold a stage-version + base SHA, validity content-addressed (§11.2); **fail loud on a non-zero `olddefconfig`** (plus a documented incompatible-pairs note for the semantic conflicts `olddefconfig` would silently resolve); lives entirely in the pipeline, not the vmm/agent core; build-time blow-up bounded by the cache (cold KASAN ~45–90 min → CI batches by label, full matrix nightly, the bound logged not silent). *Excluded as genuinely-not-easy:* **PREEMPT_RT** needs an rt-patched source (a separate registry source, not a fragment), and **KCOV extraction** needs the guest-side §16.2 helper (the fragment only enables the kernel capability).
- **Structured serial fault capture** (systems-testing, V:high/E:**low**) — generalize the boot-panic fast-fail into a serial classifier consulted throughout a VM's life, turning kernel oops/BUG/WARN/KASAN/lockdep/RCU-stall output into a typed, matchable `Error` carrying the decoded title + trace, instead of a generic exec timeout. The cheapest high-value item here. *Builds on:* the `SerialLog` seam + the per-VM `serial.log` already tailed. *Guardrail:* strengthens fail-loud (timeout-masks-error is exactly what the prime directive forbids); typed variant, never `Error::Other(String)`; the parser runs on guest-controlled bytes → bounded reads, no `unwrap`/indexing; core emits a generic "serial fault", syzkaller-grade decode is a layer.
- **Network fault injection** (cross-cutting, V:high/E:med) — a `NetFaults` config on the per-VM netns: latency/jitter/loss/dup/reorder/rate via a `netem` qdisc through **rtnetlink** (not a `tc` shell-out) + nft partition rules, plus L7 egress chaos in the proxy (synthetic 5xx/429/timeouts, throttling, truncated bodies). For Raft/gossip/backoff tests and deterministic hostile upstreams. *Builds on:* `net/tap.rs` + the `NftApplier` seam + `proxy/doubles.rs`. *Guardrail:* faults live on the snapshot-eligible tap path (compose with restore); L2 netem needs `CAP_NET_ADMIN`, so the unprivileged path returns `Error::Unsupported` (never a silent no-op); prefer in-Rust `RTM_NEWQDISC` over the GPL `tc` binary; teardown removes qdiscs/rules with the netns.
- **Arbitrary extra virtio-blk devices + disk I/O fault injection** (systems-testing, V:high/E:med) — attach N extra virtio-blk devices (raw/sparse, optional preformatted FS) and inject storage faults via guest-side device-mapper targets (`dm-error`/`dm-flakey`/`dm-delay`) driven by guest-tools. The xfstests/blktests on-ramp; extra disks alone are a small high-value primitive that even Firecracker (block-only) supports. *Builds on:* `RootfsSource::Block`'s virtio-blk path + `extra_disks: Vec<DiskConfig>` + guest-tools ioctls. *Guardrail:* plain virtio-blk is **not** vhost-user, so extra disks compose with snapshot — but never a vhost-user-blk daemon (it would sever it); `dm-*` needs `CONFIG_DM_*` (tie to the config matrix) → declare and `Error::Unsupported` if absent; `config::build()` validates disk specs.
- **Custom init + append-only boot-args** (systems-testing, V:med/E:**low**) — append-only arbitrary kernel cmdline params (`slub_debug`, `nokaslr`, `mitigations=off`, `panic_on_warn`) and an optional `init=` override, unlocking a whole class of boot-time/hardening tests. *Builds on:* the per-backend cmdline construction; `VmConfig` gains `extra_cmdline` + optional init. *Guardrail:* `ip=`/`root=`/`console=`/`init=vmcell-guest-agent` are load-bearing for the vsock handshake and zero-netlink contract, so the path is **append-only** and `build()` rejects args colliding with those keys (negative test per case); an `init=` override means no agent/no vsock results → fail loud, route output via serial.
- **Build & distribution hygiene: workspace split + content-hash bless stamp + reproducible bundle** (general, V:high/E:med — **answers `todo.md` #2; workspace + stamp ADOPTED IN v15 (§10.1/§12.8), bundle scoped down**) — split the single package into a **cargo workspace** (lib crate + a shared `vmcell-protocol` crate + separate lean-binary crates: agent, test-runner, guest-tools) so each has its own dependency graph and is stable across library churn; a `.blessed` stamp keyed on the **runner** binary's content hash so `just bless` re-runs `setcap` only when the runner actually changed (**never keyed on test-binary content** — that would re-introduce per-iteration churn and buys no security, §12.8). The **reproducible bundle is scoped to a digest-pinned fetch-and-verify *manifest*** for *our* artifacts (kernel + erofs + CA + `pins.json`), **not** a vendored copy of the VMM binaries: **vendoring is rejected** — QEMU is GPL (redistribution is a legal question the "external binary, not linked" carve-out does not cover), CH/FC are 100+ MB per release with real maintenance cost, and fetch-and-verify-by-digest already delivers the reproducibility; an offline-everything image is a consumer `Dockerfile` (productization layer, §1.3). *Builds on:* the four-target structure (§10.5) + the lean-tree CI assertions + `pins.json`. *Guardrail:* makes the lean-privileged-window boundary **structural** rather than feature-gated (stronger than the feature collapse); manifest verification fails on any digest mismatch (provenance hard stop); see §12.8 for why the workspace + the **stable-path install** are the durable fix for the re-bless pain (the workspace alone does not fix the `RUSTFLAGS` re-fingerprint).

### 16.2 Design-now-build-later — forward work worth specifying in v14

- **Single-snapshot copy-on-write clone + `fork()`/`branch()` with lineage handles** (cross-cutting, V:high/E:high) — the headline primitive **both** the agentic and serverless domains share: reflink-CoW the snapshot dir before each restore, mint N divergent clones in tens of ms with per-clone identity rotation and parent→child lineage, collapsing the N×guest-RAM disk cost to touched-pages. Agentic tree-of-thought/speculative-branching and dense fan-out are the same operation. *Builds on:* snapshot/restore + `reflink-copy` (FICLONE) + the per-restore resync; a **new injectable `OverlayStore`/`SnapshotStore` seam** alongside `Netlink`/`CgroupFs`/`Clock`. *Guardrail:* the §3.3 law binds *per clone* (`fork` rejects `Unprivileged`/virtio-fs-rootfs/data-`Share`); the CH `config.json` / FC UDS-sidecar rewrite is single-use today, so reflink-then-rewrite is genuinely new; each clone needs distinct vsock/serial/cgroup paths (path-injectivity, not `format!` stand-ins); reflink is XFS/Btrfs-only → fail loud or full-copy-with-visible-warning on ext4; the lineage-DAG navigation policy stays in a consumer. (The §15 "single-snapshot CoW for many clones" open item, made first-class.)
- **`impd` daemon + versioned control-plane API + warm-pool manager** (cross-cutting, V:high/E:high) — a persistent **unprivileged** daemon owning the host-global CID/VMID allocators and orphan-sweeper, exposing the lifecycle as a stable versioned API (HTTP/JSON over UDS, optional gRPC), plus a warm-pool manager keyed by (snapshot id, `VmConfig` shape) that keeps N CoW-ready paused instances warm and hands one out in tens of ms. The productization seam for the agentic/serverless domains, and a strong keep-general de-risker (one transport-neutral lifecycle contract). *Builds on:* `MicroVm` ordered `Drop` + the process-global allocators + the shared HTTP-over-Unix helper + the CoW-clone feature. *Guardrail:* **direct tension with keep-primitive-general** — resolve by putting a workload-agnostic `WarmPool` struct + allocator/sweeper ownership in core, the server + scheduling/billing policy in a *separate* crate; the daemon must **not** become the privileged window (caps stay behind the setup-broker below); typed API errors (not 500+string); widen `VMID`→octet beyond a single `/16` at a validated boundary (`Err`, not `assert!`).
- **Privileged-window hardening: VMM seccomp + jailer-equivalent + setup-broker** (cross-cutting, V:high/E:high — also advances `todo.md` #2) — enable each VMM's own seccomp level (CH/FC `--seccomp`), run each VMM in a dedicated uid + minimal namespaces + chroot (a jailer-equivalent), and introduce a small long-lived **setup-broker** (blessed once / socket-activated) that performs discrete privileged ops over a UDS — create netns/tap/`/30`, apply nft TPROXY, delegate cgroup, set virtiofsd uid — driven by the unprivileged daemon/test process. The broker is the real impl behind the `Netlink`/`NftApplier`/`CgroupFs` seams, and the **recommended privilege boundary for the daemon/API mode** (§12.8). *Builds on:* the VMM spawn path + existing netns/cgroup/virtiofsd-sandbox machinery + the capability runner's privileged window. *Guardrail:* the jailer and broker *are* privileged-window binaries — dependency-thin, off the host async stack, validating every request (only `vmcell-`-prefixed netns names, bounded vmid, the centralized `/30` math); an over-tight seccomp profile breaks KVM ioctls → test per backend/arch; fail loud on any op that can't be applied.
- **Generic vsock↔TCP port-forward bridge** (cross-cutting, V:high/E:med) — a workload-agnostic vsock↔TCP forward so guest code talking to `localhost:PORT` is tunneled to a host endpoint over the control plane; the LLM-shaped transcript schema (the §1.3 in-guest model-proxy bridge) sits in a thin consumer on top. *Builds on:* the vsock control plane + `agent::protocol` (`#[non_exhaustive]`: a generic `Forward`/`Stream` frame is non-breaking) + the proxy record/replay pattern. *Guardrail:* core gets only the workload-agnostic forward, the LLM transcript schema is the eval crate's; the guest forwarder stays sync/tiny (lean-agent); add the frame only when implemented (the `Hello`/`Ping` ban); on the snapshot tier use the non-vhost-user vsock; SSE/streaming chunk-boundary fidelity is the correctness trap.
- **Observability + resource controls** (cross-cutting, V:high/E:med) — wrap each exec/fork in a tracing span (CPU-usec, mem-peak, io.stat, net rx/tx, egress counts) exported over **OTLP** behind a host-only feature; per-step quotas (`memory.max`/`memory.high`); virtio-balloon + `memory.high` pressure injection; and a versioned `#[non_exhaustive]` subscribable **event stream** (lifecycle/OOM/egress/sweeper) so tests assert the *exact* signal (a cgroup OOM event) instead of the forbidden loose `137||1||-1`. *Builds on:* the `metrics.rs` cgroup readers behind `CgroupFs` + the host-side `tracing` + OOM-event detection + lifecycle transitions. *Guardrail:* `opentelemetry`/`-otlp` stay an optional **host-only** feature, never linked into the agent/runner (lean-tree assertion); io.stat/net counters must *actually be read* (the real always-zero defect); enforcement fails loud (`CapabilityUnavailable`), reads degrade with `limits_enforced=false`; balloon target re-driven on restore like clock/entropy; a slow subscriber must not backpressure VM progress (bounded/lossy channel + drop counter).
- **Persistent interactive sessions: PTY + streaming stdin + multiplexed exec** (agentic, V:high/E:med) — extend one-shot `Exec` to a persistent session with a PTY, streaming stdin, window resize, and multiple concurrent exec streams over one vsock connection — a warm REPL/Jupyter/interactive-shell loop across many tool calls. *Builds on:* `agent::protocol` (`#[non_exhaustive]`: add `Stdin`/`PtyOpen`/`PtyResize`/stream IDs) + the PID-1 fork-not-exec model. *Guardrail:* keep the agent sync/thin (lean-agent); the PID-1 reaper-vs-waiter race *sharpens* with concurrent children — the single `WNOHANG` reaper must not steal a stream's exit status (the false-127 bug); bound stdin/stdout backpressure; add variants only when implemented.
- **In-VM filesystem checkpoint/rollback** (agentic, V:med/E:med) — a per-step disk checkpoint that captures/restores the tmpfs overlay upper of a *single live* VM, undoing a failed tool call's filesystem effects without a full memory snapshot, process tree intact. *Builds on:* the tmpfs overlayfs upper over the shared erofs base + a guest-agent sync/freeze step. *Guardrail:* the upper lives in guest RAM (bounds checkpoint depth); a writable-block overlay would reintroduce a vhost-user/journal surface that breaks the §3.3 law — keep erofs+tmpfs the default; the freeze step stays sync (lean-agent).
- **kcov / gcov / sanitizer coverage extraction over vsock** (systems-testing, V:high/E:high) — a guest-tools helper drives the kcov ioctl protocol around an exec and streams coverage PCs back via a `PutFile`-symmetric message; turns the substrate into a viable syzkaller executor host. *Builds on:* the vsock plane + `#[non_exhaustive]` `agent::protocol` + the guest-tools multicall + `vmcell-out`; needs `CONFIG_KCOV=y` from the config matrix. *Guardrail:* the kcov ioctl logic lives in **guest-tools**, not the PID-1 agent (which only relays bytes, no deps pulled in); add the message only when implemented; fail loud if debugfs/kcov absent rather than returning empty coverage.
- **Multi-VM cluster topologies with a shared L2 segment** (cross-cutting, V:high/E:high) — a `Cluster` layer starting N `MicroVm`s on a shared bridged L2 segment (so they address each other), with distinct CID/VMID/IPs, per-link fault injection, and one-snapshot CoW restore of all N — the substrate for Jepsen/Antithesis-style consensus/replication/split-brain tests against real Linux networking. *Builds on:* the process-global allocators + `net/tap.rs` netns + the CoW-clone item. *Guardrail:* keep-primitive-general is sharpest here — the **core** gains only the enabling primitives (a shared-bridge option, allocator sharing, snapshot CoW); `Cluster` ships as a thin layer/example; bounded by the `/16` ceiling (widen via the daemon); ordered `Drop` reaps all N without leaking netns/bridge.
- **Kernel debugging & postmortem: gdbstub + crash-dump capture** (systems-testing, V:med/E:high) — expose the backend gdbstub on a host socket (CH `--gdb`, QEMU `-s/-S`) on the `VmInstance` handle, and on a guest panic capture a postmortem (VMM memory snapshot of the paused-on-panic guest, or guest kdump/pstore writing a vmcore to an extra block/`vmcell-out`). *Builds on:* the backends' gdb support + `gdb_socket()` on `VmInstance` + the snapshot machinery + the `panic=` cmdline. *Guardrail:* gdbstub/dump diverge per backend → `VmmCapabilities` fields + `Error::Unsupported { vmm, feature }`, never panic/stringly-`Vmm`; snapshot-on-panic needs a snapshot-eligible VM (else fall back to guest kdump-to-block, capability-aware); kdump needs `crashkernel=` (config matrix); re-verify CH `--gdb` per pin.
- **Hardware-profile matrix: CPUID feature masking + aarch64 second architecture** (cross-cutting, V:med/E:high) — a `CpuFeatures` config masking/exposing CPUID leaves (AVX-512/AVX2/SHA-NI/RDRAND) to sweep ISA-dispatch paths on one host, plus **aarch64** as a second arch (a (version × arch) kernel+snapshot registry, an arm64 fragment, CH/FC on arm64). Broadens reach to Apple-silicon dev hosts and Graviton/Ampere fleets. *Builds on:* the FC T2/`noxsave` CPU-template machinery (§3.2) + the registry + per-arch `VmmCapabilities`. *Guardrail:* masking granularity and arch support diverge per backend → report and `Error::Unsupported`; an FC snapshot is pinned to a CPU template *and now an arch* — a wrong-arch/feature-mask restore must error at a boundary, not crash the VMM; pin one CH+virtiofsd build per snapshot pool *per arch*; re-run snapshot-eligibility + seccomp profiles per arch.

- **Scale-to-zero invocation lifecycle + cold-start budget** (serverless, V:med/E:med) — a per-invocation lifecycle layered on the warm pool: route an invocation to a warm CoW clone or, on a cold miss, restore one within a declared **cold-start budget**, run to completion, then **scale to zero** (return the clone to the pool or discard), with concurrency gating so a burst can't exhaust host RAM. The serverless analog of the agentic `fork`-per-tool-call loop, and the clearest place the third domain shapes the core. *Builds on:* the `impd` warm-pool + the single-snapshot CoW clone + the per-test critical-path budget instrumentation (§13.4) repurposed as a per-invocation latency SLO. *Guardrail:* the routing/scheduling/quota *policy* is the serverless frontend's (keep-primitive-general) — the core exposes only a warm-pool checkout/return primitive and the cold-start latency as a tracked number (§13); pool exhaustion and budget-exceeded surface as typed errors, never a silent slow path; every pooled clone obeys the §3.3 snapshot-eligibility law.

### 16.3 Out-of-scope by design — consumer layers, shipped as examples on top

These are valuable and worth shipping — but as **separate crates/binaries that depend on vmcell**, never as code in `vmm`/`agent`/`orchestrator`/`metrics`. Listing them explicitly is itself the keep-general guard (§1.3): naming the boundary prevents the policy creep that the standing constraint forbids.

- **MCP server frontend** (agentic) — a consumer binary exposing `create`/`exec`/`snapshot`/`fork`/`put_file` as Model Context Protocol tools so any MCP client (Claude Code, Cursor, Codex) drives disposable sandboxes. Builds on the daemon/API; MCP is agent-specific policy → a separate crate (the official `rmcp` SDK is MIT). The highest-value *example* to ship.
- **KUnit / kselftest / LTP runner with KTAP parsing** (systems-testing) — a host-side consumer that boots a provisioned kernel, execs the entrypoint, and parses KTAP/TAP into typed per-case results. Builds on the config matrix + vsock exec; a consumer layer (LTP/kselftest are GPL but run as *guest payload*, not linked — allowed).
- **Deterministic record/replay: rr-as-payload** (systems-testing) — `rr` run as a guest payload with traces to `vmcell-out`, combined with the deterministic-inputs trio (cassettes + clock control + entropy-reseed pinning). Needs **zero** core change (it is just an exec), so it is a payload/example — the only honest core touch is a perf-counter capability probe (`rr` needs HW perf counters often unavailable to nested guests → `Error::Unsupported`, not advertised determinism). Full-VM deterministic replay (QEMU `-icount`, Antithesis) is a different architecture CH/FC don't support — explicitly out, not a silent gap.
- **Per-tool-call run bundle** (cross-cutting) — aggregate a single call's stdout/stderr/exit + the `vmcell-out` file diff + the egress log + resource spans into one content-addressed bundle for audit/eval. The underlying outputs already exist (and the adopt-now/forward features expose them); the scoring/diff *format* is the eval layer's, so the bundle convenience ships on top.

- **Per-invocation billing / usage metering** (serverless) — turn the §16.2 observability spans (CPU-usec, mem-peak, wall-time, egress bytes per invocation/fork) into billed usage records. The *measurements* are core (the metrics + event-stream features expose them); the rating, aggregation, and invoicing are a serverless-operator consumer layer — exactly the §1.3 boundary the eval layer's scoring sits behind.

### 16.4 The generality test, restated

The recurring split above is one rule: **if a capability is a workload-agnostic property of "an isolated VM" (a lifecycle verb, a clock, an extra disk, a fault knob, an egress audit), it is core; if it encodes what a *test*, an *agent*, or a *function* should *do* with that VM (a scoring rubric, an MCP tool schema, a KTAP mapping, an LLM transcript format), it is a consumer.** Every adopt-now and forward item is gated on respecting that line — and on the §3.3 law, the zero-netlink contract, and the fail-loud contract — which is what lets vmcell serve all three domains from one primitive (§15) instead of fracturing into three forks.

---

## Part IV — How we got here

The body describes the system as it stands. This part records the path: the implementation passes that produced it, the substitution experiments that fixed the dependency set, the prior art it draws on, and the order it was built in. Nothing here is required to *use* the system — it is the evidence and the reasoning behind the non-obvious choices in Parts I–III, kept out of the main flow so the main flow stays present-tense.

---

## Appendix A. Implementation-pass history ledger

The design accreted across six **implementation** passes (v8 → v13), followed by two **design-document-only** revisions (v14, v15) that added specification without a new build/validation pass. The first two passes established the architecture and the first working build on Cloud Hypervisor; passes three through six left structured feedback and are the substance of this ledger. **The architecture never changed.** Every finding below is a localized fix, a vindicated diagnosis, or a measurement — not a redesign. The settled outcome of each is already stated present-tense in the body; this appendix records what was believed before, what the pass found, and where it landed, because the *reversals* are the part a reader needs to trust the current state. **v14 (rebrand + terminology) and v15 (easy-extensions + capability-runner-resilience) are design revisions layered on the pass-6 code: every v15 addition extends an existing seam and is specified to be correct-by-construction, but the code has not been re-validated on a KVM host for v15 — so the v15 items (§12.8 bless durability, the workspace split, the lifecycle verbs, `oci2erofs`, the kernel-fragment matrix) are SPECIFIED, not yet validated-end-to-end. They carry implementation-and-validation as their definition-of-done, not a green design doc.**

### A.1 The passes at a glance

| Pass | Version | Headline |
|---|---|---|
| 3 | v10 | The big build: Firecracker backend, capability runner, both rootfs sources, unprivileged cgroup delegation, full integration suite. Surfaced four invalidations (two later vindicated the design's own diagnosis). |
| 4 | v11 | Unblocked Firecracker snapshot via MMIO; removed the netlink path from PID 1; produced the first measured numbers (cold boot). Surfaced the symmetric QEMU-vsock and Firecracker-FPU findings. |
| 5 | v12 | Closing pass: filled the warm-restore benchmark gap (the load-bearing one), fixed the FPU panic at the CPU layer keeping `trixie`, moved egress to TPROXY, restored per-request exec timeouts. Two real gaps left open. |
| 6 | v13 | Code-review (#34) + benchmark + validation pass. Ran the full §13 suite on the committed pin — settling §14/§15 open questions, several of which **inverted** (OCI base smaller than mmdebstrap; musl larger than glibc; kernel version not a hot-path lever). Enforced the snapshot-eligibility law **in code at three boundaries** (review C1); drove snapshot/restore to work end-to-end (CH `config.json` rewrite, FC vsock-UDS sidecar, guest listener re-bind); added the in-rootfs guest-tools helper; consolidated the artifact dir and content-addressed the cache keys; bumped to the 6.12.94 pin (fixing the gcc-15 build break) and added a multi-kernel registry; plumbed lazy restore + the KSM lever. Maintainer directions absorbed: **unprivileged/privileged** terminology, **fail-loud** capability contract, and the **four-build-target** feature collapse (one host feature + three lean). |

### A.2 What each pass did

**Pass 3 (v10) — the big build.** Built the Firecracker backend (manual `hyper`-over-Unix client, not an SDK; multi-call boot; external pre-compiled binary), the `vmcell-test-runner` capability runner, both rootfs sources (OCI pull + in-VM `mmdebstrap` with in-memory whiteout application), unprivileged cgroup-v2 delegation, and the cross-backend integration suite. It independently found `capabilities()` / `VmmCapabilities` *missing and necessary* and added them — confirming the capability-query contract was load-bearing, not speculative. It reconfirmed the settled mechanics (snapshot = pause→snapshot→resume; restore = `--restore`→`resume`, never boot; severed-vsock EOF → re-`accept`; postcard framing; `am-fs-erofs` over `mkfs.erofs`; `CONFIG_EROFS_FS=y` mandatory; dynamic-glibc agent) and produced a long refinements table (per-request exec timeout, 1-byte handshake reads, process-global allocators, the `(n % 254)+1` octet ceiling, the ≈16-socket smoltcp pool, host-driven clock resync). Its four invalidations are A.3 #1–#4.

**Pass 4 (v11) — MMIO unblock and first numbers.** Closed v10's two biggest open items, and notably *both closures confirmed the design's own diagnoses from pass 3 rather than overturning them* (A.3 #1, #2). It then surfaced two new findings that are the symmetric mirror of the Firecracker-snapshot case (A.3 #5, and the FPU panic in #3), and produced the first measured cold-boot distribution (N≈3, later grown). The snapshot findings began collapsing into one rule here — formalized as the §3.3 vhost-user law.

**Pass 5 (v12) — the closing pass.** Mostly resolved open items rather than discovering new ones. It filled the **warm-restore** benchmark gap — the load-bearing measurement, since the whole snapshot tier exists to make restore fast — and the result validated the central bet (restore ≈7× faster than cold boot on CH, ≈22× on Firecracker; Firecracker *wins* restore while losing cold boot, which is exactly the density/snapshot-tier role it was assigned). *(Those are v12-era absolute figures; v13 re-measured the suite on the committed pin — ≈3.7×/≈8×, FC ≈128 ms (§13.1) — and the relative invariants held; see Appendix A.3 #6.)* It fixed the FPU panic at the CPU layer keeping `trixie` (A.3 #3), moved egress from REDIRECT to nft TPROXY (A.3 #4), and restored the per-request exec timeout (10 s default) after a v11 hardcoded-600 s drift. It left two genuine gaps open: the `CgroupFs` seam (the one item that violates a load-bearing design invariant) and full per-test critical-path instrumentation (§15).

**Pass 6 (v13) — review, measure, validate.** Driven by code review #34 and the maintainer's `todo.md`. It did three things. (a) **Closed the review's findings**: enforced the snapshot-eligibility law in code at three boundaries (the C1 Critical — a data-share slipping past a rootfs-only guard), de-`expect`'d the guest-drivable smoltcp RX path, fixed the cache-key nondeterminism (sorted inputs, content-of-upstream, stage version, `guest_agent_src_hash`), removed the `/tmp/*` fallbacks, turned the theatrical restore/OOM/teardown assertions red-on-inverse, and corrected the privileged-runner blessing (`+ep`, three caps). (b) **Ran the §13 suite** on the committed pin and settled the open questions, several inverting their hypothesis (A.3 #6). (c) **Validated end-to-end on a KVM host**: with a freshly-rebuilt rootfs in a delegated `domain` scope, the unit/codec/property suite, the unprivileged suite, and the privileged suite all pass — but only after a *chain of latent bugs in the never-before-exercised privileged-tap and warm-restore paths* was fixed (A.3 #7). It also extracted the `CgroupFs` seam and instrumented the per-test budget, closing v12's two open gaps, and absorbed three maintainer directions (terminology, fail-loud, feature collapse) that are design-level, not just fixes.

### A.3 The load-bearing reversals

These are the findings worth carrying as history. Each is stated as *prior belief → finding → where it landed*. The first two are cases where the design's diagnosis was challenged by an implementer and later vindicated; the rest are genuine corrections the design absorbed.

**1. Firecracker snapshot: blocked under PCI, unblocked via MMIO.** *v9 belief:* Firecracker snapshot/UFFD is a first-class capability. *v10 finding:* the guest kernel was virtio-PCI-only, so Firecracker launched with `--enable-pci`, and Firecracker has no snapshot/restore while PCI is enabled — restore aborted (`MicroVMStoppedWithError`). The capability machinery degraded honestly: Firecracker reported `snapshot_restore: false`, the suite skipped it, the cross-backend restore comparison dropped to CH-only. *Design's proposed fix:* build the guest kernel with `CONFIG_VIRTIO_MMIO=y` and run Firecracker in native MMIO mode off the *same* `vmlinux` CH uses over PCI. *v11 outcome:* taken and validated — Firecracker boots clean over MMIO, `snapshot_restore` flips `false→true`, and the restore sequencing (pause/resume via `PATCH /vm`; restore as a fresh process + `POST /snapshot/load {resume_vm:false}` then explicit resume; drives/vsock not reconfigured around load) is now the body's §3/§4 path. The fix proposed in v10 was confirmed correct in v11. *Re-tested v16 audit (FC **v1.16.0**): overturned.* On the committed FC v1.16.0 pin, `--enable-pci` + a Full snapshot **create *and* restore both succeed** (no `MicroVMStoppedWithError`; restore resumes `Running`, PCI segment reconstructed) — the "PCI blocks snapshot/restore" block was real only in FC's ~1.10–1.12 experimental-PCI era and is now version-stale. Firecracker still defaults to MMIO here, but for **backend maturity and the shared `vmlinux`**, *not* because PCI cannot snapshot; the stated `MicroVMStoppedWithError`-under-PCI justification no longer holds.

**2. `ip=` and the netlink path the agent was designed not to have.** *v10 implementer action:* found `eth0` unconfigured, added manual `ip link/addr/route` to the PID-1 agent, attributing the failure to "no initramfs to parse `ip=`." *Design's counter-diagnosis:* that attribution is wrong — `ip=` is consumed by the kernel's IP-PNP late-initcall, not by an initramfs; the real cause was the `net-unprivileged` feature compiled out, so no virtio-net device was presented and there was nothing for `ip=` to configure. *v11 outcome:* with the device present and `CONFIG_IP_PNP=y`+`CONFIG_VIRTIO_NET=y` built in, `ip=` configures `eth0` agent-free, the manual bring-up was deleted, and the §12 `Netlink`-fake-records-zero-calls test passes for real. The zero-netlink-in-PID-1 invariant (§4.3) survived because the design refused to accept the wrong attribution as a license to keep netlink in PID 1. Agent-side bring-up survives only as a guarded last-resort fallback.

**3. The FPU/XSAVE restore panic, and the rejected `bookworm` downgrade.** *v11 finding:* Firecracker restore can panic in `restore_fpregs_from_fpstate` when the guest `glibc` dispatches to aggressive AVX/extended-FPU routines (the saved XSAVE area mismatches the restore target). *v11 implementer stopgap:* pin the FC-snapshot rootfs to `debian:bookworm-slim`. *Design's rejection of the stopgap, with reasoning:* it is **not a `trixie` bug** — any modern-`glibc` base triggers it (it is a Firecracker extended-state limitation), so a downgrade only *hides* the trigger; `forky`/`testing` do not escape it either (`forky` began as a copy of `trixie` with the same-or-newer `glibc`, and `testing` gets no timely security updates, making it a worse *base* for a CI harness); the durable fix lives in CPUID, not the OS version. A surgical, distro-agnostic fix exists: a Firecracker **CPU template** (T2/C3) masks the offending extended-state CPUID bits so the guest `glibc` never selects those paths. *v12 outcome:* applied a static **`T2` template** on `trixie-slim` (the `bookworm` stopgap dropped), plus **`noxsave`** on the guest cmdline as an independent fallback for hosts where T2/C3 don't fit the CPU model. `bookworm` is explicitly discouraged (oldstable, full security support ended June 2026, two-generations-old `glibc`). The `noxsave` cost is recorded in §3.2 and §9: it disables guest AVX/AVX2 as well as AVX-512, a test-fidelity cost that sends SIMD-correctness-sensitive tests to the CH tier. CH and QEMU place no such constraint. *Re-tested v16 audit (FC **v1.16.0**):* the T2-template + `noxsave` fix stands, with three refinements. (a) The impl applied `noxsave` **unconditionally — even alongside T2**, needlessly disabling the AVX2 the T2 template leaves usable; it is now **gated to `template.is_none()`** in code (design §138's fallback-only intent), so the always-on impl-notes deviation is superseded. (b) FC **rejects** the T2 template on modern Intel client hybrids (Lunar Lake) — `InstanceStart` returns HTTP 400 "current CPU model is not permitted to apply the CPU template" — so the T2 leg is **inoperative** on those hosts and `noxsave` is the only guard there. (c) The `restore_fpregs_from_fpstate` panic **did not reproduce** for reachable AVX2/YMM state on FC v1.16.0 with no guard; AVX-512/ZMM stays untestable on that CPU, so `noxsave` is retained as the no-template fallback.

**4. REDIRECT → TPROXY: the design's stated reason was wrong but its choice was right.** *Design's original stance:* use nft TPROXY; treat "iptables REDIRECT cannot preserve the original destination" as a correctness failure. *v10 finding:* the implementer used `iptables REDIRECT`, and REDIRECT in fact recovers the original IPv4 TCP destination via `getsockopt(SO_ORIGINAL_DST)` (an HTTP/HTTPS proxy can also read it from the `Host`/`CONNECT` target) — so the stated reason for rejecting REDIRECT was incorrect. *Interim resolution:* accept REDIRECT for the HTTP/HTTPS-over-TCP scope and restate the assertion as *the proxy observes the intended destination* (mechanism-agnostic), with TPROXY kept as the documented upgrade for its real edges (UDP/QUIC on udp/443, source preservation, no conntrack dependency across the netns boundary). *v12 outcome:* moved the interception to nft `TPROXY` (`tproxy to :<port> meta mark set 1 accept`, applied via `nft -f -`), landing on the design's original choice and closing the REDIRECT interim. The arc is worth keeping: the design's *justification* for TPROXY was refuted, but TPROXY was still the right destination, reached once UDP and source-preservation made the edges concrete.

**5. QEMU cannot snapshot over the unprivileged vsock control plane (the symmetric mirror).** *v11 finding:* QEMU's unprivileged vsock is an external `vhost-device-vsock` daemon — a stateless vhost-user backend with no state-migration support — so a VM driven over it is snapshot-ineligible by the same vhost-user law that blocks CH's virtio-fs data shares and both backends' vhost-user-net. This is the exact mirror of #1: Firecracker was blocked by a *transport mode* (PCI) and unblocked by switching it (MMIO); QEMU is blocked by a *device* (the external vsock daemon) in the unprivileged config the harness actually uses. *Outcome:* QEMU reports `snapshot_restore: false` in unprivileged+vsock and is skipped with reason; the validated snapshot backends are **CH and Firecracker**. *Recovery path (validated, v16 audit):* a privileged kernel-`vhost-vsock` QEMU config has no vhost-user device in the vsock path and **is** snapshot-eligible — QEMU 10.2 source sets no `migrate_add_blocker` on the in-kernel `vhost-vsock-pci` device (unlike the external `vhost-user-vsock` daemon), and a `migrate`-to-file → `-incoming` restore was **verified live** on the real `vmlinux`+erofs. Only the live agent-reconnect and the `snapshot()`/`restore()` backend wiring remain (both still `Unsupported`); this is now a validated capability, not merely a documented avenue (§3.3, §9, §15).

**6. The benchmark pass inverted three research-era hypotheses (v13) — the value of measuring was disproving wrong beliefs.** *Prior beliefs:* `mmdebstrap`-minbase yields a smaller rootfs than the slim OCI base; static-musl is smaller/better than glibc-dynamic; and the guest kernel version is a hot-path lever (an early cross-session comparison suggested 6.6.9 restored ~2× faster than 6.12.94). *Findings:* the OCI slim base is **~34% *smaller* apples-to-apples** (~52% vs bookworm-minbase; official `dpkg path-exclude` strips locale/doc/man — §13.6); static-musl is **~6.2% *larger*** (it static-links libc rather than borrowing the rootfs `libc.so.6` — §13.3); and an **interleaved same-session** kernel sweep showed warm restore within **~2%**, so the "2×" was cross-session host-load noise (§8.3). *Where it landed:* OCI stays the default source and earns the builder-VM its keep on *provenance*, not size; glibc-dynamic stays the default agent; the 6.12.94 distro-aligned pin carries no measurable penalty. The lesson — **never compare absolute latencies across sessions on a shared box; only interleaved same-session deltas are trustworthy** — is now §13.2 discipline. (Provenance also earned its keep three times: an LLM-supplied kernel SHA was simply *wrong* and the tarball verification rejected it before it reached an artifact.)

**7. The privileged-tap and warm-restore paths had never run end-to-end, and fixing them surfaced a chain of latent bugs (v13).** *Prior state:* both the privileged `panic_residue`/`snapshot_restore` tests and warm restore were "implemented" but every attempt died early — at netns-permission for the tap path, at vsock reconnect for restore — masking everything downstream (one such "30-minute hung test" was actually a *leaked VM*, not a live test). *Findings, once unblocked:* the runner needed a **third capability** (`CAP_DAC_OVERRIDE`, for `/var/run/netns`); a nested-tokio-runtime panic and a tap-held-open-fd (`TUNSETPERSIST` + drop) blocked the tap path; and warm restore needed **three independent host-side fixes** — CH `config.json` path rewrite, FC vsock-UDS sidecar, and a guest vsock-listener **re-bind** after the device is re-created (the single-threaded-listener and double-connect bugs were necessary-but-not-sufficient). *Where it landed:* §3.2, §6.4, §9.2 — all now validated passing. The meta-lesson reinforces the rubric: **a path with no test that can actually fail is a path that has never run** — the reap-on-spawn-failure and orphan-sweeper gaps (rubric B1) were found the same way.

**Synthesis.** Every snapshot finding across the passes collapses into the single rule stated in §3.3: a VM is snapshot-eligible only if no vhost-user device is attached, and (for Firecracker) only under MMIO *by default* (v16 audit: FC v1.16 relaxes the MMIO-only limit — A.3 #1 — and QEMU's privileged in-kernel-`vhost-vsock` config is also eligible — A.3 #5). Pass 3 surfaced the Firecracker-PCI corner, pass 4 surfaced the QEMU-vsock and the MMIO fix, and the rule that explains all of them — any external vhost-user backend is a separate stateless process the VMM cannot migrate — is the body's snapshot-eligibility law. The per-config eligibility table lives in §3.3; it is not repeated here.

### A.4 Stale notes deliberately dropped

Earlier passes left notes that later work superseded; they are recorded here as *not* regressions to honor, so a future reader does not resurrect them.

- **The host `/bin/sh`→`bash` symlink check is vestigial.** It dates to the v8 host-`mmdebstrap` path. Since `mmdebstrap` now runs *inside* the builder VM, the `dash` quirk moved into the builder rootfs (set `SHELL=/bin/bash` or ensure the symlink in that image); the host-side check guards a step the host no longer performs.
- **"Exp 4 skipped," "`mmdebstrap` on the host," "`mkfs.erofs` used."** These predate the OCI + in-VM-`mmdebstrap` + `am-fs-erofs` work (Appendix B, Exp 3 and 4). They are chronologically superseded, not current constraints.
- **`loom` concurrency tests remain deferred.** Passes skipped `loom` (CID/VMID allocators, proxy state) to stabilize the suite first — consistent with the opt-in stance in §12. Still a standing gap; the commented `loom` line in the standalone `Cargo.toml` is where to land it.

*Maintenance carried across all passes:* the standalone `Cargo.toml` artifact and the handoff notes want syncing with the embedded copy — the `[patch.crates-io]` block (§10.5) and the `restore(&VmConfig)` / `resume_vm:false` / TPROXY decisions must propagate to both.

---

## Appendix B. Substitution experiments

The dependency analysis (§10.4) deliberately kept several external tools — `virtiofsd`, `mkfs.erofs`, `mmdebstrap`, `passt`, the `nft` binary — and a later pass argued each could be absorbed into the orchestrator as a crate. Rather than adopt wholesale, each ran as an independent experiment against the green baseline, **one at a time**, behind its own Cargo feature, with the baseline mechanism retained as the fallback. The method was uniform: branch from green; gate the new path behind a feature; keep the affected requirement's integration tests as the regression oracle; graduate into the default only on the success criterion, otherwise revert. This appendix records the outcomes; the graduated results are already the design in Parts I–III.

| # | Substitution | Status | Outcome |
|---|---|---|---|
| 1 | virtiofsd → `fuse-backend-rs` | **Underway** | Scaffolded behind `experiment-fuse`; virtiofsd remains the fallback. Not concluded — blocked on read-only enforcement. |
| 2 | `nft` binary → pure-Rust nftables | **Rejected** | No permissive crate covers TPROXY (`rustables` GPLv3; `jip-nftables` read-only); `nft` binary retained. |
| 3 | `mkfs.erofs` → `am-fs-erofs` | **Graduated** | In-memory tar→erofs build, runs unprivileged. Default; `mkfs.erofs` is the fallback. |
| 4 | rootfs source: OCI pull (default) + `mmdebstrap`-in-VM | **Graduated** | OCI pull is the default host-native source; `mmdebstrap` relocated into a builder micro-VM to keep the full apt chain. Both supported. |
| 5 | `passt` → in-process `smoltcp` NAT | **Graduated** | in-process smoltcp NAT replaces passt — no external dep, better regardless. The recorded "passt CH-incompatible (seccomp)" reason was corrected in v16 (host AppArmor, not seccomp; not CH-specific; avoidable — Exp 5 / audit E5). Default for unprivileged. |

**Experiment 1 — in-process virtio-fs (`fuse-backend-rs`). Underway.** *Replaces:* the per-share `virtiofsd` daemon (§5.2), behind `experiment-fuse`, daemon as fallback. *Benefit:* `fuse-backend-rs` (Apache-2.0 AND BSD-3, cloud-hypervisor-org, underpins Kata/Nydus) embeds the vhost-user-fs server + passthrough driver in the orchestrator, removing N daemon processes and the per-VM memory/PID pressure that bounds density. *Open risk:* the orchestrator becomes the vhost-user-fs backend (its own virtqueues, thread-per-share, vhost-user protocol), and it does **not** by itself fix the snapshot↔virtio-fs fork (§3.3) — an external CH still sees a vhost-user device, so the restriction persists until CH adopts `fuse-backend-rs` internally (CH #7250). *Blocking gap:* read-only mode is **not natively enforced** by `fuse-backend-rs` yet (an upstream-library constraint), so the path cannot guarantee the `ReadOnly` share semantics that `virtiofsd --readonly` gives — silent write-through on a share declared read-only would violate the `fs` contract. *Graduate criterion:* at target density, a measurable memory/PID reduction with every share test green, no snapshot regression, and RO enforced (in the library passthrough if upstream does not). The highest-value remaining experiment.

**Experiment 2 — pure-Rust nftables. Rejected.** *Goal:* replace the `nft -f -` invocation for the privileged TPROXY ruleset with a permissive crate. *Finding:* `jip-nftables` provides only read capabilities; `rustables` provides writes but relicensed to GPL-3.0-or-later at 0.8 (disqualified by the copyleft prohibition, and `cargo-deny` rejects it); hand-assembling netlink payloads via `netlink-packet-netfilter` for a tiny fixed ruleset was judged unjustified. *Decision:* keep applying the small, fixed, security-critical ruleset via the external `nft` binary — correctness over purity. Reopen only if a vetted permissive, TPROXY-capable crate appears.

**Experiment 3 — pure-Rust erofs build (`am-fs-erofs`). Graduated.** *Replaces:* the `mkfs.erofs` shell-out in the rootfs build stage. *Implementation:* the tar output is streamed into a custom `tar_to_erofs` in-memory parser that converts tar entries into an `am-fs-erofs` `Node` tree and compiles the image, bypassing the host filesystem entirely — which **also removes the need to create device nodes or root-owned files**, so the rootfs build runs unprivileged. *Caveat carried forward:* `am-fs-erofs` is obscure; its license and maintenance are confirmed via `cargo-deny`, and byte-stable output (fixed mtimes, deterministic inode/dirent ordering) is a reproducibility requirement the determinism tests check. `mkfs.erofs` retained as fallback. *Result:* adopted as the default erofs path.

**Experiment 4 — rootfs source: OCI pull (default) + `mmdebstrap`-in-VM. Graduated.** *Goal:* stop forcing a single rootfs source. Support a host-native **OCI pull** as the default *and* keep `mmdebstrap`'s full apt chain by running it **inside a builder micro-VM**. *Why this resolves the old trade:* the prior revision deferred OCI because the only upside seemed to live in the offline pipeline while the cost was a real supply-chain reduction — so the trade looked like apt-chain verification vs build convenience, and `mmdebstrap` won. Two things change that. First, the upside is **not** purely offline: making OCI the default moves `mmdebstrap`, `apt`, `gpg`, and the shell **off the host** (which the requirements weight: prefer in-crate Rust, minimize external/privileged tooling) and retires the host `dash`/`SHELL=/bin/bash` quirk. Second, the apt chain is **not given up** — relocating `mmdebstrap` into a builder VM keeps full `InRelease`/`Release.gpg` verification (now in-guest, refuse-on-mismatch) and `snapshot.debian.org` timestamp-reproducibility for images that need them. *The critical distinction:* OCI is adopted **strictly as a build-time source** feeding the same `am-fs-erofs` packer — the guest never sees OCI, direct-kernel boot / snapshot / shared-RO-erofs density are unchanged, so it is **performance-neutral on the hot path** and may even cut build time by skipping `mmdebstrap`'s per-package dpkg unpack/configure. OCI *as a runtime mechanism* (containerd + snapshotter + runc + overlay-of-layers) would break the single shared erofs and snapshot/restore the performance story rests on and **remains out of scope**. *Crate note:* the puller is `oci-client` (oras-project, Apache-2.0 — the rename of `oci-distribution`); its manifest/descriptor types cover the spec surface, so a separate `oci-spec` dep is usually unnecessary. *Booked cost:* the OCI default's digest pin is *integrity, not authenticity* unless a cosign/sigstore signature is also verified — that drop is the explicit thing paid for when the OCI default is used; the in-VM source is the full-provenance alternative. *Size is a second, separately-measured axis of the in-VM source's benefit:* `mmdebstrap` can build a genuinely minimal rootfs (only the requested packages), which may be **smaller** than the general-purpose slim OCI base — §13.6 quantifies that delta, since it bears on whether the builder-VM complexity is worth it beyond provenance. *Result:* OCI pull is the default source, in-VM `mmdebstrap` is the full-provenance source, and the prior `mmdebstrap`-on-host path is retired.

**Experiment 5 — in-process unprivileged networking (`smoltcp` + `vhost-user-backend`). Graduated.** *Replaces:* `passt` in the unprivileged datapath (§6, M9). *Why passt is out:* smoltcp is in-process — no external dependency, no LSM/seccomp entanglement — so it is the better design regardless. The originally recorded reason — "passt's C seccomp filter drops the `accept4` CH's `--net vhost_user=true` connection needs (cascading into `epoll` `Bad file descriptor`), no opt-out — fundamentally CH-incompatible" — was **corrected in v16 (audit E5)**: passt's own seccomp *allows* `accept4` (it survives with `EACCES`, not a `SIGSYS` kill), and the `accept4`→`EACCES`→`epoll`-`EBADF` cascade is the host **AppArmor** `passt` profile's stale coarse `network unix stream` rule vs Ubuntu 26.04's af_unix fine-grained mediation — **not CH-specific** (a plain `socat` client reproduces it) and avoidable by flipping the vhost-user socket direction (CH `vhost_mode=server` + passt as client via `-F`), not fundamental. *Implementation:* a userspace smoltcp TCP/IP stack behind a `vhost-user-backend` vhost-user-net device, with egress interception at L4 in the NAT. Three non-obvious invariants made it work (now in §6.1): pin the host NAT MAC **outside the `mac_math(vmid)` range** (e.g. `02:00:00:01:00:00`; the v12 `…:fe` pin collided at vmid 254, NET-2 — §6.1), since a source-MAC collision makes smoltcp silently drop broadcast frames; iterate the virtio RX descriptor chain only when packets are queued (iterating consumes `avail_idx` and otherwise wedges the link); `enable_notification()` on the TX queue in the `handle_event` loop. *Result:* the egress-proxy and host-endpoint tests pass with no `sudo` or TAP. *Fidelity note:* a userspace stack is lower-fidelity than the privileged kernel path, which remains the default for fidelity-sensitive tests.

Two ideas from the dependency report are **not** experiments because they were already the design and were independently re-confirmed: keeping CH/Firecracker as supervised subprocesses driven by typed REST clients (rather than embedding a VMM), and `cgroups-rs` for limits/metrics.

---

## Appendix C. Prior art

Reference implementations worth mining; the ★ entries are the closest to this design.

- **`cocoonstack/cocoon`** ★ — a 2026 lightweight micro-VM engine on Cloud Hypervisor with instant snapshot+clone via reflink, COW overlays, balloon/free-page-reporting, and Firecracker as an alternate backend. Documents the exact vhost-user-snapshot constraint that becomes the §3.3 law. Closest reference to the snapshot/density path.
- **`tinylabscom/mvm`** ★ — Rust CLI with a multi-VMM backend abstraction and a vsock-only guest agent ("NO SSH ever"). A near-reference for the `Vmm` trait, the agent protocol, and the PID-1 contract.
- **`microvm.nix` agent-sandbox write-up** ★ — the egress topology to copy: CH + nftables forward-chain logging + DNS logging + read-only erofs rootfs (the shared RO erofs base, exactly as adopted).
- **`pve-microvm` (Tao of Mac)** — QEMU `microvm` as a managed guest; good reference for the kernel/rootfs split and "prebuild the rootfs, don't `apt` at boot."
- **`agentkernel`, `vmexec`** — ephemeral-VM-per-command patterns on the rust-vmm stack, in the same domain.
- **`smoltcp` + rust-vmm `vhost-user-backend`** — the building blocks of the adopted unprivileged NAT (Exp 5); `vhost-user-backend`'s examples show the vhost-user-net device wiring.
- **Kata `agent-ctl` / `kata-ctl`** — the agent-over-vsock blueprint and tooling.
- **UK AISI `inspect_ai` agent-bridge / `model-proxy-lifecycle`** — relevant only if/when an evaluation layer needs the in-guest model-proxy-over-vsock pattern (the §1.3 hook); not needed for the infrastructure library itself.

---

## Appendix D. Build roadmap

The order the system was built in. Each milestone landed a working, testable slice with at least one fine-grained integration test; a milestone was not complete until its §12 gates were green. As of **pass 6** the system is **validated end-to-end on a KVM host** — the unit/codec/property suite and both the unprivileged and privileged integration suites pass in a delegated `domain` scope (§7.2) — built out through M9, with snapshot/restore (M8) working on CH and Firecracker after the v13 host-path fixes (§3.2, §9.2). The open items in §15 are outstanding (notably the feature-collapse, live pin resolution, and the periodic orphan-sweeper). The roadmap is retained as the sequencing rationale and the test-placement map, not as remaining work.

| # | Milestone | What lands | Integration test(s) |
|---|---|---|---|
| **M0** | Skeleton | Cargo package (2024 ed.), lib + 2 bins, `error`/`config`, clippy + rustfmt + `cargo-deny` in CI, `FakeVmm` | unit: builder defaults, protocol round-trip, `/30` math, vsock-handshake state machine |
| **M1** | First boot | Artifact pipeline v0: minimal `vmlinux` with the full config fragment + erofs rootfs via the OCI source (no bootstrap dependency); CH subprocess + REST `create`/`boot`; serial→log; ordered `Drop` kill | `boot.rs`: VM reaches userspace; `lifecycle.rs`: force-shutdown a started VM |
| **M2** | vsock control | `agent::protocol`; `vmcell-guest-agent` as PID 1 (reaper, never-exit, fork-not-exec, self-check); host `AgentClient` with retry/handshake + serial-panic fast-fail | `exec_vsock.rs`: `exec("echo hello")` → `hello`, exit 0; `lifecycle.rs`: graceful `request_shutdown` |
| **M3** | Shared dirs | `fs` (virtiofsd per share, perms, tags); `--memory shared=on`, `cache=never`. **CH/QEMU only** | `shares_ro_rw.rs`: guest reads a host-placed input; write to RO share fails; host sees a guest-written file in the RW share |
| **M4** | Host endpoints + net (privileged) | `net::tap` (netns + tap + `/30`, rtnetlink); gateway-bound host server | `host_endpoint.rs`: guest GETs a host server on a dynamic port; unreachable outside the netns; raw-TCP also works |
| **M5** | Transparent proxy | `proxy` (MITM CA, log/filter, doubles); TPROXY steering in privileged mode; CA baked into rootfs | `egress_proxy.rs`: HTTPS request logged; a filter rule blocks a domain; a test-double returns a canned response |
| **M6** | Monitoring + limits | `metrics` (cgroup v2 slice, caps, peak/avg readers) | `metrics_limits.rs`: a workload shows up in `memory.peak`; `memory.max` kills a runaway allocator; avg CPU over a busy loop |
| **M7** | Nested virt | Guest kernel profile with KVM (+ `VHOST_VSOCK`) built in; host enablement docs. **CH/QEMU only** | `nested_virt.rs`: `/dev/kvm` present in guest; an inner micro-VM boots and runs a command |
| **M8** | Snapshot + density | Warm-snapshot stage (pause→snapshot→resume); restore via `--restore`→`resume` (never boot) + tmpfs overlay; host vsock reconnect; identity rotation + entropy reseed + clock resync; KSM/balloon. **Validated backends: CH + Firecracker** | `snapshot_restore.rs`: restored VM resumes (not boots) faster than cold boot; host reconnects the severed vsock; fresh CID/MAC + reseeded RNG; outputs still land in `vmcell-out` |
| **M9** | Unprivileged mode | `net::userspace` (in-process smoltcp + `vhost-user-backend` NAT, Exp 5); systemd cgroup delegation for metrics (sibling placement, direct `cgroup.procs` write) | unprivileged `host_endpoint.rs` and `egress_proxy.rs` pass with no `sudo` or TAP, gated as their own suite |

**Build-pipeline hardening track** (ran alongside, completing by M8): pin resolution + `pins.json`; record/replay split for the OCI pull, kernel-source fetch, and in-VM apt; signing-chain verification with refuse-on-mismatch; `reset_to`. The in-VM `mmdebstrap` source lands after M2 and M4 — it needs the vsock agent (M2), an `vmcell-out` share to receive the tar (M3), and builder-VM egress (M4) — and reuses that machinery rather than adding surface, with its own determinism and tampered-apt-digest tests.

**Sequencing rationale.** M1 derisks the hardest plumbing (subprocess + REST + boot + teardown) with the least surface and ships the complete kernel fragment up front so the vsock/virtio-fs symbol gaps don't ambush M2/M3. M2 establishes the control channel everything asserts through. M3–M5 add the three I/O surfaces (files, host services, egress) in increasing complexity. M6 makes runs measurable and bounded. M7 and M8 are the most environment-sensitive (nesting, snapshot/density) and come late. M9 adds unprivileged once the privileged path is solid. The roadmap builds on the primary backend (CH); the per-VMM matrix (§12.4) and cross-VMM benchmarks (§13) layer on via `capabilities()`. The backend-gated milestones are inherent, not accidental: M3 and M7 are CH/QEMU-only (Firecracker hosts neither, so its tier passes inputs as block devices and skips nesting); M8 spans CH and Firecracker with identical assertions and only the restore mechanism differing; QEMU is snapshot-ineligible in its unprivileged+vsock config; its privileged in-kernel-`vhost-vsock` path is validated (v16 audit) but not yet wired.
