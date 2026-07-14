# vmcell — Design Document (v28)

> **What this revision is.** v28 is a restructure of v27 for a developer learning the system in order to
> maintain it: one section per subsystem, each opening with the high-level view; the formerly appended
> Parts VI–IX (daemon, device knobs, hardening, lineage, sessions) are integrated into the subsystems they
> belong to; facts are stated once at their canonical home and referenced elsewhere; the revision-history
> front matter, version-bump ledgers, and inline finding-ID tags are removed (per-finding records remain in
> `docs/44`–`docs/46` and `docs/implementation-notes.md`).
>
> v28 also **directs a small set of design changes** — API simplifications, robustness and testability
> improvements found during the restructure. The body describes the *target* design in the present tense;
> **§18 (the delta register)** is the complete list of deltas from the validated v27 build, so everything
> *not* listed there is as-built and carries the validation status the body records. Section numbers
> changed; **Appendix E** maps v27 § references (which appear in code comments) to v28.

---

## 1. Overview

### 1.1 What vmcell is

**vmcell** is a micro-VM runner for isolated environments, driven entirely from one Rust library. On a
Linux/x86-64 host with KVM it lets you *create a fresh micro-VM, run a command in it over a typed control
channel, give it shared directories / host-reachable endpoints / logged-and-filtered network egress,
observe and cap its resource use, optionally snapshot-and-restore it for speed, and tear it down with no
residue*. Strip away the shares, endpoints, and proxy and what remains — create → restore-or-cold-boot →
`exec` over vsock → observe/cap → ordered teardown — is a self-contained, workload-agnostic execution
primitive.

The project's origin and still most demanding consumer is end-to-end integration testing of an
agent-harness project (a *consumer* of the runner, never the runner itself). The same primitive serves
three co-equal domains: **low-level systems testing** (a real kernel, full syscall surface, and nested
virt, per test), **agentic execution** (untrusted AI-agent tool calls in disposable, observable,
fast-to-restore sandboxes), and **generic serverless / ephemeral functions** (snapshot a warmed runtime
once, restore per invocation in tens of milliseconds, discard). Nothing in the core
(`vmm` / `agent` / `orchestrator` / `metrics`) is specific to any of the three; keeping the primitive
general is a hard design constraint (§13, law G1), not an afterthought.

Concretely, the library (plus a thin CLI and a long-lived daemon) can:

1. Build the VM artifacts (kernel, root filesystem, proxy CA) reproducibly.
2. Create, configure, start, stop, and destroy micro-VMs programmatically.
3. Give each VM read-only and read-write shared directories with independent permissions.
4. Let host-side code stand up private servers the VM can reach (and nothing else can).
5. Route the VM's web egress through a transparent, logging/filtering Rust proxy.
6. Drive the VM over a vsock control channel: one-shot `exec` with streamed output, file put, and
   persistent interactive sessions (PTY, streaming stdin, multiplexed exec).
7. Monitor and cap each VM's CPU / RAM / disk-I/O.
8. Optionally expose nested virtualization so a guest can run its own VMs.
9. Suspend one booted VM and mint many copy-on-write clones from it, with recorded fork/branch lineage.

### 1.2 The three guarantees

The runner delivers three properties **by construction rather than by cleanup**. Stated in testing terms;
substitute "invocation" or "job" for "test" for the other consumers:

1. **Isolation** — a misbehaving harness, model, or workload cannot disrupt the host.
2. **Hermeticity** — no state leaks between runs. Each starts from an identical fresh VM, and teardown is
   *structural*: the VM is discarded, not reset.
3. **Fidelity** — the in-VM environment matches a real end-user Linux system, including the demanding
   cases (nested virt, the full syscall surface, a real kernel).

### 1.3 Non-goals

The evaluation-methodology layer is out of scope: scoring, juries, dashboards, MCTS rollback engines,
stateful API simulation, CI soft-failure statistics. This library is the *substrate* such a layer sits on.
Two connection points are designed in because they map onto hard requirements: the egress proxy is the
natural home for record/replay "cassettes" and web-service test doubles, and the vsock control plane is
the natural transport for an in-guest model-proxy bridge. Everything beyond those hooks — a serverless
scheduler, an agent-sandboxing frontend, an MCP server — is a layer *on top of* this primitive (§17).

### 1.4 The system at a glance

```
┌──────────────────────── Host: Linux + KVM (nested=1 if needed) ───────────────────────┐
│                                                                                        │
│  vmcell orchestrator  (Rust, tokio)                                                    │
│   ├─ Vmm trait:  create / restore / capabilities            (+ VmInstance: boot/pause/ │
│   │     └─ impls:  CloudHypervisor (default) · Firecracker · Qemu   resume/snapshot/kill)│
│   ├─ per-VM:  cgroup v2 slice → {netns + tap (/30)  |  in-process smoltcp vhost-user NAT}│
│   ├─ AgentClient / SessionMux (AF_UNIX vsock)  ⇄  vmcell-guest-agent (PID 1)            │
│   ├─ virtiofsd × N   (one per read-only / read-write data share)                        │
│   ├─ EgressProxy (hudsucker: hyper+rustls):  {nft TPROXY | smoltcp L4} → log/filter/doubles│
│   └─ metrics:  read memory.peak / memory.current / cpu.stat / io.stat from the slice    │
│                                                                                        │
│   artifact cache:  vmlinux  ·  erofs rootfs (RO, shared)  ·  warm snapshot  ·  proxy CA │
└────────────────────────────────────────────────────────────────────────────────────────┘
        │ restore (ms) or cold-boot                          ▲ vsock: Ready/Exec/IO/Exit/PutFile/
        ▼                                                     │        Resync/Session*
  ┌──────────────────────── micro-VM (per run, ephemeral) ───────────────────────────┐
  │ kernel: direct boot, virtio + vsock + virtio-fs + (opt) KVM built-in, no initramfs │
  │ PID 1: vmcell-guest-agent  (mounts /proc /sys /dev/pts + shares, tmpfs overlay,    │
  │        brings up lo, reaps children, serves the vsock protocol)                    │
  │ root: /dev/vda = erofs (RO, shared by all VMs)  +  tmpfs overlay for writes        │
  │ net: eth0 (kernel ip= boot arg) → default route → host proxy   [opt] /dev/kvm      │
  └────────────────────────────────────────────────────────────────────────────────────┘
```

**The per-run lifecycle:**

1. **Acquire artifacts** from the cache (kernel, erofs rootfs, snapshot, CA) — built once, reused (§10).
2. **Allocate per-VM resources:** a cgroup v2 slice, networking (netns+tap on a fresh `/30`, or an
   in-process smoltcp NAT), a unique vsock **CID**, and a unique **VMID**. The erofs base is mounted
   read-only and *shared* — no per-VM disk copy; the only writable state is the tmpfs overlay.
3. **Start the VM:** either **restore** a warm agent-ready snapshot (the fast path: `--restore` →
   `resume`, never `create`/`boot`) or **cold-boot**. On restore, refresh identity, entropy, and clock —
   one native in-agent `Resync` round-trip (§8.2).
4. **Bind shares** (cold/general path): one `virtiofsd` per data share. The snapshot tier attaches *no*
   virtiofsd — see the eligibility law (§8.1); read-only data there is served as an extra erofs/block
   image.
5. **Connect + drive over vsock:** the host retries the handshake until the guest's `Ready` frame arrives
   (bounded by a timeout), while tailing the serial log so a boot panic fails fast instead of retrying to
   no avail. Then `Exec` the entrypoint (or open sessions) and stream output.
6. **Collect results:** outputs from the host side of a read-write share; `memory.peak` / `cpu.stat` /
   `io.stat` from the cgroup slice; the proxy's request log.
7. **Tear down (ordered):** force-kill the **VMM process group first**, then virtiofsd, *then* remove the
   tap/netns/cgroup/overlay/sockets. Removing a netns while the VMM still holds interfaces in it can hang
   or leak; reaping the process first makes teardown a clean kernel operation. Discard is structural —
   that *is* the no-leakage guarantee.

### 1.5 The layer map and the two operating modes

The system is a ladder of layers; each section of this document is one rung:

```
artifact pipeline ──▶ vmlinux · rootfs.erofs · warm snapshot · proxy CA        §10  (build once, cache)
Vmm trait         ──▶ CloudHypervisor · Firecracker · Qemu                     §2   (spawn/boot/restore)
guest environment ──▶ erofs+overlay · guest kernel · guest agent · guest tools §3–§5
per-VM resources  ──▶ cgroup slice · netns+tap | smoltcp NAT · proxy           §6–§7
control plane     ──▶ AgentClient / SessionMux  ⇄  agent (PID 1) over vsock    §3
MicroVm           ──▶ the owning handle; RAII: Drop is teardown                §9
Zygote / Lineage  ──▶ suspend once, CoW-clone many; fork/branch provenance     §8
vmcelld           ──▶ long-lived owner: REST + registry + store (+ broker)     §11–§12
```

Cutting across every layer are the **two operating modes** (detailed in §6.1), which govern the network
datapath, the cgroup-delegation story, snapshot eligibility, how tests split into suites, and which
operations may degrade vs must fail loud:

- **Unprivileged** — KVM-group access only, no `CAP_*`. Networking is the in-process smoltcp NAT.
- **Privileged** — `CAP_NET_ADMIN` + `CAP_SYS_ADMIN` + `CAP_DAC_OVERRIDE`, granted to the test binary
  alone via the capability runner (§15.5) or held by the daemon's broker child (§12.4). Networking is
  netns+tap with L2 fidelity; the only mode eligible for the snapshot tier.

A mode's prerequisites are probed up front and enforced fail-loud (§7.2); a requested mode whose
prerequisites are absent errors with the remediation, never a silent degrade.

### 1.6 Key decisions

| Concern | Decision |
|---|---|
| Primary VMM | **Cloud Hypervisor**, a subprocess over its REST `--api-socket`. Feature-complete: the default and the fully-featured snapshot tier. |
| Second VMM | **Firecracker** (MMIO mode) — the density tier and the fastest restore (≈24 ms p50), with two honest constraints: single-lineage host paths and no lazy restore (§2.3). |
| Fallback VMM | **QEMU `q35`** (never `microvm`) — the escape hatch and most-proven nester. C/GPL *binary*, never linked. |
| Control plane | virtio-vsock + a Rust guest agent as PID 1; framed `postcard` protocol; one-shot exec plus an additive session layer (PTY / streaming stdin / multiplexed exec). SSH is a human-only debug fallback. |
| Root filesystem | A single **read-only erofs over virtio-blk**, shared by all VMs; per-VM writes go to a tmpfs `overlayfs` upper. No journal → no recovery writes, no concurrent-mount corruption; composes with snapshot. |
| Shared dirs | virtio-fs, one `virtiofsd` per share, caller-defined mount tags. Mutually exclusive with snapshot (§8.1). |
| Networking | Per-VM netns + tap + `/30` (privileged) or an in-process smoltcp vhost-user-net NAT (unprivileged). |
| Egress proxy | A Rust MITM proxy (`hudsucker`), CA baked into the guest trust store; steered via nft TPROXY (privileged) or L4 interception in the NAT (unprivileged). |
| Limits | One cgroup v2 slice per VM; a *requested* limit that can't be enforced fails loud, never a silent no-op (§7.2). |
| Guest OS / kernel | Minimal Debian Trixie from OCI-pull (default) or in-VM `mmdebstrap`; direct-boot custom-minimal `vmlinux` (Linux 6.12 LTS), everything built in, no initramfs. |
| Speed lever | Warm snapshot + restore: ≈5.4× faster than cold boot on CH; the zygote fan-out CoW-clones one suspend image into many VMs; `Lineage` adds fork/branch provenance. |
| Third entry surface | The long-lived **`vmcelld`** daemon owns VMs across requests behind a bearer-authed REST/OpenAPI API; by default it forks a **setup broker** so the network surface holds no capabilities. |
| Dependency posture | Prefer in-crate Rust over external tools; permissive licenses only for anything linked; `cargo-deny` on every build is the source of truth (§9.6). |

### 1.7 How to read this document

§2–§12 are the subsystems, each opening with what the piece is and how to drive it before descending into
mechanics. §13 is the concentrated list of **cross-cutting laws** every change must respect — if you
remember nothing else, remember §13; each law names its owner and the gate that reddens on its inverse,
and points back at the section holding the mechanics. §14 is the meta-lessons. §15–§16 are how correctness
is forced and what the system measures. §17 is the honest edge: what is not done. §18 is the delta
register for this revision. The appendices record how the design was reached — the load-bearing reversals,
the dependency experiments, and the contested facts to re-verify per pin; nothing there is required to
*use* the system, but it is the evidence behind the non-obvious choices.

The body is written in the present tense and describes the system as designed at v28; §18 is the exact
boundary between "as built and validated" and "directed by this revision." A non-obvious choice (why erofs
and not ext4; why the snapshot tier excludes unprivileged networking; why a Firecracker snapshot lineage
shares one host vsock path) is explained inline where the component is described, and **Appendix A**
records the reversal history behind the ones that were hard-won.

---

## 2. VMM backends and the `Vmm` trait

### 2.1 The trait and the capability descriptor

The VM lifecycle is modeled as a narrow, typed contract so the finicky, subprocess-supervising,
occasionally-`unsafe` VMM glue stays behind a boundary and the orchestrator stays idiomatic and
unit-testable (a `FakeVmm` implements the same trait, §9.8). The three backends genuinely diverge —
Firecracker has no virtio-fs, no vhost-user-net, no nested virt — so the contract is **general with a
capability descriptor**, not CH-shaped:

```rust
pub trait Vmm: Send + Sync {
    type Instance: VmInstance;
    /// What this backend supports. Callers MUST consult this before invoking an optional op; the
    /// orchestrator selects a backend per tier from it, and the test/bench matrix SKIPS — never
    /// fails — a scenario a backend can't run. Reported, not assumed.
    fn capabilities(&self) -> VmmCapabilities;
    fn id(&self) -> &str;
    /// Cold path: spawn + configure the backend, place it in the cgroup slice, ready to boot().
    async fn create(&self, cfg: &VmConfig, res: &PerVmResources, cgroups: &dyn CgroupFs) -> Result<Self::Instance>;
    /// Warm path: restore from a snapshot dir. Returns a PAUSED instance — the caller continues with
    /// resume(), NEVER boot()/create(). Returns Error::Unsupported when capabilities().snapshot_restore
    /// is false OR cfg carries any vhost-user device (the eligibility law, §8.1). Takes cfg to
    /// reconstruct the NON-vhost-user device topology — it must NOT attach virtiofsd.
    async fn restore(&self, snapshot_dir: &Path, cfg: &VmConfig, res: &PerVmResources, cgroups: &dyn CgroupFs) -> Result<Self::Instance>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VmmCapabilities {
    pub snapshot_restore: bool,            // CH ✓ · FC ✓ (single-lineage host paths, §2.3) · QEMU ✗
    pub lazy_restore: bool,                // demand-paged restore. CH ✓ (--restore … prefault=off) · FC ✗ · QEMU ✗
    pub virtio_fs_shares: bool,            // CH, QEMU ✓ · FC ✗ (block-only)
    pub unprivileged_vhost_user_net: bool, // smoltcp NAT via vhost-user-net: CH, QEMU ✓ · FC ✗
    pub nested_virt: bool,                 // expose /dev/kvm to the guest: CH, QEMU ✓ · FC ✗
    pub virtio_console: bool,              // ConsoleMode::VirtioConsole: CH, QEMU ✓ · FC ✗ — rejected
                                           //   loud+early on FC, before the cmdline is built (console=hvc0
                                           //   with no device would silence the log)
    pub restore_rotates_host_paths: bool,  // CH ✓ (restore config-rewrite moves host paths into the new
                                           //   scratch dir) · FC ✗ (re-binds the baked vsock UDS verbatim) · QEMU ✗
}

pub trait VmInstance: Send {
    async fn boot(&mut self) -> Result<()>;             // cold start (after create)
    async fn request_shutdown(&mut self) -> Result<()>; // graceful (ACPI) signal only; the grace-poll +
                                                        //   SIGKILL fallback is MicroVm::shutdown() (§9.4)
    async fn has_exited(&mut self) -> bool;             // non-blocking try_wait(); trait-default false
                                                        //   (conservative for fakes)
    async fn kill(&mut self) -> Result<()>;             // force-terminate the VMM process group
    async fn pause(&mut self) -> Result<()>;            // REQUIRED before snapshot
    async fn resume(&mut self) -> Result<()>;           // after snapshot, and after restore
    async fn snapshot(&mut self, dir: &Path) -> Result<()>; // pauses, writes, resumes (or stays paused for kill)
    fn vsock_path(&self) -> &Path;                      // AF_UNIX endpoint (changes across restore)
    fn guest_cid(&self) -> u32;                         // unique per running VM (>= 3)
    fn serial_log(&self) -> &Path;                      // per-VM panic / early-boot log
}
```

Every field of `VmmCapabilities` is a property of the *pinned* VMM build and must be re-confirmed against
it (Appendix C), not hard-coded from memory. Resource *usage* is read from the cgroup slice, not from the
instance — `VmInstance` has no `stats()` method; the orchestrator reads counters through the injected
`CgroupFs` (§7). The same "report, don't assume" discipline applies to the host environment via the
`HostCapabilities` descriptor probed once at start-up (§7.2).

`restore_rotates_host_paths` carries a second role beyond the restore-time path rewrite: it is the
**concurrent zygote fan-out gate** (§8.4). Copy-on-write gives each clone its own snapshot *files*, but it
cannot change a host path a backend bakes into the binary snapshot state; only a backend that rewrites
host paths per restore can hand N *concurrent* clones distinct vsock/serial/tap paths. Reusing the
existing capability (rather than a bespoke fan-out flag) keeps one source of truth for one fact.

### 2.2 Cloud Hypervisor — the default and the fully-featured snapshot tier

Feature-complete: snapshot/restore via `--restore`+`resume`, virtio-fs shares, vhost-user-net (so the
unprivileged NAT), and nested virt. Driven over a hand-written thin REST client (`hyper`/`hyperlocal` over
the Unix `--api-socket`); **every control RPC over the API socket is bounded at 5 s**, so a wedged VMM
control socket surfaces as a typed `Error::Timeout` before any outer readiness timeout can mask it. Cold
boot ≈316 ms; warm restore ≈58 ms (§16).

Two lifecycle paths: cold = `vm.create` → `vm.boot`; warm = launch with `--restore` → `vm.resume`
(**never** `create`/`boot` — CH returns `500 "VM is already created"`). `snapshot` must `vm.pause` first,
then snapshot, then `vm.resume` (or stay paused if the VM is about to be killed).

**The restore config-rewrite (the one CH restore subtlety, canonical here).** CH `--restore` rebuilds
every device from the snapshot's `config.json`, which records the *original* instance's now-defunct
temp-dir paths for the **vsock socket**, **serial file**, and **console file**, plus the ancestor's tap in
every `net[].tap` — and CH exposes no restore-time override. So the spawn step rewrites all of them *in
the snapshot dir, before launching*: the socket and serial/console files (in lockstep with `ConsoleMode`)
to this restore's freshly-minted scratch-dir paths, and every `net[].tap` to this restore's *rotated* tap,
so the guest's rotated `/30` and its host tap/nft wiring belong to the same vmid (§8.2). Two consequences
are load-bearing: the rewrite makes a plain `restore()` **single-use** (it mutates the caller's snapshot
dir — hence the per-clone CoW copy, §8.4), and it is exactly what `restore_rotates_host_paths: true`
declares. CH also reads the baked `vsock.cid` from the restore config and reports it as `guest_cid()` —
the restored guest keeps the frozen CID (§8.2).

CH is supervised as an external release binary; only its REST *client* is a crate.

### 2.3 Firecracker — the density tier and the fastest restore

Its draw is density (low memory overhead) plus snapshot, and it has the fastest measured warm restore
(≈24 ms p50, §16) despite the slowest-but-one cold boot (≈764 ms) — exactly the density/snapshot-tier role
it is assigned. Implemented like CH (a hand-written `hyper`-over-Unix client, not `firecracker-rs-sdk`).
Its device model is deliberately minimal — virtio-{net,block,vsock,balloon,rng} — so it cannot do
virtio-fs, vhost-user-net, or nested virt, and `capabilities()` reports those `false`. Three
Firecracker-specific facts:

- **It runs in native MMIO mode** (no `--enable-pci`). The guest kernel ships both virtio-pci (for CH)
  and virtio-mmio (§5.2), so one `vmlinux` serves CH over PCI and Firecracker over MMIO. MMIO is the
  default for backend maturity and the shared `vmlinux`, **not** because PCI blocks snapshot — FC v1.16.0
  supports `--enable-pci` + snapshot (Appendix A, reversal 1).
- **Snapshot/restore is wired and validated end-to-end**, with three host-side accommodations (the guest
  agent needed no FC-specific change — its generic re-bind-after-restore loop, §3.4, covers FC too;
  Appendix A, reversal 8, records the forensic history). First, `MicroVm::snapshot()` invalidates the
  cached `AgentClient` after a successful backend snapshot — FC severs established vsock connections
  across pause/snapshot/resume where CH keeps them alive; invalidating uniformly costs at most one cheap
  reconnect. Second, FC re-binds the snapshot's recorded host vsock UDS path *verbatim* (no load-time
  override in v1.16), so `restore()` re-creates that baked path's parent directory before
  `PUT /snapshot/load` (the ancestor's scratch dir is gone by then; `Drop` removes the resurrected dir).
  The declared contract is `restore_rotates_host_paths: false`: a lineage's restores share one host vsock
  path, so `restore()` runs a fail-loud liveness guard (`reject_live_baked_vsock`, a 100 ms
  `UnixStream::connect` probe — a live listener is a typed `Error::Vmm` "still in use", never a silently
  unlinked live VM's socket; a stale file is removed; the TOCTOU window is documented as a misuse guard,
  not a security boundary). Concurrent restores from one lineage stay unsupported (§17). Third, `create()`
  attaches the entropy device (`PUT /entropy` → virtio-rng → guest `/dev/hwrng`) — without it the
  post-restore reseed reports `reseed_applied: false` and restored clones replay frozen CSPRNG state. The
  wired mechanism: a fresh process + `PUT /snapshot/load {resume_vm:false}` (restore returns paused, the
  caller resumes), `PATCH /vm` for pause/resume, and a `vmcell_host_paths.json` sidecar. `lazy_restore`
  stays an honest `false` (no UFFD backend wired, §17); the capability unit test pins `snapshot_restore`
  *true* and `restore_rotates_host_paths`/`lazy_restore` false.
- **Extended-FPU restore is constrained at the CPU layer.** FC restore can mishandle the guest's saved
  extended-FPU (XSAVE) state, so the boot applies a static **T2 CPU template** (masking the
  extended-state CPUID bits) plus **`noxsave`** on the guest cmdline as a no-template fallback (gated to
  `template.is_none()`). The operational consequence: `noxsave` disables guest AVX/AVX2 down to an SSE2
  floor — a *test-fidelity* cost — so **SIMD-correctness-sensitive tests belong on the CH tier**. The
  forensic history (the `restore_fpregs_from_fpstate` panic, the rejected `bookworm` downgrade, the Lunar
  Lake T2 rejection) is Appendix A, reversal 3.

### 2.4 QEMU `q35` — the fallback and most-proven nester

Full feature set (virtio-fs, vhost-user-net, nesting). Use **`q35` with `virtio-net-pci`**, not `microvm`
— QEMU 10.2.1's `microvm` cannot boot these PVH (the paravirtualized direct-boot entry protocol CH/FC use)
kernels to userspace at all, and it is the machine type, not the virtio-net device or header size, that is
the blocker (the early-boot-`#DE` diagnosis, reproduced ~24 ways, is Appendix A, reversal 7). Cold boot
≈965 ms.

QEMU reports `snapshot_restore: false`: over its **unprivileged** external `vhost-device-vsock` path the
vsock daemon is a stateless vhost-user backend that cannot migrate (the eligibility law, §8.1). A
privileged in-kernel `vhost-vsock` config *is* snapshot-eligible — QEMU 10.2 sets no migration blocker on
`vhost-vsock-pci`, and `migrate`→`-incoming` restore was verified live — but the backend
`snapshot()`/`restore()` are not yet wired (§17). Wiring the unprivileged smoltcp NAT to QEMU also
requires the carried vendored `vhost`/`vhost-user-backend` patch (§9.6).

### 2.5 The capability matrix

| Capability | CH | Firecracker | QEMU |
|---|---|---|---|
| `snapshot_restore` | **✓** | **✓** *(single-lineage host paths)* | ✗ *(privileged in-kernel-vhost-vsock validated, unwired)* |
| `lazy_restore` (demand-paged) | ✓ | ✗ | ✗ |
| `restore_rotates_host_paths` | ✓ *(enables concurrent zygote fan-out, §8.4)* | ✗ *(verbatim baked vsock path — single-lineage)* | ✗ |
| `virtio_fs_shares` | ✓ | ✗ (block-only) | ✓ |
| `unprivileged_vhost_user_net` | ✓ | ✗ | ✓ |
| `nested_virt` | ✓ | ✗ | ✓ |
| `virtio_console` | ✓ | ✗ *(rejected fail-loud before the cmdline is built)* | ✓ |
| cold boot (p50, §16) | ≈316 ms | ≈764 ms | ≈965 ms |
| warm restore (p50, §16) | ≈58 ms | ≈24 ms | — |

The cold-boot/restore inversion pins each backend's role: CH is the feature-complete default, cold-boot
leader, and fully-featured snapshot tier; Firecracker cold-boots slower than CH but restores fastest,
earning the density tier; QEMU is the slowest cold-booter, the fallback for the awkward cases, and the
most-proven nester. The orchestrator reads roles off `capabilities()`; the test/bench matrix **skips —
never fails** — a scenario a backend can't run (§15.4).

---
## 3. The control plane: vsock, the host clients, and the guest agent

The control plane is the one seam the host and guest share: a framed `postcard` `Message` enum over
virtio-vsock, a host `AgentClient` for one-shot request/response, a host `SessionMux` for persistent
interactive sessions, and a guest agent running as PID 1. The serial console is wired to a per-VM log for
panic capture; SSH is a human-only debugging fallback, never the control plane.

### 3.1 The wire protocol

The shared crate `vmcell-protocol` defines a small length-prefixed, `serde`+`postcard`-framed message enum
— the **only** code shared between the host and the guest agent:

```rust
#[non_exhaustive]
pub enum Message {
    // indices 0–7 — the one-shot control plane:
    Ready, Exec(ExecRequest), Stdout(Vec<u8>), Stderr(Vec<u8>), Exit(i32), PutFile { .. },
    Resync { unix_secs: u64, unix_nanos: u32, mac: Option<[u8; 6]>, ipv4: Option<Ipv4Reconfig> }, // host→guest, §8.2
    ResyncAck { clock_error: Option<String>, reseed_applied: bool, mac_applied: bool, ip_applied: bool }, // guest→host
    // indices 8–15 — the append-only session layer (§3.3), each frame keyed by SessionId:
    OpenSession  { session: SessionId, spec: SessionSpec }, // 8  host→guest: start a PTY or pipe session
    Stdin        { session: SessionId, data: Vec<u8> },     // 9  host→guest: feed a running session's stdin
    StdinEof     { session: SessionId },                    // 10 host→guest: close stdin (pipe: child sees EOF)
    Winsize      { session: SessionId, rows: u16, cols: u16 }, // 11 host→guest: resize a PTY (SIGWINCH)
    CloseSession { session: SessionId },                    // 12 host→guest: kill the session's process group
    SessionStdout{ session: SessionId, data: Vec<u8> },     // 13 guest→host: stdout / merged PTY output
    SessionStderr{ session: SessionId, data: Vec<u8> },     // 14 guest→host: stderr (pipe sessions only)
    SessionExit  { session: SessionId, code: i32 },         // 15 guest→host: terminal frame for a session
}
pub struct SessionId(pub u64);                        // Copy/Ord/Hash; monotonic per host connection
pub struct PtyConfig { pub rows: u16, pub cols: u16 } // initial window size for a PTY session
pub struct SessionSpec { pub command: ExecRequest, pub pty: Option<PtyConfig> } // reuses ExecRequest (§3.3)
```

**The append-only law.** `postcard` encodes a variant by its zero-based declaration index, so the
declaration order *is* the wire format: new variants are **appended** (never reordered or removed), the
one-shot indices 0–7 keep their bytes exactly, and a KVM-free **discriminant-stability** test pins each
appended variant to its index. The same discipline applies to fields: `Ipv4Reconfig { addr: [u8; 4],
prefix_len: u8, gateway: [u8; 4] }` carries the rotated `/30` as verbatim octets — endianness-free on the
wire — and was appended after `mac`/`mac_applied` because `postcard` field order is wire-relevant.

There is **no `Hello`, no `Ping`** — a dead variant and a no-op variant are both the "dead protocol
advertised as live" smell the review rubric bans; `#[non_exhaustive]` makes re-adding either non-breaking
if a real use appears. Every variant is live: the guest sends `Ready` as the **first frame** after
`accept`, and the host blocks for it — this is the handshake the restore path re-runs; the
`Resync`/`ResyncAck` pair carries the one-shot post-restore state refresh natively (§8.2), replacing what
were three subprocess `exec`s. Frames are bounded (`MAX_FRAME_BYTES` = 16 MiB, defined once, enforced on
both encode and decode); the default per-exec timeout is 10 s (`DEFAULT_EXEC_TIMEOUT`).

The one-shot `Exec` deliberately stays **id-less** — a host that wants multiplexing uses the session API
on a *separate* connection (§3.2), so the heavily-tested one-shot frames are untouched.

### 3.2 The host side: `AgentClient` and `SessionMux`

```rust
impl AgentClient {
    pub async fn connect(vsock_path: &Path, port: u32, timeout: Duration, timeouts: &Timeouts, serial_log: &dyn SerialLog) -> Result<Self>;
    pub async fn reconnect(&mut self, vsock_path: &Path, port: u32, timeout: Duration, timeouts: &Timeouts, serial_log: &dyn SerialLog) -> Result<()>;
    pub async fn exec(&mut self, cmd: ExecRequest) -> Result<ExecOutcome>;
    pub async fn put_file(&mut self, dst: &str, bytes: &[u8], timeout: Option<Duration>) -> Result<()>;
    pub async fn resync(&mut self, unix_secs: u64, unix_nanos: u32, mac: Option<[u8; 6]>, ipv4: Option<Ipv4Reconfig>) -> Result<ResyncOutcome>;
}
```

`connect` and `reconnect` take the **identical parameter order** — deliberately, so the two can never be
transposed at a call site. `timeouts` is the per-VM `Timeouts` knob set (§9.4): the retry backoff starts
at `connect_backoff_floor`, caps at `connect_backoff_cap`, and resets to the floor once the UDS connects;
the `OK` handshake line is read under a per-byte `connect_ok_read` deadline.

`connect` opens the host-side vsock endpoint and performs the **readiness handshake**, retrying with
backoff until the guest is listening and has sent `Ready`, OR a timeout elapses, OR the serial log shows a
kernel panic (fail fast). The transport is uniform across all three backends: each exposes a host AF_UNIX
socket with the Firecracker-style hybrid-vsock handshake (the host writes `CONNECT <port>\n`, expects
`OK <port>\n`). **Three traps live at this interface** — each presents as "a mysterious timeout" (law C2):

1. The `OK` line must be read **byte-by-byte, never with a buffered reader** — a `BufReader` pre-fetches
   and then discards the first framed payload.
2. `reconnect` after a snapshot restore is **not** a no-op — the vsock device is re-created and, on CH,
   the guest's pre-snapshot listener goes deaf (§3.4, §8.2).
3. The client tracks a **desync flag**: a send error or a timeout marks the stream desynced, and every
   later request fails loud until `reconnect()` restores sync, so a stale half-read frame is never
   mistaken for the next response.

`exec` runs a command, streams stdout/stderr, and returns the exit status. Its timeout is **per-request**
(`ExecRequest.timeout`) and set long only for the builder-VM `apt`/`mmdebstrap` call — never a single
global constant, which would force every test exec to wait minutes before failing.

**`SessionMux` — the session multiplexer.** For persistent interactive sessions the host uses
`vmcell::agent::session`, a multiplexer that owns **its own** vsock connection so it never shares a stream
with — or interleaves one-shot and session frames against — the cached `AgentClient`. It reuses the
**one** connect/handshake helper `AgentClient` uses (the byte-by-byte `OK` line + `Ready`), refactored
into a shared `connect_framed(...)` so the fragile handshake has exactly one implementation.

```rust
pub struct SessionMux { /* writer sink (Arc<Mutex<SplitSink>>), a demux registry, a reader task, next-id */ }
pub struct Session    { /* id, an mpsc receiver of SessionEvent, a clone of the writer sink */ }
pub enum SessionEvent { Stdout(Vec<u8>), Stderr(Vec<u8>), Exit(i32) }
pub struct SessionSpecBuilder { /* argv → env/cwd/pty(rows,cols)/timeout → SessionSpec */ }

impl SessionMux {
    /// Connects a fresh session-multiplexing connection to the guest agent (same handshake as AgentClient).
    pub async fn connect(vsock_path: &Path, port: u32, timeout: Duration, timeouts: &Timeouts,
        serial_log: &dyn SerialLog) -> Result<Self>;
    /// Opens a session: allocates a SessionId, registers its event channel, sends OpenSession, returns a handle.
    pub async fn open(&self, spec: SessionSpec) -> Result<Session>;
}
impl Session {
    pub fn id(&self) -> SessionId;
    pub async fn write_stdin(&self, data: &[u8]) -> Result<()>;     // Message::Stdin
    pub async fn close_stdin(&self) -> Result<()>;                  // Message::StdinEof
    pub async fn resize(&self, rows: u16, cols: u16) -> Result<()>; // Message::Winsize
    pub async fn close(&self) -> Result<()>;                        // Message::CloseSession
    pub async fn recv(&mut self) -> Option<SessionEvent>;           // next output/exit; None once Exit consumed
    pub async fn wait(&mut self) -> ExecOutcome;                    // drain to Exit, collecting output
}
```

A single background **reader task** owns the read half of the connection, decodes each frame, and routes
`SessionStdout`/`SessionStderr`/`SessionExit` to the matching session's `mpsc` sender from the demux
registry (`SessionExit` also closes that session's channel). Writes from all `Session` handles + the mux
go through one `Arc<Mutex<SplitSink>>` — the host mirror of the guest's single-writer discipline (law C4).
Dropping the `SessionMux` closes the connection, which the guest observes as the read-loop end that
triggers connection-owns-its-sessions teardown (law C3) — so a host that forgets to `close()` still cannot
leak guest processes. Per-session queues are **unbounded** and fed only by the *trusted host's own*
sessions (the guest is the sandboxed workload; the host chose to open and must drain each session) — a
deliberate, recorded trade (§17), not the untrusted-server-accumulation class the rubric flags.

`MicroVm::connect_sessions(...) -> Result<SessionMux>` is the ergonomic entry: it dials a second
control-plane connection on the same VM, and refuses fail-loud with the control-plane-disabled
`Error::Agent` when a custom `init=` has replaced the agent (§5.3), exactly as `agent()` does.

### 3.3 Interactive-session wire semantics

The one-shot path structurally cannot do three things the session layer exists for: **no PTY**
(`handle_exec` wires the child to anonymous pipes and `Stdio::null()` stdin — `isatty()` false, no line
discipline, no window size), **no stdin** (stdin deliberately points at `/dev/null` so a `cat`/heredoc
sees immediate EOF instead of blocking on the serial console — correct for one-shot, forecloses
interaction), and **no multiplexing** (`Stdout`/`Stderr`/`Exit` carry no id, and one exec owns the
connection). The session layer is purely additive at the wire and does not touch the one-shot path.

**No open-ack, by construction.** The host may send `Stdin`/`Winsize` immediately after `OpenSession`:
one vsock connection is a single ordered byte stream and the guest's reader is sequential, so
`OpenSession` is always processed before any frame the host queued after it. A failed open (bad `argv`,
PTY-alloc failure) is reported the same way the one-shot path reports a spawn failure —
**`SessionStderr{id, msg}` then `SessionExit{id, 127}`** — so there is exactly one terminal-frame
convention and no separate error variant (law C5).

**Timeout semantics: one field, one meaning ("a deadline, or none").** `SessionSpec` embeds `ExecRequest`
(reuse, not a second copy of argv/env/cwd). `ExecRequest.timeout` is uniformly *an optional kill deadline;
`None` = no deadline*. The one-shot **host** `exec()` fills `None → Some(DEFAULT_EXEC_TIMEOUT)` before
sending (so a one-shot child always has a kill thread and cannot outlive the host's abandoned wait); the
one-shot guest handler additionally `unwrap_or(DEFAULT)`s as belt-and-suspenders. The **session** path
leaves `None` as `None` — an interactive session is *persistent*, so it has no kill thread unless the
caller sets one; its lifetime is bounded instead by explicit `CloseSession`, the child exiting, or
connection teardown. No field is read with two contradictory meanings; the one-shot default is a policy
applied by the host before the byte leaves, not a second interpretation in the guest.

### 3.4 The guest: `vmcell-guest-agent` as PID 1

The agent runs as the `init=` target (`init=/usr/sbin/vmcell-guest-agent`). Its PID-1 contract is larger
than "serve the protocol," and missing any of it is painful to debug (law C1):

- **Mount** `proc`, `sys`, `devtmpfs`, **`devpts` at `/dev/pts`** (best-effort, right after `devtmpfs` —
  it is *not* in the fatal core-mount set `{overlay, /proc, /dev}`, so a failed mount fails only PTY
  sessions, which then report `SessionExit(127)`, never the control plane), the virtio-fs tags, and the
  **tmpfs `overlayfs`** over the read-only erofs root; bring up loopback via `netif::set_loopback_up()` —
  the same offset-tested, `libc::ifreq`-sized (40-byte) `IfReq` + link-up path the MAC/IP rotation uses,
  so the agent has exactly one ifreq layout (an earlier inline 18-byte ifreq was a 22-byte out-of-bounds
  stack write in PID 1 on every boot: the kernel writes back the full 40-byte struct). The proxy CA is
  *not* installed here — it is baked into the rootfs trust store at build time (§4.2).
- **Zero netlink** (law C6). The guest IP is set by the kernel `ip=` boot parameter (`CONFIG_IP_PNP=y`,
  §5.2) in both networking modes, so PID 1 does no `ip link/addr/route` at all; the restore path's
  in-guest identity writes are device-layer ioctls in the agent's `netif` module (§8.2), not netlink.
  Guarded *structurally*: `vmcell-guest-agent` has no `rtnetlink` dependency, asserted by a CI
  `cargo tree` gate — there is no netlink seam to fake because the manual bring-up an early pass added
  was deleted, not stubbed (Appendix A, reversal 2).
- **Reap zombies without stealing an exec'd child's exit status.** PID 1 is the universal reaper; the
  reaper and the exec path coordinate through a shared **`ReaperCoordinator`** with **epoch-based**
  reservation: the exec path captures `pre_spawn_epoch()` *before* `Command::spawn`, and
  `reserve(pid, epoch)` discards only a status recorded at or before that epoch (a genuine previous
  occupant of a reused pid), keeping a post-epoch status as the child's own for immediate delivery. This
  closes two races: the classic false-`127` steal, and the subtler one where an instant (~1 ms) child
  exits and is drained by the `WNOHANG` reaper *between* spawn and reserve — the pre-fix unconditional
  wipe stranded the waiter forever, presenting as a sporadic 10 s "Agent exec timed out" that retries
  papered over for weeks (§14). The residual misattribution window requires a full pid-space wrap within
  microseconds.
- **Never exit on a recoverable condition** — if PID 1 returns, the kernel panics with `Attempted to kill
  init`. Core mounts (overlay/`/proc`/`/dev`) stay fatal; everything else is logged and continued. Two
  such conditions were live regressions: a virtio-fs tag that is not attached (the exec-only path attaches
  no shares, so `virtio-fs: tag … not found` must be skipped, not propagated) and a loopback ioctl failure
  (cosmetic on the data path).
- **Fork** the workload as a child (never `exec` into it), so the agent stays PID 1 and keeps the channel.
- **Serve connections in a loop, re-binding after restore.** The agent serves each connection on **its own
  thread** (a stale pre-snapshot connection whose blocking read may never EOF parks instead of wedging the
  accept loop) and **re-`bind`s** its listener after a bounded idle period, because on CH the pre-snapshot
  bound listener goes deaf once the vhost-vsock device is re-created (§8.2). The accept wait is
  **event-driven**: `serve_vsock` blocks in `poll(2)` on the listener fd for `POLLIN` with the *remaining*
  re-bind idle window as the timeout (rustix's `event` feature — no new crate; the lean-agent gate stays
  green), so a host connect wakes the agent sub-millisecond instead of paying a mean half-interval of
  sleep on every connect. The idle window is an `Instant`-based deadline (last accept or (re)bind +
  `rebind_idle`), and only a *real* accept restarts it — an `EINTR`'d poll (PID 1 takes `SIGCHLD`, and
  `poll` never auto-restarts) and a spurious `POLLIN`→`WouldBlock` wakeup re-poll with the recomputed
  remainder without resetting the deadline, so a deaf post-restore listener still runs out the clock and
  re-binds. `POLLERR`/`POLLHUP`/`POLLNVAL` and non-`EINTR` poll errors are logged and treated as the
  deaf-listener case (re-bind, never exit); the poll timeout carries a 1 ms floor so a sub-ms remainder
  cannot truncate to a busy-spinning `0`. Consequently `guest_accept_poll` paces only the bind-failure
  retry (§5.3); the pure deadline helpers (`next_deadline`/`remaining_idle`/`poll_timeout_ms`) are
  unit-tested red-on-inverse.
- **Dispatch each connection non-blocking, through one writer, owning its sessions.** `serve_connection`
  splits the accepted stream into a read half (the dispatch loop) and a `try_clone`d write half behind an
  `Arc<Mutex<VsockStream>>` — the **single per-connection writer** every frame goes through (the initial
  `Ready`, one-shot output, put-file/resync acks, and all session pump output), via one
  `send_msg(writer, &msg)` that locks and calls the one `send_framed` (the sole framing law, with the
  `MAX_FRAME_BYTES` encode-side cap). No two threads ever write the transport concurrently, so multiplexed
  session frames never interleave-corrupt on the wire (law C4). The loop reads a frame and dispatches
  without ever blocking on a child:
  - `Exec`/`PutFile`/`Resync` → the existing handlers (unchanged behavior, now writing through the shared
    writer; one-shot `Exec` is still synchronous — it drains its child to `Exit` before the loop reads
    again, and one-shot and sessions are never mixed on one connection).
  - `OpenSession{id, spec}` → spawn the session (below), register a `SessionHandle` in the per-connection
    `SessionId → SessionHandle` table, and return immediately — the loop keeps reading.
  - `Stdin{id, data}` → look up the handle, clone its `Arc<Mutex<StdinSink>>`, **release the table lock**,
    then write the bytes (looping partial writes). A closed/unknown id is dropped at `debug` (the session
    already ended), never a desync.
  - `StdinEof{id}` → drop the pipe session's stdin writer (child sees EOF). A no-op for a PTY session
    (closing the master would tear down output; a PTY caller ends input with an in-band EOT or
    `CloseSession` — a half-closed-input refinement is §17).
  - `Winsize{id, rows, cols}` → `tcsetwinsize(pty_master, …)` for a PTY session (delivers `SIGWINCH`); a
    debug no-op for a pipe session.
  - `CloseSession{id}` → `SIGKILL` the session's process group; the waiter reports the resulting
    `SessionExit`.
  - A guest→host variant received here means the peer desynced: log loud, close the connection.

  When the loop ends for any reason (disconnect, transport error, desync), the connection **kills every
  still-open session's process group and closes its fds before returning** — no interactive session
  outlives its connection (law C3). Sessions do not survive snapshot/restore either: a restored VM
  re-binds the listener and the host reconnects on a fresh connection; the "persistent" in the feature
  name is *within a session's life across many frames*, not across a VM restore.

**Per session**, `run_session` captures the pre-spawn reaper epoch, spawns, `reserve`s the pid, and runs
pump + waiter threads exactly like `handle_exec`, but session-tagged:

- **PTY session:** `openpt(RDWR|NOCTTY|CLOEXEC)` → master; `unlockpt`/`grantpt`; open the `ptsname` slave;
  set the initial `PtyConfig` winsize on the master. The child's `pre_exec` runs `setsid()` (new session +
  process group, pgid == pid), `ioctl_tiocsctty(slave)` (the slave becomes the controlling terminal), then
  `dup2` the slave onto fds 0/1/2 — the canonical `login_tty` sequence, each step an async-signal-safe raw
  syscall via `rustix` (one `unsafe` only to borrow the raw slave fd; the master is `CLOEXEC` so it never
  reaches the exec'd program). The parent then **closes its slave** so the master EOFs (Linux `EIO`) when
  the child — the last slave holder — exits; one pump thread reads the master → `SessionStdout` (merged
  stdout+stderr, one stream). In-guest `isatty(0/1/2)` is true and a host `Winsize` delivers `SIGWINCH`
  (law C7).
- **Pipe session:** `process_group(0)` (pgid == pid); stdin/stdout/stderr piped; two pumps →
  `SessionStdout`/`SessionStderr`; the child's stdin pipe writer is the session's `StdinSink`.
- **Both:** an optional kill thread iff `spec.command.timeout` is `Some` (§3.3); a waiter thread that
  `wait_for(pid)`s the reaper, sets `has_exited`, **joins the pump(s)** so all output precedes exit
  (law C5), sends `SessionExit{id, code}`, and removes the session from the table. Both session kinds
  share `handle_exec`'s `child_path(base)` PATH augmentation (one law; a session that dropped the
  guest-tools prefix reddens a unit test).

Because it executes as PID 1 on an already-mounted rootfs that ships `libc6`, the agent could be
dynamically linked against the rootfs glibc; the shipped `GuestAgentStage` builds it as a **static-glibc
(crt-static)** binary — self-contained, so it does not depend on the base image's dynamic loader, which is
why the packer's `libc6` scan (§4.2) is a contract check rather than a hard runtime dependency for this
build. A dynamic-glibc default and a static-`musl` opt-in are both possible; measured, static-`musl` is
~6.2% *larger* than dynamic-glibc (§16), so the deciding axis is toolchain availability and
rootfs-independence, not size.

---
## 4. Storage: root filesystem, disks, and shared directories

### 4.1 The erofs read-only base + tmpfs overlay

The rootfs is a **single read-only erofs image over `virtio-blk`**, shared by all concurrent VMs with
**no per-VM copy**; per-VM writes go to a **tmpfs `overlayfs` upper** the agent mounts at boot (§3.4). One
artifact serves every path — cold boot, concurrent shared mounts, and the snapshot tier — because erofs
over virtio-blk is read-only, shareable, and snapshot-eligible (a plain block device, not vhost-user).
erofs has **no journal**, which removes two failure modes an earlier ext4-clone-per-VM design hit:
journal-recovery panics on read-only mounts, and concurrent-mount corruption. It is also a density lever:
the host page cache holds a single copy of the image for all concurrent guests (§8.3).

If a writable *disk* overlay is ever needed (rare, given the tmpfs overlay), use reflink/qcow2-backing
rather than a full copy — minding that `FICLONE` reflink works on **XFS or Btrfs**, not ext4, where it
silently degrades to a full copy. Using virtio-fs as an overlayfs lowerdir is a known sharp edge (needs
redirect_dir/metacopy) and is avoided — another reason the RO base is erofs, not a virtio-fs mount.

`RootfsSource` has two variants: `Erofs { image }` (the default above) and `Block { image, overlay }` (an
ext4 fallback for which the cmdline builder auto-emits `rootflags=noload`, §5.3). A `VirtioFs { dir }`
rootfs variant existed with no consumer and is removed in this revision (§18, delta 5).

### 4.2 Rootfs sources and the one packer

There are two rootfs sources, living in two crates: the host-native **OCI bootstrap** in `vmcell`
(`RootfsStage`), and the full-apt in-VM **`mmdebstrap`** builder in the extracted `vmcell-rootfs-builder`
crate (§9.1). Both are `vmcell::artifact::Stage` impls, both produce a merged rootfs **tar**, and both
converge on the *one* shared inject+pack tail owned by `vmcell` (`pack_erofs_with_injection`, §4.3): inject
`vmcell-guest-agent` + the proxy CA + the `vmcell-guest-tools` helper + the tmpfs/overlay scaffolding
(injected **after** the source merge, so injected files win any layer collision or whiteout), then stream
the tree through `am-fs-erofs` in memory. The in-process `tar2erofs`/`oci2erofs` writer is the **only**
wired erofs path — the designed `mkfs.erofs` shell fallback is unimplemented (§17), so a missing input is
a hard `Error::Artifact`, never a silent fallback. The in-memory pack avoids creating device nodes or
root-owned files on the host, so it runs **unprivileged**. Tar **hardlink** entries are materialized — the
link path receives a full copy of the earlier target's content — and a hardlink whose target is absent
from the merged tree or is not a regular file is a hard `Error::Artifact`, never a silent `continue` (the
pinned Debian base ships `usr/bin/perl5.40.1` → `usr/bin/perl`, which a silent-skip packer would drop).

- **Default — OCI pull (host-native, in-Rust).** Resolve a Debian base image to a **manifest digest** (pin
  the digest, never the tag), pull manifest + config + layers with `oci-client` (no Docker/containerd),
  verify every blob against its `sha256`, decompress each layer (`flate2`/`zstd`), and apply them honoring
  **OCI whiteout semantics** (`.wh.<name>` deletions, `.wh..wh..opq` opaque-dir markers) to produce the
  merged tar. The guest never sees OCI — this is OCI strictly as a *build-time source*, so direct-kernel
  boot, snapshot/restore, and shared-RO-erofs density are unchanged.
- **Full apt chain — `mmdebstrap` inside a builder micro-VM.** Reuse `vmcell`'s `resolve_builder_base` to
  build a builder rootfs via the OCI source, boot it on this project's own CH stack **on the
  privileged/tap network path with `Egress::Open`** so apt has real outbound egress (a host apt-proxy
  fallback covers hosts without direct egress), then over the vsock agent run `apt-get install mmdebstrap`
  followed by `mmdebstrap` against the pinned `snapshot.debian.org` timestamp — emitting the target rootfs
  as a tar on a read-write share, which then feeds the shared pack tail. Because `mmdebstrap` runs as root
  inside a controlled guest, apt performs the full `InRelease`/`Release.gpg` chain verification in-guest
  (refuse-on-mismatch) against the builder base image's own `debian-archive-keyring` — an equivalent trust
  root pinned transitively by the base-image digest, not a separately-pinned keyring file — and
  `mmdebstrap`, `apt`, `gpg`, and the shell all leave the host entirely.

The bootstrap chain is acyclic and terminates: kernel + OCI-built builder rootfs → builder VM → in-guest
`mmdebstrap` → target tar → erofs. The OCI source needs no VM, so the recursion bottoms out there. The
trade between the two sources is **provenance vs convenience**: the OCI digest pin is *integrity, not
authenticity* unless a cosign/sigstore signature is also verified; the in-VM source keeps the full apt
signing chain. Notably the size argument *inverted*: the official OCI slim base is ~34–39% **smaller**
than an `mmdebstrap` build (it ships `dpkg path-exclude` rules stripping locale/doc/man), so the
builder-VM source earns its keep on provenance, not size (§16; Appendix A, reversal 6).

**Bring-your-own base image.** `vmcell oci2erofs IMAGE@sha256:DIGEST -o rootfs.erofs` runs the same
pipeline against any digest-pinned base image. Two honest constraints, enforced *by the packer* so every
source gets them for free: it **scans the merged tar for `libc.so.6` and fails loud before packing** if
absent (a `libc6`-less base would boot to a dead PID 1 if the agent were dynamically linked), and a
static-`musl` agent for non-glibc bases is an explicit `--agent-musl` opt-in, never a silent fallback.

### 4.3 The rootfs-construction contract (third-party sources)

A rootfs builder is any `vmcell::artifact::Stage` that produces the merged rootfs tree; this contract lets
a third party add an alternative source (a different distro bootstrap, a Nix closure, a company-internal
base) without forking `vmcell`. Three obligations:

1. **Consume seed artifacts from `vmcell`, never re-derive them.** The stage reads from `StageInputs`
   (§10.2): the `kernel` vmlinux path (required for any source that boots a builder micro-VM; host-native
   sources ignore it); the injected `guest_agent` / `guest_tools` binaries and the deployment CA (a builder
   never bakes these itself — obligation 3 — it only needs their content hashes for its cache key); and
   **resolved pins** flowed from Stage 0 (the builder-base image@digest via `resolve_builder_base`, the
   `debian_snapshot_timestamp`, any source-specific pin). Pins arrive as data; a builder that reaches for a
   tag or a live network resolution violates the pin law (§10.2).
2. **Produce a merged rootfs TAR** — the same interchange the first-party sources emit: a single tar of
   the complete userland, with OCI whiteout / hardlink semantics already resolved into a flat tree. The
   builder's output *is* that tar; it stops there.
3. **Emit the final erofs by calling the shared `pack_erofs_with_injection` — this step belongs to the
   system, not the builder.** Routing every source through the one injection+pack tail guarantees each
   rootfs is *identically* injected — a builder that hand-rolled its own erofs could bake a stale agent or
   skip the CA and silently break the handshake or the guest trust chain. The `libc6` scan and the
   `--agent-musl` opt-in apply to every source for free.

**Cache-key discipline** (§10.2 rule 3): the builder's `cache_key` is a `blake3` fold of content and
identity that travel — the seed-kernel content, the builder-base image@digest, the snapshot timestamp, the
baked-CA content, and the guest-agent source closure plus the guest-tools content — never local
`PathBuf`s. Re-pointing any of these invalidates the rootfs. Validity is content-addressed (hash the
output), not existence-of-file; a tampered artifact with an intact `.cache_key` is rejected.

### 4.4 The in-rootfs guest-tools helper

The minimal Debian base omits `iproute2`, `curl`, and `cpu-checker` — tools a handful of integration tests
need (the snapshot test reads the rotated MAC/IP back through them; the restore path itself is native
in-agent and spawns nothing, §8.2). Rather than bloat the rootfs with distro packages or weaken the tests,
the harness ships a small **Rust multicall binary, `vmcell-guest-tools`**:

- `ip` — read-only interface/route/neighbour state from sysfs/procfs, plus `link set <dev> address <mac>`
  via the `SIOCSIFHWADDR` ioctl (the same ioctl logic the agent's `netif` module performs natively on
  restore). `ip addr`/`ip route` *write* forms are accepted as no-ops so an orchestrator `&&`-chain
  succeeds without touching the boot-time IP.
- `curl` — real HTTP/HTTPS via `reqwest`, honoring proxy env vars and `-k`/`--resolve`/`--max-time`. Exit
  codes are curl-faithful: only a 2xx tunnel establishment counts as `CONNECT` success; a blocked domain's
  403 is printed the way curl prints it (status to stderr, body to stdout) but exits non-zero; a transport
  failure exits 7 (`CURLE_COULDNT_CONNECT`) with the full error source chain on stderr — never an "any
  proxy response → exit 0" probe. Its pure parsers (and its ifreq layout) are unit-tested.
- `kvm-ok` — a real `/dev/kvm` probe for the nested-virt test.

Two properties keep it honest. It performs the **real** operations (genuine HTTP, real `/dev/kvm`, real
procfs reads), so it is not a weakening of any assertion. And it is **baked into the erofs**, not
delivered over a share: `virtiofsd` cannot enter its sandbox namespace without privilege, so a share would
fail in the *unprivileged* suite, while the erofs root is served over virtio-blk in both modes. A
`GuestToolsStage` builds the helper and the packer injects it with `ip`/`curl`/`kvm-ok` symlinks; the
agent prepends its dir to the exec `PATH`. The rootfs cache key folds the helper's content, so a helper
change re-bakes the rootfs. Because it needs `reqwest` (→ hyper → tokio) for real HTTP, `guest-tools` is
**not** subject to the lean-agent dependency ban — it is a *guest* binary that runs unprivileged, not part
of the host stack (§9.7).

### 4.5 Shared directories (virtio-fs)

Shared directories use **virtio-fs, one `virtiofsd` per `Share`**, each on its own Unix socket, with
`--readonly` for `ReadOnly` shares (the flag is `--readonly`, *not* `--read-only`, which aborts the
daemon) and `--sandbox namespace`. The VMM config must set **`--memory shared=on`** for *any* virtio-fs
share to work — without a shared guest-memory region the share does not mount at all (this
mandatory-for-virtio-fs `shared=on` is distinct from the *opt-in* KSM `shared=off` memfd toggle, §8.3).

**Share tags are caller-defined, not built-ins** (keeping the primitive general): a consumer names
whatever mount tags it wants on each `Share`, and the guest mounts exactly those. The mechanism: for every
`Share` in `VmConfig` the orchestrator appends a `vmcell_share=<tag>:<guest_path>:<ro|rw>` token to the
guest kernel command line (consistent with the `ip=` pattern); the guest agent reads `/proc/cmdline`,
mounts each `tag` at its `guest_path` (default `/<tag>`, overridable via `Share::with_guest_path`), and
applies a read-only mount for `ro` shares. `config::build()` rejects a tag/`guest_path` containing
`:`/whitespace, a non-absolute `guest_path`, or a duplicate — each with a negative test — and the agent's
cmdline parser is unit-tested (a malformed token is dropped, never mounted read-write when the host
declared read-only). The tags vmcell ships in its own tests/builder are `vmcell-in` (ro input),
`vmcell-bin` (ro, shared across tests so its pages stay hot — the consumer's binaries arrive here so a new
build does not invalidate the rootfs), and `vmcell-out` (rw output), but they are examples, not
requirements.

Two implementation subtleties:

- **Subprocess supervision.** A misconfigured `virtiofsd` exits immediately, but if the orchestrator only
  polls for the socket file, CH hangs forever waiting for the vhost-user socket — so the supervisor
  surfaces the child's exit/stderr *and* bounds the socket-wait with a timeout.
- **Service uid.** virtiofsd runs `--sandbox namespace` and, when started as root, drops to the invoking
  user's `SUDO_UID`. It deliberately refuses to fall back to `nobody` (which would `EACCES` a root-owned
  share and silently break the mount); root-with-no-usable-uid keeps privileges with a loud warning. A
  dedicated per-share service-uid allocator is forward work (§17).

**Snapshot interaction:** attaching virtiofsd (a vhost-user device) makes a VM snapshot-ineligible
(law S1), enforced by construction — `config::build()` rejects `snapshotting` combined with any virtio-fs
share. Read-only data needed in the snapshot tier is served as an **additional erofs/block image**
instead, whose cost is the extra image's page cache, not guest anonymous RAM. An in-process
`fuse-backend-rs` alternative (Appendix B) is gated behind `experiment-fuse`; it does not enforce
read-only, so a read-only share on that backend is rejected fail-loud with a typed `Error::Unsupported` —
never a silent write-through.

### 4.6 Extra virtio-blk devices and disk-I/O throttling

`BlockDevice` models one extra raw disk, mirroring `Share`'s ergonomics (`read_only(image)` /
`read_write(image)` constructors plus `.with_io_limit(DiskIoLimit)`); `VmConfig::extra_disks` attaches
them in order. The guest kernel enumerates them as **`/dev/vdb`, `/dev/vdc`, …** in attachment order; the
root disk stays `/dev/vda` (the cmdline hard-codes `root=/dev/vda`). vmcell attaches the **raw** block
device only — no partitioning, no filesystem, no mount. The guest workload owns the device; **the guest
agent does not auto-mount extra disks and needs no change** (an unknown `/dev/vdX` is invisible to it).
Raw exposure is zero new guest code and zero new cmdline token; if auto-mount is ever wanted, model it on
`vmcell_share=` parsing, best-effort so a bad token never panics PID 1.

**Per-backend wiring — attach *after* the root disk** so the root stays device index 0:

- **Cloud Hypervisor:** push one `ChDisk { path, readonly, direct: false }` per extra disk onto
  `ch_cfg.disks` after the rootfs arm; CH assigns `/dev/vd{a,b,c}` purely by array order. Every disk is
  declared `image_type=Raw` **explicitly** — CH v52 auto-detects an unspecified image as raw and disables
  sector-0 writes, a live-caught bug that also lurked on the writable `Block` rootfs path.
- **QEMU:** a split-form `-drive file=…,format=raw,id=extra{i},if=none[,readonly=on],file.locking=off` +
  `-device virtio-blk-pci,drive=extra{i}` pair per disk, after the rootfs `-drive`. No fixed device cap
  (PCI slots).
- **Firecracker:** `PUT /drives/extra{i}` with `is_root_device: false, is_read_only: readonly` after the
  rootfs PUT. Each consumes one virtio-mmio slot; FC's MMIO region is finite, so a very large list
  eventually exhausts it — surfacing fail-loud as the backend's typed API error at `create()`, never a
  silent drop. No arbitrary numeric cap is invented in the library; the exact FC MMIO budget is a
  backend-internal constant this codebase does not mirror.

**Snapshot composition and restore path-stability.** Plain virtio-blk is **not** a vhost-user device, so
an extra disk is snapshot-eligible — it does not enter `config_has_vhost_user_device` (law S1), pinned by
a unit test asserting an extra disk does not flip the predicate (a false positive would wrongly disqualify
snapshot). A block device's contents live on disk, *outside* the memory snapshot, so a writable extra disk
carries whatever bytes it holds at restore — correct block-device semantics, not a leak. Both CH and FC
restore devices from the **paths recorded at snapshot time**, so an extra disk's image path must be
**stable across a restore** (not inside the deleted per-VM scratch dir) — documented on
`VmConfig::extra_disks`; the common case (a caller-owned image at a fixed path) needs no restore-time
rewrite.

**Validation.** `build()` rejects an empty or non-absolute extra-disk image path and a duplicate image
(two attachments of one backing file — a rw corruption footgun), each with a negative test; existence is
*not* checked (consistent with rootfs/shares — `build()` never stats paths). All three backends boot off
virtio-blk, so extra virtio-blk is universally supported — no new capability flag. The KVM matrix test
attaches a marked image and reads the marker back **in-guest** off `/dev/vdb`; a snapshot variant proves
the marker survives a restore into a fresh vmid.

**Disk-I/O throttling.** `DiskIoLimit` is a `bandwidth_bytes_per_sec` and/or `iops` cap — the **portable**
form of disk fault injection (a slow/pressured disk, to test a workload's timeout/retry/backpressure),
because every backend has a native per-disk rate limiter, including the primary CH (unlike
error-injection, which is QEMU-`blkdebug`-only and stays forward work, §17). `build()` rejects an
`io_limit` that limits nothing, or any `0` cap (a `0` bucket never refills → wedged I/O). The CH and
Firecracker token buckets share **one** conversion (`IO_LIMIT_REFILL_TIME_MS`: a bucket of `size = rate`
refilled every 1000 ms), so they can never encode the same `DiskIoLimit` as different rates; QEMU takes
the per-second rate directly (`-drive …,throttling.bps-total=<B>,throttling.iops-total=<N>`). Validated on
KVM: a 1 MiB/s cap floors a 4 MiB read at ~3 s on every backend, against an un-throttled baseline in the
same VM.

---

## 5. The guest kernel

### 5.1 The base and the pin

The guest is a minimal **Debian Trixie (13)** rootfs (§4.2) with security support to 2028; the agent
bypasses distro init, so a larger userland does not grow the boot working set. The committed kernel is
**Linux 6.12.94** (the Trixie-aligned 6.12 LTS line), direct-booted as a custom-minimal `vmlinux` from
Debian kernel source. The 6.12.94 bump also fixed a from-scratch build break under modern toolchains:
gcc-15 defaults to C23, where `false`/`bool` are keywords, and `drivers/firmware/efi/libstub` was compiled
without `-std=gnu11`; 6.12.94 carries the fix (and CH boots via PVH, never the EFI stub, so
`CONFIG_EFI_STUB=n` is a clean alternative).

A `vmlinux` reaches the artifacts dir by one of **three producers** (§5.4 is the contract each must
satisfy). Two are lightweight bootstrap producers in `vmcell`: `KernelStage` host-`make`-compiles from
pinned source, and `PrebuiltKernelStage` downloads a digest-pinned prebuilt `vmlinux` and verifies its
sha256 (the bootstrap seed, §5.4). The third is the in-VM download+configure+compile builder in
`vmcell-kernel-builder` (§9.1): it host-fetches + sha-verifies the pinned kernel *source* tarball, shares
it read-only into a builder VM, and the guest runs `make defconfig kvm_guest.config` → append the microvm
fragment + sorted named fragments → `make olddefconfig` → `make -j vmlinux`, then copies `vmlinux` out.
`vmcell-cli --kernel-source prebuilt|host-make|in-vm` selects among them; all three emit the same
direct-boot PVH `vmlinux`.

### 5.2 The config fragment

The `microvm` fragment is **appended to** `make defconfig kvm_guest.config` — it is *not* a standalone
config, and `kvm_guest.config` alone omits vsock, virtio-fs, and erofs and causes real boot failures
(which failure surfaces first is order-dependent: with `kvm_guest.config` alone the boot dies at the erofs
root-mount panic before userspace; the `EAFNOSUPPORT`-at-vsock symptom needs an intermediate config with
erofs present but vsock absent). Everything the guest needs is built in (`=y`, no modules → no initramfs):

```text
# Transport — CH uses virtio-pci; ALSO build virtio-mmio so Firecracker runs in MMIO mode and snapshots
CONFIG_PCI=y  CONFIG_VIRTIO=y  CONFIG_VIRTIO_PCI=y  CONFIG_VIRTIO_MMIO=y
# Core paravirtual devices
CONFIG_VIRTIO_BLK=y  CONFIG_VIRTIO_NET=y  CONFIG_VIRTIO_CONSOLE=y
CONFIG_HW_RANDOM_VIRTIO=y          # virtio-rng — also feeds the snapshot entropy reseed
CONFIG_VIRTIO_BALLOON=y            # density lever
CONFIG_IP_PNP=y                    # guest IP via kernel `ip=` cmdline → PID 1 needs no netlink
# vsock control plane
CONFIG_VSOCKETS=y  CONFIG_VIRTIO_VSOCKETS=y   # (+ CONFIG_VIRTIO_VSOCKETS_COMMON)
# virtio-fs shared dirs
CONFIG_FUSE_FS=y  CONFIG_VIRTIO_FS=y
# Filesystems: erofs RO root + tmpfs overlay (+ ext4 only for a block fallback)
CONFIG_EROFS_FS=y  CONFIG_EROFS_FS_ZIP=y  CONFIG_OVERLAY_FS=y  CONFIG_TMPFS=y  CONFIG_EXT4_FS=y
# Console / early boot / paravirt clock
CONFIG_SERIAL_8250=y  CONFIG_SERIAL_8250_CONSOLE=y  CONFIG_DEVTMPFS=y  CONFIG_DEVTMPFS_MOUNT=y
CONFIG_PARAVIRT=y  CONFIG_KVM_GUEST=y
# Nested virt: guest exposes /dev/kvm to inner VMs
CONFIG_KVM=y  CONFIG_KVM_INTEL=y   # or CONFIG_KVM_AMD=y
CONFIG_VHOST_VSOCK=y               # HOST-side; only needed so an *inner* (L2) VM can use vsock
```

A few symbols (e.g. `CONFIG_IP_PNP`) the `kvm_guest.config` base already provides and the fragment simply
guarantees. Three precisions: `CONFIG_VHOST_VSOCK` is host-side (the base guest control plane needs only
`VSOCKETS` + `VIRTIO_VSOCKETS`; `VHOST_VSOCK` earns its place only for nested virt); the erofs
decompressor config must match the packer's compressor or the mount fails — the production packer ships
**uncompressed**, sidestepping the dependency at a size/page-cache cost; and the builder auto-emits
`rootflags=noload` for the ext4/`Block` fallback rootfs so the ext4 driver mounts strictly read-only
without journal recovery (recovery is a write and panics on a read-only device — erofs has no journal, so
the default path needs no such flag).

### 5.3 The kernel command line

```text
console=ttyS0 loglevel=6 random.trust_cpu=on random.trust_bootloader=on cryptomgr.notests raid=noautodetect
root=/dev/vda rootfstype=erofs ro panic=1 init=/usr/sbin/vmcell-guest-agent vmcell_vmid=<vmid>
ip=10.200.<n>.2::10.200.<n>.1:255.255.255.252::eth0:off   # n = (vmid % 254) + 1 (§9.3); only when net != None
kvm-intel.nested=0 kvm-amd.nested=0   # ALWAYS emitted in both directions (=1/=1 when nested_virt)
vmcell_share=<tag>:<guest_path>:<ro|rw>   # one per share (§4.5)
vmcell_accept_poll_ms=20 vmcell_rebind_idle_ms=250   # from the Timeouts profile (§9.4)
```

A single shared `config::build_kernel_cmdline` emits this for all three backends — the prior per-backend
inline copies diverged (QEMU's had dropped `loglevel=` entirely, a ≈1400→~1000 ms QEMU cold-boot bug,
§16). Ordering and conditionals are load-bearing: `rootflags=noload` is auto-emitted only for the `Block`
rootfs; Firecracker inserts its `noxsave` fallback (when no T2 CPU template is available) right before
`init=`; and the nested tokens are emitted **explicitly in both directions** — `=0` on false, not omitted
— because `-cpu host` exposes VMX unconditionally and a modern kernel defaults `nested=Y`, so omitting on
false would silently leave nesting on.

`loglevel=6` keeps the serial console attached for panic capture (`contains_panic` matches KERN_EMERG
lines) and boot diagnostics while dropping the voluminous `KERN_INFO` device-probe output that otherwise
dominates cold boot — each line is a synchronous write to the byte-at-a-time 8250 UART; this was the
single largest cold-boot lever (§16). `loglevel` is set from `VmConfig::kernel_verbosity` (default
`Balanced`=6; `Quiet`/`Verbose`/`Debug` → 3/7/8). The leading `console=` token is likewise a per-VM knob,
`VmConfig::console_mode` (default `Uart`→`console=ttyS0`; opt-in `VirtioConsole`→`console=hvc0`, batched
over a virtqueue so verbose logging avoids the UART VM-exit tax — but only after virtio-pci probe, so it
forfeits early-boot + pre-virtio panic capture; not supported on Firecracker, rejected fail-loud). The
cmdline token and the backend's console device are both derived from `console_mode` so they cannot desync.

The `vmcell_*` tuning tokens are parsed by the agent **clamped and untrusted**: `vmcell_share=` (§4.5) and
`vmcell_accept_poll_ms=`/`vmcell_rebind_idle_ms=` (the guest re-bind cadence, from the `Timeouts` profile
— so a profile tunes the guest with no rootfs rebuild; the guest re-clamps both into `[1, 10_000]` /
`[20, 60_000]` ms, garbage/overflow → the compiled default). `cryptomgr.notests` skips the built-in crypto
self-tests (≈10 ms) and `raid=noautodetect` skips the md RAID autodetect scan (≈2 ms) — the only real
cmdline-trimmable boot work a debug-verbosity `printk`-timestamp probe found; neither touches
virtio/vsock/erofs, `ip=` autoconfig, panic capture, or runtime crypto. The same probe **disqualified**
the fashionable microVM trims, kept out — do not re-derive them: `i8042.nokbd`/`i8042.noaux` target a PS/2
probe that never runs here, `pci=lastbus=0` a beyond-bus-0 scan ACPI/ECAM already constrains away,
`tsc=reliable` a calibration kvm-clock already skips (and it carries clock-watchdog risk), and
`no_timer_check` is auto-set under `CONFIG_KVM_GUEST=y`. `random.trust_cpu=on` avoids a possible CRNG-init
stall on first `getrandom()`.

**Append-only extra args (law F3).** `VmConfig::extra_kernel_args` are appended **last**, after every
token above, in caller order. "Append-only" is the safety contract: an extra arg may *add* a parameter but
never *clobber* a token vmcell owns, enforced by one predicate, `is_reserved_cmdline_arg`: the arg's key
(text before the first `=`, or the whole bare token) must not be in `RESERVED_CMDLINE_KEYS` (`console`,
`loglevel`, `root`, `rootfstype`, `rootflags`, `ro`, `panic`, `init`, `ip`, `kvm-intel.nested`,
`kvm-amd.nested`, `cryptomgr.notests`, `raid`, `random.trust_cpu`, `random.trust_bootloader`, `noxsave`)
and must not start with `vmcell_` (the agent *trusts* those tokens, so a caller must not be able to spoof
one), and the token must be a single whitespace/control-free word (a space would forge a second token —
the cmdline-injection guard; quoted values with embedded spaces are out of scope). A one-law gate builds a
cmdline exercising every emitted token (block rootfs + networking + a share + nested) and asserts
`is_reserved_cmdline_arg` is true for each, so the reserved set can never fall out of sync with the
builder — add a new builder token without reserving its key and the test goes red.

**The `init=` override — a genuine PID-1 replacement, honored honestly.** `VmConfig::init`, when `Some`,
emits `init=<custom>` in place of the fixed agent token — the **only** place either init token is
constructed; a backend never string-builds `init=`. `build()` validates the path (absolute, valid UTF-8,
single safe cmdline token). A custom init *replaces* the guest agent as PID 1 and therefore **forgoes the
vsock control plane** — no `Ready` handshake, no `exec`, no post-restore resync. vmcell makes that
consequence loud, never silent:

- `MicroVm::agent()` and `connect_sessions()` fail loud with a typed `Error::Agent` naming the custom-init
  cause, instead of hanging for the full connect timeout on a listener that will never answer.
- `MicroVm::start()` skips the QEMU control-plane health probe when `init` is overridden — that probe
  exists to confirm the *agent's* vsock transport, and there is no agent to confirm; without the skip a
  custom-init QEMU VM would re-spawn to exhaustion. (CH/FC probes are already no-ops.)
- `build()` rejects `snapshotting == true` with a custom `init` — the mandatory post-restore resync runs
  *through the agent*, which a custom init replaces; a restored custom-init clone would be stranded on
  frozen identity with silently dead egress and correlated RNG, exactly the trap law S2 forbids.

`start()` still boots and returns the handle — the caller drives/observes the VM out-of-band: the serial
log, a read-write extra virtio-blk device, a share, or networking. A caller who wants a program to run at
boot *without* giving up the control plane should keep the default init and `exec` the program over vsock;
the `init=` override is the escape hatch for booting a genuinely different PID 1 (the fidelity /
systems-testing domain). A custom init on the read-only erofs root also has no writable `/` (the agent's
tmpfs-overlay setup no longer runs), so a custom-init VM typically pairs with a writable `Block` rootfs or
a writable extra disk — a caller responsibility, documented on the field. It is a **library-only** escape
hatch: every CLI verb brings the agent up, which a custom init precludes, and the daemon owns VMs through
the control plane (§11.5), so neither exposes it.

### 5.4 The guest-kernel contract and the bootstrap seed

Whichever producer emits it, a guest `vmlinux` must satisfy one contract so it is interchangeable — a
third party pinning a prebuilt, or porting to a new kernel line, checks against *this*, not a producer's
internals. **Required output: a direct-boot PVH-ELF `vmlinux`** — CH and Firecracker boot it via the PVH
entry (never the EFI stub, never a bzImage + bootloader), so `CONFIG_PVH=y` is load-bearing. Every symbol
below is `=y`, built in — no modules, no initramfs (the guest has no early userspace to load them):

```text
CONFIG_PVH=y                                        # PVH direct-boot entry — CH/FC boot protocol
CONFIG_VIRTIO_PCI=y  CONFIG_VIRTIO_MMIO=y           # CH=virtio-pci, FC=virtio-mmio
CONFIG_VIRTIO_BLK=y  CONFIG_VIRTIO_NET=y  CONFIG_VIRTIO_CONSOLE=y
CONFIG_VSOCKETS=y  CONFIG_VIRTIO_VSOCKETS=y         # the vsock control plane (§3)
CONFIG_FUSE_FS=y  CONFIG_VIRTIO_FS=y                # virtio-fs shared dirs (§4.5)
CONFIG_EROFS_FS=y  CONFIG_EROFS_FS_ZIP=y            # erofs RO root — the decompressor MUST match the packer
CONFIG_OVERLAY_FS=y  CONFIG_TMPFS=y                 # the tmpfs overlay over the RO erofs (§4.1)
CONFIG_EXT4_FS=y                                    # the Block rootfs fallback only
CONFIG_IP_PNP=y                                     # boot-time `ip=` autoconfig → zero netlink in PID 1
CONFIG_KVM=y  CONFIG_KVM_INTEL=y  CONFIG_KVM_AMD=y  # nested virt: expose /dev/kvm to an inner VM
CONFIG_HW_RANDOM_VIRTIO=y                           # virtio-rng — feeds the snapshot entropy reseed (§8.2)
CONFIG_SERIAL_8250=y  CONFIG_SERIAL_8250_CONSOLE=y  # ttyS0 — panic/boot capture
```

Two contract clauses beyond the symbol list. **Provenance:** the source is verified against a pinned SHA
before compile, or the prebuilt binary against a pinned sha256 — no tag fetch, no unverified download.
**Decompressor match:** the production packer packs uncompressed, so plain `CONFIG_EROFS_FS=y` mounts it;
the ZIP option is required only for compressed images. Because the rootfs is kernel-independent, **one
`vmlinux` boots any erofs** and one erofs boots under any conformant `vmlinux` — the property both the
benchmark kernel-sweep and the bootstrap seed rely on.

**The seed-kernel chicken-and-egg.** The in-VM builders need a *working guest kernel* to boot the builder
VM in which they compile a kernel or build a rootfs, so the bootstrap seed must be produced *without* an
in-VM build — hence the two bootstrap producers. The seed is not any generic microVM kernel: it must
already carry EROFS + FUSE/virtio-fs + VSOCK + PVH + overlay built in to boot vmcell's erofs root at all.
**Empirical finding (validated):** a **Kata Containers** prebuilt `vmlinux.container` (Linux 6.18.35, from
`kata-static-3.32.0-amd64.tar.zst`) boots under CH against vmcell's erofs root to PID 1 + overlay, so it
is the pinned bootstrap seed (`kernel_prebuilt` in `pins.json`, downloaded + sha256-verified by
`PrebuiltKernelStage`). Generic microVM kernels do **not** qualify: a Firecracker CI microVM kernel
(tested) omits `CONFIG_EROFS_FS`/`CONFIG_FUSE_FS` and panics on the erofs root mount (`VFS: Unable to
mount root fs`, before any userspace). Host-`make` `KernelStage` remains the guaranteed fallback seed.

### 5.5 Kernel as a benchmark dimension

`pins.json` carries a `kernels` registry (`<label> → {source_url, source_sha256}`) alongside the default
kernel; `vmcell build-kernels` builds each to `vmlinux-<label>`, and `bench-vm --kernel <label>` sweeps
the §16 suite per kernel (the erofs is kernel-independent, so one rootfs boots under any `vmlinux`). The
same harness sweeps the perf knobs — `--profile default|low-latency|throughput`, `--kernel-verbosity`, and
`--console uart|virtio-console` — which is how the §16 backend × preset and console × verbosity matrices
are produced. The payoff of making kernel a dimension was *disproving* a wrong belief: an interleaved
sweep of 6.6.143 against 6.12.94 showed the guest kernel version is **not** a material hot-path lever
(warm restore within ~2%), settling an earlier cross-session "~2× slower" scare as host-load noise (§14).

A config-variant kernel is requested as **(base label, an ordered set of named KConfig fragments)** —
e.g. `6.12.94 + [KASAN, LOCKDEP]` — with `pins.json` mapping each fragment name to a KConfig string.
Fragments are canonicalized to **sorted order** at hash time (so `[KASAN, LOCKDEP]` and `[LOCKDEP, KASAN]`
resolve to the same artifact); a non-zero `make olddefconfig` is a fail-loud `Error::Artifact`; and the
build-time blow-up (a cold KASAN build is ~45–90 min) is bounded by the content-addressed cache — CI
batches by label and runs the full matrix nightly. PREEMPT_RT is *not* a fragment (it needs an rt-patched
source — a separate registry source), and KCOV *extraction* needs guest tooling (§17); the fragment only
turns the kernel capability on.

---
## 6. Networking and egress

### 6.1 The two operating modes

The harness runs in one of **two named operating modes**, and the distinction is first-class — it governs
the network datapath, the cgroup-delegation story, how tests split into suites (§15.4), and which
operations may degrade vs must fail loud (§7.2). The vocabulary replaces the older "rootless" wording,
which over-implied "zero privilege":

- **Unprivileged operation** — the process holds **KVM-group access only** (`/dev/kvm` via the `kvm`
  group, granted once with `usermod -aG kvm $USER`) and **no extra Linux capabilities**. Networking is the
  in-process smoltcp NAT; cgroup limits use whatever a `systemd-run --user` delegation provides. KVM
  access is a *group membership*, not a capability, so "unprivileged" means "no `CAP_*`," not "no access."
- **Privileged operation** — the process holds **`CAP_NET_ADMIN`** (tap, rtnetlink, nft/TPROXY),
  **`CAP_SYS_ADMIN`** (per-VM netns + `setns`), and **`CAP_DAC_OVERRIDE`**. Networking is the full
  netns+tap+`/30` path with L2 fidelity; it is the only mode eligible for the snapshot tier (law S1) and
  the default for fidelity-sensitive tests. The caps are granted to the test binary alone via the
  capability runner `vmcell-test-runner` (§15.5) — *not* `sudo -E cargo test` — or held by the daemon's
  broker child (§12.4).

**Why three caps, not two.** `CAP_DAC_OVERRIDE` is load-bearing: the privileged tap path could never
create a netns without it, because `netns_rs::NetNs::new` must create `/var/run/netns/<n>`, a
`root:root 0755` directory the dev-uid process can't write (`EPERM`). It also unblocks the benchmark-only
sysfs/procfs knob writes (CPU-frequency pinning, KSM), since those `root:root` kernfs files honour
`DAC_OVERRIDE` — whereas `drop_caches`, a procfs sysctl special-cased on `euid==0`, does not.

**Mode selection is probed and fail-loud, not discovered mid-run.** Mode prerequisites are part of the
start-up `HostCapabilities` probe (§7.2): a privileged run verifies the three caps and that
`/var/run/netns` is reachable; an unprivileged run verifies KVM-group access. A requested mode whose
prerequisites are absent errors up front with the remediation. Two host-environment caveats: (1) the
privileged tap path needs the harness in a non-threaded `domain` cgroup scope and, for limit enforcement,
in a delegated leaf — run it under `systemd-run --user --scope -p Delegate=yes` (§7.3); (2) modern Ubuntu
blocks the unprivileged-userns escape hatch by default
(`kernel.apparmor_restrict_unprivileged_userns=1`); Debian Trixie does not necessarily, so the host distro
affects whether unprivileged mode gets off the ground. **Cleanup:** a killed privileged run can leak
`/var/run/netns/<prefix>-net-*` (occasionally colliding with a later vmid); the `sweep_orphans()` free
function (backed by an injectable `OrphanScanner`, reaping only non-live vmids in netns → cgroup → scratch
order) cleans these; a fully-automatic periodic sweeper is forward work (§17), though the daemon closes
its own crash-restart case (§11.4).

### 6.2 `NetConfig` and the two datapaths

```rust
pub enum NetConfig {
    Privileged   { egress: Egress },                                  // netns + tap + /30 (CAP_NET_ADMIN)
    Unprivileged { egress: Egress, host_services_port: Option<u16> }, // in-process smoltcp NAT (no caps)
    None,
}
pub enum Egress { Filtered(ProxyConfig), Blocked, Open }
```

`host_services_port` lives **only on the `Unprivileged` variant** — the smoltcp NAT must know *which* host
port to register as a permanent forward-port, and it is the only datapath that implements the feature, so
the invalid state (a privileged config carrying the field) is unrepresentable. (It was previously a field
on both variants, rejected at `build()` on the privileged one, itself a fail-loud replacement for a prior
silent no-op; §18, delta 4, moves the field so the compiler enforces what the validator did. Wiring host
services on the privileged path — a new TPROXY accept rule plus a host binding — remains forward work,
§17, and would re-add the field there.)

`Egress::Open` — the default — selects "**no interception proxy**"; it is *not* arbitrary outbound egress.
Connectivity under `Open` is only what the mode's datapath natively provides: the unprivileged NAT reaches
the registered `host_services_port`/proxy forwards, and the privileged path reaches only what its TPROXY
ruleset admits — dialing a frame's real destination / host masquerade is not implemented in either mode
(closing the gap, by real re-origination or a typed `Unsupported`, is recorded in §17). `Open` stays the
default because the mmdebstrap builder and the lifecycle/host-endpoint tests rely on it, and none of them
needs arbitrary egress.

**Privileged (`tap`).** A per-VM network namespace, a tap, and a `/30` on `10.200.<n>.0/30` (host `.1`,
guest `.2`), where the third octet is `n = (vmid % 254) + 1` (§9.3), via `rtnetlink`. Full L2 fidelity;
the default for fidelity-sensitive tests and the only network path eligible for the snapshot tier. The
`/30` math is a pure function and unit-tested; the netlink calls and the `nft` invocation are the
side-effecting part, behind injectable `Netlink` / `NftApplier` seams (§9.8).

**Unprivileged (`userspace`).** An in-process **smoltcp** TCP/IP stack behind a `vhost-user-backend`
vhost-user-net device — no tap, no `CAP_NET_ADMIN`. Lower-fidelity (a userspace stack), reserved for
deployability rather than fidelity-sensitive tests, and it cannot be snapshotted (vhost-user-net, law S1).
`passt` was the first choice for unprivileged networking but is out: smoltcp is in-process, with no
external dependency and no LSM/seccomp entanglement, so it is the better design regardless (Appendix B,
Exp 5; the earlier "passt is CH-incompatible via seccomp" reason was wrong — it was a host AppArmor
af_unix rule, not passt's seccomp, and not CH-specific).

**The NAT's five silent-wedge invariants.** The NAT works only if five invariants hold, and each one
wedges the link — or corrupts a stream — *silently* (no error, just a dead connection or dropped bytes) if
violated:

1. smoltcp drops a broadcast frame whose *source* MAC equals the interface MAC, so the host NAT MAC must
   not collide with the guest's vmid-derived MAC — pin it **outside the range `mac_math(1..=254)` can
   emit** (backed by a unit test asserting no collision).
2. Iterate the virtio RX descriptor chain **only when the NAT actually has packets queued** — iterating
   `vring.iter()` consumes/advances `avail_idx`, so polling it while empty discards the guest's RX
   buffers.
3. Call `enable_notification()` on the TX queue inside the `handle_event` loop so the guest kicks the
   eventfd for the next packet.
4. Size the socket pool for concurrent *and* keep-alive connections (≈16 sockets per forwarded port), not
   one-per-port — a single `TcpSocket` per port means an HTTP keep-alive connection holds the only slot.
5. Bound every host-stream read to the smoltcp socket's free TX capacity
   (`host_read_budget(send_capacity, send_queue, buf.len())`) so `send_slice` enqueues the *whole* read —
   `send_slice` enqueues only down to zero free buffer and `can_send()` is true with one free byte, so an
   unbounded 8 KiB read's unsent tail was silently **dropped**, corrupting any host→guest TCP stream large
   enough to fill the guest receive window (pinned by the window-filling data-plane test
   `tests/nat_window_fill.rs` — a >64 KiB host→guest transfer with a digest compare — which reddens on
   the old unbounded read).

### 6.3 Host-served endpoints

A host test server is reachable from the guest and not exposed to other systems — by a different mechanism
per mode: on the privileged tap path the guest dials the per-VM gateway address (`10.200.<n>.1`) directly,
while on the unprivileged NAT the server's port is registered up front via `host_services_port` as a
permanent forward-port. Per-test server config and dynamically-assigned ports are configured *after* the
server is listening. Arbitrary TCP/UDP works; vsock is available as an alternate, IP-stack-free host↔guest
channel.

### 6.4 The transparent egress proxy

A `hyper`-based MITM proxy (`hudsucker` supplies the whole MITM stack — `hyper`+`rustls`+`rcgen`). For
HTTP it splices/logs; for HTTPS it terminates TLS with an on-the-fly cert minted by an in-memory CA
(`rcgen`) and re-originates upstream. The CA is baked into the guest trust store at rootfs build time, so
HTTPS interception works in both networking modes.

**CA lifetime — a recorded deviation from per-run CA hygiene.** The CA is minted once **per artifacts
dir** (default `target/vmcell-artifacts`) and cached: because the CA is baked into the *cached* rootfs, a
per-run CA would invalidate the guest trust chain on every run. A process-global cache keyed by artifacts
dir returns the generate-once CA and its parsed authority (re-self-signing per `authority()` call would
break the chain).

Test doubles let a caller register `(Matcher, Responder)` pairs (and, for the eval layer, a `record_to`
cassette that logs each **forwarded** request's method+URI, one line per request — request-line logging
only: it captures neither responses nor blocked requests, so snapshot-and-replay cassettes remain §17
forward work). HTTPS doubles must **ignore `hyper::Method::CONNECT`** — matching on the `CONNECT` itself
breaks the tunnel and yields a TLS "unexpected eof." The host-side interface:

```rust
impl EgressProxy {
    pub async fn start(cfg: ProxyConfig) -> Result<Self>;             // listen, log, filter, dispatch
    pub async fn start_transparent(cfg: ProxyConfig) -> Result<Self>; // IP_TRANSPARENT front-end (privileged)
    pub fn ca_cert_pem(&self) -> &[u8];                               // baked into the rootfs trust store
    pub fn requests(&self) -> RequestLog;                             // observed requests, for assertions
    pub fn install_double(&self, matcher: Matcher, responder: Responder); // register a test double
    pub fn record_to(&self, cassette: &Path);                         // request-line logging (replay is §17 forward work)
}
```

`MicroVm::proxy() -> Option<&EgressProxy>` hands the running proxy to the caller so it can read the
request log, register a double, or obtain the CA cert.

The proxy *process* is mode-independent; how traffic is *steered into it* is not:

- **Privileged:** an nftables **`TPROXY`** ruleset, rendered in Rust and applied via the external
  `nft -f -` binary (no permissive pure-Rust nftables crate covers the `tproxy`/`socket` expressions,
  §9.6). TPROXY carries the original destination *in the socket* (no conntrack lookup) and preserves the
  source. The ruleset **drops udp/443 (QUIC)** rather than intercepting it — a deliberate choice that
  forces clients onto HTTP/2-over-TCP so all egress stays observable through the proxy (a pure QUIC
  datapath would be opaque).
- **Unprivileged:** egress interception at **L4 inside the smoltcp NAT** — cleaner than a privileged
  front-end, since there is no tap for nftables.

**A documented limitation of the privileged path.** Full MITM interception (terminating TLS and
reconstructing absolute-form requests) is implemented for the **explicit-proxy** path — a guest that sets
`http_proxy=<gateway>:<proxy_port>` is fully MITM'd, logged, filtered, and served by doubles. The
**transparent** redirect of a *raw* 80/443 connection currently only **constrains** egress (it can drop or
block, and it observes the intended destination), not reconstruct and re-originate the request. Tests that
need full MITM point the guest at the explicit proxy; the transparent path's contract is "observe/filter
the destination," which is what the assertions check.

Standing up the privileged transparent path required four host-side fixes worth knowing. Three live in
`net::tap`: the FIB policy rule needs an explicit `AF_INET` (an `AF_UNSPEC` rule returns `EAFNOSUPPORT`);
the local route needs `RT_SCOPE_HOST` (not `RT_SCOPE_LINK`, which returns `EINVAL`); and the ruleset must
`accept iifname <tap> ip daddr <gateway> tcp dport <proxy_port>`. The fourth lives in the proxy itself:
the privileged Filtered proxy's runtime thread `setns()`s into the per-VM netns to bind its listener (so
TPROXY-redirected guest connections are deliverable), having first captured `/proc/thread-self/ns/net`,
and **re-enters the host root netns** after binding — a socket's netns is fixed at `socket()` time, so the
bound listener keeps receiving from the VM netns while every newly created upstream/DNS socket originates
in the root netns and reaches real networks. Without the re-entry the upstream leg was trapped in the
tap-`/30`-only netns and privileged Filtered egress could only ever serve doubles; a re-entry failure
aborts proxy startup loud. (The integration test proves in-path interception via a registered double — a
real-external-upstream assertion needs internet in CI.)

---

## 7. Resource monitoring and limits

### 7.1 What is read and enforced

One **cgroup v2 slice per VM**, with `ResourceLimits` applied and counters read back through the injected
`CgroupFs` seam:

```rust
pub struct ResourceUsage {
    pub mem_peak_mib: u64,  pub mem_current_mib: u64,
    pub cpu_usec: u64,      pub io_read_bytes: u64,  pub io_write_bytes: u64,
    pub mem_limit_enforced: bool,                            // the MEMORY controller is delegated (below)
    pub mem_read_ok: bool,  pub cpu_read_ok: bool,  pub io_read_ok: bool, // per-metric availability
}
pub struct ResourceLimits {   // None => unlimited; maps to cgroup v2 keys
    pub mem_max_mib: Option<u32>,  // memory.max     pub cpu_max_pct: Option<u32>, // cpu.max
    pub pids_max:    Option<u32>,  // pids.max       pub io_max:      Option<IoMax>, // io.max
}
```

Peak comes for free from `memory.peak`; average is computed from periodic `cpu.stat`/`io.stat` deltas.
Each read carries an explicit availability boolean rather than silently reporting zero — an unread counter
reported as `0` is the same lie as a missing one.

`mem_limit_enforced` (renamed from `limits_enforced` in this revision — §18, delta 3 — because the old
name over-claimed) has a precise, deliberately narrow meaning: it is `true` only when the **memory**
controller is delegated into the VM's cgroup (`cgroup.controllers` lists it) — the one controller whose
silent absence lets the memory cap not fire. The read path holds only the cgroup name, so this is *not* a
per-controller (cpu/pids/io) enforcement guarantee; a caller that needs one consults the individual
control files.

**There are no network byte counters in `ResourceUsage`.** cgroup v2 exposes no per-cgroup network
accounting (there is no `net.stat`), and the read path holds only the cgroup name, not the VM's netns or
interface — so synthesizing `net_rx_bytes`/`net_tx_bytes` fields would be exactly the always-zero lie
above. Per-VM egress bytes belong in a future *network*-scoped usage type that reads
`/sys/class/net/<if>/statistics` inside the VM netns; forward work (§17).

### 7.2 The fail-loud capability contract and `HostCapabilities`

An earlier stance — "unprivileged delegation degrades gracefully" — was in practice an invitation to
**silent no-ops**: a caller asks for a 256 MiB cap, the controller isn't delegated, the write fails, and
the VM runs *unlimited* while the call returns `Ok`. The rule is reversed: **a missing capability fails
loud unless the operation is explicitly classified as best-effort** (law F1). Three sub-rules make this
precise and uniform (they also govern netns/tap in §6.1 and the sysfs knobs in §16):

1. **Every host-facing op declares the OS capabilities it needs** — in its doc-comment and in the
   queryable **`HostCapabilities`** descriptor: one struct probed once at start-up (by mode selection, the
   daemon's main, and the test harness) recording what the host actually offers — the effective capability
   set, KVM-group access, `/var/run/netns` reachability, which cgroup controllers the current scope
   delegates, and whether the scope is a non-threaded `domain` leaf. As built, the descriptor is
   **probed once at start-up and logged** (mode selection + the daemon's `MicroVmLauncher::new`); per-op
   enforcement keeps its own authoritative fail-loud per-write check (e.g. `metrics::try_apply_limit_at` /
   `classify_limit_write_err`), so the descriptor is the queryable single source, not a replacement for
   that per-write typed error. (Directed by this revision — §18, delta 8; see implementation-notes.md,
   Delta 8, for the as-built reconciliation.)
2. **A *requested functional* op that needs an absent capability returns a typed error, not `Ok`.** Asking
   for a resource limit that cannot be enforced is `Err(Error::CapabilityUnavailable { op, needed })` —
   matchable, carrying the exact missing capability — surfaced before the VM is handed back. The typed
   error also distinguishes *why* a limit write failed: the kernel refusing the **value** (`EINVAL`, e.g.
   an `io.max` the device rejects) is `Error::Cgroup`, so the caller is not sent chasing delegation, while
   a capability/permission errno (`EACCES`/`EPERM`/`EROFS`) is `CapabilityUnavailable`; the errno split is
   a pure function unit-tested against both inverses.
3. **Observation degrades; enforcement does not.** *Reads* fall back (read
   `memory.current`/`memory.peak` straight from sysfs when a higher-level interface is absent) and surface
   what was unavailable through the `*_read_ok` / `mem_limit_enforced` booleans. A limit the caller *set*
   is functional (rule 2); a counter the caller *read* is observational (this rule).

A narrow, **explicitly-listed** best-effort tier remains for genuinely non-functional knobs — the §16
benchmark levers (CPU-frequency pinning, KSM) — which degrade to a visible `warn!` rather than aborting a
run, since benchmarks are tracked metrics, not gates. The dividing line: *if a caller's assertion can be
wrong because the op silently did nothing, it is functional and must fail loud; if the only consequence is
a less-controlled measurement, it is best-effort and warns.*

### 7.3 cgroup delegation mechanics

Limit enforcement runs into cgroup-v2 delegation edges that compound. The cgroup side effects sit behind
the injected **`CgroupFs`** trait (`create_slice`/`delete_slice`/`read_stats`/`add_task`) with a real impl
and a recording fake, so sibling-placement, the controller-enable sequence, and the limit-file contents
are unit-testable with no `/sys` writes. The edges:

- Create the slice directly with `mkdir` + direct sysfs writes — never `cgroups-rs`'s builder, which
  leaves the cgroup rejecting `cgroup.procs`.
- Place the VM cgroup as a **sibling** of the harness, not a child (the "no internal processes" rule; the
  orchestrator strips a `/supervisor` suffix).
- Write the PID directly to `cgroup.procs`.
- Run from a **non-threaded `domain`** scope — a threaded scope rejects `cgroup.procs` regardless of
  `CAP_SYS_ADMIN`.
- Controller delegation is the gating capability: an undelegated controller makes a *requested* limit fail
  loud (§7.2) while *reads* fall back to sysfs.
- `memory.max` alone does **not** bind a CH guest's RAM: CH backs guest memory with a shared memfd, which
  the kernel reclaims rather than host-OOM-caps, so a 512 MiB guest under a 256 MiB `memory.max` self-OOMs
  *inside* the guest with the cgroup's `memory.events oom_kill` still `0`. To make the cap bind and
  produce a real cgroup OOM, `create_slice` also writes **`memory.swap.max=0`** and
  **`memory.oom.group=1`**.

---
## 8. Snapshot, restore, and cloning

**Vocabulary, once.** A **snapshot directory** (or *suspend image*) is the unit everything in this section
manipulates: the guest-RAM memory file plus the backend's `config.json`/sidecar, written by
`snapshot()` from a paused VM. A **zygote master** and a **lineage node** are *roles* a snapshot directory
plays — an immutable image that clones restore from. A **vhost-user device** is a device whose backend
runs as a *separate helper process* (virtiofsd, the smoltcp NAT's vhost-user-net, an external vsock
daemon) talking to the VMM over a Unix socket; because that helper holds device state the VMM cannot
migrate, attaching one makes the VM unsnapshottable — the eligibility law (S1) every snapshot finding in
the project's history collapses into.

### 8.1 The warm-snapshot path and the eligibility law

The per-run speed lever is **warm snapshot + restore**: boot the erofs-rootfs base to agent-ready,
snapshot once, and per-run restore + add a tmpfs overlay. This skips kernel boot on the hot path — ≈5.4×
faster than cold boot on CH (316→58 ms p50); on Firecracker warm restore is faster still (764→24 ms, ≈32×
its own cold boot) (§16). The erofs RO base needs no per-run copy; the only writable per-run state is the
tmpfs overlay. The on-disk size of a suspend image **tracks guest RAM exactly** and is flat in rootfs size
(a 256 MiB-RAM guest writes an ≈256 MiB memory file whether the rootfs is slim or fat).

**The eligibility law (S1): a VM is snapshot-eligible only if no vhost-user device is attached to it.**
The consequence: the snapshot tier runs the **privileged/tap network path with a non-vhost-user vsock
transport and no virtio-fs data shares**. Anything requiring a vhost-user device — the unprivileged NAT
**or virtio-fs *data* shares, not only a virtio-fs rootfs** — is mutually exclusive with snapshot on the
same VM. (CH's base control-plane vsock and Firecracker's built-in vsock are safe because they are the
VMM's *own* implementation, not vhost-user; plain virtio-blk devices compose with snapshot, §4.6.) The
subtle point: **"attached" means *any* virtiofsd.** A read-only data share is still a vhost-user device;
there is no "small enough to be safe" exception — the rule is over the device class, not the share's role
or access mode. (An earlier pass guarded a virtio-fs rootfs + snapshot but let a data `Share` through to
the backend, which then attached virtiofsd to a VM it was about to snapshot.)

The law is enforced **in code at three boundaries**, so no single missed check can let a vhost-user device
onto a snapshot-eligible VM:

1. **`config::build()`** rejects `snapshotting == true` combined with **any** virtio-fs data `Share` or
   `NetConfig::Unprivileged` — a typed validation `Err`, with a negative test per case.
2. **`orchestrator::restore()`** re-checks the same predicate against the `cfg` it is handed (defense in
   depth) and returns `Error::Unsupported`.
3. **Backend `restore()`/`snapshot()`** self-guard on `capabilities().snapshot_restore` *and* the absence
   of any vhost-user device via the single shared `pub(crate)` predicate
   `config_has_vhost_user_device(cfg, res)` — returning `Error::Unsupported { vmm, feature }`, never a
   panic, never a stringly error. The former per-backend copies had already diverged (the Firecracker copy
   never grew a term the CH copy carried); centralizing on one predicate — pinned by a shared-predicate
   unit test — makes that divergence class impossible.

The mechanics: snapshot = `pause` → snapshot → (`resume`, or stay paused for immediate kill); restore
returns a **paused** instance the caller `resume()`s — never `boot()`/`create()`. The in-place
`config.json`/sidecar path rewrites (§2.2) make a plain `restore()` **single-use** — it mutates the
caller's snapshot dir, so it is for *one* VM. Minting *many* identical VMs from one suspend image is the
zygote fan-out (§8.4).

### 8.2 Restore correctness: a restored VM is not a fresh VM

A restored snapshot resumes at the exact instruction it was taken, so restored clones share whatever state
was frozen in. Four things must be refreshed on **every** restore (law S2), fired once on the first
post-restore `agent()` call after the vsock reconnect succeeds — as a **single native `Resync`
round-trip** (§3.1), applied in-agent by syscalls/ioctls with **no subprocess spawn** (this replaced three
`exec`s — `date`, `sh`+`head`, and the multi-MB `ip` binary — removing them from the restore hot path):

- **Identity (CID) — uniqueness among *live* clones, not a forced numeric change.** The vsock CID must be
  unique across *concurrently running* restored clones. It is **not** required to differ from a torn-down
  original: the `CidAllocator` hands out the lowest free CID and reuses freed CIDs by design. So the
  correct check on a *sequential* restore is "the restored guest has a valid, live CID," **not**
  `assert_ne!(original_cid, restored_cid)` (which fails precisely *because* reuse is correct). On CH the
  restored guest keeps the baked CID from the restore config (§2.2); the orchestrator's fresh allocation
  still reserves host-side uniqueness but is not the guest's identity.
- **Identity (MAC *and* IP) — rotated at the device layer, "rotate everything".** A snapshot is a zygote:
  one suspended VM is resumed into many *concurrent* children, each of which must have a distinct network
  identity (its own netns/tap/`/30`/MAC/IP) so they never collide on the host. The restore path therefore
  rotates the vmid, and the guest must move its whole network identity to match: the MAC via
  `SIOCSIFHWADDR`, and the IP + default route via `SIOCSIFADDR`/`SIOCSIFNETMASK`/`SIOCADDRT` — all applied
  **natively in the agent** (`netif`) as device-layer writes, consistent with zero-netlink-in-PID-1
  (law C6). The host side rewrites the baked `net[].tap` to the rotated tap in the CH restore config
  (§2.2), so the guest's rotated `/30` and its host-side tap/nft wiring belong to the same vmid. The guest
  resumes with the frozen `ip=` of the *original* vmid; an earlier "leave the IP alone" stance left every
  restored clone on a dead `/30` with silently dead egress. Both are best-effort; the ack reports
  `mac_applied` / `ip_applied`.
- **Entropy** — reseed the CSPRNG by copying 32 bytes `/dev/hwrng`→`/dev/urandom` natively in-agent. An
  unreseeded `getrandom()` can stall first use by seconds, and because every clone resumes at the same
  frozen instant, RNG reuse is otherwise silent and correlated. Best-effort; the ack's `reseed_applied`
  records whether it took (which is why FC `create()` attaches virtio-rng, §2.3).
- **Clock** — a snapshot resumed much later resumes with a stale wall clock. The guest cannot fix this
  from inside (`hwclock --hctosys` reads the *restored* RTC — the old snapshot time — and sets the clock
  *backwards*; a restored snapshot may have no network for NTP). The resync is therefore **host-driven and
  mandatory**: the host reads its clock (through the injected `Clock` seam) and pushes it in the `Resync`
  message; the agent applies it via `clock_settime`. A guest-side clock-set failure comes back as
  `ResyncAck.clock_error` and propagates as a typed `Err` **before** the `restored` flag is cleared, so
  the next `agent()` retries — and a failed resync **also evicts the cached `AgentClient`**: a transport
  failure marks the client desynced and nothing auto-reconnects it, so leaving it cached would wedge every
  future `agent()` call; eviction makes the next call re-connect and retry the whole resync. For ephemeral
  tests a stale clock is cosmetic; for anything asserting on timestamps it is not — so a resync failure
  surfaces.

**The post-restore vsock reconnect itself is mandatory and was the hardest restore bug to close.** It is
not a no-op: CH `--restore` re-creates the vhost-vsock device, leaving the guest's pre-snapshot bound
listener deaf — so the guest agent serves connections thread-per-connection and **re-`bind`s** after a
bounded idle for the host's `reconnect` to land (§3.4). This same generic re-bind is exactly what cured
Firecracker's warm restore — no FC-specific guest fix was needed; the FC-side work was purely host-side
(§2.3; Appendix A, reversal 8).

### 8.3 Density levers

RAM is the binding limit on parallelism. With DAX unavailable in CH (Appendix C), density rests on:

- **`cache=never`** on virtio-fs shares (minimal footprint).
- **The shared erofs RO base** — one host-cached copy of the image for all concurrent guests (§4.1).
- **virtio-balloon / free-page-reporting** for reclaim under host pressure.
- **KSM — opt-in, and a no-op by default on CH.** CH backs guest RAM with a shared memfd (`shared=on` →
  it lands in `RssShmem`), and KSM only merges private-anonymous pages, so global KSM deduplicates **0**
  of default-config guest RAM. The lever is an explicit `VmConfig::ksm_mergeable` that sets CH's
  `mergeable=on` **and** `shared=off` together (the coupling is mandatory). Measured, it then deduplicates
  ≈394 MiB / ~84% across 8 identical 256 MiB guests — but `shared=off` is mutually exclusive with every
  vhost-user path (the NAT, virtio-fs shares), plus KSM scan CPU, so it stays **off by default** and
  `config::build()` rejects it combined with a vhost-user device.

**Measured footprint (§16):** each CH guest demand-pages ≈58 MiB of its 256 MiB, marginal RAM per added
guest is dead-linear at ≈58 MiB, and the agent PID 1 is ≈2.4 MiB. So the RAM-tier ceiling on the 30 GiB
benchmark substrate is ≈13 GiB free / 58 MiB ≈ **~230 idle guests** (≈52 if each faults its full 256 MiB
under load). The next limits after RAM are one-virtiofsd-per-VM, tap/netns/nft scaling, and host FD/PID
limits.

### 8.4 The zygote fan-out and the `OverlayStore` seam

Booting the guest kernel to agent-ready is the dominant per-VM cost. When a workload needs *many*
identical VMs — a warm serverless pool, a fan-out of agent sandboxes, a batch of test cells — the
**zygote** pattern pays that cost once and clones the *suspended* result:

1. **Suspend once.** Boot one VM to agent-ready and snapshot it while paused. That frozen image is the
   **zygote master** (`Zygote::suspend`); it is the same snapshot the warm tier already produces — the
   pipeline's `SnapshotStage` output *is* a zygote master (§10.1).
2. **Copy-on-write per clone, through the injected `OverlayStore` seam.** To mint a clone, CoW-copy the
   whole suspend dir into the clone's own scratch dir, then `restore()` + `resume()` from that private
   copy. The copy is materialized through `overlay::OverlayStore::clone_tree(master, private_dst)` — the
   production `ReflinkOverlayStore` wraps the `reflink.rs` primitive, so on a reflink-capable host
   filesystem (XFS, Btrfs, bcachefs) the copy is a near-instant block-level `FICLONE` that shares physical
   storage with the master until a clone writes, and on any other filesystem (ext4, tmpfs) it degrades to
   a full byte copy — correct, just not free. The copy is reported as `CowSupport::{Reflink, FullCopy}` so
   a caller building a large pool on a non-reflink filesystem can warn or pick a different scratch dir.
   The vetted `reflink-copy` crate owns the ioctl and the fallback, so no new `unsafe` enters the tree.
3. **Fresh identity per clone.** Each clone allocates a fresh vmid from the shared `VmidAllocator` (hence
   a distinct `/30`/MAC/IP), its own netns/cgroup/vsock socket, and runs the mandatory post-restore resync
   on its first `agent()` call (§8.2). So N clones resumed from one frozen instant never collide on the
   host.

**Why the per-clone copy is load-bearing, not an optimization (law S3).** The single-use restore path
rewrites the snapshot's `config.json` *in place* (§2.2). Two restores from one shared dir race on that
file and corrupt it. Restoring from a **private copy** removes the race *and* keeps the zygote master
byte-for-byte immutable, so the master can be cloned again, indefinitely — the property that makes it a
*zygote* and not a one-shot snapshot. Two consequences: the integration test asserts the master's
`config.json` is byte-identical after a fan-out, and the CoW copy lives *inside* the per-VM scratch dir,
so the existing ordered teardown (law L1) reclaims it — no separate cleanup path to forget, no shared
inode two clones could race on. Enforced by construction: `restore_cow`/`Zygote` do the copy in the
orchestrator **before** calling the backend, so no code path can restore a clone directly from the master.

**The `OverlayStore` seam (law S4).** Every other host-mutating edge in vmcell is an injectable trait with
a production impl and a recording double (`Netlink`/`NftApplier`/`CgroupFs`/`OrphanScanner`); the
clone-materialization step was a bare free function until it was lifted behind the seam:

```rust
// vmcell::overlay
pub trait OverlayStore: Send + Sync + std::fmt::Debug {
    /// CoW-clones the snapshot directory `src` into a fresh private copy at `dst`.
    /// `dst` must not exist. The copy is a faithful, INDEPENDENT copy: writing it never
    /// touches `src` (the master — the S3 immutability contract). Reports whether it was
    /// a block-level reflink or a full byte copy.
    fn clone_tree(&self, src: &Path, dst: &Path) -> Result<CowSupport>;
    /// Side-effect-free probe of whether `dir`'s filesystem gives cheap block-level CoW,
    /// for an up-front cost signal before minting a pool.
    fn probe(&self, dir: &Path) -> CowSupport;
}
#[derive(Clone, Copy, Debug, Default)]
pub struct ReflinkOverlayStore;   // production: FICLONE where supported, full byte copy otherwise
// RecordingOverlayStore (test double) records every (src, dst) and returns a configurable CowSupport.
```

**Scope:** the seam clones the *suspend directory*, not a rootfs disk. In the snapshot-eligible model the
rootfs is the shared erofs RO base plus a fresh in-guest tmpfs overlay — there is no host-side writable
rootfs upper to copy; the only per-clone writable host state is the suspend directory. So `OverlayStore`
is scoped precisely to CoW-cloning that directory; it deliberately does not reach into per-backend
block-device attachment (which would import vhost-user and qcow2-backing-chain complexity a
snapshot-eligible VM does not have). **Injection:** the trait is `Send + Sync + Debug` with synchronous
methods (object-safe as `Arc<dyn OverlayStore>`), and the orchestrator runs `clone_tree` on a blocking
thread (`spawn_blocking`) so a large full-copy never stalls the async runtime. The store used by every CoW
restore is the one in the `HostEnv` handed to the spawn call (§9.3) — one source per process, injectable
in tests, defaulting to `ReflinkOverlayStore`.

**The concurrent-fan-out gate is a capability, not a flag.** CoW gives each clone its own *files*, but it
cannot change a path a backend bakes into the binary snapshot state. CH rewrites every host path per
restore into the clone's own scratch dir (`restore_rotates_host_paths: true`), so N concurrent CH clones
each get a distinct vsock/serial/tap — fan-out works. Firecracker re-binds the baked vsock UDS verbatim
(`false`), so two concurrent FC clones would fight over one socket path — and copying the dir does not
change the baked path. So `Zygote::spawn_clones(n)` **refuses `n > 1` on a non-rotating backend with a
typed `Error::Unsupported`** rather than letting the clones collide; a *single* FC clone (sequential
lineage) is fine. This reuses the exact capability the warm tier already declares — a bespoke fan-out
boolean would be a second source of truth for the same fact, free to drift.

**Cost model.** A `FullCopy` pool costs N×guest-RAM of disk and copy bandwidth (the ext4 case); a
`Reflink` pool costs ≈N×*dirtied* pages, near-zero at rest, because CH maps the memory file read-mostly
and only the tiny per-clone `config.json` diverges. RAM is unchanged from §8.3 (each clone still
demand-faults its own ≈58 MiB); the zygote win is wall-clock and disk, not RAM. `spawn_clones` mints the
pool **concurrently** and is **all-or-nothing**: if any clone fails, the ones already up are torn down in
the documented order and the first error is returned — no half-built pool leaks. Measured on CH: a live
pool of 3 concurrent clones from one zygote, each with a distinct vmid/MAC/vsock and a working `exec`,
with the master `config.json` byte-identical afterward.

### 8.5 Lineage: fork and branch

The fan-out above is *flat*: one immutable master, many independent clones, no recorded parent→child
relationship, and no first-class way to freeze a clone that has diverged (run some work) into a *new* fork
point. The **`Lineage`** handle adds a tree of provenance on top of `Zygote` without a second copy of the
clone logic:

```rust
// vmcell::lineage
pub struct LineageId(u64);                          // Copy/Ord/Hash; monotonic per allocator
pub struct LineageAllocator(/* Arc<AtomicU64> */);  // Clone; one shared allocator gives globally distinct ids
pub struct Lineage { /* id, parent, generation, ancestry: Arc<[LineageId]>, allocator, wrapped Zygote */ }

impl Lineage {
    /// Roots a lineage by suspending a live, agent-ready VM into `dir` (generation 0, no parent).
    /// `dir` is created if absent.
    pub async fn fork_from_vm<V: Vmm>(vm: &mut MicroVm<V>, cfg: VmConfig, dir: impl Into<PathBuf>,
        allocator: LineageAllocator) -> Result<Self>;
    /// Adopts an existing snapshot dir (e.g. a SnapshotStage artifact) as a root node.
    pub async fn from_snapshot_dir(dir: impl Into<PathBuf>, cfg: VmConfig, allocator: LineageAllocator) -> Result<Self>;

    pub fn id(&self) -> LineageId;
    pub fn parent(&self) -> Option<LineageId>;          // None at the root (generation 0)
    pub fn generation(&self) -> u32;                    // strictly increases along a branch chain
    pub fn ancestry(&self) -> &[LineageId];             // root .. parent inclusive (this node excluded)
    pub fn is_ancestor_of(&self, other: &Lineage) -> bool;
    pub fn master_dir(&self) -> &Path;

    /// fork(): mint ONE live child VM — a CoW clone at this node (delegates to Zygote::spawn_clone).
    pub async fn fork<V: Vmm>(&self, vmm: &V, env: &HostEnv) -> Result<MicroVm<V>>;
    /// Concurrent fan-out at this node (delegates to Zygote::spawn_clones; the §8.4 gate applies unchanged).
    pub async fn fork_many<V: Vmm>(&self, vmm: &V, count: usize, env: &HostEnv) -> Result<Vec<MicroVm<V>>>;
    /// branch(): freeze a RUNNING descendant `child` into a NEW node whose parent is this node
    /// (generation + 1, ancestry extended by this node's id). Snapshots `child` into `dir` (created if
    /// absent) and returns the new node; `child` stays live and the caller owns `dir`'s lifecycle.
    /// Re-validates snapshot-eligibility (S1) via the same check_clone_eligible predicate.
    pub async fn branch<V: Vmm>(&self, child: &mut MicroVm<V>, dir: impl Into<PathBuf>) -> Result<Lineage>;
}
```

**The tree, concretely.** `fork_from_vm` → node `root` (gen 0). `root.fork()` → a live VM; run work in it;
`root.branch(vm, dir_b1)` → node `b1` (gen 1, parent `root`, ancestry `[root]`). `b1.fork()` → a live VM;
`b1.branch(vm, dir_b2)` → node `b2` (gen 2, parent `b1`, ancestry `[root, b1]`). Each node is a complete
zygote that can be forked, concurrently and repeatedly, independent of the others — the snapshots are
immutable (S3 extends to branch nodes), so the tree is safe to fan out from any node.

**Why `Lineage` is a handle and not a field on `MicroVm`.** The lineage relationship is caller-visible
provenance, not per-VM runtime state; threading it as a value keeps it out of the 300-line `MicroVm`
struct and its nine construction sites (each an opportunity to forget a field). A `Lineage` is cheap to
clone (`Arc`-backed ancestry), so a caller holds the handles it cares about and asks each to
`fork`/`branch`. `branch(child, dir)` takes the running descendant explicitly — *you* say where the branch
diverges from, the git-branch mental model.

**Identity and eligibility reuse — no new laws.** Every forked child is a `Zygote` clone, so it draws a
fresh vmid (hence a distinct `/30`/MAC/IP) and runs the mandatory post-restore resync; two children of the
same node — or of two different nodes — never collide, exactly as fan-out siblings do not. `branch` and
`fork_from_vm` re-check snapshot-eligibility through the same `check_clone_eligible` predicate the zygote
uses — a typed `Error::Unsupported` at construction, before any snapshot or copy is minted. `fork_many`
*is* `spawn_clones`, so the concurrent-fan-out gate is the same single source of truth; a **sequential**
lineage chain (fork one, branch it, fork one, …) works on every backend, which is precisely the
single-lineage shape Firecracker supports. Lineage identity is **cross-family-safe**: `is_ancestor_of`
first checks the two nodes share a `LineageAllocator` (`Arc::ptr_eq`), then that `self.id` is in `other`'s
ancestry — so two nodes minted by distinct allocators are never a false-positive ancestry even when their
ids collide (each allocator starts at `L1`) (law S5).

### 8.6 One snapshot per node, not a backing chain

A branch is a **flat, self-contained single snapshot**, and copy-on-write happens at the
**host-filesystem** layer (reflink of that one directory), *not* as a qcow2/overlayfs backing chain. This
is deliberate and load-bearing:

- **Restore stays O(1) in lineage depth.** If `branch` layered a new overlay over its parent's image, a
  depth-`k` restore would have to assemble `k` backing layers and the backend would have to walk them —
  fragile across CH/FC snapshot formats, and a correctness hazard (a restored VM resumes at an exact
  instruction; a mis-assembled backing chain is silent corruption). Instead, `branch` writes a **complete**
  new suspend image from the diverged guest (the memory file tracks guest RAM exactly, independent of
  depth), and `fork` reflink-copies that one directory. Depth costs disk (one guest-RAM image per branch
  node the caller keeps), never restore complexity.
- **Backend-agnostic.** Every node is exactly the kind of directory the warm tier and `Zygote` already
  restore; no backend learns about lineage. The fan-out gate and the eligibility law apply per node
  unchanged.

The reflink CoW between a node and its live children is where sharing pays off: a pool forked from one
node costs ≈N×dirtied pages on a reflink filesystem; the lineage adds a *second* axis (depth) whose cost
is one full image per retained branch point, reported honestly, never hidden behind a chain. (A store that
reflinks a new branch image's unchanged pages against its parent's at snapshot time is an `OverlayStore`
refinement, §17, not a restore-path change.)

---
## 9. The Rust library (`vmcell`)

### 9.1 Workspace layout

A cargo **workspace** (2024 edition); the root is a pure `[workspace]`. Members version independently and
every public-surface change is `cargo semver-checks`-gated; current versions live in the members'
`Cargo.toml`s (the delta register's breaking pass bumps `vmcell` 0.9 → 0.10, §18). The members:

- **`vmcell`** — the library (plus the `bench-vm` harness), one package carrying the host feature stack
  (§9.7). It keeps the bootstrap artifact producers (the OCI rootfs source, the host-`make` and prebuilt
  kernel producers) and exposes the shared utilities the extracted builders reuse.
- **`vmcell-rootfs-builder`** — the extracted full-apt in-VM `mmdebstrap` rootfs source (§4.2). A `Stage`
  impl that depends on `vmcell`, boots a builder micro-VM, and emits the erofs through the shared
  `pack_erofs_with_injection`.
- **`vmcell-kernel-builder`** — the extracted in-VM download+configure+compile kernel builder (§5.1).
- **`vmcell-cli`** — the **composition-root** crate carrying the CLI (`build`, `build-kernels`,
  `oci2erofs`, the lifecycle verbs, `bundle`). It depends on `vmcell` + both builder crates and assembles
  the `Pipeline`, choosing sources via `--rootfs-source oci|mmdebstrap` / `--kernel-source
  prebuilt|host-make|in-vm`.
- **`vmcell-protocol`** — the framed postcard wire enum and the `ExecRequest`/`ExecOutcome` types; the
  *only* code the host and the guest agent share.
- **`vmcell-guest-agent`** — the guest PID-1 binary (plus the `ReaperCoordinator` library). Lean:
  `rustix`/`signal-hook`/`vsock`/`libc`/`tracing`, no host async stack.
- **`vmcell-test-runner`** — the privileged-test capability runner (§15.5). Lean: `rustix`/`capctl`/`libc`
  only, never the `vmcell` library.
- **`vmcell-guest-tools`** — the in-rootfs `ip`/`curl`/`kvm-ok` helper (§4.4). A *guest* binary; needs
  `reqwest` for real HTTP, so leaner than the host but not as lean as the agent.
- **`vmcell-privilege`** — a lean library (`rustix`/`capctl`/`libc` only) holding the capability/blessing
  predicates, extracted so the daemon and the runner share **one** copy of security-critical logic
  (§11.2). Subject to the same per-member lean-tree assertion as the runner.
- **`vmcell-daemon`** — the control-plane daemon **library** (§11): the artifact store, the owning VM
  `Registry` over the `VmLauncher`/`VmHandle` seam, the start-up sweep, the axum router + handlers, the
  bearer-auth layer, the OpenAPI document, and the DTOs.
- **`vmcelld`** — the daemon **binary**: a thin blessed wrapper (functionality in the library, binary is
  the wrapper).
- **`vmcell-daemon-client`** — a typed `reqwest` client mirroring the entry points, re-exporting the
  daemon's DTOs (§11.7).
- **`vmcelld-ctl`** — a `clap` wrapper over the client.
- **`vmcell-broker`** — the lean privileged spawn helper + `BrokerClient` (§12.4). It holds the three caps
  on behalf of a cap-dropped `vmcelld` parent, links `vmcell`'s net-privileged/metrics subset +
  `vmcell-privilege` — never the daemon's axum/hyper web stack (its own lean-tree assertion). The
  jailer-equivalent it applies lives in `vmcell::vmm::jail`, not here, so the lean
  `vmcell-privilege`/`vmcell-test-runner` tier (which never spawns a VMM) stays lean.

**Why a workspace:** a member crate's build fingerprint depends only on its own (tiny) source + deps, so
the lean-tree assertion (§9.7) becomes a **structural per-member property** — no host module can leak into
the runner or agent by construction. Extracting `vmcell-protocol` is what lets the agent be a standalone
member without a dependency edge on the whole library.

**The dependency graph is two acyclic stars on `vmcell`, wired by artifact-path passing.** The two builder
crates each depend on `vmcell` and reuse its promoted-`pub` utilities — `pack_erofs_with_injection`,
`resolve_builder_base`, `hash_file`/`hash_output`/`hash_artifacts_sorted`, `ch_binary_path`,
`HttpClient`/`ReqwestClient` — so there is **one** implementation of each, not a per-builder fork (a
divergent erofs packer or hash function across builders is exactly the duplication-hides-divergence trap).
`vmcell` has **no edge back** to either builder, so the graph never cycles; `vmcell-cli` is the
composition root and the *only* crate that names a builder — which is why the CLI had to leave the
`vmcell` package (a CLI inside `vmcell` referencing the builders would force `vmcell → builder → vmcell`).
The daemon members form the second star: the daemon depends on `vmcell` (never the reverse), and the
client links only the daemon's DTOs (§11.1). Builders pass real data through `StageInputs`/`StageOutputs`
(§10.2), never via env vars. The vendored vhost patch (`vendor/vhost`, `vendor/vhost-user-backend`) is
applied via `[patch.crates-io]` path entries at the workspace root (§9.6).

### 9.2 The module map

The `vmcell` library's module tree (`crates/vmcell/src/`), each module's job in one line:

```
lib.rs           # public re-exports; crate lints (deny missing-docs, unwrap, panic, print, indexing under not(test))
error.rs         # the crate Error enum + Result<T>
config.rs        # VmConfig + builder, RootfsSource, NetConfig, Share, ResourceLimits, RestoreMode  (host-common)
env.rs           # HostEnv: the process-wide injected-seam bundle (allocators, cgroups, clock, overlay) (§9.3)
vmm/             # Vmm + VmInstance traits, VmmCapabilities, Cid/Vmid types; cloud_hypervisor/firecracker/qemu; FakeVmm
vmm/seccomp.rs   # vmm_seccomp_args: the ONE (backend, VmmSeccomp)→CLI-flag predicate (§12.2)
vmm/jail.rs      # JailSpec + async-signal-safe apply_jail: the jailer-equivalent, seccompiler deny-list (§12.3)
agent/           # AgentClient (host vsock client, handshake + desync); agent::session multiplexer (§3.2)
fs.rs            # VirtioFsDaemon: one virtiofsd per share, perms, tags, sockets, socket-wait timeout
net/             # NetConfig dispatch: tap (netns + /30 via rtnetlink, nft TPROXY) + userspace (smoltcp NAT)
net_sys.rs       # the ONE unsafe ioctl net/ can't host (TUNSETPERSIST); net/ is #![forbid(unsafe_code)]
proxy/           # EgressProxy (hudsucker MITM), TLS CA + leaf minting, test doubles + record/replay
metrics.rs       # CgroupFs trait (real + recording fake), slice mgmt, peak/avg readers (direct sysfs writes)
cpufreq.rs       # benchmark-only CpuFreqSysfs seam: pin governor/turbo, RAII restore-on-drop
orchestrator.rs  # MicroVm handle; VmidAllocator/CidAllocator; ordered Drop; sweep_orphans
naming.rs        # one prefix → every per-VM resource name (net/tap/cgroup/scratch) + every sweep filter (§11.4)
reflink.rs       # the FICLONE-or-copy primitive behind ReflinkOverlayStore (forbid(unsafe))
overlay.rs       # OverlayStore seam: trait + ReflinkOverlayStore + RecordingOverlayStore (§8.4)
zygote.rs        # Zygote: suspend once, mint many; the concurrent-fan-out gate (§8.4)
lineage.rs       # Lineage/LineageId/LineageAllocator: fork/branch over Zygote (§8.5)
artifact/        # Stage trait, Pipeline, cache, bootstrap kernel/rootfs/snapshot stages, bundle; pub reuse surface
```

### 9.3 The public API surface

Types are `#[non_exhaustive]` where future fields are likely; builders keep call sites stable.

**`HostEnv` — the process-wide seam bundle.** Every injected seam that is process-global (or that every VM
shares) lives in one struct, built once per process and passed by reference to every spawn:

```rust
// ---- env.rs ----
#[derive(Clone)]
pub struct HostEnv {
    pub cids:    Arc<CidAllocator>,
    pub vmids:   VmidAllocator,          // Clone over an internal Arc<Mutex>
    pub cgroups: Arc<dyn CgroupFs>,
    pub clock:   Arc<dyn Clock>,
    pub overlay: Arc<dyn OverlayStore>,
}
impl HostEnv {
    /// Production: cross-process VmidAllocator::shared(), RealClock, ReflinkOverlayStore, the real CgroupFs.
    pub fn shared() -> Result<Self>;
    /// Hermetic: in-process allocators; tests substitute recording fakes field-by-field.
    pub fn hermetic() -> Self;
}
```

The allocators are process-global by design — under `cargo test`'s in-process parallelism, per-test
allocators hand concurrent tests identical IDs and collide on temp-dir paths and socket names — and the
daemon is the natural single home for the productized pair (§11.1). Bundling them with the `CgroupFs`,
`Clock`, and `OverlayStore` seams gives every spawn one parameter instead of three-to-five positional
injected arguments that grew by one per feature, removes the per-clone `make_cgroups` closures from the
fan-out APIs, and lets `agent()` take no arguments (the clock that drives the post-restore resync comes
from the env captured at construction; the connect deadline is the correctness-floor constant). Tests
build a `HostEnv` with recording fakes; per-VM assertions key on the slice/vmid the shared recording fake
recorded. This bundle is directed by this revision (§18, deltas 1–2) and is the one breaking change of the
0.10 pass.

```rust
// ---- config.rs ----
#[non_exhaustive]
pub struct VmConfig {
    pub vcpus: u8,               // > 0
    pub mem_mib: u32,            // >= 64
    pub kernel: PathBuf,         // vmlinux (direct kernel boot)
    pub rootfs: RootfsSource,    // Erofs { image } (default) | Block { image, overlay }
    pub shares: Vec<Share>,      // virtio-fs mounts; need capabilities().virtio_fs_shares
    pub net: NetConfig,
    pub nested_virt: bool,       // needs capabilities().nested_virt (not Firecracker)
    pub limits: ResourceLimits,
    pub snapshotting: bool,      // build() REJECTS this with ANY vhost-user device (S1) or a custom init
    pub vmid: Option<u32>,       // 1..=254; None => allocated
    pub restore_mode: RestoreMode, // Default | Eager | Lazy  → CH --restore prefault=on|off
    pub ksm_mergeable: bool,     // CH mergeable=on + shared=off; mutually exclusive with vhost-user (§8.3)
    pub kernel_verbosity: KernelVerbosity, // Quiet|Balanced(default)|Verbose|Debug → loglevel=3/6/7/8
    pub timeouts: Timeouts,      // per-VM hot-path timing knobs; default()/low_latency()/throughput()
    pub console_mode: ConsoleMode, // Uart(ttyS0, default) | VirtioConsole(hvc0); needs capabilities().virtio_console
    pub extra_disks: Vec<BlockDevice>,  // extra raw virtio-blk → /dev/vd{b,c,…}; snapshot-composing (§4.6)
    pub extra_kernel_args: Vec<String>, // append-only, is_reserved_cmdline_arg-guarded (§5.3)
    pub init: Option<PathBuf>,          // init= override: replaces PID 1, forgoes the control plane (§5.3)
    pub resource_prefix: String,        // names AND sweeps every per-VM host resource; default "vmcell",
                                        //   validated [A-Za-z0-9]≤6 at build() (§11.4)
    pub vmm_seccomp: VmmSeccomp,        // the VMM subprocess's OWN seccomp: Enforcing (default) | Log | Disabled
    pub jail: JailConfig,               // jailer-equivalent pre-exec hardening; default hardened() (§12.3)
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlockDevice { pub image: PathBuf, pub readonly: bool, pub io_limit: Option<DiskIoLimit> }
impl BlockDevice {
    pub fn read_only(image: impl Into<PathBuf>) -> Self;
    pub fn read_write(image: impl Into<PathBuf>) -> Self;
    pub fn with_io_limit(self, limit: DiskIoLimit) -> Self;
}
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DiskIoLimit { pub bandwidth_bytes_per_sec: Option<u64>, pub iops: Option<u64> } // build() rejects all-None / any-0

// ---- orchestrator.rs — the handle most callers hold ----
pub struct MicroVm<V: Vmm> { /* instance, cgroup, net, virtiofsd, cid, vmid, tmp_dir, env, ... */ }
impl<V: Vmm> MicroVm<V> {
    pub async fn start(vmm: &V, cfg: VmConfig, env: &HostEnv) -> Result<Self>;
    pub async fn restore(vmm: &V, snapshot_dir: &Path, cfg: VmConfig, env: &HostEnv) -> Result<Self>;
        // SINGLE-USE: rewrites snapshot_dir in place (§8.1)
    pub async fn restore_cow(vmm: &V, zygote_dir: &Path, cfg: VmConfig, env: &HostEnv) -> Result<(Self, CowSupport)>;
        // CoW-copies the suspend dir through env.overlay first (§8.4)
    pub fn vmid(&self) -> u32;
    pub fn proxy(&self) -> Option<&EgressProxy>;          // the egress-proxy handle, if egress is filtered
    pub async fn agent(&mut self) -> Result<&mut AgentClient>;
        // drives the first post-restore resync via env.clock; connect deadline is the 10 s floor constant
    pub async fn connect_sessions(&mut self, serial_log: &dyn SerialLog) -> Result<SessionMux>;
        // a 2nd control-plane connection for interactive sessions; fail-loud with custom init=
    pub async fn usage(&self) -> Result<ResourceUsage>;   // reads the cgroup slice
    pub async fn pause(&mut self) -> Result<()>;
    pub async fn resume(&mut self) -> Result<()>;
    pub async fn snapshot(&mut self, dir: &Path) -> Result<()>; // snapshot-eligible only; Unsupported otherwise
    pub async fn shutdown(self) -> Result<()>;            // graceful, then verify gone (§9.4)
}
impl<V: Vmm> Drop for MicroVm<V> { /* kill VMM proc-group → virtiofsd → tap/netns/cgroup/overlay/tmp_dir */ }

// ---- zygote.rs — suspend once, mint many (§8.4) ----
pub enum CowSupport { Reflink, FullCopy }
pub struct Zygote { /* immutable master snapshot dir + the snapshot-eligible clone config (vmid cleared) */ }
impl Zygote {
    pub async fn suspend<V: Vmm>(vm: &mut MicroVm<V>, cfg: VmConfig, master_dir: impl Into<PathBuf>) -> Result<Self>;
    pub async fn from_snapshot_dir(master_dir: impl Into<PathBuf>, cfg: VmConfig) -> Result<Self>;
    pub async fn spawn_clone<V: Vmm>(&self, vmm: &V, env: &HostEnv) -> Result<MicroVm<V>>;
    pub async fn spawn_clones<V: Vmm>(&self, vmm: &V, count: usize, env: &HostEnv) -> Result<Vec<MicroVm<V>>>;
        // concurrent pool, all-or-nothing; Unsupported when count > 1 && !restore_rotates_host_paths
    pub fn master_dir(&self) -> &Path;
}

// ---- vmm::seccomp / config — the VMM's own seccomp policy + the jailer config (§12.2–§12.3) ----
pub enum VmmSeccomp { Enforcing, Log, Disabled }  // default Enforcing; Disabled is a logged, explicit opt-out
pub fn vmm_seccomp_args(backend: &str, policy: VmmSeccomp) -> Result<Vec<String>>;
pub struct JailConfig { /* no_new_privs, clear_ambient_caps, non_dumpable, rlimit_core/fsize/nofile, seccomp_deny_list */ }
impl JailConfig { pub fn hardened() -> Self; } // no_new_privs + RLIMIT_CORE=0 + non_dumpable on; the rest off
```

Both `Zygote` constructors fail-fast reject an ineligible config (a vhost-user device) at construction,
before any copy is minted; the config's `vmid` is cleared since every clone is allocated a fresh one. A
caller wanting an up-front CoW cost signal probes directly: `env.overlay.probe(zygote.master_dir())`. The
`Lineage` API is §8.5; the session API is §3.2; `AgentClient`, `ResourceUsage`, `VmmCapabilities`,
`Vmm`/`VmInstance`, `NetConfig`, and `Share` are shown in §2–§7 where they are used.

**Allocator mechanics.** `VmidAllocator` is either hermetic (`new()`, in-process) or cross-process
(`shared()`, via `/tmp/vmcell-vmid/<vmid>.lock` files with crashed-owner reclaim; `shared_at(dir)` injects
the lock directory so the fs claim/reclaim path is unit-testable). Each lock file is **created already
carrying the owner pid** (never a create-then-write two-step that could crash into an empty, unreclaimable
lock); reclaim of a dead/empty/unparseable owner is serialized by an **atomic rename** so two racing
processes cannot dual-claim, and liveness is a `/proc/<pid>` check. The VMID is mapped to the third IPv4
octet as **`(vmid % 254) + 1`** (`10.200.<octet>.{1,2}` — a raw counter would exceed 255 and synthesize
invalid addresses), centralized in one unit-tested `/30` helper, which caps a single host at ≈254
concurrent VMs on one `/16` (§17). VMID range is `1..=254`; CID space is `3..=254`. The VMID lock dir is
deliberately *not* prefixed by `resource_prefix` — it is a cross-process rendezvous that must be stable
regardless of prefix, and it is not swept.

**`resource_prefix` + the `vmcell::naming` module — one string names *and* sweeps every per-VM host
resource (law F2).** A VM leaks four host resources if it dies ungracefully — a netns, a tap, a cgroup
slice, and a scratch dir — and the orphan sweep filters for them. Their names were four hard-coded
`vmcell-*` literals and the sweep filtered by three more — seven copies of one prefix that had to stay in
lockstep or the sweep would silently miss a leak. `vmcell::naming` collapses them: the single place that
composes every name from a prefix (`<prefix>-net-<vmid>`, `<prefix>-tap-<vmid>`, `<prefix>-vm-<vmid>`,
`<prefix>-vm-<pid>-<vmid>`) and every sweep filter (`<prefix>-net-`, `<prefix>-vm-`); a unit test pins
that each produced name **starts with** its sweep filter for any prefix. The prefix lives on
`VmConfig::resource_prefix` (validated `[A-Za-z0-9]`≤6 at `build()` so it is safe in an
interface/netns/cgroup/dir name), and `HostOrphanScanner::new(prefix)` matches by the same value — so two
daemons with distinct prefixes never sweep each other's resources (§11.4). The default reproduces the
historical `vmcell-*` names exactly.

All per-VM temporaries (API/vsock sockets, serial log, the unprivileged smoltcp socket) live under one
`/tmp/<prefix>-vm-<pid>-<vmid>/` owned by a `VmTempDir` RAII guard on `MicroVm`, created *before*
networking and dropped *last* in `Drop`. (The VMID lock files and the Firecracker T2 capability-probe
socket are deliberately outside it — they outlive any single VM.)

### 9.4 `Timeouts` and the lifecycle nuances

**`Timeouts` — the per-VM hot-path timing profile.** Seven `Duration` fields gather every tunable hot-path
wait (defaults in ms; `low_latency()` / `throughput()` in parentheses): `connect_backoff_floor` 20 (5/10)
and `connect_backoff_cap` 100 (40/75) — the vsock connect backoff, reset to the floor once the UDS
connects; `connect_ok_read` 150 (100/150); `api_socket_poll` 5 (2/3), which paces **every** VMM
control-socket / daemon readiness wait (including QEMU's `vhost-device-vsock` daemon wait and
Firecracker's T2 CPU-template probe wait); `shutdown_grace` 250 (250/50); `guest_accept_poll` 20 (5/10)
and `guest_rebind_idle` 250 (150/200), the last two emitted as `vmcell_*_ms` cmdline tokens the agent
parses clamped (§5.3), so a preset tunes the guest with **no rootfs rebuild**. `low_latency()` minimizes
time-to-first-output (tightens every connect/accept cadence, leaves teardown graceful — ~−28 ms CH cold);
`throughput()` minimizes whole-lifecycle wall clock (cuts `shutdown_grace` to 50 ms and keeps cadences
moderate, since tight polls cost idle-CPU wakeups in a dense farm). Every field clamps to a correctness
floor via `pub(crate) clamped()` (`connect_backoff_floor` ≥1 ms, `cap` ≥ floor, `connect_ok_read` ≥5 ms,
`api_socket_poll`/`guest_accept_poll` ≥1 ms, `guest_rebind_idle` ≥20 ms; `shutdown_grace` has no floor — 0
is legal, force-kill remains the fallback), and because the fields are `pub`, the orchestrator
**re-clamps at `start()`/`restore()`** so post-`build()` mutation can never busy-spin PID 1 or a readiness
poll; `vmm::wait_for_socket` additionally clamps its interval to ≥1 ms. The deliberately-*not*-in-
`Timeouts` failure ceilings are correctness-floor constants (the 2 s Ready-frame wait, the 10 s overall
connect deadline, `DEFAULT_EXEC_TIMEOUT` 10 s, the QMP/join timeouts), not knobs.

**`MicroVm::shutdown()`** (not the backend's `request_shutdown()`, which is only the graceful signal)
computes the grace deadline **before** issuing `request_shutdown` — the RPC round trip *spends* the grace
instead of silently extending it (worth ~20 ms on the default profile) — then polls
`VmInstance::has_exited()` on an **adaptive step** (grace ≤50 ms → 5 ms, ≤150 ms → 10 ms, else 20 ms) and
returns as soon as the guest powers off, capping at `Timeouts::shutdown_grace` before the SIGKILL
fallback. Because the shutdown RPC's only bound is the generic 5 s `vmm::unix_api_request` ceiling — far
longer than the grace, so a slow ack would otherwise spend the whole window — the deadline is clamped
post-ack to ≥ one poll step, so a stalled RPC still yields at least one `has_exited` check. That
`unix_api_request` ceiling bounds **every** CH/FC control RPC over the API UDS, returning a typed
`Error::Timeout`, so a wedged control socket surfaces before any outer readiness timeout can mask it.

**Error-path teardown mirrors success-path teardown through one function.** On a mid-`start()`/`restore()`
failure *before* resources move into `MicroVm`, the internal `EnvSetup` staging struct releases them via
an explicit `Drop` impl that calls the **same ordered-teardown helper** `teardown_post_instance` uses —
one law for the order (proxy and smoltcp NAT before netns; VMM process group first once an instance
exists), two callers, pinned by a drop-order recording gate. (This replaces relying on struct
field-declaration order for the error-path drop sequence, which was correct but invisible and
reshuffle-fragile — §18, delta 7. The pre-fix bug it guards against: deleting the netns before the proxy
running inside it.)

### 9.5 The error type

One `Error` enum (`thiserror`) with a variant per subsystem, `Result<T> = std::result::Result<T, Error>`.
Two deliberate properties: there is **no `Error::Other(String)` catch-all** — the review rubric bans
exactly that — and the two most caller-relevant conditions are **typed and matchable**:
`Error::Unsupported { vmm, feature }` (an op a backend doesn't advertise) and
`Error::CapabilityUnavailable { op, needed }` (a requested op whose OS capability is absent, §7.2). The
per-subsystem variants (`Vmm`/`Agent`/`Network`/`Cgroup`/`Artifact`/`Config`/…) carry a `String` payload
rather than a fully-typed source for every case; `#[from]` is used where a concrete upstream type exists
(`Hyper`, `SerdeJson`, `Io`, `Reqwest`, `Postcard`). This is an accepted trade-off — matchability where it
matters, strings elsewhere — not the `Error::Other`-everywhere anti-pattern.

### 9.6 Dependency strategy

Implementation avenues are ranked — *best:* our own well-documented Rust; *great:* a permissive crate;
*good:* a binary with a programmable interface; *okay:* an external tool — and copyleft/restrictive
licenses are forbidden for anything *linked*. Much that a naive implementation would shell out to is a
linked, permissive crate under `cargo-deny`'s license gate:

| Capability | Naive OS tool | Crate (linked) |
|---|---|---|
| netns / tap / addrs / routes | `iproute2` (`ip`) | `rtnetlink` + `netns-rs` + `tun-tap` |
| MITM CA + leaf minting | `openssl` | `rcgen` + `rustls` (via `hudsucker`) |
| cgroup peak/avg reads | parse `/sys` by hand | `cgroups-rs` + `procfs` (reads only; slice create + limit writes go direct to sysfs) |
| pull + unpack a Debian base | `skopeo` / `docker` | `oci-client` + `tar` + `flate2`/`zstd` |
| build the erofs image | `mkfs.erofs` | `am-fs-erofs` (tar→erofs in memory) |
| vsock control channel | `socat`/`ncat` | `tokio-vsock` (host), `vsock` (agent) |
| unprivileged guest net | `passt` (rejected, Exp 5) | `smoltcp` + `vhost-user-backend` |
| verify SHA256 / detached PGP | `sha256sum` / `gpgv` | `sha2` / `pgp` (rPGP) |

Three caveats shaped the choices:

- **nftables has no permissive pure-Rust path.** `rustables` relicensed to GPL-3.0-or-later; the pure-Rust
  crates don't cover the TPROXY/`socket` expressions. Since the ruleset is small, fixed, and
  security-critical, it is rendered in Rust and applied via `nft -f -` — correctness over purity.
- **A carried vendored patch of `vhost-user-backend`+`vhost`** is needed *only* to attach the unprivileged
  smoltcp NAT to QEMU (not CH), where a strict `PROTOCOL_FEATURES` check rejects `SET_VRING_ENABLE`
  arriving before `SET_FEATURES`. A live message trace confirms QEMU sends `SET_VRING_ENABLE` first while
  CH sends features first, and upstream still enforces the guard — a genuine QEMU ordering quirk, not a
  masked backend bug. The crates.io-packaged sources are vendored **in-tree** (`vendor/vhost` 0.16.0,
  `vendor/vhost-user-backend` 0.22.0 — content in git, stronger than pinning a git-fork rev), wired via
  `[patch.crates-io]` path entries with exact `=` pins. The relaxation is **gated on `features_acked`**
  (accept QEMU's early delivery, re-enforce the spec check after `SET_FEATURES` — narrower than a blanket
  relaxation), the disabled check carries an at-site rationale comment, and `just ci` asserts via
  `cargo tree` that both crates resolve from `vendor/` so a version bump cannot silently drop the patch.
  Permissively licensed (rust-vmm, Apache-2.0); drop it (delete `vendor/` + the `[patch]` entries) if the
  QEMU-unprivileged tier is dropped. (Because `just ci` sets `RUSTFLAGS=-D warnings` process-wide, the
  vendored code's unused helpers carry `#[allow(dead_code)]`.)
- **Trust `cargo-deny`, not hand-written license labels.** An earlier draft mislabeled `rustables`
  MIT/Apache when it is GPL-3.0 — exactly the class of error the allow-list catches.

`virtiofsd` is `cargo install`'d (a rust-vmm binary, Apache/BSD), so shared-directory support needs no OS
package. Irreducibly external: `cloud-hypervisor` (pinned release binary), the kernel build toolchain,
`nftables` (`nft`), `qemu-system-x86` (fallback only), and KVM. **License gate:** `cargo-deny` enforces an
allow-list (`MIT`/`Apache-2.0`/`BSD-3`/`BSD-2`/`ISC`/`Zlib`/`0BSD`/`Unicode-3.0`/`CDLA-Permissive-2.0`)
for all *linked* crates on every build, and ignores a set of dormant `unmaintained` advisories from the
`tokio-0.1` tree that enters only via `tun-tap 0.1.4 → tokio-core → tokio 0.1.22` (the optional privileged
tap path), each with a per-crate rationale.

### 9.7 Features and build shapes

The build *shapes* (things you compile and ship) are the host stack (**library + CLI + `bench-vm`**) and
the lean *binary* members (**agent**, **test-runner**, **guest-tools**, plus the daemon-tier binaries);
`vmcell-protocol` is a shared library member, never shipped on its own. Within the `vmcell` library the
per-component features remain (`cloud-hypervisor`, `firecracker`, `qemu`, `net-privileged`,
`net-unprivileged`, `proxy`, `metrics`, `pipeline`, `cli`), but each pulls in a **`host-common`** umbrella
that turns on the whole host module set, and `host-common` in turn lists the per-module features — an
intentional feature cycle cargo accepts and unifies. The effect: **any host feature yields the whole
coherent stack**, so there are no incoherent partial-host configs. This retired the fine-grained matrix
that was the direct source of feature-gating build breaks (an un-`cfg`'d `#[from]` variant broke
`--features agent`; modules gated on the wrong feature made single-feature combos fail to compile). The
feature powerset is a **blocking** CI gate (all combos compile). The trade-off is deliberate: there is no
minimal backend-only library build — a `--features qemu` build still pulls the full host stack — which is
fine, since no real deployment used a partial host build.

The leanness that *does* matter — the privileged-window binaries and the guest agent must not drag in the
host async stack — is a **structural per-member property**: each is its own crate, so building the member
*is* the lean build. A CI `cargo tree -e no-dev` per member asserts `agent` and `test-runner` (and
`vmcell-privilege`, and `vmcell-broker` for the web stack) contain no `tokio`/`hyper`/`rtnetlink`.
**`guest-tools` is deliberately not under that ban** — it needs `reqwest` for real HTTP and runs
unprivileged in-guest, so its lean boundary is "not the host *library*," not "no async."

**Toolchain note.** The crate targets `rust-version = 1.85` (the 2024-edition baseline), but the committed
`Cargo.lock` pins `time 0.3.47` to fix a RUSTSEC advisory, and `time ≥ 0.3.47` needs Rust 1.88 — so a
from-scratch build needs Rust ≥ 1.88, and a `cargo update` on a 1.85 toolchain would *downgrade* `time`
back to the vulnerable 0.3.45. Treat 1.88 as the effective build floor until the MSRV is bumped.

### 9.8 Testability seams

Four accommodations make the orchestrator unit-testable without KVM or root. **They are load-bearing, not
optional** — an implementation that skipped them (calling `ip`/`nft` directly, using module-global
`static AtomicU32` counters) is precisely why a class of correctness bugs was review-only.

1. **The `Vmm`/`VmInstance` trait seam.** `FakeVmm` implements both traits in memory, letting the
   orchestrator's logic (allocation order, ordered `Drop` cleanup, retry/timeout, snapshot-vs-cold-boot
   selection) be unit-tested with no KVM, root, or subprocess. `FakeVmm` records calls **and carries a
   scriptable fault menu** — fail `create`/`boot`/`restore` at a chosen step, delay readiness, report a
   wedged control socket — so the retry/timeout and mid-`start()` failure paths are exercised at the trait
   seam itself, not only through the surrounding seams. (The fault menu is directed by this revision —
   §18, delta 9; previously `FakeVmm` recorded calls only.)
2. **Pure/imperative split.** The genuinely-testable pure functions are isolated from I/O: nft-rule
   rendering, `/30` arithmetic, the CH REST payload builder, the vsock handshake state machine,
   cgroup-path construction, per-VM scratch-dir construction, the artifact `cache_key`, the accept-loop
   deadline policy (§3.4), and the protocol codec.
3. **Injectable side-effect traits** — `Netlink`, `NftApplier`, `CgroupFs`, `SerialLog`, `Clock`,
   `OverlayStore`, `OciPuller` (`RealOciPuller` + a recording/replaying `FakeOciPuller` serving canned
   manifests/blobs), `GuestResync`, `OrphanScanner`, and `VmidAllocator::shared_at`'s injectable lock
   directory — each with a real implementation and a recording fake, so `net`/`metrics`/`agent`/`artifact`
   orchestration can assert "the right rules/limits/handshake/pull were requested" without touching the
   host.
4. **Deterministic IDs and clocks** are injected via `HostEnv`, never module-global statics, so tests are
   reproducible.

The rule that follows: **a subsystem that cannot be unit-tested against a fake is, by this design, not
done** (§15). One nuance the seams make honest: the zero-netlink-in-PID-1 invariant (law C6) is *not*
guarded by a `Netlink` fake — the guest agent has no netlink seam to inject because the manual bring-up
was *deleted* — so it is guarded structurally by the CI assertion that `vmcell-guest-agent` has no
`rtnetlink` dependency at all.

---
## 10. The artifact build pipeline

The pipeline maps onto the artifact-production requirements: staged, pinned, deterministic, cacheable,
resettable, minimal external access, record/replay, signing-chain verified. It is exposed as the library
`artifact::Pipeline` and as CLI verbs. The bootstrap pipeline stays in `vmcell` (the `Stage` trait,
`Pipeline`, the cache, and the bootstrap producers); the in-VM builders are `Stage` impls in their own
crates; `vmcell-cli` is the composition root that assembles a `Pipeline` from either set (§9.1) and
implements `build`, `build-kernels`, `oci2erofs IMAGE@DIGEST`, the live-handle lifecycle verbs
`run`/`create`/`snapshot`/`stats` (taking `--kernel`/`--rootfs`, plus `--disk`/`--disk-rw`/`--append` as
thin wrappers over the extra-disk / extra-kernel-arg builder methods), and `bundle`/`verify-bundle` (a
digest-pinned fetch-and-verify manifest of the built artifacts). The cross-process verbs
(`exec`/`ls`/`rm`/`destroy`) belong to the daemon, which genuinely owns them (§11); the CLI's former
fail-loud stubs for them are removed in this revision, with the removal message pointing at `vmcelld-ctl`
(§18, delta 11).

### 10.1 Artifacts produced

1. **`vmlinux`** (per arch, per kernel label): one custom-minimal kernel, direct-boot, drivers built in.
   Rebuilt only when the config fragment or pinned source changes.
2. **Root filesystem** (per profile): a single read-only erofs packed in memory from a merged tar, from
   one of two interchangeable sources sharing the inject+pack tail (§4.2). Kernel-independent.
3. **Warm snapshot** (per VMM + profile): boot the erofs base to agent-ready, snapshot. This suspend image
   is directly usable as a **zygote master** (§8.4): `Zygote::from_snapshot_dir` adopts it, so the
   artifact that speeds a single restore also seeds a warm pool.
4. **Proxy CA cert**: minted once per artifacts dir and cached (the recorded deviation from per-run CA
   hygiene, §6.4), baked into the rootfs trust store.

All four live under one artifacts directory — `$VMCELL_ARTIFACTS_DIR` or the default
`target/vmcell-artifacts` (anchored on the *workspace root*, not the member CWD, so a workspace member's
tests find it) — from which `kernel_path()`/`rootfs_path()` derive (overridable via `$VMCELL_KERNEL` /
`$VMCELL_ROOTFS`). There are **no `/tmp/vmlinux`-style fallbacks**: a missing upstream artifact is an
`Error::Artifact`, never a silent boot from a world-writable path.

### 10.2 The stage model and the five cache-key rules

The pipeline is a sequence of stages behind a small trait; the load-bearing parts are that `cache_key` is
**pure** (so the cache can decide to skip a stage *before* running it) and that stages pass real data
through `StageInputs`/`StageOutputs` (not via env vars or empty structs):

```rust
pub trait Stage {
    fn name(&self) -> &str;
    fn cache_key(&self, inputs: &StageInputs) -> CacheKey;                 // PURE (law F4)
    fn out_path(&self, target_dir: &Path) -> PathBuf;                     // default: target_dir/<name>.bin
    async fn run(&self, inputs: &StageInputs, out: &Path) -> Result<StageOutputs>;
}
pub struct Pipeline { /* Vec<Box<dyn Stage>> */ }
impl Pipeline {
    pub async fn build(&self, cache: &Cache) -> Result<Artifacts>;    // skip a stage whose output content matches its key
    pub fn reset_to(&self, stage: &str, cache: &Cache) -> Result<()>; // remove that stage's + all later outputs;
                                                                      //   errors on an unknown name
}
```

**Stage 0 — the pin lock (the only non-deterministic input, isolated here).** The minimal pin set: the OCI
base-image manifest **digest** (never a tag), the `snapshot.debian.org` **timestamp** (for the in-VM
source), the kernel source version/SHA (plus the `kernels` registry, §5.5), the `kernel_prebuilt` entry
(the digest-pinned bootstrap-seed URL + sha256, §5.4), and the CH/virtiofsd release tags. These live in a
committed `pins.json`; `ResolvePinsStage` loads it once and propagates the values through `StageOutputs`
so downstream stages read pins from memory. *Live* tag→digest and timestamp resolution is forward work
(§17); the committed lock is the honest current state.

**Stages 1..n — deterministic given inputs.** Each stage's output is fully determined by its inputs +
pins: the kernel producer → `vmlinux`; then the rootfs source (either path; the in-VM `mmdebstrap` path
boots a builder VM on the compiled/seed `vmlinux`, so the kernel stage is ordered first); both converge on
the shared inject+pack tail (§4.3) → boot + snapshot.

**Caching — five rules, each its own failure mode (law F4).** Each stage has a pure `cache_key`;
`Pipeline::build` skips a stage whose **output content** matches that key:

1. **Stable hasher** — `blake3` (or `sha2`), never `DefaultHasher` (not portable across Rust versions).
2. **Deterministic input order** — hash inputs in a fixed order (sorted keys / `BTreeMap`), never
   `HashMap` iteration order.
3. **Content and identity that travel, not local paths** — hash the *content hashes* of upstream
   artifacts, never absolute `PathBuf`s under `target/`. The rootfs key folds `guest_agent_src_hash` (the
   agent's full source closure, with a distinct missing-source marker), the guest-tools content, and the
   baked deployment-CA content, so rebuilding any of them invalidates the rootfs (a stale agent baked into
   the rootfs was a real handshake-timeout bug); on the `oci2erofs --agent-musl` path it folds the
   injected agent binary's **content hash**, never its path string; the `mmdebstrap` key folds the
   resolved builder-base image+digest. The **snapshot** stage key additionally folds the pinned Cloud
   Hypervisor build identity: CH guarantees no cross-version snapshot compatibility, so a CH bump
   invalidates stale snapshots **at build time** rather than failing at first restore — `virtiofsd` is
   deliberately *not* folded, because a snapshot-eligible VM runs none (law S1).
4. **Embed a per-stage version constant and the pinned source SHA** — a build-logic change with unchanged
   pins, or re-pointing a pin at new bytes, must invalidate the key.
5. **Validity is content-addressed, not existence-based** — a tampered artifact with an intact
   `.cache_key` sidecar is **rejected**, not silently reused; re-hash on every use (including a cached OCI
   blob, whose digest is re-verified on the cache-hit path — and the layer list is parsed from the
   digest-*verified* raw manifest bytes, never a second unverified fetch). The kernel-tarball cache is
   verify-or-purge; directory-output stages hash via a deterministic sorted walk.

### 10.3 External access, signing, and determinism scope

**Minimize external access + record/replay.** Network-touching stages split into a **record** step
(populate a cache keyed to the pins) and a **replay** step (build purely from the cache); OCI blobs are
cached by digest so a later registry deletion doesn't break a rebuild. The OCI pull is behind the
injectable `OciPuller` trait, so the replay + tamper tests (tag-pull rejected, cache-hit re-verify,
cached-blob tamper rejected) run with no network.

**Signing-chain verification.** The in-VM `mmdebstrap` source verifies the Debian
`InRelease`/`Release.gpg` chain *inside the guest* before using any package (refuse-on-mismatch) against
the builder base image's own archive keyring (§4.2); `[check-valid-until=no]` disables only the freshness
window, never signature verification, and the snapshot-timestamp pin is unchanged. The OCI digest pin is
an integrity hard-stop but is *integrity, not authenticity* unless a cosign/sigstore signature is also
verified. A mismatch is a hard stop, never a warning.

**Byte-determinism, scoped honestly.** The `am-fs-erofs` packer *is* byte-deterministic (fixed mtimes,
`BTreeMap`-ordered inode/dirent emission — the same tar packs to identical bytes). But the full
`rootfs.erofs` is *not* byte-identical across independent deployments, because `RootfsStage` bakes a
freshly-minted per-deployment proxy CA into it (a reproducible shared CA key would be a security defect).
So "identical pins yield a byte-identical erofs" holds only within a fixed `artifacts_dir`/CA; across
deployments the CA varies by design while the packer stays deterministic.

---

## 11. The control-plane daemon (`vmcelld`)

### 11.1 What it adds, and where it sits

`vmcell` (the library) and `vmcell-cli` are a **single-process** model: a `MicroVm<V>` handle owns its VM
and *is* the lifetime — when the handle drops, ordered teardown destroys the VM. That model is correct and
stays the default for tests and one-shot CLI verbs, but it structurally cannot offer a VM that **outlives
the process that created it**: there is nobody to hold the handle.

**The daemon is that missing owner.** `vmcelld` is a single long-lived process that owns the VMs it
starts: it holds each `MicroVm` handle in an in-process registry, so a VM's lifetime is decoupled from any
one client request but stays tied to the daemon — and the whole "teardown is ownership, `Drop` releases
resources" invariant (law L1) carries over unchanged. Clients talk over HTTP and refer to VMs by an opaque
**id**. The one thing owning-and-`Drop` cannot handle by itself is a *hard* kill of the daemon (SIGKILL,
power loss), which skips every `Drop`; the daemon closes that with a **start-up orphan sweep** (§11.4), so
a crash-and-restart self-heals.

```
  vmcelld-ctl (CLI)  ─┐                         ┌─ artifact store  (<artifacts-dir>/<name>)  [files]
  your Rust program  ─┤── HTTP/REST (bearer) ──▶ vmcelld ─┤
  (vmcell-daemon-     ─┘   OpenAPI-described    (owning,   └─ VM registry ── holds ──▶ MicroVm … MicroVm
   client)                                       blessed)     (Drop releases; start-up sweep reclaims leaks)
```

The daemon is the natural single home for the process-global pieces: it builds **one `HostEnv`** (§9.3) —
one `VmidAllocator::shared()`, one `Arc<CidAllocator>`, the production seams — and hands it to every
launch. The daemon-tier members form an acyclic star on `vmcell` (§9.1); `vmcell` has no edge to any of
them. The wire schema is single-sourced by keeping the DTOs (and the artifact-name predicate) in
`vmcell-daemon` compiled **unconditionally**, while the whole server stack — axum router + handlers,
registry, auth, the `vmcell` host stack — sits behind a default-on `server` feature.
`vmcell-daemon-client` depends on `vmcell-daemon` with `default-features = false`, so it links **only**
the wire DTOs + the name predicate (serde + std), never axum or the server stack — the client shares the
server's exact types, and a required field added to a DTO is a compile error in the client, never a silent
skew.

Because the daemon **owns** its VM handles rather than detaching them, it needed **no** new vmcell
primitive — the single-process ownership model is reused in-process, held by a long-lived server instead
of a one-shot CLI. It forced exactly one client-side divergence: `vmcell`'s entry points take host
*paths*; over a network boundary a client path is meaningless to the daemon and a client-supplied *server*
path is a traversal hole — so the daemon's VM APIs take artifact **names** resolved against its own store,
and the client grows an upload step (§11.3). VMs deliberately do **not** outlive the daemon: a clean exit
tears them down; a hard kill leaks them and the next boot's sweep reclaims the residue. If daemon-surviving
VMs are wanted later, that is a detached variant — explicitly not v1.

### 11.2 Privilege and blessing

The daemon needs the same three capabilities as privileged operation (§6.1). Two ways to grant them:

- **Tests and dev — launch `vmcelld` through the blessed `vmcell-test-runner` (the default; no
  per-rebuild blessing).** The runner is a cap-conferring `exec` wrapper whose confinement accepts **any**
  binary under the workspace `target/` dir (§15.5) — so `vmcell-test-runner target/debug/vmcelld …` execs
  the daemon with the three caps in its effective set, and the blessing precondition passes without
  `vmcelld` itself being blessed. Because only the runner carries file-caps, and the runner rarely
  changes, `vmcelld` (which changes constantly) rebuilds freely with no `sudo setcap` on every change.
- **Standalone / production — file-caps or systemd ambient caps.** A long-lived system `vmcelld` is
  blessed once (`setcap …+ep`) or, better, granted via `systemd`'s `AmbientCapabilities=`.

**The one deliberate difference from the runner: the cap-holder retains the caps; it does not
drop-and-exec (law P1).** The runner is a *transient* wrapper — file-caps → raise ambient → drop to the
dev uid → `execvp` — so the caps live only across one `exec`. The daemon's cap-holder is a *long-lived
server* that must itself perform privileged VM operations (netns/tap/nft) for the whole process life. So
it runs the **blessing precondition** (the three caps present in the **effective** set, or `euid == 0`)
and then keeps them: no uid drop, no ambient raise, no bounding-set shrink, no `exec`. If the precondition
fails it prints the `setcap …+ep` remediation and **refuses to start** — never a daemon that came up
without `CAP_NET_ADMIN` and fails every privileged create at first use. Which process is the cap-holder
depends on the broker: by **default** `vmcelld` forks the setup broker — the broker child is the
cap-holder and owns the VM `Registry`, while the HTTP-serving parent drops all caps (law P2, §12.4);
`--no-setup-broker` selects the single-process retain-caps fallback.

**`vmcell-privilege` — one predicate, two callers.** The precondition logic is security-critical and was
private to the runner's `main.rs`; copying it into the daemon is precisely the "duplicate load-bearing
logic diverges" trap. So it is extracted, with the runner's pure, already-unit-tested seams moved verbatim:

```rust
// vmcell-privilege — lean: rustix + capctl + libc only.
pub const PRIVILEGED_CAPS: [Cap; 3] = [Cap::NET_ADMIN, Cap::SYS_ADMIN, Cap::DAC_OVERRIDE];

pub fn compute_missing(effective: &CapSet, need: &[Cap]) -> Vec<Cap>;          // pure
pub fn blessing_remediation(uid: u32, exe: &Path, missing: &[Cap]) -> String;  // pure
pub fn shell_single_quote(p: &Path) -> String;                                 // pure

/// Effective-set precondition shared by the runner and the daemon. Returns the
/// remediation string on failure. Does NOT mutate the process.
pub fn ensure_blessed_or_explain(need: &[Cap]) -> Result<(), String>;

// The runner's transient path stays runner-only (it drops uid + execs) but its PURE plan lives here:
pub struct PrivilegePlan { /* … */ }
pub fn plan_privilege_transition(/* … */) -> PrivilegePlan;   // pure, unit-tested against buggy inverses
pub fn apply_privilege_transition(plan: &PrivilegePlan) -> Result<(), String>;  // thin syscall edge
```

The daemon uses only `ensure_blessed_or_explain` + `blessing_remediation`; the runner keeps its full path
but imports it instead of defining it. The runner's red-on-inverse tests moved with the code and keep
guarding both callers. The runner's exec-target *confinement* stays runner-only (§15.5); the daemon's
analogous "anchor on trusted data" check is the artifact-name validator (§11.3), which anchors every
filesystem access on the daemon's own `--artifacts-dir`, never a client-supplied path.

### 11.3 The artifact store

The daemon receives `--artifacts-dir <path>` and manages the files under it with three operations —
**create, list, delete; no update**. This is deliberately *not* the `vmcell` artifact pipeline (§10): it
is a flat content store the VM APIs draw their `kernel`/`rootfs` inputs from. A client builds artifacts
elsewhere and **uploads** them; the daemon never fetches from the network on a client's behalf.

**One name predicate, anchored on trusted data (law P3).** Names map directly to files (`k1` →
`<artifacts-dir>/k1`), so the name validator is a security boundary of the same class as the runner's
exec-target confinement — a name that path-traverses or is absolute would read or clobber files outside
the store. One predicate, pure, unit-tested against its buggy inverses:

```rust
/// The ONLY function that turns a client-supplied artifact name into a path. Every
/// store op and every VM-API artifact reference goes through it.
pub fn resolve_artifact_path(dir: &Path, name: &str) -> Result<PathBuf, ArtifactError>;
```

Accept rule (allowlist, not denylist — a denylist of "bad" substrings is the divergence trap): a name is
valid iff it is non-empty, ≤255 bytes, every byte in `[A-Za-z0-9._-]`, not `.`/`..`, and not leading `-`
or `.` (a leading `-` would be read as a flag by any tool the name is later handed to; a leading `.` hides
the file and enables the `.`/`..` family). The result is always `dir.join(name)` with `name` a single
component — no `/` in the accepted set, so no subdirectories and no traversal are representable. Callers
**never** construct `dir.join(client_string)` themselves (grep-able gate: `dir.join(` on a client string
outside this function is a review-reject). Red-on-inverse tests: `..`, `a/b`, `/abs`, `-rf`, `.hidden`,
empty, over-255-bytes, and a NUL byte all reject; a positive control (`vmlinux-6.12`, `rootfs.erofs`)
accepts and joins to exactly `<dir>/<name>`.

**Operations:**

- **Create** — `PUT /v1/artifacts/{name}` with the file bytes as the body. **No update**: create rejects
  an existing name with a typed `AlreadyExists` (409), never a silent overwrite. Bytes are streamed
  **through a SHA-256 hasher** to a temp file in the same dir, then atomically renamed into place, so a
  crashed or truncated upload never leaves a half-written artifact — and the digest is computed once, at
  upload, and stored in a `<name>.sha256` sidecar (§18, delta 10). The write is size-capped by
  `--max-artifact-bytes`, rejected fail-loud past it — an unbounded upload is a trivial disk-fill DoS.
- **List** — `GET /v1/artifacts` → `[{name, size_bytes, sha256}]`, the digest served from the sidecar so
  list is O(entries), not O(store bytes); its purpose is client round-trip verification, and the daemon
  owns the dir, so re-hashing on every list bought nothing. Listing surfaces only direct children that
  pass `resolve_artifact_path` (a stray subdir or an out-of-band name that fails validation is skipped,
  never surfaced as a usable artifact); sidecars are internal and not listed.
- **Delete** — `DELETE /v1/artifacts/{name}` → 204. Refuses to delete an artifact **in use** by a live VM
  with a typed `InUse` (409): the handler asks the registry `is_artifact_in_use(name)` — which scans the
  owned VMs' pinned names, including extra disks — before deleting, so a kernel is never pulled out from
  under a running VM.

Every store op is a pure-ish function over `(dir, name, bytes?)` behind the validator, unit-testable
against a `tempdir` with no HTTP and no KVM — the axum handler is a thin adapter that maps the typed store
error to a status code.

### 11.4 The VM registry and the start-up sweep

The registry keeps law L1 intact end-to-end: while a handle is held the VMM process and its
netns/tap/cgroup/scratch stay alive, and when the handle drops the *same* ordered teardown runs. Two seams
and one recovery hook:

- **`VmLauncher` / `VmHandle`** — the registry drives VMs through these traits, not `MicroVm` directly, so
  its logic (id minting, the state machine, ordered teardown, artifact pinning) is unit-testable against a
  recording fake with no KVM or root. The real `MicroVmLauncher` is a thin adapter: `launch` builds a
  `VmConfig`, calls `MicroVm::start` (bringing the agent up, so a returned VM is genuinely ready — "ready"
  is derived from the VM, not a hopeful label), and boxes the handle; `exec`/`usage`/`snapshot`/`shutdown`
  forward to the `MicroVm`.
- **`Registry`** — a `tokio::sync::Mutex<HashMap<VmId, Arc<VmSlot>>>` where each `VmSlot` holds the boxed
  handle behind its **own** async mutex. Ops on different VMs run concurrently; ops on one VM serialize on
  its single vsock control channel (correct — one channel per VM). The VM's immutable identity (id, vmid,
  the artifact names it pins) is read lock-free for the delete-in-use guard; only the handle + state sit
  behind the per-VM lock. The **id** is an opaque server-minted token (`vm-<counter>-<splitmix64>` —
  readable counter + mixed suffix, unguessable, never reused in a process); it is *not* the VMID (the
  network octet).

**Teardown is ownership, two paths, one helper.** `destroy` removes the slot from the table (so no new op
finds it), marks it `Destroying`, and runs the graceful `MicroVm::shutdown`; a clean daemon exit calls
`shutdown_all`; and dropping the registry runs each `MicroVm::Drop` — the panic path — with the identical
ordered cleanup. A **hard** kill skips all three and leaks the residue.

**The start-up orphan sweep — the crash-recovery counterpart.** Before it owns any VM, the daemon runs
`sweep_orphans` with an **empty** live-vmid set, so every netns/cgroup-slice/scratch dir whose trailing
vmid is not currently owned — i.e. every orphan a previously hard-killed daemon left — is reclaimed.
(Nothing is live at start-up, so the empty set can never sweep a resource in use.) The sweep needs
`CAP_NET_ADMIN` to delete a netns, which the cap-holder has; per-resource failures are logged, not fatal.
The `--resource-prefix` flag (default `vmcell`) is threaded to *both* the launcher and the sweep, so its
VMs are named with it and the sweep reclaims exactly those names — two daemons with distinct prefixes
never sweep each other's resources (law F2; validated on KVM: a daemon run with `--resource-prefix acme`
names its VM's netns `acme-net-<vmid>`, reclaims a planted `acme-net-*` orphan, and leaves a
`vmcell-net-*` orphan from another tool untouched).

### 11.5 The HTTP REST API and its OpenAPI document

```
Artifacts
  PUT    /v1/artifacts/{name}      upload (create; 409 if exists)         body: bytes
  GET    /v1/artifacts             list                                   -> [ArtifactInfo]
  GET    /v1/artifacts/{name}      metadata (HEAD-like; no body download)
  DELETE /v1/artifacts/{name}      delete (409 if in use by a live VM)

VMs
  POST   /v1/vms                   create+boot (== `run`/`create`)        body: CreateVmRequest -> CreateVmResponse
  GET    /v1/vms                   list the daemon's owned VMs (== `ls`)  -> [VmInfo]
  GET    /v1/vms/{id}              get one                                -> VmInfo
  POST   /v1/vms/{id}/exec         run a command over vsock (== `exec`)   body: ExecRequestDto -> ExecOutcomeDto
  GET    /v1/vms/{id}/stats        resource usage (== `stats`)            -> ResourceUsageDto
  POST   /v1/vms/{id}/snapshot     write a warm snapshot (== `snapshot`)  body: {artifact_prefix} -> SnapshotInfo
  DELETE /v1/vms/{id}              destroy + teardown (== `rm`/`destroy`) -> 204

Meta
  GET    /openapi.json             the served OpenAPI 3.1 document        (unauthenticated)
  GET    /healthz                  liveness                               (unauthenticated)
```

`CreateVmRequest` carries `kernel` and `rootfs` (artifact **names**), `vcpus`, `mem_mib`, and — additive,
`#[serde(default)]` so old clients keep working — the config knobs plus the run/ephemeral pair and the
extra device fields:

- **`net: NetMode`** (`none` default | `privileged` | `unprivileged`). The cap-holder has the caps, so the
  privileged tap path is available; `unprivileged` is the smoltcp NAT (not snapshot-eligible).
- **`snapshotting: bool`** — boot a snapshot-eligible VM. Rejected fail-loud (400) with a non-eligible
  `net` *before* launch.
- **`restore_from: Option<String>`** — restore from the snapshot in the store under this prefix instead of
  a cold boot. The daemon restores via **CoW** (`MicroVm::restore_cow`), so the named snapshot is
  preserved and re-restorable; `create` then drives the mandatory post-restore resync.
- **`command: Option<Vec<String>>`** — present ⇒ `run` (exec, capture, keep-or-teardown per
  `ephemeral: bool`); absent ⇒ `create` (boot to agent-ready and register).
- **`extra_disks: Vec<ExtraDiskSpec>`** and **`extra_kernel_args: Vec<String>`** — an `ExtraDiskSpec` is
  an artifact **name** (resolved through `resolve_artifact_path`) plus an optional `io_limit`. Two
  deliberate divergences from the library, both forced by the daemon's model: **daemon extra disks are
  read-only** (the store is create-only/immutable; a writable disk backed by a shared store artifact would
  let one VM mutate an artifact another VM reads — a copy-on-attach writable-scratch disk is a follow-up,
  §17), and **no `init=` override** (the daemon owns VMs through the control plane, which a custom init
  drops). A live VM pins its extra-disk artifacts for the delete-in-use guard. A bad knob (a reserved
  kernel arg, a `0` io_limit) surfaces as the library's `Error::Config`, mapped to 400 — a
  config-validation failure is a client error, not a 500.

The daemon resolves `kernel`/`rootfs`/`restore_from` and every extra-disk name through
`resolve_artifact_path` against its own `--artifacts-dir` — a client can only ever name an artifact it
uploaded, never a host path. Snapshots land **in the artifact store**: `snapshot` writes the snapshot dir
under `<artifacts-dir>/<artifact_prefix>/…` and returns the names, so a subsequent `create {restore_from}`
restores by name — the store is the one exchange surface, no out-of-band paths. Validated end-to-end: a
marker written into a VM's tmpfs before `snapshot` survives a `restore_from` into a fresh VM.

**The OpenAPI document is generated once and gated for parity (law P5).** Rather than trust a derive
macro's output (an untested claim) or hand-maintain a separate file (a divergence trap), the document is
built by one function `openapi_document()` from the same route table the router mounts, and a parity gate
(a plain unit test, KVM-free, always runs) asserts the two agree: every mounted `(method, path)` appears
in the document, every documented path/method is actually mounted, and every component schema an operation
names exists. The `securityScheme` is declared here (bearer) and applied to every operation except
`/healthz` and `/openapi.json`; the parity gate also asserts no VM/artifact operation is missing its
security requirement. The document describes paths + auth, not request-body schemas, so additive
`#[serde(default)]` fields do not change it.

**One daemon error type, matchable, mapped to status.** Mirrors §9.5 (no catch-all; caller-relevant
conditions typed). One `DaemonError` enum, each variant carrying the HTTP status it maps to in one
`IntoResponse` impl:

```
NotFound        -> 404   (no such vm/artifact)
AlreadyExists   -> 409   (create over an existing artifact — the "no update" guard)
InUse           -> 409   (delete an artifact a live VM pins)
Conflict        -> 409   (op against a VM in the wrong state)
InvalidName     -> 400   (resolve_artifact_path rejected the name)
BadRequest      -> 400   (malformed body / knob; a config-validation Error::Config)
Unauthorized    -> 401   (missing/blank bearer)  |  Forbidden -> 403 (wrong bearer)
Unsupported     -> 501   (an op the backend does not advertise — wraps vmcell Error::Unsupported)
PayloadTooLarge -> 413   (upload past --max-artifact-bytes)
Internal        -> 500   (a wrapped vmcell::Error with no more specific mapping; body is the Display,
                          never a Debug struct-dump)
```

The error body is a small JSON `{error, message}` documented as an OpenAPI component, so a client decodes
a structured error, not a bare string.

### 11.6 Authentication — a bearer API key

The idiomatic, minimal, correct choice is a **pre-shared opaque API key presented as an HTTP Bearer
token** (`Authorization: Bearer <key>`, the RFC 6750 transport), **not** a full OAuth 2.0
authorization-server flow. Rationale, stated honestly: a full OAuth flow (an authorization server,
`/token`, grant types, JWT issuance/rotation) buys delegated third-party authorization the daemon has no
use for — it is a local, single-tenant control plane for one operator's host. The bearer *transport* is
the part of OAuth that carries the credential; adopting it (and describing it in OpenAPI as
`type: http, scheme: bearer`) gives every standard HTTP client first-class auth with zero custom flow. The
key is an opaque high-entropy secret, not a structured JWT — no signature to verify, no clock-skew window,
no rotation ceremony in v1. Comparison is **constant-time** so a timing side-channel can't leak the key
byte-by-byte.

The key is loaded from `--api-key-file` — a path, **perms-checked**: the daemon refuses a key file that is
group/other-readable (law P4). Passing the key as a CLI arg or env var is rejected in favor of the file so
it never lands in `ps` or a captured log. If no key file is given the daemon **refuses to start** (a
control plane with no auth is never an accident), unless `--allow-unauthenticated` is explicitly passed
for a loopback-only dev bind, which is logged loudly at every request.

The auth check is one tower/axum middleware layer wrapping every route **except** `/healthz` and
`/openapi.json`, so a new route is authenticated **by default** — you opt out, you don't opt in (law P4);
the parity gate asserts the opt-outs are exactly those two. The 401-vs-403 split is deliberate: **absent**
credentials are 401 (per RFC 7235, with a `WWW-Authenticate: Bearer` header); **present but wrong** are
403. Unit tests (KVM-free): correct key → 200; wrong → 403; absent → 401 with the challenge; a
world-readable key file refused at start-up; and a timing test that the compare is constant-time in shape
guards against a future `==` regression. Recorded, not built: JWT bearer tokens and per-key scopes — the
middleware seam is where they attach (§17).

### 11.7 The client library and CLI

**`vmcell-daemon-client`** offers a typed Rust API matching the `vmcell` entry points as closely as the
network boundary allows, built on `reqwest` and re-exporting the daemon's DTOs (§11.1):

```rust
pub struct DaemonClient { /* base_url, bearer key, reqwest::Client */ }
impl DaemonClient {
    pub fn new(base_url: Url, api_key: impl Into<String>) -> Result<Self>;

    // Artifact store — the divergence from vmcell entry points is HERE (paths -> upload):
    pub async fn upload_artifact(&self, name: &str, body: impl Into<UploadBody>) -> Result<ArtifactInfo>;
    pub async fn list_artifacts(&self) -> Result<Vec<ArtifactInfo>>;
    pub async fn delete_artifact(&self, name: &str) -> Result<()>;

    // VM lifecycle — one-to-one with the CLI verbs, kernel/rootfs given as artifact NAMES:
    pub async fn create_vm(&self, req: CreateVmRequest) -> Result<CreateVmResponse>;  // the general POST
    pub async fn run(&self, kernel: &str, rootfs: &str, cmd: Vec<String>) -> Result<ExecOutcomeDto>;
    pub async fn create(&self, kernel: &str, rootfs: &str) -> Result<VmInfo>;
    pub async fn exec(&self, id: &VmId, req: ExecRequestDto) -> Result<ExecOutcomeDto>;
    pub async fn stats(&self, id: &VmId) -> Result<ResourceUsageDto>;
    pub async fn snapshot(&self, id: &VmId, artifact_prefix: &str) -> Result<SnapshotInfo>;
    pub async fn ls(&self) -> Result<Vec<VmInfo>>;
    pub async fn destroy(&self, id: &VmId) -> Result<()>;               // == rm
}
```

The one forced divergence: `vmcell run --kernel <path> --rootfs <path>` becomes
`upload_artifact("k", …) + upload_artifact("r", …) + run("k", "r", cmd)` — a host path is replaced by an
upload + name reference. `upload_artifact` accepts raw bytes or a local path (v1 reads the file into
memory; streaming a large image is a follow-up, §17). The client's error type surfaces the daemon's typed
`{error, message}` as a matchable enum (a 409 `AlreadyExists` is `ClientError::AlreadyExists`, not an
opaque status), so callers branch on the same conditions the server names.

**`vmcelld-ctl`** is a thin `clap` wrapper over `DaemonClient`, reading `--daemon-url` and
`--api-key-file` from flags/env, with subcommands mirroring the client methods (`artifact put|ls|rm`,
`run|create|exec|ls|stats|snapshot|rm`). `run` streams stdout/stderr and propagates the guest exit code
exactly as `vmcell run` does. It is a wrapper only — no logic beyond argument marshaling lives here, so
its tests are argument-parsing shape tests.

---
## 12. Privilege hardening: confining the VMM

### 12.1 The problem

Everything so far makes vmcell *work*; this section makes it *contain*. The running VMM subprocess (Cloud
Hypervisor, Firecracker, QEMU) is the largest attack surface in the system: it parses guest-controlled I/O
(virtio rings, the network datapath) in a process that, on the privileged path, sits next to
`CAP_NET_ADMIN`/`CAP_SYS_ADMIN`. A guest that finds a VMM bug should hit a wall, not the host. Hardening is
three independent layers, each narrowing what the VMM can do to the host even if the layer above is
bypassed: (1) the VMM's **own** seccomp policy, (2) a **jailer-equivalent** set of pre-`exec` process
restrictions, and (3) a **setup broker** so the process that parses network input never holds the caps.
The layers compose — none of them assumes the others hold — and each is fail-loud and testable.

### 12.2 Layer 1 — the VMM's own seccomp filter

Each backend ships a syscall filter for its *own* process; vmcell's job is to make sure it is **on**, make
its state a typed choice rather than an accident, and translate that choice to each backend's dialect. The
choice is `VmConfig::vmm_seccomp: VmmSeccomp` (`Enforcing` default | `Log` | `Disabled`), and one pure
function per backend renders it:

```rust
pub fn vmm_seccomp_args(backend: &str, policy: VmmSeccomp) -> Result<Vec<String>>;
```

- **Cloud Hypervisor** — `--seccomp true` (Enforcing) / `log` (Log) / `false` (Disabled). CH's filter is
  on by default; vmcell passes the flag **explicitly** so the state is visible at the call site and in the
  process's argv, never left implicit.
- **Firecracker** — seccomp is built in and **Enforcing** by default (no flag needed); `Disabled` emits
  `--no-seccomp`; `Log` has **no Firecracker equivalent**, so it is a typed `Error::Unsupported { vmm:
  "firecracker", feature: "seccomp-log" }`, never silently downgraded to "off" or "on".
- **QEMU** — `-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny`
  (Enforcing). This is load-bearing: **QEMU runs with no seccomp at all unless `-sandbox` is passed**, so
  the earlier QEMU path — which omitted it — left the fallback backend completely unconfined. `spawn=deny`
  is the important clause (no `fork`/`exec` out of the VMM). Like Firecracker, QEMU has no "log" sandbox
  mode, so `Log` is a typed `Unsupported`.

`Disabled` exists only for diagnosing a suspected seccomp-induced failure and is a **loud, explicit**
opt-out (it widens the attack surface); it is never a silent fallback when a filter fails to apply. The
per-backend mapping is unit-tested, including that every backend's `Enforcing` renders a non-empty,
sandbox-enabling argument and that the two unsupported `Log` cases return the typed error rather than a
wrong flag.

### 12.3 Layer 2 — the jailer-equivalent (`JailSpec` + `apply_jail`)

Firecracker ships a separate `jailer` binary that hardens the process *before* `exec`ing the VMM; CH and
QEMU ship nothing equivalent. Rather than adopt FC's jailer (FC-only, and it wants to own process
creation), vmcell applies the same class of restrictions itself, uniformly across all three backends, in
the child between `fork` and `execve`:

```rust
pub struct JailSpec {
    pub no_new_privs: bool,           // PR_SET_NO_NEW_PRIVS — a set-uid bit can never regain privilege
    pub clear_ambient_caps: bool,     // drop the ambient set so the VMM cannot inherit caps (DEFAULT FALSE — see below)
    pub non_dumpable: bool,           // PR_SET_DUMPABLE 0 — no ptrace attach, no core with guest RAM
    pub rlimit_core: Option<u64>,     // RLIMIT_CORE — Some(0): no core dump (a core would contain guest RAM)
    pub rlimit_fsize: Option<u64>,    // RLIMIT_FSIZE — None on the snapshot path (a snapshot IS a large write)
    pub rlimit_nofile: Option<u64>,   // RLIMIT_NOFILE — bound the VMM's fd table
    pub seccomp: Option<Arc<BpfProgram>>, // an EXTRA vmcell-authored deny-list, ON TOP of the VMM's own filter
}
```

`apply_jail` runs in the pre-`exec` child and is written **async-signal-safe** — no allocation, no
locking, only direct syscalls — because after `fork` in a multi-threaded process the child may run only
async-signal-safe code until `execve`. Order is load-bearing and fixed: **rlimits → dumpable → ambient-clear
→ no_new_privs → seccomp → execve**. `no_new_privs` must precede the seccomp filter (installing a filter
without it requires `CAP_SYS_ADMIN` and defeats the point); the seccomp filter is installed **last** so
the setup syscalls themselves aren't filtered.

**`clear_ambient_caps` defaults to `false`, and that default is a hard-won correctness fix, not laziness.**
On the privileged tap path the VMM itself performs privileged network operations at boot — CH issues
`TapSetMac`/`TapSetOffload` ioctls, Firecracker re-opens its tap fd — which need `CAP_NET_ADMIN` *in the
VMM process*. That capability arrives via the ambient set the parent raised. Clearing it in the jailer
child stripped the capability the VMM was about to use, so every restore-with-tap test failed `EPERM` at
device setup. Because the fix is subtle, the field is explicit and defaulted off with an at-site comment;
turning it on is a real hardening increment blocked on moving tap-fd creation entirely into the broker so
the VMM never needs the cap (fd-passing, §17). Cold-boot paths that never touch a tap survived clearing it
(they don't exercise the ioctl), which is exactly why the regression was restore-with-tap-specific and
easy to miss.

**The optional extra seccomp deny-list** (`seccomp: Some(...)`) is a **defense-in-depth** filter vmcell
authors *on top of* the VMM's own (Layer 1), compiled with `seccompiler`, denying a set of syscalls no
correctly-operating VMM needs and that map to host escape or lateral movement:

```text
mount, umount2, pivot_root            # filesystem-namespace escape
kexec_load, kexec_file_load           # boot a new kernel
init_module, finit_module, delete_module  # load/unload kernel modules
ptrace, process_vm_readv, process_vm_writev  # attach to / read / write another process
bpf, perf_event_open                  # load BPF, open perf — broad kernel attack surface
add_key, keyctl, request_key          # kernel keyring
setns, unshare                        # enter / create namespaces
```

Denied syscalls return `EPERM` (not `SIGSYS`-kill), so a VMM that probes one degrades rather than dying.
The list is **default-allow, opt-in**: it is `None` by default and enabled once validated against a live
run of each backend, because a VMM that happens to need one of these at an unexercised code path would be
mysteriously broken by a `SIGSYS`. Turning it on after that validation is the plan (§17). `apply_jail`'s
pure plan (the ordered list of operations) is unit-tested; the syscall edge is thin.

**Why not chroot / uid-drop in this layer.** Two host-facing things the orchestrator does *after* the VMM
is up need the VMM reachable and signalable: the host connects to the VMM's API socket and the guest's
vsock UDS (a chroot would hide those paths), and teardown sends signals via `pidfd_send_signal`, which —
across a uid boundary — needs `CAP_KILL`. So a naive "chroot + drop to nobody" breaks the control plane
and teardown. A full jailer increment (chroot/`pivot_root` into a per-VM root, uid-drop with the fd-passing
that makes it safe) is recorded as forward work (§17); this layer does the process-restriction subset that
composes with the existing control plane today. `apply_jail` also has a `/proc/self/status` stand-in gate
that asserts the post-apply capability/`no_new_privs`/dumpable state matches the spec.

### 12.4 Layer 3 — the setup broker (network surface never holds caps)

The deepest layer addresses a structural fact the first two cannot: on the single-process privileged path,
the *same* process both parses guest/network input **and** holds `CAP_NET_ADMIN`/`CAP_SYS_ADMIN`. Layers 1
and 2 confine the *VMM child*, but the parent orchestrator — the axum server, the smoltcp NAT, the proxy —
is the cap-holder and is also on the network. The broker splits those two roles across a process boundary
(law P2): **the process on the network never holds the caps, and the process holding the caps never parses
network input.**

**Why a broker is structurally required, not merely nice.** Per-VM `setns` into a fresh network namespace
needs `CAP_SYS_ADMIN` *in the user namespace that owns the netns*. A parent that has dropped its caps can
never `setns` again. Two models can hold the caps in a separate process:

- **fd-passing model** — a privileged helper creates the netns/tap and passes *file descriptors* back to
  an unprivileged parent that spawns the VMM. Cleaner isolation, but it needs every backend to accept a
  tap **fd** (CH `--net fd=`, etc.) and a cross-process refactor of `MicroVm`, which currently creates the
  tap in-process. Recorded as the end-state (§17).
- **spawner model (chosen)** — a privileged **broker** child forks, `setns`es into the VM's netns, sets up
  the cgroup, applies the jail (Layers 1–2), and `execve`s the **VMM** inside the netns, returning the
  VMM's `pidfd` to the parent. The VMM ends up as a child of the broker at the broker's (privileged) uid,
  so the parent's later `pidfd_send_signal` for teardown works without `CAP_KILL` games. This reuses the
  in-process tap creation vmcell already has, so it ships first.

**Process topology.** The broker is forked **before the tokio runtime starts** — forking a multi-threaded
process is unsafe (only async-signal-safe code may run in the child until `exec`), so the split must
precede any thread spawn. The broker child sets `PR_SET_PDEATHSIG=SIGKILL` so it dies with the parent
(no orphaned cap-holder), and the parent drops **all** capabilities via the pure `plan_broker_parent_drop`
(the bounding-set shrink is a warned no-op without `CAP_SETPCAP`, which is fine — the effective/permitted
drop is what matters). Parent and broker speak a tiny framed enum over a `socketpair`:

```rust
pub enum BrokerRequest  { SetupNetwork(NetPlan), CreateCgroup(CgroupPlan), SpawnVmm(VmmPlan),
                          Teardown(VmId), Sweep(SweepPlan), Shutdown }
pub enum BrokerReply    { NetworkReady(NetHandles), CgroupReady, VmmSpawned { pidfd: RawFd }, Done,
                          Error(String) }
```

Frames are length-prefixed and bounded by `MAX_BROKER_FRAME_BYTES` (a broker that trusted an unbounded
length from its peer would be a trivial DoS/overflow). The broker reuses the exact same seams as the
in-process path — `Netlink`, `NftApplier`, `CgroupFs`, `OrphanScanner`, and `build_vmm_cmd` + `apply_jail`
— so there is **one** implementation of network/cgroup/spawn/jail logic, brokered or not; the broker is a
*location*, not a fork of the logic. The `vmcell` crate's `net-privileged` + `metrics` subset compiles
into the broker; **axum/hyper never do** (its own lean-tree assertion, §9.1).

**What actually shipped: the "fat", engine-owning broker.** Rather than broker only the privileged
syscalls and keep VM ownership in the parent, the shipped design puts the whole VM **`Registry` in the
privileged broker child**, and the HTTP-serving parent forwards every VM operation to it over a
multiplexed `VmEngine` JSON-RPC channel. This fell out of the constraint that the parent must drop caps
before it serves HTTP, but VM operations (create/exec/snapshot/teardown) *need* the caps throughout the VM
lifetime, not just at spawn — so the cap-holder has to be the thing that owns the VMs. Consequences worth
knowing:

- **JSON, not postcard, on the engine channel.** The forwarded DTOs use `#[serde(skip_serializing_if)]` /
  `#[serde(default)]`, and postcard's non-self-describing format silently corrupts round-trips of exactly
  those attributes (it encodes fields positionally, so a skipped field shifts every later field). A
  self-describing format (JSON) is required for DTOs that use serde's presence/absence attributes; the
  broker's *own* control enum, which uses neither, stays framed-binary. (This is the same class of finding
  as the daemon-DTO reversal — presence-dependent serde attributes need a self-describing codec.)
- **Multiplexing.** Each forwarded request carries a `u64` id and the parent matches replies via a per-id
  oneshot, so concurrent client requests to different VMs pipeline over the one engine channel without
  head-of-line blocking between VMs.
- **`--no-setup-broker` fallback.** The single-process retain-caps path (§11.2) stays for environments
  where the fork-before-runtime split is unwanted; it holds the caps in the serving process, which is the
  weaker posture the broker exists to fix. Validated end-to-end: `just test-daemon` boots `vmcelld` under
  the broker and drives 12/12 VM-lifecycle operations with the serving parent cap-dropped.

The **thin** broker (broker only `SpawnVmm`+pidfd, keep the `Registry` in the parent) remains the
cleaner long-term shape and is the fd-passing end-state's companion (§17); it needs the cross-process
`MicroVm` refactor the fat broker sidestepped.

### 12.5 The licensing constraint on seccomp crates

The seccomp layers pick **`seccompiler`** (the rust-vmm compiler, Apache-2.0 / BSD-3-Clause) — the same
library Cloud Hypervisor and Firecracker themselves use, so it is proven against this exact workload and
adds no new license class. This choice is a **hard constraint**, not a preference, and it is the one place
the license gate needs a name-based rule rather than trusting crate metadata:

| Crate | License (metadata) | Verdict |
|---|---|---|
| `seccompiler` | Apache-2.0 / BSD-3 | **chosen** — pure-Rust BPF compiler, no C lib |
| `libseccomp`, `libseccomp-sys` | metadata varies | **banned** — link the LGPL-2.1 C `libseccomp` |
| `syscallz`, `seccomp` | permissive metadata | **banned** — wrap `libseccomp-sys` → same LGPL-2.1 C lib |
| `birdcage` | permissive metadata | **banned** — pulls the same C-lib transitive edge |

The trap: the Rust *wrapper* crates advertise a permissive license in their `Cargo.toml`, but they
dynamically link the **LGPL-2.1 C `libseccomp`**, and that C dependency is **invisible to `cargo-deny`'s
license scan** (which sees only the Rust crate graph). So the ban is enforced by an explicit
`deny.toml [bans]` entry naming each wrapper crate, not left to the license allow-list — the one case in
the whole dependency strategy (§9.6) where metadata is insufficient and a by-name rule is required.

---
## 13. Cross-cutting invariants

The invariants each subsystem must uphold, gathered in one place as a checklist. Each is stated once, with
its owner, the gate that enforces it, and a pointer to the section where the mechanism lives — the
mechanics are **not** repeated here. A change that trips one of these is a design-level regression, not a
style nit. They are lettered by family so code and review can cite them (`S3`, `C6`, `P2`).

**S — Snapshot / clone semantics** (§8)

- **S1 — vhost-user ⇒ not snapshottable.** A VM is snapshot-eligible only if **no** vhost-user device
  (any virtiofsd — including a read-only data share — the unprivileged NAT, or an external vsock daemon)
  is attached. *Owner:* `config::build` + `orchestrator::restore` + backend self-guard, all through the
  one shared `config_has_vhost_user_device` predicate. *Gate:* negative build/restore tests per case +
  the shared-predicate unit test + the "extra virtio-blk does not flip the predicate" test. → §8.1.
- **S2 — a restored VM is not a fresh VM.** Every restore refreshes four frozen things — CID (live-unique,
  reuse allowed), MAC **and** IP (rotated at the device layer), entropy (CSPRNG reseed), and clock
  (host-driven) — in one native `Resync` round-trip on the first post-restore `agent()`. *Owner:*
  `orchestrator::restore` + the guest agent's `netif`/resync. *Gate:* `snapshot_restore.rs` asserts a
  live-valid CID (not `assert_ne`), a rotated MAC *and* IP (little-endian gateway compare via
  `/proc/net/route`), a pre/post RNG change without a test-issued reseed, and a first-call `FakeClock`. →
  §8.2.
- **S3 — the master is immutable; clones restore from private CoW copies.** A single-use `restore`
  rewrites its snapshot dir in place, so minting many VMs from one image restores each from its own
  CoW copy, leaving the master byte-for-byte intact and re-cloneable. Extends to every lineage **branch**
  node. *Owner:* `orchestrator::restore_cow` / `Zygote` / `Lineage`. *Gate:* the fan-out test asserts the
  master `config.json` is byte-identical afterward. → §8.4.
- **S4 — every CoW clone goes through `env.overlay`.** Clone materialization is the injected
  `OverlayStore::clone_tree(master, private_dst)`, never an ad-hoc copy, and `dst` is always a fresh
  private dir inside the clone's scratch (never the master). *Owner:* `orchestrator`. *Gate:* the
  `RecordingOverlayStore` fan-out test asserts N distinct private dsts, none equal to the master. → §8.4.
- **S5 — lineage is immutable, acyclic, cross-family-safe.** A branch node's parent is fixed at creation,
  generation strictly increases, ancestry is `parent.ancestry ++ [parent.id]`, and `is_ancestor_of` first
  checks a shared allocator via `Arc::ptr_eq` so ids from distinct allocators never false-positive.
  *Owner:* `lineage`. *Gate:* the cross-allocator ancestry unit test. → §8.5.

**C — Control-plane discipline** (§3)

- **C1 — the agent is PID 1 and behaves like an init.** It mounts `/proc`, `/sys`, `/dev/pts`, sets up the
  tmpfs overlay, reaps **all** children (not only its own sessions), and **never exits** — any exit panics
  the guest kernel. *Owner:* `vmcell-guest-agent`. *Gate:* the never-exit reviews + the reaper unit tests.
  → §3.4.
- **C2 — the vsock handshake has exactly three traps, and the host respects them.** Fresh connection per
  attempt (a refused connect poisons the socket for retries), read the `Ready` frame to completion before
  writing, uniform bounded timeout on connect/handshake. *Owner:* `agent::AgentClient`. *Gate:* the
  handshake FSM unit test over all three. → §3.2.
- **C3 — a connection owns its sessions; loop exit SIGKILLs their process groups.** When a control
  connection's dispatch loop ends, every process group it spawned is `kill(-pgid, SIGKILL)`'d, so no
  guest process outlives the connection that created it. *Owner:* `vmcell-guest-agent`. *Gate:* the KVM
  connection-drop residue test (`sh -c 'echo $$; sleep 600'`, then drop, then assert the pgroup is gone).
  → §3.4.
- **C4 — one writer per connection, both ends.** The host multiplexer and the guest dispatcher each have a
  single task that owns writes to a given vsock connection; frames from concurrent sessions are queued to
  that writer, never written from multiple tasks. *Owner:* `agent::session` (host) + the guest dispatcher.
  *Gate:* two window-filling self-identifying streams show zero cross-attribution. → §3.4.
- **C5 — session I/O is channelized with exactly one terminal `SessionExit`.** Each session's
  stdout/stderr are tagged frames; a session ends with exactly one `SessionExit` (a spawn failure is
  `SessionStderr` + `SessionExit(127)`); frames arriving after a session's exit are dropped, never
  misattributed. *Owner:* `agent::session` + the guest dispatcher. *Gate:* the demux interleave +
  post-exit-drop unit test over a tokio duplex. → §3.2 / §3.4.
- **C6 — zero netlink in PID 1.** The guest configures its network via the kernel `ip=` cmdline and
  device-layer ioctls (`SIOCSIF*`), never a netlink/`rtnetlink` bring-up. *Owner:* `vmcell-guest-agent`.
  *Gate:* a **structural** `cargo tree -e no-dev` assertion that the agent crate has no `rtnetlink`
  dependency (there is no seam to fake because the manual bring-up was deleted). → §3.4 / §9.8.
- **C7 — a PTY session is a controlling terminal with a session leader.** `setsid` + `TIOCSCTTY`,
  `isatty` true in the guest, and host `Winsize` changes forward as `SIGWINCH`. *Owner:* the guest
  dispatcher's PTY path. *Gate:* an in-guest `test -t 0 && stty size` + a resize assertion, with a
  pipe (non-PTY) negative control. → §3.4.

**L — Lifecycle / teardown** (§9.4)

- **L1 — teardown is ownership; one ordered helper cleans up, even on panic.** Resource release order is
  fixed — proxy/smoltcp NAT before the netns, VMM **process group** (`kill -9 -pgid`) first once an
  instance exists, then virtiofsd, then netns/cgroup/overlay/scratch — and the success path
  (`teardown_post_instance`), the error path (`EnvSetup::drop`), and every registry teardown variant
  (`destroy`/`shutdown_all`/`Drop`) all call the **same** helper. A hard kill that skips `Drop` is
  reclaimed by the start-up sweep against an empty live set. *Owner:* `orchestrator` + `vmcell-daemon`'s
  registry. *Gate:* the drop-order recording gate + the panic-residue-vs-computed-paths lifecycle test. →
  §9.4 / §11.4.

**F — Fail-loud / naming / cmdline / cache**

- **F1 — a missing capability fails loud, never a silent no-op.** A *requested functional* op whose OS
  capability is absent returns a typed `CapabilityUnavailable`; only an explicitly-listed best-effort knob
  (the benchmark levers) degrades to a `warn!`. *Owner:* `metrics` + `net` + `HostCapabilities`. *Gate:*
  the `CgroupFs`-fake `CapabilityUnavailable` test + the errno-split unit test. → §7.2.
- **F2 — one prefix names and sweeps every per-VM resource.** A single `resource_prefix` composes every
  per-VM resource name **and** every orphan-sweep filter through `vmcell::naming`, so a produced name can
  never fall out of lockstep with the filter that reaps it. *Owner:* `vmcell::naming`. *Gate:* the
  "every produced name starts-with its sweep filter, for any prefix" unit test. → §9.3 / §11.4.
- **F3 — extra kernel args are append-only.** A caller's `extra_kernel_args` may add a parameter but never
  clobber a token vmcell owns, enforced by the one `is_reserved_cmdline_arg` predicate (reserved-key set +
  `vmcell_` prefix guard + single-token guard). *Owner:* `config`. *Gate:* the gate that builds a cmdline
  exercising every emitted token and asserts the predicate rejects each key. → §5.3.
- **F4 — cache keys are content-addressed and deterministic.** Five rules: stable hasher, deterministic
  input order, content/identity-not-paths, per-stage version + source SHA, validity by content not
  existence. *Owner:* `artifact`. *Gate:* the `cache_key` golden test against a **real** stage + the
  tamper-rejected test. → §10.2.

**P — Privilege / daemon** (§11–§12)

- **P1 — the cap-holder retains caps; it never drops-and-execs to serve.** A long-lived privileged process
  runs the effective-set precondition and keeps its caps (no uid drop / ambient raise / bounding shrink /
  exec) for the whole lifetime, and **refuses to start** if the precondition fails — never a degraded
  server that fails privileged ops at first use. (The *transient* runner is the opposite by design: it
  drops and execs.) *Owner:* `vmcell-daemon` + `vmcell-privilege`. *Gate:* the daemon start-up
  precondition test + the runner's transition tests. → §11.2.
- **P2 — the broker model: the network surface never holds caps, the cap-holder never parses network
  input.** By default `vmcelld` forks a privileged broker that owns the caps (and, as shipped, the VM
  `Registry`) while the HTTP-serving parent drops all caps; the two speak a bounded framed protocol.
  *Owner:* `vmcell-broker` + `vmcelld`. *Gate:* `just test-daemon` drives 12/12 VM ops with the serving
  parent cap-dropped. → §12.4.
- **P3 — every client-named artifact goes through `resolve_artifact_path`.** One allowlist validator turns
  a client string into `dir.join(name)` with `name` a single safe component; no caller constructs
  `dir.join(client_string)` itself. *Owner:* `vmcell-daemon`. *Gate:* the red-on-inverse validator tests +
  a grep gate on `dir.join(` outside the validator. → §11.3.
- **P4 — authenticated by default; secrets never sit in process-visible surfaces.** The auth layer wraps
  every route except exactly `/healthz` + `/openapi.json` (opt-out, not opt-in); the key is loaded from a
  perms-checked file (never a CLI arg or env var), compared constant-time; `RLIMIT_CORE=0` keeps a VMM
  core from dumping guest RAM. *Owner:* `vmcell-daemon` + `vmm::jail`. *Gate:* the auth 200/403/401 tests +
  the world-readable-key-file-refused test + the opt-out-set parity assertion. → §11.6 / §12.3.
- **P5 — the served OpenAPI and the mounted routes are one table.** The document is built from the same
  route table the router mounts, and a parity gate asserts every mounted `(method, path)` is documented,
  every documented one is mounted, every named schema exists, and every non-meta op carries the security
  requirement. *Owner:* `vmcell-daemon`. *Gate:* the OpenAPI-parity unit test. → §11.5.

**G — Keep the primitive general**

- **G1 — no domain policy in the core.** `vmm`/`agent`/`orchestrator`/`metrics` (and the guest agent) hold
  **no** workload-, tenant-, or product-specific policy; the core is a workload-agnostic capability and a
  consumer crate supplies domain policy. Share tags, egress rules, and resource limits are all
  caller-supplied, never built-in. *Owner:* every core crate. *Gate:* review against the out-of-scope
  boundary list (§17) — naming the consumer layers is itself the guard. → §1.3.

Two invariants live with their subsystems rather than here, and are cited from it: the **cgroup edges**
that make a memory cap actually bind (sibling placement, non-threaded `domain` scope,
`swap.max=0`+`oom.group=1`) are §7.3, and the **NAT's five silent-wedge invariants** (source-MAC
collision, RX-only-when-queued, TX notification, socket-pool sizing, bounded host reads) are §6.2. They
are subsystem-local because nothing outside their module can violate them, but they are the same *class* of
load-bearing rule as the lettered set above.

---

## 14. Hard-won lessons

Five conclusions from building this that are cheap to state and expensive to re-learn. They are the
*why* behind the testing discipline (§15) and the benchmark discipline (§16); each is a rule, not an
anecdote.

1. **A path with no test that can fail has never run.** The single most expensive class of bug here was
   code that looked exercised but was not — a "leaked-VM" test that spawned a VM, never asserted teardown,
   and passed for weeks while hanging the suite for 30 minutes on a real run. The rule that falls out:
   every test must be able to **fail on the inverse** of what it claims (§15). A green test that cannot go
   red proves nothing.
2. **Only interleaved, same-session benchmark deltas are trustworthy.** Absolute latency numbers wander
   with host load, thermal state, and background noise; a number measured in one session and compared to a
   number from another session is measuring the sessions, not the change. Every performance claim here is
   an A/B delta measured **back-to-back in one run** (§16). A cross-session "~2× slower" scare turned out
   to be host-load noise, and cost real time before it was re-measured interleaved and vanished.
3. **Measuring disproves wrong beliefs — plural.** At least three confidently-held hypotheses inverted
   under measurement: the guest kernel version was assumed a hot-path lever (it is not, within ~2% on the
   warm path); CH's lazy-restore was assumed strictly faster (it front-loads, and the cost reappears as
   first-touch page faults); a fashionable set of microVM cmdline trims was assumed to help (a
   `printk`-timestamp probe showed they target probes that never run here). The discipline: a plausible
   mechanism is a hypothesis to **measure**, never a fact to ship on.
4. **"Environmental" flake is a hypothesis, not a diagnosis.** A recurring test failure was papered over
   with `nextest` retries for weeks under the label "environmental," until it was root-caused to a real
   guest-reaper epoch race (the AGENT-2 finding). Retries are a **backstop for genuinely residual**
   host-level noise, never a substitute for root-causing a reproducible failure — and the way to tell them
   apart is to **control against a known-good baseline**: the flake was isolated by re-running the exact
   suite against a git-stashed baseline until it was clear the failure tracked a code change, not the host
   (a specific `kvm_intel` EPT symptom clustered on one machine, which is what "environmental" is *supposed*
   to mean).
5. **The dev host is the KVM host — "forward work" is legitimate only when preflight says NOT READY.** The
   integration suites need KVM, and the machine running them has it. So a preflight check that prints
   **READY** means the right next step is to *run the suites now*, not to defer them; deferring real
   validation with the suites available is how review-only correctness bugs accumulate. "Forward work" is
   an honest label **only** when a preflight check prints **NOT READY** and names the specific failed
   capability (no `/dev/kvm`, no nested virt, a missing `nft`) — at which point the deferred item is
   recorded with its blocking check, not hand-waved.

---
## 15. Testing strategy

### 15.1 Philosophy: green is necessary, not sufficient

The organizing principle is a direct consequence of §14 lesson 1: **a passing test suite proves nothing
unless each test can fail on the inverse of what it claims.** This project has concrete evidence for why —
the suite passed green while *four* distinct implementations were broken, because the tests asserted that
code *ran*, not that it was *correct*. So the bar for every test is: **negate the behavior under test and
the test must go red.** A test that stays green when the thing it checks is broken is deleted or fixed, not
kept for coverage. The rest of this section is the machinery that makes that bar enforceable.

### 15.2 Lint and structural gates (compile-time, always on)

These run on every build and fail it, so a whole class of defect never reaches a test:

- **Deny-by-default lints under `not(test)`:** `unwrap`/`expect`/`panic`/`unreachable`/`todo`, arithmetic
  that can silently wrap, direct slice indexing (`clippy::indexing_slicing` — use `get`), and
  `print`/`eprint` (the library emits `tracing`, never stdout). Plus `missing_docs` (every public item is
  documented) and a lint requiring every `unsafe` block to carry a `// SAFETY:` justification.
- **`#![forbid(unsafe_code)]` on every I/O-free / logic module** — `net/` (its one irreducible ioctl is
  quarantined in `net_sys.rs`), `config`, `naming`, `artifact`'s pure core, the protocol codec — so unsafe
  can physically only live in the few modules that have a documented reason for it.
- **`RUSTFLAGS=-D warnings`** applied process-wide in `just ci`, over `clippy --all-targets
  --all-features` and `cargo fmt --check`.
- **The feature powerset compiles** — a blocking gate that builds every feature combination (§9.7), the
  fix for the feature-gating build breaks the fine-grained matrix used to cause.
- **Per-member lean-tree assertions** — `cargo tree -e no-dev` proves `vmcell-guest-agent`,
  `vmcell-test-runner`, `vmcell-privilege`, and `vmcell-broker` pull no `tokio`/`hyper`/`rtnetlink`
  (`guest-tools` is exempt, §9.7), and that both `vendor/vhost*` crates resolve from `vendor/` (§9.6).
- **`cargo-deny`** enforces the license allow-list + the seccomp-crate by-name bans (§12.5) + the
  advisory-ignore set (§9.6), and **`cargo semver-checks`** gates every public-surface change.

### 15.3 Unit tests (no KVM, no root) — the pure cores and the seams

Everything that can be tested without a VM is, against the injectable seams (§9.8) and the pure functions
(§9.8 item 2). The point of each is a *named invariant with a red-on-inverse assertion*, not line
coverage. By category, with the load-bearing ones named:

- **Pure arithmetic / codecs:** the `/30` address math (octet `= (vmid % 254) + 1`, no address > 255); the
  protocol codec **round-trips** every `Message` variant (an encode-only test would miss a decode bug);
  `mac_math` collision-freedom against the NAT's reserved MAC; `cache_key` **golden** vs a **real** stage
  (rules of §10.2); `KernelVerbosity`/`ConsoleMode` → cmdline token; `Timeouts::clamped()` at each floor;
  `parse_ms` clamp (garbage/overflow → default); the `ifreq`/`Winsize` struct layouts; `winsize_from`
  rows/cols; `child_path`/scratch-dir construction.
- **State machines / parsers:** the vsock handshake FSM over its three traps (§3.2); the CH REST restore
  config parser/rewriter; the `nft` ruleset renderer (**golden** output); the accept-loop deadline helpers
  and the reaper's "reserve after drain" ordering; the discriminant-stability check pinning the wire
  variants to `8..=15` (§3.1).
- **Seam behaviors (recording fakes):** the `CgroupFs` fake returns `CapabilityUnavailable` for an
  undelegated controller and the errno-split maps `EINVAL`→`Cgroup` / `EACCES`→`CapabilityUnavailable`
  (§7.2); the shared cmdline builder emits `loglevel=` on **all** backends (the QEMU-regression pin,
  §5.3); the `is_reserved_cmdline_arg` all-tokens gate (§5.3); path injectivity — the artifact-name
  validator's red-on-inverse battery (§11.3, a property test over the accepted byte-class); the
  drop-order recording gate (§9.4); the `demux` interleave + **post-exit-drop** over a tokio duplex (§3.2).

### 15.4 Integration tests (KVM required) — split by mode, honest about capability

VM-touching tests are `#[ignore]`d (so `cargo test` stays hermetic) and run explicitly with `--ignored`
under the capability runner (§15.5). `nextest` places them in a **serial host group** that positively
selects `package(vmcell) & kind(test) & !binary(proptests)` — a *positive* selector, so a newly-added
integration binary is included by default rather than silently left out of the serial group (a negative
"everything but X" selector is the divergence trap). The suite splits along the two operating modes (§6.1):
a privileged-mode suite (netns+tap+snapshot) and an unprivileged-mode suite (smoltcp NAT, no snapshot).

**Capability honesty is enforced, not documented.** On the **primary** backend (Cloud Hypervisor) a
missing capability is a hard `require_cap!` **panic** — CH is the reference and a silent skip there would
hide a real regression. On the fallback backends (Firecracker, QEMU) a missing capability records a
**SKIP** to a `VMCELL_SKIP_MANIFEST` manifest instead, so the run surfaces exactly what did not execute
rather than passing by omission. A per-flag capability-honesty test pins all seven capability flags
(`snapshot_restore`, `nested_virt`, `virtio_fs_shares`, `virtio_console`, the two seccomp-log unsupporteds,
`restore_rotates_host_paths`) to the backend that actually supports them, so a flag that lies (advertising
a capability the backend lacks, or vice versa) goes red. **Zero selected tests is a CI failure**
(`nextest`'s `--no-tests=fail`), so a mis-scoped filter that silently selects nothing fails loudly instead
of passing. `nextest` **retries** (exponential, count 3, 5 s→20 s) are configured as a backstop for
genuinely residual host noise only (§14 lesson 4) — never a substitute for root-causing a reproducible
failure.

The exemplar suites, each written so its assertions **fail on the inverse**:

- **`snapshot_restore.rs`** (the S2 battery, §8.2): reconnect across the **severed** vsock (the restore
  re-creates the vhost-vsock device, so a test that reused the old connection would hang); assert a
  **valid, live** CID, not `assert_ne!(orig, restored)` (which would fail *because* CID reuse is correct);
  assert the MAC **and** IP both rotated (the IP check compares the little-endian default-gateway from
  `/proc/net/route`, since a "MAC-only" assertion passed while every clone sat on a dead `/30`); assert the
  CSPRNG changed across restore **without** a test-issued reseed; assert `FakeClock` was read on the
  **first** post-restore `agent()`; and a per-backend `restore_rotates_host_paths` branch that expects
  concurrent fan-out on CH and a single-clone-only path on FC.
- **`zygote.rs`** (the S3/S4 fan-out, §8.4): N concurrent clones each get a **distinct** vmid, a MAC equal
  to `mac_math(vmid)`, and distinct vsock paths; the master `config.json` is **byte-identical** after the
  fan-out; a non-rotating backend returns `Unsupported` for `count > 1` while a single clone succeeds; and
  the `RecordingOverlayStore` shows the fan-out targeted N distinct private dirs, none the master.
- **One-liners that each pin one past bug:** `egress_proxy` (a double matches on the label **boundary**,
  and a `CONNECT` falls through rather than being matched, §6.4); `metrics_limits` (a bound guest shows
  `memory.events oom_kill > 0`, **not** an exit-137 heuristic, §7.3); `lifecycle` (after a forced panic the
  computed netns/tap/cgroup/scratch paths are **gone**, §9.4); `put_file` round-trips a payload through the
  agent.
- **Pipeline tests:** a tamper test **corrupts the artifact bytes while keeping the `.cache_key` sidecar**
  and asserts rejection (§10.2 rule 5); a warm-cache run does **zero** upstream fetches; `reset_to` removes
  exactly the named stage's and later outputs; an agent-source change **re-bakes** the rootfs (the
  stale-agent handshake-bug pin).
- **Daemon + `vmcelld`:** the KVM-free daemon gates (auth 200/403/401, OpenAPI parity, artifact-name
  red-on-inverse, delete-in-use) run always; the KVM `vmcelld` integration suite **inverts the runner** —
  the test binary itself holds the caps and spawns `vmcelld` directly in a systemd-delegated scope, then
  drives the data plane (create → exec → snapshot → `restore_from` → destroy) and asserts a tmpfs marker
  survives a restore into a fresh VM, condensing to the 12/12 cap-dropped operations of §12.4.

### 15.5 The capability test runner (`vmcell-test-runner`)

Privileged integration tests get their caps from a **`nextest` target-runner**, not `sudo -E cargo test`
(which runs the *whole* suite as root and pollutes `target/` ownership). The runner is a lean
(`rustix`/`capctl`/`libc`, never the `vmcell` library) cap-conferring `exec` wrapper: file-caps → raise
the three caps into the **ambient** set → drop to the invoking uid → `execvp` the test binary, so **only**
the test process — at the dev uid — runs privileged, and `target/` stays dev-owned. It confers `+ep` on
the *runner* (`vmcell-test-runner`), not `+p` on every test binary.

Two subtleties are load-bearing:

- **Confinement anchors on the runner's own path, not the argument's.** The runner refuses to exec
  anything whose canonicalized path is not under the workspace `target/` — but it derives that `target/`
  from **its own** `current_exe()` (walking up from the blessed `.vmcell-bin/<profile>/vmcell-test-runner`
  to `<workspace>/target`), **not** from the target argument. Anchoring on the argument's own `target/`
  ancestor is inert (a malicious argument would validate itself); anchoring on the *runner's* location is
  the real boundary. Because the OS strips file-caps on any binary rewrite, a tampered runner simply loses
  its caps — the blessing is self-invalidating, which is a feature.
- **`just bless` installs to a gitignored, mode-checked location.** It copies the runner to
  `./.vmcell-bin/<profile>/`, `chmod 0700`s it, `setcap`s it, and records a content-hash `.blessed` stamp
  **keyed on the runner binary only** (so a rebuild of the runner re-blesses, but a rebuild of an ordinary
  test binary does not). `CAP_SETPCAP` is typically absent, so the bounding-set shrink is a **warned
  no-op** (the effective/permitted path is what matters); a `setuid`-fallback path (for hosts without
  file-cap support) is verified by a pure transition test that asserts the uid change happens **before**
  the ambient raise. This whole mechanism is **dev-workstation only** — production `vmcelld` uses
  file-caps or systemd ambient caps (§11.2), never this runner.

---
## 16. Performance

**Framing (§14 lessons 2–3).** These numbers are **tracked metrics, not gates** — a benchmark number is
meaningless without the substrate it was measured on, and only same-session interleaved A/B deltas graduate
to guards (the last subsection). Every macro number below is a central tendency (median or trimmed mean)
over repeated runs on one substrate, quoted as a representative figure, not a spec.

**Substrate.** Intel Core Ultra 7 258V (8 cores / 8 threads, Lunar Lake), 30 GiB RAM, ext4-on-NVMe with
`/tmp` a tmpfs; Cloud Hypervisor v52.0.0, Firecracker v1.16.0, QEMU 10.2.1, virtiofsd 1.13.3, guest kernel
6.12.94, CPU frequency pinned to 2.2 GHz for measurement stability. "**Cold**" throughout means
**warm-cache** (artifacts already built) cold *boot*, not a from-scratch pipeline build.

**A measurement-methodology fix that moved every historical p95.** The percentile helper used
`floor(n·q)`, which for small `n` returned an index at or past the last element, so effectively **every
p95/p99 collapsed to the max** — making tail numbers look worse and noisier than reality. The corrected
estimator is nearest-rank `ceil(q·n) − 1` on the sorted sample. Any tail figure recorded before 2026-07-03
is on the old estimator and is **not comparable** to a current p95; the medians are unaffected.

**Micro-benchmarks** (representative): protocol frame **encode ≈54.8 ns**, **decode ≈86.2 ns**;
`cache_key` ≈260 ns; IP/`/30` parse ≈23.2 ns; the in-memory `tar→erofs` inner step ≈1.26 µs. These are
far below the millisecond floor of any VM operation and never dominate.

**Macro — cold boot to agent-ready** (warm-cache; p50 / p95 ms):

| Backend | p50 | p95 | notes |
|---|---:|---:|---|
| Cloud Hypervisor | 316 | 331 | ≈290 on the `low_latency` profile |
| Firecracker | 764 | 792 | |
| QEMU (q35) | 965 | 995 | after the shared-cmdline fix (was ≈1400) |

**Macro — warm restore to agent-ready** (p50 / p95 ms):

| Backend | p50 | p95 | notes |
|---|---:|---:|---|
| Firecracker | 24 | 33 | ≈23 / 28 on `low_latency` — the fastest restore |
| Cloud Hypervisor | 58 | 67 | ≈54 / 66 on `low_latency`; ≈5.4× faster than its cold boot |
| QEMU | — | — | restore not wired on the fallback backend |

**End-to-end throughput** (full lifecycle, ms): CH cold create→exec→teardown ≈361, CH **restore path
≈120**; Firecracker **restore ≈64** (create ≈13 + connect ≈13 + exec ≈10 + teardown ≈31), FC cold ≈848;
QEMU cold ≈1080. Standalone graceful teardown alone: CH ≈56, FC ≈78, QEMU ≈92.

**The optimization narrative, condensed** — each item is an interleaved A/B delta, and several inverted a
prior belief (don't re-derive these):

- **Console verbosity was the single biggest cold-boot lever.** Dropping to `loglevel=6` removed ≈231 ms
  of synchronous byte-at-a-time UART writes; a console A/B showed **558 ms verbose vs 316 ms** on CH. On a
  virtio-console the same verbosity delta nearly vanished (299 vs 291) — confirming the cost was the UART
  device, not the logging.
- **Accept-loop cadence, then event-driven accept.** The guest accept poll went 100 → 20 ms, then
  (experiment EXP-C) to a genuinely **event-driven `poll(2)`**, cutting restore-connect from **16.6 → 4.6
  ms**.
- **Deadline-before-RPC + adaptive teardown step** (EXP-D) cut standalone teardown **95 → 56 ms** (§9.4).
- **cmdline trims** removed the crypto self-test (≈9.7 ms) and RAID autodetect (≈2 ms) — a real but small
  CH −6 / FC −4 ms, and the *only* trims a `printk`-timestamp probe justified (§5.3).
- **The shared cmdline builder** (fixing QEMU's dropped `loglevel=`) took QEMU cold **≈1400 → ≈996 ms**.
- **Native in-agent resync** replaced three subprocess `exec`s on the restore hot path (§8.2).
- **CH lazy vs eager restore inverted the intuition:** lazy restore is ≈176 ms vs eager ≈258 ms *to
  resume*, but the deferred cost **reappears as first-touch page faults** during execution — faster to
  resume, not faster overall. It is a `RestoreMode` knob, not a default win.
- **Cold boot is dominated by the guest itself:** ≈79–89 % of cold-boot time is the guest kernel+userspace
  coming up; the CH REST config round-trip is ≈1 ms. Optimizing the host orchestration further has little
  headroom on cold boot — the restore path is where the wins are.

**Density** (from §8.3, measured): a CH guest demand-pages ≈58 MiB of a 256 MiB allocation; marginal RAM
per added idle guest ≈58 MiB, giving ≈**230 idle** guests (≈52 if each faults its full 256 MiB) in ≈13 GiB
free on the 30 GiB substrate; the agent PID 1 is ≈2.4 MiB. KSM merges **0** by default on CH (shared
memfd) and ≈**394 MiB / ≈84 %** across 8 identical guests when explicitly enabled (`shared=off`,
mutually exclusive with vhost-user). A suspend image is ≈268.5 MB for a 256 MiB guest — it **tracks guest
RAM, flat in rootfs size**. An OCI-sourced rootfs is ≈79 MB vs ≈120–129 MB for `mmdebstrap` (the size
inversion, §4.2); a static-musl agent adds ≈6.2 %.

**A per-phase budget** (representative, ms) — where the time actually goes:

| Phase | Cold (CH) | Restore |
|---|---:|---:|
| connect | 266 | 4.6 |
| create / restore+resume | 44 (create) | 54 |
| exec (one command) | 4 | 1 |
| teardown (Drop) | 27 | 27 |

Graceful teardown's ceiling is ≈265 ms (the full `shutdown_grace`) vs ≈27 ms for a `Drop` hard kill —
which is why `throughput()` cuts the grace. Exec round-trip alone is ≈0.7 ms p50 / ≈852 µs … ≈1013 µs
across p95/p99.

**The guards rule (§14 lesson 2).** Only **relative invariants** graduate from tracked-metric to
CI guard, because they survive substrate changes: the OCI-vs-`mmdebstrap` size relationship, the working
set staying flat in rootfs size, a suspend image staying flat in rootfs size, and the per-phase *shares*
(connect-dominated cold boot, resume-dominated restore). **Absolute latencies are never gated** — they
would red on any slower CI box.

**Deferred optimization opportunities (don't re-derive — mechanically refuted in `docs/45`).** Parallel
`virtiofsd` startup is a real latency win but `try_join_all` is cancellation-unsafe (a failed spawn would
leak the others' half-started daemons) and, worse, it is **invisible on the tracked benchmarks** (which
run zero data shares), so it stays deferred. NAT pump-cadence tuning is deferred. A ≈22 ms
`fs_initcall`-region gap and a ≈5.7 ms `cfg80211` `regulatory.db` load are observed-but-unattributed and
not chased. A 12-item opportunity-reject table in `docs/45` records each rejected micro-optimization with
its refutation — consult it before proposing one. Full experiment logs live in `docs/benchmark-results.md`,
`docs/44-claude-perf-experiments.md`, and `docs/45-claude-perf-investigation.md`.

---

## 17. Open gaps and future capabilities

The honest current state, organized by subsystem. Everything here is either wired-but-unvalidated,
validated-but-unwired, or deliberately deferred with a known blocker (§14 lesson 5: "forward work" is
legitimate only when a preflight check names what is missing). Nothing here is load-bearing for the
shipped design.

**Backends & boot.** Firecracker UFFD lazy-restore is unwired (single-lineage verbatim-vsock only, §8.4).
A privileged QEMU vhost-vsock tier is validated but unwired. `mkfs.erofs` shell fallback is designed but
unimplemented — a missing packer input is fail-loud today (§4.2). Cross-version snapshot pinning: the
snapshot cache key already folds CH build identity so a bump invalidates stale snapshots at build time
(§10.2), but the *runtime* "restore under the CH it was taken on" advice is still just advice.

**Storage & shares.** A per-share service-uid allocator for `virtiofsd` (§4.5). `fuse-backend-rs` as an
in-process share backend is gated behind `experiment-fuse` but must enforce read-only before it can
graduate (today a RO share on it is a typed `Unsupported`, §4.5). A writable-scratch extra disk
copied-on-attach from a store artifact (the daemon's read-only-disk limitation, §11.5).

**Networking.** `Egress::Open` provides no *arbitrary* outbound egress in either mode — closing it needs
real destination re-origination (or a typed `Unsupported`), §6.2. Per-VM network byte counters need a new
netns-scoped usage type reading `/sys/class/net/<if>/statistics` (§7.1). Privileged-path `host_services`
wiring (a TPROXY accept rule + a host binding) would re-add the `host_services_port` field on the
privileged variant (§6.2). The ≈254-VM-per-`/16` ceiling from the `(vmid % 254) + 1` octet map (§9.3). A
fully-automatic periodic orphan sweeper (the daemon already closes its own crash-restart case, §11.4).

**Daemon.** A UDS transport under `XDG_RUNTIME_DIR` (alongside the HTTP bind). A warm-pool manager
(`POST /v1/pools`) — because the registry already owns handles, a pool is a **hand-out policy** over the
existing fan-out capability, not a new primitive (§11.4). JWT bearer tokens + per-key scopes at the
existing auth-middleware seam (§11.6). Pause/resume routes. Artifact GC / quota. Streaming upload (v1
reads the file into memory, §11.7).

**Sessions.** Daemon-side streaming (WebSocket or chunked transfer with a `SessionId` sub-protocol, over
streaming `VmEngine` ops). A raw-mode interactive CLI with `SIGWINCH` forwarding. Per-session backpressure
(a credit/window scheme; today the host queue is trusted-unbounded — a recorded trade). PTY `StdinEof`
half-close.

**Hardening (the increments Layers 1–3 are built to grow into).** The **thin** broker (broker
`SpawnVmm`+pidfd only, keep the `Registry` in the parent) needs the cross-process `MicroVm` refactor the
fat broker sidestepped (§12.4). Turning the seccomp deny-list **default-on** after a live per-backend
validation (§12.3). Turning `clear_ambient_caps` **default-on**, blocked on fd-passing tap creation so the
VMM never needs `CAP_NET_ADMIN` (§12.3). A jailer chroot/`pivot_root`/uid-drop increment (§12.3). A CH
`--net fd=` fd-passing variant (the fd-passing broker model, §12.4). `clone3(CLONE_INTO_CGROUP)` to place
the VMM in its cgroup atomically at spawn.

**Lineage.** A sparse-snapshot `SEEK_HOLE` density lever. A non-reflink `OverlayStore` (a content-addressed
pool for ext4/tmpfs hosts). Daemon fork/branch verbs exposing `Lineage` over REST. A lineage-aware sweep.
A branch-image store that reflinks a new branch's unchanged pages against its parent at snapshot time
(§8.6).

**Future capability catalogue** (each keeps the primitive general — these are consumer-layer or
opt-in-feature ideas, not core changes): record/replay cassettes; a declarative egress policy (a DNS-label
allowlist); a deterministic guest clock API; a structured serial-console fault classifier; `netem` network
fault injection; virtio-blk error injection (QEMU `blkdebug`, the piece `DiskIoLimit` throttling doesn't
cover, §4.6); a vsock↔TCP bridge; OTLP tracing export; overlay checkpoint/rollback; `kcov`/`gcov`
extraction from the guest; multi-VM L2 clusters; a `gdbstub` debug stub; a CPUID / aarch64 capability
matrix; scale-to-zero.

**Explicitly out of scope (naming the boundary is the G1 guard, §13).** These are *consumer* layers built
**on** vmcell, never in it: an MCP frontend, a KUnit/LTP kernel-test runner, `rr`-as-payload
record/replay, run bundles, and billing. The core stays a workload-agnostic micro-VM primitive; domain
policy lives in the crate that consumes it.

---
## 18. Delta register: changes from the validated v27 build

The body of this document describes the **target** design. This section is the explicit list of where that
target differs from the last validated implementation, so a maintainer holding the running code knows
exactly what to change and why. **These eleven items are specified here but not yet built**; the
implementer executes them, then reconciles the result in `docs/implementation-notes.md` (which carries the
per-item as-built record the way the earlier finding-IDs did). They are bundled as **one breaking release,
`vmcell` 0.9 → 0.10**, because deltas 1–2 change the signature of every VM-spawning entry point and it is
cleaner to absorb the rename (delta 3), the field moves (delta 4), and the removals (deltas 5, 11) in the
same semver bump than to spread them across point releases. After implementing, update the in-code `§`
references per the map in Appendix E.

Each item: **what** changes, **why**, the **migration** for a caller, and the **gate** that pins it.

1. **`HostEnv` bundles the process-wide seams.** *What:* a new `env.rs` struct
   `{cids, vmids, cgroups, clock, overlay}` with `shared()`/`hermetic()` constructors, passed by
   reference to `start`/`restore`/`restore_cow`/`Zygote::spawn_*`/`Lineage::fork*`. *Why:* the injected
   seams had grown to three-to-five positional arguments that increased by one per feature, plus per-clone
   `make_cgroups` closures on the fan-out APIs; one bundle collapses them and lets `agent()` take no
   arguments. *Migration:* build one `HostEnv::shared()` at start-up (the daemon already has the natural
   home) and thread `&env`; replace `make_cgroups` closures with `env.cgroups`. *Gate:* the existing
   orchestrator seam tests re-parameterized on `HostEnv::hermetic()` with recording fakes; a compile-fail
   check that `agent()` takes no seam arguments. (Resolves the M-ORCH-6 argument-sprawl finding.)
2. **`restore_cow`'s `OverlayStore` folds into `HostEnv`.** *What:* the standalone
   `restore_cow(..., overlay: Arc<dyn OverlayStore>)` parameter and `Zygote::with_overlay_store` are
   retired; the store comes from `env.overlay`. *Why:* one law — *every* CoW clone materializes through
   `env.overlay` — with no second way to inject a store that could drift from the one the rest of the
   process uses (S4). *Migration:* drop the explicit `overlay` argument; set `HostEnv::overlay` once (it
   defaults to `ReflinkOverlayStore`). *Gate:* the `RecordingOverlayStore` fan-out test now asserts the
   store came from `env`.
3. **`limits_enforced` → `mem_limit_enforced`.** *What:* rename the `ResourceUsage` field. *Why:* the old
   name over-claimed a whole-`ResourceLimits` guarantee; the boolean only ever meant "the **memory**
   controller is delegated" (§7.1). *Migration:* rename at the read site. *Gate:* the field's doc-test and
   the `CgroupFs`-fake enforcement test assert the narrowed meaning.
4. **`host_services_port` moves to `NetConfig::Unprivileged` only.** *What:* remove the field from the
   `Privileged` variant (where it was accepted then rejected at `build()`); keep it only on `Unprivileged`.
   *Why:* the smoltcp NAT is the only datapath that implements it, so the invalid state (a privileged
   config carrying it) is made unrepresentable rather than validated (§6.2). *Migration:* a privileged
   config that set it (a no-op) drops the field. *Gate:* the type change makes the invalid state a compile
   error; the prior "rejected on privileged" negative test is deleted as unreachable. (Privileged
   host-services wiring stays forward work, §17.)
5. **Remove `RootfsSource::VirtioFs { dir }`.** *What:* delete the unused variant. *Why:* it has **no
   consumer** — it appears only in the type listing and inside the snapshot-eligibility predicate — and a
   virtio-fs rootfs is mutually exclusive with the snapshot tier anyway (S1), so it is dead surface that
   only invites a snapshot-ineligible rootfs. *Migration:* none (no caller). Re-adding it later is a
   `#[non_exhaustive]` additive change. *Gate:* the eligibility-predicate test loses its `VirtioFs` arm; a
   grep gate confirms no construction site remains.
6. **Demote `instance_mut()` to `pub(crate)`.** *What:* narrow the visibility of the raw backend-instance
   accessor. *Why:* exposing the underlying `VmInstance` publicly let a caller bypass the orchestrator's
   ordered teardown and identity bookkeeping — a footgun with no legitimate external use (the M-ORCH-5
   finding). *Migration:* an external caller reaches for the safe `MicroVm` methods instead (none is known
   to use it). *Gate:* the visibility change is compiler-enforced.
7. **`EnvSetup` gets an explicit `Drop` calling the shared teardown helper.** *What:* the mid-`start()`
   staging struct releases resources via an explicit `Drop` that calls the same ordered
   `teardown_post_instance` helper the success path uses, instead of relying on struct
   field-declaration order. *Why:* field-order teardown was correct but invisible and reshuffle-fragile —
   a field reorder could silently delete the netns before the proxy running inside it (L1, §9.4).
   *Migration:* none (internal). *Gate:* a **drop-order recording gate** asserts both the success and
   error paths emit the identical teardown order.
8. **`HostCapabilities` is probed once at start-up.** *What:* one descriptor struct capturing the
   effective cap set, KVM-group access, `/var/run/netns` reachability, delegated cgroup controllers, and
   whether the scope is a non-threaded `domain` leaf — probed once and read by per-op checks. *Why:*
   realizes the §7.2 "declare and check capabilities" rule with **one** probe and one source of truth,
   replacing scattered per-op re-probes (the former §16 capability-plumbing gap). *Migration:* none
   (internal); callers that re-probed now read the descriptor. *Gate:* a unit test that a probe on a
   fake-host descriptor drives the mode-selection and fail-loud decisions.
9. **`FakeVmm` gains a scriptable fault menu.** *What:* `FakeVmm` can be scripted to fail
   `create`/`boot`/`restore` at a chosen step, delay readiness, or report a wedged control socket. *Why:*
   the retry/timeout and mid-`start()` failure paths were only reachable through the *surrounding* seams;
   scripting faults at the `Vmm` seam itself exercises them directly (the M-VMM-6 finding, §9.8).
   *Migration:* none (test-only). *Gate:* new orchestrator tests drive each fault arm and assert the
   ordered-teardown/​retry behavior.
10. **The daemon artifact store computes SHA-256 during upload and serves a sidecar.** *What:* streaming an
    upload through a hasher, writing a `<name>.sha256` sidecar, and serving `list` digests from the sidecar
    (§11.3). *Why:* re-hashing the whole store on every `list` was O(store bytes); the daemon owns the dir,
    so hashing once at upload is sufficient and makes `list` O(entries). *Migration:* none (the sidecar is
    internal; the API is unchanged). *Gate:* the store test asserts the sidecar matches a streamed re-hash
    and that `list` reads it without re-hashing the body; sidecars are excluded from `list` output.
11. **Remove the `vmcell-cli` `exec`/`ls`/`rm`/`destroy` stubs.** *What:* delete the cross-process
    lifecycle stubs from the CLI; their removal message points at `vmcelld-ctl`. *Why:* those verbs
    genuinely belong to the daemon, which **owns** VMs across process boundaries; a fail-loud CLI stub for
    them was a placeholder for a capability the CLI structurally cannot have (§10, §11). *Migration:* use
    `vmcelld-ctl exec|ls|rm` against a running daemon. *Gate:* a CLI test asserts the removed verbs print
    the redirect message and exit non-zero; the daemon-client suite covers the real verbs.

---
## Appendices

The per-finding records that the v27 body carried inline (the `M-*`, `H-*`, `EXP-*`, `AGENT-*` IDs)
resolve to the project's working documents and are **not** reproduced here: performance experiments in
`docs/44-claude-perf-experiments.md`, the performance investigation log in
`docs/45-claude-perf-investigation.md`, the code-review findings in `docs/46-claude-code-review.md`, and
the as-built reconciliation in `docs/implementation-notes.md`. This document cites the *conclusions*; those
files hold the evidence.

### Appendix A — Load-bearing reversals

Each of these is a case where the obvious choice was wrong and measurement or a live trace forced the
opposite. They are here because the *reasoning* justifies a current design decision that would otherwise
look arbitrary.

1. **Firecracker: PCI → MMIO.** An early assumption that PCI snapshotting was required inverted — FC's
   maturity and snapshot support are on the **MMIO** transport, so the guest kernel builds *both*
   virtio-pci (for CH) and virtio-mmio (for FC), and FC runs in MMIO mode (§2.3, §5.2).
2. **Guest networking: `ip=`/device-layer, not netlink.** A manual `rtnetlink` bring-up in PID 1 caused
   wrong-attribution failures and dragged netlink into the agent; it was **deleted** in favor of the
   kernel `ip=` cmdline plus device-layer `SIOCSIF*` ioctls, and the net-unprivileged manual path was
   compiled out. This is *why* C6 is a structural (dependency-absence) gate, not a fake (§3.4, §9.8).
3. **FPU/XSAVE: `T2` template + `noxsave`, not a base downgrade.** A guest FPU/XSAVE mismatch on restore
   tempted a bookworm kernel downgrade; the correct fix was a Firecracker **`T2` CPU template** (a stable
   cross-host feature set) with a `noxsave` cmdline fallback gated on `template.is_none()`, keeping the
   modern base (§2.3, §5.3).
4. **Egress steering: `REDIRECT` → `TPROXY` — right choice, wrong first reason.** The transparent-proxy
   redirect moved from `REDIRECT` to `TPROXY`; the *stated* reason (needing `SO_ORIGINAL_DST`) was wrong,
   but TPROXY is still correct because it carries the original destination in the socket and preserves the
   source without conntrack (§6.4).
5. **QEMU unprivileged vsock = a stateless vhost-user mirror of the eligibility law.** The QEMU
   unprivileged-vsock path is a stateless vhost-user device, so it obeys S1 exactly as the NAT and
   virtio-fs shares do — no special case (§8.1).
6. **The rootfs size argument inverted.** The OCI slim base was assumed larger than an `mmdebstrap` build
   and turned out ≈34–39 % **smaller** (dpkg path-excludes), so the in-VM source earns its place on
   **provenance**, not size (§4.2).
7. **microVM early-boot `#DE` had ~24 candidate causes; the real one was found by live trace.** A triple
   fault / `#DE` on early microVM boot was narrowed from two dozen plausible causes to a confirmed **vhost
   fork** interaction by an actual message trace — and, separately, the `passt` incompatibility was traced
   to a host **AppArmor `af_unix`** rule, not `passt`'s seccomp and not CH-specific (feeding reversal in
   §6.2).
8. **Firecracker warm-restore was four stacked bugs, not one.** FC warm restore failed for four
   independent reasons at once — a cached client reused across the severed vsock, a baked vsock path whose
   parent dir was wrong, no entropy device to reseed, and the AGENT-2 guest-reaper epoch race — and only
   fixing **all four** made it work; the guest-side fix was the *generic* re-bind, no FC-specific guest
   change (§8.2).
9. **`clear_ambient_caps` must default off.** Clearing the ambient set in the jailer child stripped the
   `CAP_NET_ADMIN` the VMM itself needs for `TapSetMac` (CH) / tap-reopen (FC) at boot, reddening every
   restore-with-tap test while cold boot survived — so the field defaults **false** with an at-site
   rationale, and turning it on is blocked on fd-passing (§12.3).
10. **The engine channel is JSON, not postcard.** The broker's forwarded DTOs use serde
    `skip_serializing_if`/`default`, which postcard's non-self-describing format silently corrupts, so the
    engine channel uses JSON while the broker's own attribute-free control enum stays framed-binary — the
    same class of finding as the daemon-DTO reversal (§12.4).
11. **`branch`/`fork_from_vm` needed a `create_dir_all` the fake couldn't reveal.** A missing
    directory-creation on the lineage snapshot path was **invisible to `FakeVmm`** (which never touches the
    filesystem) and was caught only by the live KVM suite — a concrete instance of §14 lesson 1 and lesson
    5 (§8.5).

### Appendix B — Substitution experiments

Deliberate "replace X with a better-licensed or in-process Y" attempts, and where each landed:

| # | Substitution | Status |
|---|---|---|
| 1 | shell `mkfs.erofs` → in-process `am-fs-erofs` (tar→erofs) | **graduated** — the only wired erofs writer (§4.2) |
| 2 | `iproute2`/`skopeo` → OCI-in-Rust (`oci-client` + whiteout apply) | **graduated** — the default rootfs source (§4.2) |
| 3 | `mmdebstrap`-only rootfs → OCI slim base as the default | **graduated + wired**, `mmdebstrap` kept for provenance (§4.2) |
| 4 | `passt` → in-process `smoltcp` + `vhost-user-backend` | **graduated** — no external dep, no LSM entanglement (§6.2) |
| 5 | `rustables` (GPL) for nftables | **rejected** — no permissive pure-Rust TPROXY path; render + `nft -f -` (§9.6) |
| 6 | `virtiofsd` → in-process `fuse-backend-rs` | **underway**, blocked on read-only enforcement before it can graduate (§4.5) |

### Appendix C — Contested facts, per pin

Facts that were surprising, version-specific, or initially gotten wrong — each pinned to the version it was
verified against, because the next version may differ:

- **Cloud Hypervisor DAX is gone as of v52.** The virtio-fs DAX window was removed, so shared-directory
  density rests on `cache=never` + the shared erofs base, not DAX (§8.3).
- **CH snapshot + virtio-fs is unreachable through the API**, which is *why* S1 is enforceable at all — the
  combination can't be constructed, so rejecting it at `build()` matches the backend's own limit (§8.1).
- **CH UFFD "prefault" is confirmed lazy.** Eager restore front-loads and is ≈1.5× the resume cost of
  lazy, with the difference reappearing as first-touch faults; sparse-`SEEK_HOLE` handling is still open
  (§16, §17).
- **Vendor-published boot numbers are workload-dependent** and were not reproduced verbatim; the §16
  figures are this substrate's, measured interleaved.
- **Nested virt is host-configured, not a CH flag.** It needs host `kvm_intel nested=1` plus the guest
  `kvm-intel.nested=` cmdline token; there is no CH nested-virt flag, and AMD L1-with-L2 does not migrate
  (so a nested guest is not snapshot-portable) (§5.3).
- **There is no `herolib-virt` crate** — an early dependency assumption that did not exist; the VMM
  integration is direct against each backend's process/API.
- **CVE-2026-45782 is fixed in the pinned CH v52.0.0** — the pin is chosen to include the fix, which is
  part of why the CH build identity is folded into the snapshot cache key (§10.2).

### Appendix D — Prior art

Projects consulted while designing this, and the one idea taken from each: **cocoonstack / cocoon** (a
micro-VM sandbox shape); **tinylabscom / mvm** (a minimal Rust VMM-driver approach); the **microvm.nix**
write-up (declarative micro-VM composition); **agentkernel / vmexec** (agent-workload VM execution);
**smoltcp + vhost-user-backend** (the in-process userspace-net datapath, §6.2); and the **Kata
`agent-ctl`** tooling (the guest-agent control-protocol shape, §3). None is a dependency; each informed a
boundary or a protocol choice.

### Appendix E — Section map, v27 → v28

The code comments and `docs/` cross-references written against v27's section numbers still point at v27
numbering; when updating them (a delta-register follow-up, §18), use this map. The rewrite merged the
Parts VI–IX appendix subsystems into the main sequence and folded the three "future work" sections
together.

| v27 section | v28 location |
|---|---|
| Front matter (changelog v19–v27) | **removed** (per-item history → `docs/implementation-notes.md`) |
| §1 Overview / §2 Goals | §1 Overview (§1.3 non-goals) |
| §3 VMM backends & the `Vmm` trait | §2 |
| §4 Control plane (vsock) + §22 Sessions | §3 |
| §5 Storage/rootfs + §19.1/§19.5 (virtio-fs, extra disks) | §4 |
| §8 Guest kernel + §19.2 (kernel knobs) | §5 |
| §6 Networking & egress | §6 |
| §7 Resource monitoring & limits | §7 |
| §9 Snapshot/restore + §21 (OverlayStore / Lineage) | §8 |
| §10 The Rust library | §9 |
| §11 The artifact pipeline | §10 |
| §18 The control-plane daemon | §11 |
| §20 Privilege hardening | §12 |
| §12 Cross-cutting invariants | §13 (re-lettered S/C/L/F/P/G) |
| §13 Hard-won lessons | §14 |
| §14 Testing strategy | §15 |
| §15 Performance | §16 |
| §16 + §17 + §18.9/§20.9/§21.8/§22.7 (open gaps, per subsystem) | §17 (merged, deduped) |
| Appendix E (build roadmap) | **removed** (pure history) |
| — (new) | §18 Delta register |
| Appendices A–D (reversals, substitutions, contested facts, prior art) | Appendices A–D |
