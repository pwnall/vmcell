# vmcell — Design Document (v23)

> **v23 (this revision) — unification.** This document folds the two focused amendments that followed
> v20 into a single self-contained design: the **control-plane daemon** (formerly v21) and the
> **extra-device config surfaces** (formerly v22). Nothing is dropped and the base architecture is
> unchanged; the amendment material is integrated in place and expanded into **Part VI**. **§18** is the
> long-lived, blessed **`vmcelld` daemon** that *owns* the VMs it starts — it holds each `MicroVm` handle
> so a VM's lifetime is decoupled from any one request but is still released on `Drop` in order (§12.10) —
> plus its typed **`vmcell-daemon-client`** and **`vmcelld-ctl`** CLI, a per-daemon **artifact store**, the
> owning **VM registry** + start-up orphan sweep, a versioned **HTTP REST API** with a served **OpenAPI
> 3.1** document, **bearer-token auth** (RFC 6750 form), and the lean shared **`vmcell-privilege`**
> capability/blessing crate. **§19** is the extra-device surface: **extra virtio-blk devices**
> (`extra_disks`), **append-only extra kernel cmdline args** + an **`init=` override**, and per-disk
> **disk-I/O throttling** (`DiskIoLimit`). Amends **§2.2**, **§8.3** (the shared cmdline builder gains an
> append-only tail and an init-token override), **§10.1** (five new workspace members: `vmcell-privilege`,
> `vmcell-daemon`, `vmcelld`, `vmcell-daemon-client`, `vmcelld-ctl`), **§10.2** (`VmConfig` gains
> `extra_disks`/`extra_kernel_args`/`init`/`resource_prefix`; new `BlockDevice`/`DiskIoLimit` types; the
> `vmcell::naming` module), **§11** (the CLI's `exec`/`ls`/`rm`/`destroy` verbs are now genuinely *owned* by
> the daemon, kept as fail-loud CLI stubs; `run`/`create` gain `--disk`/`--disk-rw`/`--append`), **§12** (new
> cross-cutting invariants §12.13–§12.20), **§14** (daemon + device gates), and **§16/§17** (the daemon and
> both device features graduate from forward-work to built; the warm-pool manager and setup broker remain
> future). `vmcell` bumps **0.5.0 → 0.6.0** (the `resource_prefix`/`naming` surface); `vmcell-test-runner`
> bumps **0.2.0 → 0.3.0** (the `vmcell-privilege` extraction); the five new members version from **0.1.0**.
> All new library surface is additive and `cargo semver-checks`-clean on the existing types.
>
> **v20 — builder extraction: bootstrap-in-`vmcell`, in-VM builders in their own
> crates.** The two "build inside a VM" features move out of the `vmcell` package into dedicated
> workspace crates, leaving lightweight **bootstrap** producers in `vmcell`. Rootfs: `vmcell` keeps the
> host-native **OCI-image bootstrap** source (`RootfsStage`); the full-apt in-VM `mmdebstrap` builder —
> now **un-deferred and wired end-to-end** on the privileged/tap path with `Egress::Open` for real apt
> egress — moves to **`vmcell-rootfs-builder`**. Kernel: `vmcell` keeps two bootstrap producers,
> `KernelStage` (host-`make`) and the new **`PrebuiltKernelStage`** (download + sha256-verify a
> digest-pinned prebuilt `vmlinux`); the in-VM download+configure+compile builder moves to
> **`vmcell-kernel-builder`**. Both builders are `vmcell::artifact::Stage` impls **depending on `vmcell`
> and reusing its promoted-`pub` utilities** (`pack_erofs_with_injection`, `resolve_builder_base`,
> `hash_file`/`hash_output`/`hash_artifacts_sorted`, `ch_binary_path`, `HttpClient`/`ReqwestClient`);
> `vmcell` has **no** dependency edge back to them. To keep the graph acyclic the CLI leaves the `vmcell`
> package for a new **`vmcell-cli`** composition-root crate that depends on all three and assembles the
> `Pipeline` (choosing bootstrap vs in-VM builders via `--rootfs-source oci|mmdebstrap` /
> `--kernel-source prebuilt|host-make|in-vm`). `vmcell` bumps **0.4.0 → 0.5.0**. New/changed: **§5.4**
> (the rootfs-construction contract), **§8.5** (the guest-kernel contract), and edits to §8.2/§8.3/§8.4,
> §10.1, §11, §16. Empirically validated: a **Kata Containers** prebuilt `vmlinux.container` (Linux
> 6.18.35) is the pinned bootstrap **seed** — it boots vmcell's erofs root to PID 1 + overlay; generic
> microVM kernels omit EROFS/FUSE and panic (§8.5). Host-`make` remains the guaranteed fallback seed.
>
> **v19 — zygote suspend/resume fan-out.** Promotes the
> single-snapshot copy-on-write clone from forward-work (v18 §16/§17) to a
> built-and-tested feature: suspend one agent-ready VM into a **zygote**, then
> mint many identical VMs by reflink-copy-on-write-copying the suspend image per
> clone and restoring each private copy — paying the kernel-boot cost once, not
> per VM. New: §9.4 (the mechanism), the `Zygote` API (§10.2), invariant §12.12
> (the master is immutable — each clone restores from its own copy), and the
> concurrent-fan-out gate reusing the existing `restore_rotates_host_paths`
> capability rather than a new flag (§3.3). Validated end-to-end on CH (a live
> concurrent 3-clone pool) and FC (concurrent fan-out correctly refused; single
> clone works).

**vmcell** is a micro-VM runner for isolated environments, driven entirely from one Rust library. On a
Linux/x86-64 host with KVM it lets you *create a fresh micro-VM, run a command in it over a typed
control channel, give it shared directories / host-reachable endpoints / logged-and-filtered network
egress, observe and cap its resource use, optionally snapshot-and-restore it for speed, and tear it
down with no residue*. Strip away the shares, endpoints, and proxy and what remains — create →
restore-or-cold-boot → `exec` over vsock → observe/cap → ordered teardown — is a self-contained,
workload-agnostic execution primitive.

The project's origin and still most demanding consumer is end-to-end integration testing of a
**hypothetical agent-harness testing project** — the agentic harness this runner was originally extracted
to test. But the same primitive serves three co-equal domains: **low-level systems testing** (a real
kernel, full syscall surface, and nested virt, per test), **agentic execution** (untrusted AI-agent tool
calls in disposable, observable, fast-to-restore sandboxes), and **generic serverless / ephemeral
functions** (snapshot a warmed runtime once, restore per invocation in tens of milliseconds, discard).
Throughout this document, **"the agent-harness testing project"** refers to that origin *harness* — a
consumer of the runner, never to the runner itself.

---

**How to read this document.** It is written for someone learning the project, in six parts:

- **Part I — Overview** (§1–§2): what the system is, the guarantees it delivers, and a one-page picture
  of how a single test flows through it.
- **Part II — Components and interfaces** (§3–§11): each subsystem, its public interface, and how it
  works. This is the reference for "what are the pieces and how do I drive them."
- **Part III — The subtle parts** (§12–§13): the cross-cutting rules every developer must respect no
  matter which subsystem they touch, plus the hard-won lessons behind them. If you remember nothing
  else, remember §12.
- **Part IV — Testing and performance** (§14–§15): how correctness is forced by the test/lint/CI layer,
  and the measured performance numbers.
- **Part V — Status and roadmap** (§16–§17): what is not yet done, and the catalogue of future
  capabilities the three domains motivate.
- **Part VI — Control-plane daemon and extended device surfaces** (§18–§19): the long-lived `vmcelld`
  daemon that owns VMs across requests (its artifact store, owning registry, REST/OpenAPI surface, and
  bearer auth), and the extra-disk / custom-init / disk-I/O-throttling configuration surfaces. These are
  components layered on the §3–§11 core and built after it; they keep §1–§17's numbering stable so the
  cross-references throughout the codebase remain valid.
- **Appendices** (A–E): how the design was reached — the implementation-pass history, the load-bearing
  reversals, the dependency experiments, contested facts to re-verify per pin, prior art, and the build
  order. Nothing in the appendices is required to *use* the system; it is the evidence behind the
  non-obvious choices in Parts I–III.

The body describes the system **as it is built today**, in the present tense. Facts that were once
contested or arrived at over several implementation passes are stated in their settled form. A
non-obvious choice (why erofs and not ext4; why the snapshot tier excludes unprivileged networking; why
a Firecracker snapshot lineage shares one host vsock path) is explained inline where the component is described, and
**Appendix A** records the reversal history — what was believed before and what the implementation found —
behind the ones that were hard-won.

---

## Part I — Overview

## 1. What vmcell is

### 1.1 The execution primitive

A Rust library (plus a thin CLI) that, on a Linux/x86-64 host with KVM, can:

1. Build the VM artifacts (kernel, root filesystem, proxy CA) reproducibly.
2. Create, configure, start, stop, and destroy micro-VMs programmatically.
3. Give each VM read-only and read-write shared directories with independent permissions.
4. Let host-side code stand up private servers the VM can reach (and nothing else can).
5. Route the VM's web egress through a transparent, logging/filtering Rust proxy.
6. Drive the VM over a vsock control channel (`exec`, stream stdout/stderr, exit code, file put).
7. Monitor and cap each VM's CPU / RAM / disk-I/O.
8. Optionally expose nested virtualization so a guest can run its own VMs.

Nothing in the core (`vmm` / `agent` / `orchestrator` / `metrics`) is testing-specific, agent-specific,
or serverless-specific. The artifact pipeline produces a generic Debian rootfs, and the public handle —
**`MicroVm`** — is a thin owner over the primitive. Integration testing for the agent-harness testing
project drives every capability and so remains the most demanding consumer, but keeping the primitive
general is a hard design
constraint, not an afterthought (§12.11). The extra capabilities each domain *wants* — and how to add
them without leaking one consumer's policy into the core — are catalogued in §17.

### 1.2 The three guarantees

The runner exists to deliver three properties **by construction rather than by cleanup**. They are
stated in testing terms; substitute "invocation" or "job" for "test" for the other consumers.

1. **Isolation** — a misbehaving harness, model, or workload cannot disrupt the host.
2. **Hermeticity** — no state leaks between runs. Each starts from an identical, fresh VM, and teardown
   is *structural*: the VM is discarded, not reset.
3. **Fidelity** — the in-VM environment matches a real end-user Linux system, including the demanding
   cases (nested virt, the full syscall surface, a real kernel).

### 1.3 Non-goals

The **evaluation methodology layer** is out of scope: scoring, juries, dashboards, MCTS rollback
engines, stateful API simulation, CI soft-failure statistics. This library is the *substrate* such a
layer sits on. Two connection points are designed in because they map onto hard requirements: the
egress proxy (capability 5) is the natural home for **record/replay "cassettes"** and web-service test
doubles, and the vsock control plane (capability 6) is the natural transport for an in-guest
model-proxy bridge. Everything beyond those hooks belongs to a separate crate that depends on this one.
The same boundary applies to the other consumers: a serverless scheduler or an agent-sandboxing
frontend is a *layer on top of* this primitive, not part of it (§17).

---

## 2. System at a glance

```
┌──────────────────────── Host: Linux + KVM (nested=1 if needed) ───────────────────────┐
│                                                                                        │
│  vmcell orchestrator  (Rust, tokio)                                                    │
│   ├─ Vmm trait:  create / restore / capabilities            (+ VmInstance: boot/pause/ │
│   │     └─ impls:  CloudHypervisor (default) · Firecracker · Qemu   resume/snapshot/kill)│
│   ├─ per-VM:  cgroup v2 slice → {netns + tap (/30)  |  in-process smoltcp vhost-user NAT}│
│   ├─ AgentClient (AF_UNIX vsock, retry+handshake)   ⇄   vmcell-guest-agent (PID 1)      │
│   ├─ virtiofsd × N   (one per read-only / read-write data share)                        │
│   ├─ EgressProxy (hudsucker: hyper+rustls):  {nft TPROXY | smoltcp L4} → log/filter/doubles│
│   └─ metrics:  read memory.peak / memory.current / cpu.stat / io.stat from the slice    │
│                                                                                        │
│   artifact cache:  vmlinux  ·  erofs rootfs (RO, shared)  ·  warm snapshot  ·  proxy CA │
└────────────────────────────────────────────────────────────────────────────────────────┘
        │ restore (ms) or cold-boot                          ▲ vsock: Ready/Exec/IO/Exit/PutFile/Resync
        ▼                                                     │
  ┌──────────────────────── micro-VM (per test, ephemeral) ───────────────────────┐
  │ kernel: direct boot, virtio + vsock + virtio-fs + (opt) KVM built-in, no initramfs │
  │ PID 1: vmcell-guest-agent  (mounts /proc /sys + shares, tmpfs overlay, brings up lo,│
  │        reaps children, serves the vsock protocol; CA pre-baked into the rootfs)  │
  │ root: /dev/vda = erofs (RO, shared by all VMs)  +  tmpfs overlay for writes     │
  │ net: eth0 (kernel ip= boot arg) → default route → host proxy   [opt] /dev/kvm   │
  └─────────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 The per-test lifecycle

1. **Acquire artifacts** from the cache (kernel, erofs rootfs, snapshot, CA) — built once, reused.
2. **Allocate per-VM resources:** a cgroup v2 slice, networking (netns+tap on a fresh `/30`, or an
   in-process smoltcp NAT), a unique vsock **CID**, and a unique **VMID**. The erofs base is mounted
   read-only and *shared* — there is no per-VM disk copy; the only writable state is the tmpfs overlay.
3. **Start the VM:** either **restore** a warm "agent-ready" snapshot (the fast path: `--restore` →
   `resume`, never `create`/`boot`) or **cold-boot**. On restore, refresh identity (vsock CID; MAC +
   IPv4/default route, rotated to the new vmid), reseed entropy, and resync the guest clock — one native
   in-agent `Resync` round-trip, no subprocess (§9.2).
4. **Bind shares** (cold/general path): point one `virtiofsd` per data share at this VM's directories.
   The snapshot tier attaches *no* virtiofsd — it is a **vhost-user device** (a device whose backend runs
   as a *separate helper process* — virtiofsd, the vhost-user-net NAT, or an external vsock daemon —
   talking to the VMM over a Unix socket; because that helper holds device state the VMM cannot migrate,
   attaching one makes the VM unsnapshottable, §12.1). Read-only data on the snapshot tier is served as an
   extra erofs/block image instead.
5. **Connect + drive over vsock:** the host `AgentClient` retries the handshake until the guest's
   `Ready` frame arrives (bounded by a timeout), while tailing the serial log so a boot panic fails fast
   instead of retrying to no avail. Then `Exec` the entrypoint and stream stdout/stderr/exit.
6. **Collect results:** outputs from the host side of a read-write share; `memory.peak` / `cpu.stat` /
   `io.stat` from the cgroup slice; the proxy's request log.
7. **Tear down (ordered):** force-kill the **VMM process group first**, then virtiofsd, *then* remove
   the tap/netns/cgroup/overlay/sockets. Removing a netns while the VMM still holds interfaces or
   threads in it can hang or leak; reaping the process first makes teardown a clean kernel operation.
   Discard is structural — that *is* the no-leakage guarantee (§12.10).

### 2.2 Key decisions (bottom line up front)

| Concern | Decision |
|---|---|
| **Primary VMM** | **Cloud Hypervisor (CH)**, run as a subprocess over its REST `--api-socket`. Rust/rust-vmm, Apache-2.0/BSD. Feature-complete: the default, and the **fully-featured snapshot tier** (Firecracker is the second validated snapshot backend). |
| **Second VMM** | **Firecracker**, behind the same trait, for the density/snapshot tier. Runs in **MMIO mode**. Snapshot/restore is **wired and validated end-to-end** — the fastest restore tier (warm restore ≈24 ms p50, §15) — with two honest constraints: `restore_rotates_host_paths: false` (a snapshot lineage re-binds the baked host vsock path verbatim, so restores are single-lineage, §3.2) and `lazy_restore: false` (UFFD unwired, §16). `create()` attaches virtio-rng (`PUT /entropy`) so the post-restore reseed has a `/dev/hwrng` to draw from. No virtio-fs, no vhost-user-net, no nested virt. |
| **Fallback VMM** | **QEMU `q35`** (not `microvm`) — the documented escape hatch and most-proven nester; full feature set. Snapshot is ineligible over its unprivileged external-vsock path; a privileged in-kernel-`vhost-vsock` config is *validated but not yet wired* (§3.3). C/GPL **binary**, used as an external tool, never linked. |
| **Control plane** | **virtio-vsock + a Rust guest agent as PID 1**, framed `postcard` protocol (`Ready`/`Exec`/`Stdout`/`Stderr`/`Exit`/`PutFile`/`Resync`/`ResyncAck`). Host connects with a retry/handshake loop and reconnects after restore. Serial console → a per-VM log for panic capture. SSH is a human-only debug fallback. |
| **Root filesystem** | **erofs read-only image over `virtio-blk`**, shared by all concurrent VMs with **no per-VM copy**; per-VM writes go to a **tmpfs `overlayfs` upper**. erofs has no journal → no recovery writes, no concurrent-mount corruption, and it composes with snapshot (a plain block device, not vhost-user). |
| **Shared dirs** | **virtio-fs, one `virtiofsd` per share**, `--readonly` for read-only shares, `--sandbox namespace`. Caller-defined mount tags. |
| **Host endpoints** | Per-VM **network namespace + tap + `/30`** (privileged) *or* an **in-process smoltcp + vhost-user-net NAT** (unprivileged). Host servers reachable from the guest, not exposed beyond it. |
| **Egress proxy** | A **Rust MITM proxy** (`hudsucker` = `hyper`+`rustls`+`rcgen`) with logging, filtering, and pluggable test doubles; CA baked into the guest trust store. Steered in via **nft `TPROXY`** (privileged) or **L4 interception in the smoltcp NAT** (unprivileged). |
| **Monitoring / limits** | One **cgroup v2 slice per VM**; read `memory.peak`/`memory.current`/`cpu.stat`/`io.stat`; enforce `memory.max`/`cpu.max`/`pids.max`/`io.max`. A *requested* limit that can't be enforced **fails loud** (§7.2) — never a silent no-op. |
| **Operating modes** | **Two, named and tested separately** (§6.4): **unprivileged** (KVM-group access, no `CAP_*`; smoltcp NAT) and **privileged** (the §14 capability runner grants `CAP_NET_ADMIN`+`CAP_SYS_ADMIN`+`CAP_DAC_OVERRIDE`; netns+tap). A mode's prerequisites are probed up front and enforced fail-loud. |
| **Guest OS** | Minimal **Debian Trixie (13, kernel 6.12 LTS)**, from one of two sources feeding one erofs packer: **OCI pull** by digest (default, in-Rust, no Docker) or **`mmdebstrap` inside a builder micro-VM** (full apt signing chain). |
| **Guest kernel** | **Direct kernel boot** of a custom-minimal `vmlinux` from Debian kernel source with an explicit config fragment (§8.3) — virtio (PCI + MMIO) + vsock + virtio-fs + erofs/overlay + optional KVM, all built in, no initramfs. No project-specific patches. |
| **Speed lever** | **Warm snapshot + restore** off the erofs rootfs with a tmpfs overlay per test; cold-boot opt-in. Measured **≈5.4× faster than cold boot on CH** (316→58 ms p50; on FC, restore at 24 ms is ≈32× its 764 ms cold boot, §15). |
| **Guest tooling** | A tiny in-Rust multicall **`vmcell-guest-tools`** (`ip`/`curl`/`kvm-ok`, doing the *real* operations) **baked into the erofs**, supplying the few tools the minimal Debian base omits (§5.3). |
| **Build layout** | A **cargo workspace** (2024 edition): the `vmcell` library + its CLI, plus lean member crates — `vmcell-protocol`, `vmcell-guest-agent`, `vmcell-test-runner`, `vmcell-guest-tools`, `vmcell-privilege` — and the two in-VM builders + the artifact validator. Leanness of the privileged-window/guest binaries is a *structural per-member* property (§10.1). |
| **Control-plane daemon** | A third entry surface beside the library and CLI (§18): the long-lived blessed **`vmcelld`** daemon **owns** the VMs it starts (holds each `MicroVm` handle, releases on `Drop`), serves a versioned **HTTP REST API** with an **OpenAPI 3.1** document behind a **bearer API key**, and manages a per-daemon **artifact store**. Client library `vmcell-daemon-client` + CLI `vmcelld-ctl`. |
| **Extra device surfaces** | Additive `VmConfig` knobs (§19): **extra virtio-blk devices** (`extra_disks` → `/dev/vd{b,c,…}`, snapshot-composing), **append-only extra kernel args** + an **`init=` override** (a genuine PID-1 replacement, honored fail-loud without the control plane), and per-disk **disk-I/O throttling** (`DiskIoLimit`, bandwidth/IOPS). |
| **Dependency posture** | Prefer in-crate Rust over external tools; permissive licenses only (MIT/Apache/BSD/ISC/Zlib/0BSD/Unicode-3.0/CDLA-Permissive-2.0); copyleft tolerated only for *binaries* (QEMU, `nft`). `cargo-deny` on every build is the source of truth. |

---

## Part II — Components and interfaces

## 3. VMM backends and the `Vmm` trait

### 3.1 A narrow trait plus a capability descriptor

The VM lifecycle is modeled as a narrow, typed contract so the finicky, subprocess-supervising,
occasionally-`unsafe` VMM glue stays behind a boundary and the orchestrator stays idiomatic and
unit-testable (a `FakeVmm` implements the same trait, §10.6). The three backends genuinely diverge —
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
    /// is false OR cfg carries any vhost-user device (the §12.1 law). Takes cfg to reconstruct the
    /// NON-vhost-user device topology (rootfs/block args, tap/net wiring) — it must NOT attach virtiofsd.
    async fn restore(&self, snapshot_dir: &Path, cfg: &VmConfig, res: &PerVmResources, cgroups: &dyn CgroupFs) -> Result<Self::Instance>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VmmCapabilities {
    pub snapshot_restore: bool,          // CH ✓ · Firecracker ✓ (single-lineage host paths, §3.2) · QEMU ✗
    pub lazy_restore: bool,              // demand-paged restore (`--restore … prefault=off`). CH ✓ · FC ✗ · QEMU ✗
    pub virtio_fs_shares: bool,          // CH, QEMU ✓ · Firecracker ✗ (block-only)
    pub unprivileged_vhost_user_net: bool, // smoltcp NAT via vhost-user-net: CH, QEMU ✓ · Firecracker ✗
    pub nested_virt: bool,               // expose /dev/kvm to the guest: CH, QEMU ✓ · Firecracker ✗
    pub virtio_console: bool,            // ConsoleMode::VirtioConsole: CH, QEMU ✓ · Firecracker ✗ — rejected
                                         //   loud+early on FC, before the cmdline is built (console=hvc0
                                         //   with no device would silence the log)
    pub restore_rotates_host_paths: bool, // CH ✓ (restore config-rewrite moves vsock/serial paths into the
                                         //   new scratch dir) · FC ✗ (re-binds the baked vsock UDS verbatim) · QEMU ✗
}

pub trait VmInstance: Send {
    async fn boot(&mut self) -> Result<()>;             // cold start (after create)
    async fn request_shutdown(&mut self) -> Result<()>; // graceful (ACPI) signal only; the grace-poll + SIGKILL fallback is MicroVm::shutdown()/kill()
    async fn has_exited(&mut self) -> bool;             // non-blocking process.try_wait(); trait-default false
                                                        //   (conservative for fakes). shutdown() polls it so the
                                                        //   grace window ends as soon as the guest powers off (§10.2)
    async fn kill(&mut self) -> Result<()>;             // force-terminate the VMM process group
    async fn pause(&mut self) -> Result<()>;            // REQUIRED before snapshot
    async fn resume(&mut self) -> Result<()>;           // after snapshot, and after restore
    async fn snapshot(&mut self, dir: &Path) -> Result<()>; // pauses, writes, resumes (or stays paused for kill)
    fn vsock_path(&self) -> &Path;                      // AF_UNIX endpoint (changes across restore)
    fn guest_cid(&self) -> u32;                         // unique per running VM (>= 3)
    fn serial_log(&self) -> &Path;                      // per-VM panic / early-boot log
}
```

Every field of `VmmCapabilities` is a property of the *pinned* VMM build and must be re-confirmed
against it (Appendix C), not hard-coded from memory. Resource *usage* is read from the cgroup slice, not
from the instance — `VmInstance` has no `stats()` method; the orchestrator reads counters through the
injected `CgroupFs` (§7). The same "report, don't assume" discipline applies to the **host environment**:
the orchestrator selects an operating mode (§6.4) from what the host actually offers and fails loud when
a requested mode's prerequisites are missing. (Today this is realized by per-op capability checks;
consolidating them into one start-up `HostCapabilities` descriptor is forward work, §16.)

### 3.2 The three backends

**Cloud Hypervisor (CH) — the default and the fully-featured snapshot tier.** Feature-complete: snapshot/restore
via `--restore`+`resume`, virtio-fs shares, vhost-user-net (so the unprivileged NAT), and nested virt.
Driven over a hand-written thin REST client (`hyper`/`hyperlocal` over the Unix `--api-socket`); every
control RPC over the API socket is bounded at 5 s, so a wedged VMM control socket surfaces as a typed
`Error::Timeout` before any outer readiness timeout can mask it (M-VMM-2). Cold
boot ≈316 ms; warm restore ≈58 ms (§15). Two lifecycle paths: cold = `vm.create` → `vm.boot`; warm =
launch with `--restore` → `vm.resume` (**never** `create`/`boot` — CH returns `500 "VM is already
created"`). `snapshot` must `vm.pause` first, then snapshot, then `vm.resume` (or stay paused if the VM
is about to be killed). One restore subtlety worth flagging here: CH `--restore` rebuilds every device
from the snapshot's `config.json`, which records the *original* instance's now-defunct temp-dir paths for
the **vsock socket**, **serial file**, and **console file**, plus the ancestor's tap in every
`net[].tap`, and CH exposes no restore-time override — so the spawn step rewrites all of them *before*
launching: the socket and serial/console files (in lockstep with `ConsoleMode`) to this restore's
freshly-minted scratch-dir paths, and every `net[].tap` to this restore's *rotated* tap, so the guest's
rotated `/30` and its host tap/nft wiring belong to the same vmid (H-VMM-1, §9.2). CH is
supervised as an external release binary; only its REST *client* is a crate.

**Firecracker — the density/snapshot tier, and the fastest restore.** Its draw is density
(low memory overhead) plus snapshot, and it has the **fastest measured warm restore** (≈24 ms p50, §15).
It is
implemented like CH (a hand-written `hyper`-over-Unix client, not `firecracker-rs-sdk`). Its device model
is deliberately minimal — virtio-{net,block,vsock,balloon,rng} — so it **cannot do virtio-fs,
vhost-user-net, or nested virt**, and `capabilities()` reports those `false`. Three Firecracker-specific
facts:

- **It runs in native MMIO mode** (no `--enable-pci`). The guest kernel ships both virtio-pci (for CH)
  and virtio-mmio (§8.3), so one `vmlinux` serves CH over PCI and Firecracker over MMIO. MMIO is the
  default for backend maturity and the shared `vmlinux`, **not** because PCI blocks snapshot — FC
  **v1.16.0** supports `--enable-pci` + snapshot (Appendix A, reversal 1).
- **Snapshot/restore is wired and validated end-to-end.** The historical first-post-restore-`exec` drop
  was never the guest re-attach defect it presented as; it fell to the guest agent's generic
  re-bind-after-restore loop (§4.3) plus two host-side behaviors. First, `MicroVm::snapshot()`
  invalidates the cached `AgentClient` after a successful backend snapshot — FC severs established vsock
  connections across pause/snapshot/resume where CH keeps them alive; invalidating uniformly costs at
  most one cheap reconnect. Second, FC re-binds the snapshot's recorded host vsock UDS path *verbatim*
  (no load-time override in v1.16), so `restore()` re-creates that baked path's parent directory before
  `PUT /snapshot/load` (the ancestor's scratch dir is gone by then; `Drop` removes the resurrected dir).
  The declared contract is `restore_rotates_host_paths: false`: a lineage's restores share one host
  vsock path, so `restore()` runs a fail-loud liveness guard (`reject_live_baked_vsock`, a 100 ms
  `UnixStream::connect` probe — a live listener is a typed `Error::Vmm` "still in use", never a silently
  unlinked live VM's socket; a stale file is removed; the TOCTOU window is documented as a misuse guard,
  not a security boundary). Concurrent restores from one lineage stay unsupported (subsumed by the
  single-snapshot-CoW gap, §16). Relatedly, `create()` attaches the entropy device (`PUT /entropy` →
  virtio-rng → guest `/dev/hwrng`) — without it the post-restore reseed reports `reseed_applied: false`
  and restored clones replay frozen CSPRNG state. `lazy_restore` stays an honest `false` (no UFFD
  backend wired, §16); the capability unit test pins `snapshot_restore` *true* and
  `restore_rotates_host_paths`/`lazy_restore` false.
- **Extended-FPU restore is constrained at the CPU layer.** FC restore can mishandle the guest's saved
  extended-FPU (XSAVE) state, so the boot applies a static **`T2` CPU template** (masking the extended-state
  CPUID bits) plus **`noxsave`** on the guest cmdline as a **no-template fallback** (gated to
  `template.is_none()`). The operational consequence: `noxsave` disables guest AVX/AVX2 down to an SSE2
  floor, a *test-fidelity* cost, so **SIMD-correctness-sensitive tests belong on the CH tier** (no such
  constraint). The forensic history — the `restore_fpregs_from_fpstate` panic, the rejected `bookworm`
  downgrade, the Lunar Lake T2 rejection, and the AVX2/YMM vs AVX-512/ZMM findings — is Appendix A,
  reversal 3.

**QEMU `q35` — the fallback and most-proven nester.** Full feature set (virtio-fs, vhost-user-net,
nesting). Use **`q35` with `virtio-net-pci`**, not `microvm` — QEMU 10.2.1's `microvm` cannot boot these
PVH (the paravirtualized direct-boot entry protocol CH/FC use) kernels to userspace at all, and it is the
machine type, not the virtio-net device or header size, that is the blocker (the early-boot-`#DE`
diagnosis, reproduced ~24 ways, is Appendix A, reversal 7). QEMU reports `snapshot_restore: false`: over its **unprivileged** external `vhost-device-vsock`
path the vsock daemon is a stateless vhost-user backend that cannot migrate (§12.1). A **privileged
in-kernel `vhost-vsock`** config *is* snapshot-eligible — QEMU 10.2 sets no migration blocker on
`vhost-vsock-pci`, and `migrate`→`-incoming` restore was verified live — but the backend
`snapshot()`/`restore()` are not yet wired (§16). Wiring the unprivileged smoltcp NAT to QEMU also
requires a carried patch to `vhost-user-backend`+`vhost` — the crates.io-packaged sources vendored
in-tree and wired via workspace-root `[patch.crates-io]` path entries with exact `=` pins — that relaxes
a `PROTOCOL_FEATURES` check only until the guest's features are acked
(confirmed by a live message trace — §10.4). Cold boot ≈965 ms.

### 3.3 The capability matrix

| Capability | CH | Firecracker | QEMU |
|---|---|---|---|
| `snapshot_restore` | **✓** | **✓** *(single-lineage host paths — `restore_rotates_host_paths: false`, §16)* | ✗ *(privileged in-kernel-vhost-vsock validated, unwired)* |
| `lazy_restore` (demand-paged) | ✓ (`--restore … prefault=on\|off`) | ✗ | ✗ |
| `restore_rotates_host_paths` | ✓ *(restore config-rewrite; enables concurrent zygote fan-out, §9.4)* | ✗ *(verbatim baked vsock path — single-lineage)* | ✗ |
| `virtio_fs_shares` | ✓ | ✗ (block-only) | ✓ |
| `unprivileged_vhost_user_net` | ✓ | ✗ | ✓ |
| `nested_virt` | ✓ | ✗ | ✓ |
| `virtio_console` | ✓ | ✗ *(rejected fail-loud before the cmdline is built)* | ✓ |
| cold boot (p50, §15) | ≈316 ms | ≈764 ms | ≈965 ms |
| warm restore (p50, §15) | ≈58 ms | ≈24 ms | — |

The cold-boot/restore inversion pins each backend's role: CH is the feature-complete default
and cold-boot leader (and the fully-featured snapshot tier); Firecracker cold-boots slower than CH but
restores fastest, earning the density/snapshot tier now that its warm restore is validated end-to-end
(with the single-lineage host-path constraint, §16); QEMU is the
slowest cold-booter, the fallback for the awkward cases, and the most-proven nester. The orchestrator reads roles off
`capabilities()`; the test/bench matrix **skips — never fails** — a scenario a backend can't run.

The one law that explains every snapshot entry above — *a VM is snapshot-eligible only if no vhost-user
device is attached to it* — is stated and enforced in §12.1.

`restore_rotates_host_paths` carries a second role beyond the restore-time path rewrite: it is the
**concurrent zygote fan-out gate** (§9.4). Copy-on-write gives each clone its own snapshot *files*, but it
cannot change a host path a backend bakes into the binary snapshot state; only a backend that rewrites host
paths per restore can hand N *concurrent* clones distinct vsock/serial/tap paths. So `Zygote::spawn_clones`
reads this flag and refuses a concurrent fan-out (`n > 1`) on a backend where it is `false` — a typed
`Error::Unsupported`, never a silent socket collision. Reusing the existing capability (rather than a
bespoke fan-out flag) keeps the "report, don't assume" discipline intact and cannot drift out of sync.

---

## 4. Control plane: vsock and the guest agent

### 4.1 The protocol

The shared crate `vmcell-protocol` defines a small length-prefixed, `serde`+`postcard`-framed message
enum — the **only** code shared between the host and the guest agent:

```rust
#[non_exhaustive]
pub enum Message {
    Ready, Exec(ExecRequest), Stdout(Vec<u8>), Stderr(Vec<u8>), Exit(i32), PutFile { .. },
    Resync { unix_secs: u64, unix_nanos: u32, mac: Option<[u8; 6]>, ipv4: Option<Ipv4Reconfig> }, // host→guest, §9.2 (H-VMM-1)
    ResyncAck { clock_error: Option<String>, reseed_applied: bool, mac_applied: bool, ip_applied: bool }, // guest→host
}
```

There is **no `Hello`, no `Ping`** — a dead variant and a no-op variant are both the "dead protocol
advertised as live" smell the review rubric bans; `#[non_exhaustive]` makes re-adding either non-breaking
if a real use appears. Every variant is live: the guest sends `Ready` as the **first frame** after
`accept`, and the host blocks for it — this is the handshake the restore path re-runs (§4.2); the
`Resync`/`ResyncAck` pair carries the one-shot post-restore state refresh natively (§9.2), replacing what
were three subprocess `exec`s. `Ipv4Reconfig { addr: [u8; 4], prefix_len: u8, gateway: [u8; 4] }` (also
in `vmcell-protocol`) carries the rotated `/30` as verbatim octets — endianness-free on the wire — and
`ip_applied` reports whether the guest's IP + default-route rotation took (`ipv4`/`ip_applied` are
appended after `mac`/`mac_applied`; `postcard` field order is wire-relevant). Frames are bounded
(`MAX_FRAME_BYTES` = 16 MiB); the default per-exec
timeout is 10 s (`DEFAULT_EXEC_TIMEOUT`).

### 4.2 The host: `AgentClient`

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
transposed at a call site. `timeouts` is the per-VM `Timeouts` knob set (§10.2): the retry backoff starts
at `connect_backoff_floor`, caps at `connect_backoff_cap`, and resets to the floor once the UDS connects;
the `OK` handshake line is read under a per-byte `connect_ok_read` deadline. `resync` is the one-shot
post-restore refresh round-trip (§9.2) — send `Resync`, await `ResyncAck`, modeled on `put_file`.

`connect` opens the host-side vsock endpoint and performs the **readiness handshake**, retrying with
backoff until the guest is listening and has sent `Ready`, OR a timeout elapses, OR the serial log shows
a kernel panic (fail fast). The transport is uniform across all three backends: each exposes a host
AF_UNIX socket with the Firecracker-style hybrid-vsock handshake (the host writes `CONNECT <port>\n`,
expects `OK <port>\n`). Three subtleties live at this interface — each presents as "a mysterious timeout,"
which is why §12.5 flags them as cross-cutting traps: the `OK` line must be read **byte-by-byte, never with
a buffered reader** (a `BufReader` pre-fetches and then discards the first framed payload); `reconnect`
after a snapshot restore is **not** a no-op (the vsock device is re-created and, on CH, the guest's
pre-snapshot listener goes deaf); and the client tracks a **desync flag** — a send error or a timeout marks
the stream desynced, and every later request fails loud until `reconnect()` restores sync, so a stale
half-read frame is never mistaken for the next response.

`exec` runs a command, streams stdout/stderr, and returns the exit status. Its timeout is **per-request**
(`ExecRequest.timeout`, default 10 s) and set long only for the builder-VM `apt`/`mmdebstrap` call —
never a single global constant, which would force every test exec to wait minutes before failing.

### 4.3 The guest: `vmcell-guest-agent` as PID 1

The agent runs as the `init=` target (`init=/usr/sbin/vmcell-guest-agent`). Its PID-1 contract is larger
than "serve the protocol," and missing any of it is painful to debug (§12.6):

- **Mount** `proc`, `sys`, `devtmpfs`, the virtio-fs tags, and set up the **tmpfs `overlayfs`** over the
  read-only erofs root; bring up loopback via `netif::set_loopback_up()` — the same offset-tested,
  `libc::ifreq`-sized (40-byte) `IfReq` + link-up path the MAC/IP rotation uses, so the agent has exactly
  one ifreq layout (an earlier inline 18-byte ifreq was a 22-byte out-of-bounds stack write in PID 1 on
  every boot: the kernel writes back the full 40-byte struct). The proxy CA is *not* installed here — it
  is baked into the rootfs trust store at build time (§11.1).
- **The guest IP is set by the kernel `ip=` boot parameter** (`CONFIG_IP_PNP=y`, §8.3), in both
  networking modes, so PID 1 does **no netlink** — there is no `ip link/addr/route` in the agent at all
  (the manual bring-up an early pass added was removed). This "zero netlink in PID 1" invariant is
  guarded *structurally*: `vmcell-guest-agent` has no `rtnetlink` dependency, asserted by a CI
  `cargo tree` gate (§12.3, §14).
- **Reap zombies** (`SIGCHLD`/`waitpid`) — PID 1 is the universal reaper — coordinated with the exec
  path's waiter through a small shared `ReaperCoordinator`, so the reaper neither steals the child's exit
  status (the false-`127` race) nor discards it. The coordination is **epoch-based** (AGENT-2, §12.6):
  the exec path captures `pre_spawn_epoch()` *before* `Command::spawn`, and `reserve(pid, epoch)`
  discards only a status recorded at or before that epoch (a genuine previous occupant of a reused pid),
  keeping a post-epoch status as the child's own for immediate delivery — an instant (~1 ms) child can
  exit and be drained by the reaper *between* spawn and reserve, and the pre-fix unconditional wipe
  stranded the waiter forever, presenting as a sporadic 10 s "Agent exec timed out". The residual
  misattribution window requires a full pid-space wrap within microseconds.
- **Never exit on a recoverable condition** — if PID 1 returns, the kernel panics with `Attempted to kill
  init`. Core mounts (overlay/`/proc`/`/dev`) stay fatal; everything else is logged and continued. Two
  such conditions were live regressions: a **virtio-fs tag that is not attached** (the exec-only path
  attaches no shares, so `virtio-fs: tag … not found` must be skipped, not propagated) and a **loopback
  ioctl failure** (cosmetic on the data path).
- **Fork** the test command as a child (not `exec` into it) so the agent stays PID 1.
- **Serve connections in a loop, re-binding after restore:** the agent serves each connection on **its own
  thread** (a stale pre-snapshot connection whose blocking read may never EOF parks instead of wedging the
  accept loop) and **re-`bind`s** its listener after a bounded idle period, because on CH the pre-snapshot
  bound listener goes deaf once the vhost-vsock device is re-created (§9.2). The accept wait is
  **event-driven**: `serve_vsock` blocks in `poll(2)` on the listener fd for `POLLIN` with the
  *remaining* re-bind idle window as the timeout (rustix's `event` feature — no new crate; the
  lean-agent gate stays green), so a host connect wakes the agent sub-millisecond instead of paying a
  mean half-interval of sleep on every connect. The idle window is an `Instant`-based deadline (last
  accept or (re)bind + `rebind_idle`), and only a *real* accept restarts it — an `EINTR`'d poll (PID 1
  takes `SIGCHLD`, and `poll` never auto-restarts) and a spurious `POLLIN`→`WouldBlock` wakeup re-poll
  with the recomputed remainder without resetting the deadline, so a deaf post-restore listener still
  runs out the clock and re-binds. `POLLERR`/`POLLHUP`/`POLLNVAL` and non-`EINTR` poll errors are logged
  and treated as the deaf-listener case (re-bind, never exit); the poll timeout carries its own 1 ms
  floor so a sub-ms remainder cannot truncate to a busy-spinning `0`. Consequently
  `guest_accept_poll`/`vmcell_accept_poll_ms` paces only the bind-failure retry (§8.3); the pure deadline
  helpers (`next_deadline`/`remaining_idle`/`poll_timeout_ms`) are unit-tested red-on-inverse.

Because it executes as PID 1 on an already-mounted rootfs that ships `libc6`, the agent could be
dynamically linked against the rootfs glibc; today the shipped `GuestAgentStage` builds it as a
**static-glibc (crt-static)** binary — self-contained, so it does not depend on the base image's dynamic
loader, which is why the `oci2erofs` `libc6` scan (§8.2) is a contract check rather than a hard runtime
dependency for this build. A dynamic-glibc default and a static-`musl` opt-in are both possible; §15
benchmarks those two alternatives (static-`musl` is ~6.2% *larger* than dynamic-glibc), and the shipped
static-glibc default trades a slightly larger binary for rootfs-independence. The serial console is wired
to a per-VM log for panic capture; SSH is a human-only debugging fallback, never the control plane.

---

## 5. Root filesystem and shared directories

### 5.1 The erofs read-only base + tmpfs overlay

The rootfs is a **single read-only erofs image over `virtio-blk`**, shared by all concurrent VMs with
**no per-VM copy**; per-VM writes go to a **tmpfs `overlayfs` upper**. One artifact serves every path —
cold boot, concurrent shared mounts, and the snapshot tier — because erofs over virtio-blk is read-only,
shareable, and snapshot-eligible (a plain block device, not vhost-user). erofs has **no journal**, which
removes two failure modes an earlier ext4-clone-per-VM design hit: journal-recovery panics on read-only
mounts, and concurrent-mount corruption. It is also a density lever: the host page cache holds a single
copy of the image for all concurrent guests.

If a writable *disk* overlay is ever needed (rare, given the tmpfs overlay), use reflink/qcow2-backing
rather than a full copy — minding that `FICLONE` reflink works on **XFS or Btrfs**, not ext4, where it
silently degrades to a full copy. Using **virtio-fs as an overlayfs lowerdir** is a known sharp edge
(needs redirect_dir/metacopy) and is avoided — another reason the RO base is erofs, not a virtio-fs mount.

### 5.2 virtio-fs data / binary / output shares

Shared directories use **virtio-fs, one `virtiofsd` per `Share`**, each on its own Unix socket, with
`--readonly` for `ReadOnly` shares (the flag is `--readonly`, *not* `--read-only`, which aborts the
daemon) and `--sandbox namespace`. The VMM config must set **`--memory shared=on`** for *any* virtio-fs
share to work — without a shared guest-memory region the share does not mount at all (this is the
mandatory-for-virtio-fs `shared=on`, distinct from the *opt-in* KSM `shared=off` memfd toggle in §9.3).
**Share tags are caller-defined, not built-ins** (keeping the
primitive general): a consumer names whatever mount tags it wants on each `Share`, and the guest mounts
exactly those. The mechanism: for every `Share` in `VmConfig` the orchestrator appends a
`vmcell_share=<tag>:<guest_path>:<ro|rw>` token to the guest kernel command line (consistent with the
`ip=` pattern); the guest agent reads `/proc/cmdline`, mounts each `tag` at its `guest_path`, and applies
a read-only mount for `ro` shares. The mount point is caller-controlled (`Share::with_guest_path`
overrides the `/<tag>` default). `config::build()` rejects a tag/`guest_path` containing `:`/whitespace, a
non-absolute `guest_path`, or a duplicate — each with a negative test — and the agent's cmdline parser is
unit-tested (a malformed token is dropped, never mounted read-write a share the host declared read-only).

The tags vmcell ships in its own tests/builder are `vmcell-in` (ro input), `vmcell-bin` (ro, shared
across tests so its pages stay hot — the harness's binaries arrive here so a new build does not invalidate
the rootfs), and `vmcell-out` (rw output), but they are **examples, not requirements**.

Two implementation subtleties:

- **Subprocess supervision.** A misconfigured `virtiofsd` exits immediately, but if the orchestrator only
  polls for the socket file, CH hangs forever waiting for the vhost-user socket — so the supervisor
  surfaces the child's exit/stderr *and* bounds the socket-wait with a timeout.
- **Service uid.** virtiofsd runs `--sandbox namespace` and, when started as root, drops to the invoking
  user's `SUDO_UID`. It **deliberately refuses to fall back to `nobody`** (which would `EACCES` a
  root-owned share and silently break the mount); root-with-no-usable-uid keeps privileges under
  `--sandbox namespace` with a loud warning. A dedicated per-share service-uid allocator is forward work
  (§16).

**Snapshot interaction:** attaching virtiofsd (a vhost-user device) makes a VM snapshot-ineligible
(§12.1), and that is enforced by construction — `config::build()` rejects `snapshotting` combined with
any virtio-fs share. Read-only data needed in the snapshot tier is served as an **additional erofs/block
image** instead. An in-process `fuse-backend-rs` alternative (Appendix B) is gated behind
`experiment-fuse`; it does not enforce read-only, so a read-only share on that backend is **rejected
fail-loud** with a typed `Error::Unsupported { vmm: "in-process-virtiofsd", feature: "read-only virtio-fs
share (in-process backend)" }` — never a silent write-through.

### 5.3 The in-rootfs guest-tools helper

The minimal Debian base omits `iproute2`, `curl`, and `cpu-checker` — tools a handful of integration
tests need (the snapshot test reads the rotated MAC/IP back through them, §14; the restore path itself is
native in-agent and spawns nothing, §9.2). Rather than bloat the rootfs with distro packages or weaken
the tests, the harness ships a small **Rust multicall binary, `vmcell-guest-tools`**, providing:

- `ip` — read-only interface/route/neighbour state from sysfs/procfs, plus `link set <dev> address <mac>`
  via the `SIOCSIFHWADDR` ioctl (the same ioctl logic the lean agent's `netif` module performs natively
  on restore, §9.2 — the restore path no longer execs guest-tools at all). `ip addr`/`ip route` *write*
  forms are accepted as no-ops so an orchestrator `&&`-chain succeeds without touching the boot-time IP.
- `curl` — real HTTP/HTTPS via `reqwest`, honoring proxy env vars and `-k`/`--resolve`/`--max-time` (and
  surfacing a proxy's `CONNECT` 403 the way curl does, which the egress-block test asserts on). Exit
  codes are curl-faithful: only a 2xx tunnel establishment counts as `CONNECT` success; a blocked
  domain's 403 is printed the way curl prints it (status to stderr, body to stdout) but exits non-zero;
  and a transport failure exits 7 (`CURLE_COULDNT_CONNECT`) with the full error source chain on stderr —
  never an "any proxy response → exit 0" probe. The shim's pure parsers (and its ifreq layout) are
  unit-tested.
- `kvm-ok` — a real `/dev/kvm` probe for the nested-virt test.

Two properties keep it honest. It performs the **real** operations (genuine HTTP, real `/dev/kvm`, real
procfs reads), so it is *not* a weakening of any assertion. And it is **baked into the erofs image**, not
delivered over a share: `virtiofsd` cannot enter its `--sandbox namespace` without privilege, so a share
would fail in the *unprivileged* suite; the erofs root is served over virtio-blk in both modes. A
`GuestToolsStage` builds the helper and the packer injects it with `ip`/`curl`/`kvm-ok` symlinks; the
agent prepends its dir to the exec `PATH`. The rootfs cache key folds the helper's content, so a helper
change re-bakes the rootfs. Because it needs `reqwest` (→ hyper → tokio) for real HTTP, `guest-tools` is
**not** subject to the lean-agent dependency ban — it is a *guest* binary that runs unprivileged, not part
of the host stack, so its own crate carries those deps (§10.5).

### 5.4 The rootfs-construction contract

A **rootfs builder** is any `vmcell::artifact::Stage` that produces the merged rootfs tree; the two
first-party ones (§8.2) are the host-native OCI bootstrap (`RootfsStage`, in `vmcell`) and the in-VM
full-apt `mmdebstrap` builder (in `vmcell-rootfs-builder`). This subsection is the contract a *third
party* implements to add an alternative source (a different distro bootstrap, a Nix closure, a
company-internal base) without forking `vmcell`. The contract has three obligations.

**1. Consume seed artifacts from `vmcell`, never re-derive them.** The stage reads what it needs from
`StageInputs` (§11.2), it does not fetch or synthesize these itself:

- the **`kernel` vmlinux path** — required for any source that boots a builder micro-VM (the `mmdebstrap`
  builder boots on the privileged/tap path with `Egress::Open` for real apt egress, §8.2); host-native
  sources (OCI) ignore it.
- the injected **`guest_agent`** and **`guest_tools`** binaries and the deployment **CA** — a builder
  never bakes these itself (see obligation 3); it only needs their content hashes for its cache key.
- **resolved pins** flowed from Stage 0 (`ResolvePinsStage`): the **builder-base image@digest** (via
  `vmcell::artifact::rootfs::resolve_builder_base`, reused, never re-pinned), the
  **`debian_snapshot_timestamp`**, and any source-specific pin. Pins arrive as data through
  `StageOutputs`; a builder that reaches for a tag or a live network resolution violates the pin law
  (§11, §12.9).

**2. Produce a merged rootfs TAR** — the same interchange the two first-party sources emit (§8.2): a
single tar of the complete userland, with OCI whiteout / hardlink semantics already resolved into a flat
tree (the packer materializes hardlinks and fails loud on a dangling one, §8.2). The builder's output
*is* that tar; it stops there.

**3. Emit the final erofs by calling `vmcell`'s shared `pack_erofs_with_injection` — this step belongs
to the system, not the builder.** The packer injects `vmcell-guest-agent` + the deployment CA +
`vmcell-guest-tools` (injected **after** the source merge so injected files win any collision/whiteout,
§8.2) and packs deterministically (`am-fs-erofs`, `BTreeMap`-ordered, fixed mtimes, §11.2). Routing every
source through the *one* injection+pack tail is what guarantees each rootfs is **identically** injected —
a builder that hand-rolled its own erofs could bake a stale agent or skip the CA and silently break the
handshake or the guest trust chain. The `libc6`/`libc.so.6` scan-and-fail-loud and the
static-`musl` `--agent-musl` opt-in (§8.2) are enforced *by the packer*, so they apply to every source
for free — a third-party source cannot opt out.

**Cache-key discipline (§11.2 rule 3, content-addressed).** The builder's `cache_key` is a `blake3` fold
of **content and identity that travel**, never local `PathBuf`s: the **seed-kernel content**, the
**builder-base image@digest**, the **`snapshot.debian.org` timestamp**, the **baked-CA content**, and the
**guest-agent source closure** (`guest_agent_src_hash`, with a distinct missing-source marker) plus the
guest-tools content. Re-pointing any of these — a new base digest, a re-minted CA, a rebuilt agent —
invalidates the rootfs, exactly as the first-party sources fold them today. Validity is content-addressed
(hash the output), not existence-of-file; a tampered artifact with an intact `.cache_key` is rejected.
Cross-ref **§8.2** for the two first-party sources and the shared packer this contract is abstracted from.

---

## 6. Networking and egress

The "Privileged" / "Unprivileged" labels that head the two networking subsections below are the two
**operating modes** — their capabilities, how they are probed, and how they map to test suites are defined
in §6.4; here they select the network datapath.

### 6.1 Two modes, chosen by `NetConfig`

```rust
pub enum NetConfig {
    Privileged   { egress: Egress, host_services_port: Option<u16> }, // netns + tap + /30 (CAP_NET_ADMIN)
    Unprivileged { egress: Egress, host_services_port: Option<u16> }, // in-process smoltcp NAT (no caps)
    None,
}
pub enum Egress { Filtered(ProxyConfig), Blocked, Open }
```

`host_services_port` is `Option<u16>` (not a bare `bool`) because the unprivileged smoltcp NAT must know
*which* host port to register as a permanent forward-port; `None` disables host services. It is
implemented **only on the unprivileged NAT path**: `config::build()` rejects
`Privileged { host_services_port: Some(_) }` with a typed `Error::Config` — the privileged TPROXY
ruleset policy-drops everything but the web-TPROXY and proxy ports, so honoring the field would need a
new accept rule plus a host binding; the fail-loud rejection replaced a prior silent no-op (H-ORCH-3,
with a negative test), and wiring it on the privileged path is forward work (§16).

`Egress::Open` — the default — selects "**no interception proxy**"; it is *not* arbitrary outbound
egress. Connectivity under `Open` is only what the mode's datapath natively provides: the unprivileged
NAT reaches the registered `host_services_port`/proxy forwards, and the privileged path reaches only
what its TPROXY ruleset admits — dialing a frame's real destination / host masquerade is not implemented
in either mode (H-NET-4; closing the gap, by real re-origination or a typed `Unsupported`, is recorded
in §16). `Open` stays the default because the mmdebstrap builder and the lifecycle/host-endpoint tests
rely on it, and none of them needs arbitrary egress.

**Privileged (`tap`).** A per-VM network namespace, a tap, and a `/30` on `10.200.<n>.0/30` (host `.1`,
guest `.2`), where the third octet is `n = (vmid % 254) + 1` (§10.2), via `rtnetlink`. Full L2 fidelity; needs `CAP_NET_ADMIN`. This is the default for
fidelity-sensitive tests and the only network path eligible for the snapshot tier (§12.1).

**Unprivileged (`userspace`).** An in-process **smoltcp** TCP/IP stack behind a `vhost-user-backend`
vhost-user-net device — no tap, no `CAP_NET_ADMIN`. Lower-fidelity (a userspace stack), reserved for
deployability rather than fidelity-sensitive tests, and it cannot be snapshotted (vhost-user-net, §12.1).
Five invariants make it work, each of which wedges the link — or corrupts a stream — *silently* if
violated; they are detailed in §12.8.

`passt` was the first choice for unprivileged networking but is out: smoltcp is in-process, with no
external dependency and no LSM/seccomp entanglement, so it is the better design regardless (Appendix B,
Exp 5; the earlier "passt is CH-incompatible via seccomp" reason was wrong — it was a host AppArmor
af_unix rule, not passt's seccomp, and not CH-specific).

The `/30` math is a pure function and unit-tested; the netlink calls, the `nft` invocation, and the
smoltcp NAT's packet loop are the side-effecting part, behind injectable `Netlink` / `NftApplier` seams.

### 6.2 Host-served endpoints

A host test server is reachable from the guest and not exposed to other systems — by a different
mechanism per mode: on the privileged tap path the guest dials the per-VM gateway address
(`10.200.<n>.1`) directly, while on the unprivileged NAT the server's port is registered up front via
`host_services_port` as a permanent forward-port (the only mode that consumes the field, §6.1). Per-test
server config and dynamically-assigned ports are configured *after* the server
is listening. Arbitrary TCP/UDP works; vsock
is available as an alternate, IP-stack-free host↔guest channel.

### 6.3 The transparent egress proxy

A `hyper`-based MITM proxy (`hudsucker` supplies the whole MITM stack — `hyper`+`rustls`+`rcgen`). For
HTTP it splices/logs; for HTTPS it terminates TLS with an on-the-fly cert minted by an in-memory CA
(`rcgen`) and re-originates upstream. The CA is baked into the guest trust store, so HTTPS interception
works in both networking modes. The CA is minted once per artifacts dir (default
`target/vmcell-artifacts`) and cached — deliberately *not* per-run, a recorded deviation from the
per-run CA-hygiene rule (M-NET-6): because the CA is baked into the *cached* rootfs, a per-run CA would
invalidate the guest trust chain on every run. A process-global cache keyed by artifacts dir returns the
generate-once CA and its parsed authority (re-self-signing per `authority()` call would break the
chain). Test doubles let a caller register `(Matcher, Responder)` pairs (and, for
the eval layer, record/replay cassettes). HTTPS doubles must **ignore `hyper::Method::CONNECT`** — matching
on the `CONNECT` itself breaks the tunnel and yields a TLS "unexpected eof."

The host-side interface — the surface every §14 egress test drives — is:

```rust
impl EgressProxy {
    pub async fn start(cfg: ProxyConfig) -> Result<Self>;             // listen, log, filter, dispatch
    pub async fn start_transparent(cfg: ProxyConfig) -> Result<Self>; // IP_TRANSPARENT front-end (privileged)
    pub fn ca_cert_pem(&self) -> &[u8];                               // baked into the rootfs trust store
    pub fn requests(&self) -> RequestLog;                             // observed requests, for assertions
    pub fn install_double(&self, matcher: Matcher, responder: Responder); // register a test double
    pub fn record_to(&self, cassette: &Path);                        // record/replay (eval-layer hook)
}
```

`MicroVm::proxy() -> Option<&EgressProxy>` hands the running proxy to the test so it can read the request
log (assert the observed / blocked destination), register a double, or obtain the CA cert.

The proxy *process* is mode-independent; how traffic is *steered into it* is not:

- **Privileged:** an nftables **`TPROXY`** ruleset, rendered in Rust and applied via the external
  `nft -f -` binary (no permissive pure-Rust nftables crate covers the `tproxy`/`socket` expressions,
  §10.4). TPROXY carries the original destination *in the socket* (no conntrack lookup) and preserves the
  source. The ruleset **drops udp/443 (QUIC)** rather than intercepting it — a deliberate choice that
  forces clients onto HTTP/2-over-TCP so all egress stays observable through the transparent proxy (a
  pure QUIC datapath would be opaque). The proxy listener uses `IP_TRANSPARENT` + the socket's original
  destination.
- **Unprivileged:** egress interception at **L4 inside the smoltcp NAT** — cleaner than a privileged
  front-end, since there is no tap for nftables.

**A documented limitation of the privileged path.** Full MITM interception (terminating TLS and
reconstructing absolute-form requests) is implemented for the **explicit-proxy** path — a guest that sets
`http_proxy=<gateway>:<proxy_port>` is fully MITM'd, logged, filtered, and served by doubles. The
**transparent** redirect of a *raw* 80/443 connection currently only **constrains** egress (it can drop
or block, and it observes the intended destination), not reconstruct and re-originate the request. Tests
that need full MITM point the guest at the explicit proxy; the transparent path's contract is
"observe/filter the destination," which is what the assertions check. Standing up the privileged
transparent path also required three host-side fixes worth knowing when touching `net::tap`: the FIB
policy rule needs an explicit `AF_INET` (an `AF_UNSPEC` rule returns `EAFNOSUPPORT`), the local route
needs `RT_SCOPE_HOST` (not `RT_SCOPE_LINK`, which returns `EINVAL`), and the ruleset must `accept`
`iifname <tap> ip daddr <gateway> tcp dport <proxy_port>`. A fourth subtlety lives in the proxy itself
rather than `net::tap`: the privileged Filtered proxy's runtime thread `setns()`s into the per-VM netns
to bind its listener (so TPROXY-redirected guest connections are deliverable), having first captured
`/proc/thread-self/ns/net`, and **re-enters the host root netns** after binding — a socket's netns is
fixed at `socket()` time, so the bound listener keeps receiving from the VM netns while every newly
created upstream/DNS socket originates in the root netns and reaches real networks (H-NET-3). Without
the re-entry the upstream leg was trapped in the tap-`/30`-only netns and privileged Filtered egress
could only ever serve doubles; a re-entry failure aborts proxy startup loud. (The integration test
proves in-path interception via a registered double — a real-external-upstream assertion needs internet
in CI.)

### 6.4 Operating modes: unprivileged vs privileged

The harness runs in one of **two named operating modes**, and the distinction is first-class — it governs
the network datapath, the cgroup-delegation story, how tests are split into suites (§14), and which
operations may degrade vs must fail loud (§7.2). The vocabulary replaces the older "rootless" wording,
which over-implied "zero privilege":

- **Unprivileged operation** — the process holds **KVM-group access only** (`/dev/kvm` via the `kvm`
  group, granted once with `usermod -aG kvm $USER`) and **no extra Linux capabilities**. Networking is
  the in-process smoltcp NAT; cgroup limits use whatever a `systemd-run --user` delegation provides. KVM
  access is a *group membership*, not a capability, so "unprivileged" means "no `CAP_*`," not "no access."
- **Privileged operation** — the process holds **`CAP_NET_ADMIN`** (tap, rtnetlink, nft/TPROXY),
  **`CAP_SYS_ADMIN`** (per-VM netns + `setns`), and **`CAP_DAC_OVERRIDE`**. Networking is the full
  netns+tap+`/30` path with L2 fidelity; it is the only mode eligible for the snapshot tier (§12.1) and
  the default for fidelity-sensitive tests. The caps are granted to the test binary alone via the
  **capability runner** `vmcell-test-runner` (§14), leaving cargo/rustc unprivileged and outputs
  dev-owned — *not* `sudo -E cargo test`.

**Why three caps, not two.** `CAP_DAC_OVERRIDE` is load-bearing: the privileged tap path could never
create a netns without it, because `netns_rs::NetNs::new` must create `/var/run/netns/<name>`, a
`root:root 0755` directory the dev-uid process can't write (`EPERM`). It also unblocks the benchmark-only
sysfs/procfs knob writes (CPU-frequency pinning, KSM), since those `root:root` kernfs files honour
`DAC_OVERRIDE` — whereas `drop_caches`, a procfs sysctl special-cased on `euid==0`, does not.

**Mode selection is probed and fail-loud, not discovered mid-run.** Before a privileged run the harness
verifies it holds the three caps and that `/var/run/netns` is reachable; an unprivileged run verifies
KVM-group access. A requested mode whose prerequisites are absent errors up front with the remediation.
The two modes are exercised by two named test suites (§14).

**Two host-environment caveats.** (1) The privileged tap path needs the harness in a **non-threaded
`domain` cgroup scope** and, for limit enforcement, in a delegated leaf — run it under `systemd-run --user
--scope -p Delegate=yes` (§7.3). (2) Modern Ubuntu blocks the unprivileged-userns escape hatch by default
(`kernel.apparmor_restrict_unprivileged_userns=1`); Debian Trixie does not necessarily, so the host
distro affects whether unprivileged mode gets off the ground. **Cleanup:** a killed privileged run can
leak `/var/run/netns/vmcell-net-*` (occasionally colliding with a later vmid);
the `sweep_orphans()` free function in the orchestrator module (backed by an injectable `OrphanScanner`,
reaping only non-live vmids in netns → cgroup → scratch order) cleans these — a fully-automatic periodic sweeper is still forward work
(§16).

---

## 7. Resource monitoring and limits

### 7.1 What is read and enforced

One **cgroup v2 slice per VM**, with `ResourceLimits` applied and counters read back through the injected
`CgroupFs` seam:

```rust
pub struct ResourceUsage {
    pub mem_peak_mib: u64,  pub mem_current_mib: u64,
    pub cpu_usec: u64,      pub io_read_bytes: u64,  pub io_write_bytes: u64,
    pub limits_enforced: bool,                              // the MEMORY controller is delegated (see below)
    pub mem_read_ok: bool,  pub cpu_read_ok: bool,  pub io_read_ok: bool, // per-metric availability
}
pub struct ResourceLimits {   // None => unlimited; maps to cgroup v2 keys
    pub mem_max_mib: Option<u32>,  // memory.max     pub cpu_max_pct: Option<u32>, // cpu.max
    pub pids_max:    Option<u32>,  // pids.max        pub io_max:      Option<IoMax>, // io.max
}
```

Peak comes for free from `memory.peak`; average is computed from periodic `cpu.stat`/`io.stat` deltas.
Each read carries an explicit availability boolean (`mem_read_ok`/`cpu_read_ok`/`io_read_ok`) rather than
silently reporting zero — an unread counter reported as `0` is the same lie as a missing one.

`limits_enforced` has a precise, deliberately narrow meaning (M-HOST-5): it is `true` only when the
**memory** controller is delegated into the VM's cgroup (`cgroup.controllers` lists it) — the one
controller whose silent absence lets the memory cap not fire. The read path holds only the cgroup name,
so this is *not* a per-controller (cpu/pids/io) enforcement guarantee; a caller that needs one consults
the individual control files. The field name is kept for API stability.

**There are no network byte counters in `ResourceUsage`.** cgroup v2 exposes no per-cgroup network
accounting (there is no `net.stat`), and the read path holds only the cgroup name, not the VM's netns or
interface — so synthesizing `net_rx_bytes`/`net_tx_bytes` fields would be exactly the always-zero lie
above. Per-VM egress bytes belong in a future *network*-scoped usage type that reads
`/sys/class/net/<if>/statistics` inside the VM netns; that is forward work (§16).

### 7.2 The fail-loud capability contract

An earlier stance — "unprivileged delegation degrades gracefully" — was in practice an invitation to
**silent no-ops**: a caller asks for a 256 MiB cap, the controller isn't delegated, the write fails, and
the VM runs *unlimited* while the call returns `Ok`. The rule is reversed: **a missing capability fails
loud unless the operation is explicitly classified as best-effort.** Three sub-rules make this precise
and uniform (they also govern netns/tap in §6.4 and the sysfs knobs in §15):

1. **Every host-facing op declares the OS capabilities it needs** — in its doc-comment and, where it
   gates a mode, in a queryable descriptor. (Today this is per-op checks; a single start-up
   `HostCapabilities` descriptor is the design target, §16.)
2. **A *requested functional* op that needs an absent capability returns a typed error, not `Ok`.** Asking
   for a resource *limit* that cannot be enforced is `Err(Error::CapabilityUnavailable { op, needed })` —
   matchable, carrying the exact missing capability — surfaced before the VM is handed back. The typed
   error also distinguishes *why* a limit write failed: the kernel refusing the **value** (`EINVAL`,
   e.g. an `io.max` the device rejects) is `Error::Cgroup`, so the caller is not sent chasing
   delegation, while a capability/permission errno (`EACCES`/`EPERM`/`EROFS`) is
   `CapabilityUnavailable`; the errno split is a pure function unit-tested against both inverses
   (M-HOST-4).
3. **Observation degrades; enforcement does not.** *Reads* fall back (read `memory.current`/`memory.peak`
   straight from sysfs when a higher-level interface is absent) and surface what was unavailable through
   the `*_read_ok` / `limits_enforced` booleans. A limit the caller *set* is functional (rule 2); a
   counter the caller *read* is observational (this rule).

A narrow, **explicitly-listed** best-effort tier remains for genuinely non-functional knobs — the §15
benchmark levers (CPU-frequency pinning, KSM) — which degrade to a visible `warn!` rather than aborting a
run, since "benchmarks are tracked metrics, not gates." The dividing line: *if a caller's assertion can be
wrong because the op silently did nothing, it is functional and must fail loud; if the only consequence is
a less-controlled measurement, it is best-effort and warns.*

### 7.3 cgroup delegation mechanics

Limit enforcement runs into cgroup-v2 delegation edges that compound. The cgroup side effects sit behind
an injected **`CgroupFs`** trait (`create_slice`/`delete_slice`/`read_stats`/`add_task`) with a real impl
and a recording fake, so sibling-placement, the controller-enable sequence, and the limit-file contents
are unit-testable with no `/sys` writes. The edges (detailed in §12.7): create the slice directly with
`mkdir` + direct sysfs writes (never `cgroups-rs`'s builder); place the VM cgroup as a **sibling** of the
harness (the "no internal processes" rule); write the PID directly to `cgroup.procs`; run from a
**non-threaded `domain`** scope; and treat controller delegation as the gating capability (an
undelegated `memory`/`cpu` controller makes a *requested* limit fail loud per §7.2, while *reads* fall
back to sysfs).

One non-obvious mechanism worth stating up front: `memory.max` alone does **not** bind a CH guest's RAM.
CH backs guest memory with a shared memfd, which the kernel reclaims rather than host-OOM-caps, so a
512 MiB guest under a 256 MiB `memory.max` self-OOMs *inside* the guest with the cgroup's
`memory.events oom_kill` still `0`. To make the cap bind and produce a real cgroup OOM, `create_slice`
also writes **`memory.swap.max=0`** and **`memory.oom.group=1`**.

---

## 8. Guest OS and kernel

### 8.1 The base: Debian Trixie

The guest is a minimal **Debian Trixie (13, kernel 6.12 LTS)** rootfs. Debian 13 carries security support
to 2028. The agent bypasses distro init (`init=/usr/sbin/vmcell-guest-agent`), so a larger userland does not
grow the boot working set.

### 8.2 Two rootfs sources, one erofs packer

There are two rootfs sources, living in **two crates**: the host-native **OCI bootstrap** stays in
`vmcell` (`RootfsStage`), and the full-apt in-VM **`mmdebstrap`** builder now lives in the extracted
**`vmcell-rootfs-builder`** crate (§10.1). Both are `vmcell::artifact::Stage` impls, both produce a merged
rootfs **tar**, and both converge on the *one* shared inject+pack tail owned by `vmcell`
(`pack_erofs_with_injection`, the §5.4 contract). Both sources produce that tar, which feeds a **shared
tail**: inject
`vmcell-guest-agent` + the proxy CA + the `vmcell-guest-tools` helper + the tmpfs/overlay scaffolding
(injected **after** the source merge, so injected files win any layer collision or whiteout), then stream
the tree through `am-fs-erofs` in memory. The in-process `tar2erofs`/`oci2erofs` writer is the **only**
wired erofs path — the design's `mkfs.erofs` shell fallback is unimplemented (M-ART-11, §16), so a missing
input is a hard `Error::Artifact`, never a silent fallback. The in-memory pack avoids creating device nodes
or root-owned files on the host, so it runs **unprivileged**. Tar **hardlink** entries (`EntryType::Link`)
are materialized — the link path receives a full copy of the earlier target's content (erofs needs no
hardlink dedup here) — and a hardlink whose target is absent from the merged tree or is not a regular file
is a hard `Error::Artifact`, never a silent `continue` (the pinned Debian base ships
`usr/bin/perl5.40.1`→`usr/bin/perl`, which a silent-skip packer would drop).

- **Default — OCI pull (host-native, in-Rust).** Resolve a Debian base image to a **manifest digest** (pin
  the digest, never the tag), pull manifest + config + layers with `oci-client` (no Docker/containerd),
  verify every blob against its `sha256`, decompress each layer (`flate2`/`zstd`), and apply them honoring
  **OCI whiteout semantics** (`.wh.<name>` deletions, `.wh..wh..opq` opaque-dir markers) to produce the
  merged tar. The guest never sees OCI — this is OCI strictly as a *build-time source* feeding the erofs
  packer, so direct-kernel boot, snapshot/restore, and shared-RO-erofs density are unchanged.
- **Full apt chain — `mmdebstrap` inside a builder micro-VM (`vmcell-rootfs-builder`).** Reuse
  `vmcell`'s `resolve_builder_base` to build a builder rootfs via the OCI source, boot it on this
  project's own CH stack **on the privileged/tap network path with `Egress::Open`** so apt has real
  outbound egress, then over the vsock agent run `apt-get install mmdebstrap` followed by `mmdebstrap`
  against the pinned snapshot — emitting the target rootfs as a tar on a read-write share, which the
  builder then hands to `vmcell`'s shared `pack_erofs_with_injection` (§5.4) to emit the erofs. Because
  `mmdebstrap` runs as root inside a controlled guest, apt performs the full `InRelease`/`Release.gpg`
  chain verification in-guest (refuse-on-mismatch) against the builder base image's own
  `debian-archive-keyring` — an equivalent trust root pinned transitively by the base-image digest, not a
  separately-pinned keyring file (M-ART-5) — and `mmdebstrap`, `apt`, `gpg`, and the shell all leave the
  host entirely. This source is now **extracted to `vmcell-rootfs-builder` and wired end-to-end**
  (`vmcell-cli --rootfs-source mmdebstrap`, §10.1/§11), un-deferred from the v19 "library-present but
  deferred" state, with a host apt-proxy fallback when direct egress is unavailable (§16).

The bootstrap chain is acyclic and terminates: kernel + OCI-built builder rootfs → builder VM → in-guest
`mmdebstrap` → target tar → erofs. The OCI source needs no VM, so the recursion bottoms out there. The
trade between the two sources is **provenance vs convenience**: the OCI default's digest pin is *integrity,
not authenticity* unless a cosign/sigstore signature is also verified; the in-VM `mmdebstrap` source keeps
the full apt signing chain. Notably the size argument *inverted*: the official OCI slim base is ~34–39%
*smaller* than an `mmdebstrap` build (it ships `dpkg path-exclude` rules stripping `/usr/share/locale`,
`doc`, `man`), so the builder-VM source earns its keep on provenance, not size (§15, Appendix A, reversal 6).

**Bring-your-own base image.** `vmcell oci2erofs IMAGE@sha256:DIGEST -o rootfs.erofs` runs the *same*
rootfs pipeline against any digest-pinned base image and emits an erofs the lifecycle verbs consume via
their `--rootfs` argument. OCI never becomes a runtime source. Two honest constraints: the packer **scans
the merged tar for `libc.so.6` and fails loud before packing** if it is absent (a `libc6`-less base would
boot to a dead PID 1 if the agent were dynamically linked), and a static-`musl` agent for non-glibc bases
is an **explicit `--agent-musl` opt-in**, never a silent fallback.

### 8.3 The guest-kernel config fragment and cmdline

A `vmlinux` reaches the artifacts dir by one of **three producers** (§8.5 is the contract every one must
satisfy; §10.1/§11 wire them). Two are lightweight **bootstrap** producers living in `vmcell`:
`KernelStage` **host-`make`-compiles** from pinned Debian source, and the new **`PrebuiltKernelStage`**
**downloads a digest-pinned prebuilt `vmlinux` and verifies its sha256** (the pinned bootstrap **seed**,
§8.5). The third is the in-VM download+configure+compile builder, now extracted to
**`vmcell-kernel-builder`** (§10.1): it host-fetches + sha-verifies the pinned kernel *source* tarball,
shares it read-only into a builder VM, and the guest runs `make defconfig kvm_guest.config` → append the
microvm fragment + sorted named fragments → `make olddefconfig` → `make -j vmlinux`, then copies `vmlinux`
out and verifies it is present. `vmcell-cli --kernel-source prebuilt|host-make|in-vm` selects among them.
All three emit the **same** direct-boot PVH `vmlinux` described here.

Direct-boot a custom-minimal `vmlinux` built from Debian kernel source with an explicit `microvm`
fragment **appended to** `make defconfig kvm_guest.config` — the fragment is *not* a standalone config, and
`kvm_guest.config` alone omits vsock, virtio-fs, and erofs and causes real boot failures. (Which failure
surfaces first is order-dependent: with `kvm_guest.config` *alone* the boot dies at the **erofs root-mount
panic** before userspace; the `EAFNOSUPPORT`-at-vsock symptom needs an intermediate config with erofs
present but vsock absent.) The listing below shows what the fragment *ensures is `=y`*; a few symbols
(e.g. `CONFIG_IP_PNP`) the `kvm_guest.config` base already provides and the fragment simply guarantees.
Everything the guest needs is built in (`=y`, no modules → no initramfs):

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

The kernel command line:

```text
console=ttyS0 loglevel=6 random.trust_cpu=on random.trust_bootloader=on cryptomgr.notests raid=noautodetect
root=/dev/vda rootfstype=erofs ro panic=1 init=/usr/sbin/vmcell-guest-agent vmcell_vmid=<vmid>
ip=10.200.<n>.2::10.200.<n>.1:255.255.255.252::eth0:off   # n = (vmid % 254) + 1  (§10.2); only when net != None
kvm-intel.nested=0 kvm-amd.nested=0   # ALWAYS emitted in both directions (=1/=1 when nested_virt)
vmcell_share=<tag>:<guest_path>:<ro|rw>   # one per share (§5.2)
vmcell_accept_poll_ms=20 vmcell_rebind_idle_ms=250   # from the Timeouts profile (§10.2)
```

A single shared `config::build_kernel_cmdline` emits this for all three backends (the prior per-backend
inline copies diverged — QEMU's had dropped `loglevel=` entirely, the ≈1400→~1000 ms QEMU cold-boot bug,
§15). Ordering and conditionals are load-bearing: `rootflags=noload` is auto-emitted only for the ext4
(`Block`) rootfs; Firecracker inserts its `noxsave ` fallback (when no T2 CPU template is available) right
before `init=`; the nested tokens are emitted **explicitly in both directions** — `=0` on false, not
omitted — because `-cpu host` exposes VMX unconditionally and a modern kernel defaults `nested=Y`, so
omitting on false would silently leave nesting on.

**Append-only extra args and the `init=` override (§19.2).** Two caller knobs feed this *same* builder, and
both are honored by **one predicate** so a backend never string-builds a boot token. `VmConfig::extra_kernel_args`
are appended **last**, after every token above, in caller order; "append-only" is the safety contract — an
extra arg may *add* a parameter but never *clobber* a token vmcell owns, enforced by `is_reserved_cmdline_arg`:
the arg's key (text before the first `=`, or the whole bare token) must not be in `RESERVED_CMDLINE_KEYS`
(`console`, `loglevel`, `root`, `rootfstype`, `rootflags`, `ro`, `panic`, `init`, `ip`, `kvm-intel.nested`,
`kvm-amd.nested`, `cryptomgr.notests`, `raid`, `random.trust_cpu`, `random.trust_bootloader`, `noxsave`) and
must not start with `vmcell_` (the agent *trusts* `vmcell_share=`/`vmcell_accept_poll_ms=`/`vmcell_rebind_idle_ms=`,
so a caller must not be able to spoof one), and the token must be a single whitespace/control-free word. A
one-law gate builds a cmdline exercising every emitted token and asserts `is_reserved_cmdline_arg` is true for
each, so the reserved set can never fall out of sync with the builder (§12.20). `VmConfig::init`, when `Some`,
emits `init=<custom>` in place of the fixed `init=/usr/sbin/vmcell-guest-agent` — the **only** place either init
token is constructed. A custom init *replaces* the vmcell guest agent as PID 1 and therefore forgoes the vsock
control plane; vmcell honors that consequence fail-loud rather than hanging on a listener that never answers
(§19.2). Full treatment, per-backend disk wiring, and gates: §19.

`loglevel=6` keeps the serial console attached for panic capture (§12.10 — `contains_panic` matches
KERN_EMERG lines) and for boot diagnostics (`NOTICE`/`WARN`/`ERR`, incl. the "Linux version" banner the
`boot.rs` integration test asserts on) while dropping the voluminous `KERN_INFO` (6) device-probe
output that otherwise dominates cold boot (each line is a synchronous write to the byte-at-a-time 8250
UART); it was the single largest cold-boot lever (§15). `loglevel` is set from the per-VM
`VmConfig::kernel_verbosity` knob (default `Balanced`=6; `Verbose`/`Debug` for diagnostics). The leading
`console=` token is likewise a per-VM knob, `VmConfig::console_mode` (default `Uart`→`console=ttyS0`;
opt-in `VirtioConsole`→`console=hvc0`, batched over a virtqueue so verbose logging avoids the UART
VM-exit tax — but only after virtio-pci probe, so it forfeits early-boot + pre-virtio panic capture; not
supported on Firecracker, which rejects it. The cmdline token and the backend's console device are both
derived from `console_mode` so they cannot desync). The host
also appends per-VM tuning tokens the guest agent parses (clamped, untrusted): `vmcell_share=…` (§5.2)
and `vmcell_accept_poll_ms=`/`vmcell_rebind_idle_ms=` (the guest re-bind cadence, from the `Timeouts`
profile — so a profile tunes the guest with no rootfs rebuild; since the accept loop became event-driven
`poll(2)`, `vmcell_accept_poll_ms` now paces only the bind-failure retry, §4.3; the guest re-clamps both
into `[1, 10_000]` / `[20, 60_000]` ms, garbage/overflow → the compiled default). `cryptomgr.notests` skips
the built-in crypto self-tests (~10 ms) and `raid=noautodetect` skips the md RAID autodetect scan (~2 ms) —
the only real cmdline-trimmable boot work a debug-verbosity `printk`-timestamp probe found (CH cold −6 ms /
FC −4 ms p50, at the noise floor, kept for consistent cross-backend direction at zero risk); neither
touches virtio/vsock/virtio-fs/erofs, `ip=` autoconfig, panic capture, or runtime crypto (the self-tests
are a boot-time QA pass). The same probe **disqualified** the fashionable microVM trims and they are kept
out: `i8042.nokbd`/`i8042.noaux` target a PS/2 probe that never runs here, `pci=lastbus=0` a beyond-bus-0
scan ACPI/ECAM already constrains away, `tsc=reliable` a calibration kvm-clock already skips (and it
carries clock-watchdog risk), and `no_timer_check` is auto-set under `CONFIG_KVM_GUEST=y` — all no-ops.
`random.trust_cpu=on` avoids
a possible CRNG-init stall on first `getrandom()`. The `ip=` parameter (enabled by `CONFIG_IP_PNP=y`)
sets the guest address at boot — consumed by the
kernel's IP-PNP late-initcall, not an initramfs — so PID 1 needs no netlink in either mode (§12.3). Three
precisions: `CONFIG_VHOST_VSOCK` is host-side (the base guest control plane needs only `VSOCKETS` +
`VIRTIO_VSOCKETS`; `VHOST_VSOCK` earns its place only for nested virt); the erofs decompressor `CONFIG`
must match the packer's compressor or the mount fails — the production packer ships **uncompressed**,
sidestepping the dependency at a size/page-cache cost; and the builder **auto-emits** `rootflags=noload`
for the ext4/`Block` fallback rootfs (`RootfsSource::Block`, §10.2) so the ext4 driver mounts strictly
read-only without journal recovery (recovery is a write and panics on a read-only device — erofs has no
journal, so the default path needs no such flag).

**Pinned version.** The committed kernel is **Linux 6.12.94** (the Trixie-aligned 6.12 LTS line). The bump
from an earlier 6.6.9 also fixed a from-scratch build break under modern toolchains: gcc-15 defaults to
C23, where `false`/`bool` are keywords, and `drivers/firmware/efi/libstub` was compiled without
`-std=gnu11`; 6.12.94 carries the fix (and CH boots via PVH and never uses the EFI stub, so
`CONFIG_EFI_STUB=n` is a clean alternative). The 6.12.94 `vmlinux` builds and boots on gcc-15.2.0.

### 8.4 Kernel as a benchmark dimension and a config-fragment matrix

`pins.json` carries a `kernels` registry (`<label> → {source_url, source_sha256}`) alongside the default
kernel; `vmcell build-kernels` builds each to `vmlinux-<label>`, and `bench-vm --kernel <label>` sweeps
the §15 suite per kernel (the erofs is kernel-independent, so one rootfs boots under any `vmlinux`). The
same harness also sweeps the perf knobs — `--profile default|low-latency|throughput` (the `Timeouts`
presets, §10.2), `--kernel-verbosity`, and `--console uart|virtio-console` — which is how the §15 backend ×
preset and console × verbosity matrices are produced, each run echoing its knob configuration. The
payoff of making kernel a dimension was *disproving* a wrong belief: an interleaved sweep of the latest
6.6 LTS (6.6.143 — the current point release of the 6.6 line the old 6.12-vs-6.6.9 comparison used) against
6.12.94 shows the guest kernel version is **not a material hot-path lever** (warm restore within ~2%),
settling an earlier cross-session "~2× slower" scare as host-load noise (§15).

The config-variant sweep runs off one base source (host-`make` `KernelStage`, or the extracted in-VM
`vmcell-kernel-builder` for a hermetic guest compile — both apply the fragments identically, §8.3/§8.5):
a kernel is requested as **(base label, an ordered set of named KConfig fragments)** — e.g.
`6.12.94 + [KASAN, LOCKDEP]` — with
`pins.json` mapping each fragment name to a KConfig string. Fragments are canonicalized to **sorted order**
at hash time (so `[KASAN, LOCKDEP]` and `[LOCKDEP, KASAN]` resolve to the same artifact), a non-zero
`make olddefconfig` is a fail-loud `Error::Artifact`, and the build-time blow-up (a cold KASAN build is
~45–90 min) is bounded by the content-addressed cache — CI batches by label and runs the full matrix
nightly. PREEMPT_RT is *not* a fragment (it needs an rt-patched source — a separate registry source), and
KCOV *extraction* needs guest tooling (§17); the fragment only turns the kernel capability on.

### 8.5 The guest-kernel contract

Whichever of the three producers (§8.3) emits it, a guest `vmlinux` must satisfy one contract so it is
interchangeable — a third party pinning a prebuilt, or porting to a new kernel line, checks against
*this*, not against a producer's internals.

**Required output: a direct-boot PVH-ELF `vmlinux`.** Cloud Hypervisor and Firecracker boot it via the
PVH entry (never the EFI stub, never a bzImage + bootloader), so `CONFIG_PVH=y` is load-bearing. It must
satisfy the §8.3 built-in config. Every symbol below is **`=y`, built in — no modules, no initramfs** (the
guest has no early userspace to load them):

```text
CONFIG_PVH=y                                        # PVH direct-boot entry — CH/FC boot protocol
CONFIG_VIRTIO_PCI=y  CONFIG_VIRTIO_MMIO=y           # CH=virtio-pci, FC=virtio-mmio
CONFIG_VIRTIO_BLK=y  CONFIG_VIRTIO_NET=y  CONFIG_VIRTIO_CONSOLE=y
CONFIG_VSOCKETS=y  CONFIG_VIRTIO_VSOCKETS=y         # the vsock control plane (§4)
CONFIG_FUSE_FS=y  CONFIG_VIRTIO_FS=y                # virtio-fs shared dirs (§5.2)
CONFIG_EROFS_FS=y  CONFIG_EROFS_FS_ZIP=y            # erofs RO root — the decompressor MUST match the packer
CONFIG_OVERLAY_FS=y  CONFIG_TMPFS=y                 # the tmpfs overlay over the RO erofs (§5.1)
CONFIG_EXT4_FS=y                                    # the Block rootfs fallback only
CONFIG_IP_PNP=y                                     # boot-time `ip=` autoconfig → zero netlink in PID 1 (§12.3)
CONFIG_KVM=y  CONFIG_KVM_INTEL=y  CONFIG_KVM_AMD=y  # nested virt: expose /dev/kvm to an inner VM
CONFIG_HW_RANDOM_VIRTIO=y                           # virtio-rng — feeds the snapshot entropy reseed (§9.2)
CONFIG_SERIAL_8250=y  CONFIG_SERIAL_8250_CONSOLE=y  # ttyS0 — panic/boot capture (§12.10)
```

Two contract clauses beyond the symbol list. **Provenance:** the source is verified against a **pinned
SHA** before compile (`KernelStage`/`vmcell-kernel-builder`), or the prebuilt binary against a **pinned
sha256** (`PrebuiltKernelStage`) — no tag fetch, no unverified download (§11, §12). **Decompressor match:**
the erofs `CONFIG_EROFS_FS_ZIP`/decompressor must match what the packer emitted, or the root mount fails;
the **production packer packs uncompressed** (§8.3), so a plain `CONFIG_EROFS_FS=y` mounts it, and the ZIP
option is required only for compressed images. Because the rootfs is **kernel-independent** (§8.4), **one
`vmlinux` boots any erofs** and one erofs boots under any conformant `vmlinux` — the property the
benchmark kernel-sweep and the seed below both rely on.

**The seed-kernel chicken-and-egg.** The in-VM builders bootstrap a problem: `vmcell-kernel-builder` needs
a *working guest kernel* to boot the builder VM in which it compiles a guest kernel, and
`vmcell-rootfs-builder` likewise needs one to boot its `mmdebstrap` VM. The bootstrap seed must therefore
be produced *without* an in-VM build — hence the two bootstrap producers in `vmcell`: `PrebuiltKernelStage`
(the fast path, a pinned prebuilt) and host-`make` `KernelStage` (the guaranteed fallback). The seed is
not any generic microVM kernel: this `vmlinux` must already carry EROFS + FUSE/virtio-fs + VSOCK + PVH +
overlay **built in** to boot vmcell's erofs root at all.

**Empirical finding (validated).** A **Kata Containers** prebuilt `vmlinux.container` (Linux **6.18.35**,
from `kata-static-3.32.0-amd64.tar.zst`) **boots under Cloud Hypervisor against vmcell's erofs root to
PID 1 + overlay mount** — it ships EROFS + FUSE/virtio-fs + VSOCK + PVH + overlay compiled in — so it is
the **pinned bootstrap seed**. Generic microVM kernels do **not** qualify: a **Firecracker CI** microVM
kernel (tested) omits `CONFIG_EROFS_FS`/`CONFIG_FUSE_FS` and **panics on the erofs root mount** — the exact
failure is `VFS: Unable to mount root fs`, before any userspace runs (the same order-dependent erofs-first
panic §8.3 describes). Host-`make` `KernelStage` remains the guaranteed fallback seed when no conformant
prebuilt is pinned. Cross-ref **§8.3** (the fragment/cmdline) and **§8.4** (kernel as a benchmark
dimension and the config-fragment matrix).

---

## 9. Snapshot, restore, and density

### 9.1 The warm-snapshot path

The per-test speed lever is **warm snapshot + restore**: boot the erofs-rootfs base to "agent-ready,"
snapshot once, and per-test restore + add a tmpfs overlay. This skips kernel boot on the hot path and is
measured at **≈5.4× faster than cold boot on CH** (316→58 ms p50, §15); on Firecracker warm restore is
faster still (764→24 ms, ≈32× its own cold boot). The erofs RO base needs no per-test copy, and the
only writable per-test state is a tmpfs overlay. The snapshot tier is **CH and Firecracker** (FC with the
single-lineage host-path constraint of `restore_rotates_host_paths: false`, §3.2; QEMU's privileged tier is
validated but unwired, §3.3), on the privileged/tap path with a non-vhost-user vsock and **no virtio-fs
data shares** (§12.1 — read-only data is served as an extra erofs/block image there).

The mechanics: snapshot = `pause`→snapshot→(`resume` or stay paused for immediate kill); restore returns
a **paused** instance the caller `resume()`s — never `boot()`/`create()`. The on-disk size of a suspend
image **tracks guest RAM exactly** and is flat in rootfs size (a 256 MiB-RAM guest writes an ≈256 MiB
memory file whether the rootfs is slim or fat, §15). The in-place `config.json`/sidecar path rewrites
(§3.2) are **single-use** — a plain `restore()` mutates the caller's snapshot dir in place, so it is for
*one* VM. Minting *many* identical VMs from one suspend image is the **zygote fan-out** (§9.4): reflink-
copy-on-write-copy the suspend dir per clone and restore each private copy, so on a reflink-capable
filesystem an N-VM warm pool costs ≈N×*dirtied* pages on disk rather than N×guest-RAM.

### 9.2 Restore correctness

A restored snapshot resumes at the exact instruction it was taken, so restored clones share whatever state
was frozen in. Four things must be refreshed on **every** restore, fired once on the first post-restore
`agent()` call after the vsock reconnect succeeds — as a **single native `Resync` round-trip** (§4.1),
applied in-agent by syscalls/ioctls with **no subprocess spawn** (this replaced three `exec`s — `date`,
`sh`+`head`, and the multi-MB `ip` binary — removing them from the restore hot path, §15). This is the
concentrated "a restored VM is not a fresh VM" lesson (§12.4):

- **Identity (CID) — uniqueness among *live* clones, not a forced numeric change.** The vsock CID must be
  unique across *concurrently running* restored clones. It is **not** required to differ from a torn-down
  original: the `CidAllocator` hands out the lowest free CID and reuses freed CIDs by design. So the
  correct check on a *sequential* restore is "the restored guest has a valid, live CID," **not**
  `assert_ne!(original_cid, restored_cid)` (which is over-specified and fails precisely *because* reuse is
  correct). On CH, `--restore` rebuilds the vsock device from the snapshot's `config.json` verbatim, so the
  restored guest **keeps the baked CID** (M-VMM-3): `ChInstance` reads `vsock.cid` from the restore config
  and `guest_cid()` reports that, falling back to the orchestrator's fresh allocation only if the field is
  absent/malformed — the fresh allocation still reserves host-side uniqueness but is not the guest's
  identity, which is exactly why "valid, live CID" is the right check.
- **Identity (MAC *and* IP) — rotated at the device layer, not via netlink (H-VMM-1, "rotate
  everything").** A snapshot is a *zygote*: one suspended VM is resumed into many **concurrent** children,
  each of which must have a **distinct** network identity (its own netns/tap/`/30`/MAC/IP) so they never
  collide on the host. The restore path therefore rotates the vmid, and the guest must move its whole
  network identity to match: the MAC via `SIOCSIFHWADDR`, and — superseding the earlier "leave the IP
  alone" note — the **IP + default route** via `SIOCSIFADDR`/`SIOCSIFNETMASK`/`SIOCADDRT`, all applied
  **natively in the agent** (`netif`) as device-layer writes, consistent with zero-netlink-in-PID-1
  (§12.3). The host side rewrites the baked `net[].tap` to the rotated tap in the CH restore config, so the
  guest's rotated `/30` and its host-side tap/nft wiring belong to the same vmid. The guest resumes with the
  frozen `ip=` of the *original* vmid; leaving it (the prior behavior) left every restored clone on a dead
  `/30` with silently dead egress. Both are best-effort; the ack reports `mac_applied` / `ip_applied`.
  *(This per-clone identity rotation is exactly what makes a **concurrent** zygote fan-out safe: N clones
  resumed from one suspend image each rotate to their own vmid/tap/`/30`/MAC/IP, so they never collide on
  the host. Restoring many clones in parallel from one dir also needs a copy-on-write of that dir — the
  in-place `config.json` rewrite is single-use; that is now implemented, §9.4.)*
- **Entropy** — reseed the CSPRNG by copying 32 bytes `/dev/hwrng`→`/dev/urandom` **natively in-agent**
  (no `sh`+`head`). An unreseeded `getrandom()` can stall first use by seconds, and because every clone
  resumes at the same frozen instant, RNG reuse is otherwise silent and correlated. Best-effort; the ack's
  `reseed_applied` records whether it took.
- **Clock** — a snapshot resumed much later resumes with a stale wall clock. The guest cannot fix this from
  inside (`hwclock --hctosys` reads the *restored* RTC — the old snapshot time — and sets the clock
  *backwards*; a restored snapshot may have no network for NTP). The resync is therefore **host-driven and
  mandatory**: the host reads `SystemTime::now()` and pushes it in the `Resync` message; the agent applies
  it via `clock_settime` (no `date` spawn). A guest-side clock-set failure comes back as
  `ResyncAck.clock_error` and propagates as a typed `Err` **before** the `restored` flag is cleared, so the
  next `agent()` retries (M-RESTORE-1) — and a failed resync **also evicts the cached `AgentClient`**
  (H-ORCH-2): a transport failure marks the client desynced and nothing auto-reconnects it, so leaving it
  cached would wedge every future `agent()` call on `ensure_synced`; eviction makes the next call
  re-connect and retry the whole resync. For ephemeral tests a stale clock is cosmetic; for anything
  asserting on timestamps it is not — so a resync failure surfaces.

**The post-restore vsock reconnect itself is mandatory and was the hardest restore bug to close.** It is
not a no-op, and on CH it is not merely "reuse the surviving listener": CH `--restore` rebuilds devices
from the snapshot's `config.json` (so the spawn step's `rewrite_restore_config` first moves the vsock
socket, serial file, and console file to the restore's fresh scratch-dir paths and re-points every baked
`net[].tap` to this restore's rotated tap, §3.2) *and* re-creates the vhost-vsock device, leaving the
guest's pre-snapshot bound listener deaf — so the guest agent serves connections thread-per-connection and
**re-`bind`s** after a bounded idle for the host's `reconnect` to land (§4.3). This same generic re-bind is
exactly what cured Firecracker's warm restore — no FC-specific guest fix was needed; the FC-side work was
purely host-side (invalidate the cached `AgentClient` across FC's connection-severing snapshot, re-create
the baked vsock path's parent dir, attach the virtio-rng entropy device), §3.2.

### 9.3 Density levers

RAM is the binding limit on parallelism. With DAX unavailable in CH (Appendix C), density rests on:

- **`cache=never`** on virtio-fs shares (minimal footprint).
- **The shared erofs RO base** — one host-cached copy of the image for all concurrent guests (§5.1).
- **virtio-balloon / free-page-reporting** for reclaim under host pressure.
- **KSM — opt-in, and a no-op by default on CH.** CH backs guest RAM with a **shared memfd** (`shared=on`
  → it lands in `RssShmem`), and KSM only merges **private-anonymous** pages, so global KSM deduplicates
  **0** of default-config guest RAM. The lever is an explicit `VmConfig::ksm_mergeable` that sets CH's
  `mergeable=on` **and** `shared=off` together (the coupling is mandatory). Measured, it then deduplicates
  **≈394 MiB / ~84%** across 8 identical 256 MiB guests — but `shared=off` is **mutually exclusive with
  every vhost-user path** (the NAT, virtio-fs shares), plus KSM scan CPU, so it stays **off by default**
  and `config::build()` rejects it combined with a vhost-user device.

**Measured footprint (§15):** each CH guest demand-pages **≈58 MiB of its 256 MiB**, marginal RAM per
added guest is dead-linear at ≈58 MiB, and the agent PID 1 is ≈2.4 MiB. So the RAM-tier ceiling is
≈13 GiB (the free RAM on the 30 GiB benchmark substrate, §15) / 58 MiB ≈ **~230 idle guests** (≈52 if each
faults its full 256 MiB under load). The next limits
after RAM are one-virtiofsd-per-VM, tap/netns/nft scaling, and host FD/PID limits.

### 9.4 Zygote fan-out: copy-on-write clones from one suspend image

Booting the guest kernel to "agent-ready" is the dominant per-VM cost (§15). When a workload needs *many*
identical VMs — a warm serverless pool, a fan-out of agent sandboxes, a batch of test cells — paying that
boot cost per VM is waste. The **zygote** pattern pays it once and then clones the *suspended* result:

1. **Suspend once.** Boot one VM to agent-ready and snapshot it while paused. That frozen suspend/resume
   image is the **zygote master** (`Zygote::suspend`, §10.2). It is the same snapshot the warm tier already
   produces (§9.1) — the pipeline's `SnapshotStage` output *is* a zygote master (§11.1).
2. **Copy-on-write per clone.** To mint a clone, **reflink-copy the whole suspend dir** into the clone's
   own scratch dir, then `restore()` + `resume()` from that private copy. On a reflink-capable host
   filesystem (XFS, Btrfs, bcachefs) the copy is a near-instant block-level `FICLONE` that shares physical
   storage with the master until a clone writes; on any other filesystem (ext4, tmpfs) it degrades to a
   full byte copy — correct, just not free. The copy is reported as `CowSupport::{Reflink, FullCopy}` so a
   caller building a large pool on a non-reflink filesystem can warn (or pick a different scratch dir).
   The vetted `reflink-copy` crate owns the ioctl and the fallback, so no new `unsafe` enters the tree.
3. **Fresh identity per clone.** Each clone allocates a **fresh vmid** from the shared `VmidAllocator`
   (hence a distinct `/30`/MAC/IP, §9.2), its own netns/cgroup/vsock socket, and runs the mandatory
   post-restore resync (clock/entropy/MAC/IP) on its first `agent()` call. So N clones resumed from one
   frozen instant never collide on the host.

**Why the per-clone copy is load-bearing, not an optimization.** The single-use restore path rewrites the
snapshot's `config.json` (CH) — vsock/serial/tap host paths — *in place* (§3.2). Two restores from one
shared dir race on that file and corrupt it. Restoring from a **private copy** removes the race *and*
keeps the zygote master byte-for-byte immutable (invariant §12.12), so the master can be cloned again,
indefinitely. This is the difference between v18's single-use snapshot and v19's reusable zygote.

**The concurrent-fan-out gate is a capability, not a flag: `restore_rotates_host_paths` (§3.3).** CoW gives
each clone its own *files*, but it cannot change a path a backend **bakes into the binary snapshot state**.
CH rewrites every host path per restore into the clone's own scratch dir (`restore_rotates_host_paths:
true`), so N concurrent CH clones each get a distinct vsock/serial/tap — fan-out works. Firecracker re-binds
the vsock UDS baked into its `snapshot_file` **verbatim** (`false`, no v1.16 load-time override), so two
concurrent FC clones would fight over one socket path — and copying the dir does not change the baked path.
So `Zygote::spawn_clones(n)` **refuses `n > 1` on a non-rotating backend with a typed `Error::Unsupported`**
rather than letting the clones collide; a *single* FC clone (sequential lineage) is still fine. This reuses
the exact capability the warm tier already declares — the descriptor that says "this backend rotates host
paths on restore" is precisely the property that makes concurrent fan-out possible, so there is no new flag
to keep in sync (a bespoke fan-out boolean would be a second source of truth for the same fact, free to
drift from `restore_rotates_host_paths` — exactly the "report, don't assume" trap §3.1 warns against).

**Cost model.** A `FullCopy` pool costs N×guest-RAM of disk and copy bandwidth (the ext4 case); a `Reflink`
pool costs ≈N×*dirtied* pages, near-zero at rest, because CH maps the memory file read-mostly and only the
tiny per-clone `config.json` diverges. RAM is unchanged from §9.3 (each clone still demand-faults its own
≈58 MiB); the zygote win is **wall-clock and disk**, not RAM. `spawn_clones` mints the pool **concurrently**
and is **all-or-nothing**: if any clone fails, the ones already up are torn down in the documented order
(§12.10) and the first error is returned — no half-built pool leaks. Measured on CH: a live pool of 3
concurrent clones from one zygote, each with a distinct vmid/MAC/vsock and a working `exec`, with the master
`config.json` byte-identical afterward (§14).

---

## 10. The Rust library (`vmcell`)

### 10.1 Workspace layout

A cargo **workspace** (2024 edition). The workspace root is a pure `[workspace]`; its members are:

- **`vmcell`** — the library (plus the `bench-vm` harness), one package carrying the host feature stack
  (§10.5). It keeps the two **bootstrap** artifact producers — the OCI-image rootfs source (`RootfsStage`)
  and the two bootstrap kernel producers (`KernelStage` host-`make`, `PrebuiltKernelStage` download+verify)
  — and exposes the shared utilities the extracted builders reuse (§5.4, below). The workspace crates
  version **independently**, not in lockstep — `vmcell` is at **0.6.0** (0.4.0→0.5.0 for the CLI
  extraction and the newly-`pub` builder-reuse surface, then 0.5.0→0.6.0 for the `resource_prefix` /
  `vmcell::naming` surface the daemon needs, §10.2/§18.4) and `vmcell-protocol` at 0.3.0 (the additive
  `Resync`/`ResyncAck` variants and the `AgentClient` `Timeouts`-param arity change drove those bumps);
  `vmcell-test-runner` is at **0.3.0** (the `vmcell-privilege` extraction, §18.2), the five daemon/privilege
  members (`vmcell-privilege`, `vmcell-daemon`, `vmcelld`, `vmcell-daemon-client`, `vmcelld-ctl`, §18) version
  from **0.1.0**, and the remaining binary members version lower.
- **`vmcell-rootfs-builder`** — the extracted full-apt in-VM `mmdebstrap` rootfs source (§8.2). A
  `vmcell::artifact::Stage` impl that **depends on `vmcell`**: it boots a builder micro-VM on the
  privileged/tap path with `Egress::Open` for real apt egress, runs `apt-get` + `mmdebstrap` over the
  agent to a merged tar, then calls `vmcell`'s shared `pack_erofs_with_injection` to emit the erofs, reusing
  `vmcell::artifact::rootfs::resolve_builder_base`.
- **`vmcell-kernel-builder`** — the extracted in-VM download+configure+compile kernel builder (§8.3). A
  `vmcell::artifact::Stage` impl that host-fetches + sha-verifies the pinned kernel *source* tarball, shares
  it read-only into a builder VM, and drives the guest `make defconfig kvm_guest.config` → fragments →
  `make olddefconfig` → `make -j vmlinux` → copy-out + verify.
- **`vmcell-cli`** — the **composition-root** crate carrying the `vmcell` CLI (`build`, `build-kernels`,
  `oci2erofs`, the lifecycle verbs, `bundle`). It **depends on `vmcell` + both builder crates** and
  assembles the `Pipeline`, choosing bootstrap vs in-VM builders via `--rootfs-source oci|mmdebstrap` and
  `--kernel-source prebuilt|host-make|in-vm`. Moving the CLI **out of the `vmcell` package** is what keeps
  the dependency graph acyclic (below).
- **`vmcell-protocol`** — the framed postcard wire enum and the `ExecRequest`/`ExecOutcome` types; the
  *only* code the host and the guest agent share.
- **`vmcell-guest-agent`** — the guest PID-1 binary (plus a small `ReaperCoordinator` library). Lean:
  `rustix`/`signal-hook`/`vsock`/`libc`/`tracing`, no host async stack.
- **`vmcell-test-runner`** — the privileged-test capability runner (§14). Lean: `rustix`/`capctl`/`libc`
  only, never the `vmcell` library.
- **`vmcell-guest-tools`** — the in-rootfs `ip`/`curl`/`kvm-ok` helper (§5.3). A *guest* binary; needs
  `reqwest` for real HTTP, so it is leaner than the host but not as lean as the agent.
- **`vmcell-privilege`** — a **lean** library crate (`rustix`/`capctl`/`libc` only, never the `vmcell` host
  stack) holding the capability/blessing predicates that were private to `vmcell-test-runner`'s `main.rs`,
  extracted so the daemon and the runner share **one** copy of security-critical logic (§18.2). Subject to the
  same per-member lean-tree assertion as the runner (no `tokio`/`hyper`/`rtnetlink`).
- **`vmcell-daemon`** — the control-plane daemon **library** (host stack, §18): the artifact store, the owning
  VM `Registry` over the `VmLauncher`/`VmHandle` seam, the start-up orphan sweep, the axum router + handlers,
  the bearer-auth layer, the OpenAPI document, and the request/response DTOs (the well-tested logic — the binary
  is a thin wrapper).
- **`vmcelld`** — the daemon **binary**: a thin blessed wrapper that runs the blessing **precondition** (the
  three caps must be in its effective set, §18.2), parses `--artifacts-dir`/`--bind`/`--api-key-file`/
  `--resource-prefix`, runs the start-up sweep, builds the server from the library, and serves — tearing every
  owned VM down gracefully on a clean shutdown signal. In tests/dev it is launched **through the blessed
  runner**, so it is never blessed on the hot path.
- **`vmcell-daemon-client`** — the client **library**: a typed `reqwest` client whose Rust API mirrors the
  `vmcell` entry points (§18.7), re-exporting the DTOs from `vmcell-daemon` (with `default-features = false`,
  so it links only the wire types + the artifact-name predicate) so a request the client serializes and the
  server deserializes are the **same** Rust type.
- **`vmcelld-ctl`** — the client **CLI**: a `clap` wrapper over `vmcell-daemon-client`.

Why a workspace: a member crate's build fingerprint depends only on its own (tiny) source + deps, so the
lean-tree assertion (§10.5) becomes a **structural per-member property** — no host module can leak into
the runner by construction. Extracting `vmcell-protocol` is what lets the agent be a standalone member
without a dependency edge on the whole library. The vendored vhost patch (`vendor/vhost`,
`vendor/vhost-user-backend`) is applied via `[patch.crates-io]` path entries at the workspace root (§10.4).

**The builder dependency model is a directed acyclic star, wired by artifact-path passing (§11.2).**
`vmcell-rootfs-builder` and `vmcell-kernel-builder` each **depend on `vmcell`** and reuse its promoted-`pub`
utilities — `pack_erofs_with_injection`, `resolve_builder_base`, `hash_file`/`hash_output`/
`hash_artifacts_sorted`, `ch_binary_path`, and the `HttpClient`/`ReqwestClient` — so there is **one**
implementation of each, not a per-builder fork (a divergent erofs packer or hash function across builders
is exactly the duplication-hides-divergence trap the rubric warns against). Crucially `vmcell` has **no
edge back** to either builder — it holds only its own bootstrap producers — so the graph never cycles. The
builders are `Stage` impls that pass real data through `StageInputs`/`StageOutputs` (§11.2), never via
`VMCELL_KERNEL`/`VMCELL_ROOTFS` env vars. `vmcell-cli` is the **composition root**: it depends on all three
(`vmcell` + both builders) and is the *only* crate that names a builder, assembling the `Pipeline` from
bootstrap or in-VM stages per `--rootfs-source`/`--kernel-source`. This is why the CLI had to leave the
`vmcell` package — a CLI *inside* `vmcell` that referenced the builders would force `vmcell → builder →
vmcell`, a cycle; hoisting it into `vmcell-cli` breaks it. `vmcell` bumps **0.4.0 → 0.5.0** for the
extraction plus the newly-`pub` reuse surface (a `cargo semver-checks` event on the PR), and
**0.5.0 → 0.6.0** for the `resource_prefix`/`vmcell::naming` surface the daemon layer needs (§10.2/§18.4).
The five daemon/privilege members form a **second** acyclic star on top of `vmcell` — the daemon depends
on `vmcell` (never the reverse), and the client links only the daemon's DTOs — with `vmcell-privilege`
sitting in the lean tier beside `vmcell-test-runner`; the full graph is §18.1.

The `vmcell` library's module tree (`crates/vmcell/src/`), each module's job in one line:

```
lib.rs           # public re-exports; crate lints (deny missing-docs, unwrap, panic, print, indexing under not(test))
error.rs         # the crate Error enum + Result<T>
config.rs        # VmConfig + builder, RootfsSource, NetConfig, Share, ResourceLimits, RestoreMode  (host-common)
vmm/             # Vmm + VmInstance traits, VmmCapabilities, Cid/Vmid types; cloud_hypervisor/firecracker/qemu; FakeVmm
agent/           # AgentClient (host vsock client, handshake + desync); re-exports the protocol wire types
fs.rs            # VirtioFsDaemon: one virtiofsd per share, perms, tags, sockets, socket-wait timeout
net/             # NetConfig dispatch: tap (netns + /30 via rtnetlink, nft TPROXY) + userspace (smoltcp NAT)
net_sys.rs       # the ONE unsafe ioctl net/ can't host (TUNSETPERSIST); net/ is #![forbid(unsafe_code)]  (net-privileged)
proxy/           # EgressProxy (hudsucker MITM), TLS CA + leaf minting, test doubles + record/replay
metrics.rs       # CgroupFs trait (real + recording fake), slice mgmt, peak/avg readers (direct sysfs writes)
cpufreq.rs       # benchmark-only CpuFreqSysfs seam: pin governor/turbo, RAII restore-on-drop
orchestrator.rs  # MicroVm handle; VmidAllocator/CidAllocator; Clock seam; ordered Drop; sweep_orphans
naming.rs        # one prefix → every per-VM resource name (net/tap/cgroup/scratch) + every sweep filter (§12.19, §18.4)
reflink.rs       # zygote CoW copy: reflink-or-copy a suspend dir per clone; CowSupport (§9.4, forbid(unsafe))
zygote.rs        # Zygote: suspend once, mint many; the concurrent-fan-out gate (§9.4)
artifact/        # Stage trait, Pipeline, cache, bootstrap kernel(host-make,prebuilt)/rootfs(oci,guest_tools)/snapshot stages, bundle; pub reuse surface for builder crates (§5.4)
```

### 10.2 Public API surface

Types are `#[non_exhaustive]` where future fields are likely; builders keep call sites stable.

```rust
// ---- config.rs ----
#[non_exhaustive]
pub struct VmConfig {
    pub vcpus: u8,               // > 0
    pub mem_mib: u32,            // >= 64
    pub kernel: PathBuf,         // vmlinux (direct kernel boot)
    pub rootfs: RootfsSource,    // Erofs { image } (default) | Block { image, overlay } | VirtioFs { dir }
    pub shares: Vec<Share>,      // virtio-fs mounts; need capabilities().virtio_fs_shares
    pub net: NetConfig,
    pub nested_virt: bool,       // needs capabilities().nested_virt (not Firecracker)
    pub limits: ResourceLimits,
    pub snapshotting: bool,      // build() REJECTS this with ANY vhost-user device (§12.1)
    pub vmid: Option<u32>,       // 1..=254; None => allocated
    pub restore_mode: RestoreMode, // Default | Eager | Lazy  → CH --restore prefault=on|off
    pub ksm_mergeable: bool,     // CH mergeable=on + shared=off; mutually exclusive with vhost-user (§9.3)
    pub kernel_verbosity: KernelVerbosity, // Quiet|Balanced(default)|Verbose|Debug → loglevel=3/6/7/8 (§8.3)
    pub timeouts: Timeouts,      // per-VM hot-path timing knobs; default()/low_latency()/throughput() presets
    pub console_mode: ConsoleMode, // Uart(ttyS0, default) | VirtioConsole(hvc0); needs capabilities().virtio_console (§8.3)
    pub extra_disks: Vec<BlockDevice>,  // extra raw virtio-blk → /dev/vd{b,c,…}, attached AFTER rootfs; snapshot-composing (§19.1)
    pub extra_kernel_args: Vec<String>, // append-only extra cmdline args, is_reserved_cmdline_arg-guarded (§8.3, §19.2)
    pub init: Option<PathBuf>,          // init= override: replaces PID 1, forgoes the control plane; build() REJECTS it with snapshotting (§19.2)
    pub resource_prefix: String,        // names AND sweeps every per-VM host resource; default "vmcell", validated [A-Za-z0-9]≤6 (§12.19, §18.4)
}

// ---- config.rs — extra virtio-blk device + its optional I/O throttle (§19) ----
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlockDevice { pub image: PathBuf, pub readonly: bool, pub io_limit: Option<DiskIoLimit> }
impl BlockDevice {
    pub fn read_only(image: impl Into<PathBuf>) -> Self;   // readonly: true
    pub fn read_write(image: impl Into<PathBuf>) -> Self;  // readonly: false
    pub fn with_io_limit(self, limit: DiskIoLimit) -> Self;
}
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DiskIoLimit { pub bandwidth_bytes_per_sec: Option<u64>, pub iops: Option<u64> } // build() rejects an all-None / any-0 limit

// ---- orchestrator.rs — the handle most callers hold ----
pub struct MicroVm<V: Vmm> { /* instance, cgroup, net, virtiofsd, cid, vmid, tmp_dir, ... */ }
impl<V: Vmm> MicroVm<V> {
    pub async fn start(vmm: &V, cfg: VmConfig, cids: Arc<CidAllocator>, vmids: VmidAllocator, cgroups: Box<dyn CgroupFs>) -> Result<Self>;
    pub async fn restore(vmm: &V, snapshot_dir: &Path, cfg: VmConfig, cids: Arc<CidAllocator>, vmids: VmidAllocator, cgroups: Box<dyn CgroupFs>) -> Result<Self>; // SINGLE-USE: rewrites snapshot_dir in place
    pub async fn restore_cow(vmm: &V, zygote_dir: &Path, cfg: VmConfig, cids: Arc<CidAllocator>, vmids: VmidAllocator, cgroups: Box<dyn CgroupFs>) -> Result<(Self, CowSupport)>; // reflink-CoW copy first (§9.4)
    pub fn vmid(&self) -> u32;
    pub fn proxy(&self) -> Option<&EgressProxy>;          // the egress-proxy handle, if egress is filtered
    pub async fn agent(&mut self, timeout: Option<Duration>, clock: &dyn Clock) -> Result<&mut AgentClient>; // None => 10 s; clock drives the first post-restore resync
    pub async fn usage(&self) -> Result<ResourceUsage>;   // reads the cgroup slice
    pub async fn pause(&mut self) -> Result<()>;
    pub async fn resume(&mut self) -> Result<()>;
    pub async fn snapshot(&mut self, dir: &Path) -> Result<()>; // snapshot-eligible only; Unsupported otherwise
    pub async fn shutdown(self) -> Result<()>;            // graceful, then verify gone
}
impl<V: Vmm> Drop for MicroVm<V> { /* kill VMM proc-group → virtiofsd → tap/netns/cgroup/overlay/tmp_dir */ }

// ---- zygote.rs — suspend once, mint many (§9.4) ----
pub enum CowSupport { Reflink, FullCopy }   // was the per-clone copy a block-level reflink, or a full byte copy?
pub struct Zygote { /* immutable master snapshot dir + the snapshot-eligible clone config (vmid cleared) */ }
impl Zygote {
    pub async fn suspend<V: Vmm>(vm: &mut MicroVm<V>, cfg: VmConfig, master_dir: impl Into<PathBuf>) -> Result<Self>; // snapshot a live VM
    pub async fn from_snapshot_dir(master_dir: impl Into<PathBuf>, cfg: VmConfig) -> Result<Self>;                    // adopt a SnapshotStage artifact
    pub async fn spawn_clone<V: Vmm>(&self, vmm: &V, cids: Arc<CidAllocator>, vmids: VmidAllocator, cgroups: Box<dyn CgroupFs>) -> Result<MicroVm<V>>;       // one CoW clone
    pub async fn spawn_clones<V, F>(&self, vmm: &V, count: usize, cids: Arc<CidAllocator>, vmids: VmidAllocator, make_cgroups: F) -> Result<Vec<MicroVm<V>>> // concurrent pool, all-or-nothing
        where V: Vmm, F: FnMut() -> Box<dyn CgroupFs>;   // Unsupported when count > 1 && !capabilities().restore_rotates_host_paths (§9.4)
    pub fn probe_cow_support(&self) -> CowSupport;         // up-front reflink probe of the master's filesystem
    pub fn master_dir(&self) -> &Path;
}
```

`MicroVm::start`/`restore` take the CID allocator (`Arc<CidAllocator>`), the VMID allocator (a
`VmidAllocator` handle passed by value — it is `Clone` over an internal `Arc<Mutex>`), and the `CgroupFs`
seam (`Box<dyn CgroupFs>`, converted to an `Arc` internally) as **three separate injected seams** (distinct
ID spaces plus the recording-fake seam). Both allocators are **process-global** — a single shared instance
per test-runner process, not one per test — because under `cargo test`'s in-process parallelism per-test
allocators hand concurrent tests identical IDs and collide on temp-dir paths and socket names.
`VmidAllocator` is either hermetic (`new()`, in-process) or cross-process (`shared()`, via
`/tmp/vmcell-vmid/<vmid>.lock` files with crashed-owner reclaim; `shared_at(dir)` injects the lock
directory so the fs claim/reclaim path is unit-testable, H-ORCH-4). Each lock file is **created already
carrying the owner pid** (never a create-then-write two-step that could crash into an empty, unreclaimable
lock); reclaim of a dead/empty/unparseable owner is serialized by an **atomic rename** so two racing
processes cannot dual-claim, and liveness is a `/proc/<pid>` check. It also injects a `Clock` (bounded
`+ RefUnwindSafe` so it doesn't strip public auto-traits) for its search seed. The VMID is mapped to the
third IPv4 octet as **`(vmid % 254) + 1`** (`10.200.<octet>.{1,2}` — a raw counter would exceed 255 and
synthesize invalid addresses), centralized in one unit-tested `/30` helper, which **caps a single host at
≈254 concurrent VMs on one `/16`** (§16). VMID range is `1..=254`; CID space is `3..=254`.

**`resource_prefix` + the `vmcell::naming` module — one string names *and* sweeps every per-VM host
resource.** A VM leaks four host resources if it dies ungracefully — a **netns**, a **tap**, a **cgroup
slice**, and a **scratch dir** — and the orphan sweep (§6.4/§18.4) filters for them. Their names were four
hard-coded `vmcell-*` literals and the sweep filtered by three more — seven copies of one prefix that had to
stay in lockstep or the sweep would silently miss a leak. `vmcell::naming` collapses them: it is the single
place that composes every name from a prefix (`<prefix>-net-<vmid>`, `<prefix>-tap-<vmid>`, `<prefix>-vm-<vmid>`,
`<prefix>-vm-<pid>-<vmid>`) and every sweep filter (`<prefix>-net-`, `<prefix>-vm-`); a unit test pins that each
produced name **starts with** its sweep filter for any prefix (§12.19, one law one predicate). The prefix lives
on `VmConfig::resource_prefix` (builder `.resource_prefix()`, `DEFAULT_RESOURCE_PREFIX = "vmcell"`, validated
`[A-Za-z0-9]`≤6 at `build()` so it is safe in an interface/netns/cgroup/dir name), and
`HostOrphanScanner::new(prefix)` matches by the same value — so two daemons with distinct prefixes never sweep
each other's resources (§18.4). The default reproduces the historical `vmcell-*` names exactly, so it is a
non-behavioral change at the default. (The VMID lock dir `/tmp/vmcell-vmid` is deliberately *not* prefixed — it
is a cross-process rendezvous that must be stable regardless of prefix, and it is not swept.)

**`Zygote` — the suspend-once, mint-many handle (§9.4).** A `Zygote` owns an *immutable* master snapshot
dir plus the snapshot-eligible config its clones restore with (the config's `vmid` is cleared, since every
clone is allocated a fresh one). `suspend()` captures it from a live `MicroVm`; `from_snapshot_dir()` adopts
a `SnapshotStage` artifact (§11.1). Both fail-fast reject an ineligible config (a vhost-user device, §12.1)
at construction, before any copy is minted. `spawn_clone` reflink-copy-on-write-copies the master into the
clone's own scratch dir and restores from that private copy (so the master is never mutated, §12.12);
`spawn_clones(count)` does the same `count` times **concurrently** and **all-or-nothing** — one shared
`VmidAllocator`/`CidAllocator` hands the clones distinct vmids/CIDs, and on any error the clones already up
are torn down in order. `spawn_clones` returns `Error::Unsupported` when `count > 1` and the backend does
not rotate host paths (`restore_rotates_host_paths == false`, §3.3) — a concurrent fan-out needs per-clone
host paths, which CoW alone cannot synthesize. `restore_cow` is the same primitive without the pool
ergonomics; the low-level CoW copy lives in `reflink.rs` (`#![forbid(unsafe_code)]` — the `FICLONE` ioctl
and its full-copy fallback are the vetted `reflink-copy` crate's, so no `unsafe` enters the tree).

**`Timeouts` — the per-VM hot-path timing profile.** Seven `Duration` fields gather every tunable hot-path
wait (defaults in ms; `low_latency()` / `throughput()` in parentheses): `connect_backoff_floor` 20 (5/10)
and `connect_backoff_cap` 100 (40/75) — the vsock connect backoff, reset to the floor once the UDS
connects; `connect_ok_read` 150 (100/150); `api_socket_poll` 5 (2/3), which paces **every** VMM
control-socket / daemon readiness wait (including QEMU's `vhost-device-vsock` daemon wait and Firecracker's
T2 CPU-template probe wait, EXP-A — QEMU create phase 140→124 ms p50); `shutdown_grace` 250 (250/50);
`guest_accept_poll` 20 (5/10) and `guest_rebind_idle` 250 (150/200), the last two emitted as
`vmcell_accept_poll_ms=`/`vmcell_rebind_idle_ms=` cmdline tokens the agent parses clamped (§8.3), so a
preset tunes the guest with **no rootfs rebuild**. `low_latency()` minimizes time-to-first-output
(tightens every connect/accept cadence, leaves teardown graceful — teardown is excluded by design, ~−28 ms
CH cold); `throughput()` minimizes whole-lifecycle wall clock (cuts `shutdown_grace` to 50 ms — graceful
teardown 283→56 ms on CH once the EXP-D deadline-before-RPC and adaptive-step rework is folded in, §15 — and
keeps cadences moderate, since tight polls cost idle-CPU wakeups in a dense farm).
Every field clamps to a correctness floor via `pub(crate) clamped()` (`connect_backoff_floor` ≥1 ms,
`cap` ≥ floor, `connect_ok_read` ≥5 ms, `api_socket_poll`/`guest_accept_poll` ≥1 ms, `guest_rebind_idle`
≥20 ms; `shutdown_grace` has no floor — 0 is legal, force-kill remains the fallback), and because the
fields are `pub`, the orchestrator **re-clamps at `start()`/`restore()`** so post-`build()` mutation can
never busy-spin PID 1 or a readiness poll (M-ORCH-3); `vmm::wait_for_socket` additionally clamps its
interval to ≥1 ms. The deliberately-*not*-in-`Timeouts` failure ceilings are correctness-floor constants
(the 2 s Ready-frame wait, the 10 s overall connect deadline, `DEFAULT_EXEC_TIMEOUT` 10 s, the QMP/join
timeouts), not knobs.

Two lifecycle nuances worth knowing at the interface. First, **`MicroVm::shutdown()`** (not the backend's
`request_shutdown()` RPC, which is only the graceful signal on `VmInstance`) computes the grace deadline
**before** issuing `request_shutdown` — the RPC round trip *spends* the grace instead of silently extending
it (worth ~20 ms on the default profile) — then polls `VmInstance::has_exited()` on an **adaptive step**
(grace ≤50 ms → 5 ms, ≤150 ms → 10 ms, else 20 ms) and returns as soon as the guest powers off, capping at
the configured `Timeouts::shutdown_grace` (default 250 ms) before the SIGKILL fallback (the EXP-D
poll-until-exit rework — `has_exited` is the `try_wait` early-return). Because the shutdown RPC's only
bound is the generic 5 s `vmm::unix_api_request` ceiling — far longer than the grace, so a slow ack would
otherwise spend the whole window — the deadline is clamped post-ack to ≥ one poll step, so a stalled RPC
still yields at least one `has_exited` check (the ORCH-7 flush grace). That `unix_api_request` ceiling
bounds **every** CH/FC control RPC over the API UDS, returning a typed `Error::Timeout` (M-VMM-2), so a
wedged control socket surfaces before any outer readiness timeout can mask it. Second, `agent()` borrows
all of `MicroVm` mutably for the returned ref's lifetime, so read the cheap immutable `vmid()`/`proxy` into
locals *before* calling it; its `clock` argument drives the mandatory first-post-restore resync (tests
inject a `FakeClock`, production passes `RealClock`). `instance_mut()` stays `pub` but carries a documented
invariant — never call `VmInstance::snapshot()` through it, because `MicroVm::snapshot()` adds the
cached-`AgentClient` invalidation that a direct call bypasses (M-ORCH-5).

The `AgentClient`, `ResourceUsage`, `ResourceLimits`, `VmmCapabilities`, `Vmm`/`VmInstance`, `NetConfig`,
and `Share` shapes are shown in §3–§7 where they are used. All per-VM temporaries (API/vsock sockets,
serial log, the unprivileged smoltcp socket) live under **one** `/tmp/vmcell-vm-<pid>-<vmid>/` owned by a
`VmTempDir` RAII guard on `MicroVm`, created *before* networking and dropped *last* in `Drop`. (The VMID
cross-process lock files and the Firecracker T2 capability-probe socket are deliberately outside it — they
outlive any single VM.)

### 10.3 The error type

One `Error` enum (`thiserror`) with a variant per subsystem, `Result<T> = std::result::Result<T, Error>`.
Two deliberate properties: there is **no `Error::Other(String)` catch-all** — the review rubric bans
exactly that — and the two most caller-relevant conditions are **typed and matchable**: `Error::Unsupported
{ vmm, feature }` (an op a backend doesn't advertise) and `Error::CapabilityUnavailable { op, needed }` (a
requested op whose OS capability is absent, §7.2). The per-subsystem variants (`Vmm`/`Agent`/`Network`/
`Cgroup`/`Artifact`/`Config`/…) still carry a `String` payload rather than a fully-typed source for every
case; `#[from]` is used where a concrete upstream type exists (`Hyper`, `SerdeJson`, `Io`, `Reqwest`,
`Postcard`). This is an accepted trade-off — matchability where it matters (Unsupported/CapabilityUnavailable),
strings elsewhere — not the `Error::Other`-everywhere anti-pattern.

### 10.4 Dependency strategy

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
- **A carried vendored patch of `vhost-user-backend`+`vhost`** is needed *only* to attach the
  unprivileged smoltcp NAT to QEMU (not CH), where a strict `PROTOCOL_FEATURES` check rejects
  `SET_VRING_ENABLE` arriving before `SET_FEATURES`. A live message trace confirms QEMU sends
  `SET_VRING_ENABLE` first while CH sends features first, and upstream 0.22/0.16 still enforce the guard —
  so the patch addresses a genuine QEMU ordering quirk, not a masked backend bug. It is now the
  **crates.io-packaged sources vendored in-tree** (`vendor/vhost` 0.16.0, `vendor/vhost-user-backend`
  0.22.0 — content in git, stronger than pinning a git-fork rev), wired via `[patch.crates-io]` path entries
  at the workspace root with exact `=` version pins. The `SET_VRING_ENABLE` `PROTOCOL_FEATURES` relaxation
  is **gated on `features_acked`** (accept QEMU's early delivery, re-enforce the spec check after
  `SET_FEATURES` — narrower than the original blanket relaxation, M-VEND-2), and the disabled check carries
  an at-site rationale comment (M-VEND-1). `just ci` asserts via `cargo tree` that both crates resolve from
  `vendor/` so a future version bump cannot silently drop the patch with only a cargo warning (M-VEND-3).
  It is permissively licensed (rust-vmm, Apache-2.0); drop it (delete `vendor/` + the `[patch]` entries) if
  the QEMU-unprivileged tier is dropped. (Because `just ci` sets `RUSTFLAGS=-D warnings` process-wide, the
  vendored code's unused helpers carry `#[allow(dead_code)]` so the gate doesn't abort in it.)
- **Trust `cargo-deny`, not hand-written license labels.** An earlier draft mislabeled `rustables`
  MIT/Apache when it is GPL-3.0 — exactly the class of error the allow-list catches.

`virtiofsd` is `cargo install`'d (a rust-vmm binary, Apache/BSD), so shared-directory support needs no OS
package. Irreducibly external: `cloud-hypervisor` (pinned release binary), the kernel build toolchain,
`nftables` (`nft`), `qemu-system-x86` (fallback only), and KVM. **License gate:** `cargo-deny` enforces an
allow-list (`MIT`/`Apache-2.0`/`BSD-3`/`BSD-2`/`ISC`/`Zlib`/`0BSD`/`Unicode-3.0`/`CDLA-Permissive-2.0`) for
all *linked* crates on every build, and ignores a set of dormant `unmaintained` advisories from the
`tokio-0.1` tree that enters only via `tun-tap 0.1.4 → tokio-core → tokio 0.1.22` (the optional privileged
tap path), each with a per-crate rationale.

### 10.5 Features and build targets

The build *shapes* (things you compile and ship) are four: **the library + CLI + `bench-vm`** (the host
stack), and the three lean *binary* member crates (**agent**, **test-runner**, **guest-tools**). The
workspace has a fifth, non-shape member — the `vmcell-protocol` *library* crate the host and agent share
(§10.1). So §2/§10.1's "four lean member crates" (protocol + the three binaries) and this section's four
build shapes are the same cardinality with different membership: the member count includes `vmcell-protocol`
(a library, never shipped on its own) and excludes the host stack; the shape count is the reverse. Within
the `vmcell` library the per-component
features remain (`cloud-hypervisor`, `firecracker`, `qemu`, `net-privileged`, `net-unprivileged`, `proxy`,
`metrics`, `pipeline`, `cli`), but each pulls in a **`host-common`** umbrella that turns on the whole host
module set, and `host-common` in turn lists the per-module features — an intentional feature cycle cargo
accepts and unifies. The effect: **any host feature yields the whole coherent stack**, so there are no
incoherent partial-host configs. This retired the fine-grained matrix that used to be the direct source of
feature-gating build breaks (an un-`cfg`'d `#[from]` variant broke `--features agent`; modules gated on the
wrong feature made single-feature combos fail to compile). The feature powerset is now a **blocking** CI
gate (all combos compile). The trade-off is deliberate: there is no minimal backend-only library build any
more — a `--features qemu` build still pulls the full host stack (reqwest/oci-client/pgp) — which is fine,
since no real deployment used a partial host build.

The leanness that *does* matter — the two privileged-window binaries and the guest agent must not drag in
the host async stack — is a **structural per-member property**: each is its own crate, so building the
member *is* the lean build. A CI `cargo tree -e no-dev` per member asserts `agent` and `test-runner`
contain no `tokio`/`hyper`/`rtnetlink`. **`guest-tools` is deliberately *not* under that ban** — it needs
`reqwest` (→ hyper → tokio) for real HTTP and runs unprivileged in-guest, so its lean boundary is "not the
host *library*," not "no async."

**Toolchain note.** The crate targets `rust-version = 1.85` (the 2024-edition baseline), but the committed
`Cargo.lock` pins `time 0.3.47` to fix `RUSTSEC-2026-0009`, and `time ≥ 0.3.47` needs Rust 1.88 — so a
*from-scratch* build needs Rust ≥ 1.88, and a `cargo update` on a 1.85 toolchain would *downgrade* `time`
back to the vulnerable 0.3.45. Treat 1.88 as the effective build floor until the MSRV is bumped.

### 10.6 Testability seams

Four accommodations make the orchestrator unit-testable without KVM or root. **They are load-bearing, not
optional** — an implementation that skipped them (calling `ip`/`nft` directly, using module-global
`static AtomicU32` counters) is precisely why a class of correctness bugs was review-only.

1. **The `Vmm`/`VmInstance` trait seam.** A `FakeVmm` implements both traits in memory, letting the
   orchestrator's logic (allocation order, ordered `Drop` cleanup, retry/timeout, snapshot-vs-cold-boot
   selection) be unit-tested with no KVM, root, or subprocess. `FakeVmm` today records calls only; the
   retry/timeout and failure paths are exercised through the other recording seams (`FakeGuestResync`, an
   enforcement `CgroupFs`, a hand-built `MicroVm`) rather than by driving faults into `FakeVmm` itself
   (M-VMM-6, a still-open seam-enrichment).
2. **Pure/imperative split.** The genuinely-testable pure functions are isolated from I/O: nft-rule
   rendering, `/30` arithmetic, the CH REST payload builder, the vsock handshake state machine,
   cgroup-path construction, per-VM scratch-dir construction, the artifact `cache_key`, the accept-loop
   deadline policy (`next_deadline`/`remaining_idle`/`poll_timeout_ms`, §4.3), and the protocol codec.
3. **Injectable side-effect traits** — `Netlink`, `NftApplier`, `CgroupFs`, `SerialLog`, `Clock`,
   `OciPuller` (`RealOciPuller` + a recording/replaying `FakeOciPuller` serving canned manifests/blobs),
   `GuestResync`, and `VmidAllocator::shared_at`'s injectable lock directory — each with a real
   implementation and a recording fake, so `net`/`metrics`/`agent`/`artifact` orchestration can assert
   "the right rules/limits/handshake/pull were requested" without touching the host.
4. **Deterministic IDs and clocks** are injected, never module-global statics, so tests are reproducible.

The rule that follows: **a subsystem that cannot be unit-tested against a fake is, by this design, not
done** (§14). One nuance the seams make honest: the zero-netlink-in-PID-1 invariant (§12.3) is *not*
guarded by a `Netlink` fake — the guest agent has no netlink seam to inject because the manual bring-up was
*deleted* — so it is guarded structurally by the CI assertion that `vmcell-guest-agent` has no `rtnetlink`
dependency at all.

---

## 11. Artifact build pipeline

Maps onto the artifact-production requirements: staged, pinned, deterministic, cacheable, resettable,
minimal external access, record/replay, signing-chain verified. Exposed as the library `artifact::Pipeline`
and as CLI verbs. The **bootstrap pipeline stays in `vmcell`** (the `Stage` trait, `Pipeline`, the cache,
and the bootstrap producers — OCI rootfs, host-`make`/prebuilt kernel, snapshot); the **in-VM builders are
`Stage` impls in their own crates** (`vmcell-rootfs-builder`, `vmcell-kernel-builder`, §10.1). The
composition root that assembles a `Pipeline` from either set is **`vmcell-cli`** (§10.1), which implements
`build`, `build-kernels`, `oci2erofs IMAGE@DIGEST`, `run`/`create`/`snapshot`/`stats` (live-handle
lifecycle taking `--kernel`/`--rootfs`), and `bundle`/`verify-bundle` (a digest-pinned fetch-and-verify
manifest of the built artifacts), and selects bootstrap vs in-VM stages via
`--rootfs-source oci|mmdebstrap` and `--kernel-source prebuilt|host-make|in-vm`. `exec`/`ls`/
`rm`/`destroy` remain fail-loud **CLI stubs** (a typed `Error::Unsupported` "deferred to the daemon", never a
fake success — the `deferred_to_daemon` helper and its `daemon_deferred_subcommands_fail_loud` test are
retained), because those verbs need a cross-process VM registry the single-process `MicroVm` ownership model
can't provide. **That owner now exists** — the `vmcelld` daemon owns them for real over its owning VM registry
(§18) — so removing the stubs (or repointing them at `vmcelld-ctl`) is a straightforward follow-up once the
daemon path is KVM-validated (§16). The single-process lifecycle verbs `run`/`create` additionally take
`--disk <PATH>` (repeatable, read-only), `--disk-rw <PATH>` (repeatable, read-write), and `--append <ARG>`
(repeatable) — thin wrappers over the extra-disk / extra-kernel-arg builder methods at the single
`ephemeral_vm` construction site (§19.4). A custom `init=` is **not** a CLI flag (every CLI verb brings the
agent up, which a custom init precludes — it is a library-only escape hatch, §19.2).

### 11.1 Artifacts produced

1. **`vmlinux`** (per arch, per kernel label): one custom-minimal kernel, direct-boot, drivers built in.
   Rebuilt only when the config fragment or pinned source changes.
2. **Root filesystem** (per profile): a single read-only erofs packed in memory by `am-fs-erofs` from a
   merged tar, from one of two interchangeable sources sharing the inject+pack tail (§8.2). Kernel-independent.
3. **Warm snapshot** (per VMM + profile): boot the erofs base to "agent-ready," snapshot. This suspend image
   is directly usable as a **zygote master** (§9.4): `Zygote::from_snapshot_dir` adopts it and mints
   copy-on-write clones from it, so the artifact that speeds a single restore also seeds a warm pool.
4. **Proxy CA cert**: minted once **per artifacts dir** and cached (a process-global cache keyed by the
   artifacts dir returns the generate-once CA plus its parsed authority — re-self-signing per `authority()`
   call would break the guest trust chain), baked into the rootfs trust store. This is deliberately **not**
   per-run (a recorded deviation from the per-run CA-hygiene rule, M-NET-6): the CA is baked into the cached
   rootfs, so a per-run CA would invalidate the guest trust chain on every run.

All four live under one artifacts directory — `$VMCELL_ARTIFACTS_DIR` or the default
`target/vmcell-artifacts` (anchored on the *workspace root*, not the member CWD, so a workspace member's
tests find it) — from which `kernel_path()`/`rootfs_path()` derive (overridable via `$VMCELL_KERNEL` /
`$VMCELL_ROOTFS`). There are **no `/tmp/vmlinux`-style fallbacks**: a missing upstream artifact is an
`Error::Artifact`, never a silent boot from a world-writable path.

### 11.2 Stage model and caching

The pipeline is a sequence of stages behind a small trait; the load-bearing parts are that `cache_key` is
**pure** (so the cache can decide to skip a stage *before* running it) and that stages pass real data
through `StageInputs`/`StageOutputs` (not via env vars or empty structs):

```rust
pub trait Stage {
    fn name(&self) -> &str;
    fn cache_key(&self, inputs: &StageInputs) -> CacheKey;                 // PURE (§12.9)
    fn out_path(&self, target_dir: &Path) -> PathBuf;                      // default: target_dir/<name>.bin
    async fn run(&self, inputs: &StageInputs, out: &Path) -> Result<StageOutputs>;
}
pub struct Pipeline { /* Vec<Box<dyn Stage>> */ }
impl Pipeline {
    pub async fn build(&self, cache: &Cache) -> Result<Artifacts>;         // skip a stage whose output content matches its key
    pub fn reset_to(&self, stage: &str, cache: &Cache) -> Result<()>;      // remove that stage's + all later outputs; errors on an unknown name
}
```

- **Stage 0 — the pin lock (the only non-deterministic input, isolated here).** The minimal pin set: the
  OCI base-image manifest **digest** (never a tag), the `snapshot.debian.org` **timestamp** (for the in-VM
  `mmdebstrap` source), the kernel source version/SHA (plus the `kernels` registry), the
  **`kernel_prebuilt`** entry (the digest-pinned bootstrap-seed `vmlinux` URL + sha256 that
  `PrebuiltKernelStage` downloads and verifies — the Kata seed, §8.5), and the CH/virtiofsd release tags.
  These live in a committed `pins.json`; `ResolvePinsStage` loads it once and propagates the
  values through `StageOutputs` so downstream stages read pins from memory. *Live* tag→digest and
  timestamp resolution is forward work (§16); the committed lock is the honest current state.
- **Stages 1..n — deterministic given inputs.** Each stage's output is fully determined by its inputs +
  pins: the kernel producer (bootstrap `PrebuiltKernelStage` download+verify, or host-`make` fetch+verify
  source → compile, or `vmcell-kernel-builder`'s in-VM compile, §8.3) → `vmlinux`; then the rootfs source
  (OCI pull+verify → apply layers/whiteouts → merged tar, *or* `vmcell-rootfs-builder`'s in-VM `mmdebstrap`
  path, which boots a builder VM on the compiled/seed `vmlinux` so the kernel stage is ordered first); both
  converge on the shared inject+pack tail (`pack_erofs_with_injection`, §5.4) → boot+snapshot.
- **Caching — five rules, each its own failure mode.** Each stage has a pure `cache_key`; `Pipeline::build`
  skips a stage whose **output content** matches that key:
  1. **Stable hasher** — `blake3` (or `sha2`), never `DefaultHasher` (not portable across Rust versions).
  2. **Deterministic input order** — hash inputs in a fixed order (sorted keys / `BTreeMap`), never
     `HashMap` iteration order.
  3. **Content and identity that travel, not local paths** — hash the *content hashes* of upstream
     artifacts, never absolute `PathBuf`s under `target/`. The rootfs key folds `guest_agent_src_hash` (the
     agent's full source closure, with a distinct missing-source marker), the guest-tools content, and the
     baked deployment-CA cert content, so rebuilding any of them invalidates the rootfs (a stale agent baked
     into the rootfs was a real handshake-timeout bug); on the `oci2erofs --agent-musl` path — where
     `GuestAgentStage` is skipped — it folds the injected agent binary's **content hash** (`hash_file`),
     never its path string, and the `mmdebstrap` rootfs key folds the resolved builder-base image+digest.
     The **snapshot** stage key additionally folds the pinned Cloud Hypervisor build identity (M-ART-7): CH
     guarantees no cross-version snapshot compatibility, so a CH bump invalidates stale snapshots **at build
     time** rather than failing at first restore — `virtiofsd` is deliberately *not* folded, because a
     snapshot-eligible VM runs none (§12.1).
  4. **Embed a per-stage version constant and the pinned source SHA** — a build-logic change with unchanged
     pins, or re-pointing a pin at new bytes, must invalidate the key.
  5. **Validity is content-addressed, not existence-based** — a tampered artifact with an intact
     `.cache_key` sidecar is **rejected**, not silently reused; re-hash on every use (including a cached OCI
     blob, whose digest is re-verified on the cache-hit path — and the layer list is parsed from the
     digest-*verified* raw manifest bytes, never a second unverified fetch, M-ART-3). The kernel-tarball
     cache is **verify-or-purge**; directory-output stages hash via a deterministic sorted walk.

  `reset_to(stage)` removes that stage's and all later stages' outputs and **errors on an unknown name**.
- **Minimize external access + record/replay.** Network-touching stages split into a **record** step
  (populate a cache keyed to the pins) and a **replay** step (build purely from the cache); OCI blobs are
  cached by digest so a later registry deletion doesn't break a rebuild. The OCI pull is behind the
  `pub(crate) OciPuller` trait (`RealOciPuller` + a recording/replaying `FakeOciPuller` serving canned
  manifests/blobs), so the requirement-7 replay + tamper tests run for OCI (tag-pull rejected, cache-hit
  re-verify, cached-blob tamper rejected) with no network.
- **Signing-chain verification.** The in-VM `mmdebstrap` source verifies the Debian `InRelease`/`Release` +
  `Release.gpg` chain *inside the guest* before using any package (refuse-on-mismatch) against the
  **builder base image's own Debian archive keyring** — an equivalent trust root pinned transitively by the
  base-image digest, not a separately-pinned keyring file (M-ART-5); `[check-valid-until=no]` disables only
  the freshness window, never signature verification, and the `snapshot.debian.org` timestamp pin is
  unchanged. The OCI source's `sha256` digest pin is an integrity hard-stop but is *integrity, not
  authenticity* unless a cosign/sigstore signature is also verified. A mismatch is a hard stop, never a
  warning.

**Byte-determinism, scoped honestly.** The `am-fs-erofs` packer *is* byte-deterministic (fixed mtimes,
`BTreeMap`-ordered inode/dirent emission — the same tar packs to the identical bytes/`sha256`). But the
full `rootfs.erofs` is *not* byte-identical across independent deployments, because `RootfsStage` bakes a
**freshly-minted per-deployment proxy CA** into it (a reproducible shared CA key would be a security
defect). So "identical pins yield a byte-identical erofs" holds only within a fixed `artifacts_dir`/CA;
across deployments the CA varies by design while the packer stays deterministic.

---

## Part III — The subtle parts

The component sections above describe *what each piece is and how to drive it*. This part is the
concentrated version of *what will bite you*: a handful of rules that cut across every subsystem, and the
meta-lessons behind them. A new developer who internalizes §12 will avoid the failure modes that cost the
most debugging time.

## 12. Cross-cutting invariants (the rules of the system)

These are the laws every change must respect, no matter which subsystem it touches. Each is stated as a
rule, with the reason and where it is enforced.

### 12.1 Snapshot-eligibility: no vhost-user device

> **A VM is snapshot-eligible only if no vhost-user device is attached to it.**

Every snapshot finding across the project reduces to this one rule. Any external vhost-user backend is, by
construction, a separate stateless process the VMM cannot migrate, so it severs the snapshot. The
consequence: the warm-snapshot tier runs the **privileged/tap network path with a non-vhost-user vsock
transport and no virtio-fs data shares**. Anything requiring a vhost-user device — the unprivileged NAT
(vhost-user-net) **or virtio-fs *data* shares (virtiofsd), not only a virtio-fs *rootfs*** — is mutually
exclusive with snapshot on the same VM. (CH's base control-plane vsock and Firecracker's built-in vsock are
safe because they are the VMM's *own* implementation, not vhost-user.)

The subtle point: **"attached" means *any* virtiofsd, not just the rootfs one.** A read-only data share is
*still* a vhost-user device; there is no "small enough to be safe" exception. The rule is over the **device
class**, not the share's role or access mode. (An earlier pass guarded a virtio-fs *rootfs* + snapshot but
let a data `Share` through to the backend, which then attached virtiofsd to a VM it was about to snapshot.)

It is enforced **in code at three boundaries**, so no single missed check can let a vhost-user device onto
a snapshot-eligible VM:

1. **`config::build()`** rejects `snapshotting == true` combined with a virtio-fs *rootfs*, **any** virtio-fs
   data `Share`, or `NetConfig::Unprivileged` — a typed validation `Err`, with a negative test per case.
2. **`orchestrator::restore()`** re-checks the same predicate against the `cfg` it is handed (defense in
   depth) and returns `Error::Unsupported`.
3. **Backend `restore()`/`snapshot()`** self-guard on `capabilities().snapshot_restore` *and* the absence
   of any vhost-user device via the single shared `pub(crate)` predicate `config_has_vhost_user_device(cfg,
   res)` (covering a virtio-fs data share **or** a virtio-fs *rootfs*, `NetConfig::Unprivileged`, and an
   external vhost-user-net socket), returning `Error::Unsupported { vmm, feature }` — never a panic, never a
   stringly `Error::Vmm`. The former per-backend copies had already diverged (the Firecracker copy never
   grew the virtio-fs-*rootfs* term the CH copy carried); centralizing on one predicate — pinned by a
   shared-predicate unit test — makes that divergence class impossible.

The standing fallback for read-only data in the snapshot tier is to serve it as an **additional erofs/block
image**, whose cost is the extra image's page cache, not guest anonymous RAM.

**Plain (non-vhost-user) block devices compose with snapshot.** An *extra* virtio-blk device
(`VmConfig::extra_disks`, §19.1) is plain virtio-blk, not a vhost-user backend, so it does **not** enter
`config_has_vhost_user_device` (which keys only on virtio-fs *data* shares / a virtio-fs *rootfs*,
`NetConfig::Unprivileged` vhost-user-net, and an external vhost-user-net socket) and does **not** disqualify
snapshot — a unit test pins that adding an extra disk does not flip the predicate (a false positive would
wrongly disqualify snapshot). This is the "plain virtio-blk composes with snapshot" claim of §5.1/§17, now a
second enforcement note rather than a new predicate. A block device's contents live on disk, *outside* the
memory snapshot, so a writable extra disk carries whatever bytes it holds at restore — correct block-device
semantics, not a leak; because the restore config-rewrite rebuilds the full `disks[]` from the paths recorded
at snapshot time, an extra disk's image path must be **stable across a restore** (not inside the deleted per-VM
scratch dir), documented on `VmConfig::extra_disks` (§19.1.3).

### 12.2 Fail loud on a missing capability; never silently no-op

A host-facing operation that *can't* do what was asked must **say so with a typed error** —
`Error::CapabilityUnavailable` for an undelegated limit, `Error::Unsupported` for an unsupported backend op
— not return `Ok` while doing nothing; only the explicitly-listed §15 benchmark knobs may degrade to a
`warn!`. This is why `ResourceUsage` carries `limits_enforced` and per-metric `*_read_ok` booleans instead
of a lying `0`. The full contract and its governing test are §7.2.

### 12.3 Zero netlink in PID 1

The guest agent does **no** `ip link/addr/route`. The guest address is set by the kernel `ip=` boot
parameter (`CONFIG_IP_PNP=y`), consumed by the kernel's IP-PNP late-initcall — in *both* networking modes.
The restore path's in-guest identity writes are the MAC rotation via `SIOCSIFHWADDR` and the IPv4/default-
route rotation via `SIOCSIFADDR`/`SIOCSIFNETMASK`/`SIOCADDRT` (§9.2) — device-layer ioctls in the agent's
`netif` module, not netlink. This keeps PID 1 tiny and dependency-thin, and it is guarded
**structurally**: `vmcell-guest-agent` has no `rtnetlink` dependency, asserted by a CI `cargo tree` gate —
*not* by a "Netlink fake records zero calls" unit test, because there is no netlink seam in the agent to
inject (the manual bring-up an early pass added was deleted, not stubbed).

### 12.4 A restored VM is not a fresh VM

A snapshot resumes at the exact frozen instruction, so anything that must differ between the original and a
restored clone has to be refreshed on **every** restore — fired once on the first post-restore `agent()`
call, after the reconnect. The four things and their traps are in §9.2; the headline traps: identity is
about *live* uniqueness (CID reuse is correct — do **not** `assert_ne!(old, new)`); the **whole network
identity — MAC *and* IP + default route — rotates** to the restore's vmid (H-VMM-1 "rotate everything": a
frozen `ip=` strands every clone on the original's dead /30 with silently dead egress), applied as
device-layer ioctls in-agent so zero-netlink still holds; entropy must be reseeded (correlated RNG across
clones is otherwise silent); and the **clock must be host-driven** (the
guest cannot fix a stale wall clock from inside). And the reconnect itself is mandatory and non-trivial —
on CH the guest's pre-snapshot vsock listener goes *deaf* after the device is re-created, so the agent
serves thread-per-connection and **re-`bind`s** after a bounded idle.

### 12.5 The vsock handshake is fragile in three specific ways

The host↔guest handshake sits on a raw stream, and three traps there each present as "a mysterious
timeout": read the `OK` line **byte-by-byte** (never a `BufReader`, which eats the first framed payload);
treat `reconnect` after restore as a real reconnect (**not** a socket reuse — §12.4); and honor the
**desync flag** (a timed-out or errored request marks the stream desynced until `reconnect()`, so a
half-read frame is never mis-read as the next response). Full treatment at the interface: §4.2.

### 12.6 PID-1 discipline

Running as PID 1 imposes rules a normal process doesn't have (§4.3): **never exit on a recoverable
condition** (a returning PID 1 kernel-panics the guest — so a missing optional share or a cosmetic loopback
ioctl failure is logged and skipped, while core mounts stay fatal); **reap zombies without stealing an
exec'd child's exit status** — a single shared `ReaperCoordinator` captures a `pre_spawn_epoch()` *before*
`Command::spawn` and `reserve(pid, epoch)` after, so it discards only a status recorded at-or-before that
epoch (a genuine previous occupant of a reused pid) while keeping a post-epoch status as the child's own.
This closes two races: the classic false-`127` steal, and the subtler one where an instant child (≈1 ms —
the reseed) exits and is drained by the `WNOHANG` reaper *between* spawn and reserve, whereupon the old
unconditional wipe stranded the waiter forever (the sporadic 10 s "Agent exec timed out" the nextest retries
papered over — AGENT-2, §13); the residual misattribution window needs a full pid-space wrap within
microseconds. And **fork the test command, don't `exec` into it**, so the agent stays PID 1 and keeps the
control channel.

### 12.7 cgroup v2 delegation has sharp edges

Limit enforcement compounds several cgroup-v2 rules (§7.3): create the slice with `mkdir` + direct sysfs
writes (`cgroups-rs`'s builder leaves the cgroup rejecting `cgroup.procs`); place the VM cgroup as a
**sibling** of the harness, not a child (the "no internal processes" rule — the orchestrator strips a
`/supervisor` suffix); write the PID directly to `cgroup.procs`; run from a **non-threaded `domain`** scope
(a threaded scope rejects `cgroup.procs` regardless of `CAP_SYS_ADMIN`); and to make `memory.max` actually
bind a CH guest's shared-memfd RAM, also write `memory.swap.max=0` + `memory.oom.group=1`. Controller
delegation is the gating capability: an undelegated controller makes a *requested* limit fail loud (§12.2)
while *reads* fall back to sysfs.

### 12.8 The unprivileged NAT's five silent-wedge invariants

The in-process smoltcp NAT works only if five invariants hold, and each one wedges (or corrupts) the link
*silently* (no error, just a dead connection or dropped bytes) if violated:

1. smoltcp drops a broadcast frame whose *source* MAC equals the interface MAC, so the host NAT MAC must
   not collide with the guest's vmid-derived MAC — pin it **outside the range `mac_math(1..=254)` can
   emit** (backed by a unit test asserting no collision).
2. iterate the virtio RX descriptor chain **only when the NAT actually has packets queued** — iterating
   `vring.iter()` consumes/advances `avail_idx`, so polling it while empty discards the guest's RX buffers.
3. call `enable_notification()` on the TX queue inside the `handle_event` loop so the guest kicks the
   eventfd for the next packet.
4. size the socket pool for concurrent *and* keep-alive connections (≈16 sockets per forwarded port), not
   one-per-port — a single `TcpSocket` per port means an HTTP keep-alive connection holds the only slot.
5. bound every host-stream read to the smoltcp socket's free TX capacity
   (`host_read_budget(send_capacity, send_queue, buf.len())`) so `send_slice` enqueues the *whole* read —
   `send_slice` enqueues only down to zero free buffer and `can_send()` is true with one free byte, so an
   unbounded 8 KiB read's unsent tail was silently **dropped**, corrupting any host→guest TCP stream large
   enough to fill the guest receive window (C-NET-1 corrupts data rather than wedging the link; pinned by a
   window-filling test that reddens on the old unbounded read).

### 12.9 Cache keys are content-addressed and deterministic

The five cache-key rules (§11.2) are a cross-cutting law because a violation is invisible until it either
forces a spurious expensive rebuild (a `HashMap`-order or absolute-path key that differs across processes)
or silently reuses a stale/tampered artifact (existence-based validity). Hash a stable hasher, sorted
inputs, upstream *content* not paths, a stage-version + pinned SHA, and re-hash the output on every use so
a tampered artifact with an intact sidecar is rejected.

### 12.10 Ordered teardown owns cleanup — on panic

Every host resource is released by `Drop`, in reverse dependency order — **VMM process group → virtiofsd →
netns/cgroup/overlay/tmp-dir** — force-killing the process *group* (`kill -9 -<pgid>` then reap), not the
leader only (which orphans `ip netns exec` wrappers). Removing a netns while the VMM still holds interfaces
in it hangs or leaks, so the process is reaped first. This path must run **when a test panics** — a correct
`shutdown()` does not count; the panic path is `Drop`. Both CID and VMID are released in `Drop`, and all
per-VM temporaries live under one `VmTempDir` guard dropped last (§10.2). A periodic sweeper reaps anything
orphaned by a hard crash (§6.4). The same order also holds on a mid-`start()`/`restore()` failure *before*
resources move into `MicroVm`: the internal `EnvSetup` struct declares the proxy and the smoltcp NAT
**before** the netns field, and Rust drops fields in declaration order, so the implicit error-path drop
mirrors `teardown_post_instance` exactly (H-ORCH-1) — that field order is load-bearing and must not be
reshuffled (the pre-fix order deleted the netns before the proxy running inside it).

### 12.11 Keep the primitive general

No domain-specific assumption may leak into `vmm`/`agent`/`orchestrator`/`metrics`. All three consumer
domains are co-equal; the `MicroVm` handle is a thin owner over the primitive. A capability the *core* can
offer workload-agnostically goes in the library; a capability that encodes what a *test*, an *agent*, or a
*function* should *do* with a VM ships as a thin consumer crate on top (§17). Reviewing each addition
against this line is the standing guard.

### 12.12 A zygote master is immutable; clones restore from private copy-on-write copies

> **A zygote's suspend image is never mutated by cloning. Every clone restores from its own copy-on-write
> copy of the suspend dir, made *before* the backend touches it.**

The single-use restore path rewrites the snapshot's `config.json` (CH) — vsock/serial/tap host paths — *in
place* (§3.2). That is fine for one restore of one snapshot, but it means a plain `restore()` **mutates the
caller's dir**, and two restores from one dir race on that file and corrupt it. The zygote fan-out (§9.4)
therefore reflink-copies the whole suspend dir into each clone's own scratch dir first and restores from
that private copy. Two consequences are load-bearing:

- **The master stays byte-for-byte identical**, so it can be cloned again, indefinitely — the property that
  makes it a *zygote* and not a one-shot snapshot. The integration test asserts the master's `config.json`
  is unchanged after a fan-out (§14); the reflink unit test asserts a clone is an independent copy (writing
  the clone never touches the master).
- **The copy is the clone's scratch, so ordered teardown reclaims it.** The CoW copy lives *inside* the
  per-VM `tmp_dir`, so the existing teardown order (§12.10) removes it with everything else — no separate
  cleanup path to forget, no shared inode two clones could race on.

Enforced by construction: `restore_cow`/`Zygote` do the copy in the orchestrator **before** calling the
backend, so no backend change is needed and no code path can restore a clone directly from the master.
(A single sequential clone on a verbatim-rebind backend is still safe; the *concurrent* case is gated by
`restore_rotates_host_paths`, §3.3 / §9.4.)

The next eight invariants are introduced by the control-plane daemon (§18) and the extra-device surfaces
(§19). They are laws in the same register — one predicate, one owner, a gate that can go red.

### 12.13 Every client-named artifact goes through `resolve_artifact_path`

> **The single predicate that turns a client-supplied artifact name into a filesystem path. No handler or
> VM-API path constructs `dir.join(client_string)` itself.**

Artifact names map **directly** to files (`k1` → `<artifacts-dir>/k1`), so the name validator is a security
boundary of the same class as the runner's exec-target confinement (§14): a name that path-traverses
(`../../etc/passwd`) or is absolute would read or clobber files outside the store. `resolve_artifact_path`
(§18.3.1) accepts a name only if it is a single safe path component — non-empty, ≤255 bytes, bytes in
`[A-Za-z0-9._-]`, not `.`/`..`, not leading `-`/`.` — and always returns `dir.join(name)`. Owner:
`vmcell-daemon::artifact`. Gate: the red-on-inverse traversal tests + a positive control + a grep review-reject
on `dir.join(` over a client string (mirroring `mac_math`/`MAX_FRAME_BYTES`).

### 12.14 The daemon retains caps; it never drops-and-execs, and never runs degraded

The daemon is a *long-lived* server that must itself perform privileged VM operations (netns/tap/nft) for the
whole process lifetime, so — unlike the transient test-runner, which raises ambient caps and execs — it runs
the blessing **precondition** (the three caps present in the **effective** set, or `euid == 0`) and then
**keeps** them: no uid drop, no ambient raise, no bounding-set shrink, no `exec` (§18.2). If the precondition
fails it prints the `setcap …+ep` remediation and **refuses to start** — never a daemon that came up without
`CAP_NET_ADMIN` and fails every privileged create at first use (fail-loud-at-construction). Owner: `vmcelld`
main + `vmcell-privilege::ensure_blessed_or_explain`. Gate: the moved `compute_missing`
effective-vs-permitted test.

### 12.15 Authenticated by default; two named opt-outs

Every route is behind the bearer-auth layer **except** `/healthz` and `/openapi.json`, so a new route is
authenticated unless it explicitly opts out — the safe default (§12.2 "defaults get the strictest scrutiny").
Owner: `vmcell-daemon::auth` + the router. Gate: the OpenAPI parity test asserts the opt-out set is exactly
those two and that every VM/artifact operation carries its security requirement (§18.6).

### 12.16 The served OpenAPI document and the mounted routes are the same table

The OpenAPI 3.1 document is **built by one function** from the same route table the router mounts, and a parity
unit test (KVM-free, always runs) asserts every mounted `(method, path)` appears in the document and vice
versa, and every component schema an operation names exists (§18.5.2). The served document cannot silently
drift from the routes. Owner: `vmcell-daemon::openapi`. Gate: the route-parity test (red on adding a route
without a document entry, or vice versa).

### 12.17 The registry owns its VMs; teardown is ordered and shared; a start-up sweep reclaims crash leaks

While the daemon holds a VM's handle the VMM process and its netns/tap/cgroup/scratch stay alive; `destroy` and
a clean `shutdown_all` run the **same** graceful `MicroVm::shutdown`, and dropping the registry runs each
`MicroVm::Drop` — the panic path — with the identical ordered cleanup (§12.10). A **hard** kill skips all three
and leaks residue, which the start-up `sweep_orphans` (run with an **empty** live-vmid set before any VM
exists, so it can never sweep a live resource) reclaims on the next boot (§18.4). Owner:
`vmcell-daemon::registry` + `vmcell-daemon::sweep`. Gate: the fake-launcher registry test (the recording fake
counts shutdowns; RED if teardown is skipped) + `sweep_orphans`'s own unit test.

### 12.18 No secrets in process-visible surfaces

The daemon's API key is loaded from a **perms-checked file** (`--api-key-file`, refused if group/other-readable),
never a CLI arg / env var / serial line — the §8.3/§12.10 "no secrets in kernel cmdline or agent output" rule
extended to the daemon's own credentials, so the key never lands in `ps` or a captured log. Owner:
`vmcell-daemon::auth`. Gate: a start-up test that a group/other-readable key file is refused (§18.6).

### 12.19 One prefix composes every per-VM resource name and every sweep filter

> **`vmcell::naming` is the single place that builds a per-VM netns/tap/cgroup/scratch name from
> `resource_prefix`, and the single place that builds the sweep filters. Every produced name starts with its
> sweep filter, for any prefix.**

Seven hard-coded `vmcell-*` literals that had to stay in lockstep (or the sweep would silently miss a leak)
collapse into one option (§10.2). Owner: `vmcell::naming`; consumers are the launcher and the
`HostOrphanScanner`/`sweep_orphans`. Gate: a unit test that each produced name starts-with its sweep filter for
an arbitrary prefix (so a new name shape cannot escape the sweep), plus the daemon-isolation host test
(`--resource-prefix acme` sweeps only `acme-*`, leaves a `vmcell-*` orphan, §18.4).

### 12.20 Extra kernel args are append-only

> **A caller's `extra_kernel_args` may add a boot parameter but can never clobber a token vmcell owns.
> `is_reserved_cmdline_arg` is the one predicate that decides, and it is pinned against the builder's own
> output.**

The predicate rejects any arg whose key is in `RESERVED_CMDLINE_KEYS` or starts with `vmcell_` (the guest agent
trusts those), and any arg that is not a single whitespace/control-free token (§8.3). Owner: `config::build()` +
`is_reserved_cmdline_arg`. Gate: a one-law test builds a cmdline exercising every emitted token (block rootfs +
networking + a share + nested) and asserts `is_reserved_cmdline_arg` is `true` for each — so adding a new
builder token without reserving its key goes red (§19.2), the same discipline as `config_has_vhost_user_device`
and `mac_math`.

## 13. Hard-won lessons

Four meta-lessons recur across the implementation history (Appendix A) and are worth stating directly:

- **A path with no test that can actually fail is a path that has never run.** The privileged-tap and
  warm-restore paths were "implemented" for several passes but every attempt died early (a netns
  permission error, a vsock reconnect hang), masking a chain of latent bugs downstream — one "30-minute
  hung test" was actually a *leaked VM*. Fixing the first blocker exposed the next. Every test must be able
  to go red on the inverse of the behavior it guards (§14).
- **Only interleaved same-session benchmark deltas are trustworthy.** An early cross-session comparison
  suggested the 6.12 kernel restored ~2× slower than 6.6; an interleaved same-session sweep showed the gap
  was host-load noise (within ~2%). Never compare absolute latencies across sessions on a shared box.
- **Measuring disproves wrong beliefs as often as it confirms right ones.** The benchmark pass *inverted*
  three research-era hypotheses (the OCI slim base is smaller than mmdebstrap-minbase; static-`musl` is
  larger than glibc-dynamic; the kernel version is not a hot-path lever). The value of the instrument was
  the disproving.
- **An "environmental" flake explanation is a hypothesis, not a diagnosis.** A sporadic "Agent … timed out"
  in the CH suite was written off as a hybrid-vsock reset and papered over with nextest retries for weeks —
  until a captured guest kernel stack proved the real mechanism (a PID-1 reaper-epoch race that drained an
  instant child's status before the waiter reserved it, AGENT-2, §12.6). Keep retries as defense-in-depth,
  but do not accept "environmental" without a mechanism; the retry that hides a flake also hides its cause.

---

## Part IV — Testing and performance

## 14. Testing strategy and quality gates

The principle: the test/lint/CI layer should **force** robustness rather than rely on review to catch it.
Each defect class a review found becomes an automated gate, ordered cheapest-and-broadest first, so the
next implementation cannot merge it. **A green CI is necessary but not sufficient** — the as-built suite
once passed green for four separate broken implementations; what kept the bugs in was the absence of tests
that *could* fail. So the governing question for every test is: *would it go red on the inverse of the
behavior it guards?*

**Compiler- and lint-enforced gates (zero per-test cost).** The crate root denies, under `not(test)`,
`clippy::unwrap_used`/`panic`/`unreachable`/`todo`/`unimplemented`/`indexing_slicing`/`print_stdout`/
`print_stderr`/`dbg_macro`, plus `missing_docs`, `undocumented_unsafe_blocks`, and the `# Errors`/`# Panics`/
`# Safety` doc requirements. The `not(test)` gating is the trick: tests may `unwrap` freely; production
paths may not. I/O-free modules carry `#![forbid(unsafe_code)]`, so `unsafe` survives only where it is
genuinely needed (VMM glue, `setns`, the virtqueue ring handling, the agent's syscalls, `net_sys`). CI runs
`RUSTFLAGS="-D warnings" cargo clippy --all-targets` and `cargo fmt --check`.

**Build-matrix and dependency gates.** The feature powerset is a **blocking** gate (all combos compile),
which — with the `host-common` umbrella (§10.5) — has no partial-host holes left. Each lean member crate is
built and its `cargo tree -e no-dev` asserted free of `tokio`/`hyper`/`rtnetlink` (agent + test-runner;
guest-tools is exempt, §10.5). `cargo-deny` (licenses/advisories/bans/sources) and `cargo semver-checks`
(the public-API gate) run on every build/PR.

**Unit tests — pure functions and injected seams** (no KVM/root; property tests marked *[prop]*): the
`config::build()` rejections (a negative test each, including all three vhost-user snapshot cases and
`Privileged { host_services_port: Some(_) }`, §6.1);
per-VM path injectivity *[prop]* (distinct vmids never share a socket path — real paths varying `pid`, not
`format!` stand-ins); `/30` math for `vmid ∈ {0,1,254,255}` *[prop]*; the CID/VMID allocators (skip
reserved, wrap without emitting a live/reserved id, thread-storm contention); the protocol codec round-trip
*[prop]*; the vsock handshake FSM (`refused → OK` retry, **EOF → return to accept**, serial-panic
fast-fail); the CH REST parser (chunked, `>4096`-byte, `2xx` *[prop on status]*); the nft render (golden
text, destination preserved); cgroup-path construction (sibling placement, `/supervisor` stripped); the
`CgroupFs` fake (exact limit-file contents; a *requested* limit on an undelegated controller returns
`CapabilityUnavailable`, not `Ok`); the `cpufreq` fake (restores exactly what it changed, on panic); the
`Netlink`/`NftApplier`/smoltcp fakes (assert the rendered ruleset / call order; host-NAT-MAC never collides
with `mac_math(1..=254)`); `cache_key` (golden digest, identical across processes, sorted inputs, upstream
content, folds `guest_agent_src_hash` + a stage version — exercised against a **real** stage, not a
`DummyStage`); the runner's pure privilege-transition logic (§ below); `Drop` order against `FakeVmm`
(**still runs on `panic!`**); and the knob/perf helpers added by the 2026-07 wave — `KernelVerbosity::loglevel`
(3/6/7/8), the `Timeouts` preset ordering + every-field-≥-floor clamps, the shared cmdline builder (all three
backends emit `loglevel=`, `cryptomgr.notests raid=noautodetect`, and the `vmcell_*_ms` tokens — red on the
QEMU-`loglevel` divergence returning), the guest `parse_ms` clamp (absent/garbage/overflow → default), the
`netif` ifreq byte layout, the EXP-C accept-loop policy helpers (`next_deadline`/`remaining_idle`/
`poll_timeout_ms`), the EXP-D grace helpers, `ConsoleMode` gating (FC + `VirtioConsole` → `Unsupported`), and
`reserve_after_fast_child_already_drained_delivers_status` (AGENT-2).

**Integration tests — real environment, default-skipped, per-VMM.** Tests needing KVM or capabilities are
`#[ignore]` (CI runs them with `--ignored`) via the nextest `serial-host` group for anything touching
global host state. A laptop `cargo test` runs only the unit tests and stays green. The suite is split into
the **two operating-mode suites** (§6.4), each a first-class, separately-invoked suite whose prerequisites
are a **visible hard precondition** — a missing capability or undelegated controller is a *skip-with-reason*,
**never** a silent green, and a filter that selects **zero tests is a CI failure**, not a pass. Every
scenario is parameterized over the backend; before running a case the harness consults `capabilities()` and
emits an explicit skip-with-reason for any backend that can't support it (the `require_cap!` +
`vmm_matrix_test!` harness). Applicability: boot / exec / lifecycle / metrics / `put_file` / concurrency
and the privileged egress/host-endpoint paths run on all three; `snapshot_restore` runs on **CH and
Firecracker** (branching on `capabilities().restore_rotates_host_paths` for the per-backend host-path
assertions; QEMU skips with reason — snapshot-ineligible in unprivileged+vsock); virtio-fs shares and nested virt run
on **CH/QEMU only**; the unprivileged smoltcp suite runs on **CH/QEMU only** (Firecracker has no
vhost-user-net for the NAT to attach to).

**Skip honesty is enforced, not trusted (H-TEST-3).** `require_cap!` *panics loud* if the **primary** backend
(cloud-hypervisor) lacks a capability — "skip == pass" is impossible there; for FC/QEMU it records `SKIP
<vmm> <capability>` to a durable, run-scoped manifest (`record_capability_skip`, path `VMCELL_SKIP_MANIFEST`
defaulting to `$TMPDIR/vmcell-skips-<pid>.txt`) because a passing test's `println!` is captured and
discarded by nextest. And the actual red-on-inverse guard against a flag *silently regressing* is a per-flag
capability-honesty pin in each test file, now covering all **seven** `VmmCapabilities` flags across backends
(`unprivileged_vhost_user_net`, `nested_virt` + `virtio_console`, `virtio_fs_shares`, and the FC pins
including `restore_rotates_host_paths` and `capabilities_are_honest_about_snapshot_restore`). The "zero
selected tests is a CI failure" rule is backed by the pinned `nextest-version = 0.9.85` (where
`--no-tests=fail` became default), and the `serial-host` group *positively* selects every vmcell integration
binary (`package(vmcell) & kind(test) & !binary(proptests)`) so a new VM test auto-joins.

**The integration profile carries nextest retries** — `{ backoff = exponential, count = 3, delay = 5s,
max-delay = 20s }` — so a fresh-VM retry absorbs a transient environmental CH hybrid-vsock reset while a
genuine break still fails all attempts. The framing is honest: the dominant historical cause of the
"Agent … timed out" flake these retries once masked was the AGENT-2 reaper-epoch race, now root-caused and
fixed (§12.6); retries stay only as the residual-environment backstop. Both VM suites are scoped with
`-E 'kind(test) & …'` so the ~172 lib unit tests run only in `just test-unit`, not serialized alongside the
VM tests.

The required assertions are written to **fail on their own inverse** — the earlier versions of several were
theatrical (they passed on their inverse), which the review caught:

- `snapshot_restore.rs`: the host **reconnects the severed vsock** (not merely "restore succeeds"); the
  restored VM has a **valid, live CID** (not `assert_ne!`); a **rotated MAC *and* rotated IP/default route
  observed in-guest** — the test reads `/proc/net/route` in the guest and asserts the default route goes via
  the rotated vmid's gateway (`ip_math(new_vmid)` host IP, little-endian hex compare), reddening on the
  pre-fix H-VMM-1 defect; **clock resync** driven by an injected `FakeClock` consulted on the *first*
  post-restore call; **RNG reseed** captured pre/post *without the test issuing its own reseed*; and a
  **per-backend `restore_rotates_host_paths` branch** — host vsock/serial path rotation + rotated-vmid
  embedding on CH, path *equality* on FC — so the test consults the capability descriptor instead of encoding
  CH semantics for every backend.
- `zygote.rs` (§9.4): suspend one VM into a zygote, then on a host-path-rotating backend mint a **concurrent
  pool of N clones** and assert each has a **distinct vmid, distinct in-guest MAC (`== mac_math(vmid)`), and
  distinct host vsock path**, all alive at once with a working `exec`; assert the **master `config.json` is
  byte-identical after the fan-out** (the immutability guard, §12.12 — reddens on the single-use in-place
  rewrite reaching the master). On a verbatim-rebind backend the same test asserts a **concurrent fan-out is
  `Error::Unsupported`** while a **single clone works** — the capability-gated branch, mirroring
  `snapshot_restore.rs`. The reflink primitive and the fan-out orchestration are *also* unit-tested with no
  KVM: `reflink::tests` proves a clone is an independent copy (writing it never mutates the master) and the
  full-copy fallback path; `zygote::tests` drives a **`FakeVmm`-recorded** fan-out that asserts every clone
  restored from its **own** private CoW dir (never the master) with a distinct vmid, and that the
  concurrent-gate returns `Unsupported` on a fake whose `restore_rotates_host_paths` is `false`.
- `egress_proxy.rs`: **HTTPS** interception logged; a registered **double** answers; a **filter rule blocks
  a domain and the guest sees it, and the block is recorded**; the proxy observes the guest's **intended
  destination**; a real `CONNECT` falls through; the double **ignores `Method::CONNECT`**; the domain match
  is **label-boundary** (a sibling domain is not over-blocked).
- `metrics_limits.rs`: `memory.max` **OOM-kills** a runaway allocator — set `mem_mib(512)` + `mem_max_mib(256)`
  and assert a cgroup **`memory.events oom_kill > 0`**, not just a guest exit 137 (which the guest's own OOM
  produces regardless of the cap). This is *why* `create_slice` writes `memory.swap.max=0` + `oom.group=1`
  (§12.7). Controller delegation is a hard precondition (visible skip if absent).
- `lifecycle.rs`: **ordered `Drop` on `panic`** leaves zero residue — asserted against the *computed* per-VM
  cgroup path (not a top-level path the code never uses) plus netns/overlay/temp-dir/CID/VMID, and the
  **full teardown order** via recording fakes.
- `put_file` **round-trip** (write via `put_file`, then `cat` the file back *in the guest*, not a UDS-mock
  assertion); the **zero-netlink** invariant asserted structurally (§12.3, no `rtnetlink` in the agent
  crate); a **`FakeVmm`-driven** orchestrator test that *exercises* allocation order, retry/timeout, and
  restore-vs-cold-boot selection with no KVM.

**Build-pipeline tests** exercise the **real** `RootfsStage`/`SnapshotStage`/`KernelStage` (a `DummyStage`
can't catch the §11.2 cache bugs): a **tamper aborts** by corrupting the *artifact bytes* (intact
`.cache_key`) and asserting rejection (*not* corrupting the sidecar and asserting a rebuild — that verifies
nothing); a warm-cache second build does **zero** network fetches; a cached OCI blob is re-verified on the
hit path; `reset_to(rootfs)` rebuilds rootfs+snapshot but not the kernel and `reset_to(unknown)` errors;
and changing the **guest-agent source re-bakes `rootfs.erofs`** (the stale-agent class that cost real
debugging time).

**Daemon and device-surface gates (§18, §19).** The control-plane daemon is built so its logic is
unit-testable **without KVM or root**, and every recurring defect class has a gate that can go red. KVM-free:
`resolve_artifact_path` red-on-inverse (`..`, `/`, absolute, leading `-`/`.`, empty, over-255-bytes, NUL) with
a positive control (§12.13); the artifact store against a `tempdir` (create-then-create is `AlreadyExists` —
the "no update" guard; a delete residue check existed-before/gone-after; the atomic-rename path leaves no
`.tmp`; an oversize upload is `PayloadTooLarge`); bearer auth (correct/wrong/absent → 200/403/401 with
`WWW-Authenticate`; constant-time-compare shape; a world-readable key file refused at start-up, §12.18);
OpenAPI route⇔document parity + every op carries its security requirement + the opt-out set is exactly
`/healthz` + `/openapi.json` (§12.16); the owning `Registry` over a recording `FakeLauncher`/`FakeHandle` + a
real store (create registers `Ready`; `destroy`/`shutdown_all` run graceful teardown and clear the entry — the
fake counts shutdowns, RED if teardown is skipped; an ephemeral `run` leaves no VM; `is_artifact_in_use`
pins/releases; a missing artifact is `BadRequest`); the HTTP wiring via `tower::oneshot`; the
`DaemonError`→status map (a wrapped `vmcell::Error` renders `Display`, never the `Debug` struct-dump — the
L-BIN-4 guard); and the moved `vmcell-privilege` tests (`+ep` remediation, `compute_missing`, the plan +
confinement tests) still guarding both callers. A **`vmcelld` integration suite**
(`crates/vmcelld/tests/integration.rs`, `just test-daemon`) inverts the runner — the *test binary* holds the
caps (nextest target-runner) and spawns `vmcelld` **directly** under a systemd-delegated scope — so it can
plant privileged pre-existing state and inspect host residue, asserting on the **data plane** (the guest's
captured stdout, `limits_enforced` under delegation, the reclaimed orphan netns, the removed scratch dir, a
snapshot→restore-by-name marker, privileged tap networking, the `--resource-prefix acme` isolation, and the
`vmcelld-ctl` CLI, §18.4/§18.9) and never a silent skip. For the device surfaces (§19): the CH `ChVmConfig`
serialization test pins extra disks into `disks[]` in order with the right `readonly` **after** the root disk,
and the CH `rate_limiter_config` bucket (`size = rate`, `refill_time = 1000`); the snapshot-eligibility test
pins that an extra disk stays eligible (§12.1); the §12.20 cmdline one-law test; and `build()` negative tests
(empty/relative/duplicate extra-disk image; a reserved-key / `vmcell_`-prefixed / whitespace extra arg; a
non-absolute / whitespace init path; `snapshotting` + custom init; an all-`None` / any-`0` io_limit). KVM host
tests read an extra-disk marker back **in-guest** off `/dev/vdb`, survive it across a snapshot→restore into a
fresh vmid, throttle a disk to a measured floor, and boot a custom `init=` asserting the serial data plane plus
`agent()` fail-loud (§19.3).

**The privileged capability runner is itself unit-tested off the privileged path.** Its pure helpers are
covered against each buggy inverse: the `+ep` (not `+p`) remediation message; the path-confinement
(described in §14 below); `merge_preserved_groups` (kvm-gid preserved iff held, never invented); and — the
deepest fix — a **pure `plan_privilege_transition(CapState, need, euid)`** so the capability-state sequence
(uid → inheritable-add → bounding-drop → ambient-raise → trim) and the security-critical **setuid-form
uid-before-ambient ordering** are verified *before* a bless, not only by running the suite. Only the thin
`setresuid`/`setgroups`/`set_current`/`ambient::raise`/`exec` syscalls stay integration-only.

**The capability runner (`vmcell-test-runner`).** `sudo -E cargo test` runs the *entire* toolchain as root
— `target/` fills with root-owned artifacts and cargo's env shifts — when the privileged tests need only
three capabilities. The runner is registered as the nextest **target runner** for the privileged suite, so
nextest invokes `vmcell-test-runner <test-bin> <args…>` instead of the test binary directly; cargo/rustc
stay unprivileged. The runner holds exactly `CAP_NET_ADMIN`+`CAP_SYS_ADMIN`+`CAP_DAC_OVERRIDE`, injects
them into the test process via the **ambient** set, and execs the test **as the invoking developer's
uid/gid**. It is dependency-thin (`rustix` + `capctl` + `libc` — `libc` for the setuid fallback's
`getgrnam`/`setgroups`/`setresuid`) and initializes no tracing at full privilege.

Several security details are load-bearing and non-obvious:

- **Blessing uses `+ep`, not `+p`.** `sudo setcap cap_net_admin,cap_sys_admin,cap_dac_override+ep …` — the
  runner checks its **effective** set, so a `+p`-only blessing leaves the caps un-raised and the check
  still fails. The printed remediation says `+ep`.
- **Path-confinement is anchored on the *runner's own* location, and the exec argument is untrusted.** The
  runner derives its trusted confinement root from its own canonicalized `current_exe()` — it finds the
  `.vmcell-bin` ancestor and takes `<workspace>/target` as the trusted root (with a `target/`-ancestor dev
  fallback) — then rejects `..` on the raw target argument, canonicalizes it, and confirms it descends from
  that trusted root. Anchoring on the *argument's* own `target/` ancestor (an earlier plan) was inert: a
  caller-supplied `/home/attacker/target/debug/evil` always contains its own `target/`, so the check always
  passed. The argument is attacker-influenced; only the runner's own location is trusted.
- **The blessing is stripped whenever the file is rewritten** — a *security feature* (a rebuilt or tampered
  runner silently loses its powers). To make that not a per-iteration pain, `just bless` builds the runner
  once, **installs a copy to a stable path outside `target/`** (the gitignored `./.vmcell-bin/<profile>/
  vmcell-test-runner`), and `setcap`s *that copy*; cargo's churn in `target/` (a `RUSTFLAGS=-D warnings`
  re-fingerprint, a feature toggle, a profile change) then never touches the blessed binary. `just bless` is
  **idempotent** via a content-hash `.blessed` stamp keyed on the **runner** — never on test binaries,
  whose identity is deliberately out of scope (hashing them would re-introduce per-iteration churn and buy
  no security the confinement + exec-permission boundary doesn't already give).
- **The privilege boundary is *who may execute the runner*.** `CAP_SYS_ADMIN` is root-equivalent in blast
  radius, so `just bless` `chmod 0700`s the blessed binary (owner-only) as the enforced boundary; `0750`
  with a dedicated developer group is the documented shared-host alternative. This is a
  **developer-workstation** convenience, explicitly not for multi-tenant or production hosts (where the
  right answer is a privileged **setup broker**, §17). Two honest limitations: `CAP_SETPCAP` is *not* in the
  standing set, so `PR_CAPBSET_DROP` is a no-op on the file-cap path (the bounding set can't be shrunk
  there — only the setuid-root fallback can — and the runner warns); and the setuid-root fallback must
  change uid *before* raising ambient (verified by the pure transition test above).

## 15. Performance: measured results

Two framing rules carry this section. First, **benchmarks are tracked metrics, not pass/fail gates** —
absolute boot/restore/density numbers are hardware-bound, so a fixed threshold would be a lie on a
different box; only the *relative* invariants graduate to guards. Second, **a number is meaningless without
its substrate**. The canonical results and full method live in `docs/benchmark-results.md`; the highlights
below carry their substrate.

**Substrate:** Intel Core Ultra 7 258V (Lunar Lake, 8c/8t), 30 GiB RAM, ext4-on-NVMe (`/tmp` is tmpfs);
CH v52.0.0 / FC v1.16.0 / QEMU 10.2.1 / virtiofsd 1.13.3; guest kernel 6.12.94; THP `madvise`, KSM on;
**freq-pinned to the sustained 2.2 GHz base** (turbo off — the representative dense-operation clock). Two
honest caveats: **"cold" is warm-cache** (`drop_caches` is `euid==0`-special-cased and tmpfs pages are
immune, so true cold isn't reachable here), and the box is shared — so quote **central tendency, not
tails/SLAs**.

**Micro (criterion, in-process):** protocol encode ≈54.8 ns / decode ≈86.2 ns; `cache_key` ≈260 ns; `/30`
host-IP parse ≈23.2 ns; in-memory empty-tar→erofs ≈1.26 µs. The control-plane codec and per-VM address/cache
math are tens-to-hundreds of nanoseconds — far below anything gating a multi-second VM lifecycle.

The numbers below are the canonical **2026-07-02 post-investigation matrix** (N=20, warm-cache, 256 MiB,
default profile unless noted) after the `docs/45` EXP-A…E pass. One measurement caveat carries all of them:
percentiles are now nearest-rank, index `ceil(q·n)−1` clamped to `[0,n−1]` (C-BIN-1); the former
`floor(n·q)` returned the sample **maximum** as p95 whenever `n·q` was integral, so at N=20 every p95
published before 2026-07-03 equalled the run's max — a pessimistic overstatement. The p50 figures and every
relative/A-B conclusion are unaffected in direction; prefer p50 when reading a pre-fix table.

**Macro — cold boot to agent-`Ready`** (p50/p95 ms): CH **316/331** (≈290 under the `low_latency` profile);
Firecracker **764/792**; QEMU **965/995** (now 20/20 iterations — the AGENT-2 reaper-race fix, §12.6, which
also removed QEMU's dropped iterations). These are well below the pre-optimization figures the pass
paragraphs below trace out (QEMU especially, once it gained `loglevel` via the shared cmdline builder).

**Macro — warm restore to agent response** (p50/p95 ms): **Firecracker 24/33 — the fastest restore tier**
(23/28 under `low_latency`), beating CH despite losing cold boot: exactly the density/snapshot role it is
assigned, now realized rather than pending; CH **58/67** (54/66 `low_latency`; native in-agent resync, §9.2);
QEMU N/A (snapshot-ineligible in unprivileged+vsock).

**Macro — throughput-profile end-to-end** (p50 ms, full lifecycle incl. teardown): CH cold **361**, CH
restore **120**; FC restore **64** (create ≈13 + connect ≈13 + exec ≈10 + teardown ≈31 — the per-phase
p50s are measured independently and do not sum exactly to the end-to-end p50), FC cold **848**; QEMU cold
**≈1080**. A *standalone* graceful-teardown benchmark under this profile (docs/45 EXP-D) reads CH **56** /
FC **78** / QEMU **92** ms — higher than the FC restore path's ≈31 ms teardown because the restored FC
process exits within the grace, so `has_exited` fires early rather than running out the RPC round-trip.

**Latency optimization pass (2026-07-01).** A targeted pass recovered the latency the correct-but-
slower code had accreted vs earlier buggy-fast versions — **CH cold 642→330 ms, CH restore 166→84 ms** —
with **no invariant relaxed** (`just ci` green, unit green, privileged suite green). The levers, largest
first: the guest kernel cmdline dropped the verbose `KERN_INFO` serial flood (`loglevel=6`, keeping a
debuggable/panic-capturable log); the guest vsock accept poll `ACCEPT_POLL` 100→20 ms (then the dominant
restore-reconnect cost — the host blocks for `Ready` between its CONNECT/OK handshake and the guest's
next `accept()`; the later EXP-C event-driven `poll(2)` accept, below, removed this cost entirely, and
`guest_accept_poll` now paces only the bind-failure retry); the graceful `shutdown()` teardown now polls
`VmInstance::has_exited` up to a 250 ms (was 500) grace instead of always sleeping it; and tighter host
connect/api-socket poll cadences.

**Follow-up — tunable knobs + native resync (`docs/44-claude-perf-config-design.md`).** `KernelVerbosity` +
a unified `Timeouts` struct (`low_latency`/`throughput` presets) make the above per-VM tunable; a **shared
cmdline builder** fixed a divergence where QEMU omitted `loglevel=` (QEMU cold **≈1400→996 ms**); and the
post-restore resync is now a **single native in-agent `Resync` round-trip** (clock/RNG/MAC+IP via
syscalls+ioctl, no subprocess). The measured VM-exit cost of serial logging is **+231 ms** cold (`verbose`
561 vs `balanced` 330 on this `docs/44` pass; the later console A/B grid below measures the same effect at
≈242 ms — 558 vs 316 — on the post-investigation substrate), answering "does logging cause VM exits": yes —
`ttyS0` is a PIO UART, one exit per byte (a direct exit count via `perf kvm stat` is blocked by
`perf_event_paranoid=4` on the bench host, so the verbose-vs-balanced A/B is the evidence).

**Investigation pass (`docs/45-claude-perf-investigation.md`, EXP-A…E).** The 2026-07-02 pass took the
matrix to its canonical state above. **EXP-A** unified the readiness poll onto `timeouts.api_socket_poll`.
**EXP-B** trimmed the guest cmdline: `cryptomgr.notests` (skip the crypto self-tests, ≈9.7 ms) +
`raid=noautodetect` (skip the md autodetect scan, ≈2 ms) — the only cmdline-trimmable boot work a
printk-timestamp probe found (the fashionable microVM trims `i8042.nokbd/noaux`, `pci=lastbus=0`,
`tsc=reliable` were all measured to be no-ops in this guest, so they were rejected — do not re-derive them).
**EXP-C** made the guest accept loop event-driven `poll(2)` (§4.3), collapsing the restore `connect` phase
16.6→4.6 ms p50. **EXP-D** moved the graceful-teardown grace deadline before the shutdown RPC and made the
`has_exited` poll step adaptive, cutting throughput teardown 95→56 ms. **EXP-E** unlocked FC warm restore
(§3.2/§16) and, in the same investigation, root-caused the AGENT-2 reaper-epoch race (§12.6) that had made
the historical "Agent … timed out" flake look environmental. Full method + per-lever deltas:
`docs/benchmark-results.md`, `docs/44-claude-perf-experiments.md`, `docs/45-claude-perf-investigation.md`;
deviations: `docs/implementation-notes.md` (folded into this document at v18).

**Console transport A/B (`ConsoleMode`).** Virtio-console makes cold boot nearly **independent of log
verbosity** where UART scales with it: CH cold p50 uart×balanced 316 vs virtio-console×balanced 291, and
uart×verbose **558** vs virtio-console×verbose **299** (−46% — full kernel logs at ≈balanced-UART cost,
because `hvc0` is virtqueue-batched, not a per-byte PIO exit). Restore working at 67–70 ms across the same
grid also validates the CH `console.file` restore config-rewrite (moved in lockstep with `serial.file`)
and the QEMU virtio-serial wiring end-to-end.

Reading these together:

- **Restore validates the snapshot tier and inverts the cold-boot ordering for the metric that matters.**
  On CH, restore is **≈5.4× faster than cold** (316→58 ms). And Firecracker now **does** win restore while
  losing cold boot (24 ms restore vs 764 ms cold, ≈32×) — the density/snapshot-tier role it is assigned is
  measured, not aspirational. Both CH and FC restore today; QEMU's tier is validated-but-unwired (§16).
- **CH lazy restore (`prefault=off`, userfaultfd) is ≈1.5× faster than eager** — freq-pinned, lazy ≈176 ms
  vs eager ≈258 ms, so ≈82 ms saved (a pre-pass eager/lazy A/B; read its p50s, per the C-BIN-1 caveat above).
  But the win *understates* lazy's true cost, which reappears as in-guest first-touch page faults during
  execution — so "lazy wins" is for time-to-resume, not time-to-first-useful-work.
- **Cold boot is ≈79–89% guest-kernel-boot + agent-startup wait** (the `connect` phase); the multi-`PUT`
  REST config is ≈1 ms, so chasing the REST path won't move it.

**Density (CH, 8 concurrent, 256 MiB):** each guest demand-pages ≈58 MiB (`RssShmem` via memfd, dead-linear
per added guest); implied ceiling ≈230 idle guests / ≈52 if each faults its full 256 MiB. Default KSM
dedup is **0** (shared memfd isn't `MADV_MERGEABLE`); the opt-in `ksm_mergeable` lever dedups ≈394 MiB /
~84% across 8 identical guests (§9.3). **Suspend size tracks guest RAM exactly** and is flat in rootfs size
(256 MiB → 268.5 MB total; memory file is ~100% of it). **Rootfs size:** the OCI slim base packs to
≈79 MB uncompressed erofs vs ≈120 MB for `mmdebstrap --variant=minbase` (trixie, apples-to-apples) —
~34% smaller (the pipeline's actual `--variant=apt` build is ≈129 MB → ~39%); the OCI base earns its keep
on size, the builder-VM source on provenance. **Guest agent:** static-`musl` is ~6.2% *larger* than
glibc-dynamic (it static-links libc rather than borrowing the rootfs `libc.so.6`), so the real deciding
axis is toolchain-availability + rootfs-independence, not size.

**Per-test critical-path budget (CH, post-pass, graceful `shutdown()` teardown):** cold `connect`
(guest-boot + agent wait) ≈266 ms, create/spawn ≈44 ms, exec ≈4 ms; restore `connect` collapses to
**≈4.6 ms** (reconnect + the single native `Resync` round-trip over the now event-driven accept, EXP-C; was
≈16 ms pre-EXP-C and ≈36 ms with the 3 subprocess execs), restore+resume ≈54 ms, exec ≈1 ms. **Teardown
note:** the budget measures the *graceful* `MicroVm::shutdown()` (`request_shutdown` → poll `has_exited` up to
a 250 ms grace → force-kill) at ≈265 ms after the EXP-D deadline-before-RPC change — a ceiling, not a leak;
the fast per-test path is `Drop` (force-kill the VMM process group + reap, **≈27 ms**, §12.10), which a RAII
consumer pays instead. The vsock exec round-trip floor is sub-millisecond (p50 ≈0.7 ms — 711 µs p50 / 852 p95
/ 1013 p99, incl. in-guest fork/exec/reap).

**Which numbers become guards.** Absolute ms/density/sizes stay observational (hardware- or pin-bound).
The *relative* invariants graduate to per-backend regression guards once a baseline is pinned:
OCI-vs-`mmdebstrap` hot-path parity (delta ≈ 0), boot working set flat in image size, snapshot size flat in
rootfs size (and tracking guest RAM), and per-test critical-path **phase shares** (a phase doubling its
share is a regression even when absolute ms move with hardware). Cross-backend selection is a tracked
output, re-read per pin.

---

## Part V — Status and roadmap

## 16. Open decisions and known gaps

What is *not* yet done, so a new developer knows where the edges are. (The v14 rename to `vmcell`, the
cargo workspace, the durable re-bless fix, the lifecycle verbs, `oci2erofs`, and the feature-matrix
collapse have all **landed** — they are described in the body as current, not listed here.)

- **Firecracker warm restore has two residual gaps.** The tier itself is wired and validated
  (`snapshot_restore: true`, the fastest restore tier; the story is in §3.2). What remains: **UFFD lazy
  restore** is unwired (`lazy_restore: false`, M-VMM-1 — `RestoreMode::Lazy` would silently fault eagerly,
  deferred as OPP-18b in `docs/45`), and FC re-binds the snapshot's baked host vsock UDS **verbatim** (no
  load-time override in v1.16), declared as `restore_rotates_host_paths: false` — a lineage's restores
  share one host path, so `restore()` fail-loud-guards (the `reject_live_baked_vsock` liveness probe)
  against restoring while the snapshotted VM (or a prior restore) is still alive, and concurrent restores
  from one lineage are unsupported — so the zygote fan-out (§9.4) refuses a concurrent (`n > 1`) FC pool
  with `Error::Unsupported` (gated on `restore_rotates_host_paths`); a single FC clone is fine. For reference, the wired
  mechanism is a fresh process + `PUT /snapshot/load {resume_vm:false}` (restore returns paused, caller
  resumes), `PATCH /vm` for pause/resume, the `vmcell_host_paths.json` sidecar, and a `create()`-time
  `PUT /entropy` virtio-rng attach (without which the post-restore reseed silently reports
  `reseed_applied: false`).
- **QEMU snapshot: privileged tier validated but unwired.** `snapshot_restore: false`. The QEMU *migration
  mechanism* for the privileged in-kernel-`vhost-vsock` config is validated at the QEMU level (no
  QEMU-10.2 migration blocker; migrate→restore verified live), but it is not wired as a vmcell backend;
  remaining work is the live agent-reconnect run + wiring `snapshot()`/`restore()` and flipping the
  capability for that config only. (This "validated at the QEMU level, not wired end-to-end" is a weaker
  claim than CH's wired-and-validated tier above.)
- **Single-snapshot CoW for many clones — LANDED in v19 (§9.4).** The zygote fan-out reflink-copy-on-write-
  copies the suspend dir per clone and restores each private copy (`Zygote`, `MicroVm::restore_cow`), so the
  in-place `config.json`/sidecar rewrites are per-clone and the master stays immutable (§12.12). Concurrent
  fan-out is gated on `restore_rotates_host_paths` (CH ✓; FC single-lineage, below). **Residual:** (a) FC
  still has no per-clone host-path override, so a *concurrent* FC fan-out from one lineage is `Unsupported`
  (a single FC clone works); (b) **sparse-snapshot** (`SEEK_HOLE`) to shrink the on-disk suspend image is
  the un-taken pool-density lever (Appendix C) — orthogonal to CoW and still open.
- **Live pin resolution.** `ResolvePinsStage` loads a committed `pins.json` rather than live-resolving
  tag→digest / `snapshot.debian.org` timestamps. (The OCI fetch itself is now behind the injectable
  `OciPuller` seam with a recording/replaying `FakeOciPuller`, so the requirement-7 replay + tamper tests
  do run for OCI — only live *resolution* is forward work.)
- **The `mkfs.erofs` shell fallback is unwired (M-ART-11).** The in-process `am-fs-erofs` `tar2erofs`/
  `oci2erofs` path is the *only* wired erofs writer; the design's `mkfs.erofs` fallback was never
  implemented, and a missing input is a hard error, not a fallback. Wiring the shell fallback is forward
  work (or the claim is dropped, Appendix B).
- **In-VM `mmdebstrap` source — extracted to `vmcell-rootfs-builder` and wired end-to-end (LANDED in v20).**
  Un-deferred from v19's "library-present but deferred" state: the source moved out of the `vmcell` package
  into the `vmcell-rootfs-builder` crate (§8.2/§10.1) and is wired via `vmcell-cli --rootfs-source
  mmdebstrap`. It boots a builder micro-VM on the **privileged/tap path with `Egress::Open`** for real apt
  egress, with a **host apt-proxy fallback** when direct egress is unavailable, then emits the erofs through
  `vmcell`'s shared `pack_erofs_with_injection` (§5.4). Its apt verification uses the pinned base image's
  own `debian-archive-keyring` (an equivalent trust root pinned transitively by the base-image digest);
  passing an explicitly pinned keyring is the residual forward work.
- **Bootstrap kernel seed — Kata prebuilt pinned, host-`make` fallback (LANDED in v20).** The in-VM kernel
  and rootfs builders need a working seed `vmlinux` to boot their builder VMs, which cannot itself come from
  an in-VM build (§8.5). Research result: a **Kata Containers** prebuilt `vmlinux.container` (Linux 6.18.35,
  from `kata-static-3.32.0-amd64.tar.zst`) is **validated to boot** vmcell's erofs root to PID 1 + overlay
  under CH (it ships EROFS + FUSE/virtio-fs + VSOCK + PVH + overlay built in), so it is pinned as the
  bootstrap seed and downloaded+sha256-verified by `PrebuiltKernelStage` (`kernel_prebuilt` pin, §11.2).
  Generic microVM kernels were **disqualified** — a Firecracker CI microVM kernel omits
  `CONFIG_EROFS_FS`/`CONFIG_FUSE_FS` and panics with `VFS: Unable to mount root fs`. Host-`make`
  `KernelStage` remains the guaranteed fallback seed.
- **A single start-up `HostCapabilities` descriptor.** The fail-loud contract is realized today by
  scattered per-op checks; consolidating them into one queryable descriptor probed once at start-up (§7.2)
  is unbuilt.
- **`agent()` still takes a per-call `timeout`/`clock` (M-ORCH-6).** `MicroVm::agent(&mut self, timeout,
  clock)` (§10.2) threads a timeout and a `Clock` through every call site even though the handle already
  owns a `Timeouts` and could own its clock; folding them back in so `agent()` takes no such arguments is a
  deferred API cleanup (the current signature is accurate as-built, just more verbose than it needs to be).
- **Per-VM network byte counters.** `ResourceUsage` has none (cgroup v2 has no `net.stat`, §7.1); a
  netns-scoped usage type reading `/sys/class/net/<if>/statistics` inside the VM netns is forward work.
- **`Egress::Open` provides no *arbitrary* outbound egress (H-NET-4).** The default `Open` variant selects
  "no interception proxy"; connectivity is then only what the datapath natively provides (the unprivileged
  NAT reaches registered `host_services_port`/proxy forwards; the privileged path reaches only what its
  TPROXY ruleset admits). Dialing the frame's real destination / host masquerade is not implemented, so
  `Open` is not open internet egress (§6.1). Closing it — real re-origination/masquerade, or making `Open` a
  typed `Unsupported` — is forward work.
- **Privileged `host_services_port` is rejected, not honored (H-ORCH-3/H-NET-2).** `config::build()` returns
  a typed `Error::Config` for `Privileged { host_services_port: Some(_) }` (fail-loud, replacing a prior
  silent no-op) because the privileged TPROXY ruleset policy-drops everything but the web/proxy ports.
  Wiring it on the privileged path (a new accept rule + host binding) is forward work (§6.1).
- **In-process `fuse-backend-rs` read-only.** It does not enforce read-only, so a read-only share on that
  backend is *rejected fail-loud* (§5.2); enforcing RO in the passthrough is required before the experiment
  graduates.
- **Control-plane daemon — core verbs built; residuals catalogued in §18.9.** The productization seam
  described in §17 ships as **`vmcelld`** (§18): it owns VMs and serves `create`/`list`/`exec`/`stats`/`snapshot`/
  `destroy` over a bearer-authed REST/OpenAPI surface, with a per-daemon artifact store and a start-up orphan
  sweep. The registry *logic* is fully exercised against a recording fake launcher, but the real
  `MicroVmLauncher`'s live boot/exec/teardown is **validated only on a KVM host** (`just test-daemon`,
  empirically green there), not in this environment — written and reviewed (§18.9). Residuals — the
  warm-pool/zygote manager, the setup broker (single-process privilege ships now), a UDS transport (TCP
  loopback ships now), JWT / per-key scopes (a single all-scopes key ships now), `pause`/`resume` routes,
  writable-scratch-from-artifact disks (daemon extra disks are read-only), artifact GC/quota, and CLI-stub
  removal — are catalogued in §18.9.
- **A fully-automatic orphan sweeper.** The `sweep_orphans()` free function reaps leaked netns/cgroup/scratch
  when invoked, but a periodic background sweeper + orphan registry is not yet automatic, so a leaked netns
  can still collide with a later vmid between runs. (The daemon closes this for its own crash-restart via the
  start-up `sweep_orphans` run with an empty live set, §18.4; a general periodic background sweeper is still
  forward work.)
- **The virtiofsd per-share service-uid allocator** is unimplemented (it uses `SUDO_UID`, refuses `nobody`,
  §5.2).
- **The ≈254-concurrent-VM ceiling per `/16`.** Beyond that, widen the address scheme to a second octet
  (§10.2).
- **Cross-version snapshot fragility.** Pin one exact CH+virtiofsd build for any snapshot pool; CH does not
  guarantee cross-version snapshot compatibility. This is now *partly* mechanized: the `SnapshotStage` cache
  key folds the pinned `cloud_hypervisor` identity (M-ART-7), so a CH bump invalidates stale snapshots at
  build time rather than failing at first restore (virtiofsd is deliberately *not* folded — a
  snapshot-eligible VM runs none, §12.1); the operational "pin one build" advice still governs the runtime
  binary. x86-64 is the primary arch; aarch64 is a supported second target, not a free rebuild (kernel
  configs and snapshot artifacts differ).
- **The carried `vhost`/`vhost-user-backend` patch** — now `vendor/vhost` (0.16.0) and
  `vendor/vhost-user-backend` (0.22.0), the crates.io-packaged sources vendored **in-tree** and wired via
  `[patch.crates-io]` path entries at the workspace root with exact `=` pins (content in git, stronger than
  the old git-fork-rev posture). The `SET_VRING_ENABLE` `PROTOCOL_FEATURES` relaxation is now gated on
  `features_acked` (accept QEMU's early, pre-`SET_FEATURES` delivery; re-enforce the spec after
  `SET_FEATURES` — narrower than the original blanket relaxation, M-VEND-2), and `just ci` asserts via
  `cargo tree` that both resolve from `vendor/` so a version bump cannot silently drop the patch (M-VEND-3).
  It stays a maintenance/reproducibility cost; drop `vendor/` + the `[patch]` entries if the
  QEMU-unprivileged tier is not required (§10.4).
- **Deferred perf opportunities (vetted, not re-derive; `docs/45-claude-perf-investigation.md`).** Parallel
  virtiofsd share startup (OPP-10) is real but `try_join_all` is cancellation-unsafe — a dropped start
  future leaks the daemon process group, violating "ownership owns cleanup" — and it is invisible on every
  tracked benchmark (share-free snapshot tier by law); revisit with a `join_all`+owner-push design plus a
  zero-leak failure-injection test (the cheap lever if shares matter is the 20 ms fs socket poll → 2–5 ms).
  The smoltcp NAT pump cadence (5 ms) is a `low_latency` lever deferred until a networking-latency benchmark
  exists. Two guest-kernel-boot residues remain unattributed: a ~22 ms `fs_initcall`-region gap (an
  `initcall_debug` probe someday) and a ~5.7 ms `cfg80211` `regulatory.db` double firmware-load failure
  (kernel-config-trim territory, not cmdline). Deeper CH hybrid-vsock reliability is the residual
  environmental reset the nextest retries absorb (§14). The 12-item OPP reject table in `docs/45` (OPP-4…17)
  is mechanically refuted — don't re-derive it.

## 17. Future capabilities

The rebrand from a test platform to a general micro-VM runner surfaces a backlog each of the three domains
would use. Every candidate is gated on the §12 invariants and on the one governing rule: **a capability the
*core* can offer workload-agnostically goes in the library; a capability that encodes one domain's *policy*
ships as a thin consumer crate on top.** These are candidates, not commitments; the §15 numbers and §16
gaps gate the order.

**Cheap, high-value, extend an existing seam.** Deterministic egress + model **cassettes** (record/replay
on the proxy's `doubles` + `RequestLog`); **declarative per-sandbox egress policy** with a full
attempted-connection audit (default-deny allowlist-by-domain as *data* at the MITM proxy, matching on DNS
label boundaries); **deterministic clock control** over vsock (promote the mandatory post-restore resync
into a set/freeze/forward-jump API); **structured serial fault capture** (a classifier turning
oops/BUG/WARN/KASAN/lockdep into a typed matchable `Error` — the cheapest high-value item); **network fault
injection** (`netem` via rtnetlink on the tap path); **extra virtio-blk devices + disk-I/O throttling** and
**append-only extra kernel cmdline + an optional `init=` override** — **shipped (§19)**: `extra_disks` /
`DiskIoLimit` (portable bandwidth/IOPS caps across all three backends' native rate limiters — plain virtio-blk
composes with snapshot) and `extra_kernel_args` / `init` (a genuine PID-1 replacement, honored fail-loud
without the control plane). What remains forward work on this seam is virtio-blk **error** injection (a fault,
not a throttle — QEMU-`blkdebug`-only) and a writable-scratch-from-artifact disk on the daemon path (§19.4).

**Design-now-build-later.** Single-snapshot **copy-on-write clone / `fork()`** — the headline primitive both
the agentic and serverless domains share — **shipped in v19 as the zygote fan-out** (§9.4): `Zygote` is the
lineage handle, reflink-CoW-copies the suspend dir per clone, and mints N divergent clones concurrently.
What remains *future* on top of it: a **`fork()`-style divergence API** that clones a *running* VM at an
arbitrary point (not just the agent-ready zygote), and per-clone **overlay divergence tracking**. The
**standalone control-plane daemon** + versioned control-plane API is **shipped as `vmcelld`** (§18) — it owns the VMs it
starts and serves `list`/`rm`/standalone `exec` (plus `create`/`stats`/`snapshot`/`destroy`) over a
bearer-authed REST/OpenAPI surface, the productization seam the single-process `MicroVm` ownership model cannot
provide alone; its **warm-pool manager** (`POST /v1/pools` — pre-warm N zygote clones, hand one out per
request, scale-to-zero) remains **future** on top of it (the registry already owns the handles, so a pool is a
hand-out policy, gated on the §9.4 fan-out capability); **privileged-window
hardening** (each VMM's own seccomp, a jailer-equivalent, and a **setup broker** — the recommended privilege
boundary for the daemon/API mode); a generic **vsock↔TCP port-forward bridge** (the in-guest model-proxy
transport); **observability + resource controls** over OTLP; **persistent interactive PTY sessions**;
in-VM **filesystem checkpoint/rollback** of the tmpfs overlay; **kcov/gcov/sanitizer coverage extraction**
over vsock (a syzkaller-executor host); **multi-VM cluster topologies** on a shared L2 segment (a
Jepsen/Antithesis substrate); **gdbstub + crash-dump capture**; a **hardware-profile matrix** (CPUID
masking + aarch64); and a **scale-to-zero invocation lifecycle** on the warm pool.

**Out-of-scope by design (consumer layers, shipped as examples on top):** an **MCP server frontend**; a
**KUnit/kselftest/LTP runner** with KTAP parsing; **`rr`-as-payload** deterministic replay; a **per-tool-call
run bundle**; **per-invocation billing/metering**. Naming the boundary is itself the keep-general guard
(§12.11): if a capability is a workload-agnostic property of "an isolated VM" it is core; if it encodes what
a test, an agent, or a function should *do* with that VM, it is a consumer.

---

## Part VI — Control-plane daemon and extended device surfaces

The §3–§11 core is a single-process library: a `MicroVm<V>` handle *is* a VM's lifetime, and one-shot CLI
verbs drive it. Part VI describes the two surfaces layered on that core after it was solid — the long-lived
**daemon** that owns VMs across requests (§18) and the additive **device knobs** for extra disks, custom init,
and disk-I/O throttling (§19). Both add **no** dependency edge into `vmcell` (the daemon depends on `vmcell`,
never the reverse) and keep every §1–§17 cross-reference valid. The house rules of §12/§14 apply unchanged:
one law one predicate, validate-at-construction, fail loud, security checks anchor on trusted data and ship
with a positive control, teardown is ownership, every claim ships with a gate that can go red.

## 18. The control-plane daemon (`vmcelld`) and its client

`vmcell` (the library) and `vmcell-cli` (the CLI) are a **single-process** model: a `MicroVm<V>` handle owns
its VM and *is* the lifetime — when the handle drops, ordered teardown destroys the VM (§12.10). That model is
correct and stays the default for tests and for one-shot CLI verbs (`run`/`create`/`snapshot`/`stats`), but it
structurally cannot offer a VM that **outlives the process that created it**: there is nobody to hold the
handle. `vmcell-cli` already names this boundary — its `exec`/`ls`/`rm`/`destroy` verbs return a typed
`Error::Unsupported` "deferred to the daemon" rather than faking success (§11, the "skip == pass" anti-pattern
in CLI form).

**The daemon is that missing owner.** `vmcelld` is a single long-lived process that **owns** the VMs it starts:
it holds each `MicroVm` handle in an in-process registry (§18.4), so a VM's lifetime is decoupled from any one
client request but stays tied to the daemon — and the whole "teardown is ownership, `Drop` releases resources"
invariant (§12.10) carries over unchanged. Clients talk over HTTP and refer to VMs by an opaque **id**. The one
thing owning-and-`Drop` cannot handle by itself is a *hard* kill of the daemon (SIGKILL, power loss), which
skips every `Drop` and leaks the VMs' netns/cgroup/scratch; the daemon closes that with a **start-up orphan
sweep** (§18.4), so a crash-and-restart self-heals. This is the productization seam §17 describes (a
standalone control-plane daemon + versioned control-plane API + warm-pool manager). The daemon introduces cross-cutting invariants
§12.13–§12.20; its gates live in §14.

### 18.1 What it adds, and where it sits

Two consumers, one daemon:

```
  vmcelld-ctl (CLI)  ─┐                         ┌─ artifact store  (<artifacts-dir>/<name>)  [files]
  your Rust program  ─┤── HTTP/REST (bearer) ──▶ vmcelld ─┤
  (vmcell-daemon-     ─┘   OpenAPI-described    (owning,   └─ VM registry ── holds ──▶ MicroVm … MicroVm
   client)                                       blessed)     (Drop releases; start-up sweep reclaims leaks)
```

The daemon is **the** place the process-global allocators §10.2 mandates finally have a natural single home:
one `VmidAllocator::shared()` and one `Arc<CidAllocator>` per daemon process, handed to every launch. Under the
single-process model each CLI invocation minted its own hermetic allocators; the daemon holds the one
authoritative pair for its host.

**The five workspace members** (§10.1) form an acyclic star on top of `vmcell` — a directed star like the
builders:

```
  vmcell-privilege ◀── vmcell-test-runner        (lean tier; no vmcell edge)
        ▲
        └────────────── vmcell-daemon ──▶ vmcell (0.6.0, host stack; cloud-hypervisor+metrics+pipeline)
                             ▲
                             │  (DTOs re-exported, no server code)
                        vmcell-daemon-client ◀── vmcelld-ctl
                             ▲
                        vmcelld ──▶ vmcell-daemon
```

`vmcell` has **no** edge to any of these. The wire schema is single-sourced by keeping the DTOs (and the
artifact-name predicate, §18.3.1) in `vmcell-daemon` compiled **unconditionally**, while the whole server stack
— the axum router + handlers, the VM registry, auth, and the `vmcell` host stack — sits behind a **default-on
`server` feature**. `vmcell-daemon-client` depends on `vmcell-daemon` with **`default-features = false`**, so it
links **only** the wire DTOs + the name predicate (serde + std), never axum or the `vmcell` server stack — the
client shares the server's exact types without pulling the server. (Cargo features are additive, so an opt-out
default-on `server` feature is the idiomatic form of "the client links a subset"; the daemon binary and tests
get the full stack by default.) The daemon depends on `vmcell` with the same features `vmcell-cli` uses
(`cloud-hypervisor`, `metrics`, `pipeline`, `cli`).

### 18.2 Privilege and blessing

The daemon needs the **same three capabilities** the privileged operating mode needs
(`cap_net_admin,cap_sys_admin,cap_dac_override`, §6.4). There are two ways to give them to it, and the choice
matters for the dev inner loop:

- **Tests and dev — launch `vmcelld` through the blessed `vmcell-test-runner` (the default, no per-rebuild
  blessing).** The runner is a cap-conferring `exec` wrapper: it raises the three caps into the **ambient** set
  and `execvp`s a target confined under the workspace `target/` dir (§14). Its confinement accepts **any**
  `target/` binary, not just test binaries — so `vmcell-test-runner target/debug/vmcelld …` execs `vmcelld` with
  the three caps in its effective set, and `vmcelld`'s blessing precondition passes **without `vmcelld` itself
  being blessed**. Because only the runner carries file-caps, and the runner rarely changes, `vmcelld` (which
  changes constantly) rebuilds freely with **no `sudo setcap` on every change** — the exact churn
  `vmcell-test-runner` was introduced to kill (§14), now extended to the daemon. Integration tests spawn
  `vmcelld` this way (§14); `just daemon` runs it this way for manual poking.
- **Standalone / production — file-caps or systemd ambient caps.** A `vmcelld` run as a long-lived system
  daemon *outside* a test harness gets its caps by being blessed once (`setcap …+ep` on the installed binary)
  or, better for production, via the service manager (`systemd`'s `AmbientCapabilities=`). This path is
  unchanged by the runner shortcut; it just isn't on the dev hot path, so `just bless` no longer blesses
  `vmcelld` (only the runner), keeping the inner loop free of `setcap` prompts.

Either way the precondition below is identical.

**The one deliberate difference from the runner: the daemon retains the caps; it does not drop-and-exec.** The
test-runner is a *transient* wrapper — file-caps → raise ambient → drop to the dev uid → `execvp` the test
binary — so the caps live only across a single `exec` (§14). The daemon is a *long-lived server* that must
itself perform privileged VM operations (netns/tap/nft, §6.4) for the whole life of the process. So `vmcelld`
runs the **blessing precondition** (the three caps must be present in the **effective** set, or `euid == 0`)
and then **keeps** them; there is no uid drop, no ambient raise, no bounding-set shrink, no `exec`. If the
precondition fails it prints the same `setcap …+ep` remediation and exits non-zero — **refuse to start if
privileges are missing** (§12.14). It never silently runs degraded: a daemon that came up without
`CAP_NET_ADMIN` would fail every privileged VM create at first use, which is the fail-loud-at-construction rule.

**`vmcell-privilege` — one predicate, two callers.** The precondition logic is security-critical and was
private to the runner's `main.rs`. Copying it into the daemon is precisely the "duplicate load-bearing logic
diverges" trap the rubric bans (§12). So it is extracted into `vmcell-privilege` with the runner's pure,
already-unit-tested seams moved verbatim and re-exported:

```rust
// vmcell-privilege — lean: rustix + capctl + libc only.
pub const PRIVILEGED_CAPS: [Cap; 3] = [Cap::NET_ADMIN, Cap::SYS_ADMIN, Cap::DAC_OVERRIDE];

pub fn compute_missing(effective: &CapSet, need: &[Cap]) -> Vec<Cap>;          // pure (was runner-private)
pub fn blessing_remediation(uid: u32, exe: &Path, missing: &[Cap]) -> String;  // pure
pub fn shell_single_quote(p: &Path) -> String;                                 // pure

/// Effective-set precondition shared by the runner and the daemon. Returns the
/// remediation string on failure. Does NOT mutate the process.
pub fn ensure_blessed_or_explain(need: &[Cap]) -> Result<(), String>;

// The runner's transient path stays runner-only (it drops uid + execs) but its PURE plan moves here:
pub struct PrivilegePlan { /* … */ }
pub fn plan_privilege_transition(/* … */) -> PrivilegePlan;   // pure, unit-tested against buggy inverses
pub fn apply_privilege_transition(plan: &PrivilegePlan) -> Result<(), String>;  // thin syscall edge
```

The daemon uses only `ensure_blessed_or_explain(&PRIVILEGED_CAPS)` + `blessing_remediation`; it never calls the
transition functions (it keeps its caps). The runner keeps its full path but now imports it instead of defining
it. The runner's existing red-on-inverse tests (the `+ep`-not-`+p` remediation, the `compute_missing`
effective-vs-permitted test, the plan tests, the confinement tests) **move with the code** into
`vmcell-privilege` and keep guarding both callers — the extraction is refactor-only and the unchanged tests
prove it. The runner's exec-target **confinement** (`confine_under` / `trusted_target_root` /
`confine_target_under`, §14) stays runner-only, and it is exactly what makes the runner-launch shortcut safe:
the runner only confers caps on a binary that canonicalizes to a descendant of the trusted `<workspace>/target`
(derived from the runner's **own** location, never the argument), so `vmcell-test-runner target/debug/vmcelld`
is admitted while an arbitrary path is rejected — the same boundary that admits a test binary admits `vmcelld`,
and a unit test guards that a `vmcelld` path under `target/` is accepted. The daemon itself execs no target
binary, so it has no confinement obligation of that shape — its analogous "anchor on trusted data" check is the
**artifact-name validator** (§18.3), which anchors every filesystem access on the daemon's own `--artifacts-dir`,
never on a client-supplied path.

**Where the daemon runs its privileged work.** Same as the library today: `MicroVm::start`/`restore` perform
the netns/tap/nft bring-up (§6.4) using the caps the process holds. The daemon adds no new privileged syscalls;
it just holds the caps for longer. The §17 "setup broker" (a separate minimal-privilege helper the daemon talks
to, so the network-facing HTTP surface is **not** in the same process as the ambient caps) is the recommended
hardening and stays **forward work** (§18.9) — the daemon ships the single-process form with the HTTP surface
bound locally and behind auth, and records the broker as the next hardening step, honestly.

### 18.3 The artifact store

The daemon receives `--artifacts-dir <path>` and manages the files under it with three operations — **create,
list, delete; no update**. This is deliberately *not* the `vmcell` artifact *pipeline* (§11, which builds
kernels/rootfs/snapshots): it is a flat content store the VM APIs draw their `kernel`/`rootfs` inputs from. A
client `build`s artifacts elsewhere (or with the CLI) and **uploads** them into the daemon's store; the daemon
never fetches from the network on a client's behalf.

#### 18.3.1 One name predicate, anchored on trusted data

Names map **directly** to files: artifact `k1` is the file `<artifacts-dir>/k1`. That makes the name validator
a **security boundary** of the same class as the runner's exec-target confinement (§14) — a name that
path-traverses (`../../etc/passwd`) or is absolute would let a client read or clobber files outside the store.
So there is **one** predicate, pure and unit-tested against its buggy inverses (§12.13):

```rust
/// The ONLY function that turns a client-supplied artifact name into a path. Every
/// store op and every VM-API artifact reference goes through it. Rejects anything
/// that is not a single safe path component.
pub fn resolve_artifact_path(dir: &Path, name: &str) -> Result<PathBuf, ArtifactError>;
```

Accept rule (allowlist, not denylist — a denylist of "bad" substrings is the divergence trap): a name is valid
iff it is **non-empty**, **≤ 255 bytes**, every byte is in **`[A-Za-z0-9._-]`**, and it is **not** `.` or `..`
and does **not start with `-` or `.`** (a leading `-` would be read as a flag by any tool the name is later
handed to; a leading `.` hides the file and enables the `.`/`..` family). The result is **always**
`dir.join(name)` with `name` a single component — there is no `/` in the accepted set, so no subdirectories and
no traversal are representable. The predicate returns the joined path; callers **never** construct
`dir.join(client_string)` themselves (grep-able gate: `dir.join(` on a client string outside this function is a
review-reject, mirroring "one law, one predicate" for `mac_math`/`MAX_FRAME_BYTES`). Red-on-inverse tests: `..`,
`a/b`, `/abs`, `-rf`, `.hidden`, empty, over-255-bytes, and a NUL byte all reject; a **positive control**
(`vmlinux-6.12`, `rootfs.erofs`, `k1`) accepts and joins to exactly `<dir>/<name>`.

#### 18.3.2 Operations

- **Create** — `PUT /v1/artifacts/{name}` with the file bytes as the body (or a streamed multipart for large
  images). **No update**: create **rejects an existing name** with a typed `AlreadyExists` (409), never a
  silent overwrite. Bytes are written to a **temp file in the same dir** then **atomically renamed** into place,
  so a crashed or truncated upload never leaves a half-written artifact that a later VM boot would read. The
  write is size-capped by `--max-artifact-bytes` (default a generous ceiling), rejected fail-loud past it — an
  unbounded upload is a trivial disk-fill DoS.
- **List** — `GET /v1/artifacts` → `[{name, size_bytes, sha256}]`. The digest is a SHA-256 of the file
  contents, so a client can verify an upload round-tripped intact. Listing reads **only** direct children that
  pass `resolve_artifact_path` (a stray subdir or a name written out-of-band that fails validation is skipped,
  never surfaced as a usable artifact).
- **Delete** — `DELETE /v1/artifacts/{name}` → 204. Refuses to delete an artifact that is **in use** by a live
  VM (a VM booted from `k1` — or attaching it as an extra disk, §19.4 — pins `k1`) with a typed `InUse` (409):
  the handler asks the registry `is_artifact_in_use(name)` (which scans the owned VMs' pinned names, §18.4)
  before deleting, so the kernel is never pulled out from under a running VM. Residue check in tests: the file
  existed before delete, then is gone.

Every store op is a pure-ish function over `(dir, name, bytes?)` behind the validator, unit-testable against a
`tempdir` with **no** HTTP and **no** KVM — the axum handler is a thin adapter that maps the typed store error
to a status code (§18.5).

### 18.4 The VM registry — owned handles, `Drop`-releases-resources, start-up sweep

The daemon **owns** every VM it starts, holding the `MicroVm` handle in an in-process registry. This keeps the
§12.10/§12.17 invariant intact end-to-end: while the handle is held the VMM process and its netns/tap/cgroup/
scratch stay alive, and when the handle drops the *same* ordered teardown runs. Two seams and one recovery hook:

- **`VmLauncher` / `VmHandle`** (the seam) — the registry drives VMs through these traits, not `MicroVm`
  directly, so its logic (id minting, the state machine, ordered teardown, artifact pinning) is unit-testable
  against a recording **fake** with no KVM or root (the §10.6 injectable-seam discipline). The real
  **`MicroVmLauncher`** is a thin adapter: `launch` builds a `VmConfig`, calls `MicroVm::start` (bringing the
  agent up so a returned VM is genuinely ready), and boxes the handle; `exec`/`usage`/`snapshot`/`shutdown`
  forward to the `MicroVm`. Because the daemon holds the handle, the real backend needs **no** new vmcell
  primitive — this is the single-process ownership model kept in-process, just held by a long-lived server
  instead of a one-shot CLI.
- **`Registry`** — a `tokio::sync::Mutex<HashMap<VmId, Arc<VmSlot>>>` where each `VmSlot` holds the boxed
  handle behind its **own** async mutex. Ops on **different** VMs run concurrently; ops on **one** VM serialize
  on its single vsock control channel (correct — one channel per VM). The VM's immutable identity (id, vmid, the
  artifact **names** it pins) is read lock-free for the delete-in-use guard; only the handle + state sit behind
  the per-VM lock. The **id** is an opaque server-minted token (`vm-<counter>-<splitmix64>` — readable counter +
  mixed suffix so ids are unguessable, never reused in a process); it is **not** the VMID (the network octet,
  §10.2).

**Teardown is ownership (§12.10), two paths, one helper.** `destroy` removes the slot from the table (so no new
op finds it), marks it `Destroying`, and runs the graceful `MicroVm::shutdown`; a clean daemon exit calls
`shutdown_all` (each VM's graceful shutdown); and dropping the `Arc<Registry>` runs each `MicroVm::Drop` — the
panic path — with the identical ordered cleanup (kill VMM proc-group → virtiofsd → tap/netns/cgroup/overlay/
scratch). A **hard** kill of the daemon skips all three and leaks the residue.

**Start-up orphan sweep — the crash-recovery counterpart.** Before it owns any VM, the daemon runs `vmcell`'s
`sweep_orphans` (§6.4/§16) with an **empty** live-vmid set, so every netns/cgroup-slice/scratch dir whose
trailing vmid is not currently owned — i.e. every orphan a previously hard-killed daemon left — is reclaimed.
(Nothing is live at start-up, so the empty set can never sweep a resource in use.) The sweep needs
`CAP_NET_ADMIN` to delete a netns, which the daemon holds (§18.2); per-resource failures are logged, not fatal.
This is what makes a crash-and-restart self-heal without leaking a netns that would later collide with a reused
vmid (the exact between-runs gap §16 records).

**Create flow.** `create` resolves the `kernel`/`rootfs` names to paths (the single validated join, §18.3.1),
`launcher.launch`es the VM, mints an id, and inserts the owned handle as `Ready` (the launch only returns after
the guest agent handshakes, so "ready" is derived from the VM, not a hopeful label). With a `command` it then
`exec`s and, if `ephemeral`, `destroy`s — the `run` one-shot, reusing the same `exec`/`destroy` paths.

#### 18.4.1 The configurable resource prefix — one flag for naming *and* sweeping

The `vmcell::naming` module and `VmConfig::resource_prefix` (§10.2, §12.19) collapse the seven historical
`vmcell-*` literals into one option. In `vmcelld` it is **one CLI flag**, `--resource-prefix` (default
`vmcell`), threaded to *both* the launcher (so its VMs are named with it) and the start-up sweep (so it reclaims
exactly those names). Two daemons with distinct prefixes therefore never sweep each other's resources —
validated on KVM: a daemon run with `--resource-prefix acme` names its VM's netns `acme-net-<vmid>`, reclaims a
planted `acme-net-*` orphan, and leaves a `vmcell-net-*` orphan from another tool untouched (§18.9). The default
reproduces the historical `vmcell-*` names exactly, so this is a non-behavioral change at the default.

### 18.5 The HTTP REST API and its OpenAPI document

#### 18.5.1 Surface (versioned `/v1`)

```
Artifacts
  PUT    /v1/artifacts/{name}      upload (create; 409 if exists)         body: bytes
  GET    /v1/artifacts             list                                   -> [ArtifactInfo]
  GET    /v1/artifacts/{name}      metadata (HEAD-like; no body download by default)
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
`#[serde(default)]` so old clients keep working — three config knobs plus the run/ephemeral pair, and the extra
device fields `extra_disks`/`extra_kernel_args` (§19.4):

- **`net: NetMode`** (`none` default | `privileged` | `unprivileged`). The daemon holds the caps, so the
  **privileged** tap path (netns + `/30` + default route) is available; `none` is a no-network VM;
  `unprivileged` is the smoltcp NAT (not snapshot-eligible). Validated: a `privileged` VM gets a host
  `vmcell-net-<vmid>` netns and the guest `eth0` comes up with a `10.200.x/30` and a default route.
- **`snapshotting: bool`** — boot a **snapshot-eligible** VM (no vhost-user device, §12.1). Rejected fail-loud
  (`400`) with a non-eligible `net` (e.g. `unprivileged`) *before* launch.
- **`restore_from: Option<String>`** — restore from the snapshot in the store under this prefix instead of a
  cold boot. The daemon restores via **CoW** (`MicroVm::restore_cow`, §9.4), so the named snapshot is
  **preserved** and re-restorable; `create` then drives the mandatory post-restore resync.
- **`command: Option<Vec<String>>`** — present ⇒ `run` (exec, capture, keep-or-teardown per `ephemeral: bool`);
  absent ⇒ `create` (boot to agent-ready and register).

The daemon resolves `kernel`/`rootfs`/`restore_from` (and each extra-disk name, §19.4) through
`resolve_artifact_path` against its `--artifacts-dir` — a client can only ever name an artifact it uploaded,
never a host path (§18.8). Errors map to status by the typed daemon error (§18.5.3), never a bare
500-with-string. Snapshots land **in the artifact store**: `snapshot` writes the CH snapshot dir under
`<artifacts-dir>/<artifact_prefix>/…` and returns the names, so a subsequent `create {restore_from}` can restore
from them by name — the store is the one exchange surface, no out-of-band paths. Validated end-to-end: a marker
written into a VM's tmpfs before `snapshot` survives a `restore_from` into a fresh VM.

#### 18.5.2 The OpenAPI document is generated once and gated for parity

The API is described by an **OpenAPI 3.1** document served at `/openapi.json`. Rather than trust a derive
macro's output (an untested claim) or hand-maintain a separate file (a divergence trap), the document is
**built by one function** `openapi_document() -> serde_json::Value` from the same route table the router mounts,
and a **parity gate** (a plain unit test, KVM-free, always runs) asserts the two agree (§12.16): **every**
`(method, path)` the router mounts appears in the document, **every** path/method in the document is actually
mounted, and every request/response `component` schema named by an operation exists. Red-on-inverse: add a route
without a document entry (or vice versa) → the parity test fails. The `securityScheme` is declared here (bearer,
§18.6) and applied to every operation except `/healthz` and `/openapi.json`; the parity gate also asserts **no
VM/artifact operation is missing its security requirement**. The OpenAPI document describes paths + auth, not
request-body schemas, so the additive `extra_disks`/`extra_kernel_args` fields (§19.4) do not change it.

#### 18.5.3 One daemon error type, matchable, mapped to status

Mirrors §10.3 (no `Error::Other(String)` catch-all; the caller-relevant conditions are typed). The daemon has
one `DaemonError` enum with a variant per failure class, each carrying the HTTP status it maps to in one
`IntoResponse` impl (one law, one predicate for the mapping):

```
NotFound        -> 404   (no such vm/artifact)
AlreadyExists   -> 409   (create over an existing artifact — the "no update" guard)
InUse           -> 409   (delete an artifact a live VM pins)
Conflict        -> 409   (op against a VM in the wrong state)
InvalidName     -> 400   (resolve_artifact_path rejected the name)
BadRequest      -> 400   (malformed body / knob; a config-validation Error::Config, e.g. a reserved kernel arg or 0 io_limit, §19.4)
Unauthorized    -> 401   (missing/blank bearer)  |  Forbidden -> 403 (wrong bearer)
Unsupported     -> 501   (an op the backend does not advertise — wraps vmcell Error::Unsupported)
PayloadTooLarge -> 413   (upload past --max-artifact-bytes)
Internal        -> 500   (a wrapped vmcell::Error with no more specific mapping; body is the Display, never a struct-dump)
```

The 401-vs-403 split is deliberate: **absent** credentials are 401 (per RFC 7235, with a `WWW-Authenticate:
Bearer` header); **present but wrong** are 403. A wrapped `vmcell::Error` renders its `Display` (the `#[error]`
message), never its `Debug` — the same L-BIN-4 lesson §11 records for the CLI. The error body is a small JSON
`{error, message}` documented as a component in the OpenAPI doc, so a client decodes a structured error, not a
bare string.

### 18.6 Authentication — a bearer API key (RFC 6750 form)

The idiomatic, minimal, correct choice is a **pre-shared opaque API key presented as an HTTP Bearer token**
(`Authorization: Bearer <key>`, the RFC 6750 "OAuth 2.0 Bearer Token Usage" transport), **not** a full OAuth 2.0
authorization-server flow. Rationale, stated honestly:

- A full OAuth flow (an authorization server, `/token`, grant types, JWT issuance/rotation) buys delegated
  third-party authorization the daemon has no use for — it is a **local, single-tenant control plane** for one
  operator's host. The bearer *transport* is the part of OAuth that carries the credential; adopting it (and
  describing it in OpenAPI as `type: http, scheme: bearer`) gives every standard HTTP client and the OpenAPI
  tooling first-class auth with **zero** custom flow.
- The key is an **opaque high-entropy secret**, not a structured JWT — so there is no signature to verify, no
  clock-skew window, no key-rotation ceremony in v1. Comparison is **constant-time** (`subtle::ConstantTimeEq`
  or a hand-rolled volatile compare) so a timing side-channel can't leak the key byte-by-byte — the positive
  control being "the correct key reaches the same authorized handler."
- The key is loaded from `--api-key-file` (a path, **perms-checked**: the daemon refuses a key file that is
  group/other-readable — §12.18, the "no secrets in world-readable files" discipline). Passing the key as a CLI
  arg or env var is rejected in favor of the file so it never lands in `ps`/serial logs. If no key file is given
  the daemon **refuses to start** (fail loud — a control plane with no auth is never an accident), unless
  `--allow-unauthenticated` is explicitly passed for a loopback-only dev bind, which is logged loudly at every
  request.

The auth check is one tower/axum middleware layer wrapping every route **except** `/healthz` and `/openapi.json`,
so a new route is authenticated **by default** (you opt out, you don't opt in — the safe default, §12.2/§12.15).
The parity gate (§18.5.2) asserts the opt-outs are exactly those two. Unit tests (KVM-free): correct key → 200
(positive control); wrong key → 403; absent → 401 with `WWW-Authenticate`; and a **timing** test that the
compare is constant-time in shape (equal-length inputs take a data-independent path) is a red-on-inverse guard
against a future `==` regression. Future extension (recorded, not built): JWT bearer tokens (the `jsonwebtoken`
crate is already in-tree) for short-lived, scoped credentials, and per-key scopes (read-only vs. full). v1 is a
single all-scopes key; the middleware seam is where scopes would attach (§18.9).

### 18.7 The client library and CLI

#### 18.7.1 `vmcell-daemon-client` — a Rust API that mirrors the entry points

The client offers a typed Rust API that matches the `vmcell` entry points as closely as the network boundary
allows. It is built on `reqwest` (already in-tree, §10.4) and re-exports the DTOs from `vmcell-daemon` (with
`default-features = false`, dropping the server stack — §18.1) so a request the client serializes and the server
deserializes are **the same** Rust type — the wire schema is single-sourced, and a field added to the DTO is a
compile error in the client if it is required, never a silent skew.

```rust
pub struct DaemonClient { /* base_url, bearer key, reqwest::Client */ }
impl DaemonClient {
    pub fn new(base_url: Url, api_key: impl Into<String>) -> Result<Self>;

    // Artifact store — the divergence from vmcell entry points is HERE (paths -> upload):
    pub async fn upload_artifact(&self, name: &str, body: impl Into<UploadBody>) -> Result<ArtifactInfo>;
    pub async fn list_artifacts(&self) -> Result<Vec<ArtifactInfo>>;
    pub async fn delete_artifact(&self, name: &str) -> Result<()>;

    // VM lifecycle — one-to-one with vmcell-cli verbs, kernel/rootfs given as artifact NAMES:
    pub async fn create_vm(&self, req: CreateVmRequest) -> Result<CreateVmResponse>;  // the general POST
    pub async fn run(&self, kernel: &str, rootfs: &str, cmd: Vec<String>) -> Result<ExecOutcomeDto>; // create+exec+teardown
    pub async fn create(&self, kernel: &str, rootfs: &str) -> Result<VmInfo>;         // boot to agent-ready, keep
    pub async fn exec(&self, id: &VmId, req: ExecRequestDto) -> Result<ExecOutcomeDto>;
    pub async fn stats(&self, id: &VmId) -> Result<ResourceUsageDto>;
    pub async fn snapshot(&self, id: &VmId, artifact_prefix: &str) -> Result<SnapshotInfo>;
    pub async fn ls(&self) -> Result<Vec<VmInfo>>;
    pub async fn destroy(&self, id: &VmId) -> Result<()>;               // == rm
}
```

The mapping to the §10.2 `MicroVm` API is intentionally tight: `run`/`create`/`snapshot`/`stats` match the CLI
verbs of the same name, and `exec`/`ls`/`rm`(`destroy`) are the four verbs `vmcell-cli` could only fail-loud on
— the client is where they finally work, over the daemon's owned VM registry. The single **forced divergence**:
a `vmcell run --kernel <path> --rootfs <path>` becomes `upload_artifact("k", "…/vmlinux")` +
`upload_artifact("r", "…/rootfs.erofs")` + `run("k", "r", cmd)` — a host **path** is replaced by an **upload +
name reference** (§18.8). `upload_artifact` accepts either raw bytes or a local path (v1 reads the file into
memory; streaming a large image is a small follow-up, §18.9). The client's error type surfaces the daemon's
typed `{error, message}` as a matchable enum (a 409 `AlreadyExists` is `ClientError::AlreadyExists`, not an
opaque status), so callers branch on the same conditions the server names.

#### 18.7.2 `vmcelld-ctl` — the CLI wrapper

A thin `clap` wrapper over `DaemonClient`, reading `--daemon-url` (default the local bind) and `--api-key-file`
from flags/env, with subcommands that mirror the client methods: `vmcelld-ctl artifact put|ls|rm`, `vmcelld-ctl
run|create|exec|ls|stats|snapshot|rm`. `run` streams stdout/stderr and propagates the guest exit code exactly as
`vmcell run` does (§11, the exit-code contract). It is a **wrapper only** — no logic beyond argument marshaling
and output formatting lives here (functionality in the library, binary is the wrapper), so its tests are
argument-parsing shape tests.

### 18.8 Entry-point API changes this effort uncovered

Because the daemon **owns** its VM handles (§18.4) rather than detaching them, it needs **no** new vmcell
primitive — the single-process ownership model is reused in-process. What it uncovered is one forced client-side
divergence (paths → upload), the resource-prefix addition (§10.2/§18.4.1, the `vmcell` 0.5.0→0.6.0 bump), and
two clarifications.

1. **Artifact paths become artifact names + an upload API (the forced client divergence).** `vmcell`'s entry
   points take `kernel: PathBuf` / `rootfs: PathBuf` (host paths, §10.2). Over a network boundary a host path on
   the *client* is meaningless to the *daemon*, and a client-supplied *server* path is a traversal hole
   (§18.3.1). So the daemon's VM APIs take artifact **names** resolved against its own store, and the client
   grows an **upload** step. It is contained entirely in the daemon/client layer — `MicroVm`/`VmConfig` are
   unchanged.
2. **The process-global allocators finally have their intended single home (a clarification, not a change).**
   §10.2 says the `VmidAllocator`/`CidAllocator` "are process-global … a single shared instance per test-runner
   process." The daemon *is* that process for the productized path, so it holds one `VmidAllocator::shared()` +
   one `Arc<CidAllocator>` and injects them into every `start`/`restore`. This validates the seam design rather
   than forcing a change.
3. **`MicroVm::agent(&mut self, timeout, clock)` is verbose across a request boundary (records an existing gap,
   does not fix it).** The daemon calls `agent()` on every `exec`/`stats`, re-passing a timeout and a
   `RealClock` each time — precisely the M-ORCH-6 "`agent()` still takes a per-call timeout/clock" cleanup §16
   already lists as deferred. The daemon does not fix it (out of scope), but its call sites are a second
   consumer confirming the cleanup is worth doing.

### 18.9 Open decisions, host validation, and forward work

**Host-facing validation.** The whole subsystem is built KVM-free-testable (the gate list is §14), and its
live path is exercised by an automated integration suite (`crates/vmcelld/tests/integration.rs`, `just
test-daemon`) that **inverts** the runner: nextest wraps the *test binary* with the blessed `vmcell-test-runner`
so the *test* holds the caps and spawns `vmcelld` **directly** (the daemon inherits the ambient caps, §18.2) —
that inversion lets a privileged test plant privileged pre-existing state and inspect host residue. It runs
under a systemd-delegated cgroup scope so `limits_enforced` sees real enforcement, and it asserts on the **data
plane**, never a silent skip. **Validated on the KVM host, 11/11 green** (+ the `vmcell` unit suite via
nextest): `/healthz` + artifact list; `POST /v1/vms` **booted a real Cloud Hypervisor micro-VM** and `exec`
returned `exit 0` with the guest's stdout (`id -un`=root, `uname -r`=6.12.94 — genuine data-plane reads); the
full `create`→`list`→`exec`→`stats`→`destroy`→`list`-empty lifecycle; bearer auth 401/403/200 with the
`WWW-Authenticate` challenge; **`limits_enforced` true under the delegated scope** (and honestly false without —
both `limits_enforced` and `mem_read_ok` track delegation, §7.2); the **start-up sweep** reclaimed a planted
orphan netns; **`destroy` removed the per-VM scratch dir** (the ordered-teardown residue check); **snapshot →
restore-by-name** preserved a guest tmpfs marker across the memory round-trip; **privileged tap networking**
gave the VM a host netns and the guest `eth0` a `10.200.x/30` + default route; the **`vmcelld-ctl` CLI** drove
`run`/`ls`/`artifact ls` against a live daemon; and a **custom `--resource-prefix acme`** named the VM's netns
`acme-net-*`, swept only `acme-*`, and left a `vmcell-*` orphan untouched (§18.4.1). *Still open for the suite:*
the QEMU/Firecracker snapshot tiers (§16 lists these unwired), filtered-egress validation, and a
concurrent-load / density run.

**Forward work (honest edges, in the §16 voice):**

- **The real launcher is complete but KVM-unvalidated in this environment.** `MicroVmLauncher` needs no new
  vmcell primitive — it calls `MicroVm::start`/`agent`/`usage`/`snapshot`/`shutdown` directly. The whole
  registry *logic* is exercised by a recording fake launcher (no KVM); the real launcher's live boot/exec/
  teardown is validated on the KVM host suite above.
- **VMs do not outlive the daemon (a deliberate consequence of owning-and-`Drop`).** A clean `vmcelld` exit
  tears its VMs down; a hard kill leaks them and the next boot's sweep reclaims the residue. If daemon-surviving
  VMs are wanted later, that is the detached variant — explicitly *not* v1.
- **`pause`/`resume` are not in the v1 surface.** The registry + handle support them (the seam has
  `pause`/`resume`), but no HTTP route is mounted yet; adding the two routes + `Paused` state transitions is a
  small follow-up.
- **Single-process privilege (no setup broker yet).** The HTTP surface binds in the **same** process that holds
  the ambient caps. The §17 **setup broker** — a minimal-privilege helper that performs the netns/tap/nft
  bring-up so the network-facing process holds *no* caps — is the recommended hardening and is **forward work**.
  Mitigations shipped now: bind loopback/UDS by default, auth-by-default, the key-file perms check, and per-VMM
  seccomp is orthogonal.
- **Transport is TCP (loopback default); a `XDG_RUNTIME_DIR` Unix-socket bind is the better local default**
  (filesystem-permission access control, no port, honors the "runtime files under `XDG_RUNTIME_DIR`" rule) and
  is a small follow-up — axum serves a UDS listener with no handler changes.
- **Warm-pool / zygote manager.** The zygote primitive exists (§9.4) but there is no pool manager (pre-warm N
  clones, hand one out per request, scale-to-zero) — the natural next daemon feature (`POST /v1/pools`), gated on
  the §9.4 fan-out capability. The registry already owns the handles, so a pool is an ownership + hand-out policy
  on top, not a new primitive.
- **Auth is a single all-scopes key.** No JWT, no per-key scopes, no rotation endpoint in v1 (§18.6). The
  middleware seam is where scopes/JWT attach; `jsonwebtoken` is already in-tree.
- **Artifact GC / quotas.** The store enforces a per-upload size cap but no total-dir quota or
  unreferenced-artifact GC; a leaked upload lingers until `delete`.
- **CLI stub vs. removal (§11).** `vmcell-cli`'s `exec`/`ls`/`rm`/`destroy` stay fail-loud stubs; the daemon now
  genuinely owns those verbs, so removing the CLI stubs (or repointing them at `vmcelld-ctl`) is a
  straightforward follow-up.
- **Writable-scratch-from-artifact disk (daemon path).** Daemon extra disks are read-only because the store is
  immutable (§19.4); a copy-on-attach writable-scratch disk is a small follow-up.

## 19. Extra disks, custom init, and disk-I/O throttling

Three additive `VmConfig` knobs — `extra_disks: Vec<BlockDevice>`, `extra_kernel_args: Vec<String>`, and
`init: Option<PathBuf>` (§10.2) — plus the `BlockDevice`/`DiskIoLimit` types. All are `#[non_exhaustive]`-
compatible and `cargo semver-checks`-clean; they add **no** new crate, **no** new dependency, and **no**
guest-agent change. The one recorded deviation (an `init=` override *replaces* the guest agent as PID 1, so it
forgoes the vsock control plane — honored fail-loud, not a silent hang) is in `implementation-notes.md`.

### 19.1 Extra virtio-blk devices

#### 19.1.1 The shape

`BlockDevice` (§10.2) models one extra disk, mirroring `Share`'s ergonomics: `read_only(image)` /
`read_write(image)` constructors plus `with_io_limit(DiskIoLimit)` (§19.5). `VmConfig::extra_disks` (builder
`.with_extra_disk(BlockDevice)`, default empty) is attached in order. The guest kernel enumerates them as
**`/dev/vdb`, `/dev/vdc`, …** in attachment order; the root disk stays `/dev/vda` (the cmdline hard-codes
`root=/dev/vda`, §8.3). vmcell attaches the **raw** block device only — no partitioning, no filesystem, no
mount. The guest workload owns the device (mount it over exec, `dd` to it, read it raw); **the guest agent does
not auto-mount extra disks and needs no change** (an unknown `/dev/vdX` is invisible to it). This is the
deliberately minimal guest contract: raw exposure is zero new guest code and zero new cmdline token, and
auto-mount is a capability the workload can do itself (if it is ever wanted, model it on
`vmcell_share=`/`parse_share_mounts`, best-effort so a bad token never panics PID 1).

#### 19.1.2 Per-backend wiring — attach *after* the root disk

The root disk must remain device index 0 (`/dev/vda`), so every backend appends extra disks **after** the rootfs
disk:

- **Cloud Hypervisor** (primary): push one `ChDisk { path, readonly, direct: false }` per extra disk onto
  `ch_cfg.disks` after the rootfs arm. CH assigns `/dev/vd{a,b,c}` purely by array order. Every disk is declared
  `image_type=Raw` explicitly (CH v52 auto-detects an unspecified image as raw and disables sector-0 writes —
  see `implementation-notes.md` v22(b); this also pre-empts the same latent bug on the writable `Block` rootfs
  path).
- **QEMU**: emit a split-form `-drive file=…,format=raw,id=extra{i},if=none[,readonly=on],file.locking=off` +
  `-device virtio-blk-pci,drive=extra{i}` pair per extra disk, after the rootfs `-drive`. PCI enumeration order
  gives `vdb, vdc, …`. No fixed device cap (PCI slots).
- **Firecracker**: `PUT /drives/extra{i}` with `is_root_device: false, is_read_only: readonly` after the rootfs
  PUT. Each consumes one virtio-mmio slot; FC's MMIO region is finite, so a very large extra-disk list eventually
  exhausts it — that surfaces fail-loud as the backend's typed API error at `create()`, never a silent drop. (No
  arbitrary numeric cap is invented in the library; the exact FC MMIO budget is a backend-internal constant this
  codebase does not mirror.)

#### 19.1.3 Snapshot composition (§12.1) and restore path-stability

Plain virtio-blk is **not** a vhost-user device, so an extra disk is **snapshot-eligible** — it does not enter
`config_has_vhost_user_device` (§12.1), guarded by a unit test asserting an extra disk does **not** flip the
predicate (a false positive would wrongly disqualify snapshot). A block device's contents live on disk,
*outside* the memory snapshot, so a writable extra disk carries whatever bytes it holds at restore — correct
block-device semantics, not a leak. CH restore reconstructs the full `disks[]` array from the snapshot's
`config.json`, and FC restores devices verbatim, both using the **paths recorded at snapshot time** — so an
extra disk's image path must be **stable across a restore** (not inside the deleted per-VM scratch dir). This is
documented on `VmConfig::extra_disks`; the common case (a caller-owned image at a fixed path) needs no
restore-time rewrite.

#### 19.1.4 Validation and gates

`build()` rejects, each with a negative test: an empty or non-absolute extra-disk image path; a duplicate
extra-disk image (two attachments of one backing file — a rw corruption footgun). Existence is **not** checked
(consistent with rootfs/shares — `build()` never stats paths). Capability: all three backends boot off
virtio-blk, so extra virtio-blk is **universally supported** — no new `VmmCapabilities` flag and no
`require_cap!` gating. Gates: the CH `ChVmConfig` serialization unit test pins that extra disks serialize into
`disks[]` in order with the right `readonly` flag after the root disk; the snapshot-eligibility predicate test
pins extra disks stay eligible; and a KVM host matrix data-plane test (§19.3) attaches a marked image and reads
the marker back **in-guest**.

### 19.2 Custom init + append-only extra kernel args

#### 19.2.1 Append-only extra kernel args — the one predicate

`VmConfig::extra_kernel_args` (builder `.with_kernel_arg(impl Into<String>)`) are appended **last**, after every
token the shared `build_kernel_cmdline` (§8.3) emits, in caller order. "Append-only" is the safety contract: an
extra arg can **add** a boot parameter but can never **clobber** a token vmcell owns. It is enforced by one
predicate — `is_reserved_cmdline_arg(arg)` — used by `build()` (§8.3, §12.20):

- The arg's **key** (text before the first `=`, or the whole bare token) must not be in `RESERVED_CMDLINE_KEYS`
  (`console`, `loglevel`, `root`, `rootfstype`, `rootflags`, `ro`, `panic`, `init`, `ip`, `kvm-intel.nested`,
  `kvm-amd.nested`, `cryptomgr.notests`, `raid`, `random.trust_cpu`, `random.trust_bootloader`, `noxsave`),
  **and** must not start with `vmcell_` (the guest agent *trusts* `vmcell_share=`/`vmcell_accept_poll_ms=`/
  `vmcell_rebind_idle_ms=`, so a caller must not be able to spoof one).
- The arg must be a single cmdline token: non-empty, no whitespace, no control characters (a space would forge a
  second token — the cmdline-injection guard; quoted values with embedded spaces are out of scope this pass).

The **one-law gate** is a unit test that builds a cmdline exercising every emitted token (block rootfs +
networking + a share + nested) and asserts `is_reserved_cmdline_arg` is `true` for **every** token — so the
reserved set can never silently fall out of sync with what the builder emits (add a new builder token without
reserving its key → red). This is the same "one law, one predicate, pinned by a test" discipline as
`config_has_vhost_user_device` and `mac_math`.

#### 19.2.2 The `init=` override — a genuine PID-1 replacement, honored honestly

`VmConfig::init` (builder `.init(impl Into<PathBuf>)`), when `Some`, emits `init=<custom>` in place of the fixed
`init=/usr/sbin/vmcell-guest-agent` — the **only** place either token is constructed (one law, one predicate; a
backend never string-builds `init=`). `build()` validates the path: absolute, valid UTF-8, no whitespace/control
characters (a single safe cmdline token).

**A custom init replaces the vmcell guest agent as PID 1, so it forgoes the vsock control plane** — no `Ready`
handshake, no `exec`, no post-restore resync (all live in the agent, which is no longer running). vmcell makes
that consequence loud, never silent (§12.2):

- **`MicroVm::agent()` fails loud** with a typed `Error::Agent` naming the custom-init cause, instead of hanging
  for the full connect timeout on a listener that will never answer.
- **`MicroVm::start()` skips the QEMU control-plane health probe** (`verify_control_plane`) when `init` is
  overridden — that probe exists to confirm the *agent's* vsock transport, and there is no agent to confirm;
  without the skip a custom-init QEMU VM would re-spawn to exhaustion and fail to start. (CH/FC probes are
  already no-ops.) `start()` still boots and returns the handle — the caller drives/observes the VM out-of-band:
  the serial log (the custom init's `console=ttyS0` output is captured to `serial.log`), a read-write extra
  virtio-blk device (§19.1) or virtio-fs share, or networking.
- **`build()` rejects `snapshotting == true` with a custom `init`** — the mandatory post-restore resync (clock,
  entropy reseed, MAC/IP rotation, §12.4) runs *through the agent*, which a custom init replaces; a restored
  custom-init clone would be stranded on frozen identity with no way to fix it from inside (silently dead egress
  / correlated RNG), exactly the trap §12.4 forbids. Fail-loud at construction.

A caller who wants a program to run at boot *without* giving up the control plane should keep the default init
and `exec` the program over vsock — that is what `exec` is for; the `init=` override is the escape hatch for
booting a genuinely different PID 1 (the fidelity / systems-testing domain), which necessarily means a different
(or no) control plane. A custom init on the read-only erofs root also has no writable `/` (the agent's tmpfs
overlay setup no longer runs), so a custom-init VM typically pairs with a writable rootfs (`RootfsSource::Block`)
or a writable extra disk — a caller responsibility, documented on the field.

#### 19.2.3 Gates

`build()` negative tests (one per case): a reserved-key or `vmcell_`-prefixed extra arg; a whitespace /
control-character extra arg or init path; a non-absolute init path; `snapshotting` + custom init. A golden
`build_kernel_cmdline` test asserts the init override replaces the default (exactly one `init=` token,
`root=`/`vmcell_vmid=` intact) and that extra args appear appended after every reserved token; the existing "all
backends have loglevel" test continues to pin the default init. A KVM host test (§19.3) boots a custom init and
asserts the data plane (the kernel ran the overridden init) plus that `agent()` fails loud.

### 19.3 Host-facing validation

Both features are validated on the KVM host per §12/§14 rule 5. Neither changes the guest agent or the rootfs,
so the existing `rootfs.erofs`/`vmlinux` are reused unchanged. `#[ignore]`-gated tests, run via `just
test-privileged` under a systemd-delegated scope through the blessed `vmcell-test-runner`:

- **`tests/extra_block.rs`** (`vmm_matrix_test!`, CH/FC/QEMU): create a small marked raw image, attach it
  read-only, boot, and assert the marker read back **in-guest** off `/dev/vdb` (a data-plane read, not a proxy
  signal). A read-write variant `dd`s a marker in and reads it back. Self-cleaning (the temp image is removed on
  teardown — no sudo, per the host-hygiene preference).
- **`tests/extra_block.rs :: extra_block_survives_snapshot`** (`vmm_matrix_test!` + `require_cap!
  (snapshot_restore)`, CH/FC): the "composes with snapshot" proof — write a marker to a writable extra disk,
  snapshot, restore into a fresh VM (fresh vmid), and read the marker back off `/dev/vdb`.
- **`tests/custom_init.rs`** (CH primary): boot with an `init=` override at `Verbose` verbosity and assert the
  serial log shows the kernel ran the overridden init; assert `agent()` returns the fail-loud custom-init error.
  Snapshot + custom init is rejected at `build()` (KVM-free).

**Validated on this KVM host, all green** (via `just test-privileged` filtered to these tests, under a
systemd-delegated scope through the blessed runner): `extra_block` on **CH + Firecracker + QEMU** (two extra
disks attach after the root — `/dev/vdb` read-only marker read back in-guest, `/dev/vdc` read-write marker
round-tripped); `extra_block_survives_snapshot` on **CH + Firecracker** (the extra-disk marker survives a real
snapshot→restore into a fresh vmid — the headline claim, on the data plane; QEMU skips, no snapshot);
`custom_init` on **CH** (`init=/bin/sh` at Verbose — the kernel serial log shows `Run /bin/sh as init process`,
and `agent()` fails loud). One CH-specific fix landed en route: CH v52 auto-detects an unspecified image as raw
and disables sector-0 writes, so every disk is now declared `image_type=Raw` explicitly (also pre-empting the
same latent bug on the writable `Block` rootfs path — see `implementation-notes.md` v22(b)).

### 19.4 CLI and daemon exposure

- **CLI (`vmcell-cli`)** gains additive flags on `run`/`create`: `--disk <PATH>` (repeatable, read-only),
  `--disk-rw <PATH>` (repeatable, read-write), `--append <ARG>` (repeatable) — thin wrappers over the new builder
  methods at the single `ephemeral_vm` construction site (§11). A custom `init=` is **not** a CLI flag: every CLI
  verb brings the agent up (`run` execs, `create` confirms agent-ready), which a custom init precludes — a
  custom-init VM is a library-only escape hatch.
- **Daemon (`vmcell-daemon`).** `CreateVmRequest` gains `#[serde(default)]` `extra_disks: Vec<ExtraDiskSpec>` and
  `extra_kernel_args: Vec<String>`, threaded `CreateVmRequest → LaunchSpec → VmConfig` (the registry resolves +
  the launcher builds). An `ExtraDiskSpec` is an artifact **name** (resolved through `resolve_artifact_path` like
  `kernel`/`rootfs`, §18.3.1) plus an optional `io_limit` (§19.5). Two deliberate divergences from the library,
  both forced by the daemon's model:
  - **Extra disks are read-only.** The store is create-only/immutable (§18.3.2); a *writable* disk backed by a
    shared store artifact would let one VM mutate an artifact another VM reads. A writable-scratch-from-artifact
    (copy-on-attach) is a small follow-up (§18.9).
  - **No `init=` override.** The daemon *owns* the VM through the vsock control plane (it brings the agent up to
    mark `Ready`, and serves `exec`/`stats`), which a custom init drops — so it is not exposed; use the library
    for a custom-init VM.
  A live VM **pins** its extra-disk artifacts (the delete-in-use guard, §18.3.2, now checks extra disks as well
  as kernel/rootfs). A bad knob (a reserved kernel arg, a `0` io_limit) surfaces as the library's
  `Error::Config`, mapped to **`BadRequest` (400)** rather than a misleading 500 (a config-validation failure is
  a client error). The OpenAPI document is unchanged — it describes paths + auth, not request-body schemas, so
  the parity gate does not enumerate these additive fields (§18.5.2).

### 19.5 Disk-I/O throttling (the `BlockDevice` seam)

`BlockDevice::io_limit: Option<DiskIoLimit>` (builder `.with_io_limit(DiskIoLimit)`) is the disk half of §17's
*"extra virtio-blk devices + disk-I/O fault injection."* `DiskIoLimit` is a `bandwidth_bytes_per_sec` and/or
`iops` cap — the **portable** form of the fault (a slow/pressured disk, to test a workload's
timeout/retry/backpressure), because every backend has a native per-disk rate limiter, including the **primary**
CH (unlike error-injection, which is QEMU-`blkdebug`-only and stays forward work, §17). `build()` rejects an
`io_limit` that limits nothing, or any `0` cap (a `0` bucket never refills → wedged I/O).

Each backend expresses the cap with its native limiter, and the CH and Firecracker token buckets share **one**
conversion (`IO_LIMIT_REFILL_TIME_MS`, a bucket of `size = rate` refilled every 1000 ms = `rate`/s) so they can
never encode the same `DiskIoLimit` as different rates (one law, one predicate):

- **Cloud Hypervisor** — `ChDisk.rate_limiter_config { bandwidth, ops }` token buckets.
- **Firecracker** — the drive's `rate_limiter { bandwidth, ops }` token buckets (identical shape).
- **QEMU** — `-drive …,throttling.bps-total=<B>,throttling.iops-total=<N>` (the per-second rate directly).

It composes with snapshotting like any plain virtio-blk (§19.1.3) and is exposed over the daemon (§19.4). Gates:
a unit test pins the CH `rate_limiter_config` bucket (`size = rate`, `refill_time = 1000`); `build()` rejection
tests; and a self-calibrating KVM data-plane test (`extra_block_io_throttle`) reads an un-throttled disk and a
1 MiB/s-throttled disk of equal size in one VM and asserts the throttled read is both slow in absolute terms and
far slower than the baseline. **Validated on this KVM host, all green:** `extra_block_io_throttle` on **CH + FC +
QEMU** (the 1 MiB/s cap floors a 4 MiB read at ~3 s on every backend); the daemon
`extra_disk_over_api_data_plane_and_delete_in_use` (`just test-daemon`) drove the full HTTP path — upload a
marked image, `POST /v1/vms` with `extra_disks`, read the marker off `/dev/vdb` in-guest, and confirm the disk
artifact is pinned (delete → **409 InUse**) until the VM is destroyed.

---

## Appendices — how the design was reached

The body describes the system as it stands. These appendices record the path: the implementation passes,
the load-bearing reversals, the dependency experiments, the contested facts, and the prior art. Nothing here
is required to *use* the system — it is the evidence behind the non-obvious choices in Parts I–III.

**Finding-ID convention.** The body cites short finding anchors: `EXP-*` / `OPP-*` resolve to
`docs/45-claude-perf-investigation.md`; `H-*` / `M-*` / `C-*` / `N-*` / `L-*` to `docs/46-claude-code-review.md`;
and the older `ORCH-*` / `AGENT-*` / `M-RESTORE-*` ids to the review rubric and notes under `docs/` and
`docs/historical/`.

## Appendix A. Implementation history and the load-bearing reversals

The design accreted across six **implementation** passes (v8 → v13), then design-only revisions (v14–v17)
that added specification and corrected recorded conclusions without a new build, and then a **2026-07
implementation-and-review wave** folded into v18. **The architecture never changed** — every finding was a
localized fix, a vindicated diagnosis, or a measurement, not a redesign. The reversals below are the part a
reader needs to trust the current state; each is *prior belief → finding → where it landed*.

**The passes.** Pass 3 (v10) was the big build: the Firecracker backend, the capability runner, both rootfs
sources, unprivileged cgroup delegation, and the full integration suite — and it independently found
`VmmCapabilities` *missing and necessary*, confirming the capability-query contract was load-bearing. Pass
4 (v11) unblocked Firecracker snapshot via MMIO and removed the netlink path from PID 1. Pass 5 (v12) filled
the warm-restore benchmark gap and fixed the FPU panic at the CPU layer. Pass 6 (v13) ran the full §15 suite
on the committed pin (several hypotheses *inverted*), enforced the snapshot-eligibility law in code at three
boundaries, drove snapshot/restore to work end-to-end on CH, added the guest-tools helper, content-addressed
the cache keys, and bumped to the 6.12.94 pin. The v16/v17 revisions re-ran the recorded experiments *live*
and corrected several conclusions (below). The **2026-07 wave** folded into v18 is three linked efforts: a
performance-recovery pass that turned the latency levers into tunable knobs plus a native in-agent resync
(`docs/44`); the `docs/45` EXP-A…E investigation that carried the matrix to its canonical state, **unlocked
Firecracker warm restore**, and root-caused the AGENT-2 reaper race; and the review-46 fix pass (the
loopback OOB write, the NAT backpressure invariant, the resync client-eviction, and the rest — all landed
as body behavior, not open items).

**Reversal 1 — Firecracker snapshot: blocked under PCI, unblocked via MMIO, then PCI un-blocked.** The guest
kernel was virtio-PCI-only, so FC launched with `--enable-pci` and could not snapshot
(`MicroVMStoppedWithError`). The design's fix — build the kernel with `CONFIG_VIRTIO_MMIO=y` and run FC in
MMIO off the *same* `vmlinux` — was validated in v11. *Re-tested v16 (FC v1.16.0):* `--enable-pci` +
snapshot create *and* restore both succeed — the "PCI blocks snapshot" block was real only in FC's
~1.10–1.12 experimental-PCI era and is now version-stale. FC still defaults to MMIO, but for maturity + the
shared `vmlinux`, not because PCI can't snapshot.

**Reversal 2 — `ip=` and the netlink path the agent was designed not to have.** An implementer found `eth0`
unconfigured and added manual `ip link/addr/route` to PID 1, blaming "no initramfs to parse `ip=`." The real
cause was the `net-unprivileged` feature compiled out, so no virtio-net device was presented. With the
device present and `CONFIG_IP_PNP=y` built in, `ip=` configures `eth0` agent-free; the manual bring-up was
deleted. The zero-netlink invariant (§12.3) survived because the design refused the wrong attribution.

**Reversal 3 — the FPU/XSAVE restore panic, and the rejected `bookworm` downgrade.** FC restore can panic in
`restore_fpregs_from_fpstate` under modern glibc. An implementer's stopgap was to pin the rootfs to
`bookworm`; the design rejected it (it is not a `trixie` bug — any modern glibc triggers it; the durable fix
is in CPUID, not the OS version) and applied a **T2 CPU template** + `noxsave` fallback on `trixie`.
*Re-tested v16:* the fix stands with refinements — `noxsave` is now gated to `template.is_none()` (it was
applied unconditionally, needlessly disabling AVX2); FC *rejects* the T2 template on Lunar Lake; and the
panic didn't reproduce for reachable AVX2/YMM state on FC v1.16.0 (§3.2).

**Reversal 4 — REDIRECT → TPROXY: right choice, wrong stated reason.** The design rejected iptables REDIRECT
as "cannot preserve the original destination"; in fact REDIRECT recovers it via `getsockopt(SO_ORIGINAL_DST)`.
TPROXY was still the right destination — for UDP/QUIC handling and source preservation — reached once those
edges became concrete.

**Reversal 5 — QEMU cannot snapshot over the unprivileged vsock plane (the symmetric mirror).** QEMU's
unprivileged vsock is an external `vhost-device-vsock` daemon — a stateless vhost-user backend that can't
migrate — so it is snapshot-ineligible by the same law (§12.1) that blocks CH's virtio-fs data shares. This
is the exact mirror of reversal 1 (FC blocked by a *transport mode*; QEMU by a *device*). *Recovery path
(validated v16):* a privileged in-kernel-`vhost-vsock` QEMU config has no migration blocker and
migrate→restore was verified live — a validated capability, pending backend wiring (§3.3).

**Reversal 6 — the benchmark pass inverted three research-era hypotheses.** The OCI slim base is ~34%
*smaller* than mmdebstrap-minbase (official `dpkg path-exclude` strips locale/doc/man); static-`musl` is
~6.2% *larger* than glibc-dynamic; and an interleaved same-session kernel sweep showed warm restore within
~2%, so the earlier "2× slower" was cross-session host-load noise. The lesson is §13's discipline.

**Reversal 7 — QEMU `microvm` and the vhost fork, re-tested live (v16).** `microvm` stays rejected, but not
for the recorded reason: its `virtio-net-device` header story was unsupported (header size is
feature-negotiated, not transport-governed), and the real blocker is that QEMU 10.2.1's `microvm` can't boot
these PVH kernels to userspace (an early-boot `#DE`, reproduced ~24 ways including `-M microvm,pcie=on`). And
the vendored `vhost`/`vhost-user-backend` fork was upgraded from "lowest-confidence" to **confirmed by a live
message trace** (QEMU sends `SET_VRING_ENABLE` before `SET_FEATURES`; CH sends features first). The `passt`
rejection reason was also corrected: not passt's seccomp (it *allows* `accept4`, surviving with `EACCES`,
not a `SIGSYS` kill) but the host's stale AppArmor af_unix rule — not CH-specific, and avoidable — so smoltcp
stays for its own merits, not because passt is fundamentally incompatible.

**Reversal 8 — the Firecracker warm-restore block was never the guest re-attach.** *Prior belief (EXP-E
entry E2):* the first post-restore `exec` dropped because the guest's vsock listener failed to re-attach
after FC re-created the device, so the fix had to live in the guest agent. *Finding:* the guest side was
already correct — the block was **four causes** stacked, three host-side plus one in the guest agent.
`MicroVm::snapshot()` kept a **cached `AgentClient`** across FC's connection-severing pause/snapshot/resume
(CH keeps connections; FC drops them), so the next call spoke into a dead socket; `restore()` re-bound the
**baked host vsock path verbatim** and `ENOENT`'d when its parent dir was gone; `create()` attached **no
entropy device**, so any reseed after restore silently failed; and — the one guest-side cause — the
**AGENT-2 pre-spawn reaper-epoch race** in PID 1 turned an instant post-restore child into a 10 s "timeout"
that read as an environmental flake. *Where it landed:* the *generic* idle-window re-bind already in the
agent needed no FC-specific change; the three host-side fixes were cached-client invalidation (§3.2/§9.2),
parent-dir resurrection under the `reject_live_baked_vsock` guard (§3.2/§16), and the `PUT /entropy` attach
(§3.2/§12.4), plus the epoch-based reaper in the guest agent (§12.6) — validated by the now-passing
`snapshot_restore::firecracker` leg (§14).

**Synthesis.** Every snapshot finding collapses into §12.1: a VM is snapshot-eligible only if no vhost-user
device is attached (and, historically, FC only under MMIO — v16 relaxed that). Any external vhost-user
backend is a separate stateless process the VMM cannot migrate.

## Appendix B. Substitution experiments

Several external tools were candidates for absorption into the orchestrator as crates. Each ran as an
independent experiment against the green baseline, one at a time, behind its own Cargo feature, with the
baseline retained as fallback; graduate only on the success criterion, else revert.

| # | Substitution | Status | Outcome |
|---|---|---|---|
| 1 | virtiofsd → `fuse-backend-rs` | **Underway** | Scaffolded behind `experiment-fuse`; virtiofsd remains the fallback. Blocked on read-only enforcement — a read-only share on the in-process backend now **fails loud** (§5.2), not silent write-through. |
| 2 | `nft` binary → pure-Rust nftables | **Rejected** | No permissive crate covers TPROXY (`rustables` GPL-3.0; the pure-Rust crates are read-only or don't cover the expressions); the `nft` binary is retained. |
| 3 | `mkfs.erofs` → `am-fs-erofs` | **Graduated** | In-memory tar→erofs, runs unprivileged (no device-node creation). The **only** wired erofs writer — the design's `mkfs.erofs` shell fallback was never implemented (M-ART-11, §16), so a missing input is a hard error, not a fallback. Output is byte-deterministic (fixed mtimes, ordered emission). |
| 4 | rootfs source: OCI pull (default) + `mmdebstrap`-in-VM | **Graduated (OCI); mmdebstrap deferred** | OCI pull is the default host-native source and the only one the CLI `build` verb wires; the `mmdebstrap`-in-a-builder-micro-VM source is library-present and validated but not yet wired end-to-end (§8.2, §16). |
| 5 | `passt` → in-process `smoltcp` NAT | **Graduated** | in-process, no external dep, no LSM/seccomp entanglement — better regardless. The recorded "passt CH-incompatible (seccomp)" reason was corrected to the host AppArmor af_unix finding (Appendix A, reversal 7). Default for unprivileged. |

Two ideas were **not** experiments because they were already the design and were independently
re-confirmed: keeping CH/Firecracker as supervised subprocesses driven by typed REST clients (rather than
embedding a VMM), and `cgroups-rs` for limit/metric reads.

## Appendix C. Contested facts to re-verify per pin

These came from mid-2026 research inputs and are re-run whenever a pin bumps.

- **virtio-fs DAX is UNAVAILABLE in Cloud Hypervisor** (deprecated in v24, gone in v52). Host page-cache
  sharing for read-only data is recovered by serving the RO base over erofs/virtio-blk, not DAX.
- **Snapshot/restore and virtio-fs do not compose** — the §12.1 law, now enforced at `config::build()`, so
  the empirical "can a data share re-attach to a snapshotted VM?" question is unreachable through the public
  API.
- **userfaultfd lazy restore in CH** (`prefault=on|off`) — confirmed and plumbed via `RestoreMode` (lazy
  ≈1.5× faster than eager). Sparse snapshot (`SEEK_HOLE`) remains the un-taken pool-density lever. FC-side
  UFFD is a separate open gap (`lazy_restore: false`, M-VMM-1, §16).
- **Boot-time vendor numbers are workload-dependent** — FC's "≈125 ms to init" / "≤5 MiB overhead" are real
  AWS figures measured with the console disabled; the real stack is ~79–89% guest-boot wait. Only *relative*
  invariants travel across substrates.
- **Nested-virt enablement.** There is no `--cpu nested=on` CH flag: nesting is enabled on the host KVM
  module (`kvm-intel nested=1`), the guest kernel must have KVM built in, and CH passes `kvm-intel.nested=1`
  on the guest cmdline. On AMD, once an L1 has started an L2, that L1 should not be migrated/snapshotted.
- **Do not depend on `herolib-virt`** (a single-author crate that merely shells out to the CH binary); use a
  thin hand-written REST client.
- **Security hygiene.** CVE-2026-45782 (a virtio-block use-after-free) is fixed in CH ≥ v51.2/v52.0 — the
  pinned v52.0.0 carries it. Pin one exact CH+virtiofsd build per snapshot pool (no cross-version snapshot
  compatibility guarantee); the `SnapshotStage` cache key now folds the pinned `cloud_hypervisor` identity
  (M-ART-7), so a CH bump invalidates cached snapshots automatically at build time.

## Appendix D. Prior art

- **`cocoonstack/cocoon`** ★ — a lightweight micro-VM engine on Cloud Hypervisor with instant snapshot+clone
  via reflink, COW overlays, balloon/free-page-reporting, and Firecracker as an alternate. Documents the
  exact vhost-user-snapshot constraint that becomes §12.1. Closest reference to the snapshot/density path.
- **`tinylabscom/mvm`** ★ — a Rust CLI with a multi-VMM backend abstraction and a vsock-only guest agent
  ("NO SSH ever"). A near-reference for the `Vmm` trait, the agent protocol, and the PID-1 contract.
- **`microvm.nix` agent-sandbox write-up** ★ — the egress topology to copy: CH + nftables forward-chain
  logging + read-only erofs rootfs.
- **`agentkernel`, `vmexec`** — ephemeral-VM-per-command patterns on the rust-vmm stack.
- **`smoltcp` + rust-vmm `vhost-user-backend`** — the building blocks of the adopted unprivileged NAT.
- **Kata `agent-ctl` / `kata-ctl`** — the agent-over-vsock blueprint.

## Appendix E. Build roadmap

The order the system was built in, retained as the sequencing rationale and the test-placement map. Each
milestone landed a working, testable slice with at least one fine-grained integration test.

| # | Milestone | What lands | Integration test |
|---|---|---|---|
| M0 | Skeleton | workspace, `error`/`config`, clippy+fmt+deny in CI, `FakeVmm` | unit: builder defaults, codec, `/30` math, handshake FSM |
| M1 | First boot | artifact pipeline v0 (minimal `vmlinux` + erofs via OCI); CH subprocess + REST create/boot; serial→log; ordered `Drop` | `boot.rs`, `lifecycle.rs` |
| M2 | vsock control | `vmcell-protocol`; `vmcell-guest-agent` as PID 1; `AgentClient` with retry/handshake + serial fast-fail | `exec_vsock.rs` |
| M3 | Shared dirs | `fs` (virtiofsd per share). **CH/QEMU only** | `shares_ro_rw.rs` |
| M4 | Host endpoints + net (privileged) | `net::tap` (netns+tap+`/30`) | `host_endpoint.rs` |
| M5 | Transparent proxy | `proxy` (MITM CA, log/filter, doubles); TPROXY steering | `egress_proxy.rs` |
| M6 | Monitoring + limits | `metrics` (cgroup slice, caps, peak/avg) | `metrics_limits.rs` |
| M7 | Nested virt | guest kernel with KVM built in. **CH/QEMU only** | `nested_virt.rs` |
| M8 | Snapshot + density | warm-snapshot stage; restore via `--restore`→`resume`; reconnect + identity/entropy/clock resync; KSM/balloon. **CH + FC validated** (FC single-lineage host paths) | `snapshot_restore.rs` |
| M9 | Unprivileged mode | `net::userspace` (smoltcp + vhost-user-net NAT); systemd cgroup delegation | unprivileged `host_endpoint.rs`/`egress_proxy.rs` |

**Sequencing rationale.** M1 derisks the hardest plumbing (subprocess + REST + boot + teardown) and ships
the complete kernel fragment up front so the vsock/virtio-fs symbol gaps don't ambush M2/M3. M2 establishes
the control channel everything asserts through. M3–M5 add the three I/O surfaces in increasing complexity.
M6 makes runs measurable. M7–M8 are the most environment-sensitive (nesting, snapshot). M9 adds unprivileged
once the privileged path is solid. The backend-gated milestones are inherent, not accidental: M3 and M7 are
CH/QEMU-only (Firecracker hosts neither); M8 landed on CH and, as of the 2026-07 wave, Firecracker; QEMU's
privileged tier stays unwired.

