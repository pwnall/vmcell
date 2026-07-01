# vmcell — Design Document (v17)

**vmcell** is a micro-VM runner for isolated environments, driven entirely from one Rust library. On a
Linux/x86-64 host with KVM it lets you *create a fresh micro-VM, run a command in it over a typed
control channel, give it shared directories / host-reachable endpoints / logged-and-filtered network
egress, observe and cap its resource use, optionally snapshot-and-restore it for speed, and tear it
down with no residue*. Strip away the shares, endpoints, and proxy and what remains — create →
restore-or-cold-boot → `exec` over vsock → observe/cap → ordered teardown — is a self-contained,
workload-agnostic execution primitive.

The project's origin and still most demanding consumer is end-to-end integration testing of the **Imp**
agentic harness (the project was formerly "Imp Testing"). But the same primitive serves three co-equal
domains: **low-level systems testing** (a real kernel, full syscall surface, and nested virt, per
test), **agentic execution** (untrusted AI-agent tool calls in disposable, observable, fast-to-restore
sandboxes), and **generic serverless / ephemeral functions** (snapshot a warmed runtime once, restore
per invocation in tens of milliseconds, discard). Throughout this document, **"Imp"** refers to that
origin *harness* — a consumer of the runner, never to the runner itself.

---

**How to read this document.** It is written for someone learning the project, in five parts:

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
- **Appendices** (A–E): how the design was reached — the implementation-pass history, the load-bearing
  reversals, the dependency experiments, contested facts to re-verify per pin, prior art, and the build
  order. Nothing in the appendices is required to *use* the system; it is the evidence behind the
  non-obvious choices in Parts I–III.

The body describes the system **as it is built today**, in the present tense. Facts that were once
contested or arrived at over several implementation passes are stated in their settled form. A
non-obvious choice (why erofs and not ext4; why the snapshot tier excludes unprivileged networking; why
Firecracker snapshot is currently gated off) is explained inline where the component is described, and
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
**`MicroVm`** — is a thin owner over the primitive. Integration testing for Imp drives every capability
and so remains the most demanding consumer, but keeping the primitive general is a hard design
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
        │ restore (ms) or cold-boot                          ▲ vsock: Ready/Exec/IO/Exit/PutFile
        ▼                                                     │
  ┌──────────────────────── micro-VM (per test, ephemeral) ───────────────────────┐
  │ kernel: direct boot, virtio + vsock + virtio-fs + (opt) KVM built-in, no initramfs │
  │ PID 1: vmcell-guest-agent  (mounts /proc /sys + shares, tmpfs overlay, installs CA,│
  │        reaps children, serves the vsock protocol)                              │
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
   `resume`, never `create`/`boot`) or **cold-boot**. On restore, refresh identity (vsock CID, MAC),
   reseed entropy, and resync the guest clock (§9.2).
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
| **Primary VMM** | **Cloud Hypervisor (CH)**, run as a subprocess over its REST `--api-socket`. Rust/rust-vmm, Apache-2.0/BSD. Feature-complete: the default, and today the **only validated snapshot backend**. |
| **Second VMM** | **Firecracker**, behind the same trait, for the density/snapshot tier. Runs in **MMIO mode**. Fastest *measured* warm restore (≈128 ms), but its snapshot/restore is **currently gated off** (`capabilities().snapshot_restore == false`) pending an end-to-end post-restore-reconnect fix (§3.2, §9.2). No virtio-fs, no vhost-user-net, no nested virt. |
| **Fallback VMM** | **QEMU `q35`** (not `microvm`) — the documented escape hatch and most-proven nester; full feature set. Snapshot is ineligible over its unprivileged external-vsock path; a privileged in-kernel-`vhost-vsock` config is *validated but not yet wired* (§3.3). C/GPL **binary**, used as an external tool, never linked. |
| **Control plane** | **virtio-vsock + a Rust guest agent as PID 1**, framed `postcard` protocol (`Ready`/`Exec`/`Stdout`/`Stderr`/`Exit`/`PutFile`). Host connects with a retry/handshake loop and reconnects after restore. Serial console → a per-VM log for panic capture. SSH is a human-only debug fallback. |
| **Root filesystem** | **erofs read-only image over `virtio-blk`**, shared by all concurrent VMs with **no per-VM copy**; per-VM writes go to a **tmpfs `overlayfs` upper**. erofs has no journal → no recovery writes, no concurrent-mount corruption, and it composes with snapshot (a plain block device, not vhost-user). |
| **Shared dirs** | **virtio-fs, one `virtiofsd` per share**, `--readonly` for read-only shares, `--sandbox namespace`. Caller-defined mount tags. |
| **Host endpoints** | Per-VM **network namespace + tap + `/30`** (privileged) *or* an **in-process smoltcp + vhost-user-net NAT** (unprivileged). Host servers reachable from the guest, not exposed beyond it. |
| **Egress proxy** | A **Rust MITM proxy** (`hudsucker` = `hyper`+`rustls`+`rcgen`) with logging, filtering, and pluggable test doubles; CA baked into the guest trust store. Steered in via **nft `TPROXY`** (privileged) or **L4 interception in the smoltcp NAT** (unprivileged). |
| **Monitoring / limits** | One **cgroup v2 slice per VM**; read `memory.peak`/`memory.current`/`cpu.stat`/`io.stat`; enforce `memory.max`/`cpu.max`/`pids.max`/`io.max`. A *requested* limit that can't be enforced **fails loud** (§7.2) — never a silent no-op. |
| **Operating modes** | **Two, named and tested separately** (§6.4): **unprivileged** (KVM-group access, no `CAP_*`; smoltcp NAT) and **privileged** (the §14 capability runner grants `CAP_NET_ADMIN`+`CAP_SYS_ADMIN`+`CAP_DAC_OVERRIDE`; netns+tap). A mode's prerequisites are probed up front and enforced fail-loud. |
| **Guest OS** | Minimal **Debian Trixie (13, kernel 6.12 LTS)**, from one of two sources feeding one erofs packer: **OCI pull** by digest (default, in-Rust, no Docker) or **`mmdebstrap` inside a builder micro-VM** (full apt signing chain). |
| **Guest kernel** | **Direct kernel boot** of a custom-minimal `vmlinux` from Debian kernel source with an explicit config fragment (§8.3) — virtio (PCI + MMIO) + vsock + virtio-fs + erofs/overlay + optional KVM, all built in, no initramfs. No project-specific patches. |
| **Speed lever** | **Warm snapshot + restore** off the erofs rootfs with a tmpfs overlay per test; cold-boot opt-in. Measured **≈3.7× faster than cold boot on CH** (§15). |
| **Guest tooling** | A tiny in-Rust multicall **`vmcell-guest-tools`** (`ip`/`curl`/`kvm-ok`, doing the *real* operations) **baked into the erofs**, supplying the few tools the minimal Debian base omits (§5.3). |
| **Build layout** | A **cargo workspace** (2024 edition): the `vmcell` library + its CLI, plus four lean member crates — `vmcell-protocol`, `vmcell-guest-agent`, `vmcell-test-runner`, `vmcell-guest-tools`. Leanness of the privileged-window/guest binaries is a *structural per-member* property (§10.1). |
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
    pub snapshot_restore: bool,          // CH ✓ · Firecracker ✗ (gated off, §3.2) · QEMU ✗
    pub lazy_restore: bool,              // demand-paged restore. CH ✓ (memory_restore_mode) · FC ✗ · QEMU ✗
    pub virtio_fs_shares: bool,          // CH, QEMU ✓ · Firecracker ✗ (block-only)
    pub unprivileged_vhost_user_net: bool, // smoltcp NAT via vhost-user-net: CH, QEMU ✓ · Firecracker ✗
    pub nested_virt: bool,               // expose /dev/kvm to the guest: CH, QEMU ✓ · Firecracker ✗
}

pub trait VmInstance: Send {
    async fn boot(&mut self) -> Result<()>;             // cold start (after create)
    async fn request_shutdown(&mut self) -> Result<()>; // graceful (ACPI), then SIGKILL after a bounded grace
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

**Cloud Hypervisor (CH) — the default and the working snapshot tier.** Feature-complete: snapshot/restore
via `--restore`+`resume`, virtio-fs shares, vhost-user-net (so the unprivileged NAT), and nested virt.
Driven over a hand-written thin REST client (`hyper`/`hyperlocal` over the Unix `--api-socket`). Cold
boot ≈635 ms; warm restore ≈169 ms (§15). Two lifecycle paths: cold = `vm.create` → `vm.boot`; warm =
launch with `--restore` → `vm.resume` (**never** `create`/`boot` — CH returns `500 "VM is already
created"`). `snapshot` must `vm.pause` first, then snapshot, then `vm.resume` (or stay paused if the VM
is about to be killed). One restore subtlety worth flagging here: CH `--restore` rebuilds every device
from the snapshot's `config.json`, which records the *original* instance's now-defunct temp-dir paths for
the **vsock socket** and **serial file**, and CH exposes no restore-time override — so the spawn step
must rewrite those two paths to this restore's freshly-minted paths *before* launching (§9.2). CH is
supervised as an external release binary; only its REST *client* is a crate.

**Firecracker — the intended density/snapshot tier (snapshot currently gated off).** Its draw is density
(low memory overhead) plus snapshot, and it has the **fastest measured warm restore** (≈128 ms). It is
implemented like CH (a hand-written `hyper`-over-Unix client, not `firecracker-rs-sdk`). Its device model
is deliberately minimal — virtio-{net,block,vsock,balloon,rng} — so it **cannot do virtio-fs,
vhost-user-net, or nested virt**, and `capabilities()` reports those `false`. Two Firecracker-specific
facts:

- **It runs in native MMIO mode** (no `--enable-pci`). The guest kernel ships both virtio-pci (for CH)
  and virtio-mmio (§8.3), so one `vmlinux` serves CH over PCI and Firecracker over MMIO. MMIO is the
  default for backend maturity and the shared `vmlinux`, **not** because PCI blocks snapshot — FC
  **v1.16.0** supports `--enable-pci` + snapshot (Appendix A, reversal 1).
- **Snapshot/restore is gated off today.** FC reports `snapshot_restore: false` and `lazy_restore: false`
  (guarded by a unit test that keeps them false). The MMIO snapshot *creates* fine, but the warm
  **restore** does not survive end-to-end: the first post-restore `exec` drops with `Agent("Connection
  dropped during exec")` — the guest-side vsock listener does not re-attach cleanly after FC re-creates
  the device. Fixing that (the UFFD — userfaultfd — /vsock-rebind work) is forward work (§16); until then FC is an honest
  `false`, not an advertised-but-broken flag. The ≈128 ms figure in §15 measures restore-to-handshake,
  which is why FC is still the *intended* fast-restore tier — but CH is the only tier a test can rely on
  now.
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
requires a `[patch.crates-io]` fork of `vhost-user-backend`+`vhost` to relax a `PROTOCOL_FEATURES`
check (confirmed by a live message trace — §10.4). Cold boot ≈1405 ms.

### 3.3 The capability matrix

| Capability | CH | Firecracker | QEMU |
|---|---|---|---|
| `snapshot_restore` | **✓** | ✗ *(gated off pending reconnect fix)* | ✗ *(privileged in-kernel-vhost-vsock validated, unwired)* |
| `lazy_restore` (demand-paged) | ✓ (`memory_restore_mode`) | ✗ | ✗ |
| `virtio_fs_shares` | ✓ | ✗ (block-only) | ✓ |
| `unprivileged_vhost_user_net` | ✓ | ✗ | ✓ |
| `nested_virt` | ✓ | ✗ | ✓ |
| cold boot (p50, §15) | ≈635 ms | ≈1022 ms | ≈1405 ms |
| warm restore (p50, §15) | ≈169 ms | ≈128 ms *(measured; capability off)* | — |

The cold-boot/restore inversion pins each backend's *intended* role: CH is the feature-complete default
and cold-boot leader (and the working snapshot tier today); Firecracker cold-boots slower than CH but
restores fastest, earning the density/snapshot tier once its warm-restore reconnect is fixed; QEMU is the
slowest cold-booter, the fallback for the awkward cases, and the most-proven nester. The orchestrator reads roles off
`capabilities()`; the test/bench matrix **skips — never fails** — a scenario a backend can't run.

The one law that explains every snapshot entry above — *a VM is snapshot-eligible only if no vhost-user
device is attached to it* — is stated and enforced in §12.1.

---

## 4. Control plane: vsock and the guest agent

### 4.1 The protocol

The shared crate `vmcell-protocol` defines a small length-prefixed, `serde`+`postcard`-framed message
enum — the **only** code shared between the host and the guest agent:

```rust
#[non_exhaustive]
pub enum Message { Ready, Exec(ExecRequest), Stdout(Vec<u8>), Stderr(Vec<u8>), Exit(i32), PutFile { .. } }
```

There is **no `Hello`, no `Ping`** — a dead variant and a no-op variant are both the "dead protocol
advertised as live" smell the review rubric bans; `#[non_exhaustive]` makes re-adding either non-breaking
if a real use appears. The guest sends `Ready` as the **first frame** after `accept`, and the host blocks
for it — this is the handshake the restore path re-runs (§4.2). Frames are bounded (`MAX_FRAME_BYTES` =
16 MiB); the default per-exec timeout is 10 s (`DEFAULT_EXEC_TIMEOUT`).

### 4.2 The host: `AgentClient`

```rust
impl AgentClient {
    pub async fn connect(vsock_path: &Path, port: u32, timeout: Duration, serial_log: &dyn SerialLog) -> Result<Self>;
    pub async fn reconnect(&mut self, vsock_path: &Path, port: u32, serial_log: &dyn SerialLog, timeout: Duration) -> Result<()>;
    pub async fn exec(&mut self, cmd: ExecRequest) -> Result<ExecOutcome>;
    pub async fn put_file(&mut self, dst: &str, bytes: &[u8], timeout: Option<Duration>) -> Result<()>;
}
```

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
  read-only erofs root; install the proxy CA into the trust store; bring up loopback.
- **The guest IP is set by the kernel `ip=` boot parameter** (`CONFIG_IP_PNP=y`, §8.3), in both
  networking modes, so PID 1 does **no netlink** — there is no `ip link/addr/route` in the agent at all
  (the manual bring-up an early pass added was removed). This "zero netlink in PID 1" invariant is
  guarded *structurally*: `vmcell-guest-agent` has no `rtnetlink` dependency, asserted by a CI
  `cargo tree` gate (§12.3, §14).
- **Reap zombies** (`SIGCHLD`/`waitpid`) — PID 1 is the universal reaper — coordinated with the dedicated
  `child.wait()` for the exec'd command so the reaper does not steal the child's exit status and report a
  false `127` (§12.6). The reaper is a small `ReaperCoordinator` shared by the agent binary.
- **Never exit on a recoverable condition** — if PID 1 returns, the kernel panics with `Attempted to kill
  init`. Core mounts (overlay/`/proc`/`/dev`) stay fatal; everything else is logged and continued. Two
  such conditions were live regressions: a **virtio-fs tag that is not attached** (the exec-only path
  attaches no shares, so `virtio-fs: tag … not found` must be skipped, not propagated) and a **loopback
  ioctl failure** (cosmetic on the data path).
- **Fork** the test command as a child (not `exec` into it) so the agent stays PID 1.
- **Serve connections in a loop, re-binding after restore:** the agent serves each connection on **its own
  thread** (a stale pre-snapshot connection whose blocking read may never EOF parks instead of wedging the
  accept loop) and **re-`bind`s** its listener after a bounded idle period, because on CH the pre-snapshot
  bound listener goes deaf once the vhost-vsock device is re-created (§9.2).

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
across tests so its pages stay hot — Imp's binaries arrive here so a new build does not invalidate the
rootfs), and `vmcell-out` (rw output), but they are **examples, not requirements**.

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
tests and the restore-path MAC rotation need. Rather than bloat the rootfs with distro packages or weaken
the tests, the harness ships a small **Rust multicall binary, `vmcell-guest-tools`**, providing:

- `ip` — read-only interface/route/neighbour state from sysfs/procfs, plus `link set <dev> address <mac>`
  via the `SIOCSIFHWADDR` ioctl (the one write the restore path uses, §9.2). `ip addr`/`ip route` *write*
  forms are accepted as no-ops so an orchestrator `&&`-chain succeeds without touching the boot-time IP.
- `curl` — real HTTP/HTTPS via `reqwest`, honoring proxy env vars and `-k`/`--resolve`/`--max-time` (and
  surfacing a proxy's `CONNECT` 403 the way curl does, which the egress-block test asserts on).
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
*which* host port to register as a permanent forward-port; `None` disables host services.

**Privileged (`tap`).** A per-VM network namespace, a tap, and a `/30` on `10.200.<n>.0/30` (host `.1`,
guest `.2`), where the third octet is `n = (vmid % 254) + 1` (§10.2), via `rtnetlink`. Full L2 fidelity; needs `CAP_NET_ADMIN`. This is the default for
fidelity-sensitive tests and the only network path eligible for the snapshot tier (§12.1).

**Unprivileged (`userspace`).** An in-process **smoltcp** TCP/IP stack behind a `vhost-user-backend`
vhost-user-net device — no tap, no `CAP_NET_ADMIN`. Lower-fidelity (a userspace stack), reserved for
deployability rather than fidelity-sensitive tests, and it cannot be snapshotted (vhost-user-net, §12.1).
Four invariants make it work, each of which wedges the link *silently* if violated — detailed in §12.8.

`passt` was the first choice for unprivileged networking but is out: smoltcp is in-process, with no
external dependency and no LSM/seccomp entanglement, so it is the better design regardless (Appendix B,
Exp 5; the earlier "passt is CH-incompatible via seccomp" reason was wrong — it was a host AppArmor
af_unix rule, not passt's seccomp, and not CH-specific).

The `/30` math is a pure function and unit-tested; the netlink calls, the `nft` invocation, and the
smoltcp NAT's packet loop are the side-effecting part, behind injectable `Netlink` / `NftApplier` seams.

### 6.2 Host-served endpoints

A host test server bound to the per-VM gateway/host address is reachable from the guest and not exposed
to other systems. Per-test server config and dynamically-assigned ports are configured *after* the server
is listening (the guest is pointed at the port via `host_services_port`). Arbitrary TCP/UDP works; vsock
is available as an alternate, IP-stack-free host↔guest channel.

### 6.3 The transparent egress proxy

A `hyper`-based MITM proxy (`hudsucker` supplies the whole MITM stack — `hyper`+`rustls`+`rcgen`). For
HTTP it splices/logs; for HTTPS it terminates TLS with an on-the-fly cert minted by an in-memory CA
(`rcgen`) and re-originates upstream. The CA is baked into the guest trust store, so HTTPS interception
works in both networking modes. Test doubles let a caller register `(Matcher, Responder)` pairs (and, for
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
`iifname <tap> ip daddr <gateway> tcp dport <proxy_port>`.

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
    pub limits_enforced: bool,                              // false when the controller wasn't delegated
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
   matchable, carrying the exact missing capability — surfaced before the VM is handed back.
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

Both sources produce a merged rootfs **tar**, which feeds a **shared tail**: inject
`vmcell-guest-agent` + the proxy CA + the `vmcell-guest-tools` helper + the tmpfs/overlay scaffolding,
then stream the tree through `am-fs-erofs` in memory (the `mkfs.erofs` binary is a fallback). The
in-memory pack avoids creating device nodes or root-owned files on the host, so it runs **unprivileged**.

- **Default — OCI pull (host-native, in-Rust).** Resolve a Debian base image to a **manifest digest** (pin
  the digest, never the tag), pull manifest + config + layers with `oci-client` (no Docker/containerd),
  verify every blob against its `sha256`, decompress each layer (`flate2`/`zstd`), and apply them honoring
  **OCI whiteout semantics** (`.wh.<name>` deletions, `.wh..wh..opq` opaque-dir markers) to produce the
  merged tar. The guest never sees OCI — this is OCI strictly as a *build-time source* feeding the erofs
  packer, so direct-kernel boot, snapshot/restore, and shared-RO-erofs density are unchanged.
- **Full apt chain — `mmdebstrap` inside a builder micro-VM.** Build a builder rootfs via the OCI source,
  boot it on this project's own CH stack, then over the vsock agent run `apt-get install mmdebstrap`
  followed by `mmdebstrap` against the pinned snapshot — emitting the target rootfs as a tar on a
  read-write share, which feeds the shared tail. Because `mmdebstrap` runs as root inside a controlled
  guest, apt performs the full `InRelease`/`Release.gpg` chain verification in-guest (refuse-on-mismatch),
  and `mmdebstrap`, `apt`, `gpg`, and the shell all leave the host entirely.

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
console=ttyS0 loglevel=6 random.trust_cpu=on random.trust_bootloader=on root=/dev/vda rootfstype=erofs ro
ip=10.200.<n>.2::10.200.<n>.1:255.255.255.252::eth0:off   # n = (vmid % 254) + 1  (§10.2)
panic=1 init=/usr/sbin/vmcell-guest-agent
```

`loglevel=6` keeps the serial console attached for panic capture (§12.10 — `contains_panic` matches
KERN_EMERG lines) and for boot diagnostics (`NOTICE`/`WARN`/`ERR`, incl. the "Linux version" banner the
`boot.rs` integration test asserts on) while dropping the voluminous `KERN_INFO` (6) device-probe
output that otherwise dominates cold boot (each line is a synchronous write to the byte-at-a-time 8250
UART); it was the single largest cold-boot lever (§15). `random.trust_cpu=on` avoids a possible CRNG-
init stall on first `getrandom()`. The `ip=` parameter (enabled by `CONFIG_IP_PNP=y`) sets the guest
address at boot — consumed by the
kernel's IP-PNP late-initcall, not an initramfs — so PID 1 needs no netlink in either mode (§12.3). Three
precisions: `CONFIG_VHOST_VSOCK` is host-side (the base guest control plane needs only `VSOCKETS` +
`VIRTIO_VSOCKETS`; `VHOST_VSOCK` earns its place only for nested virt); the erofs decompressor `CONFIG`
must match the packer's compressor or the mount fails — the production packer ships **uncompressed**,
sidestepping the dependency at a size/page-cache cost; and if the ext4/`Block` fallback rootfs
(`RootfsSource::Block`, §10.2) is ever used, add `rootflags=noload` so the ext4 driver mounts strictly
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
payoff of making kernel a dimension was *disproving* a wrong belief: an interleaved sweep of the latest
6.6 LTS (6.6.143 — the current point release of the 6.6 line the old 6.12-vs-6.6.9 comparison used) against
6.12.94 shows the guest kernel version is **not a material hot-path lever** (warm restore within ~2%),
settling an earlier cross-session "~2× slower" scare as host-load noise (§15).

The same `KernelStage` can also sweep kernel *config variants* off one base source: a kernel is requested
as **(base label, an ordered set of named KConfig fragments)** — e.g. `6.12.94 + [KASAN, LOCKDEP]` — with
`pins.json` mapping each fragment name to a KConfig string. Fragments are canonicalized to **sorted order**
at hash time (so `[KASAN, LOCKDEP]` and `[LOCKDEP, KASAN]` resolve to the same artifact), a non-zero
`make olddefconfig` is a fail-loud `Error::Artifact`, and the build-time blow-up (a cold KASAN build is
~45–90 min) is bounded by the content-addressed cache — CI batches by label and runs the full matrix
nightly. PREEMPT_RT is *not* a fragment (it needs an rt-patched source — a separate registry source), and
KCOV *extraction* needs guest tooling (§17); the fragment only turns the kernel capability on.

---

## 9. Snapshot, restore, and density

### 9.1 The warm-snapshot path

The per-test speed lever is **warm snapshot + restore**: boot the erofs-rootfs base to "agent-ready,"
snapshot once, and per-test restore + add a tmpfs overlay. This skips kernel boot on the hot path and is
measured at **≈3.7× faster than cold boot on CH** (§15). The erofs RO base needs no per-test copy, and the
only writable per-test state is a tmpfs overlay. The snapshot tier is **CH today** (Firecracker's
snapshot is gated off, §3.2; QEMU's privileged tier is validated but unwired, §3.3), on the
privileged/tap path with a non-vhost-user vsock and **no virtio-fs data shares** (§12.1 — read-only data
is served as an extra erofs/block image there).

The mechanics: snapshot = `pause`→snapshot→(`resume` or stay paused for immediate kill); restore returns
a **paused** instance the caller `resume()`s — never `boot()`/`create()`. The on-disk size of a suspend
image **tracks guest RAM exactly** and is flat in rootfs size (a 256 MiB-RAM guest writes an ≈256 MiB
memory file whether the rootfs is slim or fat, §15), so an N-snapshot warm pool costs ≈N×guest-RAM on
disk. The in-place `config.json`/sidecar path rewrites (§3.2) are **single-use**, so restoring many clones
from one snapshot needs a copy-on-write of the snapshot dir first (§16).

### 9.2 Restore correctness

A restored snapshot resumes at the exact instruction it was taken, so restored clones share whatever state
was frozen in. Four things must be refreshed on **every** restore, fired once on the first post-restore
`agent()` call after the vsock reconnect succeeds. This is the concentrated "a restored VM is not a fresh
VM" lesson (§12.4):

- **Identity (CID) — uniqueness among *live* clones, not a forced numeric change.** The vsock CID must be
  unique across *concurrently running* restored clones. It is **not** required to differ from a torn-down
  original: the `CidAllocator` hands out the lowest free CID and reuses freed CIDs by design. So the
  correct check on a *sequential* restore is "the restored guest has a valid, live CID," **not**
  `assert_ne!(original_cid, restored_cid)` (which is over-specified and fails precisely *because* reuse is
  correct).
- **Identity (MAC) — rotated at the device layer, not via netlink; the IP is left alone.** MAC rotation is
  the one in-guest identity change the restore path performs, via a single `ip link set eth0 address <mac>`
  (the `SIOCSIFHWADDR` ioctl in guest-tools) — a device-layer write, consistent with zero-netlink-in-PID-1
  (§12.3). The IP is deliberately *not* rotated: `ip addr flush` would drop the IP-PNP default route and
  re-introduce in-guest netlink, so the guest keeps the address the kernel `ip=` set.
- **Entropy** — reseed via virtio-rng. An unreseeded `getrandom()` can stall first use by seconds, and
  because every clone resumes at the same frozen instant, RNG reuse is otherwise silent and correlated.
  This is best-effort (from `/dev/hwrng`); only a clock-resync failure propagates.
- **Clock** — a snapshot resumed much later resumes with a stale wall clock. The guest cannot fix this from
  inside (`hwclock --hctosys` reads the *restored* RTC — the old snapshot time — and sets the clock
  *backwards*; a restored snapshot may have no network for NTP). The resync is therefore **host-driven and
  mandatory**: immediately after reconnect the host reads `SystemTime::now()` and pushes it to the agent
  (`date -s`). For ephemeral tests a stale clock is cosmetic; for anything asserting on timestamps it is
  not — so a resync failure surfaces.

**The post-restore vsock reconnect itself is mandatory and was the hardest restore bug to close.** It is
not a no-op, and on CH it is not merely "reuse the surviving listener": CH `--restore` rebuilds devices
from the snapshot's `config.json` (so the spawn step rewrites the now-defunct vsock/serial paths first,
§3.2) *and* re-creates the vhost-vsock device, leaving the guest's pre-snapshot bound listener deaf — so
the guest agent serves connections thread-per-connection and **re-`bind`s** after a bounded idle for the
host's `reconnect` to land (§4.3). This is the same class of fix Firecracker's warm restore still needs.

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

---

## 10. The Rust library (`vmcell`)

### 10.1 Workspace layout

A cargo **workspace** (2024 edition). The workspace root is a pure `[workspace]`; its members are:

- **`vmcell`** — the library (plus the `vmcell` CLI and the `bench-vm` harness), one package carrying the
  host feature stack (§10.5). Crates are at `0.2.0`.
- **`vmcell-protocol`** — the framed postcard wire enum and the `ExecRequest`/`ExecOutcome` types; the
  *only* code the host and the guest agent share.
- **`vmcell-guest-agent`** — the guest PID-1 binary (plus a small `ReaperCoordinator` library). Lean:
  `rustix`/`signal-hook`/`vsock`/`libc`/`tracing`, no host async stack.
- **`vmcell-test-runner`** — the privileged-test capability runner (§14). Lean: `rustix`/`capctl`/`libc`
  only, never the `vmcell` library.
- **`vmcell-guest-tools`** — the in-rootfs `ip`/`curl`/`kvm-ok` helper (§5.3). A *guest* binary; needs
  `reqwest` for real HTTP, so it is leaner than the host but not as lean as the agent.

Why a workspace: a member crate's build fingerprint depends only on its own (tiny) source + deps, so the
lean-tree assertion (§10.5) becomes a **structural per-member property** — no host module can leak into
the runner by construction. Extracting `vmcell-protocol` is what lets the agent be a standalone member
without a dependency edge on the whole library. The `[patch.crates-io]` vhost fork lives at the workspace
root.

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
artifact/        # Stage trait, Pipeline, cache, kernel/rootfs(oci,guest_tools,mmdebstrap_vm)/snapshot stages, bundle
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
}

// ---- orchestrator.rs — the handle most callers hold ----
pub struct MicroVm<V: Vmm> { /* instance, cgroup, net, virtiofsd, cid, vmid, tmp_dir, ... */ }
impl<V: Vmm> MicroVm<V> {
    pub async fn start(vmm: &V, cfg: VmConfig, cids: Arc<CidAllocator>, vmids: VmidAllocator, cgroups: Box<dyn CgroupFs>) -> Result<Self>;
    pub async fn restore(vmm: &V, snapshot_dir: &Path, cfg: VmConfig, cids: Arc<CidAllocator>, vmids: VmidAllocator, cgroups: Box<dyn CgroupFs>) -> Result<Self>;
    pub fn vmid(&self) -> u32;
    pub fn proxy(&self) -> Option<&EgressProxy>;          // the egress-proxy handle, if egress is filtered
    pub async fn agent(&mut self) -> Result<&mut AgentClient>;
    pub async fn usage(&self) -> Result<ResourceUsage>;   // reads the cgroup slice
    pub async fn pause(&mut self) -> Result<()>;
    pub async fn resume(&mut self) -> Result<()>;
    pub async fn snapshot(&mut self, dir: &Path) -> Result<()>; // snapshot-eligible only; Unsupported otherwise
    pub async fn shutdown(self) -> Result<()>;            // graceful, then verify gone
}
impl<V: Vmm> Drop for MicroVm<V> { /* kill VMM proc-group → virtiofsd → tap/netns/cgroup/overlay/tmp_dir */ }
```

`MicroVm::start`/`restore` take the CID allocator (`Arc<CidAllocator>`), the VMID allocator (a
`VmidAllocator` handle passed by value — it is `Clone` over an internal `Arc<Mutex>`), and the `CgroupFs`
seam (`Box<dyn CgroupFs>`, converted to an `Arc` internally) as **three separate injected seams** (distinct
ID spaces plus the recording-fake seam). Both allocators are **process-global** — a single shared instance
per test-runner process, not one per test — because under `cargo test`'s in-process parallelism per-test
allocators hand concurrent tests identical IDs and collide on temp-dir paths and socket names.
`VmidAllocator` is either hermetic (`new()`, in-process) or cross-process (`shared()`, via
`/tmp/vmcell-vmid/<vmid>.lock` files with crashed-owner reclaim), and injects a `Clock` (bounded
`+ RefUnwindSafe` so it doesn't strip public auto-traits) for its search seed. The VMID is mapped to the
third IPv4 octet as **`(vmid % 254) + 1`** (`10.200.<octet>.{1,2}` — a raw counter would exceed 255 and
synthesize invalid addresses), centralized in one unit-tested `/30` helper, which **caps a single host at
≈254 concurrent VMs on one `/16`** (§16). VMID range is `1..=254`; CID space is `3..=254`.

Two lifecycle nuances worth knowing at the interface: `request_shutdown()` sends the graceful signal, then
SIGKILLs after a fixed **500 ms `SHUTDOWN_GRACE`** window (a true poll-until-exit needs a
`VmInstance::try_wait` method, deferred); and `agent()` borrows all of `MicroVm` mutably for the returned
ref's lifetime, so read the cheap immutable `vmid()`/`proxy` into locals *before* calling `agent()`.

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
- **A carried `[patch.crates-io]` fork of `vhost-user-backend`+`vhost`** is needed *only* to attach the
  unprivileged smoltcp NAT to QEMU (not CH), where a strict `PROTOCOL_FEATURES` check rejects
  `SET_VRING_ENABLE` arriving before `SET_FEATURES`. A live message trace confirms QEMU sends
  `SET_VRING_ENABLE` first while CH sends features first, and upstream 0.22/0.16 still enforce the guard —
  so the fork addresses a genuine QEMU ordering quirk, not a masked backend bug. It is permissively
  licensed (rust-vmm, Apache-2.0); pin it to an exact rev and drop it if the QEMU-unprivileged tier is
  dropped. (Because `just ci` sets `RUSTFLAGS=-D warnings` process-wide, the fork's unused helpers carry
  `#[allow(dead_code)]` so the gate doesn't abort in vendored code.)
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
(§10.1) — which is why §2/§10.1 count "four lean member crates" (protocol + the three binaries) while this
section counts three build shapes. Within the `vmcell` library the per-component
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
   selection) be unit-tested with no KVM, root, or subprocess.
2. **Pure/imperative split.** The genuinely-testable pure functions are isolated from I/O: nft-rule
   rendering, `/30` arithmetic, the CH REST payload builder, the vsock handshake state machine,
   cgroup-path construction, per-VM scratch-dir construction, the artifact `cache_key`, and the protocol
   codec.
3. **Injectable side-effect traits** — `Netlink`, `NftApplier`, `CgroupFs`, `SerialLog`, `Clock` — each
   with a real implementation and a recording fake, so `net`/`metrics`/`agent` orchestration can assert
   "the right rules/limits/handshake were requested" without touching the host.
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
and as CLI verbs. The CLI (`vmcell`) implements `build`, `build-kernels`, `oci2erofs IMAGE@DIGEST`,
`run`/`create`/`snapshot`/`stats` (live-handle lifecycle taking `--kernel`/`--rootfs`), and
`bundle`/`verify-bundle` (a digest-pinned fetch-and-verify manifest of the built artifacts). `exec`/`ls`/
`rm`/`destroy` are **deferred to a future `impd` daemon** (they need a cross-process VM registry the
single-process `MicroVm` ownership model can't provide) and **fail loud** with a typed error rather than
printing success.

### 11.1 Artifacts produced

1. **`vmlinux`** (per arch, per kernel label): one custom-minimal kernel, direct-boot, drivers built in.
   Rebuilt only when the config fragment or pinned source changes.
2. **Root filesystem** (per profile): a single read-only erofs packed in memory by `am-fs-erofs` from a
   merged tar, from one of two interchangeable sources sharing the inject+pack tail (§8.2). Kernel-independent.
3. **Warm snapshot** (per VMM + profile): boot the erofs base to "agent-ready," snapshot.
4. **Proxy CA cert**: minted once, baked into the rootfs trust store.

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
  `mmdebstrap` source), the kernel source version/SHA (plus the `kernels` registry), and the CH/virtiofsd
  release tags. These live in a committed `pins.json`; `ResolvePinsStage` loads it once and propagates the
  values through `StageOutputs` so downstream stages read pins from memory. *Live* tag→digest and
  timestamp resolution is forward work (§16); the committed lock is the honest current state.
- **Stages 1..n — deterministic given inputs.** Each stage's output is fully determined by its inputs +
  pins: fetch+verify kernel source → compile `vmlinux`; then the rootfs source (OCI pull+verify → apply
  layers/whiteouts → merged tar, *or* the in-VM `mmdebstrap` path, which depends on the compiled `vmlinux`
  so the kernel stage is ordered first); both converge on the shared inject+pack tail → boot+snapshot.
- **Caching — five rules, each its own failure mode.** Each stage has a pure `cache_key`; `Pipeline::build`
  skips a stage whose **output content** matches that key:
  1. **Stable hasher** — `blake3` (or `sha2`), never `DefaultHasher` (not portable across Rust versions).
  2. **Deterministic input order** — hash inputs in a fixed order (sorted keys / `BTreeMap`), never
     `HashMap` iteration order.
  3. **Content and identity that travel, not local paths** — hash the *content hashes* of upstream
     artifacts, never absolute `PathBuf`s under `target/`. The rootfs key folds `guest_agent_src_hash`
     *and* the guest-tools content, so rebuilding either invalidates the rootfs (a stale agent baked into
     the rootfs was a real handshake-timeout bug).
  4. **Embed a per-stage version constant and the pinned source SHA** — a build-logic change with unchanged
     pins, or re-pointing a pin at new bytes, must invalidate the key.
  5. **Validity is content-addressed, not existence-based** — a tampered artifact with an intact
     `.cache_key` sidecar is **rejected**, not silently reused; re-hash on every use (including a cached OCI
     blob, whose digest is re-verified on the cache-hit path). The kernel-tarball cache is **verify-or-purge**.

  `reset_to(stage)` removes that stage's and all later stages' outputs and **errors on an unknown name**.
- **Minimize external access + record/replay.** Network-touching stages split into a **record** step
  (populate a cache keyed to the pins) and a **replay** step (build purely from the cache); OCI blobs are
  cached by digest so a later registry deletion doesn't break a rebuild.
- **Signing-chain verification.** The in-VM `mmdebstrap` source verifies the Debian `InRelease`/`Release` +
  `Release.gpg` chain against the pinned keyring *inside the guest* before using any package
  (refuse-on-mismatch). The OCI source's `sha256` digest pin is an integrity hard-stop but is *integrity,
  not authenticity* unless a cosign/sigstore signature is also verified. A mismatch is a hard stop, never a
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
   of any vhost-user device, returning `Error::Unsupported { vmm, feature }` — never a panic, never a
   stringly `Error::Vmm`.

The standing fallback for read-only data in the snapshot tier is to serve it as an **additional erofs/block
image**, whose cost is the extra image's page cache, not guest anonymous RAM.

### 12.2 Fail loud on a missing capability; never silently no-op

A host-facing operation that *can't* do what was asked must **say so with a typed error** —
`Error::CapabilityUnavailable` for an undelegated limit, `Error::Unsupported` for an unsupported backend op
— not return `Ok` while doing nothing; only the explicitly-listed §15 benchmark knobs may degrade to a
`warn!`. This is why `ResourceUsage` carries `limits_enforced` and per-metric `*_read_ok` booleans instead
of a lying `0`. The full contract and its governing test are §7.2.

### 12.3 Zero netlink in PID 1

The guest agent does **no** `ip link/addr/route`. The guest address is set by the kernel `ip=` boot
parameter (`CONFIG_IP_PNP=y`), consumed by the kernel's IP-PNP late-initcall — in *both* networking modes.
The restore path's one in-guest identity write is the MAC rotation via the `SIOCSIFHWADDR` ioctl (§9.2),
a device-layer write, not netlink. This keeps PID 1 tiny and dependency-thin, and it is guarded
**structurally**: `vmcell-guest-agent` has no `rtnetlink` dependency, asserted by a CI `cargo tree` gate —
*not* by a "Netlink fake records zero calls" unit test, because there is no netlink seam in the agent to
inject (the manual bring-up an early pass added was deleted, not stubbed).

### 12.4 A restored VM is not a fresh VM

A snapshot resumes at the exact frozen instruction, so anything that must differ between the original and a
restored clone has to be refreshed on **every** restore — fired once on the first post-restore `agent()`
call, after the reconnect. The four things and their traps are in §9.2; the headline traps: identity is
about *live* uniqueness (CID reuse is correct — do **not** `assert_ne!(old, new)`); the MAC rotates but the
**IP does not** (rotating it would drop the IP-PNP route and re-introduce in-guest netlink); entropy must be
reseeded (correlated RNG across clones is otherwise silent); and the **clock must be host-driven** (the
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
ioctl failure is logged and skipped, while core mounts stay fatal); **reap zombies**, coordinated with the
exec'd child's `wait()` so the single `WNOHANG` reaper does not steal the child's exit status and report a
false `127`; and **fork the test command, don't `exec` into it**, so the agent stays PID 1 and keeps the
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

### 12.8 The unprivileged NAT's four silent-wedge invariants

The in-process smoltcp NAT works only if four invariants hold, and each one wedges the link *silently* (no
error, just a dead connection) if violated:

1. smoltcp drops a broadcast frame whose *source* MAC equals the interface MAC, so the host NAT MAC must
   not collide with the guest's vmid-derived MAC — pin it **outside the range `mac_math(1..=254)` can
   emit** (backed by a unit test asserting no collision).
2. iterate the virtio RX descriptor chain **only when the NAT actually has packets queued** — iterating
   `vring.iter()` consumes/advances `avail_idx`, so polling it while empty discards the guest's RX buffers.
3. call `enable_notification()` on the TX queue inside the `handle_event` loop so the guest kicks the
   eventfd for the next packet.
4. size the socket pool for concurrent *and* keep-alive connections (≈16 sockets per forwarded port), not
   one-per-port — a single `TcpSocket` per port means an HTTP keep-alive connection holds the only slot.

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
orphaned by a hard crash (§6.4).

### 12.11 Keep the primitive general

No domain-specific assumption may leak into `vmm`/`agent`/`orchestrator`/`metrics`. All three consumer
domains are co-equal; the `MicroVm` handle is a thin owner over the primitive. A capability the *core* can
offer workload-agnostically goes in the library; a capability that encodes what a *test*, an *agent*, or a
*function* should *do* with a VM ships as a thin consumer crate on top (§17). Reviewing each addition
against this line is the standing guard.

## 13. Hard-won lessons

Three meta-lessons recur across the implementation history (Appendix A) and are worth stating directly:

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
`config::build()` rejections (a negative test each, including all three vhost-user snapshot cases);
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
`DummyStage`); the runner's pure privilege-transition logic (§ below); and `Drop` order against `FakeVmm`
(**still runs on `panic!`**).

**Integration tests — real environment, default-skipped, per-VMM.** Tests needing KVM or capabilities are
`#[ignore]` (CI runs them with `--ignored`) via the nextest `serial-host` group for anything touching
global host state. A laptop `cargo test` runs only the unit tests and stays green. The suite is split into
the **two operating-mode suites** (§6.4), each a first-class, separately-invoked suite whose prerequisites
are a **visible hard precondition** — a missing capability or undelegated controller is a *skip-with-reason*,
**never** a silent green, and a filter that selects **zero tests is a CI failure**, not a pass. Every
scenario is parameterized over the backend; before running a case the harness consults `capabilities()` and
emits an explicit skip-with-reason for any backend that can't support it (the `require_cap!` +
`vmm_matrix_test!` harness). Applicability: boot / exec / lifecycle / metrics / `put_file` / concurrency
and the privileged egress/host-endpoint paths run on all three; `snapshot_restore` runs on **CH only**
today (FC gated off, QEMU snapshot-ineligible in unprivileged+vsock); virtio-fs shares and nested virt run
on **CH/QEMU only**; the unprivileged smoltcp suite runs on **CH/QEMU only** (Firecracker has no
vhost-user-net for the NAT to attach to).

The required assertions are written to **fail on their own inverse** — the earlier versions of several were
theatrical (they passed on their inverse), which the review caught:

- `snapshot_restore.rs`: the host **reconnects the severed vsock** (not merely "restore succeeds"); the
  restored VM has a **valid, live CID** (not `assert_ne!`); a **rotated MAC observed in-guest** (read back
  via guest-tools `ip`); **clock resync** driven by an injected `FakeClock` consulted on the *first*
  post-restore call; **RNG reseed** captured pre/post *without the test issuing its own reseed*.
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

**The privileged capability runner is itself unit-tested off the privileged path.** Its pure helpers are
covered against each buggy inverse: the `+ep` (not `+p`) remediation message; the path-confinement
(described in §14 below); `merge_preserved_groups` (kvm-gid preserved iff held, never invented); and — the
deepest fix — a **pure `plan_privilege_transition(CapState, need, euid)`** so the capability-state sequence
(inheritable-add → bounding-drop → ambient-raise → trim → uid) and the security-critical **setuid-form
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

**Micro (criterion, in-process):** protocol encode ≈56 ns / decode ≈83 ns; `cache_key` ≈218 ns; `/30`
host-IP parse ≈29 ns; in-memory empty-tar→erofs ≈1.23 µs. The control-plane codec and per-VM address/cache
math are tens-to-hundreds of nanoseconds — far below anything gating a multi-second VM lifecycle.

**Macro — cold boot to agent-`Ready`** (N=20, warm-cache, 256 MiB, **post the 2026-07-01 latency
optimization pass** — see below): CH **≈330/346 ms**; Firecracker ≈776/787 ms; QEMU ≈1400 ms
(pre-pass; code path unchanged). Pre-pass these were CH ≈635, FC ≈1022.

**Macro — warm restore to agent response** (N=20): CH **≈84/94 ms** (default ≈ lazy; eager ≈258, pre-
pass); Firecracker N/A (`snapshot_restore` gated off, §3.2); QEMU N/A (snapshot-ineligible in
unprivileged+vsock).

**Latency optimization pass (2026-07-01).** A targeted pass recovered the latency the correct-but-
slower code had accreted vs earlier buggy-fast versions — **CH cold 642→330 ms (−49%), CH restore
166→84 ms (−49%)** — with **no invariant relaxed** (verified: `just ci` green, unit 242/0, privileged
suite 232/0). The levers, largest first: the guest kernel cmdline dropped the verbose `KERN_INFO`
serial flood (`loglevel=6`, keeping a debuggable/panic-capturable log); the guest vsock accept poll
`ACCEPT_POLL` 100→20 ms (the dominant restore-reconnect cost — the host blocks for `Ready` between its
CONNECT/OK handshake and the guest's next `accept()`); the graceful `shutdown()` teardown now polls
`VmInstance::has_exited` up to a 250 ms (was 500) grace instead of always sleeping it; and tighter host
connect/api-socket poll cadences. Full method + per-lever deltas: `docs/benchmark-results.md`,
`docs/perf-experiments-log.md`; the deviations: `docs/implementation-notes.md`.

Reading these together:

- **Restore validates the snapshot tier and inverts the cold-boot ordering for the metric that matters.**
  Restore is ≈3.9× faster than cold boot on CH (330→84 ms post-pass). Firecracker *would* win restore
  while losing cold boot — exactly the density/snapshot-tier role it is assigned — once its warm-restore
  reconnect is fixed. **CH is the only backend a test can restore on today.**
- **CH lazy restore (`prefault=off`, userfaultfd) is ≈1.5× faster than eager** — freq-pinned, lazy ≈176 ms
  vs eager ≈258 ms, so ≈82 ms saved. But the win *understates* lazy's true cost, which reappears as in-guest
  first-touch page faults during execution — so "lazy wins" is for time-to-resume, not
  time-to-first-useful-work.
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
(guest-boot + agent wait) ≈284 ms, create/spawn ≈42 ms, exec ≈4 ms; restore `connect` collapses to
≈36 ms (reconnect + RNG/clock/MAC resync), restore+resume ≈58 ms, exec ≈1 ms. **Teardown note:** the
budget measures the *graceful* `MicroVm::shutdown()` (`request_shutdown` → poll `has_exited` up to a
250 ms grace → force-kill) at ≈283 ms — a ceiling, not a leak; the fast per-test path is `Drop`
(force-kill the VMM process group + reap, **≈27 ms**, §12.10), which a RAII consumer pays instead. The
vsock exec round-trip floor is sub-millisecond (p50 ≈0.7 ms incl.
in-guest fork/exec/reap).

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

- **Firecracker warm restore.** Its `snapshot_restore`/`lazy_restore` capabilities are honest `false`: the
  MMIO snapshot creates fine but the first post-restore `exec` drops (the guest vsock listener doesn't
  re-attach after FC re-creates the device). The FC restore *mechanism* is already sketched — a fresh
  process + `POST /snapshot/load {resume_vm:false}` (restore returns paused, caller resumes), `PATCH /vm`
  for pause/resume, and a `vmcell_host_paths.json` sidecar that `restore()` reads to unlink the stale host
  vsock UDS baked in at snapshot time (else `EADDRINUSE`) — so the remaining work is the **guest-side**
  rebind (the FC analog of the CH fix in §9.2) plus the UFFD lazy-restore backend. Fixing it unlocks the
  fastest-restore tier. **CH is the only wired, end-to-end-validated snapshot backend today.**
- **QEMU snapshot: privileged tier validated but unwired.** `snapshot_restore: false`. The QEMU *migration
  mechanism* for the privileged in-kernel-`vhost-vsock` config is validated at the QEMU level (no
  QEMU-10.2 migration blocker; migrate→restore verified live), but it is not wired as a vmcell backend;
  remaining work is the live agent-reconnect run + wiring `snapshot()`/`restore()` and flipping the
  capability for that config only. (This "validated at the QEMU level, not wired end-to-end" is a weaker
  claim than CH's wired-and-validated tier above.)
- **Single-snapshot CoW for many clones.** The CH `config.json` and FC sidecar path rewrites are single-use
  (in-place); restoring N clones from one snapshot needs a copy-on-write of the snapshot dir first — the
  warm-pool density story depends on it (with sparse-snapshot — `SEEK_HOLE` — the un-taken pool-density lever, Appendix C).
- **Live pin resolution.** `ResolvePinsStage` loads a committed `pins.json` rather than live-resolving
  tag→digest / `snapshot.debian.org` timestamps. Relatedly, the OCI fetch lacks an injectable record/replay
  seam, so the requirement-7 record/replay + tamper tests can't yet run for OCI.
- **A single start-up `HostCapabilities` descriptor.** The fail-loud contract is realized today by
  scattered per-op checks; consolidating them into one queryable descriptor probed once at start-up (§7.2)
  is unbuilt.
- **Per-VM network byte counters.** `ResourceUsage` has none (cgroup v2 has no `net.stat`, §7.1); a
  netns-scoped usage type reading `/sys/class/net/<if>/statistics` inside the VM netns is forward work.
- **In-process `fuse-backend-rs` read-only.** It does not enforce read-only, so a read-only share on that
  backend is *rejected fail-loud* (§5.2); enforcing RO in the passthrough is required before the experiment
  graduates.
- **A fully-automatic orphan sweeper.** The `sweep_orphans()` free function reaps leaked netns/cgroup/scratch
  when invoked, but a periodic background sweeper + orphan registry is not yet automatic, so a leaked netns
  can still collide with a later vmid between runs.
- **The virtiofsd per-share service-uid allocator** is unimplemented (it uses `SUDO_UID`, refuses `nobody`,
  §5.2).
- **`request_shutdown` polls a fixed 500 ms grace** before SIGKILL; a true poll-until-exit needs a
  `VmInstance::try_wait` method (§10.2).
- **The ≈254-concurrent-VM ceiling per `/16`.** Beyond that, widen the address scheme to a second octet
  (§10.2).
- **Cross-version snapshot fragility.** Pin one exact CH+virtiofsd build for any snapshot pool; CH does not
  guarantee cross-version snapshot compatibility. x86-64 is the primary arch; aarch64 is a supported second
  target, not a free rebuild (kernel configs and snapshot artifacts differ).
- **The carried `vhost`/`vhost-user-backend` patch** is a maintenance/reproducibility cost; drop it if the
  QEMU-unprivileged tier is not required (§10.4).

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
injection** (`netem` via rtnetlink on the tap path); **extra virtio-blk devices + disk-I/O fault
injection** (plain virtio-blk composes with snapshot); **append-only extra kernel cmdline + optional `init=`
override**.

**Design-now-build-later.** Single-snapshot **copy-on-write clone / `fork()`** with lineage handles (the
headline primitive both the agentic and serverless domains share — reflink-CoW the snapshot dir before each
restore, mint N divergent clones in tens of ms); the **`impd` daemon** + versioned control-plane API +
warm-pool manager (the productization seam — VMs that outlive their creator, which the single-process
`MicroVm` ownership model can't provide, so `list`/`rm`/standalone `exec` live here); **privileged-window
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

## Appendices — how the design was reached

The body describes the system as it stands. These appendices record the path: the implementation passes,
the load-bearing reversals, the dependency experiments, the contested facts, and the prior art. Nothing here
is required to *use* the system — it is the evidence behind the non-obvious choices in Parts I–III.

## Appendix A. Implementation history and the load-bearing reversals

The design accreted across six **implementation** passes (v8 → v13), then design-only revisions (v14–v17)
that added specification and corrected recorded conclusions without a new build. **The architecture never
changed** — every finding was a localized fix, a vindicated diagnosis, or a measurement, not a redesign.
The reversals below are the part a reader needs to trust the current state; each is *prior belief → finding
→ where it landed*.

**The passes.** Pass 3 (v10) was the big build: the Firecracker backend, the capability runner, both rootfs
sources, unprivileged cgroup delegation, and the full integration suite — and it independently found
`VmmCapabilities` *missing and necessary*, confirming the capability-query contract was load-bearing. Pass
4 (v11) unblocked Firecracker snapshot via MMIO and removed the netlink path from PID 1. Pass 5 (v12) filled
the warm-restore benchmark gap and fixed the FPU panic at the CPU layer. Pass 6 (v13) ran the full §15 suite
on the committed pin (several hypotheses *inverted*), enforced the snapshot-eligibility law in code at three
boundaries, drove snapshot/restore to work end-to-end on CH, added the guest-tools helper, content-addressed
the cache keys, and bumped to the 6.12.94 pin. The v16/v17 revisions re-ran the recorded experiments *live*
and corrected several conclusions (below).

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
| 3 | `mkfs.erofs` → `am-fs-erofs` | **Graduated** | In-memory tar→erofs, runs unprivileged (no device-node creation). Default; `mkfs.erofs` is the fallback. Output is byte-deterministic (fixed mtimes, ordered emission). |
| 4 | rootfs source: OCI pull (default) + `mmdebstrap`-in-VM | **Graduated** | OCI pull is the default host-native source; `mmdebstrap` relocated into a builder micro-VM to keep the full apt chain. Both supported. |
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
  ≈1.5× faster than eager). Sparse snapshot (`SEEK_HOLE`) remains the un-taken pool-density lever.
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
  compatibility guarantee).

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
| M8 | Snapshot + density | warm-snapshot stage; restore via `--restore`→`resume`; reconnect + identity/entropy/clock resync; KSM/balloon. **CH validated** | `snapshot_restore.rs` |
| M9 | Unprivileged mode | `net::userspace` (smoltcp + vhost-user-net NAT); systemd cgroup delegation | unprivileged `host_endpoint.rs`/`egress_proxy.rs` |

**Sequencing rationale.** M1 derisks the hardest plumbing (subprocess + REST + boot + teardown) and ships
the complete kernel fragment up front so the vsock/virtio-fs symbol gaps don't ambush M2/M3. M2 establishes
the control channel everything asserts through. M3–M5 add the three I/O surfaces in increasing complexity.
M6 makes runs measurable. M7–M8 are the most environment-sensitive (nesting, snapshot). M9 adds unprivileged
once the privileged path is solid. The backend-gated milestones are inherent, not accidental: M3 and M7 are
CH/QEMU-only (Firecracker hosts neither); M8 is CH today (FC gated off, QEMU's privileged tier unwired).

