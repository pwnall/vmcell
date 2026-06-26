# Imp Testing — Design Document

*An end-to-end integration-testing and evaluation platform for the **Imp** agentic harness. Each test runs in a fresh micro-VM for structural isolation, hermetic state, and production fidelity. Driven entirely from a single Rust library.*

**How to read this document.** Parts I–III describe the system **as it currently is** — the architecture, each subsystem, the test and benchmark strategy, and the open items. Facts that were once contested, reversed, or arrived at across multiple implementation passes are stated here in their settled, present-tense form. **Part IV is the history**: the implementation-pass ledger (what each pass confirmed or overturned), the substitution experiments, prior art, and the build roadmap. Where a current design choice is non-obvious — why erofs and not ext4, why Firecracker runs in MMIO mode, why the snapshot tier excludes rootless networking — the body points to the appendix that explains how it was reached. Measured numbers are real and recorded inline (§13); the substrate they were measured on is recorded with them, and several remain to be re-confirmed against the exact pinned tool versions (§14).

---

## Part I — Orientation

## 1. Purpose, scope, and non-goals

### 1.1 What this builds

A Rust library (plus a thin CLI binary) that, on a Linux/x86_64 host with KVM, can:

1. Build the VM artifacts (kernel, root filesystem, proxy CA) reproducibly.
2. Create, configure, start, stop, and destroy micro-VMs programmatically.
3. Give each VM read-only and read-write shared directories with independent permissions.
4. Let host-side test code stand up private HTTP (and other) servers the VM can reach.
5. Route all VM web egress through a transparent, logging/filtering Rust proxy.
6. Drive the VM's "console" over a vsock control channel (exec, stream I/O, exit code).
7. Monitor and cap each VM's CPU / RAM / disk-I/O / net-I/O.
8. Optionally expose nested virtualization so Imp-under-test can run its own VMs.

### 1.2 The three guarantees

The platform exists to deliver three properties, by construction rather than by cleanup:

1. **Isolation** — a misbehaving harness or model cannot disrupt the host.
2. **Hermeticity** — no state leaks between tests; each starts from an identical, fresh VM, and teardown is structural (the VM is discarded, not reset).
3. **Fidelity** — the test environment matches the real one, including full-host-access use cases.

### 1.3 Non-goals: the evaluation methodology layer

Scoring, juries, dashboards, multi-juror adversarial evaluation, MCTS rollback engines, stateful API simulation, and CI soft-failure statistics are **out of scope**. This library is the *substrate* such a layer sits on. Two connection points are designed in now because they map onto hard requirements:

- The transparent egress proxy (capability 5) is the natural home for **record/replay "cassettes"** and **Rust test doubles** for web services.
- The vsock control plane (capability 6) is the natural transport for an **in-guest model-proxy bridge** (the agent talks to `localhost:PORT`, the harness forwards over vsock and records the transcript) if Imp evaluations later need it.

Everything beyond those hooks belongs to a separate crate that depends on this one.

---

## 2. System at a glance

```
┌──────────────────────── Host: Linux + KVM (nested=1 if needed) ───────────────────────┐
│                                                                                        │
│  imp_testing orchestrator  (Rust, tokio)                                               │
│   ├─ Vmm trait:  create / boot / request_shutdown / kill / snapshot / restore / stats  │
│   │     └─ impls:  CloudHypervisor (default) · Firecracker (dense) · Qemu (fallback)   │
│   ├─ per-test:  cgroup v2 slice  →  {netns + tap (/30)  |  smoltcp vhost-user NAT}      │
│   ├─ AgentClient (tokio-vsock / AF_UNIX, retry+handshake)   ⇄   imp-guest-agent (PID 1) │
│   ├─ virtiofsd × N  (imp-in ro · imp-bin ro · imp-out rw)                               │
│   ├─ EgressProxy (hyper+rustls):  {nft TPROXY | smoltcp L4}  →  log/filter/doubles → WAN│
│   └─ Metrics:  read memory.peak / cpu.stat / io.stat from the slice                     │
│                                                                                        │
│   artifact cache:  vmlinux  ·  erofs rootfs (RO, shared)  ·  warm snapshot  ·  proxy CA │
└────────────────────────────────────────────────────────────────────────────────────────┘
        │ restore (ms) or cold-boot                          ▲ vsock: Ready/Exec/IO/Exit
        ▼                                                     │
  ┌──────────────────────── micro-VM (per test, ephemeral) ───────────────────────┐
  │ kernel: direct boot, virtio + vsock + virtio-fs + (opt) KVM built-in, no initramfs │
  │ PID 1: imp-guest-agent  (mounts /sys /proc + shares, sets up tmpfs overlay,     │
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
4. **Bind shares:** point `imp-in` / `imp-out` virtiofsd at this test's input/output dirs; `imp-bin` is shared read-only across all tests so its pages stay hot.
5. **Connect + drive over vsock:** the host `AgentClient` retries the vsock handshake until the guest's `Ready` frame arrives (bounded by a timeout), while tailing the serial log so a boot panic fails fast instead of retrying to no avail. Then `Exec` the entrypoint; stream stdout/stderr/exit. On the restore path the connection is **re-established, not reused** (§4).
6. **Collect results:** outputs from the host `imp-out` dir; `memory.peak`/`cpu.stat`/`io.stat` from the slice; the proxy's request log.
7. **Tear down (ordered):** force-kill the **VMM process group first**, then the virtiofsd processes, *then* remove the tap/netns/cgroup/overlay/sockets. Removing a netns while the VMM still holds interfaces or threads in it can hang or leak; reaping the process first makes teardown a clean kernel operation. Discard is structural — that *is* the no-leakage guarantee.

### Decisions summary (bottom line up front)

| Concern | Decision |
|---|---|
| **Primary VMM** | **Cloud Hypervisor (CH)**, run as a subprocess over its REST `--api-socket`. Rust/rust-vmm, Apache-2.0/BSD-3. Meets every functional capability; the feature-complete default. |
| **Secondary VMM** | **Firecracker** behind the same trait, for the dense/snapshot tier. Runs in **MMIO mode**, snapshots with UFFD lazy restore. **Fastest warm restore of the three** (≈35 ms) though slowest cold boot. No virtio-fs, no vhost-user-net (so no rootless mode), no nested virt. |
| **Fallback VMM** | **QEMU `q35`** (not `microvm`) as a documented escape hatch and the most-proven nester; full feature set. Snapshot is currently disabled in all configs (§3). C/GPL **binary**, used as an external tool, not linked. |
| **Control plane** | **virtio-vsock + a Rust guest agent as PID 1** (dynamic-glibc by default), framed postcard protocol (`Ready`/`Exec`/`Stdout`/`Stderr`/`Exit`). Host connects with a retry/handshake loop and reconnects after restore. Serial console wired to a per-VM log for panic capture and fast-fail. SSH only as a human debugging fallback. |
| **Shared dirs** | **virtio-fs, one `virtiofsd` per share**, `--readonly` for inputs/binaries, rw for output; `--memory shared=on`; `cache=never`. |
| **Root filesystem** | **erofs read-only image over `virtio-blk`**, shared by all concurrent VMs with **no per-VM copy**; per-VM writes go to a **tmpfs `overlayfs` upper**. erofs has no journal → no recovery writes, no concurrent-mount corruption, and it composes with snapshot (a plain block device, not vhost-user). |
| **Host-served endpoints** | Per-VM **network namespace + tap + `/30`** (privileged) *or* an **in-process smoltcp + vhost-user-net NAT** (rootless). Host test servers reachable, not exposed beyond the VM. Mode chosen via `NetConfig`. |
| **Transparent proxy** | **nftables `TPROXY`** (privileged) or **L4 interception in the smoltcp NAT** (rootless) → a **Rust MITM proxy** (`hyper`+`rustls`, or `hudsucker`) with logging, filtering, pluggable **test doubles**, CA baked into the guest trust store. |
| **Monitoring / limits** | One **cgroup v2 slice per VMM (and per virtiofsd) process**; read `memory.peak`/`memory.current`/`cpu.stat`/`io.stat`; enforce `memory.max`/`cpu.max`/`pids.max`/`io.max`. Rootless runs target a **delegated** subtree; limits are best-effort there. |
| **Guest OS** | Minimal **Debian Trixie (13, kernel 6.12 LTS)** rootfs, from one of two sources feeding the same erofs packer: **OCI pull** by digest (default — host-native, in-Rust, no Docker/containerd), or **`mmdebstrap` inside a builder micro-VM** for the full apt signing chain. |
| **Guest kernel** | **Direct kernel boot** of a custom-minimal `vmlinux` from **Debian kernel source** with an **explicit config fragment** (§8) — virtio (PCI + MMIO) + vsock + virtio-fs + erofs/overlay + optional KVM, all built-in, no initramfs. No project-specific patches. |
| **Speed lever** | **Warm snapshot + restore** off the erofs rootfs, with a tmpfs overlay per test; cold-boot opt-in. Measured ≈7–22× faster than cold boot (§13). |
| **Density levers** | `cache=never` + shared erofs RO base (one host-cached copy for all guests) + **KSM** + **virtio-balloon / free-page-reporting**. **Not DAX** (unavailable in CH, §14). |
| **Dependency posture** | Prefer in-crate Rust over external tools; permissive licenses only (MIT/Apache/BSD); copyleft tolerated only for *binaries* (QEMU, `nft`). Vet with `cargo-deny` on every build. |

---

## Part II — The system, subsystem by subsystem

## 3. VMM backends and the `Vmm` trait

### 3.1 Why a trait plus a capability descriptor

The lifecycle is modeled as a narrow, well-typed contract — `capabilities()` plus `create` / `boot` / `request_shutdown` / `kill` / `snapshot` / `restore` / `stats` — so the finicky, subprocess-supervising, occasionally-`unsafe` VMM glue stays behind a boundary and the orchestrator stays idiomatic and unit-testable (a `FakeVmm` implements the same trait, §10.6). The three backends genuinely diverge — Firecracker has no virtio-fs, no vhost-user-net, and no nested virt — so the contract is **general with a capability descriptor**, not CH-shaped. Each method documents the *behavior*; the backend-specific mechanism stays inside the impl; a backend reports what it supports via `capabilities()`, so an unsupported op returns `Error::Unsupported { vmm, feature }` and the orchestrator (and the test/bench matrix) degrades gracefully rather than assuming CH semantics everywhere. The orchestrator selects a backend per tier from `capabilities()`; the test and benchmark harnesses **skip — never fail** — scenarios a backend cannot run (§12.4 / §13).

Every field of `VmmCapabilities` is a property of the *pinned* VMM build and must be re-confirmed against it (§14), not hard-coded from memory.

### 3.2 The three backends

**Cloud Hypervisor (CH) — the default.** The feature-complete backend: snapshot/restore via `--restore`+`resume`, virtio-fs shares, vhost-user-net (so the rootless smoltcp NAT), and nested virt. Controlled over a hand-written thin REST client (`hyper`/`hyperlocal` over the Unix `--api-socket`, with `serde` types from CH's in-repo OpenAPI YAML). Cold boot ≈324 ms; warm restore ≈47 ms (§13). The lifecycle has two distinct paths: cold = `vm.create` → `vm.boot`; warm = launch with `--restore` → `vm.resume` (**never** `create`/`boot` — CH returns `500 "VM is already created"`). `snapshot` must `vm.pause` first, then snapshot, then `vm.resume` (or stay paused if the VM is about to be killed). CH is supervised and pinned as an external release binary — it is **not** cargo-installable and has no embeddable library crate; only its REST *client* is a crate.

**Firecracker — the dense/snapshot tier.** Its draw is **density (low memory overhead) + snapshot**, and it has the **fastest warm restore of the three** (≈35 ms p50), the metric the per-test hot path actually uses — even though it has the slowest cold boot (≈781 ms). Implemented the same way as CH: a hand-written `hyper`-over-Unix client (not `firecracker-rs-sdk`), with the binary managed as an external pre-compiled download (it needs its containerized `tools/devtool` build, so `cargo install` is not an option). Its device model is deliberately minimal — virtio-{net,block,vsock,balloon,rng,pmem} — so it **cannot do virtio-fs, vhost-user-net, or nested virt**; the orchestrator reads this off `capabilities()` and the test/bench matrix skips those scenarios. Two Firecracker-specific facts:

- **It runs in native MMIO mode** (no `--enable-pci`). The guest kernel ships both virtio-pci (for CH) and virtio-mmio (§8), so one `vmlinux` serves CH over PCI and Firecracker over MMIO. This is what makes Firecracker snapshot-eligible at all: it has no snapshot under PCI. Its restore sequencing differs from CH's — pause/resume is `PATCH /vm` (not `PUT`); restore is a fresh process + `POST /snapshot/load {resume_vm:false}`; drives and vsock may **not** be (re)configured around load, so per-restore identity uses *relative* snapshot paths resolved per sandbox dir. `resume_vm:false` is deliberate: restore returns the VM *paused* and the orchestrator calls `resume()` explicitly, so both backends share the trait's "restore returns paused, caller resumes" shape. The cost is one extra round-trip and a failed-`resume()` zombie risk, reaped by the ordered `Drop`.
- **Extended-FPU restore is constrained at the CPU layer.** Firecracker restore can panic in `restore_fpregs_from_fpstate` when the guest `glibc` dispatches to aggressive AVX/extended-FPU paths (the saved XSAVE area mismatches on restore). The fix is a static **`T2` CPU template** on the `MachineConfig` (masking `avx512_vnni` and the other extended-state CPUID bits) plus **`noxsave`** on the guest kernel command line as an independent fallback. This keeps the `trixie` base — the bug is a Firecracker extended-state limitation that any modern-`glibc` base triggers, so the durable fix lives in CPUID, not the OS version (history and the rejected `bookworm` downgrade are in Appendix A). The trade-off to record: `noxsave` is broader than the template — it disables guest AVX/AVX2 as well as AVX-512 (SSE2 floor), whereas the template leaves AVX2 usable. That is a **test-fidelity** cost: software that dispatches to AVX/AVX2 runs its scalar/SSE2 paths inside a Firecracker VM, so SIMD-correctness-sensitive tests belong on the **CH tier** (full vector ISA, no `noxsave`), with Firecracker reserved for density/snapshot workloads.

**QEMU `q35` — the fallback and most-proven nester.** Full feature set (virtio-fs, vhost-user-net, nesting). Use **`q35` with `virtio-net-pci`**, not `microvm`: `microvm`'s `virtio-net-device` falls back to the legacy 10-byte virtio-net header (vs the modern 12-byte mergeable-rx header) and breaks guest networking. Snapshot is currently **disabled in all configurations** (`snapshot_restore: false`): the rootless vsock path uses an external `vhost-device-vsock` daemon, a stateless vhost-user backend that cannot migrate, so QEMU is snapshot-ineligible over the vsock control plane the harness uses (§3.3); a privileged kernel-`vhost-vsock` config is the only avenue to QEMU snapshot and is itself unvalidated, so a `restore()` impl exists but is dead code behind the capability gate. Wiring the rootless smoltcp NAT to QEMU also requires a `[patch.crates-io]` fork of `vhost-user-backend` + `vhost` to relax a `PROTOCOL_FEATURES` check (§10.4). Cold boot ≈1126 ms.

### 3.3 The snapshot-eligibility law

Every snapshot finding across the project reduces to one rule:

> **A VM is snapshot-eligible only if no vhost-user device is attached to it — and, for Firecracker, only under MMIO.**

Any external vhost-user backend is, by construction, a separate stateless process the VMM cannot migrate, so it severs the snapshot. The practical consequence: **the warm-snapshot tier is {CH, Firecracker} on the privileged/tap network path with a non-vhost-user vsock transport.** Any feature that requires a vhost-user device — the rootless NAT (vhost-user-net) or virtio-fs *data* shares (virtiofsd) — is mutually exclusive with snapshot on the same VM. CH's base control-plane vsock is safe because it is CH's *userspace* implementation, not vhost-user; Firecracker's built-in vsock is likewise migratable.

| Backend + config | Snapshot-eligible? | Why |
|---|---|---|
| **CH** + erofs-block rootfs + userspace vsock + tap net | **Yes** | no vhost-user device in the path; the validated default snapshot tier |
| **CH** + a virtio-fs **data** share attached | **No** | `virtiofsd` is a vhost-user device — serve RO data as an extra erofs/block image in the snapshot tier instead |
| **CH** or **QEMU** + rootless smoltcp NAT (vhost-user-net) | **No** | the NAT is a vhost-user-net backend — rootless mode is not the snapshot path |
| **Firecracker** + MMIO + built-in vsock + tap net | **Yes** | native MMIO snapshot; vsock/balloon/rng/block are built-in, not vhost-user — plus the §3.2 extended-FPU CPU-template guard |
| **QEMU** + rootless external `vhost-device-vsock` | **No** | the external vsock daemon is a stateless vhost-user backend that cannot migrate |
| **QEMU** + privileged kernel-`vhost-vsock` | **Likely, unvalidated** | no vhost-user device in the vsock path; needs the privileged path, not yet tested |

The orchestrator reads this off `capabilities()` and the test/bench matrix skips the impossible combinations rather than discovering them at runtime.

### 3.4 Capability matrix

To re-confirm against the pinned builds (§14):

| Capability | CH | Firecracker | QEMU |
|---|---|---|---|
| `snapshot_restore` | ✓ (PCI) | ✓ (MMIO) | ✗ in all configs today (rootless vhost-user-vsock; privileged path unvalidated) |
| `lazy_restore` (demand-paged) | ✓ (`memory_restore_mode`) | ✓ (UFFD) | — |
| `virtio_fs_shares` | ✓ | ✗ (block-only) | ✓ |
| `rootless_vhost_user_net` | ✓ | ✗ | ✓ |
| `nested_virt` | ✓ | ✗ | ✓ |
| cold boot (p50, §13) | ≈324 ms | ≈781 ms | ≈1126 ms |
| warm restore (p50, §13) | ≈47 ms | ≈35 ms | N/A |

The cold-boot/restore inversion pins each backend's role precisely: **Firecracker is slower to cold-boot but fastest to restore**, so it earns the density+snapshot tier (the hot path); **CH stays the feature-complete default and cold-boot leader**; **QEMU is the fallback** for the awkward cases.

---

## 4. Control plane: vsock and the guest agent

### 4.1 The protocol

`agent::protocol` defines a small length-prefixed, `serde`+`postcard`-framed message enum (host and guest standardize on postcard's length-delimited framing): `Hello`/`Ready`, `Exec{argv,env,cwd}`, `Stdout(bytes)`, `Stderr(bytes)`, `Exit(i32)`, `PutFile`, `Ping`. This module is the *only* code shared between the host and the guest agent, keeping "all functionality in one library crate" essentially true while the guest binary stays thin.

### 4.2 The host: `AgentClient`

`connect` opens the host-side vsock endpoint and performs the **readiness handshake**, retrying with backoff until the guest is listening and has sent `Ready`, OR a timeout elapses, OR the serial log shows a kernel panic (fail fast). The transport is uniform across all three backends: CH and Firecracker expose a host AF_UNIX socket with the **Firecracker-style hybrid-vsock handshake** (the host writes `CONNECT <port>\n`, expects `OK <port>\n`); the QEMU backend uses vhost-user-vsock so `vsock_path()` stays a Unix path and the handshake is identical. CH (and Firecracker) accept the Unix-socket connection *before* the guest has booted and bound, so the retry belongs at the handshake level, not around a single `connect()`.

Two invariants the protocol depends on:

- **Read the `OK <port>\n` line with exact 1-byte reads, never a buffered reader.** The framed protocol follows immediately on the *same* stream, so a `BufReader` that reads the line pre-fetches the first framed payload into its buffer, which is then silently discarded when the reader is dropped before handing the raw stream to the codec — manifesting as a mysterious connection timeout. Read exactly up to the `\n`, then pass the unbuffered stream to the codec.
- **`reconnect` after restore is not a no-op.** All restorable backends reset the vsock device on restore, so the prior connection is dead (the guest sees EOF): CH re-creates the host socket; Firecracker closes open connections and bumps the `guest_cid`. On both, the guest's LISTEN socket survives, so reconnect is fast — but the old client must be dropped and a new connection opened to the new endpoint.

`exec` runs a command, streams stdout/stderr, and returns the exit status. Its timeout is **per-request** (`ExecRequest.timeout`), defaulting to **10 s** for ordinary commands and set long only for the builder-VM `apt`/`mmdebstrap` call — never a single global constant, which would force every test exec to wait minutes before failing.

### 4.3 The guest: `imp-guest-agent` as PID 1

The agent runs as the `init=` target (`init=/sbin/imp-guest-agent`). Because it executes as PID 1 on an already-mounted rootfs that ships `libc6` (any Debian base), the default build is **dynamically linked against the rootfs glibc** — no extra toolchain. A fully static `musl` build is optional (for a rootfs-independent agent) but needs `musl-tools`, which is not installable without root in some CI environments. Its PID-1 contract is larger than "serve the protocol," and missing any of it is painful to debug:

- mount `proc`, `sys`, `devtmpfs`, the virtio-fs tags, and set up the **tmpfs `overlayfs`** over the read-only erofs root;
- install the proxy CA into the trust store and bring up loopback. **The guest address is set by the kernel `ip=` boot parameter** (`CONFIG_IP_PNP=y`, §8), in both privileged tap and rootless smoltcp modes, so PID 1 needs **no netlink**. Agent-side network bring-up survives only as a guarded, last-resort fallback;
- **reap zombies** (`SIGCHLD`/`waitpid`) — PID 1 is the universal reaper; skip this and the guest fills with defunct processes;
- **never exit** — if PID 1 returns, the kernel panics with "init died";
- **fork** the test command as a child (not `exec` into it) so the agent stays PID 1 and retains the control channel and reaping duty;
- a **boot-time self-check** probing for the device nodes / FS support it depends on (vsock, virtio-fs), emitting a clear diagnostic before binding so a missing-kernel-symbol regression fails legibly instead of as a raw errno panic;
- **serve connections in a loop, not one-shot:** after a snapshot restore the host reconnects on a freshly re-created vsock socket, so the agent must detect the old connection's EOF, return to `accept`, and handle the next client.

The serial console is wired to a per-VM log for panic capture and fast-fail; SSH is a human-only debugging fallback, never the control plane.

---

## 5. Root filesystem and shared directories

### 5.1 The erofs read-only base + tmpfs overlay

The rootfs is a **single read-only erofs image over `virtio-blk`**, shared by all concurrent VMs with **no per-VM copy**; per-VM writes go to a **tmpfs `overlayfs` upper**. This one artifact serves every path — cold boot, concurrent shared mounts, and the snapshot tier — because erofs over virtio-blk is read-only, shareable, and snapshot-eligible (it is a plain block device, not vhost-user). erofs has **no journal**, which removes two failure modes an earlier ext4-clone-per-VM design hit: journal-recovery panics on read-only mounts, and concurrent-mount corruption. It is also a density lever: the host page cache holds a single copy of the image for all concurrent guests (the partial recovery of the page-cache-sharing benefit DAX would have provided, which is unavailable, §14).

If a writable *disk* overlay is ever needed (rare, given the tmpfs overlay), use reflink/qcow2-backing rather than a full copy — minding that `FICLONE` works on **XFS or Btrfs**, not ext4, where it silently degrades to a full copy. Using **virtiofs as an overlayfs lowerdir** is a known sharp edge (historically needs redirect_dir/metacopy) and is avoided — another reason the RO base is erofs, not a virtio-fs mount.

### 5.2 virtio-fs data / binary / output shares

Shared directories use **virtio-fs, one `virtiofsd` per `Share`**, each on its own Unix socket, with `--readonly` for `ReadOnly` shares (the flag is `--readonly`, *not* `--read-only`, which aborts the daemon) and a `--sandbox namespace` + dedicated uid so a daemon can reach only its one directory. The orchestrator emits the `--fs tag=…,socket=…` config and ensures `--memory shared=on`; cache policy defaults to `never` for density. The standard shares are `imp-in` (ro, per-test input), `imp-bin` (ro, shared across all tests so its pages stay hot — Imp's binaries arrive here, so a new Imp build does not invalidate the rootfs), and `imp-out` (rw, per-test output).

**Subprocess-supervision invariant:** a misconfigured `virtiofsd` exits immediately, but if the orchestrator only polls for the socket file, CH hangs forever waiting for the vhost-user socket — so the supervisor must surface the child's exit/stderr *and* bound the socket-wait with a timeout.

**Snapshot interaction:** attaching virtiofsd (a vhost-user device) makes a VM snapshot-ineligible (§3.3), so the snapshot tier attaches data shares only if post-restore attach is validated; otherwise it serves the same read-only data as an additional erofs/block image. An in-process `fuse-backend-rs` alternative (Appendix B, Exp 1) is gated behind `experiment-fuse` with the daemon as the fallback; it does **not** yet enforce read-only, an open correctness gap (§15).

---

## 6. Networking and egress

### 6.1 Two modes, chosen by `NetConfig`

**Privileged (`tap`).** A per-VM network namespace, a `veth`/tap pair, and a `/30` (`10.200.<vmid>.0/30`, host `.1`, guest `.2`) via `rtnetlink`. Full L2 fidelity; needs `CAP_NET_ADMIN`. This is the default for fidelity-sensitive tests and the only network path eligible for the snapshot tier (§3.3).

**Rootless (`userspace`).** An in-process **smoltcp** TCP/IP stack behind a `vhost-user-backend` vhost-user-net device — no tap, no `CAP_NET_ADMIN`. Lower-fidelity (a userspace stack), so it is reserved for deployability rather than fidelity-sensitive tests, and it cannot be snapshotted (vhost-user-net, §3.3). Four invariants make it work, worth encoding because each one wedges the link silently:

1. smoltcp silently drops a broadcast frame whose *source* MAC equals the interface MAC, so the host NAT MAC is pinned to `02:00:00:00:00:fe` to avoid colliding with the guest's vmid-derived MAC;
2. iterate the virtio RX descriptor chain **only when the NAT actually has packets queued** for the guest — iterating `vring.iter()` consumes/advances `avail_idx`, so polling it while empty discards the guest's RX buffers and permanently wedges the link;
3. call `enable_notification()` on the TX queue inside the `handle_event` loop so the guest knows to kick the eventfd for the next packet;
4. size the smoltcp socket pool for concurrent *and* keep-alive connections (≈16 sockets per forwarded port), not one-per-port — a single `TcpSocket` per port means an HTTP keep-alive connection holds the only slot and the next connection gets `Connection refused`.

(`passt` was the first choice and is **incompatible with CH** — its C seccomp filter drops the `accept4` that CH's vhost-user connection needs, with no opt-out; Appendix B, Exp 5.)

The `/30` math is a pure function and unit-tested; the netlink calls, the `nft` invocation, and the smoltcp NAT's packet loop are the side-effecting part.

### 6.2 Host-served endpoints

A host test server bound to the per-VM gateway/host address is reachable from the guest and not exposed to other systems. Per-test server config and dynamically-assigned ports are configured *after* the server is listening. Arbitrary TCP/UDP works. vsock is available as an alternate, IP-stack-free host↔guest channel.

### 6.3 The transparent egress proxy

A `hyper`-based MITM proxy (`hudsucker` supplies the whole MITM stack — `hyper`+`rustls`+`rcgen`, Apache/MIT). For HTTP it splices/logs; for HTTPS it terminates TLS with an on-the-fly cert minted by an in-memory CA (`rcgen`) and re-originates upstream. The CA is baked into the guest trust store, so HTTPS interception works in both networking modes. `doubles` lets a test register `(Matcher, Responder)` pairs (and, for the eval layer, record/replay cassettes). HTTPS test doubles must **ignore `hyper::Method::CONNECT`** — matching on the `CONNECT` itself breaks the tunnel and yields a TLS "unexpected eof."

The proxy *process* is mode-independent; how traffic is *steered into it* is not, so the module exposes one proxy with two front-ends:

- **Privileged:** an nftables **`TPROXY`** ruleset (`tproxy to :<port> meta mark set 1 accept`, plus `drop`/`log`), rendered in Rust and applied via the external `nft -f -` binary — no permissive pure-Rust nftables crate covers the `tproxy`/`socket` expressions (§10.4). TPROXY carries the original destination *in the socket* (no conntrack lookup), preserves the original source, and handles **UDP** (transparent QUIC/HTTP-3 on udp/443). The assertion that matters, and what the test checks, is that the proxy observes the guest's intended destination.
- **Rootless:** egress interception at **L4 inside the smoltcp NAT** (cleaner than a privileged front-end, since there is no tap for nftables).

### 6.4 The networking-privilege fork

`sudo -E cargo test` is global — it runs the whole toolchain as root, taints `target/` with root-owned artifacts, and shifts cargo's environment. The privileged suite instead runs through the **capability runner** `imp-test-runner` (§12.8), which grants only `CAP_NET_ADMIN`+`CAP_SYS_ADMIN` to the test binary while leaving cargo/rustc unprivileged and outputs dev-owned (`sudo -E` or a dedicated root job remains the CI-only fallback). The rootless path runs as its own suite needing no elevation — keeping it separate is the only way it stays honestly exercised. Note that modern Ubuntu blocks the unprivileged-userns escape hatch by default (`kernel.apparmor_restrict_unprivileged_userns=1`), while Debian Trixie does not necessarily, so the host distro affects whether rootless even gets off the ground.

---

## 7. Monitoring and limits

One **cgroup v2 slice per VMM (and per virtiofsd) process** (via `cgroups-rs`), with `ResourceLimits` applied and `memory.peak`/`memory.current`/`cpu.stat`/`io.stat` plus net counters read back. Peak comes for free from `memory.peak`; average is computed from periodic `cpu.stat`/`io.stat` deltas. The mapping is direct: `mem_max_mib`→`memory.max`, `cpu_max_pct`→`cpu.max`, `pids_max`→`pids.max`, `io_max`→`io.max`.

**Rootless delegation has sharp edges**, and they compound:

- `cgroups-rs`'s `CgroupBuilder` defaults to creating cgroups at the *root* (`/sys/fs/cgroup/imp-vm-XXX`), which fails `EPERM` unprivileged. The orchestrator reads `/proc/self/cgroup` and nests the VM cgroup inside the runner's systemd-delegated slice (`Delegate=yes`).
- The cgroup-v2 **"no internal processes"** rule then bites: a cgroup may hold processes *or* enable controllers for children, not both — and the `cargo test` process is itself internal — so the VM cgroup must be a **sibling** of the runner (move the runner into a `…/supervisor` leaf and place VM cgroups beside it), not a child.
- `cgroups-rs`'s `add_task()` raises a `CgroupMode` error on deeply nested unprivileged cgroups (and can hang), so the PID is written **directly** via `std::fs::write(cgroup/"cgroup.procs", pid)`.
- **The `memory` controller may simply not be delegated** to an unprivileged runner at all. Where it isn't, `memory.high` writes fail with `Operation not supported`. This is an *environment* limit, not a code defect, so the design **degrades gracefully**: read `memory.current`/`memory.peak` straight from sysfs (bypassing `cgroups-rs`, which assumes the controller is present), surface a failed limit-set as a logged `limits_enforced: bool` capability gap rather than a hard error, and reserve hard memory-limit enforcement for the privileged path or a runner with confirmed `systemd-run --user -p MemoryMax=` delegation.

**Requirement-6 memory limits are therefore best-effort in rootless mode and may be a no-op**; the privileged path enforces them.

---

## 8. Guest OS and kernel

### 8.1 The base: Debian Trixie

The guest is a minimal **Debian Trixie (13, kernel 6.12 LTS)** rootfs. Debian 13 carries security support to 2028. The agent bypasses distro init (`init=/sbin/imp-guest-agent`), so a larger userland does not grow the boot working set.

### 8.2 Two rootfs sources, one erofs packer

Both sources produce a merged rootfs **tar**, which feeds a **shared tail**: inject `imp-guest-agent` + the proxy CA + the tmpfs/overlay scaffolding, then stream the tree through `am-fs-erofs` in memory (the `mkfs.erofs` binary is the fallback). The in-memory pack avoids creating device nodes or root-owned files on the host, so it runs **unprivileged**.

- **Default — OCI pull (host-native, in-Rust).** Resolve a Debian base image to a **manifest digest** (pin the digest, never the tag), pull manifest + config + layers with `oci-client` (no Docker/containerd daemon), verify every blob against its `sha256` digest, decompress each layer (`flate2`/`zstd`), and apply them in order honoring **OCI whiteout semantics** (`.wh.<name>` deletions and `.wh..wh..opq` opaque-dir markers) to produce the merged tar. The guest never sees OCI — this is OCI strictly as a *build-time source* feeding the erofs packer, so direct-kernel boot, snapshot/restore, and shared-RO-erofs density are unchanged. The only new linked crate is `oci-client` (Apache-2.0).
- **Full apt chain — `mmdebstrap` inside a builder micro-VM.** Build a builder rootfs via the OCI source (stock `debian:trixie-slim` + the agent), boot it on this project's own CH stack, then over the vsock agent run `apt-get install mmdebstrap` followed by `mmdebstrap` against the pinned snapshot — emitting the target rootfs as a tar on the `imp-out` rw share, which feeds the shared inject+pack tail. Because `mmdebstrap` runs as root inside a controlled guest, apt performs the full `InRelease`/`Release.gpg` chain verification in-guest (refuse-on-mismatch), Debian fidelity and `snapshot.debian.org` timestamp-reproducibility are preserved, and **`mmdebstrap`, `apt`, `gpg`, and the shell all leave the host entirely**.

The **bootstrap chain is acyclic and terminates**: kernel + OCI-built builder rootfs → builder VM → in-guest `mmdebstrap` → target tar → erofs. The OCI source needs no VM, so the recursion bottoms out there. The builder-VM boot is a build-time cost paid once per pin and cached; it does **not** touch per-test running time or VM density. The trade between the two sources is provenance vs convenience: the OCI default's digest pin is *integrity, not authenticity* unless a cosign/sigstore signature is also verified; the in-VM `mmdebstrap` source keeps the full apt signing chain for images that need it. Choose per profile and book the signing-chain drop as the explicit cost when using the OCI default (the resolution is detailed in Appendix B, Exp 4).

### 8.3 The guest-kernel config fragment

Direct-boot a custom-minimal `vmlinux` built from **Debian kernel source** with an explicit `microvm` fragment — **not** `kvm_guest.config` alone, which omits vsock, virtio-fs, and erofs and causes real boot failures (the first symbol gap shows up as `EAFNOSUPPORT` at vsock; the same class of failure waits at virtio-fs and erofs). Everything the guest needs is built **in** (`=y`, no modules → no initramfs, nothing to probe):

```text
# Transport — CH uses virtio-pci; ALSO build virtio-mmio so Firecracker runs in
# MMIO mode and snapshots (one vmlinux serves CH over PCI and Firecracker over MMIO;
# FC cannot snapshot under --enable-pci, so the MMIO path is what unblocks it — §3.2)
CONFIG_PCI=y  CONFIG_VIRTIO=y  CONFIG_VIRTIO_PCI=y  CONFIG_VIRTIO_MMIO=y
# Core paravirtual devices
CONFIG_VIRTIO_BLK=y  CONFIG_VIRTIO_NET=y  CONFIG_VIRTIO_CONSOLE=y
CONFIG_HW_RANDOM_VIRTIO=y          # virtio-rng — also feeds the snapshot entropy reseed
CONFIG_VIRTIO_BALLOON=y            # density lever
CONFIG_IP_PNP=y                    # guest IP via kernel `ip=` cmdline → PID 1 needs no netlink
# vsock control plane  — MISSING from kvm_guest.config (caused EAFNOSUPPORT)
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
- **erofs compression must match.** If the erofs builder compresses with lz4/zstd, the kernel needs the matching decompressor (`CONFIG_EROFS_FS_ZIP` for lz4; `…_ZIP_ZSTD`/`…_ZIP_LZMA`/`…_ZIP_DEFLATE` as applicable) or the mount fails. Building uncompressed sidesteps the dependency at a size/page-cache cost.

### 8.4 The kernel command line

```text
console=ttyS0 root=/dev/vda rootfstype=erofs ro
ip=10.200.<vmid>.2::10.200.<vmid>.1:255.255.255.252::eth0:off
init=/sbin/imp-guest-agent
```

The `ip=` parameter (enabled by `CONFIG_IP_PNP=y`) sets the guest address at boot — consumed by the kernel's IP-PNP late-initcall, not an initramfs — so PID 1 needs no netlink in either networking mode (the rootless smoltcp NAT uses a matching subnet). Nested virt adds `kvm-intel.nested=1` on the guest cmdline (and the host KVM module needs `nested=1`). If a block-ext4 fallback rootfs is ever used, add `rootflags=noload` so the ext4 driver mounts strictly read-only without journal recovery — recovery is a write and panics on a read-only device; erofs has no journal, so the default path needs no such flag.

---

## 9. Snapshot, restore, and density

### 9.1 The warm-snapshot path

The per-test speed lever is **warm snapshot + restore**: boot the erofs-rootfs base to "agent-ready," snapshot once, and per-test restore + add a tmpfs overlay. This skips kernel boot on the hot path and is measured at ≈7–22× faster than cold boot (§13). The erofs RO base needs **no per-test copy** (it is shared read-only), virtio-fs data shares avoid image copies (just re-point a daemon), and the only writable per-test state is a tmpfs overlay. The snapshot tier is {CH, Firecracker} on the privileged/tap path with a non-vhost-user vsock (§3.3). The mechanics: snapshot = `pause`→snapshot→(`resume` or stay paused for immediate kill); restore returns a **paused** instance the caller `resume()`s — never `boot()`/`create()`.

### 9.2 Restore correctness

A restored snapshot resumes at the exact instruction it was taken, so restored clones share whatever state was frozen in. Three things must be refreshed on **every** restore, not just at first boot:

- **Identity** — rotate the vsock CID and MAC/IP so restored clones don't collide.
- **Entropy** — reseed via virtio-rng (rotate the RNG state / surface a VMGenID-style change). An unreseeded `getrandom()` can stall first use by seconds, and because every clone resumes at the same frozen instant, RNG reuse is otherwise silent and correlated.
- **Clock** — a snapshot resumed much later resumes with a stale wall clock. kvm-clock keeps the *monotonic* source sane, but the RTC/wall clock is frozen at the snapshot instant. The guest **cannot fix this from inside**: `hwclock --hctosys` reads the *restored* RTC (the old snapshot time) and sets the system clock *backwards*; and a restored snapshot may have networking disabled, so there is no in-guest NTP either. The resync is therefore **host-driven and mandatory for any time-sensitive test**: immediately after the post-restore vsock reconnect, the host reads `SystemTime::now()` and pushes it to the agent, which sets the clock (e.g. `date -s`). For purely ephemeral tests a stale clock is cosmetic; for anything that asserts on timestamps it is not.

The post-restore vsock reconnect itself is mandatory and not a no-op (§4.2).

### 9.3 Density levers

RAM is the binding limit on parallelism. With DAX unavailable in CH (§14), density rests on:

- **`cache=never`** on virtio-fs shares (minimal footprint).
- **The shared erofs RO base** — one host-cached copy of the image for all concurrent guests (§5.1).
- **KSM** (`merge_across_nodes=0` on NUMA; budget ≈5–10% CPU for `ksmd`).
- **virtio-balloon / free-page-reporting** for reclaim under host pressure.

Plan with **128–256 MiB/guest as a must-re-benchmark figure** — the guest userland, not the ≤5 MiB VMM overhead, dominates. The next limits after RAM are typically one-virtiofsd-per-VM (mitigated by the in-process `fuse-backend-rs` experiment), tap/bridge/nft (or the in-process NAT's per-VM threads) scaling, and host FD/PID limits. Each lever's effectiveness is itself a tracked number (§13.5).

---

## 10. The Rust library (`imp_testing`)

This section covers the crate layout, the public API surface, each module's responsibility, the in-crate-vs-external-tool decision per capability, and the accommodations that make the orchestrator unit-testable.

### 10.1 Crate and workspace layout

One Cargo **package**, 2024 edition, with one **library crate** plus **binary** targets that wrap it:

```
imp-testing/
├─ Cargo.toml                 # edition = "2024"; [lib] + [[bin]] targets
├─ deny.toml                  # cargo-deny: permissive-license allow-list, advisory DB
├─ rustfmt.toml               # clippy is config-via-CI
├─ README.md                  # external tools + Debian install instructions
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
│  │  ├─ mod.rs               # NetConfig dispatch: privileged vs rootless
│  │  ├─ tap.rs               # netns + tap + /30 addressing (rtnetlink); nft TPROXY emission
│  │  └─ userspace.rs         # rootless: smoltcp + vhost-user-backend NAT (L4 interception)
│  ├─ proxy/
│  │  ├─ mod.rs               # EgressProxy: listen, log, filter, dispatch
│  │  ├─ tls.rs               # MITM CA, on-the-fly cert minting (rcgen/rustls)
│  │  └─ doubles.rs           # test-double + record/replay (cassette) hooks
│  ├─ metrics.rs              # cgroup v2 slice mgmt + peak/avg readers (cgroups-rs)
│  ├─ artifact/
│  │  ├─ mod.rs               # Stage trait, Pipeline, cache, record/replay, signing
│  │  ├─ kernel.rs            # vmlinux build stage (+ the config fragment, §8)
│  │  ├─ rootfs/
│  │  │  ├─ mod.rs            # rootfs build stage: source dispatch, shared agent+CA inject, erofs pack
│  │  │  ├─ oci.rs            # default source: pull by digest, verify blobs, apply layers (whiteouts) → tar
│  │  │  └─ mmdebstrap_vm.rs  # full-apt source: drive `mmdebstrap` inside a builder micro-VM, collect tar
│  │  └─ snapshot.rs          # warm-snapshot build stage
│  ├─ orchestrator.rs         # TestVm handle tying it together; ordered Drop teardown; sweeper
│  └─ error.rs                # crate Error/Result (thiserror)
├─ src/bin/
│  ├─ imp-testing.rs          # CLI wrapping the lib (clap): build, run, exec, ls, rm …
│  ├─ imp-guest-agent.rs      # guest PID 1 (dynamic-glibc default; static-musl optional)
│  ├─ imp-test-runner.rs      # privileged-test cap runner (§12.8): file-caps → ambient caps → exec as dev uid
│  └─ bench-vm.rs             # macro/VM-level benchmark harness (§13); shares the cap runner
└─ tests/                     # one integration test per capability / VM operation
   ├─ boot.rs                 ├─ exec_vsock.rs        ├─ shares_ro_rw.rs
   ├─ host_endpoint.rs        ├─ egress_proxy.rs      ├─ metrics_limits.rs
   ├─ nested_virt.rs          ├─ snapshot_restore.rs  └─ lifecycle.rs
```

`imp-guest-agent` and `imp-test-runner` are deliberately thin. The agent shares only the small `agent::protocol` module with the host. The cap runner must be **blessed** once with privileges (file caps or setuid) and that blessing is stripped whenever the file is rewritten, so it must almost never rebuild: it depends only on `rustix` + `capctl`, pulls in no async runtime and **not** the `imp_testing` library, and has no edge to `lib.rs`, so library churn never recompiles it. Keeping it tiny is also a security property — every dependency is code that runs inside the privileged window.

### 10.2 Public API surface

Types are `#[non_exhaustive]` where future fields are likely; builders keep call sites stable. Async is via native `async fn` in traits; `#[async_trait]` only where `dyn Vmm` object-safety is required.

```rust
// ---- config.rs ------------------------------------------------------------
#[derive(Clone, Debug)]
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
    pub limits: ResourceLimits, // cgroup caps
}
impl VmConfig { pub fn builder(kernel: impl Into<PathBuf>) -> VmConfigBuilder { /* … */ } }

#[derive(Clone, Debug)]
pub struct Share {
    pub tag: String,            // guest mount tag, e.g. "imp-in"
    pub host_path: PathBuf,
    pub access: Access,         // ReadOnly | ReadWrite
    pub cache: CachePolicy,     // Never (default) | Auto | Always
}
pub enum Access { ReadOnly, ReadWrite }

#[derive(Clone, Debug)]
pub enum NetConfig {
    /// Full L2 fidelity; needs CAP_NET_ADMIN (capability runner / privileged CI).
    Privileged { egress: Egress, host_services: bool },
    /// Rootless via an in-process smoltcp NAT; egress interception at L4 inside the NAT.
    /// Needs capabilities().rootless_vhost_user_net (not Firecracker).
    Rootless   { egress: Egress, host_services: bool },
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
    /// is false. Takes cfg because restoring (and, for QEMU, re-launching) must reconstruct the device
    /// topology — the virtio-fs daemons, the rootfs/block args, the net wiring — which lives in the
    /// config, not the snapshot file. The MECHANISM is backend-specific and kept out of this contract:
    /// CH launches a new process with --restore then needs an explicit vm.resume; Firecracker (MMIO)
    /// POSTs /snapshot/load {resume_vm:false} (leaving the VM paused, symmetric with CH) and may NOT
    /// (re)configure drives/vsock around load, so per-restore identity uses relative snapshot paths;
    /// QEMU reports snapshot_restore:false in all configs today. All restorable backends reset the
    /// vsock device on restore — see AgentClient::reconnect.
    async fn restore(&self, snapshot: &Path, cfg: &VmConfig, res: &PerVmResources) -> Result<Self::Instance>;
}

/// Backend capability descriptor. Each field is a property of the PINNED VMM build and must be
/// re-confirmed against it, not hard-coded. An optional op invoked on a backend that lacks it
/// returns Error::Unsupported { vmm, feature } rather than panicking.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct VmmCapabilities {
    pub snapshot_restore: bool,         // CH ✓; Firecracker ✓ via MMIO; QEMU ✗ in all configs today.
    pub lazy_restore: bool,             // demand-paged restore: CH memory_restore_mode, Firecracker UFFD.
    pub virtio_fs_shares: bool,         // CH, QEMU. NOT Firecracker (block-only).
    pub rootless_vhost_user_net: bool,  // smoltcp NAT via vhost-user-net: CH, QEMU. NOT Firecracker.
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
    /// sees EOF); the guest's LISTEN socket survives, so this is fast — but NOT a no-op.
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
    pub limits_enforced: bool,  // false when the cgroup controller wasn't delegated (rootless, §7)
}

// ---- orchestrator.rs ------------------------------------------------------
/// The handle most tests hold. Owns all per-VM resources; Drop force-cleans in order.
pub struct TestVm<V: Vmm> { /* instance, cgroup, net, virtiofsd procs, cid, overlay */ }
impl<V: Vmm> TestVm<V> {
    pub async fn start(vmm: &V, cfg: VmConfig, ids: Arc<VmidAllocator>) -> Result<Self>; // allocator INJECTED, shared
    pub fn vmid(&self) -> u32;                          // cheap Copy metadata
    pub fn proxy(&self) -> &EgressProxyHandle;
    pub async fn agent(&mut self) -> Result<&mut AgentClient>;
    pub async fn usage(&self) -> Result<ResourceUsage>;
    pub async fn shutdown(self) -> Result<()>;          // graceful, then verify gone
    // NOTE: agent() borrows all of TestVm mutably for the lifetime of the returned ref, so read the
    // cheap immutable metadata (vmid/proxy) into locals BEFORE calling agent(), or hand the agent
    // handle out disjointly. vmid()/proxy() stay &self/Copy so the read-first pattern is always available.
}
impl<V: Vmm> Drop for TestVm<V> { /* kill VMM proc-group → virtiofsd → tap/netns/cgroup/overlay/sockets */ }

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

- **`config`** — Pure data + builders. No I/O, so trivially unit-tested: builder defaults, validation that share tags are unique, that a virtio-fs *rootfs* combined with snapshotting is rejected, that `vcpus`/`mem_mib` are nonzero and the kernel path nonempty. `build()` returns `Result` and validates — not a bare struct.
- **`vmm`** — The trait boundary and backends (§3). `cloud_hypervisor` owns process spawning, the REST payload, lifecycle calls, counters, and snapshot/restore. `firecracker`/`qemu` are feature-gated, implement the same traits, and differ in mechanism and what `capabilities()` reports. A backend invoked for an op it does not advertise returns `Error::Unsupported`, never a panic.
- **`agent`** — `protocol` is the shared framed enum; `mod` is the host client with the hybrid-vsock handshake, retry, and serial-panic watch (§4). The guest side in `src/bin/imp-guest-agent.rs` runs as PID 1 (§4.3).
- **`fs`** — virtiofsd supervision: one per share, perms, tags, sockets, the socket-wait timeout, and the snapshot caveat (§5.2). The in-process `fuse-backend-rs` alternative lives here behind `experiment-fuse`.
- **`net`** — Two implementations behind `NetConfig` (§6): `tap` (privileged netns+tap+`/30` via rtnetlink, nft TPROXY emission) and `userspace` (rootless smoltcp + vhost-user-backend NAT with L4 interception). Pure parts (the `/30` math, the nft-ruleset render) are unit-tested; the netlink calls, the `nft` invocation, and the packet loop are the side-effecting part.
- **`proxy`** — The `hyper`/`hudsucker` MITM proxy with logging, filtering, and doubles; one proxy, two front-ends (§6.3).
- **`metrics`** — The per-VM cgroup v2 slice, limit application, and peak/avg readout, with the rootless-delegation handling and `limits_enforced` degradation (§7).
- **`artifact`** — The staged build pipeline (§11): a `Stage` trait with a pure `cache_key`, a `Pipeline::build` that skips stages whose outputs exist, and `reset_to` for invalidation. The rootfs stage has two interchangeable sources feeding one shared inject+pack tail (§8.2). The in-VM `mmdebstrap` path is the one place the pipeline depends on the runtime (it boots a builder VM via this crate's own machinery); the dependency edge is acyclic because the builder VM's rootfs comes from the OCI source, which needs no VM.
- **`orchestrator`** — `TestVm` composes everything and owns **ordered** `Drop` teardown (VMM proc-group → virtiofsd → tap/netns/cgroup/overlay/sockets), so a panicking test cannot leak host resources and the netns isn't torn down under a live process; a periodic sweeper reaps anything orphaned by a hard crash.
- **`error`** — One `Error` enum (`thiserror`) with variants per subsystem; `Result<T> = std::result::Result<T, Error>`.
- **`bin/imp-testing`** — `clap`-based CLI: `build` / `run` / `exec` / `ls` / `rm` / `stats`. (The library API is the product surface; the CLI subcommands are currently thin pending per-subcommand argument design, §15.)

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
| cgroup v2 limits + peak/avg | parse `/sys` by hand | `cgroups-rs` + `procfs` |
| vsock control channel | `socat`/`ncat` | `tokio-vsock` (host), `vsock` (agent) |
| rootless guest networking | `passt` (CH-incompatible) | `smoltcp` + `vhost-user-backend` |
| pull + unpack a Debian base | `skopeo` / `docker` | `oci-client` + `tar` + `flate2`/`zstd` |
| build the erofs image | `mkfs.erofs` | `am-fs-erofs` (tar→erofs in memory) |

**Cargo-installable binaries, run as subprocesses (not linked).** `virtiofsd` is `cargo install virtiofsd` (a rust-vmm binary, Apache-2.0 AND BSD-3), so shared-directory support needs no OS package. Dev tooling is the rest: `cargo install cargo-deny`, `rustup component add rustfmt clippy`.

**Irreducibly external — OS packages, release binaries, or kernel features.** The README's external-tools section: **`cloud-hypervisor`** (pinned release binary — not cargo-installable, no embeddable crate), **`mmdebstrap`** (no longer a host dependency — runs *inside* a builder VM, §8.2), **`erofs-utils`** (`mkfs.erofs`, now an optional fallback), the **kernel build toolchain** (`gcc`/`clang`, `make`, `flex`, `bison`, `bc`, `libelf-dev`, `libssl-dev`, `cpio`), **`nftables`** (`nft`, applies the privileged TPROXY ruleset), **`qemu-system-x86`** (fallback VMM only), and **KVM** (`/dev/kvm`; host `nested=1` for nested virt).

**Feature-gating for a lean agent.** Heavy host crates are `optional = true` and pulled in by features. The guest agent is built with `--no-default-features --features agent`, so it compiles only `serde`/`postcard`/`thiserror` plus `vsock`/`rustix`/`signal-hook` — no tokio, hyper, or netlink.

Caveats that shaped the choices:

- **nftables has no permissive pure-Rust path today.** `rustables` (the obvious pure-netlink crate) relicensed to **GPL-3.0-or-later** at 0.8, so it is disqualified by the copyleft prohibition and `cargo-deny` would reject it. `nftables-rs` still needs the `nft` binary + `libnftables`; `nftnl-rs` is FFI to C `libnftnl`; the pure-Rust crates are unverified for the TPROXY/`socket` expressions. Since the ruleset is small, fixed, and security-critical, the design renders it in Rust and applies it via `nft -f -` — correctness over purity (a pure-Rust replacement is a future experiment, Appendix B, Exp 2).
- **A carried `[patch.crates-io]` fork of `vhost-user-backend` + `vhost`** is in the tree, needed *only* to attach the rootless smoltcp NAT to QEMU (not CH), where a strict vhost-user `PROTOCOL_FEATURES` check rejects `SET_VRING_ENABLE` arriving before `SET_FEATURES`. It is permissively licensed (rust-vmm, Apache-2.0), so `cargo-deny` is satisfied, but a patched dependency is a maintenance/reproducibility cost: pin the fork to an exact rev, prefer a narrow upstream-tracking patch, and re-evaluate at each bump. **If QEMU-rootless is not a required tier, dropping the patch is the cheaper path** (CH-rootless needs no fork). The `[patch.crates-io]` block must be carried in both the in-doc manifest and the standalone `Cargo.toml` artifact.
- **`oci-client` is Apache-2.0** (the rename of the older `oci-distribution`); its default TLS is rustls, so pin `default-features = false, features = ["rustls-tls"]` to keep OpenSSL out. **`am-fs-erofs` is obscure — confirm its license and maintenance via `cargo-deny`** before it stays in the default path, keeping `mkfs.erofs` as the fallback.
- **`lzma-rs` (pure Rust) vs `xz2` (links `liblzma`).** Debian kernel tarballs are `.tar.xz`. The sketch uses `lzma-rs` to keep it in-Cargo at a speed cost.
- **Trust `cargo-deny`, not hand-written license labels.** An earlier draft mislabeled `rustables` MIT/Apache when it is GPL-3.0-or-later — exactly the class of error the `cargo-deny` allow-list (run on every CI build) exists to catch. The license notes here are guidance; the gate is the source of truth.

**License gate:** `cargo-deny` enforces an allow-list (MIT/Apache-2.0/BSD-3/ISC/Zlib/0BSD/Unicode-3.0) for all *linked* crates and fails the build on copyleft or non-OSI licenses. Build-time tools (`mmdebstrap`, the `mkfs.erofs` fallback, the kernel toolchain), the `nft` binary, and the QEMU fallback are external executables, not linked, so their copyleft status is acceptable.

### 10.5 The `Cargo.toml`

This manifest realizes §10.4: one package (2024 edition) with the library, the CLI binary, and the feature-gated thin agent and cap runner. Heavy host crates are optional so the agent builds lean. Versions are conservative floors — resolve exact pins with `cargo add` and gate the set through `cargo-deny`. Lines flagged `VERIFY` are where a crate may not cover the exact need; the OS-tool fallback is named in §10.4.

```toml
[package]
name = "imp-testing"
version = "0.0.0"
edition = "2024"
rust-version = "1.85"          # 2024-edition baseline; bump to match your toolchain
license = "MIT OR Apache-2.0"
description = "Micro-VM-per-test integration & evaluation platform for the Imp agentic harness"
publish = false

[lib]
name = "imp_testing"
path = "src/lib.rs"

[[bin]]
name = "imp-testing"
path = "src/bin/imp-testing.rs"
required-features = ["cli"]

# Guest PID-1 agent. DEFAULT build: dynamically linked against the rootfs glibc on the host gnu
# target. OPTIONAL fully static build (needs musl-tools, may be unavailable without root in CI):
#   cargo build --release --bin imp-guest-agent --no-default-features --features agent \
#       --target x86_64-unknown-linux-musl
[[bin]]
name = "imp-guest-agent"
path = "src/bin/imp-guest-agent.rs"
required-features = ["agent"]

# Privileged-test capability runner (§12.8). Blessed once (`setcap cap_net_admin,cap_sys_admin+p`);
# blessing is stripped on every rebuild, so it must almost never rebuild — depends only on rustix +
# capctl, NOT the imp_testing lib, so library churn never recompiles it.
[[bin]]
name = "imp-test-runner"
path = "src/bin/imp-test-runner.rs"
required-features = ["test-runner"]

# Micro-benchmark target (§13): criterion harness for pure/IO-light hot-path code.
[[bench]]
name = "micro"
harness = false
required-features = ["pipeline"]

# Macro/VM-level benchmark harness (§13): boots real VMs. A bin (not a [[bench]]) because it needs
# KVM/root; runs on the gated CI job, NOT under `cargo bench`. Emits latency distributions.
[[bin]]
name = "bench-vm"
path = "src/bin/bench-vm.rs"
required-features = ["cli", "cloud-hypervisor", "metrics"]

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

# ---- rootless networking: in-process smoltcp NAT ----
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
toml         = { version = "0.8", optional = true }    # pins.lock + config
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
assert_cmd   = "2"     # exercise the imp-testing CLI end to end
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
default = ["cloud-hypervisor", "net-privileged", "proxy", "metrics", "pipeline", "cli"]

host-common = [
    "dep:tokio", "dep:futures", "dep:bytes",
    "dep:tracing", "dep:tracing-subscriber",
    "dep:tokio-vsock", "dep:nix", "dep:uuid", "dep:which",
]

cloud-hypervisor = ["host-common", "dep:hyper", "dep:hyper-util", "dep:http-body-util", "dep:hyperlocal", "dep:serde_json"]
firecracker      = ["host-common", "dep:hyper", "dep:hyper-util", "dep:http-body-util", "dep:hyperlocal", "dep:serde_json"]
qemu             = ["host-common", "dep:qapi", "dep:serde_json"]

net-privileged = ["host-common", "dep:rtnetlink", "dep:netns-rs", "dep:tun-tap", "dep:ipnet"]
net-rootless   = ["host-common", "dep:smoltcp", "dep:vhost-user-backend"]

proxy          = ["host-common", "dep:rustls", "dep:tokio-rustls", "dep:rcgen", "dep:rustls-pemfile"]
proxy-hudsucker = ["host-common", "dep:hudsucker"]

metrics = ["host-common", "dep:cgroups-rs", "dep:procfs"]

pipeline = [
    "host-common",
    "dep:reqwest", "dep:pgp", "dep:sha2", "dep:blake3",
    "dep:tar", "dep:oci-client", "dep:am-fs-erofs", "dep:flate2", "dep:lzma-rs", "dep:zstd",
    "dep:reflink-copy", "dep:walkdir", "dep:toml", "dep:tempfile",
]
# The mmdebstrap-in-VM source additionally needs a VMM backend feature (it boots a builder VM).

cli = ["host-common", "dep:clap", "dep:anyhow", "dep:serde_json"]

# Guest agent: deliberately omits host-common so it does NOT compile tokio/hyper/etc.
agent = ["dep:vsock", "dep:rustix", "dep:signal-hook"]

# Privileged-test cap runner: like agent, omits host-common and the lib — only syscalls + caps.
test-runner = ["dep:rustix", "dep:capctl"]

experiment-fuse = ["host-common", "dep:fuse-backend-rs", "dep:vhost-user-backend"]
codegen = ["dep:progenitor"]

# ---- carried patch: QEMU-rootless vhost-user only ----
# Relaxes a PROTOCOL_FEATURES check on SET_VRING_ENABLE that QEMU sends before SET_FEATURES finalizes.
# NOT needed for CH-rootless — drop it if the QEMU-rootless tier isn't required. Pin to an exact rev.
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

---

## 11. Artifact build pipeline

Maps onto the VM-artifact-production requirements: staged, pinned, deterministic, cacheable, resettable, minimal external access, record/replay, signing-chain verified. Exposed both as the library `artifact::Pipeline` API and as `imp-testing build [--reset-to STAGE]` on the CLI.

### 11.1 Artifacts produced

1. **`vmlinux`** (per arch): one custom-minimal kernel, direct-boot, drivers built in, optional KVM-for-nesting. Host-side, shared by all VMs; rebuilt only when the config fragment or pinned source changes.
2. **Root filesystem** (per profile): a **single read-only erofs image** packed in memory by `am-fs-erofs` from a merged rootfs **tar**, from one of two interchangeable sources sharing the inject+pack tail (§8.2). That one artifact serves cold boot, concurrent shared mounts, and the snapshot tier. Imp's own binaries are *not* baked in — they arrive over the `imp-bin` virtio-fs share, so a new Imp build does not invalidate the rootfs.
3. **Warm snapshot** (per VMM + profile): boot the erofs-rootfs base to "agent-ready," snapshot. Per-test = restore + tmpfs overlay. The Firecracker snapshot profile applies the `T2` CPU template + `noxsave` extended-FPU guard (§3.2).
4. **Proxy CA cert**: minted once, baked into the rootfs trust store.

### 11.2 Stage model

- **Stage 0 — resolve pins (the only non-deterministic stage).** Determine up-to-date values for a minimal pin set: the **OCI base-image manifest digest** (resolve the tag to a `sha256:…` digest and pin *that*), the Debian package-repo **snapshot timestamp** (via `snapshot.debian.org`, used by the in-VM `mmdebstrap` source), the kernel source version/commit, and the CH/virtiofsd release tags. Output: a small, committed `pins.lock`.
- **Stages 1..n — deterministic given inputs.** Each stage's output is fully determined by its inputs + pins. Examples: fetch+verify kernel source; configure+compile `vmlinux`; then the rootfs source-of-record (OCI: pull+verify the pinned image → apply layers/whiteouts → merged tar; or in-VM: build the builder rootfs via OCI → boot the builder VM → run `mmdebstrap` at the pinned snapshot → collect the target tar — this stage **depends on the compiled `vmlinux`**, so the kernel stage is ordered before it). Both paths converge on the shared tail: inject `imp-guest-agent` + CA → erofs pack → boot+snapshot.
- **Caching.** Each stage has a pure `cache_key` (hash of inputs + pins + stage version); `Pipeline::build` skips a stage whose outputs already exist under that key. `reset_to(stage)` removes the outputs of that stage and all later ones.
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

- **Feature powerset.** `cargo hack --feature-powerset --depth 2 clippy --all-targets`. The single highest-value CI addition for a feature-heavy crate; it catches a dependency imported unconditionally but gated behind a feature (e.g. `cgroups-rs` under `metrics` breaking `--no-default-features --features cloud-hypervisor`). `--all-features` always compiles, so without the powerset that broken combination ships green.
- **Lean-agent invariant, asserted.** A dedicated job builds `--no-default-features --features agent` and asserts `cargo tree -e no-dev` does not contain `tokio`, `hyper`, or `rtnetlink` — guarding the §10.4 promise against accidental re-coupling.
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
| `config::VmConfigBuilder::build()` | returns `Result`; rejects duplicate share tags, virtio-fs-rootfs + snapshot, `vcpus==0`, `mem_mib==0`, empty kernel path |
| per-VM path construction | injective in `(pid, vmid)` *[prop]* — distinct vmids never share `api.sock`/`vsock.sock`/`serial.log` |
| `/30` address math | guest/host/mask correct for `vmid ∈ {0,1,254,255}`; a vmid that would overflow an IPv4 octet is rejected *[prop]* |
| `CidAllocator` | skips reserved 0/1/2; wraps without emitting a live or reserved CID; tracks the in-use set; thread-storm contention test |
| vmid allocator | wrap at 254 consults the in-use set, not just a counter |
| `agent::protocol` codec | round-trips through the `LengthDelimitedCodec` framing, incl. partial buffers and oversized-frame rejection *[prop]* |
| vsock handshake FSM | `Connection refused → OK` retry; **EOF → return to `accept`** (restore survival); serial-log panic → fast-fail |
| CH REST request/response | golden-JSON payload; parser handles chunked, `>4096`-byte, and `201/202/204` responses *[prop on status]* |
| nft ruleset render | golden-text test; asserts the steering form preserves the destination |
| cgroup-path construction | pure: nests under `/proc/self/cgroup`, places the VM cgroup as a *sibling* of the runner |
| `artifact::cache_key` | golden digest pinned to a stable hash; identical across processes and runs (not `DefaultHasher`, which isn't portable across Rust versions) |
| `Error` | `Display` + `From` per variant; `#[non_exhaustive]` compile-guard |
| `SmoltcpProcess` / `EgressProxy` shutdown | a cancellation signal joins the worker within a timeout; `Drop` triggers it |
| `Drop` order | against `FakeVmm`: teardown runs VMM-proc-group → virtiofsd → netns/cgroup/overlay/sockets, and **still runs on `panic!`** |

### 12.4 Integration tests — real environment, default-skipped, per-VMM

**Gating.** Tests needing KVM or `CAP_NET_ADMIN` are `#[ignore]` by default (CI runs them with `--ignored` on a capable runner) and carry `#[serial_test::serial]` when they touch global host state. A laptop `cargo test` therefore runs only the §12.3 unit tests and doctests and stays green. Run the suite under **`cargo nextest` with a per-test timeout** so a hang (the virtiofsd-socket-wait or a `cgroups-rs add_task` hang) fails as a timeout, not a stuck CI job. The CLI binary gets `assert_cmd`/`predicates` smoke tests.

The required assertions go beyond the happy path:

- `snapshot_restore.rs`: the host **reconnects the severed vsock** (not merely "restore succeeds"), and the restored VM shows a **rotated CID/MAC**, a **reseeded RNG**, and a **resynced clock**.
- `egress_proxy.rs`: **HTTPS** interception is logged; a registered **test double** answers; a **filter rule blocks a domain and the guest sees the block**; the proxy observes the guest's **intended destination** (the assertion is on the *observed destination*, not the steering mechanism). The HTTPS double must **ignore `Method::CONNECT`**.
- `metrics_limits.rs`: `memory.max` **OOM-kills** a runaway allocator; **average CPU** is computed over a busy loop.
- `lifecycle.rs`: **ordered `Drop` teardown on `panic`** leaves zero residue, asserted via the sweeper/registry.
- `concurrency.rs`: N VMs in one process with **no CID/VMID/socket-path collision**.
- `put_file` round-trip; agent **zero-netlink** assertion (the injected `Netlink` fake records zero calls, since `ip=` configures `eth0`); a **`FakeVmm`-driven** orchestrator test exercising the full lifecycle logic with no KVM.

**Per-VMM matrix.** Every scenario is parameterized over the backend. Before running a case, the harness consults `capabilities()` and emits an explicit **skip-with-reason** for any backend that can't support it — so an unsupported feature surfaces as a visible, attributed gap, never a silent green. Applicability: boot / exec / lifecycle / metrics / `put_file` / concurrency and the **privileged** (tap) `egress_proxy`/`host_endpoint` paths run on **all three**; `snapshot_restore.rs` runs on **CH and Firecracker** (QEMU skips — snapshot-ineligible in rootless+vsock); `shares_ro_rw.rs` (virtio-fs) and the **nested-virt** class run on **CH/QEMU only** (Firecracker block-only, no nesting); the **rootless** (smoltcp) suite runs on **CH/QEMU only** (Firecracker has no vhost-user-net for the NAT to attach to). A backend silently *failing* a scenario it claims to support — rather than skipping one it doesn't — is itself the bug this matrix catches.

**Build-pipeline tests:** a **tampered package digest aborts** the build; a **warm-cache second build performs zero network fetches and skips stages**; `reset_to(rootfs)` **rebuilds rootfs and snapshot but not the kernel**; **determinism** — identical pins yield a byte-identical erofs image and an identical `cache_key`.

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
| `cargo test` fails off a capable host | `#[ignore]` + `#[serial]` gating; split suites; nextest timeout | test cfg |

### 12.8 Privileged tests without `sudo -E`: the capability runner

**The problem.** `sudo -E cargo test` runs the *entire* toolchain as root — rustc, build scripts, nextest, the test binaries — so `target/` fills with root-owned artifacts the next unprivileged `cargo build` cannot overwrite, and cargo's cache/env shift. It is also maximally broad: everything gets full root when the privileged tests need only **`CAP_NET_ADMIN`** (tap, rtnetlink, nft/TPROXY) and **`CAP_SYS_ADMIN`** (per-test netns + `setns`). KVM access is *not* a capability — `/dev/kvm` is governed by the `kvm` group, granted once with `usermod -aG kvm $USER`.

**The mechanism.** `imp-test-runner` is registered as the cargo/nextest **target runner** for the privileged suite, so nextest invokes `imp-test-runner <test-bin> <args…>` instead of executing the test binary directly. cargo and rustc stay **unprivileged**; only the test binary is wrapped. The helper holds exactly `CAP_NET_ADMIN`+`CAP_SYS_ADMIN`, injects them into the test process via the **ambient** capability set, and execs the test **as the invoking developer's uid/gid** — so test-created files are dev-owned and the test runs with two capabilities, not full root. (`bench-vm` reuses the same runner.)

**Blessing it — one-time, redone only when the helper itself rebuilds.** Two forms, least-privilege first:

- *File capabilities (preferred).* `sudo setcap cap_net_admin,cap_sys_admin+p target/<profile>/imp-test-runner`. The helper then holds *only* those two caps, never full root, and already runs as the dev uid. (Requires a filesystem with security xattrs, not mounted `nosuid`.)
- *setuid-root (fallback).* `sudo chown root:$(id -gn) … && sudo chmod 4750 …`. Use **4750 with the developer's group**, not `4755`: a world-executable setuid-root binary that hands out `CAP_SYS_ADMIN` is a local privilege-escalation on a shared box. It momentarily grants all capabilities on exec, so it must `prctl(PR_SET_KEEPCAPS,1)`, drop to the dev uid (`setresgid`/`setgroups`/`setresuid`) *before* raising ambient, and trim `P`/`E` to the two caps. The file-cap form needs none of that dance because it never changed uid.

Both blessings are **stripped on every rebuild** (writing the file clears the setuid bit and file caps alike) — a *feature*: re-blessing is a deliberate root action, so a rebuilt or tampered helper silently loses its powers instead of running modified code with privilege. That is precisely why the helper is built to almost never rebuild (`rustix`+`capctl` only, not the lib). The hand-off, file-cap form:

```rust
// imp-test-runner — sketch (rustix + capctl); no async, no lib, no_std-friendly
let need = [Cap::CAP_NET_ADMIN, Cap::CAP_SYS_ADMIN];
ensure_blessed_or_explain(&need)?;                 // else print the fix and exit non-zero
let target = argv.get(1).ok_or(Usage)?;
ensure_under_cargo_target_dir(target)?;            // defense-in-depth: refuse arbitrary paths
let mut caps = CapState::get_current()?;           // permitted already has the two (file caps)
caps.inheritable = need.iter().copied().collect();
caps.set_current()?;
for c in need { ambient::raise(c)?; }              // PR_CAP_AMBIENT_RAISE
bounding::drop_all_except(&need)?;                 // optional: test can never acquire a 3rd cap
Command::new(target).args(&argv[2..]).exec();      // execve; ambient set survives into the no-caps test binary
```

**Fail loud, print the fix.** On startup the helper checks it holds `need` (or `geteuid()==0` for the setuid form); if not — almost always because it was just rebuilt — it exits non-zero and prints the exact `setcap` command, with the path resolved from `/proc/self/exe`. A `just bless` recipe wraps it, so the dev loop is *rebuild → `just bless` → run*. The helper never invokes `sudo` itself (circular) — it only prints.

**Threat model.** This is a **developer-workstation** convenience, explicitly **not** for multi-tenant or production hosts. `CAP_SYS_ADMIN` is root-equivalent in blast radius, so the privilege boundary is *who may execute the helper*: restrict it to the developer's group, keep its code minimal, drop the bounding set. The `ensure_under_cargo_target_dir` check is defense-in-depth, not the boundary. If test processes must hold **zero** standing privilege, the heavier alternative is a small **setup broker** (a privileged daemon that creates netns/tap/nft on request and passes back fds) — more secure, more machinery, a separate design. CI runners that are single-tenant and ephemeral can keep a dedicated root job.

---

## 13. Performance: measured results and the benchmark plan

The design rests on performance assertions; this section is the instrument that settles each. Two framing rules carry it. First, **benchmarks are tracked metrics, not pass/fail gates** — absolute boot/restore/density numbers are hardware-bound, so a fixed threshold would be a lie on a different box; the exception is the few *relative* invariants in §13.6. Second, **a number is meaningless without its substrate**: every result records the pinned CH/virtiofsd/kernel build from `pins.lock`, the host CPU/RAM/storage, and the THP/KSM/`memory_restore_mode` settings. A milestone's performance claims are not "settled" until its benchmark has run on the pinned substrate.

### 13.1 Measured numbers

**Micro (criterion, 100 samples, in-process):**

| Benchmark | What it measures | p50 |
|---|---|---|
| `protocol_encode` | `postcard` length-delimited encode of `Message::Exec` | ≈57 ns |
| `protocol_decode` | `postcard` length-delimited decode | ≈84 ns |
| `cache_key_generation` | hashing struct variants + configs for the artifact cache key | ≈195 ns |
| `math_30_ipv4_parse` | `/30` host-IP parse (`10.200.<vmid>.1`) | ≈31 ns |
| `in_memory_tar2erofs_empty` | erofs node-tree pack of an empty tar stream, in-memory | ≈1.25 µs |

The control-plane codec and the per-VM address/cache math are tens-to-hundreds of nanoseconds — far below anything that gates a multi-second VM lifecycle.

**Macro — cold boot to agent-`Ready`** (host page-caches dropped before each iteration; VMM boot command → guest agent completes the vsock handshake and replies `Ready`):

| Backend | N | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| **Cloud Hypervisor** | 10 | **≈324 ms** | 343 ms | 343 ms | 343 ms |
| **Firecracker** | 10 | **≈781 ms** | 790 ms | 790 ms | 790 ms |
| **QEMU** (`q35`) | 9 | **≈1126 ms** | 1180 ms | 1180 ms | 1180 ms |

**Macro — warm restore to agent response** (`TestVm::restore` → vsock reconnect → agent replies):

| Backend | N | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| **Firecracker** | 10 | **≈35 ms** | 46 ms | 46 ms | 46 ms |
| **Cloud Hypervisor** | 10 | **≈47 ms** | 58 ms | 58 ms | 58 ms |
| **QEMU** (`q35`) | — | **N/A** | — | — | — (snapshot-ineligible in rootless+vsock, §3.3) |

Reading these together:

- **The restore numbers validate the whole snapshot-tier design and invert the cold-boot ordering for the metric that matters.** Restore is **≈7× faster than cold boot on CH (324→47 ms) and ≈22× on Firecracker (781→35 ms)** — the empirical justification for making the per-test path restore rather than cold boot. And **Firecracker *wins* restore (≈35 ms) over CH (≈47 ms)** — the reverse of cold boot. So Firecracker is **slower to cold-boot but fastest to restore**: it earns the **density + snapshot tier** (the hot path), while CH stays the feature-complete default and cold-boot leader. Firecracker's ≈35 ms lands close to a ≈28 ms reference restore; the extra few ms are plausibly the explicit-`resume()` round-trip plus the mandated vsock reconnect and clock resync.
- **The optimistic vendor cold-boot figures are refuted.** CH is *not* <100 ms; Firecracker is *not* ≈125 ms — that figure excludes the console and the agent-ready handshake that dominate here (cold boot is ≈98% guest kernel boot + agent startup; the multi-`PUT` config is ≈1 ms, so chasing the REST path will not move it).

**Two caveats bound the numbers.** Even at N≈10 the tails are thin (p95=p99=max), so the distributions' shape is not yet characterized — fine for the central-tendency claims, not for tail/SLA quoting. And the restore figure is measured to agent-response and so includes the reconnect and clock resync, but a single-restore bench may not exercise the full **identity rotation + RNG reseed** the per-test path carries — so treat ≈35/47 ms as the warm-start *floor*; the complete per-test critical-path budget (§13.4) is the next thing to instrument.

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
| **Idle guest RSS** | park a booted (and a restored) VM idle | steady-state host RSS per parked VM, **post-KSM / post-balloon** | a pre-balloon, pre-KSM snapshot overstates footprint |
| **Density ceiling + start throughput** | ramp concurrent VMs per RAM tier to first OOM; separately, sustained starts/sec | **max concurrent VMs per RAM tier**; **sustained start rate** under teardown pressure | a peak instantaneous rate vs a sustained rate while teardown competes |
| **Snapshot ↔ virtio-fs-data composition** | attempt restore with a virtio-fs *data* share attached | **boolean composes/fails**; if it fails, the **fallback cost** (RO data as an extra erofs/block image) | treating this as pure correctness — the fallback has a real density cost |
| **OCI-vs-mmdebstrap hot-path parity** | run the boot/restore/density benches against the *same* erofs built from each source | **delta** (expected ≈ 0) | assuming the source can affect the hot path — it must not, since both produce the same erofs |
| **Snapshot-size independence** | snapshot the same workload on slim vs fat rootfs | **snapshot artifact size** and **restore latency** vs rootfs size (expected ~flat) | assuming a bigger rootfs ⇒ a bigger/slower snapshot |

Three rows are backend-shaped (must include Firecracker as well as CH, since those settle the disputed *Firecracker* figures): cold-boot, density/throughput, idle RSS. The lazy-restore row is **CH and Firecracker** (two different lazy-restore mechanisms). The snapshot↔virtio-fs-data probe is **CH/QEMU only** (Firecracker has no virtio-fs to compose with snapshot).

### 13.4 Per-test critical-path budget

The number density and throughput ultimately reduce to. Instrument one test end-to-end as `tracing` spans — acquire artifacts → allocate {slice, net, CID} → start {restore | cold-boot} → vsock connect + handshake → exec → collect → ordered teardown — and report the **distribution per phase**, so a regression is localized to the phase that moved. Two budgets: the **restore path** (the hot path) and the **cold-boot path** (opt-in). Teardown is on the budget on purpose: the reap-VMM-first ordering trades a little teardown latency for the no-leak guarantee, so that cost is measured, not assumed-free. **This budget — instrumented as phases including identity rotation + RNG reseed — is the highest-value remaining performance instrumentation** (the current restore numbers measure only restore-to-agent-response).

### 13.5 Density, datapath, and build-time

- **Density levers as tracked numbers (§9.3):** KSM dedup ratio (`pages_shared`/`pages_sharing`) and its CPU cost; balloon/free-page-reporting pages reclaimed and reclaim latency; the shared-erofs image-attributable-pages figure; idle and marginal RSS per guest. The per-RAM-tier ceiling is their joint product.
- **Datapath:** vsock frame round-trip latency and IO-streaming throughput (gates `exec` responsiveness); virtio-fs per-share throughput with attention to `imp-bin` (its page-cache hit behaviour is a density lever); egress-proxy overhead privileged (tap+TPROXY) vs rootless (smoltcp L4, CH/QEMU only), putting a cost number next to the fidelity/convenience trade; the reflink overlay cliff (conditional — only if a writable disk overlay is used).
- **Build-time (offline), paid once per pin, never folded into per-test:** erofs build wall-clock OCI vs `mmdebstrap`-in-VM (as a *whole-pipeline* number including the builder-VM boot); source/blob cache cold vs warm; `am-fs-erofs` pack throughput; builder-VM amortization (build-time-per-pin ÷ tests-per-pin).

### 13.6 Tracked metric vs regression guard

Most of §13 is observational; a minority graduates to a guard. **Stays observational (no threshold):** absolute cold-boot/restore ms, density ceiling, start throughput, idle RSS — all hardware-bound, so trend across pins but never gate. **Becomes a regression guard once a baseline is pinned** — the *relative* invariants, portable across hardware because they are deltas or ratios: OCI-vs-`mmdebstrap` hot-path parity (delta ≈ 0); boot working set flat in image size; snapshot size flat in rootfs size; per-test critical-path **phase shares** (a phase doubling its share is a regression even when absolute ms move with hardware). Each guard is **per-backend**. **Cross-backend selection is a tracked output, not a guard:** the backend-per-tier default is informed by the cross-VMM numbers but re-read per pin, since relative VMM performance shifts with kernel/hardware/pinned builds.

---

## 14. Contested facts to re-verify per pin

These load-bearing facts come from mid-2026 research inputs that conflicted on several points (CH was at v52.0 and Kata 4.0 in preview at research time). The design does **not** hard-depend on the optimistic reading of any of them; each must be re-confirmed against the exact CH / virtiofsd / kernel versions pinned in `pins.lock`. The §13 suite is what performs that re-verification and settles the numbers.

1. **virtio-fs DAX is treated as UNAVAILABLE in Cloud Hypervisor.** CH `docs/fs.md` states DAX "is not available in Cloud Hypervisor"; it was deprecated in CH v24.0. **Consequence:** host page-cache sharing for read-only data cannot come from virtio-fs DAX; it is partially recovered by serving the read-only base over erofs/virtio-blk (one host-cached copy for all guests), with per-share virtio-fs at `cache=never`. Re-check on the pinned CH; if DAX returns it becomes an opt-in optimization, not a load-bearing assumption.
2. **Snapshot/restore and virtio-fs do not currently compose.** CH refuses to snapshot a VM with vhost-user devices attached; restoring a snapshot of a VM with a virtio-fs *rootfs* hangs/fails. This is the §3.3 vhost-user law. The design boots the erofs-over-virtio-blk rootfs (snapshots fine) and uses virtio-fs only for data/binary/output shares. The open empirical question is whether virtio-fs *data* shares can be (re)attached to a snapshotted VM; if not, the snapshot tier serves read-only data via additional erofs/block images.
3. **userfaultfd lazy/demand-paged restore in CH** (`memory_restore_mode`, with dramatic restore/RSS numbers) is **claimed but not uniformly confirmed.** Treat it as a *probable* win to verify, not a guarantee. (Sparse snapshot via `SEEK_DATA`/`SEEK_HOLE`, SEV-SNP, iommufd, and the `QcowDiskAsync` io_uring backend *were* confirmed.)
4. **Boot-time numbers are workload-dependent — quote none as authoritative.** Firecracker's "≈125 ms to `/sbin/init`" and "≤5 MiB overhead" are real AWS figures but measured with the serial console disabled and a minimal kernel/rootfs; "150 µVMs/s/host" is benchmark-specific. With snapshot/restore, cold-boot numbers fall off the per-test critical path anyway. (§13.1 now refutes the optimistic figures on this stack.)
5. **Nested-virt enablement.** There is **no** `--cpu nested=on` CH flag. Nesting is enabled on the **host** KVM module (`kvm-intel nested=1` / `kvm-amd nested=1`), the **guest kernel** must have KVM built in, and CH passes `kvm-intel.nested=1` on the **guest** cmdline. On AMD, once an L1 has started an L2 guest, that L1 should no longer be migrated/snapshotted.
6. **Do not depend on `herolib-virt`.** It is an obscure single-author crate whose CH module merely shells out to the `cloud-hypervisor` binary. Use first-party `ch-remote` + a thin hand-written REST client, or the unofficial-but-cleaner `cloud-hypervisor-client` (0.3.x, MIT OR Apache-2.0).
7. **Security hygiene.** CVE-2026-45782 (a virtio-block use-after-free) is fixed in CH ≥ v51.2 / v52.0 — pin a patched release. CH does not guarantee snapshot/restore compatibility across versions, so a snapshot pool must pin one exact CH (and virtiofsd) build.

---

## 15. Risks and open decisions

- **The snapshot ↔ virtio-fs-data fork (highest risk).** §14 #2. The erofs-block rootfs snapshots cleanly; the open item is whether virtio-fs *data* shares attach to a snapshotted VM on the pinned CH/virtiofsd. Build both (virtiofsd data shares vs extra erofs/block data images) and pick per tier from measurements.
- **The `CgroupFs` testability seam is not yet extracted (open testability-contract gap).** `src/metrics.rs` defines only `ResourceUsage`; cgroup/procfs reads live inline in the orchestrator, so the cgroup-limit path lacks the fake-based unit test the design requires (§10.6 / §12.5). By the design's own rule ("not testable against a fake ⇒ not done"), the cgroup path is not done until the seam is extracted and unit-tested. **This is the one open item that violates a load-bearing design invariant.**
- **Full per-test critical-path instrumentation is incomplete.** §13.4. Restore-to-agent-response is measured; the identity-rotation/RNG-reseed phases are not. The highest-value remaining performance work.
- **In-process `fuse-backend-rs` does not enforce read-only.** Appendix B, Exp 1. An upstream-library constraint, gated behind `experiment-fuse` with `virtiofsd --readonly` as the enforced-RO fallback. Must close (or enforce RO in the passthrough) before the experiment graduates, since silent write-through on a share declared read-only would violate the `fs` contract.
- **QEMU snapshot is unvalidated.** §3.2. `snapshot_restore: false` in all configs today, conservatively disabling even the privileged kernel-`vhost-vsock` path. Unblocking means validating that path, then flipping the capability for that config only.
- **The rootfs source is a two-method fork with a pipeline→runtime dependency edge.** §8.2. The in-VM `mmdebstrap` source can only run once the runtime is solid (kernel + agent + CH + an `imp-out` share + builder egress), and a runtime regression can block a rootfs rebuild. Keep the OCI source self-sufficient so first boot never depends on the VM stack it is trying to build.
- **OCI reproducibility hinges on three things.** §11.2. Pin the manifest digest, never a tag; cache pulled blobs by digest (registry retention is the weak point); confirm `am-fs-erofs` output is byte-stable (fixed mtimes, deterministic inode/dirent ordering). If any fails, neither source produces a byte-identical image and the determinism tests catch it.
- **Networking privilege is a first-class fork.** §6.4. tap+TPROXY needs `CAP_NET_ADMIN`; the rootless smoltcp path is lower-fidelity. Privileged tap remains the default for fidelity-sensitive tests; the capability runner (not `sudo -E`) is how the privileged suite runs on a dev box.
- **The carried `vhost-user-backend`/`vhost` patch** is a maintenance/reproducibility cost; drop it if QEMU-rootless is not required. §10.4.
- **The CLI subcommands are stubs.** §10.3. The library API is the product surface; the CLI is a thin pending wrapper.
- **The ≈254-concurrent-VM ceiling per `/16`.** §10.2. Beyond that, widen the address scheme to a second octet.
- **Cross-version snapshot fragility** (pin one exact CH+virtiofsd build for any snapshot pool) and **x86_64 as the primary arch** (aarch64 is a supported second target, not a free rebuild — kernel configs and snapshot artifacts differ).

*Maintenance note:* the standalone `Cargo.toml` artifact and the handoff notes want syncing — the `[patch.crates-io]` block (§10.5) and the `restore(&VmConfig)` / `resume_vm:false` / TPROXY decisions should propagate to both.

---

## Part IV — How we got here

The body describes the system as it stands. This part records the path: the implementation passes that produced it, the substitution experiments that fixed the dependency set, the prior art it draws on, and the order it was built in. Nothing here is required to *use* the system — it is the evidence and the reasoning behind the non-obvious choices in Parts I–III, kept out of the main flow so the main flow stays present-tense.

---

## Appendix A. Implementation-pass history ledger

The design accreted across five passes (v8 → v12). The first two established the architecture and the first working build on Cloud Hypervisor; passes three through five left structured feedback and are the substance of this ledger. **The architecture never changed.** Every finding below is a localized fix, a vindicated diagnosis, or a measurement — not a redesign. The settled outcome of each is already stated present-tense in the body; this appendix records what was believed before, what the pass found, and where it landed, because the *reversals* are the part a reader needs to trust the current state.

### A.1 The passes at a glance

| Pass | Version | Headline |
|---|---|---|
| 3 | v10 | The big build: Firecracker backend, capability runner, both rootfs sources, rootless cgroup delegation, full integration suite. Surfaced four invalidations (two later vindicated the design's own diagnosis). |
| 4 | v11 | Unblocked Firecracker snapshot via MMIO; removed the netlink path from PID 1; produced the first measured numbers (cold boot). Surfaced the symmetric QEMU-vsock and Firecracker-FPU findings. |
| 5 | v12 | Closing pass: filled the warm-restore benchmark gap (the load-bearing one), fixed the FPU panic at the CPU layer keeping `trixie`, moved egress to TPROXY, restored per-request exec timeouts. Two real gaps left open. |

### A.2 What each pass did

**Pass 3 (v10) — the big build.** Built the Firecracker backend (manual `hyper`-over-Unix client, not an SDK; multi-call boot; external pre-compiled binary), the `imp-test-runner` capability runner, both rootfs sources (OCI pull + in-VM `mmdebstrap` with in-memory whiteout application), rootless cgroup-v2 delegation, and the cross-backend integration suite. It independently found `capabilities()` / `VmmCapabilities` *missing and necessary* and added them — confirming the capability-query contract was load-bearing, not speculative. It reconfirmed the settled mechanics (snapshot = pause→snapshot→resume; restore = `--restore`→`resume`, never boot; severed-vsock EOF → re-`accept`; postcard framing; `am-fs-erofs` over `mkfs.erofs`; `CONFIG_EROFS_FS=y` mandatory; dynamic-glibc agent) and produced a long refinements table (per-request exec timeout, 1-byte handshake reads, process-global allocators, the `(n % 254)+1` octet ceiling, the ≈16-socket smoltcp pool, host-driven clock resync). Its four invalidations are A.3 #1–#4.

**Pass 4 (v11) — MMIO unblock and first numbers.** Closed v10's two biggest open items, and notably *both closures confirmed the design's own diagnoses from pass 3 rather than overturning them* (A.3 #1, #2). It then surfaced two new findings that are the symmetric mirror of the Firecracker-snapshot case (A.3 #5, and the FPU panic in #3), and produced the first measured cold-boot distribution (N≈3, later grown). The snapshot findings began collapsing into one rule here — formalized as the §3.3 vhost-user law.

**Pass 5 (v12) — the closing pass.** Mostly resolved open items rather than discovering new ones. It filled the **warm-restore** benchmark gap — the load-bearing measurement, since the whole snapshot tier exists to make restore fast — and the result validated the central bet (restore ≈7× faster than cold boot on CH, ≈22× on Firecracker; Firecracker *wins* restore at ≈35 ms while losing cold boot, which is exactly the density/snapshot-tier role it was assigned). It fixed the FPU panic at the CPU layer keeping `trixie` (A.3 #3), moved egress from REDIRECT to nft TPROXY (A.3 #4), and restored the per-request exec timeout (10 s default) after a v11 hardcoded-600 s drift. It left two genuine gaps open: the `CgroupFs` seam (the one item that violates a load-bearing design invariant) and full per-test critical-path instrumentation (§15).

### A.3 The load-bearing reversals

These are the findings worth carrying as history. Each is stated as *prior belief → finding → where it landed*. The first two are cases where the design's diagnosis was challenged by an implementer and later vindicated; the rest are genuine corrections the design absorbed.

**1. Firecracker snapshot: blocked under PCI, unblocked via MMIO.** *v9 belief:* Firecracker snapshot/UFFD is a first-class capability. *v10 finding:* the guest kernel was virtio-PCI-only, so Firecracker launched with `--enable-pci`, and Firecracker has no snapshot/restore while PCI is enabled — restore aborted (`MicroVMStoppedWithError`). The capability machinery degraded honestly: Firecracker reported `snapshot_restore: false`, the suite skipped it, the cross-backend restore comparison dropped to CH-only. *Design's proposed fix:* build the guest kernel with `CONFIG_VIRTIO_MMIO=y` and run Firecracker in native MMIO mode off the *same* `vmlinux` CH uses over PCI. *v11 outcome:* taken and validated — Firecracker boots clean over MMIO, `snapshot_restore` flips `false→true`, and the restore sequencing (pause/resume via `PATCH /vm`; restore as a fresh process + `POST /snapshot/load {resume_vm:false}` then explicit resume; drives/vsock not reconfigured around load) is now the body's §3/§4 path. The fix proposed in v10 was confirmed correct in v11.

**2. `ip=` and the netlink path the agent was designed not to have.** *v10 implementer action:* found `eth0` unconfigured, added manual `ip link/addr/route` to the PID-1 agent, attributing the failure to "no initramfs to parse `ip=`." *Design's counter-diagnosis:* that attribution is wrong — `ip=` is consumed by the kernel's IP-PNP late-initcall, not by an initramfs; the real cause was the `net-rootless` feature compiled out, so no virtio-net device was presented and there was nothing for `ip=` to configure. *v11 outcome:* with the device present and `CONFIG_IP_PNP=y`+`CONFIG_VIRTIO_NET=y` built in, `ip=` configures `eth0` agent-free, the manual bring-up was deleted, and the §12 `Netlink`-fake-records-zero-calls test passes for real. The zero-netlink-in-PID-1 invariant (§4.3) survived because the design refused to accept the wrong attribution as a license to keep netlink in PID 1. Agent-side bring-up survives only as a guarded last-resort fallback.

**3. The FPU/XSAVE restore panic, and the rejected `bookworm` downgrade.** *v11 finding:* Firecracker restore can panic in `restore_fpregs_from_fpstate` when the guest `glibc` dispatches to aggressive AVX/extended-FPU routines (the saved XSAVE area mismatches the restore target). *v11 implementer stopgap:* pin the FC-snapshot rootfs to `debian:bookworm-slim`. *Design's rejection of the stopgap, with reasoning:* it is **not a `trixie` bug** — any modern-`glibc` base triggers it (it is a Firecracker extended-state limitation), so a downgrade only *hides* the trigger; `forky`/`testing` do not escape it either (`forky` began as a copy of `trixie` with the same-or-newer `glibc`, and `testing` gets no timely security updates, making it a worse *base* for a CI harness); the durable fix lives in CPUID, not the OS version. A surgical, distro-agnostic fix exists: a Firecracker **CPU template** (T2/C3) masks the offending extended-state CPUID bits so the guest `glibc` never selects those paths. *v12 outcome:* applied a static **`T2` template** on `trixie-slim` (the `bookworm` stopgap dropped), plus **`noxsave`** on the guest cmdline as an independent fallback for hosts where T2/C3 don't fit the CPU model. `bookworm` is explicitly discouraged (oldstable, full security support ended June 2026, two-generations-old `glibc`). The `noxsave` cost is recorded in §3.2 and §9: it disables guest AVX/AVX2 as well as AVX-512, a test-fidelity cost that sends SIMD-correctness-sensitive tests to the CH tier. CH and QEMU place no such constraint.

**4. REDIRECT → TPROXY: the design's stated reason was wrong but its choice was right.** *Design's original stance:* use nft TPROXY; treat "iptables REDIRECT cannot preserve the original destination" as a correctness failure. *v10 finding:* the implementer used `iptables REDIRECT`, and REDIRECT in fact recovers the original IPv4 TCP destination via `getsockopt(SO_ORIGINAL_DST)` (an HTTP/HTTPS proxy can also read it from the `Host`/`CONNECT` target) — so the stated reason for rejecting REDIRECT was incorrect. *Interim resolution:* accept REDIRECT for the HTTP/HTTPS-over-TCP scope and restate the assertion as *the proxy observes the intended destination* (mechanism-agnostic), with TPROXY kept as the documented upgrade for its real edges (UDP/QUIC on udp/443, source preservation, no conntrack dependency across the netns boundary). *v12 outcome:* moved the interception to nft `TPROXY` (`tproxy to :<port> meta mark set 1 accept`, applied via `nft -f -`), landing on the design's original choice and closing the REDIRECT interim. The arc is worth keeping: the design's *justification* for TPROXY was refuted, but TPROXY was still the right destination, reached once UDP and source-preservation made the edges concrete.

**5. QEMU cannot snapshot over the rootless vsock control plane (the symmetric mirror).** *v11 finding:* QEMU's rootless vsock is an external `vhost-device-vsock` daemon — a stateless vhost-user backend with no state-migration support — so a VM driven over it is snapshot-ineligible by the same vhost-user law that blocks CH's virtio-fs data shares and both backends' vhost-user-net. This is the exact mirror of #1: Firecracker was blocked by a *transport mode* (PCI) and unblocked by switching it (MMIO); QEMU is blocked by a *device* (the external vsock daemon) in the rootless config the harness actually uses. *Outcome:* QEMU reports `snapshot_restore: false` in rootless+vsock and is skipped with reason; the validated snapshot backends are **CH and Firecracker**. *Recovery path (unvalidated):* a privileged kernel-`vhost-vsock` QEMU config has no vhost-user device in the vsock path and should be snapshot-eligible, but it requires the privileged path and is untested — a documented avenue, not a claim (§15).

**Synthesis.** Every snapshot finding across the passes collapses into the single rule stated in §3.3: a VM is snapshot-eligible only if no vhost-user device is attached, and (for Firecracker) only under MMIO. Pass 3 surfaced the Firecracker-PCI corner, pass 4 surfaced the QEMU-vsock and the MMIO fix, and the rule that explains all of them — any external vhost-user backend is a separate stateless process the VMM cannot migrate — is the body's snapshot-eligibility law. The per-config eligibility table lives in §3.3; it is not repeated here.

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
| 5 | `passt` → in-process `smoltcp` NAT | **Graduated** | passt is CH-incompatible (seccomp); replaced by an in-process smoltcp NAT. Default for rootless. |

**Experiment 1 — in-process virtio-fs (`fuse-backend-rs`). Underway.** *Replaces:* the per-share `virtiofsd` daemon (§5.2), behind `experiment-fuse`, daemon as fallback. *Benefit:* `fuse-backend-rs` (Apache-2.0 AND BSD-3, cloud-hypervisor-org, underpins Kata/Nydus) embeds the vhost-user-fs server + passthrough driver in the orchestrator, removing N daemon processes and the per-VM memory/PID pressure that bounds density. *Open risk:* the orchestrator becomes the vhost-user-fs backend (its own virtqueues, thread-per-share, vhost-user protocol), and it does **not** by itself fix the snapshot↔virtio-fs fork (§3.3) — an external CH still sees a vhost-user device, so the restriction persists until CH adopts `fuse-backend-rs` internally (CH #7250). *Blocking gap:* read-only mode is **not natively enforced** by `fuse-backend-rs` yet (an upstream-library constraint), so the path cannot guarantee the `ReadOnly` share semantics that `virtiofsd --readonly` gives — silent write-through on a share declared read-only would violate the `fs` contract. *Graduate criterion:* at target density, a measurable memory/PID reduction with every share test green, no snapshot regression, and RO enforced (in the library passthrough if upstream does not). The highest-value remaining experiment.

**Experiment 2 — pure-Rust nftables. Rejected.** *Goal:* replace the `nft -f -` invocation for the privileged TPROXY ruleset with a permissive crate. *Finding:* `jip-nftables` provides only read capabilities; `rustables` provides writes but relicensed to GPL-3.0-or-later at 0.8 (disqualified by the copyleft prohibition, and `cargo-deny` rejects it); hand-assembling netlink payloads via `netlink-packet-netfilter` for a tiny fixed ruleset was judged unjustified. *Decision:* keep applying the small, fixed, security-critical ruleset via the external `nft` binary — correctness over purity. Reopen only if a vetted permissive, TPROXY-capable crate appears.

**Experiment 3 — pure-Rust erofs build (`am-fs-erofs`). Graduated.** *Replaces:* the `mkfs.erofs` shell-out in the rootfs build stage. *Implementation:* the tar output is streamed into a custom `tar_to_erofs` in-memory parser that converts tar entries into an `am-fs-erofs` `Node` tree and compiles the image, bypassing the host filesystem entirely — which **also removes the need to create device nodes or root-owned files**, so the rootfs build runs unprivileged. *Caveat carried forward:* `am-fs-erofs` is obscure; its license and maintenance are confirmed via `cargo-deny`, and byte-stable output (fixed mtimes, deterministic inode/dirent ordering) is a reproducibility requirement the determinism tests check. `mkfs.erofs` retained as fallback. *Result:* adopted as the default erofs path.

**Experiment 4 — rootfs source: OCI pull (default) + `mmdebstrap`-in-VM. Graduated.** *Goal:* stop forcing a single rootfs source. Support a host-native **OCI pull** as the default *and* keep `mmdebstrap`'s full apt chain by running it **inside a builder micro-VM**. *Why this resolves the old trade:* the prior revision deferred OCI because the only upside seemed to live in the offline pipeline while the cost was a real supply-chain reduction — so the trade looked like apt-chain verification vs build convenience, and `mmdebstrap` won. Two things change that. First, the upside is **not** purely offline: making OCI the default moves `mmdebstrap`, `apt`, `gpg`, and the shell **off the host** (which the requirements weight: prefer in-crate Rust, minimize external/privileged tooling) and retires the host `dash`/`SHELL=/bin/bash` quirk. Second, the apt chain is **not given up** — relocating `mmdebstrap` into a builder VM keeps full `InRelease`/`Release.gpg` verification (now in-guest, refuse-on-mismatch) and `snapshot.debian.org` timestamp-reproducibility for images that need them. *The critical distinction:* OCI is adopted **strictly as a build-time source** feeding the same `am-fs-erofs` packer — the guest never sees OCI, direct-kernel boot / snapshot / shared-RO-erofs density are unchanged, so it is **performance-neutral on the hot path** and may even cut build time by skipping `mmdebstrap`'s per-package dpkg unpack/configure. OCI *as a runtime mechanism* (containerd + snapshotter + runc + overlay-of-layers) would break the single shared erofs and snapshot/restore the performance story rests on and **remains out of scope**. *Crate note:* the puller is `oci-client` (oras-project, Apache-2.0 — the rename of `oci-distribution`); its manifest/descriptor types cover the spec surface, so a separate `oci-spec` dep is usually unnecessary. *Booked cost:* the OCI default's digest pin is *integrity, not authenticity* unless a cosign/sigstore signature is also verified — that drop is the explicit thing paid for when the OCI default is used; the in-VM source is the full-provenance alternative. *Result:* OCI pull is the default source, in-VM `mmdebstrap` is the full-provenance source, and the prior `mmdebstrap`-on-host path is retired.

**Experiment 5 — in-process rootless networking (`smoltcp` + `vhost-user-backend`). Graduated.** *Replaces:* `passt` in the rootless datapath (§6, M9). *Why passt is out:* its C seccomp filter drops the `accept4` that CH's `--net vhost_user=true` connection needs (cascading into `epoll` `Bad file descriptor`), with no opt-out — fundamentally CH-incompatible. *Implementation:* a userspace smoltcp TCP/IP stack behind a `vhost-user-backend` vhost-user-net device, with egress interception at L4 in the NAT. Three non-obvious invariants made it work (now in §6.1): pin the host NAT MAC to `02:00:00:00:00:fe` (a source-MAC collision otherwise makes smoltcp silently drop broadcast frames); iterate the virtio RX descriptor chain only when packets are queued (iterating consumes `avail_idx` and otherwise wedges the link); `enable_notification()` on the TX queue in the `handle_event` loop. *Result:* the egress-proxy and host-endpoint tests pass with no `sudo` or TAP. *Fidelity note:* a userspace stack is lower-fidelity than the privileged kernel path, which remains the default for fidelity-sensitive tests.

Two ideas from the dependency report are **not** experiments because they were already the design and were independently re-confirmed: keeping CH/Firecracker as supervised subprocesses driven by typed REST clients (rather than embedding a VMM), and `cgroups-rs` for limits/metrics.

---

## Appendix C. Prior art

Reference implementations worth mining; the ★ entries are the closest to this design.

- **`cocoonstack/cocoon`** ★ — a 2026 lightweight micro-VM engine on Cloud Hypervisor with instant snapshot+clone via reflink, COW overlays, balloon/free-page-reporting, and Firecracker as an alternate backend. Documents the exact vhost-user-snapshot constraint that becomes the §3.3 law. Closest reference to the snapshot/density path.
- **`tinylabscom/mvm`** ★ — Rust CLI with a multi-VMM backend abstraction and a vsock-only guest agent ("NO SSH ever"). A near-reference for the `Vmm` trait, the agent protocol, and the PID-1 contract.
- **`microvm.nix` agent-sandbox write-up** ★ — the egress topology to copy: CH + nftables forward-chain logging + DNS logging + read-only erofs rootfs (the shared RO erofs base, exactly as adopted).
- **`pve-microvm` (Tao of Mac)** — QEMU `microvm` as a managed guest; good reference for the kernel/rootfs split and "prebuild the rootfs, don't `apt` at boot."
- **`agentkernel`, `vmexec`** — ephemeral-VM-per-command patterns on the rust-vmm stack, in the same domain.
- **`smoltcp` + rust-vmm `vhost-user-backend`** — the building blocks of the adopted rootless NAT (Exp 5); `vhost-user-backend`'s examples show the vhost-user-net device wiring.
- **Kata `agent-ctl` / `kata-ctl`** — the agent-over-vsock blueprint and tooling.
- **UK AISI `inspect_ai` agent-bridge / `model-proxy-lifecycle`** — relevant only if/when an evaluation layer needs the in-guest model-proxy-over-vsock pattern (the §1.3 hook); not needed for the infrastructure library itself.

---

## Appendix D. Build roadmap

The order the system was built in. Each milestone landed a working, testable slice with at least one fine-grained integration test; a milestone was not complete until its §12 gates were green. As of pass 5 the system is built out through M8 on the validated backends, with M9 (rootless mode) landed and the open items in §15 outstanding. The roadmap is retained as the sequencing rationale and the test-placement map, not as remaining work.

| # | Milestone | What lands | Integration test(s) |
|---|---|---|---|
| **M0** | Skeleton | Cargo package (2024 ed.), lib + 2 bins, `error`/`config`, clippy + rustfmt + `cargo-deny` in CI, `FakeVmm` | unit: builder defaults, protocol round-trip, `/30` math, vsock-handshake state machine |
| **M1** | First boot | Artifact pipeline v0: minimal `vmlinux` with the full config fragment + erofs rootfs via the OCI source (no bootstrap dependency); CH subprocess + REST `create`/`boot`; serial→log; ordered `Drop` kill | `boot.rs`: VM reaches userspace; `lifecycle.rs`: force-shutdown a started VM |
| **M2** | vsock control | `agent::protocol`; `imp-guest-agent` as PID 1 (reaper, never-exit, fork-not-exec, self-check); host `AgentClient` with retry/handshake + serial-panic fast-fail | `exec_vsock.rs`: `exec("echo hello")` → `hello`, exit 0; `lifecycle.rs`: graceful `request_shutdown` |
| **M3** | Shared dirs | `fs` (virtiofsd per share, perms, tags); `--memory shared=on`, `cache=never`. **CH/QEMU only** | `shares_ro_rw.rs`: guest reads a host-placed input; write to RO share fails; host sees a guest-written file in the RW share |
| **M4** | Host endpoints + net (privileged) | `net::tap` (netns + tap + `/30`, rtnetlink); gateway-bound host server | `host_endpoint.rs`: guest GETs a host server on a dynamic port; unreachable outside the netns; raw-TCP also works |
| **M5** | Transparent proxy | `proxy` (MITM CA, log/filter, doubles); TPROXY steering in privileged mode; CA baked into rootfs | `egress_proxy.rs`: HTTPS request logged; a filter rule blocks a domain; a test-double returns a canned response |
| **M6** | Monitoring + limits | `metrics` (cgroup v2 slice, caps, peak/avg readers) | `metrics_limits.rs`: a workload shows up in `memory.peak`; `memory.max` kills a runaway allocator; avg CPU over a busy loop |
| **M7** | Nested virt | Guest kernel profile with KVM (+ `VHOST_VSOCK`) built in; host enablement docs. **CH/QEMU only** | `nested_virt.rs`: `/dev/kvm` present in guest; an inner micro-VM boots and runs a command |
| **M8** | Snapshot + density | Warm-snapshot stage (pause→snapshot→resume); restore via `--restore`→`resume` (never boot) + tmpfs overlay; host vsock reconnect; identity rotation + entropy reseed + clock resync; KSM/balloon. **Validated backends: CH + Firecracker** | `snapshot_restore.rs`: restored VM resumes (not boots) faster than cold boot; host reconnects the severed vsock; fresh CID/MAC + reseeded RNG; outputs still land in `imp-out` |
| **M9** | Rootless mode | `net::userspace` (in-process smoltcp + `vhost-user-backend` NAT, Exp 5); systemd cgroup delegation for metrics (sibling placement, direct `cgroup.procs` write) | rootless `host_endpoint.rs` and `egress_proxy.rs` pass with no `sudo` or TAP, gated as their own suite |

**Build-pipeline hardening track** (ran alongside, completing by M8): pin resolution + `pins.lock`; record/replay split for the OCI pull, kernel-source fetch, and in-VM apt; signing-chain verification with refuse-on-mismatch; `reset_to`. The in-VM `mmdebstrap` source lands after M2 and M4 — it needs the vsock agent (M2), an `imp-out` share to receive the tar (M3), and builder-VM egress (M4) — and reuses that machinery rather than adding surface, with its own determinism and tampered-apt-digest tests.

**Sequencing rationale.** M1 derisks the hardest plumbing (subprocess + REST + boot + teardown) with the least surface and ships the complete kernel fragment up front so the vsock/virtio-fs symbol gaps don't ambush M2/M3. M2 establishes the control channel everything asserts through. M3–M5 add the three I/O surfaces (files, host services, egress) in increasing complexity. M6 makes runs measurable and bounded. M7 and M8 are the most environment-sensitive (nesting, snapshot/density) and come late. M9 adds rootless once the privileged path is solid. The roadmap builds on the primary backend (CH); the per-VMM matrix (§12.4) and cross-VMM benchmarks (§13) layer on via `capabilities()`. The backend-gated milestones are inherent, not accidental: M3 and M7 are CH/QEMU-only (Firecracker hosts neither, so its tier passes inputs as block devices and skips nesting); M8 spans CH and Firecracker with identical assertions and only the restore mechanism differing; QEMU is snapshot-ineligible in its rootless+vsock config and is gated on the unvalidated privileged `vhost-vsock` path.
