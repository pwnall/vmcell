# Imp Testing — Design Document

*An end-to-end integration-testing and evaluation platform for the **Imp** agentic harness. Each test runs in a fresh micro-VM for structural isolation, hermetic state, and production fidelity. Driven entirely from a single Rust library.*

This document synthesizes the project requirements with the five research/fact-check inputs (`1-claude-design`, `2-gemini-research`, `3-claude-research`, `4-claude-fact-check`, `5-gemini-fact-check`). Where those inputs disagree, the disagreement is called out explicitly and the design is made robust to the conservative reading. **One synthesis note up front:** the most *recent* input (the Gemini fact-check) re-introduced at least one claim (virtio-fs DAX availability) that the earlier Claude fact-check had already refuted with verbatim primary-source quotes, and it did not surface the snapshot/virtio-fs incompatibility. "Most recent" is therefore not treated as "most authoritative"; contested points are flagged in §3 and must be re-verified against the exact pinned tool versions.

**This revision incorporates findings from two implementation passes and a dependency-substitution study.** None overturned the architecture. The first pass drove the rootfs strategy (now erofs-read-only-shared by default, §3.2 / §6 / §7), the explicit guest-kernel config fragment (§7), the vsock readiness handshake and PID-1 contract (§5.2 / §5.3), and the two-mode networking fork with its proxy coupling (§5.3 / §6 / §9). The second pass pinned the CH snapshot/restore API sequencing (pause→snapshot, restore→resume — never boot — §5.2 / §9), the vsock reconnect after restore (§5.2 / §5.3), the agent's dynamic-glibc default (§5.1 / §5.4), and several build-host quirks (§7). The dependency study corrected a licensing error (`rustables` is GPLv3, so privileged TPROXY is applied via the `nft` binary — §5.4) and seeded the future-work experiments (§10). Inline call-outs mark where an implementation actually tripped. **An independent code review of the implementation built against the prior revision** then surfaced a class of correctness, robustness, and API-guideline defects that the as-built test suite passed green — the suite had no automated opinion on any of them. That review motivated **§12 (testing strategy and quality gates)**, which turns each observed defect class into an automated gate (lint, feature-matrix build, unit/integration test, or CI check), on the principle that the test/lint/CI layer should *force* robustness rather than rely on review to catch it. Defects imported from that review carry the same **(observed)** marker as the implementation findings. **This revision also resolves the OCI-vs-`mmdebstrap` rootfs question that §10 Exp 4 had left postponed: rather than pick one, the design now supports *both* — a host-native, mostly-Rust **OCI pull** as the default rootfs source, and **`mmdebstrap` relocated to run *inside* a builder micro-VM** for the full apt signing chain — which moves `mmdebstrap`, `dash`, `apt`, and `gpg` off the host entirely (§2, §5.4, §7, §10 Exp 4).**

---

## 1. Purpose, scope, and non-goals

### 1.1 What this builds
A Rust library (plus a thin CLI binary) that can, on a Linux/x86_64 host:

1. Build the VM artifacts (kernel, root filesystem, proxy CA) reproducibly.
2. Create, configure, start, stop, and destroy micro-VMs programmatically.
3. Give each VM read-only and read-write shared directories with independent permissions.
4. Let host-side test code stand up private HTTP (and other) servers the VM can reach.
5. Route all VM web egress through a transparent, logging/filtering Rust proxy.
6. Drive the VM's "console" over a vsock control channel (exec, stream I/O, exit code).
7. Monitor and cap each VM's CPU / RAM / disk-I/O / net-I/O.
8. Optionally expose nested virtualization so Imp-under-test can run its own VMs.

The three benefits this exists to deliver, restated from the requirements: **(1)** harness/model bugs can't disrupt the host, **(2)** no state leakage between tests (hermetic by construction, not by cleanup), and **(3)** the test environment matches the real one, including full-host-access use cases.

### 1.2 Non-goals (the eval *methodology* layer)
The Gemini fact-check ranges into evaluation methodology — multi-juror adversarial scoring (ProofAgent), MCTS rollback engines (DeltaBox / DeltaFS / DeltaCR), stateful API simulation (Gecko), the UK AISI Inspect `sandbox_agent_bridge`, and CI soft-failure statistics. **These are out of scope for this infrastructure library.** This library is the *substrate* that such a layer would sit on. Two connection points are worth designing for now, because they map directly onto hard requirements, and are noted where they arise:

- The transparent egress proxy (requirement 4) is the natural home for **record/replay "cassettes"** and **Rust test doubles** for web services — the requirement's own "great extra."
- The vsock control plane (requirement 10) is the natural transport for an **in-guest model-proxy bridge** (agent talks to `localhost:PORT`, the harness forwards over vsock and records the transcript) if Imp evaluations later need it.

Everything beyond those hooks — scoring, juries, dashboards — belongs to a separate crate that depends on this one.

---

## 2. Summary of decisions (bottom line up front)

| Concern | Decision | Tier vs. requirement |
|---|---|---|
| **Primary VMM** | **Cloud Hypervisor (CH)**, run as a subprocess, controlled over its REST `--api-socket`. Rust/rust-vmm, Apache-2.0/BSD-3. | Meets every mandatory functional requirement simultaneously. |
| **Secondary VMM** | **Firecracker** behind the same trait, for the dense / no-nesting / no-shared-FS test tier (≤5 MiB VMM overhead, ~125 ms cold boot). First-class snapshot/restore (UFFD lazy restore). | Optional perf backend; **cannot do virtio-fs, vhost-user-net (so no rootless mode), or nested virt** — the trait reports this via `capabilities()` (§5.2) and the test/bench matrix skips those scenarios (§12.4/§13). |
| **Fallback VMM** | **QEMU `microvm`/`q35`** as a documented escape hatch and the most-proven nester; full feature set (virtio-fs, vhost-user-net, nesting), heavier snapshot via `savevm`/migrate. | C/GPL **binary** (acceptable as an external tool, not linked). |
| **Control plane** | **virtio-vsock + a Rust guest agent as PID 1** (dynamically linked against the rootfs glibc by default; static-musl optional, §5.4) speaking a framed (postcard) protocol (`Ready`/`Exec`/`Stdout`/`Stderr`/`Exit`). Host connects with a **retry/handshake loop** and **reconnects after restore** (§5.2). Serial console wired to a per-VM log for panic capture *and* fast-fail. SSH only as a human debugging fallback. | Requirement 10 "great" tier (vsock client+server in Rust). |
| **Shared dirs** | **virtio-fs, one `virtiofsd` per share** (or in-process `fuse-backend-rs`, §10 Exp 1), `--readonly` for inputs/binaries, rw for output; CH `--memory shared=on`; `cache=never`. | Requirement 2 mandatory + "great" (per-mount perms). The "good" extra (host page-cache sharing) is partially recovered by the erofs RO base below, not by DAX (§3.1). |
| **Root filesystem** | **erofs read-only image over `virtio-blk`**, shared by all concurrent VMs with **no per-VM copy**; per-VM writes go to a **tmpfs `overlayfs` upper**. erofs has no journal → no recovery writes, no concurrent-mount corruption. | Eliminates the v1 ext4 pitfalls (§3.2); composes with snapshot/restore (it is a plain block device, not vhost-user). |
| **Host-served endpoints** | Per-VM **network namespace + tap + `/30`** (privileged mode) *or* an **in-process smoltcp + `vhost-user-backend` NAT** (rootless mode, §10 Exp 5 — adopted; passt proved incompatible with CH); host test servers reachable, not exposed beyond the VM. Dynamic ports configured after listen. | Requirement 3 mandatory + both "great" extras + "other protocols." Mode chosen via `NetConfig` (§5.3 / §9). |
| **Transparent proxy** | **nftables `TPROXY`** (applied via the `nft` binary) in privileged mode, **L4 interception in the smoltcp NAT** in rootless mode → a **Rust MITM proxy** (`hyper`+`rustls`, or `hudsucker`) with logging, filtering, pluggable **test doubles**, CA baked into the guest trust store. | Requirement 4 mandatory + "great." **Two implementation variants, selected by the networking mode** (§6.4). |
| **Monitoring / limits** | One **cgroup v2 slice per CH (and per virtiofsd) process**; read `memory.peak`/`memory.current`/`cpu.stat`/`io.stat`; enforce `memory.max`/`cpu.max`/`pids.max`/`io.max`. Rootless runs target a **delegated** subtree, not a root slice (§9). | Requirement 8 (peak + average resource usage). |
| **Guest OS** | Minimal **Debian Trixie (13, kernel 6.12 LTS)** rootfs, from one of two sources feeding the *same* erofs packer: **OCI pull** of a pinned Debian image by digest (default — host-native, in-Rust via `oci-client`, unprivileged, no Docker/containerd), or **`mmdebstrap` run inside a builder micro-VM** for the full apt `InRelease`/`Release.gpg` chain (§7, §10 Exp 4). The guest agent + proxy CA are injected post-merge for either source. | Requirement 5 "good" tier both ways; the in-VM `mmdebstrap` path reaches the "great" tier and keeps full provenance. |
| **Guest kernel** | **Direct kernel boot** of a custom-minimal `vmlinux` built from **Debian kernel source** with an **explicit config fragment** (§7) — virtio + vsock + virtio-fs + erofs/overlay + optional KVM, all built-in, no initramfs. No project-specific patches. | Requirement 6 "good" tier; "unacceptable" (project kernel patches) avoided. |
| **Speed lever** | **Warm snapshot + restore** off the erofs-block rootfs, with a tmpfs overlay per test; cold-boot opt-in per test. Writable *disk* overlays (if ever needed) use reflink/qcow2-backing, with the ext4-reflink caveat in §3.2. | Performance non-functional; see the snapshot/virtio-fs fork in §3. |
| **Density levers** | `cache=never` + erofs RO base shared via host page cache + **KSM** (`merge_across_nodes=0` on NUMA) + **virtio-balloon / free-page-reporting**. **Not DAX** (§3.1). | RAM is the binding constraint on parallelism. |
| **Dependency posture** | Prefer in-crate Rust over external tools; permissive licenses only (MIT/Apache/BSD); copyleft tolerated only for *binaries* (QEMU) when it unlocks a fallback. Vet with `cargo-deny`. | Source-code & system-dependency requirements. |

---

## 3. Contested facts — verify against pinned versions before relying on them

The research inputs conflict on several load-bearing points. The design below does **not** hard-depend on the optimistic reading of any of these. Each should be re-confirmed against the exact CH / virtiofsd / kernel versions that get pinned.

1. **virtio-fs DAX is treated as UNAVAILABLE in Cloud Hypervisor.** Both Gemini documents claim DAX is a live density lever (`dax=on,cache_size=…`). The Claude fact-check refutes this with a verbatim quote from CH `docs/fs.md` — DAX "is not available in Cloud Hypervisor" — and notes it was deprecated in CH v24.0 (#3889). **Consequence:** the "good extra" of host page-cache sharing for read-only data (requirement 2) cannot come from virtio-fs DAX today. It is instead partially recovered a different way: serving the **read-only base over erofs/virtio-blk** lets the host page cache hold a single copy of that image for all concurrent guests. Per-share virtio-fs uses `cache=never` to minimize footprint. Re-check `docs/fs.md` on the pinned CH; if DAX returns and stabilizes it becomes an opt-in optimization, not a load-bearing assumption.

2. **Snapshot/restore and virtio-fs do not currently compose** (the single biggest architectural fork). CH issue #6931 reports that restoring a snapshot of a VM with a virtio-fs *rootfs* hangs/fails, and CH refuses to snapshot a VM with **vhost-user** devices attached (corroborated by the `cocoonstack/cocoon` docs). **Consequence:** you cannot have *both* "ms-fast warm-snapshot start" *and* a virtio-fs *rootfs*. The design boots the **erofs-over-virtio-blk rootfs** (a plain block device, *not* vhost-user, so it snapshots fine) and uses virtio-fs only for *data/binary/output* shares. The remaining open question is whether virtio-fs *data* shares can be (re)attached to a VM that is also snapshotted — validate empirically; if not, the snapshot tier serves read-only data via additional erofs/block images instead of virtiofsd. (See §6, requirement-pair 2+perf.)

3. **userfaultfd lazy/demand-paged restore in CH v52.0** (`memory_restore_mode`) with dramatic numbers (≈7,140 ms → ≈83 ms restore; 7 MB vs 2,048 MB RSS) is **claimed but not uniformly confirmed.** The Gemini fact-check asserts it; the Claude fact-check could not confirm it in the v52.0 notes it verified (it *did* confirm sparse snapshot via `SEEK_DATA`/`SEEK_HOLE`, SEV-SNP, iommufd, and the `QcowDiskAsync` io_uring backend). Treat lazy-restore as a *probable* win to verify, not a guarantee.

4. **Boot-time numbers are unreconciled and workload-dependent.** CH cold boot is quoted as both "<100 ms" (Gemini) and "~200 ms" (Claude/Northflank); Firecracker's "~125 ms to `/sbin/init`" and "≤5 MiB overhead" are real AWS spec figures but measured with the serial console disabled and a minimal kernel/rootfs; "150 µVMs/s/host" is benchmark-specific marketing. **Quote none of these as authoritative — benchmark on the real kernel/rootfs/hardware.** With snapshot/restore, cold-boot numbers fall off the per-test critical path anyway.

5. **Nested-virt enablement mechanism.** There is **no** `--cpu nested=on` CH flag that "defaults to on for x86_64" (a Gemini claim the Claude fact-check refutes). Nesting is enabled on the **host** KVM module (`kvm-intel nested=1` / `kvm-amd nested=1`), the **guest kernel** must have KVM built in, and CH's own docs pass `kvm-intel.nested=1` on the **guest** kernel command line. On AMD, once an L1 has started an L2 guest, that L1 should no longer be migrated/snapshotted — relevant if nesting and snapshotting are combined.

6. **Do not depend on `herolib-virt`.** The Gemini research recommends it; the Claude fact-check shows it is an obscure single-author crate whose CH module merely shells out to the `cloud-hypervisor` binary (it re-exports the real `virtiofsd` crate). Use the first-party `ch-remote` plus a thin hand-written REST client, or the unofficial-but-cleaner `cloud-hypervisor-client` (0.3.3, MIT OR Apache-2.0).

7. **Security hygiene:** CVE-2026-45782 (a real virtio-block use-after-free, GHSA-f47p-p25q-83rh) is fixed in CH **≥ v51.2 / v52.0** — pin a patched release. CH does not guarantee snapshot/restore compatibility across versions, so a snapshot pool must pin one exact CH (and virtiofsd) build.

---

## 4. Architecture

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
2. **Allocate per-test resources:** a cgroup v2 slice, networking (netns+tap on a fresh `/30`, or an in-process smoltcp NAT), and a unique vsock **CID** (§5.2). The erofs base is mounted read-only and shared — *no per-VM disk copy*; writable state is the tmpfs overlay.
3. **Start the VM:** either **restore** a warm "agent-ready" snapshot (fast path: launch CH `--restore` → `vm.resume`, **not** create/boot) or **cold-boot** (`vm.create` → `vm.boot`; opt-in for tests that mutate global state the snapshot would have baked in). On restore, **rotate identity** (vsock CID, MAC/IP, reseed entropy via virtio-rng) and **resync the guest clock** (§7 snapshot stage).
4. **Bind shares:** point `imp-in` / `imp-out` virtiofsd at this test's input/output dirs; `imp-bin` is shared read-only across all tests so its pages stay hot.
5. **Connect + drive over vsock:** the host `AgentClient` retries the vsock `CONNECT` handshake until the guest's `Ready` frame arrives (bounded by a timeout), while tailing the serial log so a boot panic fails fast instead of retrying to no avail. Then `Exec` the entrypoint; stream stdout/stderr/exit. **On the restore path the connection must be re-established, not reused:** CH re-creates the host-side vsock socket on restore, severing the prior connection (the guest sees EOF), so the host reconnects to the new socket. This is fast (the agent is already listening) but it is *not* a no-op, and the guest agent must serve connections in a loop (§5.3).
6. **Collect results:** outputs from the host `imp-out` dir; `memory.peak`/`cpu.stat`/`io.stat` from the slice; the proxy's request log.
7. **Tear down (ordered):** force-kill the **VMM process group first**, then the virtiofsd processes, *then* remove the tap/netns/cgroup/overlay/sockets. Removing a netns while the VMM still holds interfaces or threads in it can hang or leak; reaping the process first makes teardown a clean kernel operation. Discard is structural — that *is* the no-leakage guarantee.

### Why a `Vmm` trait rather than a single VMM
Both `mvm` and Kata abstract over multiple VMMs because each is optimal for a different slice (Firecracker for density, CH for features, QEMU for the awkward cases). Modeling the lifecycle as a narrow, well-typed contract (`capabilities` + `create/boot/request_shutdown/kill/snapshot/restore/stats`) keeps the finicky, subprocess-supervising, occasionally-`unsafe` VMM glue behind a boundary and lets the orchestrator stay idiomatic and unit-testable (a `FakeVmm` implements the same trait — see §5.6). Because the three backends genuinely diverge — Firecracker has no virtio-fs, no vhost-user-net, and no nested virt — the contract is **general with a capability descriptor**, not CH-shaped: each method documents the *behavior*, the backend-specific mechanism stays inside the impl, and a backend reports what it supports via `capabilities()` (§5.2) so an unsupported op returns `Error::Unsupported` and the orchestrator (and the test/bench matrix) degrades gracefully rather than assuming CH semantics everywhere.

---

## 5. The Rust library (`imp_testing`)

This section covers **all the parts of the expected library**: crate layout, the public API surface, each module's responsibility, the external-tool-vs-in-crate decision per capability, and the architectural accommodations that make it unit-testable.

### 5.1 Crate and workspace layout

One Cargo **package**, 2024 edition, containing one **library crate** plus **binary** targets that wrap it (a single package can expose `src/lib.rs` and multiple `src/bin/*.rs`):

```
imp-testing/
├─ Cargo.toml                 # edition = "2024"; [lib] + [[bin]] targets
├─ deny.toml                  # cargo-deny: permissive-license allow-list, advisory DB
├─ rustfmt.toml               # clippy is config-via-CI
├─ README.md                  # external tools + Debian install instructions (req: source 5)
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
│  │  ├─ kernel.rs            # vmlinux build stage (+ the config fragment, §7)
│  │  ├─ rootfs/
│  │  │  ├─ mod.rs            # rootfs build stage: source dispatch, shared agent+CA inject, erofs pack
│  │  │  ├─ oci.rs           # default source: pull image by digest, verify blobs, apply layers (whiteouts) → tar
│  │  │  └─ mmdebstrap_vm.rs # full-apt source: drive `mmdebstrap` inside a builder micro-VM, collect tar
│  │  └─ snapshot.rs          # warm-snapshot build stage
│  ├─ orchestrator.rs         # TestVm handle tying it together; ordered Drop teardown; sweeper
│  └─ error.rs                # crate Error/Result (thiserror)
├─ src/bin/
│  ├─ imp-testing.rs          # CLI wrapping the lib (clap): build, run, exec, ls, rm …
│  ├─ imp-guest-agent.rs      # guest PID 1 (dynamic-glibc default; static-musl optional); uses agent::protocol
│  ├─ imp-test-runner.rs      # privileged-test cap runner (§12.8): file-caps/setuid → ambient caps → exec test as dev uid
│  └─ bench-vm.rs             # macro/VM-level benchmark harness (§13.1); shares the cap runner for its privileged runs
└─ tests/                     # one integration test per requirement / VM operation
   ├─ boot.rs                 ├─ exec_vsock.rs        ├─ shares_ro_rw.rs
   ├─ host_endpoint.rs        ├─ egress_proxy.rs      ├─ metrics_limits.rs
   ├─ nested_virt.rs          ├─ snapshot_restore.rs  └─ lifecycle.rs
```

`imp-guest-agent` runs as the `init=` target. Because it executes as PID 1 on an *already-mounted* rootfs that ships `libc6` (any Debian base — the OCI image or `mmdebstrap`), the simplest build is **dynamically linked against the rootfs glibc on the host gnu target** — no extra toolchain, and it works because the rootfs's loader and libc are present by the time the kernel execs init. A fully static `musl` build is **optional**, for a rootfs-independent agent; it requires `musl-tools` on the build host, which the implementation pass found is not installable without root in some CI environments (§5.4). Either way the binary shares only the small `agent::protocol` module with the host, keeping "all functionality in one library crate" essentially true while the guest binary stays thin.

`imp-test-runner` is the second deliberately-thin binary, and for the same reason as the agent: it must be *blessed* once with privileges (file capabilities or the setuid bit) and that blessing is stripped whenever the file is rewritten, so it has to **almost never rebuild**. It therefore depends only on a syscall crate (`rustix`) and a small capability-set crate (`capctl`), pulls in **no async runtime and not the `imp_testing` library**, and — crucially — has no edge to `lib.rs`, so library churn never recompiles it. It is the mechanism that lets the privileged integration suite run without `sudo -E` (full design in §12.8); the `bench-vm` harness reuses it for the same reason. Like the agent it can be a static `musl` build to shed the runtime linker entirely. Keeping it tiny is also a security property — every dependency is code that executes inside the privileged window.

### 5.2 Public API surface (illustrative sketches)

Types are `#[non_exhaustive]` where future fields are likely; builders keep call sites stable. Async is via native `async fn` in traits; `#[async_trait]` is used only where `dyn Vmm` object-safety is required.

```rust
// ---- config.rs ------------------------------------------------------------
#[derive(Clone, Debug)]
pub struct VmConfig {
    pub vcpus: u8,
    pub mem_mib: u32,
    pub kernel: PathBuf,        // vmlinux (direct kernel boot)
    pub rootfs: RootfsSource,   // Erofs { image } (default) | Block { image, overlay } | VirtioFs { dir }
                                // Erofs/Block are virtio-blk → all backends; VirtioFs rootfs needs capabilities().virtio_fs_shares
    pub shares: Vec<Share>,     // virtio-fs mounts (data/binaries/output); need capabilities().virtio_fs_shares —
                                // Firecracker is block-only, so a FC tier passes inputs as block devices or skips
                                // share-dependent scenarios (§12.4)
    pub net: NetConfig,
    pub nested_virt: bool,      // build/boot guest kernel with KVM exposed; needs capabilities().nested_virt (CH/QEMU; not Firecracker)
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
    /// Full L2 fidelity; needs CAP_NET_ADMIN (sudo runner / privileged CI).
    Privileged { egress: Egress, host_services: bool },
    /// Rootless via an in-process smoltcp NAT (vhost-user-net backend); egress
    /// interception happens at L4 inside the NAT. Needs capabilities().rootless_vhost_user_net
    /// (CH/QEMU; Firecracker's net is tap-backed virtio-net with no vhost-user-net backend).
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

    /// What this backend supports. Callers MUST consult this before invoking an optional
    /// operation or configuring an optional device; the orchestrator selects a backend per
    /// tier from it (§5.3), and the test/bench harness SKIPS — does not fail — scenarios a
    /// backend can't run (§12.4 / §13.1). Reported, not assumed, because the three real
    /// backends diverge sharply (e.g. Firecracker has no virtio-fs, no vhost-user-net, and
    /// no nested virt).
    fn capabilities(&self) -> VmmCapabilities;

    /// Cold path: spawn + configure the backend (does not start the guest yet) → boot().
    async fn create(&self, cfg: &VmConfig, res: &PerVmResources) -> Result<Self::Instance>;

    /// Warm path: restore a VM from a snapshot into an already-created instance — continue it
    /// with resume(), NEVER boot()/create(). Returns `Err(Error::Unsupported)` when
    /// `capabilities().snapshot_restore` is false. The MECHANISM is backend-specific and
    /// deliberately kept out of this contract: CH launches a new process with `--restore` and
    /// rejects a boot of a restored VM with 500 "VM is already created"; Firecracker calls its
    /// `LoadSnapshot` API (guest must have been Paused at snapshot time); QEMU uses incoming
    /// migration / `loadvm`. All three reset the vsock device on restore — see
    /// `AgentClient::reconnect`.
    async fn restore(&self, snapshot: &Path, res: &PerVmResources) -> Result<Self::Instance>;
}

/// Backend capability descriptor; §5.3 carries the per-backend matrix. Each field is a property
/// of the *pinned* VMM build and must be re-confirmed against it (§3 discipline), not hard-coded
/// from memory. An optional op invoked on a backend that lacks it returns
/// `Error::Unsupported { vmm, feature }` rather than panicking, so callers degrade gracefully.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct VmmCapabilities {
    pub snapshot_restore: bool,         // CH, Firecracker, QEMU (savevm/migrate). FakeVmm: simulated.
    pub lazy_restore: bool,             // demand-paged restore (§3.3): CH `memory_restore_mode`, Firecracker UFFD.
    pub virtio_fs_shares: bool,         // virtio-fs data/binary/output shares: CH, QEMU. NOT Firecracker (block-only).
    pub rootless_vhost_user_net: bool,  // smoltcp NAT attaches via vhost-user-net (§10 Exp 5): CH, QEMU. NOT Firecracker.
    pub nested_virt: bool,              // expose /dev/kvm to the guest (M7): CH, QEMU. NOT Firecracker.
}

pub trait VmInstance: Send {
    async fn boot(&mut self) -> Result<()>;            // cold start (after create)
    async fn pause(&mut self) -> Result<()>;           // REQUIRED before snapshot
    async fn resume(&mut self) -> Result<()>;          // after snapshot, and after restore
    async fn request_shutdown(&mut self) -> Result<()>;// graceful (ACPI)
    async fn kill(&mut self) -> Result<()>;            // force-terminate VMM process group
    /// Pauses internally, writes the snapshot, then resumes (or stays paused for immediate kill).
    /// Returns `Err(Error::Unsupported)` when `capabilities().snapshot_restore` is false.
    async fn snapshot(&mut self, dir: &Path) -> Result<()>;
    async fn stats(&self) -> Result<ResourceUsage>;    // live counters
    fn vsock_path(&self) -> &Path;                     // AF_UNIX endpoint for AgentClient (changes across restore)
    fn guest_cid(&self) -> u32;                         // unique per running VM (>= 3)
    fn serial_log(&self) -> &Path;                     // per-VM panic/early-boot log
}

// ---- agent/mod.rs ---------------------------------------------------------
pub struct AgentClient { /* tokio-vsock connection */ }
impl AgentClient {
    /// Opens the host-side vsock endpoint and performs the readiness handshake, retrying with
    /// backoff until the guest is listening and has sent `Ready`, OR `timeout` elapses, OR the
    /// serial log shows a kernel panic (fail fast). Transport is backend-specific: CH and
    /// Firecracker expose a host AF_UNIX socket with the Firecracker-style hybrid-vsock handshake
    /// (`CONNECT <port>\n` → expect `OK <port>\n`); the QEMU backend uses vhost-user-vsock so that
    /// `vsock_path()` stays a unix path and this handshake is uniform across all three.
    pub async fn connect(vsock_path: &Path, port: u32, timeout: Duration,
                         serial_log: &Path) -> Result<Self>;
    /// Re-establish after a snapshot restore. Backends reset the vsock device on restore, so the
    /// prior connection is dead (the guest sees EOF): CH re-creates the host socket; Firecracker
    /// closes open connections and bumps the `guest_cid` — on both, the guest's LISTEN socket
    /// survives. The guest is already listening, so this is fast, but it is NOT a no-op: drop the
    /// old client and connect to the new endpoint.
    pub async fn reconnect(vsock_path: &Path, port: u32) -> Result<Self>;
    /// Run a command; stream stdout/stderr; return exit status.
    pub async fn exec(&mut self, cmd: ExecRequest) -> Result<ExecOutcome>;
    pub async fn put_file(&mut self, dst: &str, bytes: &[u8]) -> Result<()>;
}
pub struct ExecRequest { pub argv: Vec<String>, pub env: Vec<(String,String)>, pub cwd: Option<String> }
pub struct ExecOutcome { pub code: i32, pub stdout: Vec<u8>, pub stderr: Vec<u8> }

// ---- proxy/mod.rs ---------------------------------------------------------
pub struct EgressProxy { /* … */ }
impl EgressProxy {
    pub async fn start(cfg: ProxyConfig) -> Result<Self>;
    pub fn ca_cert_pem(&self) -> &[u8];                // baked into the rootfs trust store
    pub fn requests(&self) -> RequestLog;              // observed requests, for assertions
    pub fn install_double(&self, m: Matcher, r: Responder); // requirement 4 "great extra"
    pub fn record_to(&self, cassette: &Path);          // record/replay (eval-layer hook)
}

// ---- metrics.rs -----------------------------------------------------------
#[derive(Clone, Debug)]
pub struct ResourceUsage {
    pub mem_peak_mib: u64,  pub mem_current_mib: u64,
    pub cpu_usec: u64,      pub io_read_bytes: u64, pub io_write_bytes: u64,
    pub net_rx_bytes: u64,  pub net_tx_bytes: u64,
}

// ---- orchestrator.rs ------------------------------------------------------
/// The handle most tests hold. Owns all per-VM resources; Drop force-cleans in order.
pub struct TestVm<V: Vmm> { /* instance, cgroup, net, virtiofsd procs, cid, overlay */ }
impl<V: Vmm> TestVm<V> {
    pub async fn start(vmm: &V, cfg: VmConfig) -> Result<Self>;
    pub async fn agent(&mut self) -> Result<&mut AgentClient>;
    pub async fn usage(&self) -> Result<ResourceUsage>;
    pub async fn shutdown(self) -> Result<()>;         // graceful, then verify gone
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

### 5.3 Module responsibilities

- **`config`** — Pure data + builders. No I/O, so it is trivially unit-tested (e.g., builder defaults, validation that share tags are unique, that a virtio-fs *rootfs* combined with snapshotting is rejected as the contested combo from §3.2).
- **`vmm`** — The trait boundary and backends. `cloud_hypervisor` owns: spawning the `cloud-hypervisor` process with `--api-socket`; constructing the `VmConfig` REST payload; the lifecycle calls; reading `counters`; and snapshot/restore. **The lifecycle is two distinct paths the implementation pass pinned down:** cold = `vm.create` → `vm.boot`; warm = launch with `--restore` → `vm.resume` (never `create`/`boot` — CH returns *500 "VM is already created"*). `snapshot` must `vm.pause` first, then snapshot, then `vm.resume` (or leave paused if the VM is about to be killed). The REST client is a hand-written thin wrapper over `hyperlocal` (Unix-socket HTTP) with `serde` types generated from CH's in-repo OpenAPI YAML (or vendored from `cloud-hypervisor-client`, pinned; `firecracker-rs-sdk` is the analogue for the Firecracker backend). `mod` also owns a **CID allocator**: every running VM needs a unique guest context ID (≥ 3), handed out collision-free and rotated on restore. `firecracker` and `qemu` are feature-gated and implement the *same* traits; what differs is the **mechanism** behind each call and what each `capabilities()` reports (§5.2). The matrix, to re-confirm against the pinned builds (§3): **CH** — the default; snapshot/restore via `--restore`+`resume`, virtio-fs shares, vhost-user-net (so the rootless smoltcp NAT), and nested virt; the full feature set. **Firecracker** — the dense tier; snapshot/restore via the `LoadSnapshot` API (and UFFD lazy restore, §3.3), vsock, balloon/rng, and a tap-backed virtio-net — but **no virtio-fs, no vhost-user-net, no nested virt** (its device model is deliberately minimal: virtio-{net,block,vsock,balloon,rng,pmem}). A Firecracker tier therefore passes inputs as block devices instead of virtio-fs shares, runs only the privileged (tap) network path, and cannot host the nested-virt class — the orchestrator reads this off `capabilities()` and the test/bench harness skips those scenarios (§12.4 / §13). **QEMU** — the fallback and the most-proven nester; the full feature set (virtio-fs, vhost-user-net, nesting) but snapshot/restore via the heavier `savevm`/`loadvm` or migrate-to-file path (driven over QMP via `qapi`), so its warm-start numbers are expected to trail CH/Firecracker (§13). A backend invoked for an op it does not advertise returns `Error::Unsupported { vmm, feature }`, never a panic.
- **`agent`** — `protocol` defines a small length-prefixed, `serde`+`postcard`-framed message enum (the implementation pass standardized host and guest on postcard's length-delimited framing): `Hello/Ready`, `Exec{argv,env,cwd}`, `Stdout(bytes)`, `Stderr(bytes)`, `Exit(i32)`, `PutFile`, `Ping`. `mod` is the host client; its `connect` implements the **Firecracker-style hybrid-vsock handshake** — shared by CH and Firecracker, with the QEMU backend using vhost-user-vsock over a unix socket so the client stays uniform (CH does *not* accept a bare `connect()` — the host opens the Unix socket and writes `CONNECT <port>\n`, expecting `OK <port>\n`), retrying until the guest binds and sends `Ready`, with a timeout and a serial-log panic watch so a dead boot fails fast. **Implementation note (observed):** CH accepts the Unix-socket connection *before* the guest has booted and bound, so without this retry the host sees `Connection refused`/handshake failure; the retry belongs at the handshake level, not around a single `connect()`.

  The guest side lives in `src/bin/imp-guest-agent.rs` and runs as **PID 1** (via `init=/sbin/imp-guest-agent`). Its contract is larger than "serve the protocol," and missing any of it is painful to debug:
  - mount `proc`, `sys`, `devtmpfs`, the virtio-fs tags, and set up the **tmpfs `overlayfs`** over the read-only erofs root;
  - install the proxy CA into the trust store and bring up loopback (the guest address is set by the kernel `ip=` boot parameter — privileged tap and rootless smoltcp both use a matching subnet — so PID 1 needs no netlink, see §5.4);
  - **reap zombies** (`SIGCHLD`/`waitpid`) — PID 1 is the universal reaper; skip this and the guest fills with defunct processes;
  - **never exit** — if PID 1 returns, the kernel panics with "init died"; and
  - **fork** the test command as a child (not `exec` into it) so the agent stays PID 1 and retains the control channel and reaping duty;
  - a **boot-time self-check**: probe for the device nodes / FS support it depends on (vsock, virtio-fs) and emit a clear diagnostic before binding, so a missing-kernel-symbol regression fails legibly instead of as a raw errno panic;
  - **serve connections in a loop, not one-shot:** after a snapshot restore the host reconnects on a freshly re-created vsock socket, so the agent must detect the old connection's EOF, return to `accept`, and handle the next client (validated by the implementation pass). (Pattern overall validated by `mvm`'s "vsock-only agent, NO SSH ever.")
- **`fs`** — Spawns one `virtiofsd` per `Share`, each on its own Unix socket, with **`--readonly`** for `ReadOnly` shares (note: the flag is `--readonly`, *not* `--read-only` — the latter aborts the daemon) and a `--sandbox namespace` + dedicated uid so a daemon can reach only its one directory. Emits the CH `--fs tag=…,socket=…` config and ensures `--memory shared=on`. Cache policy defaults to `never` (density). **Subprocess-supervision note (observed):** a misconfigured `virtiofsd` exits immediately, but if the orchestrator only polls for the socket file, CH hangs forever waiting for the vhost-user socket — so the supervisor must surface the child's exit/stderr *and* bound the socket-wait with a timeout. **Snapshot note:** attaching virtiofsd (a vhost-user device) is what makes a VM ineligible for CH snapshotting (§3.2), so the snapshot tier attaches data shares only if post-restore attach is validated. The in-process `fuse-backend-rs` alternative (§10 Exp 1) lives here behind `experiment-fuse`, with the daemon as the fallback.
- **`net`** — Two implementations behind `NetConfig` (see §6.3/§6.4 and §9):
  - `tap` (**privileged**): a per-VM network namespace, a `veth`/tap pair, and a `/30` (`10.200.<vmid>.0/30`, host `.1`, guest `.2`) via `rtnetlink`; an nftables `TPROXY` redirect of guest tcp/80,443 (and optionally udp/443) to the host proxy, plus `drop`/`log` rules. **The ruleset is rendered in Rust but applied via the external `nft -f -` binary** — no permissive pure-Rust nftables crate covers the TPROXY/`socket` expressions (`rustables` is GPLv3; see §5.4 and the §10 experiment).
  - `userspace` (**rootless**): an in-process **smoltcp** TCP/IP stack behind a `vhost-user-backend` vhost-user-net device — no tap, no `CAP_NET_ADMIN`. Egress interception lives at **L4 inside the NAT** (cleaner than the privileged front-end). Three gotchas the implementation pass hit, worth encoding as invariants: **(1)** smoltcp silently drops a broadcast frame whose *source* MAC equals the interface MAC, so the host NAT MAC is pinned to `02:00:00:00:00:fe` to avoid colliding with the guest's vmid-derived MAC; **(2)** only iterate the virtio RX descriptor chain when the NAT actually has packets queued for the guest — iterating `vring.iter()` consumes/advances `avail_idx`, so polling it while empty discards the guest's RX buffers and permanently wedges the link; **(3)** call `enable_notification()` on the TX queue inside the `handle_event` loop so the guest knows to kick the eventfd for the next packet. (passt was tried first and is **incompatible with CH** — its C seccomp filter drops the `accept4` that CH's vhost-user connection needs, with no opt-out; §10 Exp 5.)
  The `/30` math and the nft-ruleset rendering are pure functions → unit-tested; the netlink calls, the `nft` invocation, and the smoltcp NAT's packet loop are the side-effecting part.
- **`proxy`** — A `hyper`-based transparent proxy. For HTTP it splices/logs; for HTTPS it terminates TLS with an on-the-fly cert minted by an in-memory CA (`rcgen`) and re-originates upstream (`hudsucker` can supply this whole MITM machinery if preferred — Apache/MIT). `doubles` lets a test register `(Matcher, Responder)` pairs (the "great extra") and, for the eval layer, record/replay cassettes. The proxy *process* is mode-independent; how traffic is *steered into it* is not (TPROXY vs the in-process smoltcp NAT), so this module exposes one proxy with two front-ends.
- **`metrics`** — Creates the per-VM cgroup v2 slice (via `cgroups-rs`), applies `ResourceLimits`, and reads `memory.peak`/`memory.current`/`cpu.stat`/`io.stat` plus net counters (tap, or the NAT's byte counters) for net I/O. Peak comes "for free" from `memory.peak`; average is computed from periodic `cpu.stat`/`io.stat` deltas. **Rootless caveat — concretely (observed):** `cgroups-rs`'s `CgroupBuilder` defaults to creating cgroups at the *root* (`/sys/fs/cgroup/imp-vm-XXX`), which fails `EPERM` unprivileged. The orchestrator instead reads `/proc/self/cgroup` and nests the VM cgroup inside the runner's systemd-delegated slice (`Delegate=yes`). The cgroup-v2 **"no internal processes"** rule then bites: a cgroup may hold processes *or* enable controllers for children, not both — and the `cargo test` process is itself internal — so the VM cgroup must be created as a **sibling** of the runner (move the runner into a `…/supervisor` leaf and place VM cgroups beside it), not a child. Finally, `cgroups-rs`'s `add_task()` raises a `CgroupMode` error on deeply nested unprivileged cgroups (and can hang the test), so the PID is written **directly** via `std::fs::write(cgroup/"cgroup.procs", pid)`.
- **`artifact`** — The staged build pipeline (full detail in §7): a `Stage` trait with a *pure* `cache_key`, a `Pipeline::build` that skips stages whose outputs already exist, and `reset_to` for invalidation. First stage resolves the up-to-date pins; all later stages are deterministic given their inputs. The rootfs stage (`rootfs/`) has **two interchangeable sources** feeding one shared agent-inject + erofs-pack tail: an **OCI pull** (default; pure-Rust, host-native) and **`mmdebstrap` inside a builder micro-VM** (full apt chain). The latter is the one place the *pipeline depends on the runtime* — it stands up a builder VM via the same `Vmm`/`AgentClient`/`Share` machinery this crate ships; the dependency edge is acyclic because the builder VM's own rootfs comes from the OCI source, which needs no VM (§7).
- **`orchestrator`** — `TestVm` composes everything and owns **ordered** teardown. Its `Drop` kills the VMM process group, then the virtiofsd processes, then removes the tap/netns/cgroup/overlay/sockets, so a panicking test cannot leak host resources and the netns isn't torn down under a live process; a periodic sweeper reaps anything orphaned by a hard crash (pattern from the `processkit`/cocoon references).
- **`error`** — One `Error` enum (`thiserror`) with variants per subsystem; `Result<T> = std::result::Result<T, Error>`.
- **`bin/imp-testing`** — `clap`-based CLI: `build` (run the artifact pipeline), `run`/`exec` (start a VM and run a command), `ls`/`rm` (manage VMs), `stats`. This is the "binary crate wrapping the library to quickly try the functionality."

### 5.4 Dependency strategy

The requirements rank implementation avenues ("best: our own well-documented Rust; great: a permissive crate; …; okay: a binary with a programmable interface") and forbid copyleft/restrictive licenses for anything *linked*. Two orthogonal cuts make the dependency surface concrete: by **avenue tier** (how programmable a thing is) and by **install mechanism** (what a developer actually has to install). The avenue-tier view:

| Capability | Mechanism | Avenue tier | License |
|---|---|---|---|
| VM lifecycle | `cloud-hypervisor` **binary** over REST; thin Rust client | Good (binary w/ programmable iface) | Apache-2.0/BSD-3 |
| Shared dirs | `virtiofsd` **daemon** per share | Good (binary) | Apache-2.0 AND BSD-3 |
| vsock control | **our Rust** (`tokio-vsock` + own protocol) | Best (own library) | MIT/Apache (crate) |
| Guest agent | **our Rust** (static musl PID 1) | Best | — |
| Networking (priv.) | **our Rust** netlink (`rtnetlink`); **`nft` binary** for TPROXY rules | Best (netlink) + Okay (nft) | MIT/Apache (netlink); GPL (nft binary, not linked) |
| Networking (rootless) | **our Rust** (`smoltcp` + `vhost-user-backend`) | Best/Great | 0BSD (smoltcp) / Apache-2.0 (vhost-user-backend) |
| Egress proxy | **our Rust** (`hyper`+`rustls`/`rcgen`, or `hudsucker`) | Best/Great | MIT/Apache |
| Monitoring/limits | **our Rust** cgroup v2 (`cgroups-rs`) | Great | MIT/Apache |
| Rootfs source (default) | **our Rust** OCI pull (`oci-client`) + layer-apply → tar | Great (permissive crate) | Apache-2.0 (`oci-client`) |
| Rootfs source (full apt chain) | `mmdebstrap` **inside a builder micro-VM** — not a host tool | Okay (external tool, runs in-guest) | GPL (in the guest image; not linked, not host-installed) |
| erofs pack | **our Rust** (`am-fs-erofs`, tar→erofs in memory); `mkfs.erofs` fallback | Best (crate) + Okay (fallback) | crate **VERIFY** license; GPL (mkfs fallback) |
| Kernel build | Debian kernel source + toolchain (build-time) | per requirement 6 "good" | GPL (source, build-time) |
| Fallback VMM | `qemu-system` **binary** (QMP via `qapi`) | Okay (binary) | GPL-2.0 (binary, allowed as exception) |

The install-mechanism view is what the README's "required tools" list ultimately encodes, and it splits three ways.

**(A) Linked crates — the bulk of the work, all permissive.** The complete, grouped list is the `Cargo.toml` in §5.5. The notable point is how much that a naive implementation would shell out to is instead a linked crate, kept inside Cargo and under `cargo-deny`'s license gate:

| Capability | Naive OS tool | Crate (linked) |
|---|---|---|
| netns / tap / addrs / routes | `iproute2` (`ip`) | `rtnetlink` + `netns-rs` + `tun-tap` |
| kernel-source / detached PGP verify (Debian apt chain now verifies in-guest) | `gpgv` / `gpg` | `pgp` (rPGP) |
| Fetch in record-step (apt snapshot, kernel src) | `curl` / `wget` | `reqwest` (rustls) |
| Reflink overlay clone | `cp --reflink` | `reflink-copy` (FICLONE) |
| Verify Debian SHA256 digests | `sha256sum` | `sha2` |
| MITM CA + leaf cert minting | `openssl` | `rcgen` + `rustls` |
| cgroup v2 limits + peak/avg readout | parse `/sys` by hand / `systemd-cgtop` | `cgroups-rs` + `procfs` |
| vsock control channel | `socat`/`ncat` over vsock | `tokio-vsock` (host), `vsock` (agent) |
| rootless guest networking | `passt` binary (CH-incompatible) | `smoltcp` + `vhost-user-backend` (§10 Exp 5) |
| pull + unpack a Debian base image | `skopeo` / `docker` / `debootstrap` | `oci-client` + `tar` + `flate2`/`zstd` (§10 Exp 4) |
| build the erofs image | `mkfs.erofs` binary | `am-fs-erofs` (tar→erofs in memory, §10 Exp 3) |

**(B) Cargo-installable binaries, run as subprocesses (not linked).** The standout is **`virtiofsd`**: it is `cargo install virtiofsd` (a rust-vmm binary, Apache-2.0 AND BSD-3), so shared-directory support needs no OS package — it can be pinned exactly like a crate. Dev tooling is the rest of this bucket: `cargo install cargo-deny` (the license/advisory gate) and `rustup component add rustfmt clippy`. **By contrast, Cloud Hypervisor is *not* cargo-installable** — it ships as GitHub release binaries (or a distro package) and has no embeddable library crate, so it is pinned and supervised as an external process; only its REST *client* is a crate (hand-rolled over `hyper`/`hyperlocal`, generated via `progenitor`, or the unofficial `cloud-hypervisor-client`).

**(C) Irreducibly external — OS packages, release binaries, or kernel features.** No Cargo path exists; this is essentially the README's external-tools section:
- **`cloud-hypervisor`** — pinned release binary. The VMM.
- **`mmdebstrap`** — **no longer a host dependency.** The default rootfs source is the in-Rust OCI pull (bucket A). When the full apt signing chain is wanted, `mmdebstrap` runs *inside a builder micro-VM* (its rootfs built by the OCI source), so it is installed in the guest image, never on the host — which also retires the host `dash`/`SHELL` quirk noted in §7. (§10 Exp 4.)
- **`erofs-utils`** (`mkfs.erofs`) — `apt install erofs-utils`. **Now optional** — a fallback for the adopted `am-fs-erofs` crate (§10 Exp 3).
- **Kernel build toolchain** — `gcc`/`clang`, `make`, `flex`, `bison`, `bc`, `libelf-dev`, `libssl-dev`, `cpio`. For the custom `vmlinux`.
- **`nftables`** (`nft`) — `apt install nftables`. Applies the privileged-mode TPROXY/`drop`/`log` ruleset via `nft -f -`; no permissive pure-Rust crate covers the needed expressions (caveat below; §10 Exp 2, rejected).
- **`qemu-system-x86`** — `apt install qemu-system-x86`. Fallback VMM only.
- **KVM** (`/dev/kvm`; host `nested=1` for M7) — kernel feature.
- A C compiler (`cc`) at build time — pulled transitively by `zstd`/`rustls` backends; standard Rust build tooling, not a runtime tool.

(In-guest tools such as `update-ca-certificates` live inside the Debian rootfs, not in the host dependency set.)

**Feature-gating for a lean agent.** Heavy host crates are `optional = true` and pulled in by features (§5.5). The guest agent is built with `--no-default-features --features agent`, so it compiles only `serde`/`postcard`/`thiserror` plus `vsock`/`rustix`/`signal-hook` — no tokio, hyper, or netlink — keeping the static musl PID-1 binary small and simple to cross-compile.

**Dev-dependencies are themselves crates:** `axum` to stand up host-side HTTP servers in the requirement-3 tests, `assert_cmd`/`predicates` to exercise the CLI, and `serial_test` to serialize the integration tests that touch global host resources (netns, cgroups, nft) — directly addressing the concurrency hazard the implementation pass hit.

**Caveats that shaped the choices:**
- **nftables has no permissive pure-Rust path today; apply TPROXY via the `nft` binary.** `rustables` — the obvious pure-netlink crate — relicensed to **GPL-3.0-or-later** at 0.8, so it is disqualified by the copyleft prohibition (and `cargo-deny` would reject it). The remaining options each have a catch: `nftables-rs` (the `nftables` JSON crate, MIT/Apache) still requires the `nft` binary + `libnftables`; `nftnl-rs` is FFI to the C `libnftnl`; the pure-Rust `jip-nftables`/`nftables_netlink` is obscure and unverified for the TPROXY + `socket` expressions. Since the ruleset is small, fixed, and security-critical, the design **renders the ruleset in Rust and applies it via `nft -f -`** (an external binary, bucket C) — correctness over purity. Replacing `nft` with a vetted permissive crate is a future-work experiment (§10).
- **Newly-adopted crates still face the gate.** The graduated experiments (§10) add `am-fs-erofs` (erofs build), `smoltcp` + `vhost-user-backend` (rootless NAT), and **`oci-client`** (OCI pull, §10 Exp 4). `smoltcp` (0BSD) and `vhost-user-backend` (rust-vmm, Apache-2.0) are well-established. **`oci-client` is Apache-2.0 (verified against its repo manifest), maintained by the oras-project — it is the rename of the `oci-distribution` crate the earlier Exp 4 named, so update references; its default TLS is rustls, so pin `default-features = false, features = ["rustls-tls"]` to keep OpenSSL out.** **`am-fs-erofs` is obscure — confirm its license and maintenance via `cargo-deny` before it stays in the default path**, keeping `mkfs.erofs` as the fallback (the `rustables` incident is the cautionary precedent; the gate, not these notes, is the source of truth).
- **`lzma-rs` (pure Rust) vs `xz2` (links `liblzma`).** Debian kernel tarballs are `.tar.xz`. `lzma-rs` keeps it in-Cargo at a speed cost; `xz2` is faster but adds an OS `liblzma-dev` dependency. The sketch uses `lzma-rs`.
- **Agent linking: dynamic-glibc by default, static-musl optional.** The agent runs as init on an already-mounted rootfs that ships `libc6` (the Debian OCI base or `mmdebstrap` output), so dynamic linking against the rootfs glibc works and needs no extra host toolchain — this is the default. A fully static `musl` build (for a rootfs-independent agent) is optional and requires `musl-tools` on the build host, which the implementation pass found is not installable without root in some CI environments. `rustix` (linux_raw) keeps the agent's syscalls libc-free and helps the static build; `nix` (libc-based) is the host's choice for `setns`/`unshare`.
- **Networking config stays out of the agent.** Rather than have PID 1 configure `eth0` (which would pull netlink into the agent), the address is set via the kernel `ip=` boot parameter (`CONFIG_IP_PNP=y`, §7) in both modes — privileged tap and the rootless smoltcp NAT use matching subnets. That is why the `agent` feature has no networking crates.
- **Versions in the sketch are floors.** Exact mid-2026 versions are deliberately unpinned; resolve them with `cargo add` and lock the result through `cargo-deny`, consistent with the `pins.lock` discipline in §7. The two crate facts already corroborated by the research inputs are the `virtiofsd` crate and `cloud-hypervisor-client` 0.3.x.
- **Trust `cargo-deny`, not hand-written license labels.** An earlier draft of this manifest labeled `rustables` MIT/Apache when it is in fact GPL-3.0-or-later — exactly the class of error the `cargo-deny` allow-list (run on every CI build) exists to catch. The license notes in this document are guidance; the gate is the source of truth.

License gate: `cargo-deny` enforces an allow-list (MIT/Apache-2.0/BSD-3/ISC/Zlib) for all *linked* crates and fails the build on copyleft or non-OSI licenses. Build-time tools (mmdebstrap, the `mkfs.erofs` fallback, the kernel toolchain), the `nft` binary, and the QEMU fallback are external executables, not linked, so their copyleft status is acceptable under the requirements.

### 5.5 The `Cargo.toml` (draft)

This manifest realizes §5.4: one package (2024 edition) with the library, the CLI binary, and the feature-gated static guest agent. Heavy host crates are optional so the agent builds lean. Versions are conservative floors — resolve exact pins with `cargo add` and gate the set through `cargo-deny`. Lines flagged `VERIFY` are the few where a crate may not cover the exact need; the concrete OS-tool fallback is named in §5.4.

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

# CLI that wraps the library (req: "binary crate wrapping the library crate").
[[bin]]
name = "imp-testing"
path = "src/bin/imp-testing.rs"
required-features = ["cli"]

# Guest PID-1 agent. DEFAULT build: dynamically linked against the rootfs glibc on the
# host gnu target (the Debian rootfs ships libc6, whether OCI or mmdebstrap) — no extra toolchain needed.
# OPTIONAL fully static build for a rootfs-independent agent (needs `musl-tools` on the
# host, which may be unavailable without root in CI):
#   cargo build --release --bin imp-guest-agent \
#       --no-default-features --features agent \
#       --target x86_64-unknown-linux-musl
[[bin]]
name = "imp-guest-agent"
path = "src/bin/imp-guest-agent.rs"
required-features = ["agent"]

# Privileged-test capability runner (§12.8). Deliberately as thin as the agent: it is BLESSED
# once with file caps (`setcap cap_net_admin,cap_sys_admin+p`) or the setuid bit, and that
# blessing is stripped on every rebuild — so it must almost never rebuild. It depends only on
# `rustix` + `capctl`, pulls in NO async runtime and NOT the `imp_testing` lib, so library churn
# never recompiles it. Built like the agent (and optionally a static musl build):
#   cargo build --release --bin imp-test-runner --no-default-features --features test-runner
[[bin]]
name = "imp-test-runner"
path = "src/bin/imp-test-runner.rs"
required-features = ["test-runner"]

# Micro-benchmark target (§13.1): criterion harness for pure/IO-light hot-path code.
[[bench]]
name = "micro"
harness = false                # criterion drives its own harness
required-features = ["pipeline"]   # tar→erofs pack bench needs am-fs-erofs

# Macro/VM-level benchmark harness (§13.1): boots real VMs to measure cold-boot, restore,
# idle RSS, and the density ceiling. A bin (not a `[[bench]]`) because it needs KVM/root and
# a capable runner; invoked on the same gated CI job as the §12.4 integration suite, NOT under
# `cargo bench`. Emits a latency DISTRIBUTION (p50/p95/p99/max) plus the pinned substrate.
[[bin]]
name = "bench-vm"
path = "src/bin/bench-vm.rs"
required-features = ["cli", "cloud-hypervisor", "metrics"]

# ===========================================================================
# Dependencies grouped by capability.
#
# Heavy host-only crates are `optional = true` and pulled in by features, so
# the guest agent (built with `--no-default-features --features agent`) does
# NOT compile tokio/hyper/rtnetlink/etc. Only `serde`, `postcard`, `thiserror`
# are unconditional (the shared wire protocol + error type).
#
# Versions below are conservative floors. Resolve exact pins at impl time with
# `cargo add` and gate the whole set through `cargo-deny` (license + advisory).
# Lines flagged "VERIFY" are the few where a crate may not cover the exact need;
# a concrete OS-tool fallback is named in the accompanying notes.
# ===========================================================================

[dependencies]

# ---- unconditional shared core (lib + guest agent) ----
serde      = { version = "1", features = ["derive"] }
postcard   = { version = "1", features = ["use-std"] }   # compact framed vsock messages (no_std-friendly)
thiserror  = "2"

# ---- host common (tokio stack + shared host utilities) ----
tokio              = { version = "1", optional = true, features = ["rt-multi-thread", "macros", "io-util", "net", "process", "sync", "time", "signal"] }
futures            = { version = "0.3", optional = true }
bytes              = { version = "1", optional = true }
tracing            = { version = "0.1", optional = true }
tracing-subscriber = { version = "0.3", optional = true, features = ["env-filter"] }
tokio-vsock        = { version = "0.7", optional = true }   # rust-vmm; async AF_VSOCK (host side)
nix                = { version = "0.29", optional = true, features = ["mount", "sched", "process", "signal", "user"] } # setns/unshare/mount on host
uuid               = { version = "1", optional = true, features = ["v4"] }   # VMGenID-style identity rotation on restore
which              = { version = "6", optional = true }                      # locate external binaries; clear preflight errors

# ---- Cloud Hypervisor REST client over --api-socket (feature: cloud-hypervisor) ----
hyper          = { version = "1", optional = true, features = ["client", "http1"] }
hyper-util     = { version = "0.1", optional = true, features = ["client", "client-legacy", "tokio"] }
http-body-util = { version = "0.1", optional = true }
hyperlocal     = { version = "0.9", optional = true }   # Unix-domain-socket connector for hyper 1.x
serde_json     = { version = "1", optional = true }
# Alternative to hand-rolling: vendor the unofficial `cloud-hypervisor-client` (0.3.x, MIT/Apache)
# or generate a typed client at build time from CH's OpenAPI YAML via `progenitor` (feature: codegen).

# ---- QEMU fallback backend: QMP + guest-agent (feature: qemu) ----
qapi = { version = "0.14", optional = true, features = ["qmp", "qga", "tokio-stream"] }

# ---- privileged networking: netns + tap (feature: net-privileged) ----
rtnetlink = { version = "0.14", optional = true }   # links/addrs/routes via netlink (pure Rust) — replaces `ip route/addr/link`
netns-rs  = { version = "0.1", optional = true }    # create/enter network namespaces — replaces `ip netns`
tun-tap   = { version = "0.1", optional = true }    # /dev/net/tun ioctl: create + persist the tap — replaces `ip tuntap`
ipnet     = { version = "2", optional = true }      # /30 subnet arithmetic
# nftables: NO permissive pure-Rust crate covers TPROXY today. `rustables` is GPL-3.0-or-later
# (disqualified); `nftables` (JSON) and `nftnl-rs` still need the nft binary / libnftnl C lib.
# The privileged TPROXY ruleset is rendered in Rust and applied via the external `nft` binary
# (see §5.4 + §10 Exp 2, rejected). No crate dependency here.

# ---- rootless networking: in-process smoltcp NAT (feature: net-rootless) — §10 Exp 5, adopted ----
smoltcp            = { version = "0.11", optional = true, default-features = false, features = ["std", "medium-ethernet", "proto-ipv4", "socket-tcp", "socket-udp"] } # userspace TCP/IP — replaces passt (CH-incompatible)
vhost-user-backend = { version = "0.17", optional = true }   # rust-vmm; vhost-user-net (and -fs) backend in-process

# ---- transparent egress proxy (feature: proxy) ----
rustls         = { version = "0.23", optional = true }
tokio-rustls   = { version = "0.26", optional = true }
rcgen          = { version = "0.13", optional = true }   # mint the MITM root CA + per-host leaf certs — replaces `openssl`
rustls-pemfile = { version = "2", optional = true }
# Optional all-in-one MITM stack (bundles hyper + rustls + rcgen). If used, prefer it over the four crates above.
hudsucker      = { version = "0.23", optional = true }

# ---- monitoring + limits (feature: metrics) ----
cgroups-rs = { version = "0.3", optional = true }   # cgroup v2 slices; read memory.peak / cpu.stat / io.stat
procfs     = { version = "0.16", optional = true }  # per-process / net-iface counters fallback

# ---- artifact build pipeline (feature: pipeline) ----
reqwest      = { version = "0.12", optional = true, default-features = false, features = ["rustls-tls", "stream"] } # replaces curl/wget
pgp          = { version = "0.14", optional = true }   # rPGP: verify Debian InRelease / Release.gpg in pure Rust — replaces gpgv
sha2         = { version = "0.10", optional = true }   # verify Debian SHA256 digests — replaces sha256sum
blake3       = { version = "1", optional = true }      # fast internal content-addressed cache keys
tar          = { version = "0.4", optional = true }    # parse OCI layer tars + the merged rootfs tar fed to am-fs-erofs
oci-client   = { version = "0.16", optional = true, default-features = false, features = ["rustls-tls"] } # §10 Exp 4: pull a pinned Debian image by digest (oras-project; renamed from `oci-distribution`); Apache-2.0
am-fs-erofs  = { version = "0.1", optional = true }    # §10 Exp 3, adopted: build erofs in memory from a tar stream — VERIFY license via cargo-deny; mkfs.erofs is the fallback
flate2       = { version = "1", optional = true }      # gzip — kernel/source tarballs AND gzip OCI layers
lzma-rs      = { version = "0.3", optional = true }    # pure-Rust xz (kernel tarballs) — see notes vs `xz2`
zstd         = { version = "0.13", optional = true }   # bundles libzstd from source via cc; zstd OCI layers + general use; no OS package needed
# NOTE: the `mmdebstrap`-in-a-builder-VM rootfs source (§7, §10 Exp 4) needs NO new crates — it drives the
# existing VMM + AgentClient + Share machinery (host-common / cloud-hypervisor features), then reuses am-fs-erofs.
reflink-copy = { version = "0.1", optional = true }    # FICLONE — replaces `cp --reflink` (XFS/Btrfs only; see notes)
walkdir      = { version = "2", optional = true }
toml         = { version = "0.8", optional = true }    # pins.lock + config
tempfile     = { version = "3", optional = true }

# ---- CLI (feature: cli) ----
clap   = { version = "4", optional = true, features = ["derive"] }
anyhow = { version = "1", optional = true }            # ergonomic top-level errors in the binary only

# ---- guest agent only (feature: agent) — kept minimal; dynamic-glibc by default, static-musl optional ----
vsock       = { version = "0.5", optional = true }     # sync AF_VSOCK; avoids pulling tokio into the agent
rustix      = { version = "0.38", optional = true, features = ["fs", "mount", "process"] } # libc-free mount(2)/waitpid(2)/reboot(2); also execve/setresuid/getuid for the test-runner
signal-hook = { version = "0.3", optional = true }     # SIGCHLD reaping as PID 1

# ---- privileged-test capability runner only (feature: test-runner) — minimal, blessed once (§12.8) ----
capctl      = { version = "0.2", optional = true }     # pure-Rust capset/capget + ambient set + securebits + bounding drop; MIT/Apache
# NOTE: the runner pulls ONLY rustix + capctl (no async, no clap, NOT the imp_testing lib), so library
# churn never recompiles it and its one-time file-cap/setuid blessing survives normal iteration.

# ---- in-process virtio-fs experiment (feature: experiment-fuse) — §10 Exp 1, underway ----
fuse-backend-rs = { version = "0.12", optional = true }   # rust-vmm vhost-user-fs + passthrough; virtiofsd remains the fallback
# (vhost-user-backend, declared above, is shared with this experiment)

[dev-dependencies]
axum         = "0.7"   # spin up host-side HTTP test servers in integration tests (req 3)
assert_cmd   = "2"     # exercise the imp-testing CLI end to end
predicates   = "3"
serial_test  = "3"     # serialize tests that touch global host resources (netns / cgroups / nft)
tempfile     = "3"
tracing-test = "0.2"
proptest     = "1"     # property tests: path-injectivity, codec round-trip, /30 math, cache-key stability (§12.3)
criterion    = { version = "0.5", features = ["html_reports"] }  # MICRO-benchmarks only (§13.1): codec, cache_key, /30 math, in-memory tar→erofs pack, loopback vsock RTT. The MACRO/VM-level benches (boot, restore, density) do NOT use criterion — they need KVM/root and a multi-second launch criterion's sampling model can't fit; they run from a custom harness (the `bench-vm` bin) gated like §12.4's integration tests.
# loom (concurrency model-checker for the CID/VMID allocators, §12.3) is opt-in: it requires the
# allocator to use `loom::sync` atomics under `#[cfg(loom)]`, so add it only if the thread-storm test is
# not enough. Integration tests run under `cargo nextest` with a per-test timeout (§12.4).

[build-dependencies]
# Optional: generate a typed CH REST client from the OpenAPI YAML at build time.
progenitor = { version = "0.8", optional = true }

[features]
default = ["cloud-hypervisor", "net-privileged", "proxy", "metrics", "pipeline", "cli"]

# Shared host stack; every host feature pulls this in so tokio is always present off the agent.
host-common = [
    "dep:tokio", "dep:futures", "dep:bytes",
    "dep:tracing", "dep:tracing-subscriber",
    "dep:tokio-vsock", "dep:nix", "dep:uuid", "dep:which",
]

cloud-hypervisor = ["host-common", "dep:hyper", "dep:hyper-util", "dep:http-body-util", "dep:hyperlocal", "dep:serde_json"]
firecracker      = ["host-common", "dep:hyper", "dep:hyper-util", "dep:http-body-util", "dep:hyperlocal", "dep:serde_json"]
qemu             = ["host-common", "dep:qapi", "dep:serde_json"]

net-privileged = ["host-common", "dep:rtnetlink", "dep:netns-rs", "dep:tun-tap", "dep:ipnet"]   # TPROXY applied via external nft binary; no permissive pure-Rust nftables crate (see §5.4)
net-rootless   = ["host-common", "dep:smoltcp", "dep:vhost-user-backend"]   # in-process smoltcp NAT (§10 Exp 5); passt removed (CH-incompatible)

proxy          = ["host-common", "dep:rustls", "dep:tokio-rustls", "dep:rcgen", "dep:rustls-pemfile"]
proxy-hudsucker = ["host-common", "dep:hudsucker"]

metrics = ["host-common", "dep:cgroups-rs", "dep:procfs"]

pipeline = [
    "host-common",
    "dep:reqwest", "dep:pgp", "dep:sha2", "dep:blake3",
    "dep:tar", "dep:oci-client", "dep:am-fs-erofs", "dep:flate2", "dep:lzma-rs", "dep:zstd",
    "dep:reflink-copy", "dep:walkdir", "dep:toml", "dep:tempfile",
]
# The `mmdebstrap`-in-VM rootfs source additionally needs a VMM backend feature (e.g. `cloud-hypervisor`)
# enabled, since it boots a builder VM. The OCI source has no such requirement. The `default` set has both.

cli = ["host-common", "dep:clap", "dep:anyhow", "dep:serde_json"]

# Guest agent: deliberately omits host-common so it does NOT compile tokio/hyper/etc.
agent = ["dep:vsock", "dep:rustix", "dep:signal-hook"]

# Privileged-test cap runner (§12.8): like `agent`, omits host-common and the lib — only syscalls + caps.
test-runner = ["dep:rustix", "dep:capctl"]

# In-process virtio-fs (§10 Exp 1, underway). Off by default; virtiofsd is the fallback.
experiment-fuse = ["host-common", "dep:fuse-backend-rs", "dep:vhost-user-backend"]

codegen = ["dep:progenitor"]
```

### 5.6 Architectural accommodations for testability

The "minor accommodations for unit-test coverage" the requirements ask for, without over-engineering:

1. **The `Vmm`/`VmInstance` trait seam.** A `FakeVmm` (test-only) implements both traits in memory, letting the orchestrator's logic (resource allocation order, ordered `Drop` cleanup, retry/timeout handling, snapshot-vs-cold-boot selection, CID allocation) be unit-tested with no KVM, no root, no subprocess.
2. **Pure/imperative split.** The genuinely-testable pure functions are isolated from I/O: nft-rule rendering, `/30` address arithmetic, the CH REST payload builder, the vsock handshake state machine, cgroup-path construction, the artifact `cache_key`, and the agent protocol's encode/decode. Each gets `#[cfg(test)]` unit tests. The thin I/O wrappers around them are exercised by the integration tests.
3. **Injectable side-effect traits where it pays off.** `Netlink`, `NftApplier`, `CgroupFs`, and a `SerialLog` reader are small traits with a real implementation and a recording/fake one, so `net`/`metrics`/`agent` orchestration is unit-testable (assert "the right rules/limits/handshake were requested") without touching the host.
4. **Deterministic IDs and clocks** are injected (a `vmid`/`cid` allocator, a `Clock`) so tests are reproducible.

The integration tests in `tests/` (one per requirement/operation) are the real-environment counterpart; they require KVM + elevated capabilities and are gated so `cargo test` stays green on a laptop while CI runs the full suite on a capable runner. **Because the runner trick (below) is global**, the privileged suite is kept as its own gated target so a plain `cargo test` of the pure unit tests does not silently run under `sudo`.

**These four accommodations are load-bearing, not optional (observed).** The implementation built against the prior revision skipped them: it called `ip`/`nft` and read sysfs directly with no trait boundary, and used module-global `static AtomicU32` counters for CID and VMID. That is the *direct cause* of the corresponding defects being review-only — with no fake there was no unit test that could assert allocator wraparound, cgroup sibling-placement, or the zero-netlink contract. The full test plan and the gates that enforce these seams are in §12; the rule that follows from it is that a subsystem which cannot be unit-tested against a fake is, by this design, not done (§12.5).

---

## 6. Requirement-by-requirement realization

A compressed pass over the ten functional requirements (mechanism → tier achieved), plus the non-functional ones.

1. **Host OS / arch.** CH fully supports Linux **x86_64** (mandatory) and **aarch64** (the "good extra"). macOS is *not* supported by CH; the macOS-on-Apple-Silicon "nice-to-have" is explicitly tie-breaker-only and is **not** pursued, since chasing it would force a weaker stack (libkrun/Apple Container with a single guest+VMM security context). **Met on the mandatory axis; aarch64 extra met; macOS deliberately skipped.**

2. **Shared dirs.** virtio-fs, one `virtiofsd` per tag (or in-process `fuse-backend-rs`, §10 Exp 1) → multi-dir (mandatory). `--readonly` per daemon → per-mount permissions (the "great" extra). The "good" extra (host page-cache sharing) historically came from DAX, which is unavailable (§3.1); it is partially recovered by the **erofs read-only base shared via the host page cache**, while per-share virtio-fs uses `cache=never`. **Mandatory + great met; the page-cache "good" extra partially recovered (for the RO base), not via DAX.**

   *2 + performance (the snapshot fork):* the **snapshot fast path boots from the erofs/virtio-blk rootfs** — a plain block device that snapshots cleanly (unlike a virtio-fs rootfs, §3.2) and needs **no per-VM copy** because it is read-only and shared. virtio-fs is used for the *data/binary/output* shares. The one open item is whether virtio-fs *data* shares attach reliably to a snapshotted VM; if not, data-heavy tests serve inputs via extra erofs/block images on the snapshot tier. This branch is the single most important thing to benchmark. (v1 proposed an ext4 rootfs cloned per VM; the implementation pass showed that path causes journal-recovery panics on read-only mounts and concurrent-mount corruption — erofs removes both, see §7.)

3. **Host-served endpoints.** Host test server bound to the per-VM gateway/host address → reachable from the guest, not exposed to other systems (mandatory). Per-test server config and dynamically-assigned ports are straightforward from Rust (configure the VM's view *after* the server is listening). Arbitrary TCP/UDP/etc. works (the "other protocols" extra). **Two delivery modes** (chosen by `NetConfig`): privileged netns+tap+`/30`, or a rootless in-process smoltcp NAT (§10 Exp 5). vsock is available as an alternate, IP-stack-free host↔guest channel. **Mandatory + both great extras + the good extra met.**

4. **Transparent proxy.** All egress is logged and filtered through the Rust MITM proxy (mandatory), with **test doubles** for web services (the "great" extra) and the record/replay hook. **The steering mechanism has two variants tied to the networking mode** (and is *not* independent of it): in privileged mode, nftables **`TPROXY`** (not `REDIRECT`/DNAT — TPROXY preserves the original destination and handles UDP; the small ruleset is applied via the `nft` binary, §5.4); in rootless mode there is no tap for nftables, so interception lives at **L4 inside the in-process smoltcp NAT**. HTTPS interception works in both because the proxy CA is baked into the guest trust store. **Mandatory + great met (two variants).**

5. **Guest environment.** Two rootfs sources feed the same erofs image (§7). **Default — OCI pull:** fetch a pinned official Debian image by digest (`oci-client`), apply its layers, inject the agent + CA, pack erofs — a real Debian userland assembled host-natively in Rust, no Docker/containerd/`mmdebstrap` on the host (the "good" tier). **Full apt chain — `mmdebstrap` in a builder micro-VM:** run `mmdebstrap` (and, if a test needs it, a full installed Debian-server flavor) *inside* a VM whose own rootfs came from the OCI source, with apt verifying the `InRelease`/`Release.gpg` chain in-guest; this reaches the "great" tier and preserves snapshot.debian.org reproducibility, at a build-time (not per-test) cost. **Good tier met host-natively; great tier + full provenance available via the in-VM `mmdebstrap` path.**

6. **Guest kernel.** Direct-boot a custom-minimal `vmlinux` built from **Debian kernel source** with the **explicit config fragment in §7** (the "good" tier). Using a Debian-provided kernel *image* unmodified (the "great" tier) is also supported as a profile. **Project-specific kernel patches (the "unacceptable" option) are never used.** The fragment matters: the implementation pass started from `kvm_guest.config` and hit `EAFNOSUPPORT` because vsock symbols were absent — and the *same* class of failure waits at virtio-fs (`FUSE_FS`/`VIRTIO_FS`) and erofs unless the fragment is complete. **Good tier met; great tier available.**

7. **Nested virtualization.** Build KVM into the guest kernel and enable it on the host (`kvm-intel nested=1`, guest cmdline `kvm-intel.nested=1`); the L1 guest then gets `/dev/kvm` and Imp-under-test can run inner VMs (CH or Firecracker). This is a separate *test class*, not the default fast path. If the inner VM needs vsock, the **L1 guest kernel** also needs `VHOST_VSOCK=y` (the host-side vhost driver — see §7). Peripheral passthrough (USB) is tie-breaker-only and not pursued. **Met with CH** (Firecracker and libkrun cannot do this — another reason they aren't primary).

8. **Programmable infra control.** The CH REST API + `ch-remote` cover create/delete/list, start/request-shutdown/force-shutdown, and configuration of shares/networking/nested-virt. Performance monitoring (peak + average CPU/RAM/disk-I/O/net-I/O) comes from the per-VM cgroup v2 slice (`memory.peak`, `memory.current`, `cpu.stat`, `io.stat`) plus net counters, layered with CH's live `counters`. **Met.**

9. **Programmable artifact build.** The staged pipeline in §7 builds filesystem/disk images, kernel/firmware, and config files, with content-addressed caching. **Met.**

10. **Programmable console.** The vsock Rust client (host) + Rust server (guest agent) hits the top "great" tier, with the readiness handshake and PID-1 contract spelled out in §5.2/§5.3. TTY emulation (serial) is retained for panic capture and fast-fail; SSH is a human-only fallback, never the control plane. **Great tier met.**

**Non-functional — performance (running time).** Most tests are seconds; the lever is **warm-snapshot restore** off the shared erofs rootfs (tmpfs overlay per test) so the per-test critical path skips kernel boot. Per-test artifact-prep time is counted (per the requirements): the erofs RO base needs **no per-test copy at all** (it is shared read-only), virtio-fs data shares avoid image copies (just re-point a daemon), and the only writable per-test state is a tmpfs overlay. If a test ever needs a writable *disk* overlay, use reflink/qcow2-backing rather than a full copy — minding the reflink caveat (§3.2 / §9).

**Non-functional — RAM density.** RAM is the binding limit on parallelism. Levers: `cache=never`, the **shared erofs RO base** (one host-cached copy for all guests), **KSM** (`merge_across_nodes=0` on NUMA; budget ~5–10% CPU for `ksmd`), and **virtio-balloon/free-page-reporting**. Plan with **128–256 MiB/guest as a must-re-benchmark figure** (the guest userland, not the ≤5 MiB VMM overhead, dominates). The next limits after RAM are typically one-virtiofsd-per-VM (mitigated by the in-process `fuse-backend-rs` experiment), tap/bridge/nft (or the in-process NAT's per-VM threads) scaling, and host FD/PID limits.

**Non-functional — Rust ergonomics & licensing.** Covered by §5.4 (avenue tiers, permissive-only via `cargo-deny`).

---

## 7. Artifact build pipeline

Maps directly onto the VM-artifact-production requirements (staged, pinned, deterministic, cacheable, resettable, minimal external access, record/replay, signing-chain verified).

### Artifacts produced
1. **`vmlinux`** (per arch): one custom-minimal kernel, direct-boot, drivers built in, optional KVM-for-nesting. Host-side, shared by all VMs; rebuilt only when the config fragment or pinned source changes.
2. **Root filesystem** (per profile): a **single read-only erofs image** packed in memory by `am-fs-erofs` (§10 Exp 3; `mkfs.erofs` fallback), built from a merged rootfs **tar** that comes from one of **two interchangeable sources**. Whichever source produces the tar, the **tail is shared**: inject `imp-guest-agent` + the proxy CA + the tmpfs/overlay scaffolding into the merged tree, then stream it through `am-fs-erofs` — which avoids creating device nodes or root-owned files on the host, so the pack runs unprivileged. That one artifact serves *every* path — cold boot, concurrent shared mounts, and the snapshot tier — because erofs over virtio-blk is read-only, shareable, and snapshot-eligible. (v1 specified a dual emission, erofs *and* a separate block image; with erofs-over-virtio-blk the two collapse into one.) **Imp's own binaries are *not* baked in** — they arrive over the `imp-bin` virtio-fs share, so a new Imp build does not invalidate the rootfs. The two sources:

   - **Default — OCI pull (host-native, in-Rust).** Resolve a Debian base image to a **manifest digest**, pull manifest + config + layers with `oci-client` (no Docker/containerd daemon), verify every blob against its `sha256` digest (`sha2`), decompress each layer (`flate2` for gzip, `zstd` for zstd), and apply them in order honoring **OCI whiteout semantics** (`.wh.<name>` deletions and `.wh..wh..opq` opaque-dir markers) to produce the merged tar. The guest never sees OCI — this is OCI strictly as a *build-time source* feeding the erofs packer (the load-bearing distinction in §10 Exp 4), so direct-kernel boot, snapshot/restore, and shared-RO-erofs density are all unchanged. Runs unprivileged; the only new linked crate is `oci-client` (Apache-2.0).
   - **Full apt chain — `mmdebstrap` inside a builder micro-VM.** Build a **builder rootfs** via the OCI source (stock `debian:trixie-slim` + the agent), boot it on *this project's own* CH stack, then over the vsock agent run `apt-get install mmdebstrap` followed by `mmdebstrap` against the pinned snapshot — emitting the target rootfs as a **tar on the `imp-out` rw share**, which the host then feeds to the shared inject+pack tail above. Because `mmdebstrap` runs **as root inside a controlled guest**, apt performs the full `InRelease`/`Release.gpg` chain verification in-guest (refuse-on-mismatch), Debian fidelity and snapshot.debian.org timestamp-reproducibility are preserved, and **`mmdebstrap`, `apt`, `gpg`, and the shell all leave the host**. This is why the host `dash` quirk is gone: **(observed)** host-side `mmdebstrap` fails under Ubuntu's default `dash` and needs `SHELL=/bin/bash` with `/bin/sh`→`bash` — a fragility that motivated running it in a controlled VM rather than papering over it on every host. (Optional optimization: snapshot the "builder, `mmdebstrap` installed" state and restore it per build to skip the install; rootfs builds are rare, so this is minor.)

   The **bootstrap chain is acyclic and terminates**: kernel (artifact 1) + OCI-built builder rootfs → builder VM → in-guest `mmdebstrap` → target tar → erofs. The OCI source needs no VM, so the recursion bottoms out there; the only external trust roots are the registry digest of the base image (optionally a cosign/sigstore signature) and the Debian archive keyring apt uses inside the VM. The builder-VM boot is a **build-time cost paid once per pin and cached** (then the per-test path is snapshot-restore as always), so the full-apt source costs build time and complexity for provenance/fidelity — it does **not** touch per-test running time or VM density.
3. **Warm snapshot** (per VMM + profile): boot the erofs-rootfs base to "agent-ready," snapshot. Per-test = restore + tmpfs overlay.
4. **Proxy CA cert**: minted once, baked into the rootfs trust store.

### The guest-kernel config fragment
Start from Debian's kernel source and apply an explicit `microvm` fragment — **not** `kvm_guest.config` alone, which omits vsock, virtio-fs, and erofs and caused real boot failures in the implementation pass. Everything the guest needs is built **in** (`=y`, no modules → no initramfs, nothing to probe):

```text
# Transport (CH uses virtio-pci)
CONFIG_PCI=y  CONFIG_VIRTIO=y  CONFIG_VIRTIO_PCI=y
# Core paravirtual devices
CONFIG_VIRTIO_BLK=y  CONFIG_VIRTIO_NET=y  CONFIG_VIRTIO_CONSOLE=y
CONFIG_HW_RANDOM_VIRTIO=y          # virtio-rng — also feeds the snapshot entropy reseed
CONFIG_VIRTIO_BALLOON=y            # density lever
CONFIG_IP_PNP=y                    # guest IP via kernel `ip=` cmdline → PID 1 needs no netlink
# vsock control plane  — MISSING from kvm_guest.config (caused EAFNOSUPPORT)
CONFIG_VSOCKETS=y  CONFIG_VIRTIO_VSOCKETS=y
# virtio-fs shared dirs — ALSO MISSING; the same failure waits at M3 without these
CONFIG_FUSE_FS=y  CONFIG_VIRTIO_FS=y
# Filesystems: erofs RO root + tmpfs overlay (+ ext4 only if you keep a block fallback)
CONFIG_EROFS_FS=y  CONFIG_EROFS_FS_ZIP=y   # match the erofs builder's compressor; see note
CONFIG_OVERLAY_FS=y  CONFIG_TMPFS=y  CONFIG_EXT4_FS=y
# Console / early boot
CONFIG_SERIAL_8250=y  CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_DEVTMPFS=y  CONFIG_DEVTMPFS_MOUNT=y
# Paravirt clock (helps clock stability across pause/restore)
CONFIG_PARAVIRT=y  CONFIG_KVM_GUEST=y
# Nested virt (M7): guest exposes /dev/kvm to inner VMs
CONFIG_KVM=y  CONFIG_KVM_INTEL=y          # or CONFIG_KVM_AMD=y
CONFIG_VHOST_VSOCK=y                       # only needed so an *inner* (L2) VM can use vsock
```

Two precisions the notes surfaced:
- **`CONFIG_VHOST_VSOCK` is host-side**, not required in the guest for the base control plane — CH's vsock is a userspace implementation, so the base guest needs only `VSOCKETS` + `VIRTIO_VSOCKETS`. It earns its place in the *guest* kernel only at M7, when the L1 guest acts as host to an inner L2 VM that wants vsock. (The original note listed it as needed for the base case; it is harmless but not necessary there.)
- **erofs compression must match.** If the erofs builder (`am-fs-erofs` or `mkfs.erofs`) compresses with lz4/zstd, the kernel needs the matching decompressor (`CONFIG_EROFS_FS_ZIP` for lz4; `…_ZIP_ZSTD`, `…_ZIP_LZMA`, `…_ZIP_DEFLATE` as applicable) or the mount fails. Building the image uncompressed sidesteps the dependency at the cost of size and page-cache footprint.

The kernel command line pins the boot path explicitly, e.g.:
`console=ttyS0 root=/dev/vda rootfstype=erofs ro ip=10.200.<vmid>.2::10.200.<vmid>.1:255.255.255.252::eth0:off init=/sbin/imp-guest-agent`. The `ip=` parameter (enabled by `CONFIG_IP_PNP=y`) sets the guest address at boot in privileged tap mode, so PID 1 needs no netlink (§5.4); the same `ip=` config applies in rootless mode (the smoltcp NAT uses a matching subnet). (If a block-ext4 fallback is ever used, add `rootflags=noload` so the ext4 driver mounts strictly read-only without journal recovery — recovery is a write and panics on a read-only device. erofs has no journal, so the default path needs no such flag.)

### Stage model
- **Stage 0 — resolve pins (the only non-deterministic stage).** Determine the most up-to-date values for a minimal pin set: the **OCI base-image manifest digest** (resolve the tag to a `sha256:…` digest and pin *that*, not the tag — a tag is not reproducible), the Debian package-repo **snapshot timestamp** (via `snapshot.debian.org`, used by the in-VM `mmdebstrap` source), the kernel source version/commit, and the CH/virtiofsd release tags. Output: a small, committed `pins.lock`.
- **Stages 1..n — deterministic given inputs.** Each stage's output is fully determined by its inputs + the pins. Examples: *fetch+verify kernel source*, *configure+compile `vmlinux`*, and then the rootfs source-of-record: for the **OCI path**, *pull+verify the pinned base image* → *apply layers (whiteouts) → merged tar*; for the **in-VM `mmdebstrap` path**, *build the builder rootfs (OCI) → boot the builder VM → run `mmdebstrap` at the pinned snapshot → collect the target tar* (this stage **depends on the compiled `vmlinux`**, so the kernel stage is ordered before it). Both paths converge on the shared tail: *inject `imp-guest-agent` + CA → erofs pack (stream the merged tar into `am-fs-erofs` in memory; `mkfs.erofs` fallback)*, then *boot+snapshot*.
- **Caching.** Each stage has a pure `cache_key` (hash of inputs + pins + stage version); `Pipeline::build` skips a stage whose outputs already exist under that key. `reset_to(stage)` removes the outputs of that stage and all later ones.
- **Minimize external access + record/replay.** Network-touching stages are split into a **record** step (populate an on-demand cache keyed to the pins) and a **replay** step (build purely from the cache); iteration and CI then hit the network at most once per pin. For the **OCI source** the record step is the registry pull — **cache the pulled blobs by digest** so a later registry deletion/overwrite doesn't break a rebuild (registry retention is the OCI path's reproducibility weak point), then replay from the local blob cache. For the **in-VM `mmdebstrap` source** the apt fetch happens *inside the builder VM*; its egress can run through this project's own **egress proxy with a record/replay cassette** (§1.2 / §10) — a natural fit that needs no separate mirror — or an apt cache mounted into the VM via a share. Kernel-source fetches record/replay as before.
- **Signing-chain verification — two forms, honest about what each gives.** For the **in-VM `mmdebstrap` source**, apt verifies the Debian `InRelease`/`Release` + `Release.gpg` chain against the pinned archive keyring *inside the guest* before using any package — full provenance, **refuse-on-mismatch**, a hard stop. For the **OCI source**, the `sha256` **digest pin is an integrity hard-stop** (a blob whose content doesn't match its digest aborts the build), but digest-pinning is *integrity, not authenticity*: to also get provenance, optionally verify a **cosign/sigstore** signature on the image (a different trust root than apt's keyring, and not every base image is signed). Kernel-source signatures/hashes are verified where published. The strong apt chain is therefore retained for the security-sensitive image via the in-VM source; the OCI default trades that chain for registry-digest trust (the explicit cost booked in §10 Exp 4). In all cases a mismatch is a hard stop, not a warning.

### Snapshot stage specifics (restore correctness)
A restored snapshot resumes at the exact instruction it was taken — which means restored clones share whatever state was frozen in. Two things must be refreshed on every restore, not just at first boot:
- **Entropy:** reseed via virtio-rng (rotate the RNG state / surface a VMGenID-style change). An unreseeded `getrandom()` can stall first use by seconds. (Brooker et al., arXiv 2102.12892; note `MADV_WIPEONSUSPEND` there is a *proposed* flag, distinct from the existing `MADV_WIPEONFORK`.)
- **Clock:** a snapshot resumed much later resumes with a stale wall clock. kvm-clock keeps the monotonic source sane, but if a test asserts on timestamps, force a time resync after restore (e.g., the host delivers the current time over vsock and the agent sets it). For most ephemeral tests this is cosmetic; for time-sensitive ones it is not.
- **Identity:** rotate vsock CID and MAC/IP so restored clones don't collide.

The pipeline is exposed both as the library `artifact::Pipeline` API and as `imp-testing build [--reset-to STAGE]` on the CLI.

---

## 8. Implementation roadmap (simple-and-testable first, then feature-by-feature)

Each milestone lands a working, testable slice and at least one fine-grained integration test (the requirements ask for ~one test per requirement / VM operation). The artifact-pipeline track is partly a prerequisite (you need *a* kernel + rootfs to boot at all), so its first stages land inside M1.

| # | Milestone | What lands | Integration test(s) | Requirement(s) |
|---|---|---|---|---|
| **M0** | Skeleton | Cargo package (2024 ed.), lib + 2 bins, `error`/`config`, clippy+rustfmt+`cargo-deny` in CI, README scaffold, `FakeVmm` | unit: builder defaults, protocol round-trip, `/30` math, vsock-handshake state machine | source-code reqs 1,2,3,6,7,8 |
| **M1** | First boot | Artifact pipeline v0: build a minimal `vmlinux` with the **full config fragment** + an **erofs** rootfs **via the OCI pull source** (host-native, no bootstrap dependency); CH subprocess + REST `create`/`boot`; serial→log; ordered `Drop` kill | `boot.rs`: VM reaches userspace (known string in serial log). `lifecycle.rs`: force-shutdown a started VM | 1, 6, 9, parts of 8 |
| **M2** | vsock control | `agent::protocol`; `imp-guest-agent` as PID 1 (reaper, never-exit, fork-not-exec, self-check); host `AgentClient` with **retry/handshake + serial-panic fast-fail** | `exec_vsock.rs`: `exec("echo hello")` → stdout `hello`, exit 0. `lifecycle.rs`: graceful `request_shutdown` | 10, rest of 8 |
| **M3** | Shared dirs | `fs` (virtiofsd per share, perms, tags); `--memory shared=on`, `cache=never`. **Confirm `FUSE_FS`/`VIRTIO_FS` are in the kernel** (else the M2-class errno failure recurs) | `shares_ro_rw.rs`: guest reads a host-placed input file; write to RO share fails; host sees a file the guest wrote to the RW share | 2 (mandatory + great) |
| **M4** | Host endpoints + net (privileged) | `net::tap` (netns + tap + `/30`, rtnetlink); gateway-bound host server | `host_endpoint.rs`: guest GETs a host HTTP server on a dynamic port; server unreachable outside the netns; a second protocol (raw TCP) works | 3 (+extras) |
| **M5** | Transparent proxy | `proxy` (MITM CA, log/filter, doubles); **TPROXY** steering in privileged mode; bake CA into rootfs | `egress_proxy.rs`: HTTPS request is logged; a filter rule blocks a domain (guest sees the block); a registered test-double returns a canned response | 4 (+great) |
| **M6** | Monitoring + limits | `metrics` (cgroup v2 slice, caps, peak/avg readers) | `metrics_limits.rs`: a workload allocating N MiB shows up in `memory.peak`; `memory.max` kills a runaway allocator; avg CPU computed over a busy loop | 8 (perf monitoring) |
| **M7** | Nested virt | Guest kernel profile with KVM (+ `VHOST_VSOCK` for inner vsock) built-in; host enablement docs | `nested_virt.rs`: `/dev/kvm` present in guest; an inner micro-VM boots and runs a command | 7 |
| **M8** | Snapshot + density | Warm-snapshot stage (**pause→snapshot→resume**); restore via **`--restore`→`resume`** (never boot) + tmpfs overlay; **host vsock reconnect** after restore; identity rotation + **entropy reseed + clock resync**; KSM/balloon wiring | `snapshot_restore.rs`: restored VM **resumes** (not boots) faster than cold boot; the host **reconnects the severed vsock**; restored VM has fresh CID/MAC + reseeded RNG; outputs still land in `imp-out` | perf + density non-functional |
| **M9** | Rootless mode | `net::userspace` (in-process **smoltcp + `vhost-user-backend`** NAT, §10 Exp 5); systemd cgroup **delegation** for metrics (nested under `/proc/self/cgroup`, sibling placement, direct `cgroup.procs` write) | rootless `host_endpoint.rs` and `egress_proxy.rs` **pass without `sudo` or TAP**, gated as their own suite. (passt was tried first and is CH-incompatible — seccomp drops `accept4`; replaced by the smoltcp NAT.) | 3/4 deployability (§9) |

**Build-pipeline hardening track** (runs alongside, completes by M8): Stage 0 pin resolution + `pins.lock`; record/replay split for the OCI pull, the kernel-source fetch, and (in the in-VM source) apt; signing-chain verification with refuse-on-mismatch; `reset_to`. Each gets its own test (e.g., "a tampered OCI blob digest aborts the build"; "a second build with a warm cache performs zero network fetches"; "`reset_to(rootfs)` rebuilds rootfs and snapshot but not the kernel"). **The in-VM `mmdebstrap` rootfs source lands after M2 and M4** — it needs the vsock agent (M2), an `imp-out` rw share to receive the tar (M3), and builder-VM egress to the Debian mirror (M4) — and reuses that machinery rather than adding new surface. Its own tests: "the in-VM `mmdebstrap` build yields a byte-identical erofs for a pinned snapshot" (determinism) and "a tampered apt digest aborts in-guest, failing the build" (the apt chain is a hard stop, now enforced inside the builder VM).

**Test-suite split.** Privileged integration tests (netns/tap/cgroup-at-root) run on a dev box through the **capability runner** (`imp-test-runner`, §12.8) — which grants just `CAP_NET_ADMIN`+`CAP_SYS_ADMIN` and keeps artifacts dev-owned — with `sudo -E` or a dedicated root job as the CI fallback; rootless tests (the in-process smoltcp NAT + delegated cgroup) run as their own suite and need no elevation. Keeping them separate — rather than assuming root everywhere — is both cleaner and the only way the rootless path stays honestly exercised. The pure unit tests run under a plain `cargo test`.

**Sequencing rationale.** M1 derisks the hardest plumbing (subprocess + REST + boot + teardown) with the least surface — and now ships the complete kernel fragment and erofs rootfs up front so the vsock/virtio-fs symbol gaps don't ambush M2/M3. M2 establishes the control channel everything else asserts through, with the readiness handshake and PID-1 contract that the implementation pass proved are load-bearing. M3–M5 add the three I/O surfaces (files, host services, egress) in increasing complexity. M6 makes runs measurable and bounded. M7 and M8 are the most environment-sensitive (nesting, snapshot/density) and come late. M9 adds the rootless deployment mode once the privileged path is solid.

The per-milestone tests named above are the *placement*; their **assertion-level specifications** — including the missing assertions an independent code review found (severed-vsock reconnect, original-destination preservation, ordered-`Drop`-on-panic, concurrent-collision freedom) — plus the **automated quality gates** (the crate-level lint set, the feature-powerset build, `cargo-deny`, and the unit/integration catalogs that turn each reviewed defect into a CI failure) are consolidated in §12. The roadmap and §12 are meant to be read together: a milestone is not complete until its §12 gates are green. The roadmap builds out on the **primary backend (CH)**; the **per-VMM matrix** (§12.4) and **cross-VMM benchmarks** (§13) then layer on top via `capabilities()` (§5.2). Two milestones are inherently backend-gated rather than CH-specific by accident: **M3** (virtio-fs shares) and **M7** (nested virt) are **CH/QEMU only** — Firecracker can't host them, so its tier passes inputs as block devices and skips the nesting class — whereas **M8** (snapshot/restore + density) spans **all three** with identical assertions and only the restore mechanism differing. The Firecracker and QEMU backends are not a late afterthought: they implement the same trait from M1, and their scenario coverage and performance numbers expand with the matrix as each milestone lands.

---

## 9. Risks, open decisions, and what to benchmark

- **The snapshot ↔ virtio-fs fork (highest risk).** §3.2. The erofs-block rootfs snapshots cleanly; the open item is whether virtio-fs *data* shares attach to a snapshotted VM on your pinned CH/virtiofsd. Build both (virtiofsd data shares vs extra erofs/block data images) and pick per tier from measurements.
- **The rootfs source is a two-method fork with a bootstrap dependency.** §7 / §10 Exp 4. Default **OCI pull** (host-native, in-Rust, digest-pinned) vs **`mmdebstrap` in a builder micro-VM** (full apt chain). The in-VM source depends on the OCI source (for its builder rootfs) *and* on a working VM stack (kernel + agent + CH + an `imp-out` rw share + builder egress), which adds a **pipeline→runtime dependency edge**. The chain is acyclic and terminates because the OCI source needs no VM — but it does mean the in-VM source can only be exercised once M1–M4 are solid, and a regression in the runtime can block a rootfs rebuild. Keep the OCI source self-sufficient so first boot never depends on the VM stack it is trying to build.
- **OCI reproducibility hinges on three things; get all three or the path isn't reproducible.** §7 stage model. (1) Pin the **manifest digest**, never a tag. (2) **Cache pulled blobs by digest** so a deleted/overwritten registry image doesn't break a rebuild (registry retention is the weak point, unlike `snapshot.debian.org`, which rebuilds from a timestamp from first principles — the in-VM source keeps that stronger property). (3) Confirm **`am-fs-erofs` output is byte-stable** (fixed mtimes, deterministic inode/dirent ordering) — a known erofs reproducibility concern; if it isn't, neither rootfs source produces a byte-identical image and the determinism tests (§8) will catch it.
- **The OCI provenance trade is explicit, not eliminated.** §10 Exp 4. OCI-by-digest is *integrity, not authenticity* unless a cosign/sigstore signature is also verified against a separate trust root. The strong apt signing chain is retained — for whatever image security demands it — via the in-VM `mmdebstrap` source. Choose per profile and book the signing-chain drop as the thing being paid for when using the OCI default.
- **Networking privilege is a first-class fork, not an afterthought.** tap + TPROXY needs `CAP_NET_ADMIN`; the implementation pass confirmed modern **Ubuntu** blocks the unprivileged-userns escape hatch by default (`kernel.apparmor_restrict_unprivileged_userns=1`). Note this is largely an Ubuntu 24.04+ default — **Debian Trixie does not necessarily enable it**, which is mildly relevant given the earlier Debian-vs-Ubuntu deliberation; the host distro affects whether rootless even gets off the ground. Two supported modes (§5.3/§6): **privileged** (tap+TPROXY, full L2 fidelity; on a dev box, run via the capability runner `imp-test-runner`, §12.8, rather than `sudo -E`) and **rootless** (in-process **smoltcp NAT** + cgroup delegation — §10 Exp 5, adopted; passt was tried first and is CH-incompatible, its C seccomp filter dropping the `accept4` that CH's vhost-user connection needs, with no opt-out). `sudo -E cargo test` is global — it runs the whole toolchain as root, so it taints `target/` with root-owned artifacts and shifts cargo's environment; **§12.8's capability runner exists precisely to fix this**, granting only `CAP_NET_ADMIN`+`CAP_SYS_ADMIN` to the test binary while leaving cargo/rustc unprivileged and outputs dev-owned (`sudo -E` or a root job remains the CI-only fallback). Note the rootless datapath is a *userspace* TCP/IP stack (smoltcp) with its own quirks (the MAC/RX/notification invariants in §5.3), so it is lower-fidelity than the privileged kernel path — privileged tap remains the default for fidelity-sensitive networking tests.
- **Proxy steering is coupled to the networking mode.** §6.4. TPROXY only exists with a tap; rootless mode intercepts at L4 in the in-process smoltcp NAT. Requirement 4 therefore has two implementations, not one — don't design the proxy as if the front-end were uniform.
- **Rootless cgroup delegation has sharp edges.** §5.3 `metrics`. Limits only work if the VM cgroup is nested under the runner's systemd-delegated slice (`Delegate=yes`, path read from `/proc/self/cgroup`) and placed as a *sibling* of the runner to satisfy the cgroup-v2 "no internal processes" rule; `cgroups-rs` defaults to the root slice (fails unprivileged) and its `add_task()` errors on nested cgroups, so PIDs are written directly to `cgroup.procs`. Without a delegated slice, rootless metrics/limits are unavailable.
- **DAX is gone (density plan).** §3.1. Rely on the shared erofs RO base + `cache=never` + KSM + balloon, not DAX. Re-check on the pinned CH.
- **reflink only helps on the right filesystem.** If a writable *disk* overlay is ever needed, `cp --reflink=auto` / `FICLONE` works on **XFS or Btrfs**, not ext4 — on ext4 it silently degrades to a full copy and the density/speed win evaporates. Alternatives: a CH **qcow2 overlay with a backing file** (you must flip `backing_files=on`, which is off-by-default for security, §3.2-adjacent), or `dm-snapshot`. With the erofs-RO-shared base + tmpfs overlay this is rarely needed.
- **Boot/density numbers are unverified.** §3.4. Benchmark cold-boot, restore, idle guest RSS, and the concurrent-VM ceiling per RAM tier on the actual hardware before quoting anything. The suite that does this — and settles the rest of the §3 contested facts and the Exp-4 hot-path claims — is **§13**.
- **Nested-virt host requirements.** §3.5. Needs host `nested=1` (bare-metal or a nesting-capable cloud instance, e.g. AWS C8i/M8i/R8i via `NestedVirtualization=enabled`, or `.metal`). On AMD, don't snapshot an L1 that has started an L2.
- **nftables programming has no permissive pure-Rust path.** §5.4. `rustables` is GPL-3.0-or-later (disqualified); `nftables-rs`/`nftnl-rs` still need the `nft` binary or the C `libnftnl`; the pure-netlink crates are unproven for TPROXY. The design applies the small, fixed TPROXY ruleset via `nft -f -`. A pure-Rust replacement is a future-work experiment (§10), not a baseline dependency.
- **Snapshot restore correctness.** §7 snapshot stage. Rotate identity (CID/MAC/IP), reseed entropy (virtio-rng), and resync the clock on every restore; otherwise clones reuse RNG state and carry a stale wall clock. Operationally (confirmed by the implementation pass): snapshot requires `vm.pause` first, and a restored VM continues via `vm.resume` — **booting a restored VM errors (`500 "VM is already created"`)**. Because CH re-creates the host-side vsock socket on restore, the host must **reconnect** and the guest agent must survive the severed connection's EOF and re-`accept` (§5.2/§5.3).
- **vsock CID allocation.** Each running VM needs a unique guest CID (≥ 3); the host must allocate collision-free and rotate on restore. A naive fixed CID collides the moment two VMs run concurrently.
- **overlayfs-over-virtiofs is a known sharp edge.** The default writable overlay is tmpfs-over-**erofs**, which is fine. Using **virtiofs as an overlayfs lowerdir** has historically needed specific kernel features (redirect_dir/metacopy) and is best avoided — another reason the RO base is erofs, not a virtio-fs mount.
- **Cross-version snapshot fragility.** Pin one exact CH + virtiofsd build for any snapshot pool; CH does not guarantee snapshot compatibility across versions.
- **Primary architecture.** x86_64 is the mandatory CI arch and the place to invest first; aarch64 is a supported extra but kernel configs and snapshot artifacts differ, so treat it as a second target, not a free rebuild.

---

## 10. Substitution experiments: outcomes and remaining work

The dependency analysis (§5.4) deliberately kept several external tools — `virtiofsd`, `mkfs.erofs`, `mmdebstrap`, `passt`, the `nft` binary — and a second research pass argued each could be absorbed into the orchestrator as a crate. Rather than adopt wholesale, each was run as an independent experiment against the working baseline, **one at a time**, behind its own Cargo feature flag, with the baseline mechanism retained as the fallback. The methodology held: branch from the green baseline; gate the new path behind a feature; keep the affected requirement's integration tests as the regression oracle; graduate into the default only on the success criterion, otherwise revert. Results so far:

| # | Substitution | Status | Outcome |
|---|---|---|---|
| 1 | virtiofsd → `fuse-backend-rs` | **Underway** | Scaffolded behind `experiment-fuse`; virtiofsd remains the fallback. Not yet concluded. |
| 2 | `nft` binary → pure-Rust nftables | **Rejected** | No permissive crate covers TPROXY (`rustables` GPLv3; `jip-nftables` read-only); `nft` retained. |
| 3 | `mkfs.erofs` → `am-fs-erofs` | **Graduated** | In-memory tar→erofs build; runs unprivileged. Adopted as default; `mkfs.erofs` is the fallback. |
| 4 | rootfs source: OCI pull (default) + `mmdebstrap`-in-VM | **Graduated** | OCI pull (digest-pinned, in-Rust) is the default host-native source; `mmdebstrap` relocated into a builder micro-VM to keep the full apt chain. Resolves the signing-vs-convenience trade by supporting both. |
| 5 | `passt` → `smoltcp` NAT | **Graduated** | passt is CH-incompatible (seccomp); replaced by an in-process smoltcp NAT. Adopted for rootless. |

**Experiment 1 — In-process virtio-fs (`fuse-backend-rs`). Status: underway.** *Replaces:* the per-share `virtiofsd` daemon (§5.3 `fs`), behind the `experiment-fuse` feature, with the daemon as the fallback. *Benefit:* `fuse-backend-rs` (Apache-2.0 AND BSD-3, cloud-hypervisor-org, mature — underpins Kata/Nydus) embeds the vhost-user-fs server + a passthrough driver in the orchestrator, removing N daemon processes and cutting the per-VM memory/PID pressure that bounds density (§6). *Open risk:* the orchestrator becomes the vhost-user-fs backend (its own virtqueues, thread-per-share, vhost-user protocol), and it does **not** by itself fix the snapshot↔virtio-fs fork (§3.2) — an external CH still sees a vhost-user device, so the restriction persists until CH adopts `fuse-backend-rs` internally (CH #7250). *Graduate / revert:* keep it if, at target density, it delivers a measurable memory/PID reduction with every M3 share test green and no snapshot regression. **Highest-value remaining experiment.**

**Experiment 2 — Pure-Rust nftables. Status: rejected.** *Goal:* replace the `nft -f -` invocation for the privileged TPROXY ruleset with a permissive crate. *Finding:* `jip-nftables` provides only read capabilities; `rustables` provides writes but is GPLv3 (disqualified); and hand-assembling netlink payloads (via `rust-netlink/netlink-packet-netfilter`) for a tiny, fixed ruleset was judged unjustified. *Decision:* keep applying the ruleset via the external `nft` binary (§5.3 `net`, §5.4). Reopen if a vetted permissive, TPROXY-capable crate appears.

**Experiment 3 — Pure-Rust erofs build (`am-fs-erofs`). Status: graduated.** *Replaces:* the `mkfs.erofs` shell-out in the rootfs build stage (§7). *Implementation:* the `mmdebstrap` tar output is streamed into a custom `tar_to_erofs` in-memory parser that converts tar entries into an `am-fs-erofs` `Node` tree and compiles the image — bypassing the host filesystem entirely, which **also removes the need to create device nodes or root-owned files**, so the rootfs build runs unprivileged. *Caveat carried forward:* `am-fs-erofs` is an obscure crate; its license and maintenance must be confirmed via `cargo-deny` (§5.4), and `mkfs.erofs` is retained as the fallback. *Result:* adopted as the default erofs path.

**Experiment 4 — Rootfs source: OCI pull (default) + `mmdebstrap`-in-VM. Status: graduated.** *Goal:* stop forcing a single rootfs source. Support a host-native **OCI pull** as the default *and* keep `mmdebstrap`'s full apt chain by running it **inside a builder micro-VM** — getting the convenience upside without paying the signing-chain cost, which is what kept `mmdebstrap`-only in the prior revision. **The critical distinction is still OCI-as-build-source vs OCI-as-runtime-mechanism — opposite performance profiles, and only the former is adopted.** *As a build-time source* (what is adopted): `oci-client` does registry HTTP pulls in the pipeline — **no Docker/containerd daemon** — and the extracted, whiteout-applied layer tar feeds the *same* `am-fs-erofs` packer to produce the *same* erofs image booted today. The guest never sees OCI; direct-kernel boot, snapshot/restore, and shared-RO-erofs page-cache density are all unchanged, so this is **performance-neutral on the hot path** (per-test running time and VM density), and build time may even drop by skipping `mmdebstrap`'s per-package dpkg unpack/configure. The usual worries don't bite: a fatter `*-slim` base costs host disk and a one-time cache warm-up, not per-test time, because erofs over virtio-blk is demand-paged and shared (boot touches only the working set, once, for all VMs); the agent bypasses distro init (`init=/sbin/imp-guest-agent`) so a larger userland doesn't grow the boot working set; snapshots capture guest *RAM*, not the rootfs disk; and Imp's binaries arrive over the `imp-bin` virtio-fs share rather than the image. *As a runtime mechanism* (containerd + snapshotter + runc + overlay-of-layers) every worry is real — extra daemons, per-pull layer decompress/assembly, an overlayfs-of-many-layers with worse inode/page-sharing — and it would break the single shared erofs and snapshot/restore the performance story rests on; **this remains out of scope and must not be pursued.**

*Why both, and why this resolves the old trade:* the prior revision deferred OCI because the only upside seemed to live in the offline pipeline (weighted lightly) while the cost was a genuine supply-chain reduction — so the trade looked like apt-chain verification *vs* build convenience, and `mmdebstrap` won. Two things change that. First, the upside is **not** purely offline: making OCI the default **moves `mmdebstrap`, `apt`, `gpg`, and the shell off the host**, which the requirements *do* weight (prefer in-crate Rust over external tools; minimize external/privileged tooling) — and it retires the **(observed)** host `dash`/`SHELL=/bin/bash` quirk. Second, the apt chain is **not given up** — relocating `mmdebstrap` into a builder VM keeps full `InRelease`/`Release.gpg` verification (now performed in-guest, refuse-on-mismatch) and `snapshot.debian.org` timestamp-reproducibility for any image that needs them. So the design adopts OCI **strictly as a build-time source feeding the same erofs packer** (the prior revision's own "if revisited" rule) for the default, and retains the in-VM `mmdebstrap` source for the full chain — and **books the signing-chain drop as the explicit thing paid for** whenever the OCI default is used (digest pinning is integrity, not authenticity, unless a cosign/sigstore signature is also checked; §7).

*Bootstrap (acyclic):* kernel + an OCI-built builder rootfs (stock `debian:trixie-slim` + agent) → boot the builder VM on this project's own CH stack → `apt-get install mmdebstrap` then `mmdebstrap` at the pinned snapshot → target tar on the `imp-out` share → shared inject+erofs-pack tail. The OCI source needs no VM, so the recursion bottoms out; the in-VM source can only run once M1–M4 are solid (§8). *Crate note:* the puller is **`oci-client`** (oras-project, Apache-2.0) — the rename of the `oci-distribution` crate the prior draft named; its `OciImageManifest`/descriptor types cover the spec surface needed, so a separate `oci-spec` dep is usually unnecessary, and `flate2`/`zstd`/`tar`/`sha2` (already in the manifest) cover layer decompression, parsing, and digest verification. *Result:* OCI pull adopted as the default rootfs source; in-VM `mmdebstrap` adopted as the full-provenance source; the prior `mmdebstrap`-on-host path is retired. (Orthogonal and separately useful: pushing the *built* erofs image to a registry as an OCI artifact is OCI-for-distribution — handy for sharing pre-built rootfs across CI runners, independent of both the rootfs source and provenance.)

**Experiment 5 — In-process rootless networking (`smoltcp` + `vhost-user-backend`). Status: graduated.** *Replaces:* `passt` in the rootless datapath (§5.3 `net`, M9). *Why passt is out:* its C seccomp filter drops the `accept4` that CH's `--net vhost_user=true` connection needs (cascading into `epoll` `Bad file descriptor`), with no opt-out — fundamentally incompatible with CH. *Implementation:* a userspace smoltcp TCP/IP stack behind a `vhost-user-backend` vhost-user-net device, with egress interception at L4 in the NAT. Three non-obvious invariants made it work (recorded in §5.3 `net`): pin the host NAT MAC to `02:00:00:00:00:fe` to avoid a source-MAC collision that makes smoltcp silently drop broadcast frames; iterate the virtio RX descriptor chain only when packets are queued (iterating consumes `avail_idx` and otherwise wedges the link); and `enable_notification()` on the TX queue in the `handle_event` loop. *Result:* `test_egress_proxy` and `test_host_endpoint` pass with no `sudo` or TAP. *Fidelity note:* this is a userspace stack, lower-fidelity than the privileged kernel path, which remains the default for fidelity-sensitive tests.

Two ideas from the dependency report are **not** experiments because they are already the design, and were independently re-confirmed by the report: keeping CH/Firecracker as supervised subprocesses driven by typed REST clients (`cloud-hypervisor-client` / `firecracker-rs-sdk`) rather than embedding a VMM (§5.3), and `cgroups-rs` for limits/metrics (§5.3 `metrics`).

---

## 11. Prior art worth mining before writing code

- **`cocoonstack/cocoon`** ★ — a 2026 lightweight micro-VM engine on Cloud Hypervisor with instant snapshot+clone via **reflink**, COW overlays, balloon/free-page-reporting, and Firecracker as an alternate backend; it documents the exact vhost-user-snapshot constraint from §3.2. Closest reference to the snapshot/density path.
- **`tinylabscom/mvm`** ★ — Rust CLI with a multi-VMM backend abstraction and a **vsock-only guest agent ("NO SSH ever")**; a near-reference for the `Vmm` trait, the agent protocol, and the PID-1 contract.
- **`microvm.nix` agent-sandbox write-up** ★ — the egress topology to copy: CH + nftables forward-chain logging + DNS logging + read-only `erofs` rootfs (note the shared RO erofs base, exactly as adopted here).
- **`pve-microvm` (Tao of Mac)** — QEMU `microvm` as a managed guest; good reference for the kernel/rootfs split and "prebuild the rootfs, don't `apt` at boot."
- **`agentkernel`, `vmexec`** — ephemeral-VM-per-command patterns on the rust-vmm stack, in your exact domain.
- **`smoltcp` + rust-vmm `vhost-user-backend`** — the building blocks of the adopted rootless NAT (§10 Exp 5); `vhost-user-backend`'s examples show the vhost-user-net device wiring. (passt, the C user-mode-networking tool, was tried first and is CH-incompatible — see §5.3.)
- **Kata `agent-ctl` / `kata-ctl`** — the agent-over-vsock blueprint and tooling.
- **UK AISI `inspect_ai` agent-bridge / `model-proxy-lifecycle`** — only if/when the eval layer needs the in-guest model-proxy-over-vsock pattern (the §1.2 hook); not needed for the infrastructure library itself.

---

## 12. Testing strategy and quality gates

This section is the testing counterpart to §5.6 (the seams) and §8 (the roadmap). It exists because an independent code review of the implementation built against the prior revision found correctness bugs (no `Drop` teardown, temp-dir collisions, a non-portable cache hash), robustness gaps (`.unwrap()` on the hot path, undocumented `unsafe`, thread/FD leaks), and API-guideline violations that the as-built suite passed green — the suite had no automated opinion on any of them. The design response is to make each *class* of those defects fail an automated gate, ordered **cheapest-and-broadest first**, so the next implementation cannot merge them and review is freed to find genuinely new problems. Findings imported from the review/implementation pass are marked **(observed)**, as elsewhere in the doc. The consolidated defect→guard index is §12.7.

The leverage ordering matters: the highest-value gates cost *zero per-test authoring* — they are crate-level lints, a feature-matrix build, doctests, and `cargo-deny`, and they catch whole defect families on every build. The hand-written unit/integration tests (§12.3/§12.4) are the next layer; the injectable seams (§12.5) are what make that layer possible — their absence is precisely why the bugs above were review-only.

### 12.1 Compiler- and lint-enforced gates

The crate root carries a deny-list. These need no test to be written; they turn defect classes into compile errors.

```rust
// lib.rs — gates that need no test written
#![deny(missing_docs)]                        // §1.1: v6 shipped `warn`, so undocumented items passed CI (observed)
#![deny(unsafe_op_in_unsafe_fn)]              // force explicit unsafe scoping
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(
    clippy::undocumented_unsafe_blocks,       // §3.3/§3.4/§7.4: setns & set_var had no `// SAFETY:` (observed)
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,               // §7.2: Result-returning fns document their errors
    clippy::missing_panics_doc,               // §7.3
)]
#![cfg_attr(not(test), deny(
    clippy::unwrap_used,                      // §3.2: hot-path panics in proxy/agent/smoltcp (observed).
                                              //       `.expect("invariant: …")` is the permitted escape hatch.
    clippy::panic, clippy::unreachable,
    clippy::todo, clippy::unimplemented,      // §4.7: a `todo!()` is loud; a silent `Ok(())` no-op is not
    clippy::indexing_slicing,                 // §5.1: the fixed-4096 buffer + single read is this family — forces `.get()`/bounded reads
    clippy::print_stdout, clippy::print_stderr, // §5.4/§1.3: proxy logged via println!/eprintln! and swallowed errors (observed) — forces `tracing`
    clippy::dbg_macro,
))]
```

Two structural rules accompany the deny-list:

- **Contain `unsafe` with per-module `#![forbid(unsafe_code)]`.** The I/O-free modules — `config`, `agent::protocol` (codec), `artifact` (`cache_key`), and the `/30` math in `net` — forbid `unsafe` outright, so it survives only in the four places that genuinely need it (`vmm` subprocess glue, `proxy::setns`, the `net::userspace` virtqueue ring handling, and the guest agent's syscalls). This matches the project-wide "isolate `unsafe` to well-defined locations" stance and makes a stray `unsafe` a compile error rather than a review note.
- **CI backstop: `RUSTFLAGS="-D warnings"` with `cargo clippy --all-targets --all-features`.** Anything left at `warn` — including a future regression back to `#![warn(missing_docs)]`, the exact §1.1 bug — still fails CI. `cargo fmt --check` is a separate required step.

The `not(test)` gating is the load-bearing trick: tests may `unwrap` freely, production paths may not. This one attribute turns every §3.2 panic site into a compile error.

### 12.2 Build-matrix and dependency gates

These catch the defects that `--all-features` hides.

- **Feature powerset.** `cargo hack --feature-powerset --depth 2 clippy --all-targets`. The single highest-value CI addition for a feature-heavy crate. It directly catches §9.1 **(observed)**: `cgroups-rs` imported unconditionally but gated behind `metrics`, which breaks `cargo build --no-default-features --features cloud-hypervisor`. `--all-features` always compiles, so without the powerset that broken combination ships green.
- **Lean-agent invariant, asserted.** A dedicated job builds `cargo build --no-default-features --features agent` and asserts the dependency tree stays thin: `cargo tree -e no-dev --no-default-features --features agent` must not contain `tokio`, `hyper`, or `rtnetlink`. This guards the §5.4 promise (the guest PID-1 binary omits the host stack) against accidental re-coupling — a promise nothing enforced before.
- **`cargo-deny` is the license/advisory source of truth.** `cargo deny check` (licenses, advisories, bans, sources) on every build. The open `am-fs-erofs` license question (§5.4 / review §9.3) is **resolved by this gate, not by reading a label** — the `rustables`-mislabeled-as-MIT incident is the precedent. A `deny.toml` must exist and be CI-enforced; the modern (allow-only) skeleton:

```toml
# deny.toml — finalize against the pinned cargo-deny (0.19.x at writing); the allow-list IS the gate.
[licenses]
allow = ["MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception",
         "BSD-3-Clause", "BSD-2-Clause", "ISC", "Zlib", "0BSD", "Unicode-3.0"]
# Anything not in `allow` fails the build — this is what disqualifies GPL/AGPL crates
# (rustables, GPL-3.0) and what `am-fs-erofs` must clear to remain in the default path.

[bans]
multiple-versions = "warn"
wildcards = "deny"           # no `*` version requirements

[advisories]
yanked = "deny"              # RUSTSEC DB; unmaintained/vulnerable crates fail unless explicitly ignored

[sources]
unknown-registry = "deny"
unknown-git = "deny"
```

- **Public-API gate.** `cargo semver-checks` on every PR. There is **no lint that requires `#[non_exhaustive]`** (§2.1), so enforcement is indirect: semver-checks turns the *consequence* — adding a field to a now-frozen exhaustive struct — into a CI failure the next time it happens, instead of a silent breaking change. The omission of `#[non_exhaustive]` itself stays a review item; pair with `cargo public-api` if you want the surface diffed per PR.

### 12.3 Unit tests — pure functions and injected seams

Each row is a pure function or seam (per the §5.6 split) and the defect it guards. `proptest` carries the invariants marked *[prop]*. None need KVM or root, so they run under a plain `cargo test`.

| Unit under test | Assertion | Guards (observed) |
|---|---|---|
| `config::VmConfigBuilder::build()` | returns `Result`; rejects duplicate share tags, virtio-fs-rootfs + snapshot, `vcpus==0`, `mem_mib==0`, empty kernel path | §2.4 — `build()` returned `VmConfig` with no validation |
| per-VM path construction | injective in `(pid, vmid)` *[prop]* — distinct vmids never share `api.sock`/`vsock.sock`/`serial.log` | §4.9 — the tmp dir was keyed on PID only; concurrent VMs clobbered each other |
| `/30` address math | guest/host/mask correct for `vmid ∈ {0,1,254,255}`; a vmid that would overflow an IPv4 octet is rejected before use *[prop]* | impl-notes — a raw VMID could exceed 255 and produce an invalid `10.200.<vmid>.1` |
| `CidAllocator` | skips reserved 0/1/2; wraps without emitting a live or reserved CID; `allocate`/`release`/re-`allocate` tracks the in-use set; thread-storm contention test (optional `loom` model) | §8.1 — a bare `static AtomicU32` wraps into reserved CIDs and isn't injectable |
| vmid allocator | wrap at 254 consults the in-use set, not just a counter | §8.1 — after 254 VMs the counter collides with live VMs |
| `agent::protocol` codec | round-trips through the `LengthDelimitedCodec` framing (not just bare postcard), incl. partial buffers and oversized-frame rejection *[prop]* | review §6.1 — only postcard was tested, not the framing layer |
| vsock handshake FSM | `Connection refused → OK` retry; **EOF → return to `accept`** (restore survival); serial-log panic → fast-fail | §4.5/§4.6 — `reconnect()` and the serial-panic watch were absent |
| CH REST request builder | golden-JSON test of the `VmConfig` payload | review §6.4 — payload builder not extracted or tested |
| CH REST response parser | handles chunked, `>4096`-byte, and `201/202/204` responses *[prop on status]* | §5.1 — read one 4096-byte chunk and matched `"HTTP/1.1 200"` by prefix |
| nft ruleset render | golden-text test; asserts the **TPROXY** form, which preserves the original destination | §4.1 — `iptables REDIRECT` cannot preserve the original destination a transparent proxy needs |
| cgroup-path construction | pure: nests under `/proc/self/cgroup`, places the VM cgroup as a *sibling* of the runner | review §6.4 / §5.3 — the logic was inline and untestable |
| `artifact::cache_key` | golden digest pinned to a stable hash; identical across processes and runs | §4.4 — `DefaultHasher` is not portable across Rust versions; the cache silently breaks |
| `Error` | `Display` + `From` per variant; `#[non_exhaustive]` compile-guard | §3.1 — three coarse variants, `Error::Other` everywhere |
| `SmoltcpProcess` / `EgressProxy` shutdown | a cancellation signal joins the worker thread/runtime within a timeout; `Drop` triggers it | §8.3 — both spawned forever with no shutdown; leaked on `TestVm` drop |
| `Drop` order | against `FakeVmm`: teardown runs VMM-proc-group → virtiofsd → netns/cgroup/overlay/sockets, and **still runs on `panic!`** | §4.8 — `TestVm` had no `Drop`; a panicking test leaks every resource |

### 12.4 Integration tests — real environment, default-skipped

**Gating.** Tests needing KVM or `CAP_NET_ADMIN` are `#[ignore]` by default (CI runs them with `--ignored` on a capable runner) and carry `#[serial_test::serial]` when they touch global host state (netns, cgroups, nft). A laptop `cargo test` therefore runs only the §12.3 unit tests and the doctests, and stays green — closing review §6.3 **(observed)**, where v6 had neither gate, so `cargo test` *failed* rather than skipped off a capable host. The two suites of §8 (privileged via the §12.8 capability runner — or `sudo -E`/a root job in CI; rootless under no elevation) keep the rootless path honestly exercised. Run the suite under **`cargo nextest` with a per-test timeout** so a hang — the virtiofsd-socket-wait or the `cgroups-rs add_task` hang the implementation pass hit — fails as a timeout instead of a stuck CI job. The CLI binary gets `assert_cmd`/`predicates` smoke tests (`build`/`run`/`exec`/`ls`/`rm`), already provisioned in §5.5.

The review found the existing integration tests assert only the happy path. The design requires the **missing assertions**, mapped to their milestones:

- `snapshot_restore.rs` (M8): the host **reconnects the severed vsock** (not merely "restore succeeds"), and the restored VM shows a **rotated CID/MAC**, a **reseeded RNG**, and a **resynced clock** — review §6.2.
- `egress_proxy.rs` (M5): **HTTPS** interception is logged; a registered **test double** answers; a **filter rule blocks a domain and the guest sees the block**; the proxy observes the **original destination** (the assertion `iptables REDIRECT` fails and `TPROXY` passes — §4.1).
- `metrics_limits.rs` (M6): `memory.max` **OOM-kills** a runaway allocator; **average CPU** is computed over a busy loop — review §6.2.
- `lifecycle.rs` (M1/M8): **ordered `Drop` teardown on `panic`** leaves zero residue — no VMM process, netns, cgroup, or socket survives, asserted via the §5.3 sweeper/registry — review §6.2 / §4.8.
- `concurrency.rs` (**new**): N VMs in one process with **no CID/VMID/socket-path collision** — the end-to-end form of the §4.9/§8.1 unit guards — review §6.2 / §9.
- `put_file` round-trip: write then read back; a no-op `Ok(())` (§4.7) fails this.
- agent **zero-netlink** assertion: with the address set by the kernel `ip=` cmdline, the injected `Netlink` fake records zero calls — guards the §5.4 contract that v6 violated by configuring the network in PID 1 (§4.2).
- a **`FakeVmm`-driven** orchestrator test exercises the full lifecycle logic (allocation order, retry/timeout, restore-vs-cold-boot selection, ordered teardown) with no KVM — review §6.4 noted `FakeVmm` exists but is unused.

**Per-VMM matrix.** Every scenario above is parameterized over the backend, not pinned to CH. The harness runs each against each compiled-in `Vmm` (the `cloud-hypervisor`, `firecracker`, and `qemu` features) and, before running a case, consults `capabilities()` (§5.2) and emits an explicit **skip-with-reason** for any backend that can't support it — so an unsupported feature surfaces as a visible, attributed gap, never a silent green. Applicability follows the §5.3 matrix: boot / exec / lifecycle / metrics / `put_file` / concurrency and the **privileged** (tap) `egress_proxy` and `host_endpoint` paths run on **all three**; `snapshot_restore.rs` runs on **all three** (CH `--restore`, Firecracker `LoadSnapshot`, QEMU `loadvm`/migrate) with the rotate/reseed/resync and severed-vsock-reconnect assertions identical and only the restore mechanism differing; `shares_ro_rw.rs` (virtio-fs) and the **nested-virt** class run on **CH/QEMU only**, with Firecracker skipped (block-only, no nesting) plus a Firecracker-specific variant that passes the same input as a block device where a scenario needs the data; the **rootless** (smoltcp) `egress_proxy`/`host_endpoint` suite runs on **CH/QEMU only** (Firecracker has no vhost-user-net for the NAT to attach to). The `FakeVmm` orchestrator test is backend-agnostic by construction. This is the integration-test complement to the §5.2 capability contract: the same `capabilities()` that lets the orchestrator pick a backend per tier defines which scenarios a backend must pass and which it is exempt from — and a backend silently *failing* a scenario it claims to support (rather than skipping one it doesn't) is itself the bug this matrix catches.

**Build-pipeline tests** (the §8 hardening track, made concrete): a **tampered package digest aborts** the build (signing chain is a hard stop, §7); a **warm-cache second build performs zero network fetches and skips stages** (cache hit); `reset_to(rootfs)` **rebuilds rootfs and snapshot but not the kernel**; **determinism** — identical pins yield a byte-identical erofs image and an identical `cache_key`. These exercise the pipeline guarantees the v6 stubs (`StageInputs`/`StageOutputs` empty, `reset_to` a no-op — review §5.8/§5.9) cannot currently meet.

### 12.5 The injectable seams are load-bearing, not optional

§5.6 lists four testability accommodations; the v6 implementation skipped them **(observed)** — it called `ip`/`nft` and read sysfs directly with no trait boundary, and used module-global `static AtomicU32` counters for CID and VMID. That is the *direct cause* of the bugs being review-only: with no fake there was no unit test that could assert the allocator wraparound, the cgroup sibling-placement, or the zero-netlink contract. The design therefore treats these as requirements with teeth:

- Side-effecting subsystems are written against a small trait — `Netlink`, `NftApplier`, `CgroupFs`, `SerialLog`, `Clock` — each with a real implementation and a recording fake, so `net`/`metrics`/`agent` orchestration can assert "the right rules/limits/handshake were requested" without touching the host.
- IDs and time come from **injected allocators** (`CidAllocator`, the vmid allocator, `Clock`), never module-global mutable statics. An optional CI grep bans new `static mut` / `static …: Atomic…` outside the allocator module.

This is the structural complement to §12.1: the lints make sloppy code fail to compile; the seams make correct code unit-testable. A subsystem that cannot be unit-tested against a fake is, by this design, not done.

### 12.6 What remains review-or-benchmark, not a pass/fail gate

Stated so these are not mistaken for covered:

- **Syscall/FFI `unsafe` is not Miri-checkable.** Run Miri on the pure-logic `unsafe` only (allocator atomics, the virtqueue ring-index arithmetic, the codec). `setns`, `mount(2)`, the vhost ioctls, and the vsock path are exercised by integration tests and gated by SAFETY review — Miri cannot execute them.
- **Mutex-poisoning cascade** (review §8.2): partly testable (panic under the lock, assert the next acquisition recovers), but the real fix is `lock().unwrap_or_else(|e| e.into_inner())` or `parking_lot`; no lint catches poison propagation.
- **Performance/density** (§3.4/§9): benchmarks for cold-boot, restore, idle RSS, the concurrent ceiling, and the asserted-but-unmeasured Exp-4 claims are **tracked metrics, not gates**, consistent with §3.4's "quote no number as fact." The full benchmark design — which contested fact each settles, the exact metric, and the misreading it guards against — is **§13** (the benchmarking counterpart to this section); a small set of *relative* invariants there do become regression guards (§13.7).
- **`#[non_exhaustive]` omission** (§2.1): semver-checks catches the resulting break, not the omission.

### 12.7 Defect → guard index

The consolidated map: each reviewed finding and the automated mechanism that now catches it ("type" = where it fires).

| Defect (ref) | Guard | Type |
|---|---|---|
| No `Drop` teardown; leak on panic (§4.8) | `FakeVmm` Drop-order unit test + `lifecycle.rs` panic-residue test | unit + integ |
| Temp-dir collision on PID-only path (§4.9) | path-injectivity prop test + `concurrency.rs` | unit + integ |
| `cgroups-rs` unconditional under a gate (§9.1) | `cargo hack` feature powerset | CI matrix |
| `.unwrap()`/`panic` on hot path (§3.2) | `deny(clippy::unwrap_used, …)` under `not(test)` | lint |
| `DefaultHasher` cache key (§4.4) | golden-digest + cross-process `cache_key` test | unit |
| Undocumented `unsafe` (§3.3/§3.4/§7.4) | `deny(undocumented_unsafe_blocks)` + `unsafe_op_in_unsafe_fn` | lint |
| `println!`/`eprintln!` logging, swallowed errors (§5.4/§1.3) | `deny(clippy::print_stdout, print_stderr)` → forces `tracing` | lint |
| `warn(missing_docs)` let items pass (§1.1) | `deny(missing_docs)` + `-D warnings` in CI | lint + CI |
| Missing `restore()`; cold/warm conflation (§2.6) | `Vmm::restore` in the trait + `FakeVmm` restore-path test | API + unit |
| Missing `reconnect()`; severed vsock (§4.5/§4.6) | handshake-FSM EOF→accept unit test + `snapshot_restore.rs` | unit + integ |
| `build()` doesn't validate (§2.4) | `config::build()` validation tests (returns `Result`) | unit |
| Coarse `Error` enum (§3.1) | per-variant `Display`/`From` tests + `#[non_exhaustive]` | unit |
| CID/VMID wraparound, not injectable (§8.1) | `CidAllocator`/vmid allocator unit + contention tests | unit |
| Thread/FD leak; no shutdown (§8.3) | cancellation+`Drop`; test asserts the worker joins after shutdown | unit |
| Fragile 4096-byte HTTP parse (§5.1) | response-parser tests (chunked/large/2xx) via `hyperlocal` | unit |
| Missing `#[non_exhaustive]` (§2.1) | `cargo semver-checks` (catches the break) | CI |
| `iptables REDIRECT` vs `TPROXY` (§4.1) | nft golden-render + original-destination integ assertion | unit + integ |
| Agent does its own networking (§4.2) | zero-netlink assertion via `Netlink` fake | unit |
| `put_file()` silent no-op (§4.7) | round-trip integ test + `deny(clippy::unimplemented/todo)` | integ + lint |
| Pipeline stubs (`reset_to`, stage I/O) (§5.8/§5.9) | cache-hit / `reset_to` / determinism pipeline tests | integ |
| `cargo test` fails off a capable host (§6.3) | `#[ignore]` + `#[serial]` gating; split suites; nextest timeout | test cfg |
| Promised seams not built (§6.4) | seams are requirements (§12.5) + a `FakeVmm` orchestrator test | design + unit |

### 12.8 Privileged tests without `sudo -E`: the capability-granting runner

**The problem with `sudo -E cargo test`.** It runs the *entire* toolchain as root — rustc, build scripts, nextest, and the test binaries — so `target/` fills with root-owned artifacts the next unprivileged `cargo build` cannot overwrite, and cargo's cache/env shift under the elevated user (the §9 observation). It is also maximally broad: everything gets full root when the privileged tests need only **`CAP_NET_ADMIN`** (tap, rtnetlink, nft/TPROXY) and **`CAP_SYS_ADMIN`** (per-test netns creation + `setns`). KVM access is *not* a capability — `/dev/kvm` is governed by the `kvm` group or an ACL, granted once with `usermod -aG kvm $USER`, and is out of scope for this helper.

**The mechanism: a tiny capability runner the harness shells through.** A standalone helper, `imp-test-runner`, is registered as the cargo/nextest **target runner** for the privileged suite, so nextest invokes `imp-test-runner <test-bin> <args…>` instead of executing the test binary directly — the same hook used for cross/qemu runners. cargo and rustc stay **unprivileged**; only the test binary is wrapped. The helper holds exactly `CAP_NET_ADMIN`+`CAP_SYS_ADMIN`, injects them into the test process via the **ambient** capability set, and execs the test **as the invoking developer's uid/gid** — so test-created files are dev-owned and the test runs with two capabilities, not full root. This retires the exact `sudo -E` ownership-and-scope problem §9 names. (`bench-vm`, §13.1, reuses the same runner for its privileged runs.)

**Blessing it — one-time, redone only when the helper itself rebuilds.** Two forms, least-privilege first:

- *File capabilities (preferred).* `sudo setcap cap_net_admin,cap_sys_admin+p target/<profile>/imp-test-runner`. The helper then holds *only* those two caps, never full root, and already runs as the dev uid — the simplest and tightest option. (Requires a filesystem with security xattrs, not mounted `nosuid`; ext4/btrfs/xfs and modern tmpfs qualify.)
- *setuid-root (fallback, e.g. a filesystem without file-cap support).* `sudo chown root:$(id -gn) … && sudo chmod 4750 …`. This momentarily grants the helper **all** capabilities on exec, so it must drop to the dev uid before running the test (sequence below). Use **4750 with the developer's group**, not `4755`: a world-executable setuid-root binary that hands out `CAP_SYS_ADMIN` (≈ root) is a local privilege-escalation for *any* user on a shared box. On a single-user box the distinction is academic; 4750 costs nothing.

Both blessings are **stripped on every rebuild** — writing the file clears the setuid bit and file caps alike. That is a *feature*, not a wart: re-blessing is a deliberate root action, so a rebuilt or tampered helper silently loses its powers instead of running modified code with privilege. The cost — one command after the helper changes — is precisely why the helper is built to **almost never rebuild**: it depends only on `rustix`+`capctl` and **not** on the `imp_testing` lib (§5.1/§5.5), so library churn never recompiles it.

**The capability hand-off (file-cap form).** Running as the dev uid with permitted set `P = {NET_ADMIN, SYS_ADMIN}`:

```rust
// imp-test-runner — sketch (rustix + capctl); no async, no lib, no_std-friendly
let need = [Cap::CAP_NET_ADMIN, Cap::CAP_SYS_ADMIN];
ensure_blessed_or_explain(&need)?;                 // else print the fix and exit non-zero (below)
let target = argv.get(1).ok_or(Usage)?;            // the test binary nextest wants to run
ensure_under_cargo_target_dir(target)?;            // defense-in-depth: refuse arbitrary paths

let mut caps = CapState::get_current()?;           // permitted already has the two (file caps)
caps.inheritable = need.iter().copied().collect(); // I := need  (allowed: each is in P ∩ bounding)
caps.set_current()?;
for c in need { ambient::raise(c)?; }              // PR_CAP_AMBIENT_RAISE — requires c ∈ P ∧ c ∈ I ✓
bounding::drop_all_except(&need)?;                 // optional: test can never acquire a 3rd cap
// execve: ambient set survives exec into a file with no caps / not setuid →
//   test's P' = E' = ambient = need, at the unchanged developer uid (capabilities(7))
Command::new(target).args(&argv[2..]).exec();      // std CommandExt::exec = execve, no extra dep
```

After exec, by the `capabilities(7)` transformation for a target with no file caps and no setuid, the test process gets `P' = E' = ambient = {NET_ADMIN, SYS_ADMIN}` at the developer's uid. **The setuid-root form is identical except** it must first `prctl(PR_SET_KEEPCAPS, 1)` (or set `SECBIT_KEEP_CAPS`), then `setresgid` / `setgroups` / `setresuid` *down to the dev uid* **before** raising ambient — raising ambient must come *after* the uid change, since the change would otherwise clear it — and it should trim `P`/`E` to the two caps for hygiene. The file-cap form needs none of that dance because it never changed uid in the first place; that is the second reason to prefer it.

**Fail loud, print the fix.** On startup the helper checks it actually holds `need` (file-cap form) or that `geteuid()==0` (setuid form); if not — almost always because it was just rebuilt — it exits non-zero and prints the exact remediation, with the path resolved from `/proc/self/exe` so it is copy-pasteable through cargo's hashed paths:

```
error: imp-test-runner is missing CAP_NET_ADMIN/CAP_SYS_ADMIN (uid=1000, no file caps).
       It was almost certainly rebuilt. Restore its privileges (one-time, until next rebuild):

           sudo setcap cap_net_admin,cap_sys_admin+p /home/v/imp-testing/target/debug/imp-test-runner

       Then re-run the privileged suite. See §12.8.
```

A `cargo xtask bless-runner` (or a `just bless` recipe) wraps that single command, so the dev loop is *rebuild → `just bless` → run*. The helper itself never invokes `sudo` (circular and surprising) — it only prints.

**Threat model and scope, stated plainly.** This is a **developer-workstation** convenience, explicitly **not** for multi-tenant or production hosts. The capabilities it grants — `CAP_SYS_ADMIN` above all — are root-equivalent in blast radius, so the privilege boundary is *who may execute the helper*: restrict it to the developer's group (file caps on a dev-owned, non-world-traversable `target/`, or 4750), keep its code minimal, and drop the bounding set so a grant can't widen. The `ensure_under_cargo_target_dir` check is defense-in-depth, not the boundary — the boundary is execute permission. If you need test processes to hold **zero** standing privilege, the heavier alternative is a small **setup broker**: a privileged, long-lived daemon that creates netns/tap/nft on request over a unix socket and passes back fds, leaving every test process fully unprivileged — more secure, more machinery, and a separate design. CI runners that are single-tenant and ephemeral can keep a dedicated root job (or the `sudo -E` fallback); the capability runner is what keeps a *shared, persistent dev box* clean.

---

## 13. Performance benchmarking

This is the benchmarking counterpart to §12. Where §12 turns each *correctness* defect into an automated gate, §13 is the instrument that settles each *performance* claim. It exists because the design rests on performance assertions that are, today, unmeasured: §3 lists contested facts the research inputs disagree on and ends with "quote no number as fact," and the Exp-4 rationale (§10) leans on a chain of "demand-paged, shared, performance-neutral" claims that have never been put on a scale. This section enumerates every such claim, the benchmark that resolves it, the exact metric, and the misreading each is prone to — so the next pass measures the right thing the right way instead of re-quoting marketing figures.

Two framing rules carry the whole section. First, **benchmarks are tracked metrics, not pass/fail gates** — absolute boot/restore/density numbers are hardware-bound, so a fixed threshold would be a lie on a different box (§3.4); the named exception is §13.7, the few *relative* invariants that become regression guards once a baseline is pinned. Second, **a number is meaningless without its substrate**: every result records the pinned CH / virtiofsd / kernel build from `pins.lock`, the host CPU/RAM/storage, and the THP/KSM/`memory_restore_mode` settings alongside it (the §3 closing rule, made operational). This pairs with §8: a milestone's performance claims are not "settled" until its §13 benchmark has run on the pinned substrate, exactly as a milestone is not "done" until its §12 gates are green.

### 13.1 Harness, method, and noise discipline

Method first, because a benchmark you can't trust is worse than none. Two tiers, paralleling §12.3/§12.4:

- **Micro (in-process, no KVM) — `criterion`.** The pure and IO-light hot-path code: the `agent::protocol` codec, `artifact::cache_key`, the `/30` math, the in-memory tar→erofs pack of a fixed tar, and a loopback vsock frame round-trip. Runs anywhere under `cargo bench` (the `micro` target, §5.5). criterion's sample-many-iterations-of-a-cheap-closure model is correct *here and only here*.
- **Macro (full-system, KVM + sometimes root, default-skipped) — custom harness.** Everything that boots a VM: cold-boot, restore, idle RSS, the density ceiling, datapath throughput. These run from the `bench-vm` bin (§5.5) on the same gated CI runner as the §12.4 integration suite — **not** under `cargo bench` — because a multi-second, root-requiring, global-state-mutating VM launch does not fit criterion's harness. On a dev box its privileged runs go through the **§12.8 capability runner** (same as the integration suite), not `sudo -E`. The harness records a full latency **distribution**, not a sampled mean.

The discipline that makes macro numbers honest:

- **Report distributions, not means — p50 / p95 / p99 / max.** Boot and restore are tail-heavy (page-fault storms, scheduler jitter, virtiofsd warm-up); a mean hides the p99 that actually bounds CI wall-clock and the density ceiling.
- **Cold vs warm is a deliberate axis, not luck.** Drop the page cache (`echo 3 > /proc/sys/vm/drop_caches`) before cold-start runs and explicitly *warm* it before warm runs — because the page-cache-sharing claim (§3.1) is the very thing under measurement, so which state the cache is in must be controlled, not incidental.
- **Control the noise floor.** Pin the harness and the VMM to disjoint cpusets, fix CPU frequency (disable turbo / `ondemand`), and record storage backend explicitly (NVMe vs network block changes erofs demand-paging behaviour). Run enough repetitions that the p95 is stable across runs, and discard a warm-up batch.
- **Never fold one-time into per-test.** Build-time costs (§13.6) are paid once per pin; hot-path costs (§13.3) recur per test. The Exp-4 argument hinges on this split, so the two never share a number.
- **VMM is a primary axis, and the cross-backend comparison *is* a result.** Every macro number carries a backend label, and each macro benchmark runs against each compiled-in backend that supports the feature under test — skip-not-fail for unsupported, the same `capabilities()` gate as §12.4. This is not optional polish: the §3.4 figures actually in dispute are *Firecracker's* (≈125 ms cold boot, ≤5 MiB overhead, 150 µVMs/s/host), so only measuring Firecracker **and** CH (**and** QEMU where it applies) on the real substrate settles them — and the output answers which backend wins which tier (§4: Firecracker for density, CH for features, QEMU for the awkward cases), making backend-per-tier a measured decision rather than a static assumption. Unsupported combinations (Firecracker has no virtio-fs, no vhost-user-net, no nesting) are absent from the matrix by capability, not by omission.

### 13.2 The contested-fact benchmarks

The core of the section: each contested or asserted performance claim, the benchmark that settles it, the metric(s) that constitute "settled," and the misreading the benchmark is designed to prevent. Refs are to the claim's origin (§3 contested facts; §10 Exp 4 assertions).

| Claim (ref) | Benchmark | Metric(s) that settle it | Misreading it guards against |
|---|---|---|---|
| **Shared-erofs page-cache density** (§3.1) — DAX is gone, so a single RO erofs base must hold *one* host copy for N guests | Boot 1→N guests off the shared erofs base, fixed workload | Host **file-backed pages attributable to the image** (`fincore` on the image file, or per-slice `memory.stat` file pages) as N grows; **marginal host RSS per added guest** | Reading total host `used` (conflates anonymous guest RAM with shared file cache); the figure that matters is image-attributable *file* pages, which should stay ~flat while marginal RSS ≈ the guest's private working set |
| **Demand-paged boot working set** (§3.1, Exp-4) — a fatter rootfs must not cost per-test boot time | Same boot, slim base vs a deliberately fatter base (e.g. +500 MB unused userland) | **Pages faulted in during boot** (fincore delta over the image across one boot, or guest major-fault count) and **boot latency**, vs total image size | Assuming on-disk image size ≈ RAM/time cost; demand-paging + the agent bypassing distro init (`init=/sbin/imp-guest-agent`) means untouched files are never paged, so working set and latency should be ~flat in image size |
| **userfaultfd lazy restore** (§3.3) — the headline ≈7,140 ms→≈83 ms restore, ≈2,048 MB→≈7 MB RSS | Restore the same snapshot, eager vs `memory_restore_mode` lazy | **restore→resume latency**, **RSS immediately post-resume**, and **time-to-first-useful-work** (resume → first agent response under a real workload, i.e. *including* fault-in) | Quoting resume latency alone — lazy restore moves cost to first-touch page faults, so the honest figure is time-to-first-work, where the lazy win shrinks or grows with the workload's touch set |
| **Cold-boot latency** (§3.4) — "<100 ms" vs "~200 ms" | `create→boot→agent Ready` on the real kernel/rootfs/hw | Latency distribution, **console-enabled and console-disabled as an explicit axis** | Comparing a console-off vendor figure (Firecracker's ~125 ms was measured with the serial console disabled) against a console-on local run; reproduce both so the console tax is a measured delta, not a hidden one |
| **Restore latency, per-test critical path** (§3.4) | `restore→resume→vsock reconnect→Ready`, **including** identity rotation + RNG reseed + clock resync (§7) | Latency distribution of the *complete* warm-start path | Timing `resume` but omitting the mandatory reconnect+rotate+reseed — the per-test path cannot skip them, so a number that excludes them overstates the warm-start win M8 claims over cold boot |
| **Idle guest RSS** (§3.4) | Park a booted (and separately, a restored) VM idle; sample steady state | Steady-state host RSS per parked VM, **post-KSM / post-balloon** | A pre-balloon, pre-KSM snapshot overstates steady-state footprint and therefore understates the density ceiling |
| **Density ceiling + start throughput** (§3.4) — the "150 µVMs/s/host" figure | Ramp concurrent VMs per RAM tier to the first OOM / SLA breach; separately, sustained VMs-started-per-second (cold and restore) | **Max concurrent VMs per RAM tier**; **sustained start rate** under teardown pressure | A peak *instantaneous* rate (marketing) vs a sustained rate while teardown (§4: kill-VMM→virtiofsd→netns) competes for the same host |
| **Snapshot ↔ virtio-fs-data composition** (§3.2) — feasibility fork with a measured fallback | Attempt restore of a snapshot with a virtio-fs *data* share attached on the pinned CH/virtiofsd | **Boolean composes/fails**; if it fails, the **fallback cost** — same RO data served as an extra erofs/block image (extra build time + extra page-cache) vs the virtiofsd share | Treating this as pure correctness — the fallback that §3.2/§9 already anticipates has a real, measurable density cost that belongs in the budget, not a footnote |
| **OCI-vs-mmdebstrap hot-path parity** (Exp-4) — "performance-neutral on the hot path" | Run §13.3/§13.4 against the *same* erofs image built from each source | **Delta** in boot / restore / idle RSS / density ceiling between the two sources (expected ≈ 0) | Assuming the source can affect the hot path at all — it must not, since both produce the same erofs; this row is the guard that catches a future change making one source emit a heavier image |
| **Snapshot-size independence** (Exp-4) — "snapshots capture guest RAM, not the rootfs disk" | Snapshot the same workload on slim vs fat rootfs | **Snapshot artifact size** and **restore latency** vs rootfs image size (expected ~flat) | Assuming a bigger rootfs ⇒ a bigger or slower snapshot; the snapshot is guest RAM + device state, so it should be independent of the on-disk rootfs |

Per §13.1, every row that boots or restores a VM is run across the supported backends, so the table states the *metric*, not the backend. Three rows are backend-shaped: **cold-boot**, **density/throughput**, and **idle RSS** must include Firecracker as well as CH — those are the rows that settle the disputed *Firecracker* figures; **userfaultfd lazy restore** is explicitly a cross-backend comparison of CH `memory_restore_mode` against Firecracker's UFFD path (two different lazy-restore mechanisms — measure both, the delta is the point); and the **snapshot ↔ virtio-fs-data composition** probe is **CH/QEMU only** — it does not arise on Firecracker, which has no virtio-fs to compose with snapshot (a Firecracker tier serves read-only data as block images unconditionally, so its "fallback" is the only path). The OCI-vs-mmdebstrap parity and snapshot-size rows are backend-agnostic and run wherever snapshots do.

### 13.3 Per-test critical-path budget

The number density and throughput ultimately reduce to. Instrument one test end-to-end as `tracing` spans — acquire artifacts → allocate {slice, net, CID} → start {restore | cold-boot} → vsock connect + handshake → exec → collect → ordered teardown — and report the **distribution per phase**, so a regression is localized to the phase that moved rather than buried in a single total. Two separate budgets: the **restore path** (the hot path for most tests) and the **cold-boot path** (opt-in tests that mutate global state, §4). Teardown is on the budget on purpose: §4's reap-VMM-first ordering trades a little teardown latency for the no-leak guarantee, so that cost is measured, not assumed-free.

### 13.4 Density and memory levers

DAX is gone (§3.1/§9), so the density story rests on the levers that replace it — which makes each lever's effectiveness itself a tracked number. **KSM:** dedup ratio from `pages_shared` / `pages_sharing`, and its CPU cost. **Balloon + free-page-reporting:** pages reclaimed under host pressure, and reclaim latency. **Shared-erofs file cache:** the image-attributable-pages figure from §13.2. **Idle RSS** and **marginal RSS per guest** (§13.2) combine with these into the per-RAM-tier ceiling. Reported together because the ceiling is their joint product, not any one in isolation.

### 13.5 Datapath and I/O

- **vsock control plane** — frame round-trip latency (micro, §13.1) and IO-streaming throughput (stdout/stderr/file). This path gates `exec` responsiveness on every test.
- **virtio-fs shares** — read/write throughput per share, with attention to **`imp-bin`**: binaries arrive over it and it is shared RO across all tests, so its page-cache hit behaviour is a density lever, not just a throughput number.
- **Egress-proxy overhead, privileged vs rootless** — added latency/throughput of **tap + TPROXY** (privileged, all three backends) against the **in-process smoltcp L4 NAT** (rootless, **CH/QEMU only** — Firecracker has no vhost-user-net, §5.3). §9 already flags the smoltcp datapath as lower-*fidelity*; this puts a *cost* number next to the fidelity/convenience trade so it is decided on data, not vibes.
- **reflink overlay cliff (tracked, conditional)** — only if a writable *disk* overlay is ever used (§9): clone time and space on XFS/Btrfs vs ext4, where `FICLONE` silently degrades to a full copy. Measured so the cliff is visible up front rather than discovered as a mysterious slowdown in production.

### 13.6 Build-time (offline) benchmarks

Paid once per pin, never on the per-test path — the Exp-4 distinction, kept separate from §13.3 by §13.1's rule.

- **erofs image build wall-clock: OCI source vs `mmdebstrap`-in-VM source.** Settles Exp-4's "build time may even drop by skipping `mmdebstrap`'s per-package dpkg unpack/configure" — but counted as a **whole-pipeline** number that *includes the in-VM source's builder-VM boot*, so the comparison is honest rather than mmdebstrap-step-only.
- **Source/blob cache: cold vs warm.** Warm cache = zero network fetches and skipped stages (also a §12.4 correctness test); here the metric is the wall-clock saved.
- **`am-fs-erofs` pack throughput** (micro). Output *byte-stability* is a determinism test (§12.4), not a perf metric; pack *time* is.
- **Builder-VM amortization.** build-time-per-pin ÷ tests-per-pin, to show the in-VM source's one-time cost vanishes at realistic reuse — the quantitative form of "build-time, not per-test."

### 13.7 Tracked metric vs regression guard

The honesty boundary, paralleling §12.6. Most of §13 is observational; a minority graduates to a guard.

- **Stays observational (no threshold).** Absolute cold-boot/restore ms, the density ceiling, start throughput, idle RSS — all hardware-bound. Record and trend across pins; **never gate**, because the same code on a slower box would "fail" a fixed bar (§3.4).
- **Becomes a regression guard once a baseline is pinned.** The *relative* invariants, which are portable across hardware because they are deltas or ratios: OCI-vs-`mmdebstrap` hot-path parity (§13.2 — a delta of ≈ 0); boot working set flat in image size (§13.2); snapshot size flat in rootfs size (§13.2); and the per-test critical-path **phase shares** (§13.3 — a phase doubling its share of the budget is a regression even when absolute ms move with the hardware). These guard ratios, not absolutes — which is the only kind of performance assertion that survives a hardware change. Each guard is **per-backend**: a parity or flatness invariant is checked separately for CH, Firecracker, and QEMU, since a regression can hit one backend's path and not another's.
- **Cross-backend selection is a tracked output, not a guard.** The backend-per-tier choice (§4: Firecracker for density, CH for features, QEMU fallback) is *informed* by the cross-VMM numbers (§13.1) but stays observational — relative VMM performance shifts with kernel, hardware, and the pinned VMM builds, so the matrix is re-read per pin rather than frozen into a threshold. What it does feed is which backend each tier *defaults* to, and that default is revisited when a pin moves.
- **Milestone wiring.** A benchmark attaches to a milestone like a test does (§8): restore/density numbers cannot exist before **M8**; the privileged-vs-rootless datapath comparison needs **M9**; the build-time source comparison needs the in-VM `mmdebstrap` source (post-**M4**). The §3 contested facts are not closed until their §13 row has run on the pinned substrate — which is what turns the §3 caveat and the closing note below from open questions into measured results.

---

*Version/feature claims reflect the mid-2026 research inputs; CH was at v52.0 and Kata 4.0 in preview at research time. Re-verify the §3 contested items — DAX availability, snapshot/virtio-fs composability, userfaultfd restore, nested-virt flags, and all boot/density numbers — against the exact tool versions pinned in `pins.lock`. §13 is the suite that performs that re-verification and settles the numbers.*
