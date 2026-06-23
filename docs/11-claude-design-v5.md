# Imp Testing — Design Document

*An end-to-end integration-testing and evaluation platform for the **Imp** agentic harness. Each test runs in a fresh micro-VM for structural isolation, hermetic state, and production fidelity. Driven entirely from a single Rust library.*

This document synthesizes the project requirements with the five research/fact-check inputs (`1-claude-design`, `2-gemini-research`, `3-claude-research`, `4-claude-fact-check`, `5-gemini-fact-check`). Where those inputs disagree, the disagreement is called out explicitly and the design is made robust to the conservative reading. **One synthesis note up front:** the most *recent* input (the Gemini fact-check) re-introduced at least one claim (virtio-fs DAX availability) that the earlier Claude fact-check had already refuted with verbatim primary-source quotes, and it did not surface the snapshot/virtio-fs incompatibility. "Most recent" is therefore not treated as "most authoritative"; contested points are flagged in §3 and must be re-verified against the exact pinned tool versions.

**This revision incorporates findings from two implementation passes and a dependency-substitution study.** None overturned the architecture. The first pass drove the rootfs strategy (now erofs-read-only-shared by default, §3.2 / §6 / §7), the explicit guest-kernel config fragment (§7), the vsock readiness handshake and PID-1 contract (§5.2 / §5.3), and the two-mode networking fork with its proxy coupling (§5.3 / §6 / §9). The second pass pinned the CH snapshot/restore API sequencing (pause→snapshot, restore→resume — never boot — §5.2 / §9), the vsock reconnect after restore (§5.2 / §5.3), the agent's dynamic-glibc default (§5.1 / §5.4), and several build-host quirks (§7). The dependency study corrected a licensing error (`rustables` is GPLv3, so privileged TPROXY is applied via the `nft` binary — §5.4) and seeded the future-work experiments (§10). Inline call-outs mark where an implementation actually tripped.

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
| **Secondary VMM** | **Firecracker** behind the same trait, for the dense / no-nesting / no-shared-FS test tier (≤5 MiB VMM overhead, ~125 ms cold boot). | Optional perf backend; cannot do virtio-fs or nested virt. |
| **Fallback VMM** | **QEMU `microvm`/`q35`** as a documented escape hatch and the most-proven nester. | C/GPL **binary** (acceptable as an external tool, not linked). |
| **Control plane** | **virtio-vsock + a Rust guest agent as PID 1** (dynamically linked against the rootfs glibc by default; static-musl optional, §5.4) speaking a framed (postcard) protocol (`Ready`/`Exec`/`Stdout`/`Stderr`/`Exit`). Host connects with a **retry/handshake loop** and **reconnects after restore** (§5.2). Serial console wired to a per-VM log for panic capture *and* fast-fail. SSH only as a human debugging fallback. | Requirement 10 "great" tier (vsock client+server in Rust). |
| **Shared dirs** | **virtio-fs, one `virtiofsd` per share**, `--read-only` for inputs/binaries, rw for output; CH `--memory shared=on`; `cache=never`. | Requirement 2 mandatory + "great" (per-mount perms). The "good" extra (host page-cache sharing) is partially recovered by the erofs RO base below, not by DAX (§3.1). |
| **Root filesystem** | **erofs read-only image over `virtio-blk`**, shared by all concurrent VMs with **no per-VM copy**; per-VM writes go to a **tmpfs `overlayfs` upper**. erofs has no journal → no recovery writes, no concurrent-mount corruption. | Eliminates the v1 ext4 pitfalls (§3.2); composes with snapshot/restore (it is a plain block device, not vhost-user). |
| **Host-served endpoints** | Per-VM **network namespace + tap + `/30`** (privileged mode) *or* **`passt`** (rootless mode); host test servers reachable, not exposed beyond the VM. Dynamic ports configured after listen. | Requirement 3 mandatory + both "great" extras + "other protocols." Mode chosen via `NetConfig` (§5.3 / §9). |
| **Transparent proxy** | **nftables `TPROXY`** in privileged mode, **`passt` outbound interception** in rootless mode → a **Rust MITM proxy** (`hyper`+`rustls`, or `hudsucker`) with logging, filtering, pluggable **test doubles**, CA baked into the guest trust store. | Requirement 4 mandatory + "great." **Two implementation variants, selected by the networking mode** (§6.4). |
| **Monitoring / limits** | One **cgroup v2 slice per CH (and per virtiofsd) process**; read `memory.peak`/`memory.current`/`cpu.stat`/`io.stat`; enforce `memory.max`/`cpu.max`/`pids.max`/`io.max`. Rootless runs target a **delegated** subtree, not a root slice (§9). | Requirement 8 (peak + average resource usage). |
| **Guest OS** | Minimal **Debian Trixie (13, kernel 6.12 LTS)** rootfs via **`mmdebstrap`**; agent injected with `--customize-hook=copy-in`. | Requirement 5 "good" tier (stripped Debian via supported methods). |
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
│   ├─ per-test:  cgroup v2 slice  →  {netns + tap (/30)  |  passt}                       │
│   ├─ AgentClient (tokio-vsock / AF_UNIX, retry+handshake)   ⇄   imp-guest-agent (PID 1) │
│   ├─ virtiofsd × N  (imp-in ro · imp-bin ro · imp-out rw)                               │
│   ├─ EgressProxy (hyper+rustls):  {nft TPROXY | passt path}  →  log/filter/doubles → WAN│
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
2. **Allocate per-test resources:** a cgroup v2 slice, networking (netns+tap on a fresh `/30`, or a `passt` instance), and a unique vsock **CID** (§5.2). The erofs base is mounted read-only and shared — *no per-VM disk copy*; writable state is the tmpfs overlay.
3. **Start the VM:** either **restore** a warm "agent-ready" snapshot (fast path: launch CH `--restore` → `vm.resume`, **not** create/boot) or **cold-boot** (`vm.create` → `vm.boot`; opt-in for tests that mutate global state the snapshot would have baked in). On restore, **rotate identity** (vsock CID, MAC/IP, reseed entropy via virtio-rng) and **resync the guest clock** (§7 snapshot stage).
4. **Bind shares:** point `imp-in` / `imp-out` virtiofsd at this test's input/output dirs; `imp-bin` is shared read-only across all tests so its pages stay hot.
5. **Connect + drive over vsock:** the host `AgentClient` retries the vsock `CONNECT` handshake until the guest's `Ready` frame arrives (bounded by a timeout), while tailing the serial log so a boot panic fails fast instead of retrying to no avail. Then `Exec` the entrypoint; stream stdout/stderr/exit. **On the restore path the connection must be re-established, not reused:** CH re-creates the host-side vsock socket on restore, severing the prior connection (the guest sees EOF), so the host reconnects to the new socket. This is fast (the agent is already listening) but it is *not* a no-op, and the guest agent must serve connections in a loop (§5.3).
6. **Collect results:** outputs from the host `imp-out` dir; `memory.peak`/`cpu.stat`/`io.stat` from the slice; the proxy's request log.
7. **Tear down (ordered):** force-kill the **VMM process group first**, then the virtiofsd processes, *then* remove the tap/netns/cgroup/overlay/sockets. Removing a netns while the VMM still holds interfaces or threads in it can hang or leak; reaping the process first makes teardown a clean kernel operation. Discard is structural — that *is* the no-leakage guarantee.

### Why a `Vmm` trait rather than a single VMM
Both `mvm` and Kata abstract over multiple VMMs because each is optimal for a different slice (Firecracker for density, CH for features, QEMU for the awkward cases). Modeling the lifecycle as a narrow, well-typed contract (`create/boot/request_shutdown/kill/snapshot/restore/stats`) keeps the finicky, subprocess-supervising, occasionally-`unsafe` VMM glue behind a boundary and lets the orchestrator stay idiomatic and unit-testable (a `FakeVmm` implements the same trait — see §5.6).

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
│  │  └─ passt.rs             # rootless user-mode networking + outbound interception
│  ├─ proxy/
│  │  ├─ mod.rs               # EgressProxy: listen, log, filter, dispatch
│  │  ├─ tls.rs               # MITM CA, on-the-fly cert minting (rcgen/rustls)
│  │  └─ doubles.rs           # test-double + record/replay (cassette) hooks
│  ├─ metrics.rs              # cgroup v2 slice mgmt + peak/avg readers (cgroups-rs)
│  ├─ artifact/
│  │  ├─ mod.rs               # Stage trait, Pipeline, cache, record/replay, signing
│  │  ├─ kernel.rs            # vmlinux build stage (+ the config fragment, §7)
│  │  ├─ rootfs.rs            # mmdebstrap rootfs build stage → erofs pack
│  │  └─ snapshot.rs          # warm-snapshot build stage
│  ├─ orchestrator.rs         # TestVm handle tying it together; ordered Drop teardown; sweeper
│  └─ error.rs                # crate Error/Result (thiserror)
├─ src/bin/
│  ├─ imp-testing.rs          # CLI wrapping the lib (clap): build, run, exec, ls, rm …
│  └─ imp-guest-agent.rs      # guest PID 1 (dynamic-glibc default; static-musl optional); uses agent::protocol
└─ tests/                     # one integration test per requirement / VM operation
   ├─ boot.rs                 ├─ exec_vsock.rs        ├─ shares_ro_rw.rs
   ├─ host_endpoint.rs        ├─ egress_proxy.rs      ├─ metrics_limits.rs
   ├─ nested_virt.rs          ├─ snapshot_restore.rs  └─ lifecycle.rs
```

`imp-guest-agent` runs as the `init=` target. Because it executes as PID 1 on an *already-mounted* rootfs that ships `libc6` (via `mmdebstrap minbase`), the simplest build is **dynamically linked against the rootfs glibc on the host gnu target** — no extra toolchain, and it works because the rootfs's loader and libc are present by the time the kernel execs init. A fully static `musl` build is **optional**, for a rootfs-independent agent; it requires `musl-tools` on the build host, which the implementation pass found is not installable without root in some CI environments (§5.4). Either way the binary shares only the small `agent::protocol` module with the host, keeping "all functionality in one library crate" essentially true while the guest binary stays thin.

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
    pub shares: Vec<Share>,     // virtio-fs mounts (data/binaries/output)
    pub net: NetConfig,
    pub nested_virt: bool,      // build/boot guest kernel with KVM exposed
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
    /// Rootless via passt; egress interception moves into passt's outbound path.
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
    /// Cold path: spawn + configure the backend (does not start the guest yet) → boot().
    async fn create(&self, cfg: &VmConfig, res: &PerVmResources) -> Result<Self::Instance>;
    /// Warm path: launch CH with `--restore`. The returned instance is ALREADY created;
    /// continue it with resume() — NOT boot()/create(). (CH returns
    /// "500 VM is already created" if you boot a restored VM.)
    async fn restore(&self, snapshot: &Path, res: &PerVmResources) -> Result<Self::Instance>;
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
    fn vsock_path(&self) -> &Path;                     // AF_UNIX endpoint for AgentClient (changes across restore)
    fn guest_cid(&self) -> u32;                         // unique per running VM (>= 3)
    fn serial_log(&self) -> &Path;                     // per-VM panic/early-boot log
}

// ---- agent/mod.rs ---------------------------------------------------------
pub struct AgentClient { /* tokio-vsock connection */ }
impl AgentClient {
    /// Opens the CH AF_UNIX vsock socket and performs the hybrid-vsock handshake
    /// (`CONNECT <port>\n` → expect `OK <port>\n`), retrying with backoff until the
    /// guest is listening and has sent `Ready`, OR `timeout` elapses, OR the serial
    /// log shows a kernel panic (fail fast).
    pub async fn connect(vsock_path: &Path, port: u32, timeout: Duration,
                         serial_log: &Path) -> Result<Self>;
    /// Re-establish after a snapshot restore. CH re-creates the host vsock socket, so the
    /// prior connection is severed (guest sees EOF). The guest is already listening, so this
    /// is fast — but it is NOT a no-op: drop the old client and connect to the new socket.
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
- **`vmm`** — The trait boundary and backends. `cloud_hypervisor` owns: spawning the `cloud-hypervisor` process with `--api-socket`; constructing the `VmConfig` REST payload; the lifecycle calls; reading `counters`; and snapshot/restore. **The lifecycle is two distinct paths the implementation pass pinned down:** cold = `vm.create` → `vm.boot`; warm = launch with `--restore` → `vm.resume` (never `create`/`boot` — CH returns *500 "VM is already created"*). `snapshot` must `vm.pause` first, then snapshot, then `vm.resume` (or leave paused if the VM is about to be killed). The REST client is a hand-written thin wrapper over `hyperlocal` (Unix-socket HTTP) with `serde` types generated from CH's in-repo OpenAPI YAML (or vendored from `cloud-hypervisor-client`, pinned; `firecracker-rs-sdk` is the analogue for the Firecracker backend). `mod` also owns a **CID allocator**: every running VM needs a unique guest context ID (≥ 3), handed out collision-free and rotated on restore. `firecracker` and `qemu` are feature-gated and implement the same traits.
- **`agent`** — `protocol` defines a small length-prefixed, `serde`+`postcard`-framed message enum (the implementation pass standardized host and guest on postcard's length-delimited framing): `Hello/Ready`, `Exec{argv,env,cwd}`, `Stdout(bytes)`, `Stderr(bytes)`, `Exit(i32)`, `PutFile`, `Ping`. `mod` is the host client; its `connect` implements the **CH hybrid-vsock handshake** (CH does *not* accept a bare `connect()` — the host opens the Unix socket and writes `CONNECT <port>\n`, expecting `OK <port>\n`), retrying until the guest binds and sends `Ready`, with a timeout and a serial-log panic watch so a dead boot fails fast. **Implementation note (observed):** CH accepts the Unix-socket connection *before* the guest has booted and bound, so without this retry the host sees `Connection refused`/handshake failure; the retry belongs at the handshake level, not around a single `connect()`.

  The guest side lives in `src/bin/imp-guest-agent.rs` and runs as **PID 1** (via `init=/sbin/imp-guest-agent`). Its contract is larger than "serve the protocol," and missing any of it is painful to debug:
  - mount `proc`, `sys`, `devtmpfs`, the virtio-fs tags, and set up the **tmpfs `overlayfs`** over the read-only erofs root;
  - install the proxy CA into the trust store and bring up loopback (the guest address is set by the kernel `ip=` boot parameter in privileged mode, or by passt in rootless mode — PID 1 needs no netlink, see §5.4);
  - **reap zombies** (`SIGCHLD`/`waitpid`) — PID 1 is the universal reaper; skip this and the guest fills with defunct processes;
  - **never exit** — if PID 1 returns, the kernel panics with "init died"; and
  - **fork** the test command as a child (not `exec` into it) so the agent stays PID 1 and retains the control channel and reaping duty;
  - a **boot-time self-check**: probe for the device nodes / FS support it depends on (vsock, virtio-fs) and emit a clear diagnostic before binding, so a missing-kernel-symbol regression fails legibly instead of as a raw errno panic;
  - **serve connections in a loop, not one-shot:** after a snapshot restore the host reconnects on a freshly re-created vsock socket, so the agent must detect the old connection's EOF, return to `accept`, and handle the next client (validated by the implementation pass). (Pattern overall validated by `mvm`'s "vsock-only agent, NO SSH ever.")
- **`fs`** — Spawns one `virtiofsd` per `Share`, each on its own Unix socket, with `--read-only` for `ReadOnly` shares and a `--sandbox namespace` + dedicated uid so a daemon can reach only its one directory. Emits the CH `--fs tag=…,socket=…` config and ensures `--memory shared=on`. Cache policy defaults to `never` (density). **Note:** attaching virtiofsd (a vhost-user device) is what makes a VM ineligible for CH snapshotting (§3.2), so the snapshot tier attaches data shares only if post-restore attach is validated.
- **`net`** — Two implementations behind `NetConfig` (see §6.3/§6.4 and §9):
  - `tap` (**privileged**): a per-VM network namespace, a `veth`/tap pair, and a `/30` (`10.200.<vmid>.0/30`, host `.1`, guest `.2`) via `rtnetlink`; an nftables `TPROXY` redirect of guest tcp/80,443 (and optionally udp/443) to the host proxy, plus `drop`/`log` rules. **The ruleset is rendered in Rust but applied via the external `nft -f -` binary** — no permissive pure-Rust nftables crate covers the TPROXY/`socket` expressions (`rustables` is GPLv3; see §5.4 and the §10 experiment).
  - `passt` (**rootless**): a user-mode networking daemon attached to the guest's virtio-net; egress interception moves into passt's outbound path (point its forwarding at the local proxy, or use passt itself as the choke point) since there is **no tap to hang nftables off** in this mode.
  The `/30` math and the nft-ruleset rendering are pure functions → unit-tested; the netlink calls, the `nft` invocation, and passt are the side-effecting part.
- **`proxy`** — A `hyper`-based transparent proxy. For HTTP it splices/logs; for HTTPS it terminates TLS with an on-the-fly cert minted by an in-memory CA (`rcgen`) and re-originates upstream (`hudsucker` can supply this whole MITM machinery if preferred — Apache/MIT). `doubles` lets a test register `(Matcher, Responder)` pairs (the "great extra") and, for the eval layer, record/replay cassettes. The proxy *process* is mode-independent; how traffic is *steered into it* is not (TPROXY vs passt), so this module exposes one proxy with two front-ends.
- **`metrics`** — Creates the per-VM cgroup v2 slice (via `cgroups-rs`), applies `ResourceLimits`, and reads `memory.peak`/`memory.current`/`cpu.stat`/`io.stat` plus tap/passt counters for net I/O. Peak comes "for free" from `memory.peak`; average is computed from periodic `cpu.stat`/`io.stat` deltas over the run. **Rootless caveat:** the cgroup-v2 "no internal processes" rule plus unprivileged restrictions mean limits must target a **systemd-delegated** subtree (`Delegate=yes`), not a root-level slice — the orchestrator takes the delegated slice path as config.
- **`artifact`** — The staged build pipeline (full detail in §7): a `Stage` trait with a *pure* `cache_key`, a `Pipeline::build` that skips stages whose outputs already exist, and `reset_to` for invalidation. First stage resolves the up-to-date pins; all later stages are deterministic given their inputs.
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
| Networking (rootless) | `passt` **binary** | Good (binary) | GPL-2.0+ / BSD (binary, not linked) |
| Egress proxy | **our Rust** (`hyper`+`rustls`/`rcgen`, or `hudsucker`) | Best/Great | MIT/Apache |
| Monitoring/limits | **our Rust** cgroup v2 (`cgroups-rs`) | Great | MIT/Apache |
| Rootfs build | `mmdebstrap` **tool** (build-time only) | Okay (external build tool) | GPL/Free (not linked) |
| erofs pack | `mkfs.erofs` (erofs-utils, build-time) | Okay (build tool) | GPL-2.0+ (not linked) |
| Kernel build | Debian kernel source + toolchain (build-time) | per requirement 6 "good" | GPL (source, build-time) |
| Fallback VMM | `qemu-system` **binary** (QMP via `qapi`) | Okay (binary) | GPL-2.0 (binary, allowed as exception) |

The install-mechanism view is what the README's "required tools" list ultimately encodes, and it splits three ways.

**(A) Linked crates — the bulk of the work, all permissive.** The complete, grouped list is the `Cargo.toml` in §5.5. The notable point is how much that a naive implementation would shell out to is instead a linked crate, kept inside Cargo and under `cargo-deny`'s license gate:

| Capability | Naive OS tool | Crate (linked) |
|---|---|---|
| netns / tap / addrs / routes | `iproute2` (`ip`) | `rtnetlink` + `netns-rs` + `tun-tap` |
| Debian `InRelease`/`Release.gpg` verify | `gpgv` / `gpg` | `pgp` (rPGP) |
| Fetch in record-step (apt snapshot, kernel src) | `curl` / `wget` | `reqwest` (rustls) |
| Reflink overlay clone | `cp --reflink` | `reflink-copy` (FICLONE) |
| Verify Debian SHA256 digests | `sha256sum` | `sha2` |
| MITM CA + leaf cert minting | `openssl` | `rcgen` + `rustls` |
| cgroup v2 limits + peak/avg readout | parse `/sys` by hand / `systemd-cgtop` | `cgroups-rs` + `procfs` |
| vsock control channel | `socat`/`ncat` over vsock | `tokio-vsock` (host), `vsock` (agent) |

**(B) Cargo-installable binaries, run as subprocesses (not linked).** The standout is **`virtiofsd`**: it is `cargo install virtiofsd` (a rust-vmm binary, Apache-2.0 AND BSD-3), so shared-directory support needs no OS package — it can be pinned exactly like a crate. Dev tooling is the rest of this bucket: `cargo install cargo-deny` (the license/advisory gate) and `rustup component add rustfmt clippy`. **By contrast, Cloud Hypervisor is *not* cargo-installable** — it ships as GitHub release binaries (or a distro package) and has no embeddable library crate, so it is pinned and supervised as an external process; only its REST *client* is a crate (hand-rolled over `hyper`/`hyperlocal`, generated via `progenitor`, or the unofficial `cloud-hypervisor-client`).

**(C) Irreducibly external — OS packages, release binaries, or kernel features.** No Cargo path exists; this is essentially the README's external-tools section:
- **`cloud-hypervisor`** — pinned release binary. The VMM.
- **`mmdebstrap`** — `apt install mmdebstrap`. Rootfs assembly.
- **`erofs-utils`** (`mkfs.erofs`) — `apt install erofs-utils`. Packs the read-only root image.
- **Kernel build toolchain** — `gcc`/`clang`, `make`, `flex`, `bison`, `bc`, `libelf-dev`, `libssl-dev`, `cpio`. For the custom `vmlinux`.
- **`passt`** — `apt install passt`. Rootless networking mode only (M9).
- **`nftables`** (`nft`) — `apt install nftables`. Applies the privileged-mode TPROXY/`drop`/`log` ruleset via `nft -f -`; no permissive pure-Rust crate covers the needed expressions (caveat below; §10 experiment).
- **`qemu-system-x86`** — `apt install qemu-system-x86`. Fallback VMM only.
- **KVM** (`/dev/kvm`; host `nested=1` for M7) — kernel feature.
- A C compiler (`cc`) at build time — pulled transitively by `zstd`/`rustls` backends; standard Rust build tooling, not a runtime tool.

(In-guest tools such as `update-ca-certificates` live inside the Debian rootfs, not in the host dependency set.)

**Feature-gating for a lean agent.** Heavy host crates are `optional = true` and pulled in by features (§5.5). The guest agent is built with `--no-default-features --features agent`, so it compiles only `serde`/`postcard`/`thiserror` plus `vsock`/`rustix`/`signal-hook` — no tokio, hyper, or netlink — keeping the static musl PID-1 binary small and simple to cross-compile.

**Dev-dependencies are themselves crates:** `axum` to stand up host-side HTTP servers in the requirement-3 tests, `assert_cmd`/`predicates` to exercise the CLI, and `serial_test` to serialize the integration tests that touch global host resources (netns, cgroups, nft) — directly addressing the concurrency hazard the implementation pass hit.

**Caveats that shaped the choices:**
- **nftables has no permissive pure-Rust path today; apply TPROXY via the `nft` binary.** `rustables` — the obvious pure-netlink crate — relicensed to **GPL-3.0-or-later** at 0.8, so it is disqualified by the copyleft prohibition (and `cargo-deny` would reject it). The remaining options each have a catch: `nftables-rs` (the `nftables` JSON crate, MIT/Apache) still requires the `nft` binary + `libnftables`; `nftnl-rs` is FFI to the C `libnftnl`; the pure-Rust `jip-nftables`/`nftables_netlink` is obscure and unverified for the TPROXY + `socket` expressions. Since the ruleset is small, fixed, and security-critical, the design **renders the ruleset in Rust and applies it via `nft -f -`** (an external binary, bucket C) — correctness over purity. Replacing `nft` with a vetted permissive crate is a future-work experiment (§10).
- **`lzma-rs` (pure Rust) vs `xz2` (links `liblzma`).** Debian kernel tarballs are `.tar.xz`. `lzma-rs` keeps it in-Cargo at a speed cost; `xz2` is faster but adds an OS `liblzma-dev` dependency. The sketch uses `lzma-rs`.
- **Agent linking: dynamic-glibc by default, static-musl optional.** The agent runs as init on an already-mounted rootfs that ships `libc6` (via `mmdebstrap minbase`), so dynamic linking against the rootfs glibc works and needs no extra host toolchain — this is the default. A fully static `musl` build (for a rootfs-independent agent) is optional and requires `musl-tools` on the build host, which the implementation pass found is not installable without root in some CI environments. `rustix` (linux_raw) keeps the agent's syscalls libc-free and helps the static build; `nix` (libc-based) is the host's choice for `setns`/`unshare`.
- **Networking config stays out of the agent.** Rather than have PID 1 configure `eth0` (which would pull netlink into the agent), the address is set via the kernel `ip=` boot parameter (`CONFIG_IP_PNP=y`, §7) in privileged mode, or by passt in rootless mode. That is why the `agent` feature has no networking crates.
- **Versions in the sketch are floors.** Exact mid-2026 versions are deliberately unpinned; resolve them with `cargo add` and lock the result through `cargo-deny`, consistent with the `pins.lock` discipline in §7. The two crate facts already corroborated by the research inputs are the `virtiofsd` crate and `cloud-hypervisor-client` 0.3.x.
- **Trust `cargo-deny`, not hand-written license labels.** An earlier draft of this manifest labeled `rustables` MIT/Apache when it is in fact GPL-3.0-or-later — exactly the class of error the `cargo-deny` allow-list (run on every CI build) exists to catch. The license notes in this document are guidance; the gate is the source of truth.

License gate: `cargo-deny` enforces an allow-list (MIT/Apache-2.0/BSD-3/ISC/Zlib) for all *linked* crates and fails the build on copyleft or non-OSI licenses. Build-time tools (mmdebstrap, mkfs.erofs, the kernel toolchain), `passt`, and the QEMU fallback are external executables, not linked, so their copyleft status is acceptable under the requirements.

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
# host gnu target (mmdebstrap minbase ships libc6) — no extra toolchain needed.
# OPTIONAL fully static build for a rootfs-independent agent (needs `musl-tools` on the
# host, which may be unavailable without root in CI):
#   cargo build --release --bin imp-guest-agent \
#       --no-default-features --features agent \
#       --target x86_64-unknown-linux-musl
[[bin]]
name = "imp-guest-agent"
path = "src/bin/imp-guest-agent.rs"
required-features = ["agent"]

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
# (see §5.4 + the §10 experiment). No crate dependency here.

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
tar          = { version = "0.4", optional = true }
flate2       = { version = "1", optional = true }      # gzip
lzma-rs      = { version = "0.3", optional = true }    # pure-Rust xz (kernel tarballs) — see notes vs `xz2`
zstd         = { version = "0.13", optional = true }   # bundles libzstd from source via cc; no OS package needed
reflink-copy = { version = "0.1", optional = true }    # FICLONE — replaces `cp --reflink` (XFS/Btrfs only; see notes)
walkdir      = { version = "2", optional = true }
toml         = { version = "0.8", optional = true }    # pins.lock + config
tempfile     = { version = "3", optional = true }

# ---- CLI (feature: cli) ----
clap   = { version = "4", optional = true, features = ["derive"] }
anyhow = { version = "1", optional = true }            # ergonomic top-level errors in the binary only

# ---- guest agent only (feature: agent) — kept minimal for a small static musl binary ----
vsock       = { version = "0.5", optional = true }     # sync AF_VSOCK; avoids pulling tokio into the agent
rustix      = { version = "0.38", optional = true, features = ["fs", "mount", "process"] } # libc-free mount(2)/waitpid(2)/reboot(2)
signal-hook = { version = "0.3", optional = true }     # SIGCHLD reaping as PID 1

[dev-dependencies]
axum         = "0.7"   # spin up host-side HTTP test servers in integration tests (req 3)
assert_cmd   = "2"     # exercise the imp-testing CLI end to end
predicates   = "3"
serial_test  = "3"     # serialize tests that touch global host resources (netns / cgroups / nft)
tempfile     = "3"
tracing-test = "0.2"

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
net-rootless   = ["host-common"]   # passt is an external binary, managed via tokio::process — no crate

proxy          = ["host-common", "dep:rustls", "dep:tokio-rustls", "dep:rcgen", "dep:rustls-pemfile"]
proxy-hudsucker = ["host-common", "dep:hudsucker"]

metrics = ["host-common", "dep:cgroups-rs", "dep:procfs"]

pipeline = [
    "host-common",
    "dep:reqwest", "dep:pgp", "dep:sha2", "dep:blake3",
    "dep:tar", "dep:flate2", "dep:lzma-rs", "dep:zstd",
    "dep:reflink-copy", "dep:walkdir", "dep:toml", "dep:tempfile",
]

cli = ["host-common", "dep:clap", "dep:anyhow", "dep:serde_json"]

# Guest agent: deliberately omits host-common so it does NOT compile tokio/hyper/etc.
agent = ["dep:vsock", "dep:rustix", "dep:signal-hook"]

codegen = ["dep:progenitor"]
```

### 5.6 Architectural accommodations for testability

The "minor accommodations for unit-test coverage" the requirements ask for, without over-engineering:

1. **The `Vmm`/`VmInstance` trait seam.** A `FakeVmm` (test-only) implements both traits in memory, letting the orchestrator's logic (resource allocation order, ordered `Drop` cleanup, retry/timeout handling, snapshot-vs-cold-boot selection, CID allocation) be unit-tested with no KVM, no root, no subprocess.
2. **Pure/imperative split.** The genuinely-testable pure functions are isolated from I/O: nft-rule rendering, `/30` address arithmetic, the CH REST payload builder, the vsock handshake state machine, cgroup-path construction, the artifact `cache_key`, and the agent protocol's encode/decode. Each gets `#[cfg(test)]` unit tests. The thin I/O wrappers around them are exercised by the integration tests.
3. **Injectable side-effect traits where it pays off.** `Netlink`, `NftApplier`, `CgroupFs`, and a `SerialLog` reader are small traits with a real implementation and a recording/fake one, so `net`/`metrics`/`agent` orchestration is unit-testable (assert "the right rules/limits/handshake were requested") without touching the host.
4. **Deterministic IDs and clocks** are injected (a `vmid`/`cid` allocator, a `Clock`) so tests are reproducible.

The integration tests in `tests/` (one per requirement/operation) are the real-environment counterpart; they require KVM + elevated capabilities and are gated so `cargo test` stays green on a laptop while CI runs the full suite on a capable runner. **Because the runner trick (below) is global**, the privileged suite is kept as its own gated target so a plain `cargo test` of the pure unit tests does not silently run under `sudo`.

---

## 6. Requirement-by-requirement realization

A compressed pass over the ten functional requirements (mechanism → tier achieved), plus the non-functional ones.

1. **Host OS / arch.** CH fully supports Linux **x86_64** (mandatory) and **aarch64** (the "good extra"). macOS is *not* supported by CH; the macOS-on-Apple-Silicon "nice-to-have" is explicitly tie-breaker-only and is **not** pursued, since chasing it would force a weaker stack (libkrun/Apple Container with a single guest+VMM security context). **Met on the mandatory axis; aarch64 extra met; macOS deliberately skipped.**

2. **Shared dirs.** virtio-fs, one `virtiofsd` per tag → multi-dir (mandatory). `--read-only` per daemon → per-mount permissions (the "great" extra). The "good" extra (host page-cache sharing) historically came from DAX, which is unavailable (§3.1); it is partially recovered by the **erofs read-only base shared via the host page cache**, while per-share virtio-fs uses `cache=never`. **Mandatory + great met; the page-cache "good" extra partially recovered (for the RO base), not via DAX.**

   *2 + performance (the snapshot fork):* the **snapshot fast path boots from the erofs/virtio-blk rootfs** — a plain block device that snapshots cleanly (unlike a virtio-fs rootfs, §3.2) and needs **no per-VM copy** because it is read-only and shared. virtio-fs is used for the *data/binary/output* shares. The one open item is whether virtio-fs *data* shares attach reliably to a snapshotted VM; if not, data-heavy tests serve inputs via extra erofs/block images on the snapshot tier. This branch is the single most important thing to benchmark. (v1 proposed an ext4 rootfs cloned per VM; the implementation pass showed that path causes journal-recovery panics on read-only mounts and concurrent-mount corruption — erofs removes both, see §7.)

3. **Host-served endpoints.** Host test server bound to the per-VM gateway/host address → reachable from the guest, not exposed to other systems (mandatory). Per-test server config and dynamically-assigned ports are straightforward from Rust (configure the VM's view *after* the server is listening). Arbitrary TCP/UDP/etc. works (the "other protocols" extra). **Two delivery modes** (chosen by `NetConfig`): privileged netns+tap+`/30`, or rootless `passt`. vsock is available as an alternate, IP-stack-free host↔guest channel. **Mandatory + both great extras + the good extra met.**

4. **Transparent proxy.** All egress is logged and filtered through the Rust MITM proxy (mandatory), with **test doubles** for web services (the "great" extra) and the record/replay hook. **The steering mechanism has two variants tied to the networking mode** (and is *not* independent of it): in privileged mode, nftables **`TPROXY`** (not `REDIRECT`/DNAT — TPROXY preserves the original destination and handles UDP; the small ruleset is applied via the `nft` binary, §5.4); in rootless mode there is no tap for nftables, so interception lives in **`passt`'s outbound path**. HTTPS interception works in both because the proxy CA is baked into the guest trust store. **Mandatory + great met (two variants).**

5. **Guest environment.** Minimal Debian Trixie via `mmdebstrap` = "stripped-down Debian via supported methods" (the "good" tier); the agent is injected with `--customize-hook=copy-in` (§7). A full installed Debian-server flavor (the "great" tier) is possible if a specific test needs it, at a boot-time cost — exposed as a heavier rootfs profile. **Good tier met; great tier available on demand.**

6. **Guest kernel.** Direct-boot a custom-minimal `vmlinux` built from **Debian kernel source** with the **explicit config fragment in §7** (the "good" tier). Using a Debian-provided kernel *image* unmodified (the "great" tier) is also supported as a profile. **Project-specific kernel patches (the "unacceptable" option) are never used.** The fragment matters: the implementation pass started from `kvm_guest.config` and hit `EAFNOSUPPORT` because vsock symbols were absent — and the *same* class of failure waits at virtio-fs (`FUSE_FS`/`VIRTIO_FS`) and erofs unless the fragment is complete. **Good tier met; great tier available.**

7. **Nested virtualization.** Build KVM into the guest kernel and enable it on the host (`kvm-intel nested=1`, guest cmdline `kvm-intel.nested=1`); the L1 guest then gets `/dev/kvm` and Imp-under-test can run inner VMs (CH or Firecracker). This is a separate *test class*, not the default fast path. If the inner VM needs vsock, the **L1 guest kernel** also needs `VHOST_VSOCK=y` (the host-side vhost driver — see §7). Peripheral passthrough (USB) is tie-breaker-only and not pursued. **Met with CH** (Firecracker and libkrun cannot do this — another reason they aren't primary).

8. **Programmable infra control.** The CH REST API + `ch-remote` cover create/delete/list, start/request-shutdown/force-shutdown, and configuration of shares/networking/nested-virt. Performance monitoring (peak + average CPU/RAM/disk-I/O/net-I/O) comes from the per-VM cgroup v2 slice (`memory.peak`, `memory.current`, `cpu.stat`, `io.stat`) plus net counters, layered with CH's live `counters`. **Met.**

9. **Programmable artifact build.** The staged pipeline in §7 builds filesystem/disk images, kernel/firmware, and config files, with content-addressed caching. **Met.**

10. **Programmable console.** The vsock Rust client (host) + Rust server (guest agent) hits the top "great" tier, with the readiness handshake and PID-1 contract spelled out in §5.2/§5.3. TTY emulation (serial) is retained for panic capture and fast-fail; SSH is a human-only fallback, never the control plane. **Great tier met.**

**Non-functional — performance (running time).** Most tests are seconds; the lever is **warm-snapshot restore** off the shared erofs rootfs (tmpfs overlay per test) so the per-test critical path skips kernel boot. Per-test artifact-prep time is counted (per the requirements): the erofs RO base needs **no per-test copy at all** (it is shared read-only), virtio-fs data shares avoid image copies (just re-point a daemon), and the only writable per-test state is a tmpfs overlay. If a test ever needs a writable *disk* overlay, use reflink/qcow2-backing rather than a full copy — minding the reflink caveat (§3.2 / §9).

**Non-functional — RAM density.** RAM is the binding limit on parallelism. Levers: `cache=never`, the **shared erofs RO base** (one host-cached copy for all guests), **KSM** (`merge_across_nodes=0` on NUMA; budget ~5–10% CPU for `ksmd`), and **virtio-balloon/free-page-reporting**. Plan with **128–256 MiB/guest as a must-re-benchmark figure** (the guest userland, not the ≤5 MiB VMM overhead, dominates). The next limits after RAM are typically one-virtiofsd-per-VM, tap/bridge/nft (or passt-process) scaling, and host FD/PID limits.

**Non-functional — Rust ergonomics & licensing.** Covered by §5.4 (avenue tiers, permissive-only via `cargo-deny`).

---

## 7. Artifact build pipeline

Maps directly onto the VM-artifact-production requirements (staged, pinned, deterministic, cacheable, resettable, minimal external access, record/replay, signing-chain verified).

### Artifacts produced
1. **`vmlinux`** (per arch): one custom-minimal kernel, direct-boot, drivers built in, optional KVM-for-nesting. Host-side, shared by all VMs; rebuilt only when the config fragment or pinned source changes.
2. **Root filesystem** (per profile): `mmdebstrap` minbase + the test toolchain + `imp-guest-agent` (injected via `--customize-hook=copy-in`), packed as a **single read-only erofs image**. That one artifact serves *every* path — cold boot, concurrent shared mounts, and the snapshot tier — because erofs over virtio-blk is read-only, shareable, and snapshot-eligible. (v1 specified a dual emission, erofs *and* a separate block image; with erofs-over-virtio-blk the two collapse into one.) **Imp's own binaries are *not* baked in** — they arrive over the `imp-bin` virtio-fs share, so a new Imp build does not invalidate the rootfs. **Build-host note (observed):** `mmdebstrap` invokes a shell and fails under Ubuntu's default `dash`; run it with `SHELL=/bin/bash` (and ensure `/bin/sh` → `bash`). The `imp-testing build` command preflight-checks this and halts with a clear message if it is misconfigured. (This host quirk is also part of the case for the OCI-rootfs experiment in §10.)
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
CONFIG_EROFS_FS=y  CONFIG_EROFS_FS_ZIP=y   # match mkfs.erofs compressor; see note
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
- **erofs compression must match.** If `mkfs.erofs` compresses with lz4/zstd, the kernel needs the matching decompressor (`CONFIG_EROFS_FS_ZIP` for lz4; `…_ZIP_ZSTD`, `…_ZIP_LZMA`, `…_ZIP_DEFLATE` as applicable) or the mount fails. Building the image uncompressed sidesteps the dependency at the cost of size and page-cache footprint.

The kernel command line pins the boot path explicitly, e.g.:
`console=ttyS0 root=/dev/vda rootfstype=erofs ro ip=10.200.<vmid>.2::10.200.<vmid>.1:255.255.255.252::eth0:off init=/sbin/imp-guest-agent`. The `ip=` parameter (enabled by `CONFIG_IP_PNP=y`) sets the guest address at boot in privileged tap mode, so PID 1 needs no netlink (§5.4); in rootless mode passt supplies the address instead. (If a block-ext4 fallback is ever used, add `rootflags=noload` so the ext4 driver mounts strictly read-only without journal recovery — recovery is a write and panics on a read-only device. erofs has no journal, so the default path needs no such flag.)

### Stage model
- **Stage 0 — resolve pins (the only non-deterministic stage).** Determine the most up-to-date values for a minimal pin set: the Debian package-repo **snapshot timestamp** (via `snapshot.debian.org`), the kernel source version/commit, and the CH/virtiofsd release tags. Output: a small, committed `pins.lock`.
- **Stages 1..n — deterministic given inputs.** Each stage's output is fully determined by its inputs + the pins. Examples: *fetch+verify kernel source*, *configure+compile `vmlinux`*, *`mmdebstrap` rootfs at the pinned snapshot*, *copy-in `imp-guest-agent` + CA*, *`mkfs.erofs` pack*, *boot+snapshot*.
- **Caching.** Each stage has a pure `cache_key` (hash of inputs + pins + stage version); `Pipeline::build` skips a stage whose outputs already exist under that key. `reset_to(stage)` removes the outputs of that stage and all later ones.
- **Minimize external access + record/replay.** Network-touching stages (apt, source fetch) are split into a **record** step (populate an on-demand cache keyed to the snapshot, e.g. an apt package cache or an `mmdebstrap` mirror hook) and a **replay** step (build purely from the cache). Iteration and CI then hit the network at most once per pin.
- **Signing-chain verification.** Verify the Debian `InRelease`/`Release` + `Release.gpg` chain against the pinned archive keyring before using any package, and verify kernel-source signatures/hashes where published; **refuse to proceed on mismatch.** This is a hard stop, not a warning.

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
| **M1** | First boot | Artifact pipeline v0: build a minimal `vmlinux` with the **full config fragment** + an **erofs** rootfs; CH subprocess + REST `create`/`boot`; serial→log; ordered `Drop` kill | `boot.rs`: VM reaches userspace (known string in serial log). `lifecycle.rs`: force-shutdown a started VM | 1, 6, 9, parts of 8 |
| **M2** | vsock control | `agent::protocol`; `imp-guest-agent` as PID 1 (reaper, never-exit, fork-not-exec, self-check); host `AgentClient` with **retry/handshake + serial-panic fast-fail** | `exec_vsock.rs`: `exec("echo hello")` → stdout `hello`, exit 0. `lifecycle.rs`: graceful `request_shutdown` | 10, rest of 8 |
| **M3** | Shared dirs | `fs` (virtiofsd per share, perms, tags); `--memory shared=on`, `cache=never`. **Confirm `FUSE_FS`/`VIRTIO_FS` are in the kernel** (else the M2-class errno failure recurs) | `shares_ro_rw.rs`: guest reads a host-placed input file; write to RO share fails; host sees a file the guest wrote to the RW share | 2 (mandatory + great) |
| **M4** | Host endpoints + net (privileged) | `net::tap` (netns + tap + `/30`, rtnetlink); gateway-bound host server | `host_endpoint.rs`: guest GETs a host HTTP server on a dynamic port; server unreachable outside the netns; a second protocol (raw TCP) works | 3 (+extras) |
| **M5** | Transparent proxy | `proxy` (MITM CA, log/filter, doubles); **TPROXY** steering in privileged mode; bake CA into rootfs | `egress_proxy.rs`: HTTPS request is logged; a filter rule blocks a domain (guest sees the block); a registered test-double returns a canned response | 4 (+great) |
| **M6** | Monitoring + limits | `metrics` (cgroup v2 slice, caps, peak/avg readers) | `metrics_limits.rs`: a workload allocating N MiB shows up in `memory.peak`; `memory.max` kills a runaway allocator; avg CPU computed over a busy loop | 8 (perf monitoring) |
| **M7** | Nested virt | Guest kernel profile with KVM (+ `VHOST_VSOCK` for inner vsock) built-in; host enablement docs | `nested_virt.rs`: `/dev/kvm` present in guest; an inner micro-VM boots and runs a command | 7 |
| **M8** | Snapshot + density | Warm-snapshot stage (**pause→snapshot→resume**); restore via **`--restore`→`resume`** (never boot) + tmpfs overlay; **host vsock reconnect** after restore; identity rotation + **entropy reseed + clock resync**; KSM/balloon wiring | `snapshot_restore.rs`: restored VM **resumes** (not boots) faster than cold boot; the host **reconnects the severed vsock**; restored VM has fresh CID/MAC + reseeded RNG; outputs still land in `imp-out` | perf + density non-functional |
| **M9** | Rootless mode | `net::passt` + passt-path egress interception; systemd cgroup **delegation** for metrics | rootless variants of `host_endpoint.rs` and `egress_proxy.rs`, gated as a **known-fragile** separate suite (passt + CH `vhost_user` hit `accept4 EACCES` under passt's seccomp filter inside a netns during the implementation pass — privileged stays the default for networking tests) | 3/4 deployability (§9) |

**Build-pipeline hardening track** (runs alongside, completes by M8): Stage 0 pin resolution + `pins.lock`; record/replay split for apt + source fetch; signing-chain verification with refuse-on-mismatch; `reset_to`. Each gets its own test (e.g., "a tampered package digest aborts the build"; "a second build with a warm cache performs zero network fetches"; "`reset_to(rootfs)` rebuilds rootfs and snapshot but not the kernel").

**Test-suite split.** Privileged integration tests (netns/tap/cgroup-at-root) run via a `runner = "sudo -E"` target or a dedicated CI job; rootless tests (passt + delegated cgroup) run as their own suite. Keeping them separate — rather than assuming root everywhere — is both cleaner and the only way the rootless path stays honestly exercised. The pure unit tests run under a plain `cargo test` with no elevation.

**Sequencing rationale.** M1 derisks the hardest plumbing (subprocess + REST + boot + teardown) with the least surface — and now ships the complete kernel fragment and erofs rootfs up front so the vsock/virtio-fs symbol gaps don't ambush M2/M3. M2 establishes the control channel everything else asserts through, with the readiness handshake and PID-1 contract that the implementation pass proved are load-bearing. M3–M5 add the three I/O surfaces (files, host services, egress) in increasing complexity. M6 makes runs measurable and bounded. M7 and M8 are the most environment-sensitive (nesting, snapshot/density) and come late. M9 adds the rootless deployment mode once the privileged path is solid.

---

## 9. Risks, open decisions, and what to benchmark

- **The snapshot ↔ virtio-fs fork (highest risk).** §3.2. The erofs-block rootfs snapshots cleanly; the open item is whether virtio-fs *data* shares attach to a snapshotted VM on your pinned CH/virtiofsd. Build both (virtiofsd data shares vs extra erofs/block data images) and pick per tier from measurements.
- **Networking privilege is a first-class fork, not an afterthought.** tap + TPROXY needs `CAP_NET_ADMIN`; the implementation pass confirmed modern **Ubuntu** blocks the unprivileged-userns escape hatch by default (`kernel.apparmor_restrict_unprivileged_userns=1`). Note this is largely an Ubuntu 24.04+ default — **Debian Trixie does not necessarily enable it**, which is mildly relevant given the earlier Debian-vs-Ubuntu deliberation; the host distro affects whether rootless even gets off the ground. Two supported modes (§5.3/§6): **privileged** (tap+TPROXY, full L2 fidelity, `runner = "sudo -E"`) and **rootless** (`passt` + cgroup delegation). The `sudo -E` runner is global and changes output-file ownership and cargo's environment, so it is pragmatic for CI but is scoped to the integration target rather than applied to every `cargo test`. The implementation pass also found `passt` + CH `--net vhost_user=true` failing with `accept4 EACCES` under passt's seccomp filter inside a netns, reinforcing privileged-tap as the reliable default for networking tests (and motivating the `smoltcp` experiment in §10).
- **Proxy steering is coupled to the networking mode.** §6.4. TPROXY only exists with a tap; rootless mode intercepts in passt's outbound path. Requirement 4 therefore has two implementations, not one — don't design the proxy as if the front-end were uniform.
- **DAX is gone (density plan).** §3.1. Rely on the shared erofs RO base + `cache=never` + KSM + balloon, not DAX. Re-check on the pinned CH.
- **reflink only helps on the right filesystem.** If a writable *disk* overlay is ever needed, `cp --reflink=auto` / `FICLONE` works on **XFS or Btrfs**, not ext4 — on ext4 it silently degrades to a full copy and the density/speed win evaporates. Alternatives: a CH **qcow2 overlay with a backing file** (you must flip `backing_files=on`, which is off-by-default for security, §3.2-adjacent), or `dm-snapshot`. With the erofs-RO-shared base + tmpfs overlay this is rarely needed.
- **Boot/density numbers are unverified.** §3.4. Benchmark cold-boot, restore, idle guest RSS, and the concurrent-VM ceiling per RAM tier on the actual hardware before quoting anything.
- **Nested-virt host requirements.** §3.5. Needs host `nested=1` (bare-metal or a nesting-capable cloud instance, e.g. AWS C8i/M8i/R8i via `NestedVirtualization=enabled`, or `.metal`). On AMD, don't snapshot an L1 that has started an L2.
- **nftables programming has no permissive pure-Rust path.** §5.4. `rustables` is GPL-3.0-or-later (disqualified); `nftables-rs`/`nftnl-rs` still need the `nft` binary or the C `libnftnl`; the pure-netlink crates are unproven for TPROXY. The design applies the small, fixed TPROXY ruleset via `nft -f -`. A pure-Rust replacement is a future-work experiment (§10), not a baseline dependency.
- **Snapshot restore correctness.** §7 snapshot stage. Rotate identity (CID/MAC/IP), reseed entropy (virtio-rng), and resync the clock on every restore; otherwise clones reuse RNG state and carry a stale wall clock. Operationally (confirmed by the implementation pass): snapshot requires `vm.pause` first, and a restored VM continues via `vm.resume` — **booting a restored VM errors (`500 "VM is already created"`)**. Because CH re-creates the host-side vsock socket on restore, the host must **reconnect** and the guest agent must survive the severed connection's EOF and re-`accept` (§5.2/§5.3).
- **vsock CID allocation.** Each running VM needs a unique guest CID (≥ 3); the host must allocate collision-free and rotate on restore. A naive fixed CID collides the moment two VMs run concurrently.
- **overlayfs-over-virtiofs is a known sharp edge.** The default writable overlay is tmpfs-over-**erofs**, which is fine. Using **virtiofs as an overlayfs lowerdir** has historically needed specific kernel features (redirect_dir/metacopy) and is best avoided — another reason the RO base is erofs, not a virtio-fs mount.
- **Cross-version snapshot fragility.** Pin one exact CH + virtiofsd build for any snapshot pool; CH does not guarantee snapshot compatibility across versions.
- **Primary architecture.** x86_64 is the mandatory CI arch and the place to invest first; aarch64 is a supported extra but kernel configs and snapshot artifacts differ, so treat it as a second target, not a free rebuild.

---

## 10. Future work: pure-Rust substitutions as sequenced experiments

The dependency analysis (§5.4) deliberately keeps several external tools — `virtiofsd`, `mkfs.erofs`, `mmdebstrap`, `passt`, the `nft` binary — because the crate replacements are either immature, license-incompatible, or a large reimplementation of a hardened tool. A second research pass argued each can be absorbed into the orchestrator process; several are genuinely attractive, but **none should go in before there is a working, measured baseline** (M0–M9). Each is framed below as an independent experiment to run *after* the baseline, **one at a time**, behind its own Cargo feature flag so it is opt-in and reversible, with the baseline mechanism retained as the fallback.

Methodology for each experiment: branch from the green baseline; gate the new path behind a feature; keep the integration tests for the affected requirement unchanged (they are the regression oracle); measure against the baseline on the same hardware; **graduate** the experiment into the default only if it meets the stated success criterion, otherwise **revert** and the baseline stands. Recommended order is lowest-risk / highest-payoff first.

**Experiment 1 — In-process virtio-fs (`fuse-backend-rs`).** *Replaces:* the per-share `virtiofsd` daemon (§5.3 `fs`). *Benefit:* `fuse-backend-rs` (Apache-2.0 AND BSD-3, cloud-hypervisor-org, mature — underpins Kata/Nydus) embeds the vhost-user-fs server + a passthrough driver directly in the orchestrator, removing N daemon processes, collapsing cgroup accounting to one process, and cutting the per-VM memory and PID pressure that bound density (§6). *Risk & unknowns:* the orchestrator becomes the vhost-user-fs backend (its own virtqueues, thread-per-share, vhost-user protocol — real engineering), and it does **not** by itself fix the snapshot↔virtio-fs fork (§3.2): an *external* CH still sees a vhost-user device, so the restriction persists until CH adopts `fuse-backend-rs` internally (CH issue #7250), which is out of scope here. *Graduate / revert:* keep it if, at target density, it delivers a measurable memory/PID reduction with every M3 share test green and no snapshot regression; revert if it destabilizes the data path or worsens the fork. **Highest-value experiment.**

**Experiment 2 — Pure-Rust nftables (replace the `nft` binary).** *Replaces:* the `nft -f -` invocation for the privileged TPROXY ruleset (§5.3 `net`). *Benefit:* removes the last privileged-mode external binary, with atomic in-process rule application (no shell, no parsing). *Risk & unknowns:* needs a **permissive** crate that actually supports the `tproxy` statement + `socket` match — `rustables` is GPLv3 (out), `jip-nftables`/`nftables_netlink` is obscure and unverified, and the reputable building blocks (`rust-netlink/netlink-packet-netfilter`, permissive) require hand-assembling the netfilter expressions. *Graduate / revert:* keep it only if a vetted permissive crate applies the exact ruleset and the M5 egress tests pass; otherwise keep `nft` — the ruleset is tiny and security-critical, so purity doesn't justify the risk.

**Experiment 3 — Pure-Rust erofs build (`erofs-rs`).** *Replaces:* `mkfs.erofs` in the rootfs build stage (§7). *Benefit:* in-process, in-memory image generation; one fewer build-time tool; tighter layout control. *Risk & unknowns:* `erofs-rs` began as a *reader*; its *writer* maturity for producing kernel-mountable, correctly-compressed images is unproven, and `mkfs.erofs` already works and is build-time only (low blast radius if left alone). *Graduate / revert:* keep it if `erofs-rs` emits an image that mounts under the pinned guest kernel and passes every boot/share test at equivalent size; revert if mounts fail or its compression support lags the kernel's decompressors. **Low risk, low payoff — a cheap probe.**

**Experiment 4 — OCI-image rootfs (`oci-distribution` + `oci-spec`).** *Replaces:* `mmdebstrap` runtime rootfs assembly (§7), eliminating the `dash`/`SHELL` host quirk. *Benefit:* pull a pinned Debian image **by SHA256 digest**, layer in the agent in memory, feed it to the erofs packer — pure-Rust fetch, digest-locked reproducibility. *Risk & unknowns:* this **trades a stated requirement** — OCI pull verifies a *registry digest*, not the Debian apt signing chain (`InRelease`/`Release.gpg`) that the `mmdebstrap` + rPGP path provides; and there is no pure-Rust `mmdebstrap`, so it is a provenance pivot, not a drop-in. *Graduate / revert:* keep it only if a pinned-digest build is bit-reproducible, all boot/share tests pass, **and** the team explicitly accepts registry-digest trust in place of apt-chain verification (a documented decision); otherwise keep `mmdebstrap`.

**Experiment 5 — In-process rootless networking (`smoltcp`).** *Replaces:* `passt` in the rootless datapath (§5.3 `net`, M9). *Benefit:* a userspace TCP/IP stack in-process puts rootless networking **and** egress interception at L4 in your own code (cleaner than passt-path interception, §6.4), with bounded reassembly buffers for DoS resistance, and sidesteps the passt seccomp/`EACCES` issue. *Risk & unknowns:* this reimplements what `passt` does (NAT, port-forwarding, TCP state) — `passt` is mature and security-hardened, so it is a large new attack/maintenance surface inside a *test harness*; the payoff applies only to the rootless tier, which is already the constrained, non-default path. *Graduate / revert:* keep it only if the rootless `host_endpoint` + `egress_proxy` tests pass with throughput within an acceptable margin of privileged tap **and** the security posture is defensible; otherwise keep `passt` (or privileged tap). **Heaviest experiment — do last, if at all.**

Two ideas from the dependency report are **not** experiments because they are already the design, and were independently re-confirmed by the report: keeping CH/Firecracker as supervised subprocesses driven by typed REST clients (`cloud-hypervisor-client` / `firecracker-rs-sdk`) rather than embedding a VMM (§5.3), and `cgroups-rs` for limits/metrics (§5.3 `metrics`).

---

## 11. Prior art worth mining before writing code

- **`cocoonstack/cocoon`** ★ — a 2026 lightweight micro-VM engine on Cloud Hypervisor with instant snapshot+clone via **reflink**, COW overlays, balloon/free-page-reporting, and Firecracker as an alternate backend; it documents the exact vhost-user-snapshot constraint from §3.2. Closest reference to the snapshot/density path.
- **`tinylabscom/mvm`** ★ — Rust CLI with a multi-VMM backend abstraction and a **vsock-only guest agent ("NO SSH ever")**; a near-reference for the `Vmm` trait, the agent protocol, and the PID-1 contract.
- **`microvm.nix` agent-sandbox write-up** ★ — the egress topology to copy: CH + nftables forward-chain logging + DNS logging + read-only `erofs` rootfs (note the shared RO erofs base, exactly as adopted here).
- **`pve-microvm` (Tao of Mac)** — QEMU `microvm` as a managed guest; good reference for the kernel/rootfs split and "prebuild the rootfs, don't `apt` at boot."
- **`agentkernel`, `vmexec`** — ephemeral-VM-per-command patterns on the rust-vmm stack, in your exact domain.
- **`passt` / Red Hat "rootless VMs with user-mode networking"** — the reference for the rootless networking mode (M9) and where to hook egress interception without a tap.
- **Kata `agent-ctl` / `kata-ctl`** — the agent-over-vsock blueprint and tooling.
- **UK AISI `inspect_ai` agent-bridge / `model-proxy-lifecycle`** — only if/when the eval layer needs the in-guest model-proxy-over-vsock pattern (the §1.2 hook); not needed for the infrastructure library itself.

---

*Version/feature claims reflect the mid-2026 research inputs; CH was at v52.0 and Kata 4.0 in preview at research time. Re-verify the §3 contested items — DAX availability, snapshot/virtio-fs composability, userfaultfd restore, nested-virt flags, and all boot/density numbers — against the exact tool versions pinned in `pins.lock`.*
