# Imp Testing — Design Document

*An end-to-end integration-testing and evaluation platform for the **Imp** agentic harness. Each test runs in a fresh micro-VM for structural isolation, hermetic state, and production fidelity. Driven entirely from a single Rust library.*

This document synthesizes the project requirements with the five research/fact-check inputs (`1-claude-design`, `2-gemini-research`, `3-claude-research`, `4-claude-fact-check`, `5-gemini-fact-check`). Where those inputs disagree, the disagreement is called out explicitly and the design is made robust to the conservative reading. **One synthesis note up front:** the most *recent* input (the Gemini fact-check) re-introduced at least one claim (virtio-fs DAX availability) that the earlier Claude fact-check had already refuted with verbatim primary-source quotes, and it did not surface the snapshot/virtio-fs incompatibility. "Most recent" is therefore not treated as "most authoritative"; contested points are flagged in §3 and must be re-verified against the exact pinned tool versions.

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
| **Control plane** | **virtio-vsock + a statically-linked Rust guest agent as PID 1** speaking a framed protocol (`Ready`/`Exec`/`Stdout`/`Stderr`/`Exit`). Serial console wired to a per-VM log for panic capture. SSH only as a human debugging fallback. | Requirement 10 "great" tier (vsock client+server in Rust). |
| **Shared dirs** | **virtio-fs, one `virtiofsd` per share**, `--read-only` for inputs/binaries, rw for output; CH `--memory shared=on`; `cache=never`. | Requirement 2 mandatory + "great" (per-mount perms). "Good" extra (host page-cache sharing) — see §3. |
| **Host-served endpoints** | Per-VM **network namespace + tap + `/30`**; host test servers bind the gateway IP; dynamic ports configured after listen; not exposed beyond the netns. | Requirement 3 mandatory + both "great" extras + "other protocols." |
| **Transparent proxy** | **nftables `TPROXY`** → a **Rust MITM proxy** (`hyper` + `rustls`, or `hudsucker`) with logging, filtering, pluggable **test doubles**, and a CA baked into the guest trust store. | Requirement 4 mandatory + "great" extra. |
| **Monitoring / limits** | One **cgroup v2 slice per CH (and per virtiofsd) process**; read `memory.peak`/`memory.current`/`cpu.stat`/`io.stat`; enforce `memory.max`/`cpu.max`/`pids.max`/`io.max`. | Requirement 8 (peak + average resource usage). |
| **Guest OS** | Minimal **Debian Trixie (13, kernel 6.12 LTS)** rootfs via **`mmdebstrap`/`mkosi`**; read-only `erofs`/`squashfs` base + tmpfs/overlay for writes. | Requirement 5 "good" tier (stripped Debian via supported methods). |
| **Guest kernel** | **Direct kernel boot** of a custom-minimal `vmlinux` built from **Debian kernel source** with a microvm config (virtio + KVM built-in, no initramfs). No project-specific patches. | Requirement 6 "good" tier; "unacceptable" (project kernel patches) avoided. |
| **Speed lever** | **Warm snapshot + reflink/COW per-test overlay** off a *block* rootfs, with cold-boot opt-in per test. | Performance non-functional; see the snapshot/virtio-fs fork in §3. |
| **Density levers** | `cache=never` + **KSM** (`merge_across_nodes=0` on NUMA) + **virtio-balloon / free-page-reporting**. **Not DAX** (§3). | RAM is the binding constraint on parallelism. |
| **Dependency posture** | Prefer in-crate Rust over external tools; permissive licenses only (MIT/Apache/BSD); copyleft tolerated only for *binaries* (QEMU) when it unlocks a fallback. Vet with `cargo-deny`. | Source-code & system-dependency requirements. |

---

## 3. Contested facts — verify against pinned versions before relying on them

The research inputs conflict on several load-bearing points. The design below does **not** hard-depend on the optimistic reading of any of these. Each should be re-confirmed against the exact CH / virtiofsd / kernel versions that get pinned.

1. **virtio-fs DAX is treated as UNAVAILABLE in Cloud Hypervisor.** Both Gemini documents claim DAX is a live density lever (`dax=on,cache_size=…`). The Claude fact-check refutes this with a verbatim quote from CH `docs/fs.md` — DAX "is not available in Cloud Hypervisor" — and notes it was deprecated in CH v24.0 (#3889). **Consequence:** the "good extra" of host page-cache sharing for read-only data (requirement 2) is *not* achievable via DAX today. Density comes from `cache=never` + KSM + ballooning instead. Re-check `docs/fs.md` on the pinned CH version; if DAX has returned and stabilized, it becomes an opt-in optimization, not a load-bearing assumption.

2. **Snapshot/restore and virtio-fs do not currently compose** (the single biggest architectural fork). CH issue #6931 reports that restoring a snapshot of a VM with a virtio-fs *rootfs* hangs/fails, and CH refuses to snapshot a VM with vhost-user devices attached (corroborated by the `cocoonstack/cocoon` docs). **Consequence:** you cannot have *both* "ms-fast warm-snapshot start" *and* "zero-copy virtio-fs rootfs" on the same VM. The design splits this (see §6, requirement-pair 2+perf): **snapshot path → block rootfs; virtio-fs → data/binary shares only.** Whether virtio-fs data shares can be (re)attached *after* a restore is the key thing to validate empirically on your versions; if not, the snapshot tier serves read-only data via block images instead.

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
│   ├─ per-test:  cgroup v2 slice  →  network namespace  →  tap (/30)                     │
│   ├─ AgentClient (tokio-vsock / AF_UNIX)   ⇄   imp-guest-agent                          │
│   ├─ virtiofsd × N  (imp-in ro · imp-bin ro · imp-out rw)                               │
│   ├─ EgressProxy (hyper+rustls):  nft TPROXY  →  log / filter / test-doubles  →  WAN    │
│   └─ Metrics:  read memory.peak / cpu.stat / io.stat from the slice                     │
│                                                                                        │
│   artifact cache:  vmlinux  ·  base rootfs (block + erofs)  ·  warm snapshot  ·  CA     │
└────────────────────────────────────────────────────────────────────────────────────────┘
        │ restore (ms) or cold-boot                          ▲ vsock: Ready/Exec/IO/Exit
        ▼                                                     │
  ┌──────────────────────── micro-VM (per test, ephemeral) ───────────────────────┐
  │ kernel: direct boot, virtio + (opt) KVM built-in, no initramfs                  │
  │ PID 1: imp-guest-agent  (brings up mounts/net, then serves the vsock protocol)  │
  │ mounts: /in (virtiofs ro) · /opt/imp (virtiofs ro) · /out (virtiofs rw)         │
  │ net: eth0 (tap) → default route → host TPROXY                                   │
  │ [optional] /dev/kvm present → Imp-under-test runs its own inner VMs             │
  └─────────────────────────────────────────────────────────────────────────────────┘
```

### Per-test lifecycle
1. **Acquire artifacts** from the cache (kernel, rootfs/snapshot, CA) — built once, reused.
2. **Allocate per-test resources:** a cgroup v2 slice, a network namespace, a tap on a fresh `/30`, and a writable per-test overlay (reflink/COW) over the read-only base.
3. **Start the VM:** either `restore` a warm "agent-ready" snapshot (fast path) or cold-boot (opt-in for tests that mutate global state the snapshot would have baked in). On restore, **rotate identity** (vsock CID, MAC/IP, reseed entropy via virtio-rng).
4. **Bind shares:** point `imp-in` / `imp-out` virtiofsd at this test's input/output dirs; `imp-bin` is shared read-only across all tests so its pages stay hot.
5. **Drive it over vsock:** `Exec` the entrypoint; stream stdout/stderr/exit; tail the serial log for panics.
6. **Collect results:** outputs from the host `imp-out` dir; `memory.peak`/`cpu.stat`/`io.stat` from the slice; the proxy's request log.
7. **Tear down:** force-kill the VMM, delete the netns/tap/cgroup/overlay. No guest-state cleanup needed — discard is structural, which *is* the no-leakage guarantee.

### Why a `Vmm` trait rather than a single VMM
Both `mvm` and Kata abstract over multiple VMMs because each is optimal for a different slice (Firecracker for density, CH for features, QEMU for the awkward cases). Modeling the lifecycle as a narrow, well-typed contract (`create/boot/request_shutdown/kill/snapshot/restore/stats`) keeps the finicky, subprocess-supervising, occasionally-`unsafe` VMM glue behind a boundary and lets the orchestrator stay idiomatic and unit-testable (a `FakeVmm` implements the same trait — see §5.5).

---

## 5. The Rust library (`imp_testing`)

This section covers **all the parts of the expected library**: crate layout, the public API surface, each module's responsibility, the external-tool-vs-in-crate decision per capability, and the architectural accommodations that make it unit-testable.

### 5.1 Crate and workspace layout

One Cargo **package**, 2024 edition, containing one **library crate** plus **binary** targets that wrap it (a single package can expose `src/lib.rs` and multiple `src/bin/*.rs`):

```
imp-testing/
├─ Cargo.toml                 # edition = "2024"; [lib] + [[bin]] targets
├─ deny.toml                  # cargo-deny: permissive-license allow-list, advisory DB
├─ rustfmt.toml  clippy is config-via-CI
├─ README.md                  # external tools + Debian install instructions (req: source 5)
├─ src/
│  ├─ lib.rs                  # re-exports the public API; crate docs
│  ├─ config.rs               # VmConfig, Share, NetConfig, ResourceLimits, NestedVirt …
│  ├─ vmm/
│  │  ├─ mod.rs               # `Vmm` + `VmInstance` traits, shared types
│  │  ├─ cloud_hypervisor.rs  # subprocess supervisor + REST client (primary)
│  │  ├─ firecracker.rs       # optional dense backend (feature = "firecracker")
│  │  └─ qemu.rs              # optional fallback (feature = "qemu")
│  ├─ agent/
│  │  ├─ mod.rs               # AgentClient (host side, tokio-vsock/AF_UNIX)
│  │  └─ protocol.rs          # framed wire protocol (shared by host + guest agent)
│  ├─ fs.rs                   # virtiofsd supervision: one per share, perms, tags, sockets
│  ├─ net.rs                  # netns + tap + /30 addressing (rtnetlink); nft rule emission
│  ├─ proxy/
│  │  ├─ mod.rs               # EgressProxy: listen, log, filter, dispatch
│  │  ├─ tls.rs               # MITM CA, on-the-fly cert minting (rcgen/rustls)
│  │  └─ doubles.rs           # test-double + record/replay (cassette) hooks
│  ├─ metrics.rs              # cgroup v2 slice mgmt + peak/avg readers (cgroups-rs)
│  ├─ artifact/
│  │  ├─ mod.rs               # Stage trait, Pipeline, cache, record/replay, signing
│  │  ├─ kernel.rs            # vmlinux build stage
│  │  ├─ rootfs.rs            # mmdebstrap/mkosi rootfs build stage
│  │  └─ snapshot.rs          # warm-snapshot build stage
│  ├─ orchestrator.rs         # TestVm handle tying it together; Drop teardown; sweeper
│  └─ error.rs                # crate Error/Result (thiserror)
├─ src/bin/
│  ├─ imp-testing.rs          # CLI wrapping the lib (clap): build, run, exec, ls, rm …
│  └─ imp-guest-agent.rs      # static (musl) guest PID 1; uses agent::protocol
└─ tests/                     # one integration test per requirement / VM operation
   ├─ boot.rs                 ├─ exec_vsock.rs        ├─ shares_ro_rw.rs
   ├─ host_endpoint.rs        ├─ egress_proxy.rs      ├─ metrics_limits.rs
   ├─ nested_virt.rs          ├─ snapshot_restore.rs  └─ lifecycle.rs
```

`imp-guest-agent` is built for `x86_64-unknown-linux-musl` so it is fully static and drops into any rootfs as `/sbin/init`. It shares only the small `agent::protocol` module with the host, keeping "all functionality in one library crate" essentially true while the guest binary stays thin.

### 5.2 Public API surface (illustrative sketches)

Types are `#[non_exhaustive]` where future fields are likely; builders keep call sites stable. Async is via native `async fn` in traits; `#[async_trait]` is used only where `dyn Vmm` object-safety is required.

```rust
// ---- config.rs ------------------------------------------------------------
#[derive(Clone, Debug)]
pub struct VmConfig {
    pub vcpus: u8,
    pub mem_mib: u32,
    pub kernel: PathBuf,        // vmlinux (direct kernel boot)
    pub rootfs: RootfsSource,   // Block { image, overlay } | VirtioFs { dir }
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
pub struct NetConfig {
    pub egress: Egress,         // Filtered { proxy: ProxyConfig } | Blocked | Open
    pub host_services: bool,    // expose gateway IP for host-bound test servers
}

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
    /// Spawn + configure the backend (does not start the guest yet).
    async fn create(&self, cfg: &VmConfig, res: &PerVmResources) -> Result<Self::Instance>;
}

pub trait VmInstance: Send {
    async fn boot(&mut self) -> Result<()>;            // start guest execution
    async fn request_shutdown(&mut self) -> Result<()>;// graceful (ACPI)
    async fn kill(&mut self) -> Result<()>;            // force-terminate VMM process
    async fn snapshot(&mut self, dir: &Path) -> Result<()>;
    async fn stats(&self) -> Result<ResourceUsage>;    // live counters
    fn vsock_path(&self) -> &Path;                     // AF_UNIX endpoint for AgentClient
    fn serial_log(&self) -> &Path;                     // per-VM panic/early-boot log
}

// ---- agent/mod.rs ---------------------------------------------------------
pub struct AgentClient { /* tokio-vsock connection */ }
impl AgentClient {
    pub async fn connect(vsock_path: &Path, port: u32) -> Result<Self>;
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
/// The handle most tests hold. Owns all per-VM resources; Drop force-cleans.
pub struct TestVm<V: Vmm> { /* instance, cgroup, netns, tap, virtiofsd procs, overlay */ }
impl<V: Vmm> TestVm<V> {
    pub async fn start(vmm: &V, cfg: VmConfig) -> Result<Self>;
    pub async fn agent(&mut self) -> Result<&mut AgentClient>;
    pub async fn usage(&self) -> Result<ResourceUsage>;
    pub async fn shutdown(self) -> Result<()>;         // graceful, then verify gone
}
impl<V: Vmm> Drop for TestVm<V> { /* kill VMM proc-group; rm tap/netns/cgroup/overlay/sockets */ }

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

- **`config`** — Pure data + builders. No I/O, so it is trivially unit-tested (e.g., builder defaults, validation that share tags are unique, that `ReadWrite` + snapshot are flagged as the contested combo).
- **`vmm`** — The trait boundary and backends. `cloud_hypervisor` owns: spawning the `cloud-hypervisor` process with `--api-socket`; constructing the `VmConfig` REST payload; `PUT vm.create` / `vm.boot` / `vm.shutdown`; reading `counters`; and `snapshot`/`restore`. The REST client is a hand-written thin wrapper over `hyperlocal` (Unix-socket HTTP) with `serde` types generated from CH's in-repo OpenAPI YAML (or vendored from `cloud-hypervisor-client`, pinned). `firecracker` and `qemu` are feature-gated and implement the same traits (Firecracker via its REST socket; QEMU via QMP, e.g. the `qapi` crate, which also speaks the guest-agent protocol).
- **`agent`** — `protocol` defines a small length-prefixed, `serde`-(bincode/postcard)-framed message enum: `Hello/Ready`, `Exec{argv,env,cwd}`, `Stdout(bytes)`, `Stderr(bytes)`, `Exit(i32)`, `PutFile`, `Ping`. `mod` is the host client over `tokio-vsock`/AF_UNIX. The guest side lives in `src/bin/imp-guest-agent.rs`: as PID 1 it mounts `proc`/`sys`/the virtio-fs tags, brings up `eth0` with a static address, installs the proxy CA, then serves the protocol on a fixed vsock port. (Pattern validated by `mvm`'s "vsock-only agent, NO SSH ever.")
- **`fs`** — Spawns one `virtiofsd` per `Share`, each on its own Unix socket, with `--read-only` for `ReadOnly` shares and an isolating uid + mount namespace so a daemon can reach only its one directory. Emits the CH `--fs tag=…,socket=…` config and ensures `--memory shared=on`. Cache policy defaults to `never` (density).
- **`net`** — Creates a per-VM network namespace, a `veth`/tap pair, and assigns a `/30` (`10.200.<vmid>.0/30`, host = `.1`, guest = `.2`) via `rtnetlink` (pure-Rust netlink). Emits nftables rules: a `TPROXY` redirect of guest tcp/80,443 (and optionally udp/443) to the host proxy, plus `drop`/`log` rules for filtered egress. The `/30`-math and the nft-rule rendering are pure functions → unit-tested; the actual netlink/nft application is the side-effecting part.
- **`proxy`** — A `hyper`-based transparent proxy. For HTTP it splices/logs; for HTTPS it terminates TLS with an on-the-fly cert minted by an in-memory CA (`rcgen`) and re-originates upstream (`hudsucker` can supply this whole MITM machinery if preferred — Apache/MIT). `doubles` lets a test register `(Matcher, Responder)` pairs (the "great extra") and, for the eval layer, record/replay cassettes. `requests()` exposes an assertable log.
- **`metrics`** — Creates the per-VM cgroup v2 slice (via `cgroups-rs`), applies `ResourceLimits`, and reads `memory.peak`/`memory.current`/`cpu.stat`/`io.stat` plus tap counters for net I/O. Peak comes "for free" from `memory.peak`; average is computed from periodic `cpu.stat`/`io.stat` deltas over the run.
- **`artifact`** — The staged build pipeline (full detail in §7): a `Stage` trait with a *pure* `cache_key`, a `Pipeline::build` that skips stages whose outputs already exist, and `reset_to` for invalidation. First stage resolves the up-to-date pins (e.g., the Debian snapshot timestamp); all later stages are deterministic given their inputs.
- **`orchestrator`** — `TestVm` composes everything and, crucially, owns teardown. Its `Drop` kills the VMM process group and removes the tap/netns/cgroup/overlay/virtiofsd sockets so a panicking test cannot leak host resources; a periodic sweeper reaps anything orphaned by a hard crash (pattern from the `processkit`/cocoon references).
- **`error`** — One `Error` enum (`thiserror`) with variants per subsystem; `Result<T> = std::result::Result<T, Error>`.
- **`bin/imp-testing`** — `clap`-based CLI: `build` (run the artifact pipeline), `run`/`exec` (start a VM and run a command), `ls`/`rm` (manage VMs), `stats`. This is the "binary crate wrapping the library to quickly try the functionality."

### 5.4 In-crate vs. external tool, per capability (with licenses)

Applying the requirements' avenue ranking ("best: our own Rust; …; okay: a binary with a programmable interface"):

| Capability | Mechanism | Avenue tier | License |
|---|---|---|---|
| VM lifecycle | `cloud-hypervisor` **binary** over REST; thin Rust client | Good (binary w/ programmable iface) | Apache-2.0/BSD-3 |
| Shared dirs | `virtiofsd` **daemon** per share | Good (binary) | Apache-2.0 AND BSD-3 |
| vsock control | **our Rust** (`tokio-vsock` + own protocol) | Best (own library) | MIT/Apache (crate) |
| Guest agent | **our Rust** (static musl PID 1) | Best | — |
| Networking | **our Rust** netlink (`rtnetlink`) + nft emission | Best/Great | MIT/Apache |
| Egress proxy | **our Rust** (`hyper`+`rustls`/`rcgen`, or `hudsucker`) | Best/Great | MIT/Apache |
| Monitoring/limits | **our Rust** cgroup v2 (`cgroups-rs`) | Great | MIT/Apache |
| Rootfs build | `mmdebstrap`/`mkosi` **tools** (build-time only) | Okay (external build tool) | GPL/Free (not linked) |
| Kernel build | Debian kernel source + toolchain (build-time) | per requirement 6 "good" | GPL (source, build-time) |
| Fallback VMM | `qemu-system` **binary** (QMP via `qapi`) | Okay (binary) | GPL-2.0 (binary, allowed as exception) |

License gate: `cargo-deny` enforces an allow-list (MIT/Apache-2.0/BSD-3/ISC/Zlib) for all *linked* crates and fails the build on copyleft or non-OSI licenses. Build-time tools (mmdebstrap, the kernel toolchain) and the QEMU fallback are external executables, not linked, so their copyleft status is acceptable under the requirements.

### 5.5 Architectural accommodations for testability

The "minor accommodations for unit-test coverage" the requirements ask for, without over-engineering:

1. **The `Vmm`/`VmInstance` trait seam.** A `FakeVmm` (test-only) implements both traits in memory, letting the orchestrator's logic (resource allocation order, `Drop` cleanup, retry/timeout handling, snapshot-vs-cold-boot selection) be unit-tested with no KVM, no root, no subprocess.
2. **Pure/imperative split.** The genuinely-testable pure functions are isolated from I/O: nft-rule rendering, `/30` address arithmetic, the CH REST payload builder, cgroup-path construction, the artifact `cache_key`, and the agent protocol's encode/decode. Each gets `#[cfg(test)]` unit tests. The thin I/O wrappers around them are exercised by the integration tests.
3. **Injectable side-effect traits where it pays off.** `Netlink`, `NftApplier`, and `CgroupFs` are small traits with a real implementation and a recording fake, so `net`/`metrics` orchestration is unit-testable (assert "the right rules/limits were requested") without touching the host.
4. **Deterministic IDs and clocks** are injected (a `vmid` allocator, a `Clock`) so tests are reproducible.

The integration tests in `tests/` (one per requirement/operation) are the real-environment counterpart; they require KVM + root-ish capabilities and are gated behind a `--features integration` / an env guard so `cargo test` stays green on a laptop while CI runs the full suite on a KVM-capable runner.

---

## 6. Requirement-by-requirement realization

A compressed pass over the ten functional requirements (mechanism → tier achieved), plus the non-functional ones.

1. **Host OS / arch.** CH fully supports Linux **x86_64** (mandatory) and **aarch64** (the "good extra"). macOS is *not* supported by CH; the macOS-on-Apple-Silicon "nice-to-have" is explicitly tie-breaker-only and is **not** pursued, since chasing it would force a weaker stack (libkrun/Apple Container with a single guest+VMM security context). **Met on the mandatory axis; aarch64 extra met; macOS deliberately skipped.**

2. **Shared dirs.** virtio-fs, one `virtiofsd` per tag → multi-dir (mandatory). `--read-only` per daemon → per-mount permissions (the "great" extra). The "good" extra (host page-cache sharing) historically came from DAX, which is unavailable (§3.1); `cache=never` minimizes guest footprint instead. **Mandatory + great met; the page-cache "good" extra not met today.**

   *2 + performance (the snapshot fork):* because snapshot/restore does not compose with virtio-fs (§3.2), the **snapshot fast path boots from a block rootfs**, and virtio-fs is used for the *data/binary/output* shares. If post-restore virtio-fs attach proves reliable on the pinned versions, the warm-snapshot + virtio-fs-data hybrid becomes the universal path; if not, data-heavy tests serve inputs via read-only block images on the snapshot tier. This branch is the single most important thing to benchmark.

3. **Host-served endpoints.** Per-VM netns + tap + `/30`, host test server bound to the gateway IP → reachable from the guest, not exposed to other systems (mandatory). Per-test server config and dynamically-assigned ports are straightforward from Rust (configure the VM's view *after* the server is listening). Arbitrary TCP/UDP/etc. "just works" over the L2 link (the "other protocols" extra). vsock is available as an alternate, IP-stack-free host↔guest channel. **Mandatory + both great extras + the good extra met.**

4. **Transparent proxy.** tap + nftables **`TPROXY`** (not `REDIRECT`/DNAT — TPROXY preserves the original destination and handles UDP; confirmed against the kernel docs) → the Rust MITM proxy logs and filters all egress (mandatory). The proxy being our own Rust code makes **test doubles** for web services natural (the "great" extra), and is the hook for record/replay cassettes. **Mandatory + great met.**

5. **Guest environment.** Minimal Debian Trixie via `mmdebstrap`/`mkosi` = "stripped-down Debian via supported methods" (the "good" tier). A full installed Debian-server flavor (the "great" tier) is possible if a specific test needs it, at a boot-time cost — exposed as a heavier rootfs profile. **Good tier met; great tier available on demand.**

6. **Guest kernel.** Direct-boot a custom-minimal `vmlinux` built from **Debian kernel source** with a microvm config (the "good" tier) — virtio core/pci/blk/net/console/rng, fuse/virtio-fs, vsock, the rootfs FS, optional KVM, serial console; no initramfs. Using a Debian-provided kernel *image* unmodified (the "great" tier) is also supported as a profile. **Project-specific kernel patches (the "unacceptable" option) are never used.** **Good tier met; great tier available.**

7. **Nested virtualization.** Build KVM into the guest kernel and enable it on the host (`kvm-intel nested=1`, guest cmdline `kvm-intel.nested=1`); the L1 guest then gets `/dev/kvm` and Imp-under-test can run inner VMs (CH or Firecracker). This is a separate *test class*, not the default fast path. Peripheral passthrough (USB) is tie-breaker-only and not pursued. **Met with CH** (Firecracker and libkrun cannot do this — another reason they aren't primary).

8. **Programmable infra control.** The CH REST API + `ch-remote` cover create/delete/list, start/request-shutdown/force-shutdown, and configuration of shares/networking/nested-virt. Performance monitoring (peak + average CPU/RAM/disk-I/O/net-I/O) comes from the per-VM cgroup v2 slice (`memory.peak`, `memory.current`, `cpu.stat`, `io.stat`) plus tap counters, layered with CH's live `counters`. **Met.**

9. **Programmable artifact build.** The staged pipeline in §7 builds filesystem/disk images, kernel/firmware, and config files, with content-addressed caching. **Met.**

10. **Programmable console.** The vsock Rust client (host) + Rust server (guest agent) hits the top "great" tier. TTY emulation (serial) is retained for panic capture; SSH is a human-only fallback, never the control plane. **Great tier met.**

**Non-functional — performance (running time).** Most tests are seconds; the lever is **warm-snapshot restore + reflink/COW overlay** so the per-test critical path skips kernel boot and pays only a near-instant COW disk fork plus restore. Per-test artifact-prep time is counted (per the requirements): virtio-fs avoids any per-test image copy (just re-point a daemon) but pays virtiofsd start + the snapshot-incompatibility cost; block+reflink pays a near-zero COW fork but composes with snapshots. The design implements **both** so the per-tier choice is empirical.

**Non-functional — RAM density.** RAM is the binding limit on parallelism. Levers: `cache=never`, **KSM** (`merge_across_nodes=0` on NUMA; budget ~5–10% CPU for `ksmd`), and **virtio-balloon/free-page-reporting**. Plan with **128–256 MiB/guest as a must-re-benchmark figure** (the guest userland, not the ≤5 MiB VMM overhead, dominates). The next limits after RAM are typically one-virtiofsd-per-VM, tap/bridge/nft scaling, and host FD/PID limits.

**Non-functional — Rust ergonomics & licensing.** Covered by §5.4 (avenue tiers, permissive-only via `cargo-deny`).

---

## 7. Artifact build pipeline

Maps directly onto the VM-artifact-production requirements (staged, pinned, deterministic, cacheable, resettable, minimal external access, record/replay, signing-chain verified).

### Artifacts produced
1. **`vmlinux`** (per arch): one custom-minimal kernel, direct-boot, drivers built in, optional KVM-for-nesting. Host-side, shared by all VMs; rebuilt only when the config or pinned source changes.
2. **Base rootfs** (per profile): `mmdebstrap` minbase + the test toolchain + `imp-guest-agent`, emitted **two ways** — a read-only `erofs`/`squashfs` (for the virtio-fs/cold-boot path) and a block image (for the snapshot path). **Imp's own binaries are *not* baked in** — they arrive over the `imp-bin` virtio-fs share, so a new Imp build does not invalidate the rootfs.
3. **Warm snapshot** (per VMM + profile): boot the block-rootfs base to "agent-ready," snapshot. Per-test = restore + COW overlay.
4. **Proxy CA cert**: minted once, baked into the rootfs trust store.

### Stage model
- **Stage 0 — resolve pins (the only non-deterministic stage).** Determine the most up-to-date values for a minimal pin set: the Debian package-repo **snapshot timestamp** (via `snapshot.debian.org`), the kernel source version/commit, and the CH/virtiofsd release tags. Output: a small, committed `pins.lock`.
- **Stages 1..n — deterministic given inputs.** Each stage's output is fully determined by its inputs + the pins. Examples: *fetch+verify kernel source*, *configure+compile `vmlinux`*, *`mmdebstrap` rootfs at the pinned snapshot*, *install `imp-guest-agent` + CA*, *pack erofs*, *pack block image*, *boot+snapshot*.
- **Caching.** Each stage has a pure `cache_key` (hash of inputs + pins + stage version); `Pipeline::build` skips a stage whose outputs already exist under that key. `reset_to(stage)` removes the outputs of that stage and all later ones.
- **Minimize external access + record/replay.** Network-touching stages (apt, source fetch) are split into a **record** step (populate an on-demand cache, e.g. an apt package cache keyed to the snapshot, or an `mmdebstrap` `--setup-hook` mirror) and a **replay** step (build purely from the cache). Iteration and CI then hit the network at most once per pin.
- **Signing-chain verification.** Verify the Debian `InRelease`/`Release` + `Release.gpg` chain against the pinned archive keyring before using any package, and verify kernel-source signatures/hashes where published; **refuse to proceed on mismatch.** This is a hard stop, not a warning.

The pipeline is exposed both as the library `artifact::Pipeline` API and as `imp-testing build [--reset-to STAGE]` on the CLI.

---

## 8. Implementation roadmap (simple-and-testable first, then feature-by-feature)

Each milestone lands a working, testable slice and at least one fine-grained integration test (the requirements ask for ~one test per requirement / VM operation). The artifact-pipeline track is partly a prerequisite (you need *a* kernel + rootfs to boot at all), so its first stages land inside M1.

| # | Milestone | What lands | Integration test(s) | Requirement(s) |
|---|---|---|---|---|
| **M0** | Skeleton | Cargo package (2024 ed.), lib + 2 bins, `error`/`config`, clippy+rustfmt+`cargo-deny` in CI, README scaffold, `FakeVmm` | unit: builder defaults, protocol round-trip, `/30` math | source-code reqs 1,2,3,6,7,8 |
| **M1** | First boot | Artifact pipeline v0 (build a minimal `vmlinux` + tiny rootfs via real stages); CH subprocess + REST `create`/`boot`; serial→log; `Drop` kill | `boot.rs`: VM reaches userspace (known string in serial log). `lifecycle.rs`: force-shutdown a started VM | 1, 6, 9, parts of 8 |
| **M2** | vsock control | `agent::protocol`; `imp-guest-agent` as PID 1; host `AgentClient` | `exec_vsock.rs`: `exec("echo hello")` → stdout `hello`, exit 0. `lifecycle.rs`: graceful `request_shutdown` | 10, rest of 8 |
| **M3** | Shared dirs | `fs` (virtiofsd per share, perms, tags); `--memory shared=on`, `cache=never` | `shares_ro_rw.rs`: guest reads a host-placed input file; write to RO share fails; host sees a file the guest wrote to the RW share | 2 (mandatory + great) |
| **M4** | Host endpoints + net | `net` (netns + tap + `/30`, rtnetlink); gateway-bound host server | `host_endpoint.rs`: guest GETs a host HTTP server on a dynamic port; server unreachable outside the netns; a second protocol (raw TCP) works | 3 (+extras) |
| **M5** | Transparent proxy | `proxy` (TPROXY redirect, MITM CA, log/filter, doubles); bake CA into rootfs | `egress_proxy.rs`: HTTPS request is logged; a filter rule blocks a domain (guest sees the block); a registered test-double returns a canned response | 4 (+great) |
| **M6** | Monitoring + limits | `metrics` (cgroup v2 slice, caps, peak/avg readers) | `metrics_limits.rs`: a workload allocating N MiB shows up in `memory.peak`; `memory.max` kills a runaway allocator; avg CPU computed over a busy loop | 8 (perf monitoring) |
| **M7** | Nested virt | Guest kernel profile with KVM built-in; host enablement docs | `nested_virt.rs`: `/dev/kvm` present in guest; an inner micro-VM boots and runs a command | 7 |
| **M8** | Snapshot + density | Warm-snapshot build stage; restore + reflink/COW overlay; identity rotation + entropy reseed; KSM/balloon wiring | `snapshot_restore.rs`: restore is faster than cold boot; restored VM has fresh CID/MAC + reseeded RNG; outputs still land in `imp-out` | perf + density non-functional |

**Build-pipeline hardening track** (runs alongside, completes by M8): Stage 0 pin resolution + `pins.lock`; record/replay split for apt + source fetch; signing-chain verification with refuse-on-mismatch; `reset_to`; dual rootfs emission (erofs + block). Each gets its own test (e.g., "a tampered package digest aborts the build"; "a second build with a warm cache performs zero network fetches"; "`reset_to(rootfs)` rebuilds rootfs and snapshot but not the kernel").

**Sequencing rationale.** M1 derisks the hardest plumbing (subprocess + REST + boot + teardown) with the least surface. M2 establishes the control channel everything else asserts through. M3–M5 add the three I/O surfaces (files, host services, egress) in increasing complexity. M6 makes runs measurable and bounded. M7 and M8 are the two "advanced" capabilities (nesting, snapshot/density) deliberately last because they're the most environment-sensitive and the most likely to need version-specific tuning.

---

## 9. Risks, open decisions, and what to benchmark

- **The snapshot ↔ virtio-fs fork (highest risk).** §3.2. Decide empirically per test tier; the whole M8/M3 interaction hinges on whether post-restore virtio-fs attach works on your pinned CH/virtiofsd. Build both paths; pick per tier from measurements.
- **DAX is gone (density plan).** §3.1. Any plan assuming shared host-page mapping for read-only data via DAX is invalid; rely on `cache=never` + KSM + balloon. Re-check on the pinned CH.
- **Rootless vs. tap networking.** tap + TPROXY needs `CAP_NET_ADMIN` (root-ish) on the runner, which the Gemini fact-check rightly flags as a deployment constraint for locked-down CI. **Userspace networking (`passt`/`gvproxy`)** is a rootless alternative and a natural egress choke point, at some L2-fidelity and throughput cost. Recommendation: expose networking as a config axis — tap+TPROXY for fidelity tiers, passt for rootless/CI tiers — behind the same `NetConfig`.
- **Boot/density numbers are unverified.** §3.4. Benchmark cold-boot, restore, idle guest RSS, and the concurrent-VM ceiling per RAM tier on the actual hardware before quoting anything.
- **Nested-virt host requirements.** §3.5. Needs host `nested=1` (bare-metal or a nesting-capable cloud instance, e.g. AWS C8i/M8i/R8i via `NestedVirtualization=enabled`, or `.metal`). On AMD, don't snapshot an L1 that has started an L2.
- **Snapshot uniqueness.** Restored clones must not reuse RNG state/secrets — rotate identity (VMGenID/SysGenId concept) and reseed entropy (virtio-rng) on restore; an unreseeded `getrandom()` can stall first-RPC by seconds. (See Brooker et al., arXiv 2102.12892, for the `MADV_WIPEONSUSPEND` + VMGenID approach — note `WIPEONSUSPEND` is a *proposed* flag, distinct from the existing `MADV_WIPEONFORK`.)
- **Cross-version snapshot fragility.** Pin one exact CH + virtiofsd build for any snapshot pool; CH does not guarantee snapshot compatibility across versions.
- **Primary architecture.** x86_64 is the mandatory CI arch and the place to invest first; aarch64 is a supported extra but kernel configs and snapshot artifacts differ, so treat it as a second target, not a free rebuild.

---

## 10. Prior art worth mining before writing code

- **`cocoonstack/cocoon`** ★ — a 2026 lightweight micro-VM engine on Cloud Hypervisor with instant snapshot+clone via **reflink**, COW overlays, balloon/free-page-reporting, and Firecracker as an alternate backend; it documents the exact vhost-user-snapshot constraint from §3.2. Closest reference to the snapshot/density path.
- **`tinylabscom/mvm`** ★ — Rust CLI with a multi-VMM backend abstraction and a **vsock-only guest agent ("NO SSH ever")**; a near-reference for the `Vmm` trait and the agent protocol.
- **`microvm.nix` agent-sandbox write-up** ★ — the egress topology to copy: CH + nftables forward-chain logging + DNS logging + read-only `erofs` rootfs.
- **`pve-microvm` (Tao of Mac)** — QEMU `microvm` as a managed guest; good reference for the kernel/rootfs split and "prebuild the rootfs, don't `apt` at boot."
- **`agentkernel`, `vmexec`** — ephemeral-VM-per-command patterns on the rust-vmm stack, in your exact domain.
- **Kata `agent-ctl` / `kata-ctl`** — the agent-over-vsock blueprint and tooling.
- **UK AISI `inspect_ai` agent-bridge / `model-proxy-lifecycle`** — only if/when the eval layer needs the in-guest model-proxy-over-vsock pattern (the §1.2 hook); not needed for the infrastructure library itself.

---

*Version/feature claims reflect the mid-2026 research inputs; CH was at v52.0 and Kata 4.0 in preview at research time. Re-verify the §3 contested items — DAX availability, snapshot/virtio-fs composability, userfaultfd restore, nested-virt flags, and all boot/density numbers — against the exact tool versions pinned in `pins.lock`.*
