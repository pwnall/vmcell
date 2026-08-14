# vmcell — Design Document (v31)

> **v31 (2026-08-14) is the post-landing re-base.** The v30 register's nine deltas are **built,
> live-validated, and reconciled** — `vmcell` is **0.13** — and the code review that followed them
> (`docs/78`) landed in two fix waves. So v31 changes no architecture: it re-states the body as the
> system now is, wherever the two disagreed. The corrections it carries are the ones the landing
> produced, each verified against the tree: §3.2 replaces "EOF propagates in both directions" with the
> measured four-backend half-close table; §6.5's bridge-unique-MAC and already-sweeps-segments premises
> are corrected to the fixes they forced; §6.2/§6.5 state the two-channel tap wiring (`res.tap_name` in
> the backends, `net_uses_tap` config-side, joined by `assert_tap_wiring_matches`) instead of the
> single predicate that never existed; §6.2's NAT invariants gain a **sixth** (the guest→host drain
> consumes only the contiguous span — a real panic that wedged the link silently); §8.1's eligibility
> law is the one config-only predicate, now refusing custom-init and host-USB configs, with the
> falsified "every backend's `restore()` rejects a non-snapshotting config" premise stated as such;
> §2.3/§8.2 record Firecracker's `network_overrides` tap rebind and scope
> `restore_rotates_host_paths` to the vsock/serial paths; §12.3 folds the three deny-list carry-overs
> and describes the three gates that actually read the post-jail state; §5.4, §5.6, §7.2, §9.1, §9.2,
> §11.3, §11.4, §15.4 and Appendix C are corrected against the shipped names, rosters, filters and
> pins. §17 is re-checked rather than copied forward. §18 becomes the **landed** record of the v30
> pass, its register conventions kept as standing rules for the next one. **No section renumbers.**
>
> **Where this document came from.** v28 restructured v27 for a developer learning the system in order to
> maintain it — one section per subsystem, facts stated once at their canonical home — and directed the
> eleven-item **0.9 → 0.10 breaking pass** through the delta-register convention it introduced (the body
> states the target in the present tense; §18 lists the exact deltas from the last validated build). That
> pass is **fully landed and reconciled**; its per-item as-built record is
> `docs/implementation-notes.md` ("v28 — the 0.9 → 0.10 delta register, as built"). **v29 added the
> fourth VMM backend, crosvm** (§2.5), validated live end-to-end including snapshot/restore, bumping
> `vmcell` 0.11 → 0.12 (`VmmCapabilities` gained `disk_io_throttle`). Section numbering is unchanged
> since v28; **Appendix E** still maps v27 § references (which appear in code comments) to the current
> numbering.
>
> **v30 is the downstream-platform pass.** vmcell has its first out-of-repo consumer — usb-teleporter, a
> USB-over-IP forwarding system whose kernel-facing test tiers run inside vmcell micro-VMs, consuming
> `vmcell` and `vmcell-artifact-validator` as rev-pinned git dependencies. Its feature-request document
> (usb-teleporter `docs/feature-requests-vmcell.md`, FR-V1…FR-V6; current-state claims verified against
> the 0.12 tree, 2026-08-11) asks — under an explicit generality directive — for **mechanisms, never
> consumer content**: build + validate out-of-repo guest kernels (FR-V1, the one P-blocking item), a
> VM-to-VM network segment (FR-V2), host→guest inbound dial (FR-V3), downstream rootfs composition on
> the packer path (FR-V4), a host-USB passthrough capability (FR-V5, ranked last by its own requester),
> and pins-override / artifact-cache / git-dep ergonomics (FR-V6). v30 designs all six. The **new §18
> delta register** — nine deltas, replacing the landed v28 register — was the exact boundary between "as
> built and validated at v29/0.12" and "directed by that revision"; deltas 1–8 landed as one breaking pass
> (`vmcell` 0.12 → 0.13), with delta 9 (FR-V5) separable and last. New sections: **§5.6** (the
> downstream kernel toolkit), **§6.5** (VM-to-VM segments), **§10.4** (the downstream toolkit contract);
> §1.6, §2, §3.2, §4.2, §5.5, §6.2, §9, §10, §13, §15, and §17 gain woven additions; **no section
> renumbers**.
>
> v30 also **re-bases the body on the as-built system**, so it again describes reality with no external
> errata: the two `docs/historical/70` errata are folded in (§9.7 — the 1.96.1 single-source MSRV; §15.2
> — the broker's web-server-stack-only lean boundary), §9.3's `agent()` signature is reconciled to the
> recorded v28 delta-1 deviation (the retained `timeout` budget), §9.1 gains the
> `vmcell-artifact-validator` member the v29 roster omitted, §5.3's description of `contains_panic` now
> matches the shipped matcher, and the §2.6/§16 tables pick up the 2026-07-17 canonical benchmark matrix
> (which measured crosvm and QEMU restore — the old "restore not wired" note was stale). The §18 preamble states four register-authoring conventions the v24–v28 passes taught, so the
> next implementer hits fewer of the traps recorded in `docs/implementation-notes.md`.

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
│   │     └─ impls:  CloudHypervisor (default) · Firecracker · Qemu · Crosvm  resume/snapshot/kill)│
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
Vmm trait         ──▶ CloudHypervisor · Firecracker · Qemu · Crosvm            §2   (spawn/boot/restore)
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
| Second VMM | **Firecracker** (MMIO mode) — the density tier and the fastest restore (≈27 ms p50), with two honest constraints: single-lineage host paths and no lazy restore (§2.3). |
| Fallback VMM | **QEMU `q35`** (never `microvm`) — the escape hatch and most-proven nester. C/GPL *binary*, never linked. |
| Fourth VMM | **crosvm** (v29, §2.5) — a boot-first secondary: baked-CID snapshot (single-lineage), in-kernel vsock, the most consistent (flake-free) cold boot; opt-in live matrix (`just test-crosvm`). |
| Control plane | virtio-vsock + a Rust guest agent as PID 1; framed `postcard` protocol; one-shot exec plus an additive session layer (PTY / streaming stdin / multiplexed exec). SSH is a human-only debug fallback. |
| Root filesystem | A single **read-only erofs over virtio-blk**, shared by all VMs; per-VM writes go to a tmpfs `overlayfs` upper. No journal → no recovery writes, no concurrent-mount corruption; composes with snapshot. |
| Shared dirs | virtio-fs, one `virtiofsd` per share, caller-defined mount tags. Mutually exclusive with snapshot (§8.1). |
| Networking | Per-VM netns + tap + `/30` (privileged) or an in-process smoltcp vhost-user-net NAT (unprivileged). |
| Egress proxy | A Rust MITM proxy (`hudsucker`), CA baked into the guest trust store; steered via nft TPROXY (privileged) or L4 interception in the NAT (unprivileged). |
| Limits | One cgroup v2 slice per VM; a *requested* limit that can't be enforced fails loud, never a silent no-op (§7.2). |
| Guest OS / kernel | Minimal Debian Trixie from OCI-pull (default) or in-VM `mmdebstrap`; direct-boot custom-minimal `vmlinux` (Linux 6.12 LTS), everything built in, no initramfs. |
| Speed lever | Warm snapshot + restore: ≈5.8× faster than cold boot on CH; the zygote fan-out CoW-clones one suspend image into many VMs; `Lineage` adds fork/branch provenance. |
| Third entry surface | The long-lived **`vmcelld`** daemon owns VMs across requests behind a bearer-authed REST/OpenAPI API; by default it forks a **setup broker** so the network surface holds no capabilities. |
| Downstream consumption | Git-dep workspaces are first-class consumers (v30): a **documented toolkit contract** — pins overlay, the `VMCELL_*` env contract, out-of-repo kernel build + validation, rootfs extra-files — kept honest by an out-of-tree example workspace CI builds on every push (§10.4). vmcell ships mechanisms, never consumer content (law G1). |
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

The body is written in the present tense and describes the system as designed at v30; §18 is the exact
boundary between "as built and validated" and "directed by this revision." A non-obvious choice (why erofs
and not ext4; why the snapshot tier excludes unprivileged networking; why a Firecracker snapshot lineage
shares one host vsock path) is explained inline where the component is described, and **Appendix A**
records the reversal history behind the ones that were hard-won.

---

## 2. VMM backends and the `Vmm` trait

### 2.1 The trait and the capability descriptor

The VM lifecycle is modeled as a narrow, typed contract so the finicky, subprocess-supervising,
occasionally-`unsafe` VMM glue stays behind a boundary and the orchestrator stays idiomatic and
unit-testable (a `FakeVmm` implements the same trait, §9.8). The backends genuinely diverge —
Firecracker has no virtio-fs, no vhost-user-net, no nested virt; crosvm (v29, §2.5) additionally ships
without snapshot in its first cut — so the contract is **general with a capability descriptor**, not
CH-shaped:

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
// Deliberately EXHAUSTIVE (no #[non_exhaustive]) since the backend extraction: a new capability field
// must force every backend to declare its stance — a compile error in all five construction sites,
// never a silent default. vmcell is publish = false, so no external consumer relies on
// non-exhaustiveness. Adding a field is a breaking bump (the 0.11→0.12 disk_io_throttle precedent;
// usb_host_passthrough repeats it, §18 delta 9).
pub struct VmmCapabilities {
    pub snapshot_restore: bool,            // CH ✓ · FC ✓ (single-lineage host paths, §2.3) · QEMU ✓ (in-kernel vhost-vsock, §2.4) · crosvm ✓ (baked-CID, FC-pattern, §2.5)
    pub lazy_restore: bool,                // demand-paged restore. CH ✓ (--restore … prefault=off) · FC ✗ · QEMU ✗ · crosvm ✗
    pub virtio_fs_shares: bool,            // CH, QEMU ✓ · FC ✗ (block-only) · crosvm ✗ (has --shared-dir; unvalidated, §2.5)
    pub unprivileged_vhost_user_net: bool, // smoltcp NAT via vhost-user-net: CH, QEMU ✓ · FC ✗ · crosvm ✗ (unvalidated, §2.5)
    pub nested_virt: bool,                 // expose /dev/kvm to the guest: CH, QEMU ✓ · FC ✗ · crosvm ✗ (documented-unsupported)
    pub virtio_console: bool,              // ConsoleMode::VirtioConsole: CH, QEMU, crosvm ✓ · FC ✗ — rejected
                                           //   loud+early on FC, before the cmdline is built (console=hvc0
                                           //   with no device would silence the log)
    pub restore_rotates_host_paths: bool,  // scope: the vsock/serial host paths — the TAP is rebound to
                                           //   res.tap_name on every backend, so this flag never describes
                                           //   it. CH ✓ (restore config-rewrite moves host paths into the
                                           //   new scratch dir) · FC ✗ (re-binds the baked vsock UDS
                                           //   verbatim; its tap rides `network_overrides`, §2.3)
                                           //   · QEMU ✓ (restore rotates the host-global guest CID, §2.4)
                                           //   · crosvm ✗ (crosvm bakes+requires the vsock CID on restore
                                           //   — the FC pattern; reuses the baked CID, §2.5)
    pub disk_io_throttle: bool,            // per-drive I/O rate limit (§4.6): CH (rate_limiter_config),
                                           //   FC (rate_limiter), QEMU (throttling.*) ✓ · crosvm ✗
                                           //   (--block has no bandwidth/iops key) — rejects a throttled
                                           //   disk fail-loud; extra_block_io_throttle skips it (v29)
    pub usb_host_passthrough: bool,        // attach a host USB device via xhci + usb-host (§2.4, v30 §18
                                           //   delta 9): QEMU ✓ (opt-in live-validated) · CH ✗ (no
                                           //   upstream USB) · FC ✗ · crosvm ✗ (its xhci is not
                                           //   Suspendable; vmcell always passes --no-usb, §2.5) —
                                           //   non-supporting backends reject fail-loud, feature string
                                           //   == the field name. Deliberately NARROW (USB, not a generic
                                           //   host_device flag): the flag claims exactly what is
                                           //   validated; the flag+config+typed-refusal PATTERN is what
                                           //   generalizes to other device classes (the v28 delta-3
                                           //   naming lesson — the mem_limit_enforced rename, §7.1:
                                           //   narrow names for narrow claims)
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
    fn vsock_endpoint(&self) -> VsockEndpoint;          // default: Unix{vsock_path(), AGENT_VSOCK_PORT};
                                                        //   overridden by the AF_VSOCK backends (QEMU
                                                        //   in-kernel, crosvm) — the endpoint the control
                                                        //   plane and dial_vsock actually dial (§3.2)
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
host paths per restore can hand N *concurrent* clones distinct **vsock/serial** paths. (The tap is not in
that set: every backend rebinds it to `res.tap_name` on restore, so it never gates fan-out — §8.2.)
Reusing the existing capability (rather than a bespoke fan-out flag) keeps one source of truth for one fact.

### 2.2 Cloud Hypervisor — the default and the fully-featured snapshot tier

Feature-complete: snapshot/restore via `--restore`+`resume`, virtio-fs shares, vhost-user-net (so the
unprivileged NAT), and nested virt. Driven over a hand-written thin REST client (`hyper`/`hyperlocal` over
the Unix `--api-socket`); **every control RPC over the API socket is bounded at 5 s**, so a wedged VMM
control socket surfaces as a typed `Error::Timeout` before any outer readiness timeout can mask it. Cold
boot ≈305 ms; warm restore ≈53 ms (§16).

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
(≈27 ms p50, §16) despite a mid-pack cold boot (≈775 ms) — exactly the density/snapshot-tier role
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
  The declared contract is `restore_rotates_host_paths: false`, and its scope is **the vsock and serial
  host paths, not the tap**: a lineage's restores share one host vsock
  path, so `restore()` runs a fail-loud liveness guard (`reject_live_baked_vsock`, a 100 ms
  `UnixStream::connect` probe — a live listener is a typed `Error::Vmm` "still in use", never a silently
  unlinked live VM's socket; a stale file is removed; the TOCTOU window is documented as a misuse guard,
  not a security boundary). Concurrent restores from one lineage stay unsupported (§17). Third, `create()`
  attaches the entropy device (`PUT /entropy` → virtio-rng → guest `/dev/hwrng`) — without it the
  post-restore reseed reports `reseed_applied: false` and restored clones replay frozen CSPRNG state. The
  wired mechanism: a fresh process + `PUT /snapshot/load {resume_vm:false}` (restore returns paused, the
  caller resumes), `PATCH /vm` for pause/resume, and a `vmcell_host_paths.json` sidecar. Fourth — and the
  reason the flag's scope has to be stated — `restore()` sends a **`network_overrides`** entry on
  `PUT /snapshot/load` (FC 1.8+; validated on 1.16.0) rebinding the snapshotted interface to this
  restore's fresh tap. Without it FC re-binds the *baked* tap name, whose netns died with the ancestor:
  the VM restores clean, reports healthy, and has no data plane at all. The override is matched to the
  snapshotted device **by `iface_id`**, so the create path's `PUT /network-interfaces/<id>` and the
  override share one `FC_IFACE_ID` const — a mismatch is not an error, it is a silently ignored override
  that falls back to the baked name. The tapless shape is unaffected (the key is omitted). `lazy_restore`
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
≈991 ms.

QEMU reports `snapshot_restore: true`, earned **only** in the snapshot-eligible config. Its default
**unprivileged** external `vhost-device-vsock` daemon is a stateless vhost-user backend that cannot
migrate (the eligibility law, §8.1), so a `snapshotting` VM instead attaches the privileged **in-kernel
`vhost-vsock-pci`** device (`guest-cid=` on the device line) — QEMU 10.2 sets no migration blocker on it.
The selector is `VmConfig::vsock_transport` (`Auto | InKernel | ExternalDaemon`), routed through one
`uses_in_kernel_vsock` predicate — an **explicit, fail-loud** choice, never the silent daemon-to-in-kernel
fallback an earlier pass removed (the sin was the silence, not the device). `Auto` follows `snapshotting`
(the unprivileged default keeps the external daemon for a non-snapshot VM); `InKernel` lets a privileged
**non-snapshot** QEMU take the deterministic in-kernel transport, shedding the external daemon's ~11%
bring-up flake; `build()` rejects `snapshotting` + `ExternalDaemon` (a non-migratable vhost-user device
cannot back a snapshot). `snapshot()` drives QMP `stop` → `migrate file:<dir>/state.bin` → poll
`query-migrate` to `completed` (a `file:` URI, never `exec:`, which QEMU's `-sandbox …,spawn=deny` would
kill); `restore()` spawns a topology-congruent VM with `-incoming defer`, drives `migrate-incoming`, polls
to completion, and returns **paused** for the orchestrator to `resume()`. No sidecar is carried — the
migration stream (`state.bin`) is the whole snapshot; a pre-spawn `state.bin` existence check is the
fail-loud-before-spawn guard. The external-daemon config returns `Unsupported` from `snapshot()`/`restore()`.
Because the in-kernel device exposes the guest on the host **AF_VSOCK** namespace (not the daemon's AF_UNIX
bridge), the host agent client dials it by CID — the one place the control plane leaves the hybrid
`CONNECT/OK` handshake (§3.2). `restore_rotates_host_paths` is **`true`**: `restore()` programs a fresh
allocator-unique `res.guest_cid` on the destination device (the `guest-cid` is a device property, not part
of the migration stream), and the guest — which binds `VMADDR_CID_ANY:5000` — is reachable at the rotated
CID even though its cached CID lives in migrated RAM (validated live; the earlier same-CID-only audit is
superseded). Each concurrent clone thus holds its own host-global CID, so concurrent QEMU zygote fan-out is
supported (§8.4); the kernel's `VHOST_VSOCK_SET_GUEST_CID` `EADDRINUSE` at realize is the fail-loud backstop.
Wiring the unprivileged smoltcp NAT to QEMU still requires the carried vendored `vhost`/`vhost-user-backend`
patch (§9.6), orthogonal to the vsock snapshot path.

**Host-USB passthrough (v30, §18 delta 9 — FR-V5).** QEMU is the one backend whose upstream binary
attaches a host USB device, so it alone reports `usb_host_passthrough: true`. When
`VmConfig::usb_host_devices` is non-empty, the spawn appends one `-device qemu-xhci,id=vmcell-xhci`
plus, per device, `-device usb-host,vendorid=0x<vid>,productid=0x<pid>` — after the extra-disk block,
before `-kernel` (QEMU runs `-nodefaults`, so no controller exists unless vmcell adds one). The USB argv
assembly is a **pure, KVM-free-testable args helper** (the `build_crosvm_run_args` precedent — today
QEMU's argv is assembled inline in `spawn_qemu`, which is why crosvm's arg bugs were pinnable and QEMU's
would not be). Three host-environment facts are validated live before the flag is true, not assumed:
the QEMU process must be able to open the device's `/dev/bus/usb/BBB/DDD` node (the blessed-runner path
inherits ambient `CAP_DAC_OVERRIDE`; an unprivileged run depends on udev permissions and surfaces
QEMU's own fail-loud open error), the `-sandbox …,spawn=deny` Enforcing filter must tolerate usbfs
ioctls, and the jailer defaults must not strip the access — any conflict is resolved and recorded,
never met with a silent sandbox downgrade. `build()` rejects `snapshotting` + a USB device (a
passed-through device is not migratable), and every non-QEMU backend's `create()` refuses with a typed
`Error::Unsupported { vmm, feature: "usb_host_passthrough" }`. The opt-in gate's guest kernel is a
`vmlinux-usbhost` label built through the §5.6 toolkit from a **vmcell-owned generic host-controller
fragment** (xhci + USB core + the one class-smoke driver, and nothing else). Against the requester's
generality directive this is defended, not assumed: a capability flag must be live-validated (AGENTS.md
rule 5), live validation requires guest USB-host symbols, and this fragment is vmcell's own
capability-gate infrastructure — the IKCONFIG example-fragment precedent — carrying **none** of the
consumer-owned usbip/`vhci_hcd`/gadget/`dummy_hcd` closure the FR withdrew; it is also a recorded,
deliberate deviation from FR-V5's "downstream-built via FR-V1" phrasing (vmcell acting as its own
toolkit consumer for its own gate).

### 2.5 crosvm — the fourth backend (v29, boot-first)

crosvm is the ChromeOS Rust VMM, added in v29 as a fourth *secondary* backend (`vmcell-crosvm` crate,
§9.1) alongside Firecracker and QEMU. **Structurally it follows QEMU, not Firecracker**: it is configured
by a device model built on one `crosvm run` launch command line (not a post-spawn REST sequence), and its
control plane is a **side socket driven out-of-band** — but by *re-invoking the crosvm binary as a client*
(`crosvm resume|suspend|powerbtn|stop <socket>`), a third control shape (neither CH/FC's HTTP-over-Unix nor
QEMU's QMP-JSON). The socket wire protocol is unstable binary and is **never hand-rolled**, so the crate
carries no serde/JSON — the same "supervise an external binary, don't SDK-link it" discipline as QEMU/CH.

Lifecycle maps onto the trait as: `create()` launches `crosvm run --disable-sandbox --suspended --no-usb`
(devices + vCPUs frozen at launch — the create-then-boot split, mirroring QEMU `-S`); `boot()` issues
`crosvm resume --full` (wake devices **and** vCPUs — a plain `resume` wakes only vCPUs and crosvm errors
"Trying to wake Vcpus while Devices are asleep"); `pause()`/`resume()` are vCPU-only `crosvm
suspend`/`resume`; `request_shutdown()` issues `crosvm powerbtn` (ACPI, honored by the PID-1 agent);
`kill()` best-effort `crosvm stop` then SIGKILLs the process group. Three device/flag facts are
empirically load-bearing (each validated live, each a KVM-free arg-builder assertion): **`--disable-sandbox`**
(crosvm's own multiprocess minijail `pivot_root`s into `/var/empty` and forks per-device children,
incompatible with the single-process supervision model — see the seccomp posture below and §12.2);
**`--no-usb`** (crosvm attaches a legacy xhci USB controller by default which is not `Suspendable`, so the
`--suspended`→`resume` device-wake cycle panics on it); and **`resume --full`** (the full-suspend wake).
The rootfs is the first `--block` device (→ `/dev/vda`, what the shared cmdline's `root=/dev/vda` boots
from; crosvm's own `root=` auto-append is deliberately unused), extra disks follow in order, and networking
is a privileged `--net tap-name=…,mac=<mac_math(vmid)>`.

**vsock is in-kernel vhost-vsock on the host AF_VSOCK namespace** — like a snapshot-eligible QEMU, not the
AF_UNIX hybrid default — so `vsock_endpoint()` returns `VsockEndpoint::Vsock{cid, 5000}` and there is no
external vsock daemon to own. Validated live in the **privileged** mode; whether `/dev/vhost-vsock` is
reachable in the **unprivileged** (KVM-group) mode is still an open question (§17).

**Snapshot/restore — the Firecracker pattern, not QEMU's.** `snapshot()` full-suspends the VM (crosvm
requires all devices asleep to snapshot), runs `crosvm snapshot take <dir>/crosvm-snapshot <sock>`,
persists a CID sidecar, and resumes the source; `restore()` spawns `crosvm run --suspended --restore
<snap> …`, returns a paused instance, and the orchestrator's `resume()` issues the completing
`crosvm resume --full` (a `restored` one-shot flag, consumed only on success). The load-bearing empirical
finding: **crosvm bakes the vsock CID into the snapshot and rejects a rotated one on restore** ("Virtio
vsock incorrect cid for restore: Expected N, Actual M", validated live). So — unlike QEMU's rotating CID —
crosvm reuses the **baked** CID (carried in the `crosvm-host-cid.txt` sidecar, the AF_VSOCK analogue of
FC's `HOST_PATHS_SIDECAR`), and `restore_rotates_host_paths` is **false**: the vmid/MAC/IP still rotate to
`res.vmid` via the post-restore resync (§8.2), but the vsock CID does not, so restore-while-alive and
concurrent restores from one lineage are unsupported (the §17 single-snapshot-CoW gap — exactly FC's
constraint). The **one non-Suspendable device** is the default xhci USB controller, already dropped via
`--no-usb`; the block/net/vsock/serial set snapshots cleanly.

**All of crosvm's shipped path is VALIDATED live** — the full `vmm_matrix_test!` set (boot + agent-exec +
put_file, sessions, concurrency, extra-block, privileged egress/host-endpoint, metrics/cgroup limits,
**snapshot/restore + extra-block-survives-snapshot + fork/branch lineage**, and every `require_cap!` skip)
passes on a KVM host with a source-built crosvm via the opt-in `just test-crosvm` (§15.4); it stays out of
the default `test-privileged` because the binary is absent on CI. The remaining capabilities are
honest-`false`: `virtio_fs_shares` (crosvm has in-process `--shared-dir type=fs`, framed differently from
the external-vhost-user `config_has_vhost_user_device` law, unvalidated — `create()` rejects a share),
`unprivileged_vhost_user_net`, `lazy_restore`, `restore_rotates_host_paths` (baked CID, above), and
`disk_io_throttle` (crosvm's `--block` has no bandwidth/iops key, unlike CH/FC/QEMU — the divergence that
added the `disk_io_throttle` capability, §2.6; `create()` rejects a throttled disk fail-loud). `nested_virt`
is a **hard** documented-unsupported (no working guest `/dev/kvm`). Each `false` self-skips its matrix leg
via `require_cap!` (recorded to the skip manifest, never a silent green) and carries a KVM-free honesty pin.

### 2.6 The capability matrix

| Capability | CH | Firecracker | QEMU | crosvm *(v29, validated)* |
|---|---|---|---|---|
| `snapshot_restore` | **✓** | **✓** *(single-lineage host paths)* | **✓** *(in-kernel vhost-vsock + `migrate`/`-incoming`, §2.4)* | **✓** *(baked-CID reuse, FC-pattern, §2.5)* |
| `lazy_restore` (demand-paged) | ✓ | ✗ | ✗ | ✗ |
| `restore_rotates_host_paths` | ✓ *(enables concurrent zygote fan-out, §8.4)* | ✗ *(verbatim baked vsock path — single-lineage)* | ✓ *(restore rotates the host-global guest CID — concurrent fan-out, §2.4/§8.4)* | ✗ *(baked vsock CID reused — single-lineage, FC-like, §2.5)* |
| `virtio_fs_shares` | ✓ | ✗ (block-only) | ✓ | ✗ *(has `--shared-dir`; unvalidated)* |
| `unprivileged_vhost_user_net` | ✓ | ✗ | ✓ | ✗ *(unvalidated)* |
| `nested_virt` | ✓ | ✗ | ✓ | ✗ *(documented-unsupported)* |
| `virtio_console` | ✓ | ✗ *(rejected fail-loud before the cmdline is built)* | ✓ | ✓ |
| `disk_io_throttle` (per-drive I/O limit, §4.6) | ✓ *(`rate_limiter_config`)* | ✓ *(`rate_limiter`)* | ✓ *(`throttling.*`)* | ✗ *(no `--block` bandwidth/iops key — rejects fail-loud, v29)* |
| `usb_host_passthrough` (xhci + usb-host, §2.4, v30) | ✗ *(no upstream USB)* | ✗ | ✓ *(opt-in live-validated, §18 delta 9)* | ✗ *(xhci not `Suspendable` — always `--no-usb`, §2.5)* |
| cold boot (p50, §16) | ≈305 ms | ≈775 ms | ≈991 ms | ≈1413 ms *(the most consistent — no flake tail)* |
| warm restore (p50, §16) | ≈53 ms | ≈27 ms | ≈475 ms *(full-memory migrate stream)* | ≈76 ms *(sparse snapshot)* |

The cold-boot/restore inversion pins each backend's role: CH is the feature-complete default, cold-boot
leader, and fully-featured snapshot tier; Firecracker cold-boots slower than CH but restores fastest,
earning the density tier; QEMU is the slowest restorer (its restore streams the full memory image via
`migrate-incoming`), the fallback for the awkward cases, and the most-proven nester; crosvm (v29) is the
slowest cold-booter but the most *consistent* (in-kernel vsock, no external-daemon flake) with a fast
sub-100 ms sparse-snapshot restore — the flake-averse single-lineage tier.
The orchestrator reads roles off `capabilities()`; the test/bench matrix **skips — never fails** — a
scenario a backend can't run (§15.4).

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
kernel panic (fail fast). The common transport is a host AF_UNIX socket with the Firecracker-style
hybrid-vsock handshake (the host writes `CONNECT <port>\n`, expects `OK <port>\n`) — CH, Firecracker, and
QEMU's default external `vhost-device-vsock` daemon. A snapshot-eligible QEMU on the in-kernel
`vhost-vsock` transport (§2.4) is the one exception: the host dials the guest directly on the **AF_VSOCK**
namespace by CID, with no bridge and thus no `CONNECT/OK` prologue (the guest's first frame is already
`Ready`). Each `VmInstance` reports a `VsockEndpoint` (`Unix{path,port}` or `Vsock{cid,port}`) that selects
the connect branch through the **one** `connect_framed` law; the framed protocol after `Ready` is
byte-identical, so a single concrete `ControlStream` enum keeps `AgentClient`/`SessionMux` non-generic.
**Three traps live at this interface** — each presents as "a mysterious timeout" (law C2):

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
registry (`SessionExit` also closes that session's channel). The registry is **closable**, and the
reader's terminal step closes it: `open()` then checks-closed and inserts in one critical section, so a
session opened after the reader has gone is a typed `Error::Agent`, not a handle whose `recv()` waits
forever for a router that no longer exists. Writes from all `Session` handles + the mux
go through one `Arc<Mutex<SplitSink>>` — the host mirror of the guest's single-writer discipline (law C4).
Dropping the `SessionMux` closes the connection, which the guest observes as the read-loop end that
triggers connection-owns-its-sessions teardown (law C3) — so a host that forgets to `close()` still cannot
leak guest processes. Per-session queues are **unbounded** and fed only by the *trusted host's own*
sessions (the guest is the sandboxed workload; the host chose to open and must drain each session) — a
deliberate, recorded trade (§17), not the untrusted-server-accumulation class the rubric flags.

`MicroVm::connect_sessions(...) -> Result<SessionMux>` is the ergonomic entry: it dials a second
control-plane connection on the same VM, and refuses fail-loud with the control-plane-disabled
`Error::Agent` when a custom `init=` has replaced the agent (§5.3), exactly as `agent()` does.

**Raw vsock dial (v30, §18 delta 7 — FR-V3).** `MicroVm::dial_vsock(port, timeout)` opens a plain
byte stream to an arbitrary guest vsock port — the guest process on the other end owns its own
protocol; no framing, no `Ready`, no agent involvement:

```rust
impl<V: Vmm> MicroVm<V> {
    /// Dials a raw byte stream to a guest AF_VSOCK listener on `port`. Independent of the guest
    /// agent: works under a custom `init=` (the control-plane guard does not apply — the vsock
    /// DEVICE is attached unconditionally on every backend; only the agent is absent).
    pub async fn dial_vsock(&self, port: u32, timeout: Duration) -> Result<VsockDial>;
}
pub struct VsockDial(/* the crate's ControlStream */);  // AsyncRead + AsyncWrite; public newtype so
                                                        // ControlStream stays pub(crate) and non-generic
```

Reuse discipline: the endpoint comes from `instance.vsock_endpoint()` with the port overridden, the
socket-open goes through the existing `connect_control_stream`, the transport dispatch through the
existing `hybrid_prologue_port` — and the fragile `CONNECT <port>`/`OK` prologue, today **inline in
`connect_framed`**, is **extracted into one function** the framed connect and the raw dial share, so the
handshake keeps exactly one implementation (the same one-law refactor that produced `connect_framed`
when `SessionMux` arrived; the extraction also fixes the recorded no-backoff busy-retry on a failed
`CONNECT` write). What the raw dial deliberately does **not** reuse is `connect_framed`'s
retry-until-deadline loop: that loop exists to outwait a *booting agent* and folds "nobody listens" into
a terminal `Error::Timeout`, whereas `dial_vsock` is called against a VM the caller already brought up,
so it **interprets the transport's refusal signals** and fails fast typed — the CH/FC in-VMM muxer
closes the hybrid stream without an `OK` line (EOF ⇒ a typed no-listener `Error::Agent` naming the
port), an AF_VSOCK endpoint (QEMU in-kernel, crosvm — dial by `guest_cid()`) surfaces the kernel's
connect error, and QEMU's external daemon, which accepts a `CONNECT` and never answers a dead port, runs
out the bounded per-byte read (`Timeouts::connect_ok_read`) into a typed timeout naming the port.

**Half-close does not forward on every backend.** EOF in the *guest→host* direction is portable — the
host sees EOF when the guest half-closes or exits, on all four. The reverse is a property of each
backend's vsock bridge, not of the dial; measured 2026-08-11 on the live matrix, five connections per
backend (write a request, `shutdown()`, drain the guest's echo):

| backend | host-side transport | reply after the host's `shutdown()` |
| --- | --- | --- |
| Cloud Hypervisor | in-VMM hybrid muxer over AF_UNIX | arrives — 5/5 |
| crosvm | in-kernel AF_VSOCK, no bridge | arrives — 5/5 |
| Firecracker | in-VMM hybrid muxer over AF_UNIX | **discarded — 0/5** |
| QEMU | external `vhost-device-vsock` daemon over AF_UNIX | **races the teardown — 2/5** |

On FC and QEMU the host's `SHUT_WR` on the bridge socket becomes a teardown of the whole vsock
connection, dropping whatever the guest had not yet flushed, and the loss is **silent**: the host's next
read returns `Ok(0)`, an ordinary clean EOF. The portable rule the `VsockDial` rustdoc carries (with this
table, dated and version-anchored): treat `shutdown()` as end-of-conversation, never as an in-band
"your turn" signal; frame the guest protocol so a reply's end is knowable without an EOF (length prefix,
delimiter, fixed size), drain it, and only then half-close. This is **not** a `VmmCapabilities` field
(§7.2): no operation refuses on it, and the drain-first order works identically on all four, so no
caller is forced to branch — the flag would ship only for a caller that must branch programmatically.
The matrix leg asserts the portable order; the two backends where half-close *does* forward are pinned
positively by `dial_vsock_host_half_close_forwards_on_cloud_hypervisor` / `…_on_crosvm`.

Two documented caveats: a *user* listener gets no
post-restore re-bind service — only the agent re-binds after a restore re-creates the vhost-vsock
device (§3.4), so dial afresh after a restore; and on the non-rotating backends (FC, crosvm) the
endpoint is the baked path/CID (§2.6), exactly as the agent connect already handles. The in-guest test
listener is a new `echo-server` guest-tools applet (`--vsock <port>` / `--tcp <addr:port>` — one applet
also serving the §6.5 segment gates), a real listener baked into the erofs like the other applets
(§4.4); adding it touches `rootfs_injection_manifest` *and* its pin test — the warm-cache rootfs makes
a missed injection invisible, twice shipped as exactly that regression.

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
  - `Stdin{id, data}` → look up the handle and **queue** the bytes to that session's own **stdin writer
    thread**, then keep reading. The queue is unbounded (fed only by the trusted host's own sessions — the
    recorded trade, §17), so the `send` never blocks. The blocking write must not happen here: written
    inline, a child that stopped reading its stdin filled the 64 KiB pipe and parked the *whole
    connection*, so `CloseSession` was never dispatched and, on host disconnect, the dispatch loop never
    returned — `teardown_sessions` never ran and the child outlived its connection, breaking law C3 at the
    one moment it matters. The writer thread writes in `PIPE_BUF`-sized chunks after `poll`, re-checking a
    `stdin_closing` flag every 100 ms so teardown's join is bounded even against a child that never
    drains. A closed/unknown id is dropped at `debug` (the session already ended), never a desync.
  - `StdinEof{id}` → travels through the **same queue** as the bytes, so a pipe session's write end closes
    only after everything queued ahead of it is written (an out-of-band close truncates the child's
    input). A no-op for a PTY session (closing the master would tear down output; a PTY caller ends input
    with an in-band EOT or `CloseSession` — a half-closed-input refinement is §17).
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
rootfs variant existed with no consumer and was removed by the v28 pass (its delta 5 — landed;
implementation-notes.md records it was more woven than the delta's premise claimed).

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

**Bring-your-own base image.** `vmcell oci2-erofs IMAGE@sha256:DIGEST -o rootfs.erofs` runs the same
pipeline against any digest-pinned base image. Two honest constraints, enforced *by the packer* so every
source gets them for free: it **scans the merged tar for `libc.so.6` and fails loud before packing** if
absent (a `libc6`-less base would boot to a dead PID 1 if the agent were dynamically linked), and a
static-`musl` agent for non-glibc bases is an explicit `--agent-musl` opt-in, never a silent fallback.

**Downstream extra files (v30, §18 delta 6 — FR-V4).** A caller composes its own content into the image
at pack time — daemons, CLIs, test fixtures — so the image stays the artifact and per-boot `put_file`
pushes disappear from the hot path:

```rust
pub struct ExtraFile { pub dest: String, pub src: PathBuf, pub mode: u32 }  // regular files only (v1)
// vmcell oci2-erofs … --inject dest=/usr/local/bin/acme-daemon,src=./acme,mode=0755   (repeatable)
```

The parameter threads through the **one** inject+pack tail — `pack_erofs_with_injection` gains
`extra: &[ExtraFile]` — so both rootfs sources (and any third-party `Stage`, §4.3) get it identically;
the CLI flag reaches it as a new `RootfsStage` field (the CLI is not a direct packer caller — it
assembles a `Pipeline`). Semantics, in the packer's own terms: extra files are inserted into the merged
tree **after** the layer merge (like vmcell's own injections, they win base-image collisions and
whiteouts — deliberate composition) and **before** the unconditional vmcell injections. Today the
injection tail has *no* collision handling at all (`entries.insert` is last-wins, and an injected
symlink would silently clobber a same-dest injected file); extra files make that unacceptable, so the
tail gains one predicate — **`is_reserved_injection_path(dest)`**, listing exactly the vmcell-owned
dests (`usr/sbin/vmcell-guest-agent`, the two CA trust-store paths, `vmcell-tools/` and everything
under it) — and a dest that hits it, or duplicates another extra file, is a build-time
`Error::Artifact`, never a silent overwrite (one law; the vmcell injections stay unconditional and
authoritative). Validation: `dest` absolute, UTF-8, no trailing slash; `mode` is honored **explicitly**
(extra files do not inherit the `injected_file_mode` bin/sbin heuristic — the caller said what they
meant); missing parents are synthesized `0o755 root:root` exactly as the packer already does; uid/gid 0,
mtime 0 (the deterministic-emission discipline, §10.3). Symlinks and xattrs stay out of v1 — consistent
with the recorded PAX-xattr limitation — and the whole tail buffers in memory, so very large extra
files cost peak RSS (recorded; the alternative for bulk data remains an extra virtio-blk image, §4.6).
**Cache identity:** `fold_rootfs_injection_identity` folds each extra file as
`(dest, mode, content-hash)` in sorted-dest order — content that travels, never the `src` path (F4 rule
3) — and both source stages bump their `STAGE_VERSION` (the recorded v20 precedent: an identity-fold
change without the bump serves stale images). Gates: KVM-free injection-layer tests (files + modes
present in the merged tree; reserved-dest and duplicate-dest reject red-on-inverse; the `--inject`
parser), a cache-key test (content change re-packs), and a live matrix leg that boots an image with an
injected marker and `cat`s + `stat`s it back **in-guest** before the first exec — the data-plane form of
FR-V4's acceptance criteria.

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
   skip the CA and silently break the handshake or the guest trust chain. The `libc6` scan, the
   `--agent-musl` opt-in, and the downstream extra-files parameter with its reserved-path collision
   guard (v30, §4.2) apply to every source for free.

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
- `curl` — real HTTP/HTTPS via `reqwest`, honoring proxy env vars and
  `-k`/`-L`/`--resolve`/`--max-time`/`-H`/`-X`/`-o`/`-w`/`-d`/`--data-binary`. Exit
  codes are curl-faithful: only a 2xx tunnel establishment counts as `CONNECT` success; a blocked domain's
  403 is printed the way curl prints it (status to stderr, body to stdout) but exits non-zero; a transport
  failure exits 7 (`CURLE_COULDNT_CONNECT`) with the full error source chain on stderr — never an "any
  proxy response → exit 0" probe. Its pure parsers (and its ifreq layout) are unit-tested. **It is not GNU
  curl and the rootfs carries none**, so law F1 applies to it exactly as to a config field: every accepted
  flag is honored or rejected at parse time — an unknown option, an unparseable `--max-time`, a
  malformed `-H`/`--resolve`, an unsupported `--write-out` variable, a flag missing its value all fail
  loud naming the flag. Silently ignoring `--data-binary`/`-w`/`-o` is what let a test "upload" nothing
  and still pass.
- `kvm-ok` — a real `/dev/kvm` probe for the nested-virt test.
- `echo-server` — the real listener the dial and segment gates need: `--vsock <port>` or
  `--tcp <addr>:<port>`, echoing until EOF (§3.2/§6.5). Its accept loop paces retries and caps its
  logging, because PID 1 cannot exit and its stdout *is* the persisted serial console.

Two properties keep it honest. It performs the **real** operations (genuine HTTP, real `/dev/kvm`, real
procfs reads), so it is not a weakening of any assertion. And it is **baked into the erofs**, not
delivered over a share: `virtiofsd` cannot enter its sandbox namespace without privilege, so a share would
fail in the *unprivileged* suite, while the erofs root is served over virtio-blk in both modes. A
`GuestToolsStage` builds the helper and the packer injects it with one symlink per applet — the
`APPLETS` table and `rootfs_injection_manifest` are checked against each other, because a one-sided
edit means a custom-`init=` boot exits 2 and panics the guest kernel; the agent prepends its dir to
the exec `PATH`. The rootfs cache key folds the helper's content, so a helper
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
direct-boot PVH `vmlinux`. **The in-VM producer is reachable only through `build-kernels`**: it boots a
builder micro-VM, which needs an already-working `vmlinux` published under the `kernel` artifact key, and
`vmcell build` cannot stage that seed ahead of it — the unlabelled `InVmKernelStage` answers `name()`
with `kernel` and `out_path()` with `vmlinux`, exactly the pair `PrebuiltKernelStage` uses, so the two
would share one `vmlinux.cache_key` sidecar and overwrite each other's key every run, making every build
miss cache and re-run the up-to-2-hour compile. So `vmcell build --kernel-source in-vm` is a **typed
refusal naming `build-kernels`**, not a copy of its seed staging: the obvious fix is the wrong one. The
refusal is the first statement of pipeline assembly (nothing is printed, allocated, or downloaded before
the flag is honored or rejected) rather than a clap-level rejection, so it is the matchable
`Error::Unsupported` every other CLI refusal is instead of an exit-2 usage error.

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
                                          # segment members instead get 10.201.<s>.<k+1>, gateway .1,
                                          # mask /24, derived from res.segment (v30, §6.5)
kvm-intel.nested=0 kvm-amd.nested=0   # ALWAYS emitted in both directions (=1/=1 when nested_virt)
vmcell_share=<tag>:<guest_path>:<ro|rw>   # one per share (§4.5)
vmcell_accept_poll_ms=20 vmcell_rebind_idle_ms=250   # from the Timeouts profile (§9.4)
```

A single shared `config::build_kernel_cmdline` emits this for every backend (crosvm's `create` calls it
too, §2.5) — the prior per-backend inline copies diverged (QEMU's had dropped `loglevel=` entirely, a
≈1400→~1000 ms QEMU cold-boot bug,
§16). Ordering and conditionals are load-bearing: `rootflags=noload` is auto-emitted only for the `Block`
rootfs; Firecracker inserts its `noxsave` fallback (when no T2 CPU template is available) right before
`init=`; and the nested tokens are emitted **explicitly in both directions** — `=0` on false, not omitted
— because `-cpu host` exposes VMX unconditionally and a modern kernel defaults `nested=Y`, so omitting on
false would silently leave nesting on.

`loglevel=6` keeps the serial console attached for panic capture (`contains_panic` matches the literal
panic markers — `Kernel panic`, `panicked at`, `panic - not syncing` — not log-level prefixes; the
"KERN_EMERG lines" phrasing earlier revisions carried was drift) and boot diagnostics while dropping the
voluminous `KERN_INFO` device-probe output that otherwise
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

A config-variant kernel is requested as **(base label, a set of named KConfig fragments)** — e.g.
`6.12.94 + [KASAN, LOCKDEP]` — with the pins registry mapping each fragment name to a KConfig string
(`kernel_fragments.<NAME>`) and, as of v30 (§18 delta 3), each `kernels.<label>` entry optionally
declaring `fragments: [<NAME>, …]` so the label alone fully determines the build — previously the
fragment set was reachable only by constructing a `KernelStage` programmatically (`build-kernels` always
passed `fragments: None`, an undocumented dead end §5.6 closes). Fragments are canonicalized to
**sorted order** at hash time (so `[KASAN, LOCKDEP]` and `[LOCKDEP, KASAN]` resolve to the same
artifact); a fragment named but absent from the registry is a hard `Error::Artifact` in `run()` **and
folds a distinct missing-fragment marker in `cache_key()`** (previously it folded empty bytes, letting
two stages that differ only in an unresolvable fragment share a key until `run()` failed); a non-zero
`make olddefconfig` is a fail-loud `Error::Artifact`; labels build in **sorted label order** — today the
order is sorted only as an unpinned artifact of serde_json's default `BTreeMap` backing (a transitive
dep enabling `preserve_order` would silently change it), so the delta makes it explicit and pins it;
and the build-time blow-up (a
cold KASAN build is ~45–90 min) is bounded by the content-addressed cache — CI batches by label and runs
the full matrix nightly. PREEMPT_RT is *not* a fragment (it needs an rt-patched source — a separate
registry source), and KCOV *extraction* needs guest tooling (§17); the fragment only turns the kernel
capability on.

### 5.6 The downstream kernel toolkit (v30 — FR-V1, the P-blocking request)

vmcell's first out-of-repo consumer permanently owns a guest-kernel config fragment in *its* repo and
needs to build **and validate** kernels carrying it — with zero vmcell-source edits, no fork of
`pins.json`, and no reliance on unpromised surface. The toolkit is the kernel-side analogue of an
out-of-repo codec kit: vmcell ships the *mechanism* (build entry points, the conformance battery, the
contract), never the fragment (law G1; the requester's own generality directive). It is assembled almost
entirely from parts that already exist — the labelled-kernel registry (§5.5), the public
`Stage`/`Pipeline`/`ResolvePinsStage` (§10.2), and the `vmcell-artifact-validator` battery (§9.1) — and
what v30 adds is the four pieces that made the existing path *semi-public in practice*:

**Build (§18 deltas 1, 3).** A downstream workspace extends the pins registry through the **overlay**
(`VMCELL_PINS`, §10.2) — adding its own `kernel_fragments.<NAME>` entries (flattened pin key:
`kernel_fragments_<NAME>`) and a `kernels.<label>` entry carrying **all three** of `source_url`,
`source_sha256` and `fragments: [<NAME>, …]` (a fragments-only entry is a legal registry entry — it
declares the label for enumeration — but carries no source to build from, so `KernelStage::run`
refuses it fail-loud naming the two **overlay** keys to add, `kernels.<label>.source_url` and
`kernels.<label>.source_sha256`; the flattened `kernel_<label>_source_url` spelling names no key a
pins document may carry, and pasting it into an overlay is rejected by the top-level namespace check
§10.2 describes) — and
builds `vmlinux-<label>` into its own
`VMCELL_ARTIFACTS_DIR` via either entry point: the CLI (`vmcell build-kernels --pins <file>`, from a
vmcell checkout) or, from the consumer's own harness, the library
(`vmcell::artifact::build_labelled_kernel(label, target_dir, overlay_file)` — a thin assembler of
`ResolvePinsStage → KernelStage` that any git-dep workspace can call. Its producer scope is the
host-`make` one, the only compiling producer `vmcell` can name: `InVmKernelStage` lives in
`vmcell-kernel-builder`, which depends on `vmcell`, so naming it here would invert that edge and break
§9.1's acyclicity — the in-VM producer stays reachable through the composition root
(`vmcell build-kernels --kernel-source in-vm`). With no in-VM producer there is no `CidAllocator` to
inject, so the parameter is not a `&HostEnv` carrying nothing but the explicit `target_dir` +
`overlay_file` (the latter resolving explicit-path-else-`$VMCELL_PINS`). It deliberately
does **not** ride `ensure_test_artifacts`, which is the vmcell-workspace test bootstrap and structurally
cannot run downstream — its fingerprint hashes the guest-agent *source closure* out of the vmcell
workspace tree, §10.2). The default kernel is byte-unchanged for consumers that do not opt in. Two fail-louds
the pre-v30 tree lacked: requesting a label or fragments with `--kernel-source prebuilt` is a typed
error (it used to drop both silently and hand back the default seed), and a labelled build reports
which producer it used.

**The resolved config is an artifact (§18 delta 3).** `make olddefconfig` silently drops any symbol
whose dependencies are unmet — the classic way a fragment author ships a kernel that quietly lacks the
one symbol they added. So every *compiling* producer (host-`make` `KernelStage`, `InVmKernelStage`)
copies the post-`olddefconfig` `.config` out beside the kernel as **`vmlinux-<label>.config`**,
content-addressed with it (the in-VM builder ships it back on the output share; today both producers
discard it). A fragment author asserts against the *result*, not the fragment, using the tiny pure
parser the validator crate gains (`KconfigValues::parse(&str)` → tristate lookup — mechanism, so the
assertion itself stays downstream). The prebuilt bootstrap seed has no config to copy and ships none —
recorded honestly; the seed is a bootstrap producer, not a fragment consumer (§5.4).

**Validate (§18 delta 4).** The conformance battery already exists and already takes explicit paths:
`vmcell_artifact_validator::validate(&ArtifactSet { kernel, rootfs }, &ValidationOptions)` runs the
named checks (`boot.kernel_banner`, `boot.agent_ready`, `agent.exec_roundtrip`, … at `Core`, plus the
capability-gated `Extended`/`Full` tiers) and refuses to return a green all-skipped report on a
KVM-less host. v30 promotes it to contract surface (§10.4) and closes its one FR-relevant gap:
**failure classification**. A kernel missing a baseline symbol used to fail `boot.kernel_banner` or
`boot.agent_ready` with a raw serial tail; the `classify` module maps the console onto the §5.4 clause
it breaks. `classify_serial(&str) -> Option<ContractViolation>` keys on **the emitters' real text**,
never on a mnemonic — the four `#[non_exhaustive]` variants are `RootDeviceMissing`, `RootFsMount`,
`VsockTransport` and `NoDirectBootKernel`, each carrying `clause()` (the §5.4 prose) and `symbols()`
(the unconditionally-`=y` `CONFIG_*` set). Two signature corrections are load-bearing and were found
only by reading what the emitters print: `VFS: Unable to mount root fs` is the **shared** panic of a
missing root *device* and a missing root *filesystem*, so `ROOT_DEVICE_SIGNATURES` (which also prints
`VFS: Cannot open root device`) is checked **first** and gets the virtio symbol set — otherwise a
kernel built without `CONFIG_VIRTIO_BLK` is told to fix its erofs decompressor; and the vsock clause
keys on the guest agent's own PID-1 lines (its boot self-check and its bind failure), because
`EAFNOSUPPORT` reaches no serial log and the rendered errno prose also appears on an unrelated
`AF_INET` failure. Rendering is **two** functions, chosen by whether console evidence exists — never by
convenience: `explain_boot_failure(log, base)` when the console was captured (an empty capture is
itself evidence: the VM ran and printed nothing ⇒ `NoDirectBootKernel`), and
`explain_without_serial(base, why)` when there is none, which names candidate causes and keeps the
§5.4 pointer instead of asserting a clause the evidence does not support. `checks` routes every arm
reporting a failed `MicroVm::start` or a failed agent handshake through one of the two — three wiring
points, not one, because a bad kernel fails in three shapes (a garbage file → `Error::VmmApi` at
`vm.boot`, no timeout and no log; boots-but-silent → the banner budget expiring; boots-then-panics →
`contains_panic` surfacing fast on the handshake arm). `missing_symbols(violation, &KconfigValues)`
is the honest other half: the console says which clause broke, delta 3's resolved-config sidecar says
which symbol `make olddefconfig` dropped, tested with `is_builtin` because `=m` is as broken as absent
in a guest with no early userspace. The classifier is pure and red-on-inverse-tested on canned logs,
and `validate()` against a garbage kernel file stays the cheap live red path the smoke test exercises.
A boot failure it does *not* recognize still reports the named check, what expired, and the serial tail
with a pointer to the §5.4 contract checklist — the residual class fails named-and-loud too, and a
newly-understood signature grows the classifier, never the timeout path. `await_kernel_banner(path,
budget)` computes one `tokio::time::Instant` deadline and bounds its whole loop (which is also what
makes its failure path unit-drivable on a 50 ms budget); the agent budgets are `Duration`s that
`connect_framed` turns into an `Instant` one layer down. There is deliberately **no overall wall-clock
budget on `validate()`** — a `Full` run boots several VMs sequentially — so "fails loudly, not by
hanging" holds per check, not per battery (§17).

**Kept honest by an out-of-tree example (§18 delta 5).** The pattern's proof is a small example
workspace, **`examples/downstream-kernel/`** — its own Cargo workspace, deliberately *outside* the
vmcell workspace, consuming `vmcell` + `vmcell-artifact-validator` the way a git-dep consumer does —
that carries its own pins overlay and its own deliberately *non-consumer* fragment
(`CONFIG_IKCONFIG=y` + `CONFIG_IKCONFIG_PROC=y`), builds `vmlinux-ikconfig` through the toolkit, asserts
its symbols survived in the resolved-config sidecar, runs the validation battery, and proves the
fragment took effect **on the data plane**: the booted guest has `/proc/config.gz` (a file that exists
*only* if the fragment survived) and its content round-trips the very config the sidecar recorded. CI
builds and runs it on every push (the KVM leg on the self-hosted KVM runner, §15.4) — the toolkit
contract cannot silently drift because its consumer-shaped user is in CI. The fragment choice is the
point: self-proving, tiny, and owned by vmcell as *example mechanism*, not consumer content.

What the toolkit deliberately does not do, with the FR's own concurrence: no **modules** pipeline
(fragments build everything `=y`; a modules + rootfs-module-tree work item is out of scope and
recorded), and no vmcell-shipped consumer fragments (withdrawn by the requester under the generality
directive — the example fragment above is the mechanism's own proof, not a capability).

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
function (backed by an injectable `OrphanScanner`, reaping only non-live vmids — and, v30, non-live
segids for the `-seg-` class (§6.5) — in netns → cgroup → scratch order) cleans these; a fully-automatic periodic sweeper is forward work (§17), though the daemon closes
its own crash-restart case (§11.4).

### 6.2 `NetConfig` and the two datapaths

```rust
#[non_exhaustive]
pub enum NetConfig {
    Privileged   { egress: Egress },                                  // netns + tap + /30 (CAP_NET_ADMIN)
    Unprivileged { egress: Egress, host_services_port: Option<u16> }, // in-process smoltcp NAT (no caps)
    Segment      { segment: NetSegmentRef },                          // shared L2 bridge domain (v30, §6.5)
    None,
}
pub enum Egress { Filtered(ProxyConfig), Blocked, Open }
```

`Segment` (v30, §18 delta 8 — FR-V2) joins the VM to a shared bridge domain (§6.5). It deliberately
carries **no `egress` field and no `host_services_port`** — a segment VM's connectivity is
segment-internal by definition in v30, so the invalid states (a MITM proxy or a NAT forward on a
segment member) are unrepresentable rather than validated, the same move the v28 pass's delta 4 made
for `host_services_port` (per-segment filtered egress is recorded forward work, §17). One structural
caveat the implementer must not miss: `NetConfig` is `#[non_exhaustive]`, so the out-of-tree backends
match it with wildcard arms and a new variant is **not** a compile error there — the fail-loud channel
is `PerVmResources` (deliberately exhaustive): segment membership travels as a new `res.segment` field,
which every backend must acknowledge to compile. The tap-vs-NAT question is answered on **two channels
held in lockstep**, not one: `net_uses_tap(&NetConfig)` (`Privileged | Segment`) is the
orchestrator/config-side predicate — exhaustive in-crate, so a new variant is a compile error there —
while every backend keys its device wiring on `res.tap_name.is_some()`, the stronger signal, and never
looks at `cfg.net`. That is why a `Segment` variant populating `res.tap_name`/`res.netns_name` took the
identical tap arm with zero backend edits. Giving `build_ch_net(res)` a `cfg` it does not need would
move the decision from the exhaustive-struct channel onto a weaker one, so instead the two are joined
by a fail-loud post-condition run once in `setup_env`: `assert_tap_wiring_matches(net, tap_present)`
makes a datapath that claims a tap and was handed none — or the reverse — an `Error::Network` at
construction, not a guest with an unconfigurable `eth0` (§6.5).

`host_services_port` lives **only on the `Unprivileged` variant** — the smoltcp NAT must know *which* host
port to register as a permanent forward-port, and it is the only datapath that implements the feature, so
the invalid state (a privileged config carrying the field) is unrepresentable. (It was previously a field
on both variants, rejected at `build()` on the privileged one, itself a fail-loud replacement for a prior
silent no-op; the v28 pass's delta 4 — landed — moved the field so the compiler enforces what the
validator did. Wiring host
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
Exp 4; the earlier "passt is CH-incompatible via seccomp" reason was wrong — it was a host AppArmor
af_unix rule, not passt's seccomp, and not CH-specific).

**The NAT's six silent-wedge invariants.** The NAT works only if six invariants hold, and each one
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
6. The mirror rule on the **guest→host** half: the drain consumes only the **contiguous** span smoltcp's
   `recv` closure offers. The two APIs disagree on purpose — `peek_slice` copies *across* the RX ring's
   wrap and reports the whole queued length, while the `recv` closure's return value feeds
   `dequeue_many_with`, which **asserts** the count fits the contiguous span. Pairing them (peek the full
   length, then return it as consumed) panics `run_network` the moment a stream wraps the ring, i.e. on
   any sustained upload past the ring size — and the panic is silent in the worst way: the vhost thread
   keeps the device attached, so the guest sees a live link that never drains. The write therefore happens
   **inside** the `recv` closure, over the slice it was handed, which makes `consumed <= span` true by
   construction and leaves the wrapped remainder queued for the next tick. Two gates:
   `guest_to_host_drain_consumes_only_the_contiguous_span` (KVM-free, driven through a real
   wrap-positioned smoltcp ring) and the live `nat_window_fill_upload` (a 1 MiB guest→host upload against
   a backpressuring host sink, digest-compared).

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

### 6.5 VM-to-VM segments (`NetSegment`) — v30, §18 delta 8 (FR-V2)

Until v30, two vmcell VMs could not reach each other at all: each privileged VM sits alone in its own
netns on an isolated `/30`, and neither egress datapath re-originates toward another guest. A
**segment** is the opt-in shared L2 domain that changes that — the mechanism behind a two-kernel
client/server test, a small cluster topology, or fault-injected link testing between real guests. It is
privileged-capability-class only (the same three caps, probed fail-loud via `HostCapabilities`), and it
deliberately reuses the existing tap machinery — a segment is *where the taps live*, not a new
datapath:

```rust
// vmcell::net::segment
pub struct NetSegment(/* Arc<SegmentInner> */);       // cheap-clone handle; RAII (below)
pub type NetSegmentRef = NetSegment;                  // what NetConfig::Segment carries
impl NetSegment {
    /// Creates the segment: allocates a segment id, creates netns `<prefix>-seg-<segid>` holding
    /// bridge `<prefix>-br-<segid>` with the gateway address, ready for members. `prefix` goes
    /// through the SAME single validator `VmConfig::build()` uses (`validate_resource_prefix` —
    /// one law; the F2 lockstep and IFNAMSIZ safety rest on it), rejected fail-loud.
    pub fn new(prefix: &str, env: &HostEnv) -> Result<NetSegment>;
    pub fn netns_path(&self) -> PathBuf;              // for a harness's own tooling (e.g. `tc netem`)
    pub fn bridge_name(&self) -> &str;
    pub fn gateway(&self) -> Ipv4Addr;                // 10.201.<s>.1 — the host side of the bridge
    /// Dials a TCP listener inside a member guest from the host (FR-V3's privileged shape): the
    /// socket is created on a dedicated thread INSIDE the segment netns — the §6.4 capture-root →
    /// setns → socket → re-enter-root pattern — because a socket's netns is fixed at socket() time.
    /// Bounded, typed refusal; never a hang.
    pub async fn dial_tcp(&self, addr: SocketAddrV4, timeout: Duration) -> Result<TcpStream>;
}
```

**Mechanism.** One **netns per segment** holding one Linux **bridge** (rtnetlink 0.21's typed
`LinkBridge` builder — the first bridge in the tree, same `Netlink` seam, same dedicated-thread runtime
discipline as the tap path). A member VM gets **no per-VM netns**: its tap (still `<prefix>-tap-<vmid>`,
still `TUNSETPERSIST`'d and opened only by the VMM) is created in the *segment* netns and enslaved to
the bridge, and the VMM child `setns`es into the segment netns through the exact `build_vmm_cmd`
pre-exec path the per-VM netns uses — a different netns *name*, zero new spawn logic; each backend
keys its device wiring on `res.tap_name`, kept in lockstep with the config-side `net_uses_tap(cfg)`
predicate by `assert_tap_wiring_matches` (§6.2), so `Privileged` and `Segment` take the identical tap
arm with no backend edit. Isolation between
segments, and between a segment and the per-VM `/30`s, is the netns boundary itself: a third VM off the
segment has no route, no interface, and no namespace in common with it (the negative-control gate).

**Addressing — one pure function, a disjoint range.** Members share one `/24`:
`10.201.<s>.0/24` with `s = (segid % 254) + 1` — deliberately a different `/16` from the per-VM
`10.200.<n>.0/30`s, which fully consume their third-octet space, so the two schemes cannot collide. The
bridge gateway is `.1`; member slot `k` (1-based, from the segment's slot free-list, freed on member
teardown) is `.(k + 1)` — 253 members per segment, 254 segments per host. The math is
`segment_ip_math(segid, slot)` — it takes the segid so the `s = (segid % 254) + 1` derivation is
written once, the shape `ip_math` uses — a unit-tested sibling of `ip_math` in the same module, with
`MAX_SEGMENT_ID` / `MAX_SEGMENT_SLOT` as public consts so the two limits are named, not inlined. The guest
still learns its address from the kernel `ip=` token (gateway `.1`, mask `/24`) — **zero new guest
code, zero netlink in PID 1** (law C6 untouched); the cmdline builder reads it from the new
`res.segment: Option<SegmentMembership>` on the (exhaustive) `PerVmResources`, which is also the
compile-time channel that forces every backend to acknowledge segments (§6.2). Guest MACs are
`mac_math(vmid)` on **every** arm of **every** backend — vmids are host-unique, so member MACs are
bridge-unique by the existing collision-freedom law, and the scheme stays outside the NAT's
reserved-MAC image. That was a premise, not a fact, until delta 8 made it one: `mac_math` reached only
the *vhost-user* arm, `build_ch_net`'s tap arm emitted `mac: None` (CH generated its own), and QEMU's
tap arm emitted no `mac=` at all, so every QEMU guest carried QEMU's fixed default
`52:54:00:12:34:56`. Harmless while each privileged VM owned an isolated `/30` L2 domain; a
deterministic L2 collision for two QEMU members on one bridge. Both arms now set it, each pinned over
the shape the process actually receives — CH's serialized `ChNet`, QEMU's *composed* argv.

**Identity and lifetime.** Segment ids come from a **`SegmentIdAllocator`** on `HostEnv`
(`env.segids`; an additive field — the bundle is documented to grow by field). It does not re-implement
cross-process claiming: the `VmidAllocator`'s per-id lock-file + `flock`-coordinated claim/reclaim
internals (the H1 fix) are **extracted and parameterized** (`dir`, range) so both allocators share one
claim law — the exactly-one-winner race gate re-runs against the generalized core, red-on-inverse as
before. The lock dir is `/tmp/vmcell-segid`: deliberately un-prefixed bare-`/tmp`, not swept — the same
recorded cross-process-rendezvous pattern as `/tmp/vmcell-vmid`, adopted on purpose, not by accident.
`NetSegment` is an `Arc`-backed handle; **every member `MicroVm` holds a clone**, and the netns/bridge
are deleted when the last holder drops. That makes the "never delete a netns under a live VMM" hazard
(§1.4 step 7) *structural*: a member's teardown — VMM process group first, then its slot released back
to the segment, through the same ordered helper as every other resource (law L1; `EnvSetup`'s error
path included) — necessarily precedes the segment's netns removal, because the member holds the Arc.
Member teardown never touches the netns; segment teardown owns it.

**Sweep.** `<prefix>-seg-<segid>` joins `vmcell::naming` as a composer + sweep-filter pair (law F2
extended: one prefix names and sweeps every per-VM *and per-segment* resource; the
starts-with-its-filter pin gains the new class). The orphan sweep gets the class with its **own live-id
space**: `sweep_orphans` takes live *segids* alongside live vmids — the existing `trailing_vmid` key
would otherwise liveness-check a leaked segment netns against the wrong id space. The daemon's start-up
sweep passes both sets empty, so a hard-killed process's segments are reclaimed exactly like its VMs.
The **two netns sweep filters are distinct stems** (`<prefix>-net-` and `<prefix>-seg-`), and each
class must be swept explicitly: a filter is a literal `starts_with`, so `vmcell-seg-1` matched neither
the test-start sweeper nor the daemon start-up sweep while both passed only the per-VM stem — a leaked
segment netns was reaped by nothing, and an aborted run poisoned that segid forever. `clean_vmcell_netns`
and `HostOrphanScanner` now iterate **both** composers, and `naming`'s pin asserts each class's names
start with its own filter *and* not with the other's.

**Fault injection (`tc netem`).** v30 exposes the *names*, not a typed API: `netns_path()` +
`tap_name` + `bridge_name()` are stable documented accessors, and a harness (or vmcell's own gate)
injects delay/loss/partition with `nsenter --net=<netns_path> tc qdisc add dev <tap> root netem …`.
This is a deliberate simplicity cut, not an oversight: the rtnetlink stack in use has **no typed netem
support** (netlink-packet-route 0.30 types only fq_codel/ingress, and `QDiscNewRequest` exposes no
generic kind/options seam), so a typed `SegmentImpairment` API means hand-assembled `TcMessage`s —
recorded as forward work (§17) rather than shipped half-validated. Tests may shell out; production code
does not.

**What a segment refuses, typed, at `build()`:** `snapshotting` + `Segment` (restore-time slot and
addressing semantics are deliberately unspecified in v30 — §17; the consumer topology that wants
segments is a live two-VM test, not a restore farm), and a member whose `resource_prefix` differs from
the prefix its segment was created with (one prefix must name every resource in the domain, or the F2
name/sweep lockstep splits across two prefixes). `Egress` and `host_services_port` are unrepresentable
on the variant (§6.2). Everything else composes: shares (non-snapshot VMs), extra disks, sessions,
resource limits.

**Gates.** Live matrix (CH primary; FC/QEMU/crosvm legs cheap — the tap mechanics are shared): two VMs
on one segment complete a TCP round-trip **in both directions** (the `echo-server` guest-tools applet
in `--tcp` mode is the listener; guest-tools `curl`/the dialer side drives it), with a third
off-segment VM's dial to **both** members refused/timed out as the negative
control against the same targets that just accepted (the positive-control law); `dial_tcp` reaches a
member listener from the host; a `tc netem` 50 ms delay on one member tap measurably shifts the
guest↔guest round-trip, and a `netem loss 100%` on the same tap times out an in-flight dial that
succeeds again once the qdisc is removed (delay and loss/partition are one qdisc mechanism, but the
partition leg is gated on its own — a bridge that silently healed a partition would pass a delay-only
gate); teardown leaves the segment netns existing-before/gone-after the last holder drops; the
sweep gate plants an orphan `<prefix>-seg-*` and reclaims it, leaving a foreign-prefix segment
untouched. KVM-free: `segment_ip_math` (range, injectivity, disjointness from `ip_math`), the naming
starts-with pin, the slot free-list (claim/free/exhaustion at 253), the generalized-allocator
exactly-one-winner race, and every `build()` rejection red-on-inverse.

**Performance.** Members ride the identical tap datapath as privileged VMs — no proxy hop, no
userspace NAT, kernel-bridged L2 between guests — so per-VM hot-path cost is unchanged and guest↔guest
throughput is whatever the host bridge does. Segment setup adds one netns + one bridge + one enslave
per member (rtnetlink round-trips, milliseconds); nothing on the non-segment paths changes.

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

`mem_limit_enforced` (renamed from `limits_enforced` by the v28 pass — its delta 3, landed — because the old
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
   queryable **`HostCapabilities`** descriptor: one struct probed once at start-up — by
   `NetSegment::new`'s privileged-net gate (§6.5), the daemon's `MicroVmLauncher::new` boot log (§11.2),
   and `bench-vm`'s privileged net-egress self-skip, which are its three production consumers — recording
   what the host actually offers: the effective capability
   set, KVM-group access, `/var/run/netns` reachability, which cgroup controllers the current scope
   delegates, and whether the scope is a non-threaded `domain` leaf. As built, the descriptor is
   **probed once at start-up and logged**; per-op
   enforcement keeps its own authoritative fail-loud per-write check (e.g. `metrics::try_apply_limit_at` /
   `classify_limit_write_err`), so the descriptor is the queryable single source, not a replacement for
   that per-write typed error. (The v28 pass's delta 8 — landed; implementation-notes.md, Delta 8,
   carries the as-built reconciliation.)
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
snapshot once, and per-run restore + add a tmpfs overlay. This skips kernel boot on the hot path — ≈5.8×
faster than cold boot on CH (305→53 ms p50); on Firecracker warm restore is faster still (775→27 ms, ≈29×
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
2. **`orchestrator::restore()`** re-checks against the `cfg` it is handed (defense in depth) and returns
   `Error::Unsupported`. That check is the one **config-only** predicate,
   `clone_ineligible_feature(&VmConfig) -> Option<&'static str>`, and it is wider than vhost-user: it also
   refuses a `NetConfig::Segment` member (§6.5 leaves restore-time slot/addressing unspecified), a
   **custom `init=`** (it replaces the guest agent, and the mandatory post-restore resync — clock, CSPRNG
   reseed, MAC/IP — runs *through* that agent, so the clone would resume on a frozen clock with a
   correlated CSPRNG and a stale MAC/IP), and a non-empty **`usb_host_devices`** (a passed-through host
   device is host state living outside guest RAM; the stream carries the guest's view of the xhci
   controller, not the device behind it, and a fan-out would leave N guests fighting over one device).
   `build()` rejects both of those last two *paired with `snapshotting`*, but that is not the same check:
   the v30 delta-9 premise that "every backend's `restore()` rejects a non-snapshotting config" is
   **empirically false** — no backend's `restore()` reads `cfg.snapshotting` — so a
   `{ InKernel, snapshotting: false }` config carrying either reached the backend unguarded. This is why
   the law is config-only and boundary-independent, and why the wrapping refusal (the prose and the vmm
   id) is all that is per-boundary. `MicroVm::snapshot()` guards the same custom-init case through
   `control_plane_disabled`, because a live `MicroVm` no longer owns the `VmConfig` the predicate takes,
   and names itself (`vmm: "orchestrator"`) rather than blaming a backend. The zygote's fail-fast
   `check_clone_eligible` is the *same law applied earlier* — before CoW copies are minted — and it
   **wraps the predicate rather than restating it**: while it open-coded its own three arms the pair had
   already drifted, so a custom-init config was fanned out and only refused per clone at the restore
   boundary, N copies later.
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
  (law C6). The host side rebinds the baked tap to the rotated one on **every** tap-bearing backend, by
  the route each offers: CH rewrites `net[].tap` in the restore config (§2.2), Firecracker sends a
  `network_overrides` entry on `PUT /snapshot/load` (§2.3), and QEMU and crosvm re-pass `-netdev
  tap,ifname=…` / `--net tap-name=…` because their restores rebuild the argv from the fresh
  `PerVmResources`. So the guest's rotated `/30` and its host-side tap/nft wiring belong to the same
  vmid, on all four. The guest
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
`Cargo.toml`s (`vmcell` is at 0.12 as of v29; the v30 register's breaking pass bumps it to 0.13, §18).
The members:

- **`vmcell`** — the library, one package carrying the host feature stack (§9.7). It keeps **only the
  primary Cloud Hypervisor backend**, the shared `Vmm`/`VmInstance` traits + `VmmCapabilities`, the
  jail/seccomp predicates, the spawn/reap/console/eligibility helpers, and the bootstrap artifact producers
  (the OCI rootfs source, the host-`make` and prebuilt kernel producers); it exposes the shared utilities
  the extracted builders and backends reuse.
- **`vmcell-firecracker` / `vmcell-qemu` / `vmcell-crosvm`** — the three **secondary** VMM backends,
  extracted into their own crates so the core carries only Cloud Hypervisor. Each depends on `vmcell` for
  the one `Vmm` trait + the shared jail/seccomp/spawn/console/eligibility helpers; `vmcell` has **no
  production edge back** (only a dev-dep, for the matrix tests), so the graph stays acyclic.
  `vmcell-crosvm` (crosvm, §2.5) is the v29 addition — boot-first, driven purely as an external binary
  (`crosvm run` + `crosvm <ctl> <socket>` clients), so it carries no serde/JSON.
- **`vmcell-bench`** — the cross-backend `bench-vm` harness, the one composition root wiring all four
  backends (each secondary backend behind an optional `firecracker`/`qemu`/`crosvm` feature; all four
  are in the default set — `crosvm` graduated in after its live validation, mirroring `qemu`; only its
  live runtime matrix stays opt-in because the binary is absent on CI). Kept outside `vmcell` so the
  dependency graph stays acyclic.
- **`vmcell-artifact-validator`** — the artifact conformance kit (a roster omission in v28/v29,
  corrected here): `validate(&ArtifactSet { kernel, rootfs }, &ValidationOptions)` boots real micro-VMs
  and runs the named check battery (`boot.kernel_banner`, `boot.agent_ready`, `agent.exec_roundtrip`, …)
  at `Core`/`Extended`/`Full` levels against the whole artifact↔system contract (§5.4, §5.6), plus the
  `harness` module (`get_vmlinux`/`get_rootfs`/`start_vm`, binary resolvers, capability probes) that
  vmcell's own integration tests and `vmcell-bench` consume. Depends on `vmcell`; `vmcell` dev-depends
  back on it for the matrix tests (a permitted dev-dep cycle, like the backends). As of v30 it is
  **downstream contract surface** (§10.4): the battery is how an out-of-repo kernel proves
  vmcell-compatibility from the consumer position.
- **`vmcell-rootfs-builder`** — the extracted full-apt in-VM `mmdebstrap` rootfs source (§4.2). A `Stage`
  impl that depends on `vmcell`, boots a builder micro-VM, and emits the erofs through the shared
  `pack_erofs_with_injection`.
- **`vmcell-kernel-builder`** — the extracted in-VM download+configure+compile kernel builder (§5.1).
- **`vmcell-cli`** — the **composition-root** crate carrying the CLI (`build`, `build-kernels`,
  `oci2-erofs`, the lifecycle verbs, `bundle`). It depends on `vmcell` + both builder crates and assembles
  the `Pipeline`, choosing sources via `--rootfs-source oci|mmdebstrap` / `--kernel-source
  prebuilt|host-make|in-vm`.
- **`vmcell-protocol`** — the framed postcard wire enum and the `ExecRequest`/`ExecOutcome` types; the
  *only* code the host and the guest agent share.
- **`vmcell-guest-agent`** — the guest PID-1 binary (plus the `ReaperCoordinator` library). Lean:
  `rustix`/`signal-hook`/`vsock`/`libc`/`tracing`, no host async stack.
- **`vmcell-test-runner`** — the privileged-test capability runner (§15.5). Lean: `rustix`/`capctl`/`libc`
  only, never the `vmcell` library.
- **`vmcell-guest-tools`** — the in-rootfs multicall helper: four applets, `ip`/`curl`/`kvm-ok`/`echo-server`
  (§4.4). A *guest* binary; needs
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
  `vmcell-privilege` — never the daemon's web-**server** stack (`axum`/`vmcell-daemon` absent by its
  lean-tree assertion; `hyper` enters legitimately via the proxy/HTTP-client subset — §15.2). The
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
hostcaps.rs      # HostCapabilities: the ONE start-up probe of caps/KVM/netns/cgroup delegation (§7.2)
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
#[non_exhaustive]                        // documented to GROW BY FIELD — a new process-global seam is
                                         // a field here, never a new positional argument
pub struct HostEnv {
    pub cids:    Arc<CidAllocator>,
    pub vmids:   VmidAllocator,          // Clone over an internal Arc<Mutex>
    pub segids:  SegmentIdAllocator,     // v30 (§6.5): segment ids; shares the vmid allocator's
                                         //   extracted flock claim core, lock dir /tmp/vmcell-segid
    pub cgroups: Arc<dyn CgroupFs>,
    pub clock:   Arc<dyn Clock + RefUnwindSafe>,  // the bound the v28 sketch elided (as-built)
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
fan-out APIs, and lets `agent()` take no *seam* arguments — the clock that drives the post-restore
resync comes from the env captured at construction; the one retained parameter is the per-call connect
**budget** (`None` ⇒ the 10 s default; the recorded as-built deviation from the v28 sketch,
implementation-notes Delta 1 — see the API listing below). Tests
build a `HostEnv` with recording fakes; per-VM assertions key on the slice/vmid the shared recording fake
recorded. The bundle arrived with the v28 pass (its deltas 1–2, landed — the one breaking change of the
0.10 release); v30 grows it by the `segids` field, the documented growth mode.

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
    pub usb_host_devices: Vec<UsbHostDevice>, // host-USB passthrough (v30 §2.4); needs
                                        //   capabilities().usb_host_passthrough (QEMU only);
                                        //   build() rejects with snapshotting
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

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]                       // bus/port addressing can arrive later without a break
pub struct UsbHostDevice { pub vendor_id: u16, pub product_id: u16 }  // v30 (§2.4); duplicates rejected at build()

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
    pub async fn agent(&mut self, timeout: Option<Duration>) -> Result<&mut AgentClient>;
        // drives the first post-restore resync via env.clock. Takes NO seam arguments (the v28 delta-1 gate);
        // the one retained parameter is the per-call connect BUDGET (None => the 10 s default) — a
        // consumer running slow builder-VM boots or restore-under-load legitimately needs 60–180 s
        // windows, and `Timeouts` deliberately carries no overall agent-connect field (the recorded
        // as-built deviation from the v28 delta-1 sketch; implementation-notes.md, Delta 1)
    pub async fn connect_sessions(&self, timeout: Option<Duration>) -> Result<SessionMux>;
        // a 2nd control-plane connection for interactive sessions; fail-loud with custom init=
        // (&self + per-call budget, matching agent() — the as-built shape)
    pub async fn dial_vsock(&self, port: u32, timeout: Duration) -> Result<VsockDial>;
        // raw byte stream to a guest vsock listener (v30, §3.2); agent-independent — works under
        // a custom init=; typed fail-fast on a dead port, never a hang
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
`Lineage` API is §8.5; the session API and `VsockDial` are §3.2; the `NetSegment` API is §6.5;
`AgentClient`, `ResourceUsage`, `VmmCapabilities`, `Vmm`/`VmInstance`, `NetConfig`, and `Share` are
shown in §2–§7 where they are used. The v30 additions land as one breaking pass, `vmcell` 0.12 → 0.13
(§18): the delta-9 `usb_host_passthrough` capability field is the separable exception, explicitly
ranked last by its requester.

**Allocator mechanics.** `VmidAllocator` is either hermetic (`new()`, in-process) or cross-process
(`shared()`, via `/tmp/vmcell-vmid/<vmid>.lock` files with crashed-owner reclaim; `shared_at(dir)` injects
the lock directory so the fs claim/reclaim path is unit-testable). Each lock file is **created already
carrying the owner pid** (never a create-then-write two-step that could crash into an empty, unreclaimable
lock); the whole read→liveness→(re)claim sequence is serialized by an **exclusive `flock` on a per-vmid
coordination file**, with the claim itself an atomic `hard_link` of a pid-bearing temp file (the H1 fix
— the code's own comments record why rename-based claiming dual-claims), and liveness is a
`/proc/<pid>` check. The VMID is mapped to the third IPv4
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
reshuffle-fragile — the v28 pass's delta 7, landed. The pre-fix bug it guards against: deleting the
netns before the proxy running inside it.)

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
| unprivileged guest net | `passt` (rejected, Exp 4) | `smoltcp` + `vhost-user-backend` |
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
*is* the lean build. A CI `cargo tree -e no-dev` per member asserts `agent`, `test-runner`, and
`vmcell-privilege` contain no `tokio`/`hyper`/`rtnetlink`; `vmcell-broker`'s distinct web-server-stack
assertion (no `axum`, no `vmcell-daemon` — it legitimately owns the engine) is §15.2.
**`guest-tools` is deliberately not under that ban** — it needs `reqwest` for real HTTP and runs
unprivileged in-guest, so its lean boundary is "not the host *library*," not "no async."

**Toolchain note.** The MSRV is **1.96.1, single-sourced**: `rust-toolchain.toml` pins it and the one
`[workspace.package] rust-version` equals it, with a CI sync assertion so the two cannot drift. The
declared MSRV is the *tested floor*, never an aspiration — an **understated** `rust-version` is a live
vulnerability path, because an MSRV-aware resolver re-resolves older consumers onto dependency versions
the lockfile pins were bumped past (the `time 0.3.45` / RUSTSEC-2026-0009 class). Build `--locked`; never
`cargo update` on an older toolchain. (This supersedes — and folds in — the pre-bump "targets 1.85 /
effective floor 1.88" note that `docs/historical/70` carried as an erratum against this section.)

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
   the v28 pass's delta 9, landed; previously `FakeVmm` recorded calls only.)
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
implements `build`, `build-kernels` (both accepting `--pins <file>` as of v30 — the overlay, §10.2, and
the retirement of the CLI's private `pins_path()` near-duplicate of `workspace_root()`),
`oci2-erofs IMAGE@DIGEST [--inject dest=…,src=…,mode=…]` (§4.2), the live-handle lifecycle verbs
`run`/`create`/`snapshot`/`stats` (taking `--kernel`/`--rootfs`, plus `--disk`/`--disk-rw`/`--append` as
thin wrappers over the extra-disk / extra-kernel-arg builder methods), and `bundle`/`verify-bundle` (a
digest-pinned fetch-and-verify manifest of the built artifacts). The cross-process verbs
(`exec`/`ls`/`rm`/`destroy`) belong to the daemon, which genuinely owns them (§11); the CLI's former
fail-loud stubs for them were removed by the v28 pass (its delta 11, landed), each verb redirecting to
the exact `vmcelld-ctl` subcommand that owns it.

### 10.1 Artifacts produced

1. **`vmlinux`** (per arch, per kernel label): one custom-minimal kernel, direct-boot, drivers built in.
   Rebuilt only when the config fragment or pinned source changes. Every *compiling* producer also
   emits the post-`olddefconfig` resolved config beside it as **`vmlinux[-<label>].config`** (v30,
   §5.6 — the anti-silent-drop artifact; the prebuilt seed has none to emit).
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

**Stage 0 — the pin lock (the only non-deterministic input, isolated here).** The pin *schema* covers:
the OCI base-image manifest **digest** (never a tag), the `snapshot.debian.org` **timestamp** (for the
in-VM source), the kernel source version/SHA (plus the `kernels` registry, §5.5), the `kernel_prebuilt`
entry (the digest-pinned bootstrap-seed URL + sha256, §5.4), and the CH/virtiofsd release identities.
The committed `pins.json` currently carries the kernel/`kernels`/`kernel_prebuilt`/rootfs/fragments
pins; the CH/virtiofsd and snapshot-timestamp pins are **recognized-when-present but not currently
committed** — so the snapshot stage's CH-build-identity fold arms only once that pin is added (an
honesty note, not a promise). Pins live in `pins.json`; `ResolvePinsStage` loads it once and propagates the values through `StageOutputs`
so downstream stages read pins from memory. *Live* tag→digest and timestamp resolution is forward work
(§17); the committed lock is the honest current state.

**The pins overlay (v30, §18 delta 1 — FR-V6).** A downstream consumer extends the registry without
forking it: `ResolvePinsStage` gains `overlay_file: Option<PathBuf>`, set from **`VMCELL_PINS`** (env)
or `--pins` (CLI) or directly (library). Semantics are **key-level overlay over the committed
baseline**: a flattened key present in the overlay wins; a key absent from the overlay resolves from
the baseline — that fallback is the vetted default, not a degrade, and it is exactly what retires the
forked-pins maintenance the overlay exists for. The baseline is vmcell's own committed `pins.json`,
**embedded at compile time** (`include_str!`) so a git-dep workspace needs no fragile
filesystem hunt for the checkout; inside the vmcell workspace the embedded copy and the on-disk file
are the same committed bytes by construction (the one-sentence rationale for what looks like two
sources). Safety properties, each gated: a fragment or label *referenced* but resolvable nowhere stays the
existing hard error naming the key; and — because reference-time errors cannot catch a typo'd
**override** of a key that then silently resolves from the baseline (the accept-then-ignore class the
fail-loud rule bans, on a surface whose whole purpose is overriding) — the overlay parser is
**stricter than the baseline's**: every top-level overlay key must match the known pins namespace (the
fixed pin names, `kernels.*`, `kernel_fragments.*`), and a key matching none is a hard error naming it
(new entries *within* a namespace stay legal; the baseline file itself keeps its ignore-unknown
semantics — it is vmcell-committed, not caller input). The stage's `cache_key` folds **both** files'
content, so an overlay edit re-resolves. What the
overlay deliberately does **not** do: make `ensure_test_artifacts` a downstream entry point — that
helper is the vmcell-workspace test bootstrap, and its fingerprint hashes the guest-agent/guest-tools
*source closures* out of the workspace tree, which no pins seam can conjure in a consumer workspace.
The downstream build entry points are §5.6's; the downstream artifact story is §10.4's env contract.

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
   the rootfs was a real handshake-timeout bug); on the `oci2-erofs --agent-musl` path it folds the
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

### 10.4 The downstream toolkit contract (v30, §18 deltas 2, 5 — FR-V1/FR-V6)

Everything a git-dep consumer stands on is named in **one list**, documented as consumable, and held
still by gates — retiring "public in the Rust-visibility sense but semi-public in practice." The
contract surface: the pins schema + overlay semantics (§10.2); `Stage`, `Pipeline`, `ResolvePinsStage`,
`StageInputs`/`StageOutputs`, `CacheKey`, and the hash helpers (§10.2); the kernel build entry points
and the resolved-config sidecar (§5.6); `pack_erofs_with_injection` + `ExtraFile` and the
rootfs-construction contract (§4.2–§4.3); the `VMCELL_*` env contract (below); and the
`vmcell-artifact-validator` battery + `KconfigValues` (§5.6, §9.1). Versioning is the convention the
crates already follow — pre-1.0 breaking-changes-as-minor-bumps, announced in the comment-changelog at
the top of `crates/vmcell/Cargo.toml` — so a break is a deliberate, findable ledger entry, never
discovered by compile failure. Gates: `cargo semver-checks` extends to **`-p
vmcell-artifact-validator`** alongside `-p vmcell` (the validator is now contract surface; today only
`vmcell` is checked), `missing_docs` already denies on every public item, and the out-of-tree example
workspace (§5.6) is the living consumer that reddens CI when any listed surface drifts — its CI job
invokes the **exact documented CLI commands** (`vmcell build-kernels --pins …`,
`vmcell oci2-erofs … --inject …`) so the CLI half of the contract, which `semver-checks` cannot see,
has a consumer-shaped gate too.

**The `VMCELL_*` environment contract** — the supported override set, with the semantics each one has
had *specified* rather than discovered:

| Variable | Contract |
|---|---|
| `VMCELL_ARTIFACTS_DIR` | Relocates the artifact cache; all freshness/fingerprint logic runs there unchanged. |
| `VMCELL_KERNEL` | Path redirect only: the harness uses this kernel verbatim and still requires it to exist (fail-loud); it does **not** disable any build. |
| `VMCELL_ROOTFS` | The externally-managed-artifacts switch: its presence makes `ensure_test_artifacts` a **full no-op** (not a rootfs-only skip — kernel-presence check and agent/tools rebuilds included), and the harness uses the named rootfs verbatim. The switch a downstream harness sets. |
| `VMCELL_PINS` | The pins overlay (§10.2), read by every pins resolution — the toolkit build entry points (§5.6), the CLI, and (in the vmcell workspace) `ensure_test_artifacts`. |
| `VMCELL_CH_BIN` / `_FC_BIN` / `_QEMU_BIN` / `_CROSVM_BIN` | Backend binary resolvers (already shipped; now contract). |
| `VMCELL_SKIP_MANIFEST` | The capability-skip manifest sink (§15.4; already shipped; now contract). |

**The harness getters, downstream — specified, not discovered.** In a consumer workspace,
`harness::get_vmlinux()`/`get_rootfs()` have exactly two behaviors: with `VMCELL_KERNEL` +
`VMCELL_ROOTFS` set (the documented downstream configuration — `VMCELL_ROOTFS` no-ops the ensure
bootstrap), they return the named paths after an existence check; **without** them — including with
`VMCELL_PINS` alone — they **fail loud** with a message naming the two-step route (build the kernel via
the §5.6 toolkit, then point `VMCELL_KERNEL`/`VMCELL_ROOTFS` at the outputs), never a silent attempt to
run the workspace bootstrap against the cargo checkout. This is a **recorded, deliberate deviation from
FR-V6's letter** ("`get_vmlinux()` builds per the downstream pins file"): the ensure bootstrap
structurally cannot build downstream (§10.2), so the criterion is met by the documented substitution —
overlay-driven *build* through the toolkit, getter-driven *consumption* through the env contract — and
the substitution itself is gated: the example workspace (§5.6) calls the getters under the full
override set *and* asserts the fail-loud message without it, so the observable downstream behavior is
pinned from the consumer position.

**Consuming vmcell as a git dependency** — the guidance section (README + rustdoc) a consumer follows,
each item load-bearing and learned the hard way: (1) pin by `rev`, build `--locked`, toolchain ≥ the
single-source MSRV (§9.7); (2) **replicate the `[patch.crates-io]` vendored-vhost stanza** into your
workspace root *if* you use QEMU + `NetConfig::Unprivileged` — cargo honors patch sections only from
the consuming workspace's root, so a plain git dep silently drops the `SET_VRING_ENABLE` quirk fix and
regresses that one path to a cryptic vhost-handshake boot failure; the doc gives the exact two-line
stanza (the `=`-pins make versions match) and states when it is *not* needed (every other
backend/mode); (3) run the downstream-runnable vendor assertion — `scripts/check-vendored-vhost.sh`,
path-independent (it greps your own `cargo tree` for the `vendor/` resolution), the same check vmcell's
CI runs — in your CI when (2) applies; its **positive control** is the example workspace, whose
manifest replicates the stanza against a vhost-resolving feature set and runs the script green in CI
(`cargo tree` only — no NAT compile), while the red leg drops the stanza in a temp copy and asserts the
script fails; (4) artifacts: build the rootfs with a vmcell checkout's
`vmcell build` / `oci2-erofs --inject` and point your harness at it via `VMCELL_ROOTFS` +
`VMCELL_ARTIFACTS_DIR`; kernels build downstream through §5.6; (5) privileged runs need a capability
runner **installed under the consumer's own workspace**, and the route is four explicit steps, not
`just bless` — that recipe belongs to the vmcell checkout (§15.5) and `vmcell-test-runner` is not a
member of the consumer's workspace, so there is nothing there for it to bless: build
`-p vmcell-test-runner` from the pinned vmcell checkout, `install -D -m 0700` that binary into the
consumer's own `.vmcell-bin/<profile>/` (`release/` for the usual `--release` runs),
`sudo setcap cap_net_admin,cap_sys_admin,cap_dac_override+ep`
the installed copy, then point `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER` at it — once per
profile tested under (README § "Consuming vmcell as a dependency (the downstream contract)", step 5,
carries the runnable form). The copy must live in the
consumer's workspace because the runner derives its confinement root from its **own** canonicalized
path (§15.5): one blessed inside the vmcell checkout anchors on *that* `target/` and refuses the
consumer's test binaries. `0700` before the caps land is the security boundary, and writing a file
strips its capabilities — so the install+`setcap` pair repeats on every runner rebuild. A
build-script probe that would auto-detect a missing vhost patch was considered and rejected: the
failure it prevents is loud (a boot error), just cryptic — a documented stanza + a one-line CI check
beats autoconf machinery (simplicity is reliability).

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
  upload, and stored in a `<name>.sha256` sidecar (the v28 pass's delta 10, landed). The write is size-capped by
  `--max-artifact-bytes`, rejected fail-loud past it — an unbounded upload is a trivial disk-fill DoS.
- **List** — `GET /v1/artifacts` → `[{name, size_bytes, sha256}]`, the digest served from the sidecar so
  list is O(entries), not O(store bytes); its purpose is client round-trip verification, and the daemon
  owns the dir, so re-hashing on every list bought nothing. Listing surfaces only direct children that
  pass `resolve_artifact_path` (a stray subdir or an out-of-band name that fails validation is skipped,
  never surfaced as a usable artifact); sidecars are internal and not listed.
- **Snapshot prefix** — a warm snapshot writes into `<artifacts-dir>/<prefix>/`, and that prefix is part
  of the same create-only namespace: the registry mints it with `create_dir`, **not** `create_dir_all`, so
  an existing prefix is an `AlreadyExists` (409) naming the delete-then-retry route. The kernel's `EEXIST`
  *is* the check, so it is atomic against a concurrent snapshot to the same prefix — no check-then-act
  window. Under `create_dir_all` a second snapshot overwrote an older one file-by-file and a `restore_from`
  copy racing that write read a torn mix of two lineages. A failed snapshot removes the dir it created
  when it is empty; a partially-written one is kept for diagnosis.
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
`shutdown_all`; and dropping the table runs each **`MicroVm`'s own** `Drop` — the panic path — with the
identical ordered cleanup. `Registry` deliberately has **no `Drop` impl**: it owns nothing beyond the
handles, so the third path is the contained `MicroVm`s dropping, not a registry-level teardown, and
writing one would be a second copy of the ordered helper. A **hard** kill skips all three and leaks the
residue.

**The start-up orphan sweep — the crash-recovery counterpart.** Before it owns any VM, the daemon runs
`sweep_orphans` with **empty** live-vmid and live-segid sets, so every netns/cgroup-slice/scratch dir
(and segment netns, §6.5) whose trailing id is not currently owned — i.e. every orphan a previously
hard-killed daemon left — is reclaimed.
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
Hypervisor, Firecracker, QEMU, crosvm) is the largest attack surface in the system: it parses guest-controlled I/O
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
  "firecracker", feature: "seccomp_log" }`, never silently downgraded to "off" or "on".
- **QEMU** — `-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny`
  (Enforcing). This is load-bearing: **QEMU runs with no seccomp at all unless `-sandbox` is passed**, so
  the earlier QEMU path — which omitted it — left the fallback backend completely unconfined. `spawn=deny`
  is the important clause (no `fork`/`exec` out of the VMM). Like Firecracker, QEMU has no "log" sandbox
  mode, so `Log` is a typed `Unsupported`.
- **crosvm** (v29) — crosvm's own sandbox is a **multiprocess minijail** (per-device jailed subprocesses
  that `pivot_root` into `/var/empty` and load policy-dir seccomp). The initial design kept it on for
  `Enforcing` (the Firecracker analogue), but **live validation refuted that**: it fails
  `"/var/empty" is not a directory, cannot create jail` unless that dir is pre-created, and its
  device-child forking fights the single-process supervision model (cgroup `add_task`/pgid-reap/
  `find_host_pid` all assume one leader). So crosvm **always** runs `--disable-sandbox` (a single
  externally-jailed process). To keep the "never unconfined by default" invariant, its seccomp confinement
  moves to the **Layer-2 jailer deny-list**: `Crosvm::create` turns `JailConfig::seccomp_deny_list` **on**
  for `Enforcing` (the default) and **off** for `Disabled` (the loud opt-out). Both emit the same
  `--disable-sandbox`; the Enforcing/Disabled distinction lives in the jail spec, not the argv. `Log` is a
  typed `Unsupported`. This is the one backend whose confinement is Layer-2 rather than its own filter, and
  it is the empirically-forced per-backend enablement the deny-list was designed for (§12.3).

`Disabled` exists only for diagnosing a suspected seccomp-induced failure and is a **loud, explicit**
opt-out (it widens the attack surface); it is never a silent fallback when a filter fails to apply. The
per-backend mapping is unit-tested, including that every backend with its *own* filter renders a
non-empty, sandbox-enabling argument under `Enforcing` (crosvm's `Enforcing` is instead asserted as
`--disable-sandbox` **plus** the Layer-2 deny-list turned on — its confinement lives there, above) and
that the three unsupported `Log` cases (Firecracker, QEMU, crosvm) return the typed error rather than
a wrong flag.

### 12.3 Layer 2 — the jailer-equivalent (`JailSpec` + `apply_jail`)

Firecracker ships a separate `jailer` binary that hardens the process *before* `exec`ing the VMM; CH and
QEMU ship nothing equivalent. Rather than adopt FC's jailer (FC-only, and it wants to own process
creation), vmcell applies the same class of restrictions itself, uniformly across all backends (including
crosvm, §2.5), in the child between `fork` and `execve`:

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
reboot                                # reboot/halt the HOST (a guest reboot is a VMM-internal transition)
swapon, swapoff                       # reconfigure host swap
```

`DENIED_SYSCALLS` in `vmm/jail.rs` is the one authoritative copy of that roster; this table is checked
against it, in both directions — a syscall that belongs is added to *both*, never dropped from the const
to "match the doc".

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
composes with the existing control plane today.

**How the post-apply state is gated.** Three routes, because no single one can read all of it. (a) A
stand-in child spawned through `build_vmm_cmd` `cat`s its own `/proc/self/status` and `/proc/self/limits`,
which covers `no_new_privs` (`NoNewPrivs: 1`, with the `VmmSeccomp::Disabled` jail as the inverse that
reads `0`) and `RLIMIT_CORE` (asserted against a jail that *raises* it to a nonzero value, so a host
whose ambient soft limit is already 0 cannot make the assertion vacuous). (b) **Dumpable has no
`/proc/<pid>/status` field** — `prctl(PR_GET_DUMPABLE)` in the jailed child is the only read route — so it
is gated by a KVM-free forked-child probe, both ways. (c) The **ambient-capability** half is a privileged,
`#[ignore]`d leg: an unprivileged process's ambient set is already empty, so the assertion would pass
against an `apply_jail` that did nothing. It runs under the blessed runner in `just test-privileged`,
where `CAP_NET_ADMIN` *is* in the ambient set (§11.2) — asserted as a precondition, never assumed — and
its inverse pins the shipped `clear_ambient_caps = false` default (Appendix A reversal 9). All three live
in `tests/jail_hardening.rs`, which routes every leg through one `fork_probe` helper rather than a second
copy of the fork dance.

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
(no orphaned cap-holder) and, in the same few post-fork instructions, sets **SIGINT/SIGTERM to
`SIG_IGN`**: `fork(2)` leaves it in the parent's process group, so a terminal Ctrl-C reaches the
cap-holding child too, and at the default disposition that kills it outright — its `Registry` never
drops and the VMM processes (each in its own group, no `PDEATHSIG`) survive as orphans pinning guest RAM
and `/dev/kvm`, which the *next* daemon's start-up sweep then de-resources underneath. Ignoring both lets
the graceful path (parent death, or `ShutdownAll`/EOF on the bridge) win the race. Because an **ignored**
disposition survives `execve` — unlike a caught one — `build_vmm_cmd`'s `pre_exec` resets both to
`SIG_DFL` in the VMM child, as its first step, so an operator's `kill` and the teardown's own signals
still work. The parent drops **all** capabilities via the pure `plan_broker_parent_drop`
(the bounding-set shrink needs `CAP_SETPCAP`, which `just bless` grants the runner file as a
transient cap; where it is absent the shrink degrades to a warned no-op and the effective/permitted
drop — the load-bearing half — still happens). Parent and broker speak a tiny framed enum over a `socketpair`:

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
into the broker; **`axum` and the `vmcell-daemon` crate never do** (its lean-tree assertion, specified
at §15.2; `hyper` enters legitimately via the proxy/HTTP-client subset).

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
  the broker and drives its whole VM-lifecycle suite with the serving parent cap-dropped (the suite's
  size is what `just test-daemon` reports, not a figure quoted here).

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
  (`destroy`, `shutdown_all`, and the contained `MicroVm`s' `Drop` when the table goes — the registry
  itself has no `Drop` impl, §11.4) all call the **same** helper. A hard kill that skips `Drop` is
  reclaimed by the start-up sweep against an empty live set. *Owner:* `orchestrator` + `vmcell-daemon`'s
  registry. *Gate:* the drop-order recording gate + the panic-residue-vs-computed-paths lifecycle test. →
  §9.4 / §11.4.

**F — Fail-loud / naming / cmdline / cache**

- **F1 — a missing capability fails loud, never a silent no-op.** A *requested functional* op whose OS
  capability is absent returns a typed `CapabilityUnavailable`; only an explicitly-listed best-effort knob
  (the benchmark levers) degrades to a `warn!`. *Owner:* `metrics` + `net` + `HostCapabilities`. *Gate:*
  the `CgroupFs`-fake `CapabilityUnavailable` test + the errno-split unit test. → §7.2.
- **F2 — one prefix names and sweeps every per-VM (and per-segment) resource.** A single
  `resource_prefix` composes every per-VM *and per-segment* resource name **and** every orphan-sweep
  filter through `vmcell::naming`, so a produced name can never fall out of lockstep with the filter
  that reaps it — and each swept class is liveness-checked against **its own id space** (vmids for
  `-net-`/`-vm-`, segids for `-seg-`, §6.5). *Owner:* `vmcell::naming`. *Gate:* the "every produced
  name starts-with its sweep filter, for any prefix" unit test, extended per class. → §9.3 / §11.4 /
  §6.5.
- **F3 — extra kernel args are append-only.** A caller's `extra_kernel_args` may add a parameter but never
  clobber a token vmcell owns, enforced by the one `is_reserved_cmdline_arg` predicate (reserved-key set +
  `vmcell_` prefix guard + single-token guard). *Owner:* `config`. *Gate:* the gate that builds a cmdline
  exercising every emitted token and asserts the predicate rejects each key. → §5.3.
- **F4 — cache keys are content-addressed and deterministic.** Five rules: stable hasher, deterministic
  input order, content/identity-not-paths, per-stage version + source SHA, validity by content not
  existence. *Owner:* `artifact`. *Gate:* the `cache_key` golden test against a **real** stage + the
  tamper-rejected test. → §10.2.
- **F5 — rootfs injection has one reserved-path predicate (v30).** Every downstream `ExtraFile` dest is
  checked against the single `is_reserved_injection_path` list of vmcell-owned dests (agent, CA trust
  store, `vmcell-tools/`); a hit — or a duplicate extra dest — is a build-time `Error::Artifact`, and
  vmcell's own injections stay unconditional and authoritative. Never a second copy of the list, never
  a silent last-writer-wins among injected entries. *Owner:* `artifact::rootfs`. *Gate:* the
  reserved-dest + duplicate-dest red-on-inverse tests + the manifest pin test. → §4.2.

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
  *Owner:* `vmcell-broker` + `vmcelld`. *Gate:* `just test-daemon` drives the whole VM-op suite with
  the serving parent cap-dropped. → §12.4.
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
`swap.max=0`+`oom.group=1`) are §7.3, and the **NAT's six silent-wedge invariants** (source-MAC
collision, RX-only-when-queued, TX notification, socket-pool sizing, bounded host reads, contiguous-span
guest reads) are §6.2. They
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
  `vmcell-test-runner`, and `vmcell-privilege` pull no `tokio`/`hyper`/`rtnetlink` (`guest-tools` is
  exempt, §9.7). **`vmcell-broker`'s boundary is different and narrower**: it legitimately *owns* the
  engine (`tokio`, `rtnetlink`, and — transitively via the proxy/HTTP-client subset — `hyper`), so its
  assertion is that the HTTP-**server** stack is absent: no `axum` and no `vmcell-daemon` (the P2
  boundary; `vmcelld`, which legitimately links both, is the gate's positive control). Both
  `vendor/vhost*` crates are asserted to resolve from `vendor/` (§9.6). (This folds in the second
  `docs/historical/70` erratum — the earlier phrasing lumped the broker into the `tokio`/`rtnetlink`
  ban it never had.)
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
selects `package(~vmcell) & kind(test) & !binary(proptests)` — a *positive* selector, so a newly-added
integration binary is included by default rather than silently left out of the serial group (a negative
"everything but X" selector is the divergence trap). The `~` is a **substring** match over package
names, which is what makes it a workspace glob: the exact-name form needed one override per member
(`package(vmcell)` plus a separate `package(vmcelld)`) and each silently denied every member added
later, so a new VM-booting binary in `vmcelld` or `vmcell-daemon` ran unserialized and raced on
netns/cgroups/nft. The cost — serializing a few cheap KVM-free daemon integration tests — buys that
auto-inclusion; `proptests` is excluded because it is pure in-memory property testing and keeps its
parallelism. The suite splits along the two operating modes (§6.1):
a privileged-mode suite (netns+tap+snapshot) and an unprivileged-mode suite (smoltcp NAT, no snapshot).

**Capability honesty is enforced, not documented.** On the **primary** backend (Cloud Hypervisor) a
missing capability is a hard `require_cap!` **panic** — CH is the reference and a silent skip there would
hide a real regression. On the secondary backends (Firecracker, QEMU, crosvm) a missing capability records
a **SKIP** to a `VMCELL_SKIP_MANIFEST` manifest instead, so the run surfaces exactly what did not execute
rather than passing by omission — and each such `false` capability additionally carries a KVM-free honesty
pin so a silently-flipped flag reddens even without the live leg (this is how crosvm's honest-`false`
capabilities, §2.5, stay auditable — each honest `false` shows up as a `require_cap!` skip in the
opt-in `just test-crosvm` run's skip manifest, which is the roster to read). A per-flag
capability-honesty test pins every `VmmCapabilities` field — all nine (`snapshot_restore`, `lazy_restore`, `virtio_fs_shares`,
`unprivileged_vhost_user_net`, `nested_virt`, `virtio_console`, `restore_rotates_host_paths`,
`disk_io_throttle`, `usb_host_passthrough`) — to the backend that actually supports it, plus the three
seccomp-`Log` unsupporteds (FC/QEMU/crosvm, §12.2) as separate non-descriptor pins, so a flag that lies
(advertising a capability the backend lacks, or vice versa) goes red. **Zero selected tests
is a CI failure**
(`nextest`'s `--no-tests=fail`), so a mis-scoped filter that silently selects nothing fails loudly instead
of passing. `nextest` **retries** (exponential, count 3, 5 s→20 s) are configured as a backstop for
genuinely residual host noise only (§14 lesson 4) — never a substitute for root-causing a reproducible
failure.

The exemplar suites, each written so its assertions **fail on the inverse**:

- **`snapshot_restore.rs`** (the S2 battery, §8.2): reconnect across the **severed** vsock (the restore
  re-creates the vhost-vsock device, so a test that reused the old connection would hang); assert the
  **transport-real** restored identity per backend inside a `restore_rotates_host_paths` branch — CH's
  rotated AF_UNIX vsock path (embedding the new vmid), QEMU's rotated guest **CID** (`assert_ne!` vs the
  source CID, made non-vacuous by reserving that CID up front), and FC's verbatim baked vsock path; assert
  the MAC **and** IP both rotated (the IP check compares the little-endian default-gateway from
  `/proc/net/route`, since a "MAC-only" assertion passed while every clone sat on a dead `/30`); assert the
  CSPRNG changed across restore **without** a test-issued reseed; and assert `FakeClock` was read on the
  **first** post-restore `agent()`.
- **`zygote.rs`** (the S3/S4 fan-out, §8.4): N concurrent clones each get a **distinct** vmid, a MAC equal
  to `mac_math(vmid)`, distinct vsock paths, and — for QEMU (the Vsock endpoint) — a distinct guest **CID**
  (the host-global resource it rotates); concurrent fan-out on the rotating backends (CH **and** QEMU) and a
  single-clone-only Unsupported path on FC; the master `config.json` is **byte-identical** after the
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
  survives a restore into a fresh VM — the cap-dropped operation set of §12.4.
- **The v30 downstream batteries (§18):** the **segment** set (two-VM bidirectional TCP, off-segment
  negative with on-segment positive control, host `dial_tcp`, a `netem` delay that measurably shifts the
  guest↔guest round-trip, last-holder netns residue, orphan-`seg` sweep with foreign-prefix isolation —
  §6.5); the **dial** set (echo round-trip + EOF both ways per backend/endpoint arm, dead-port typed
  error not a hang — §3.2); the **injection** set (in-guest `cat` + `stat` of an injected file before
  first exec, reserved/duplicate-dest rejects, cache-key invalidation — §4.2); the **toolkit** set (pins
  overlay wins/falls-back/fails-loud, resolved-config sidecar present and assertable, the serial-log
  classifier red-on-inverse on canned logs, and the **out-of-tree example workspace** built and run by
  CI — its KVM leg on the self-hosted runner boots the fragment-built kernel and proves
  `/proc/config.gz` on the data plane — §5.6/§10.4); and the **opt-in USB recipe**
  (`just test-usb-passthrough`, env-gated on a designated `VMCELL_TEST_USB_DEVICE=<vid>:<pid>`, staged
  exactly like `just test-crosvm` because CI has no designated device — §2.4; its KVM-free honesty pins
  and argv golden tests always run).

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
  test binary does not). the granted set is `BLESSED_FILE_CAPS` — the three `PRIVILEGED_CAPS` the mode
  uses plus a **transient `CAP_SETPCAP`**, whose only purpose is `PR_CAPBSET_DROP`: the transition
  drops it out of the bounding set (it is in `supported` but not in `need`) and out of
  permitted/effective (step 5 trims to exactly `need`), so no test or VMM ever holds it. Without it
  the bounding-set shrink is a **warned no-op** and the bounding set stays at the kernel's full
  width; with it the exec'd test's bounding set is exactly the three delivered caps, gated live by
  `the_bounding_set_is_shrunk_to_exactly_the_delivered_caps`. `vmcell-privilege::setcap_arg` is the
  one composer of the `setcap` argument, and a unit gate reads the `bless` recipe and the preflight
  probe so the shell copies cannot drift from the constant; a `setuid`-fallback path (for hosts without
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

**Macro — cold boot to agent-ready** (warm-cache; p50 / p95 ms; the 2026-07-17 canonical matrix —
`docs/benchmark-results.md` holds every prior matrix and the per-phase evidence; the end-to-end and
phase-budget figures further below quote their own recorded measurement rounds):

| Backend | p50 | p95 | notes |
|---|---:|---:|---|
| Cloud Hypervisor | 305 | 322 | ≈290 on the `low_latency` profile |
| Firecracker | 775 | 785 | |
| QEMU (q35) | 991 | 1132 | after the shared-cmdline fix (was ≈1400); one recovered ~5 s p99 vsock-daemon flake tail |
| crosvm | 1413 | 1420 | slowest but the most consistent — in-kernel vsock, no flake tail; the cost is guest bring-up (≈79 % `connect`) |

**Macro — warm restore to agent-ready** (p50 / p95 ms):

| Backend | p50 | p95 | notes |
|---|---:|---:|---|
| Firecracker | 27 | 29 | the fastest restore |
| Cloud Hypervisor | 53 | 62 | ≈5.8× faster than its cold boot |
| crosvm | 76 | 86 | sparse ~58 MiB snapshot via `run --restore`, baked CID |
| QEMU | 475 | 487 | shipped v29 (§2.4); slowest by construction — `migrate-incoming` streams the full memory image |

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

**Deferred optimization opportunities (don't re-derive — mechanically refuted in `docs/historical/45`).** Parallel
`virtiofsd` startup is a real latency win but `try_join_all` is cancellation-unsafe (a failed spawn would
leak the others' half-started daemons) and, worse, it is **invisible on the tracked benchmarks** (which
run zero data shares), so it stays deferred. NAT pump-cadence tuning is deferred. A ≈22 ms
`fs_initcall`-region gap and a ≈5.7 ms `cfg80211` `regulatory.db` load are observed-but-unattributed and
not chased. A 12-item opportunity-reject table in `docs/historical/45` records each rejected micro-optimization with
its refutation — consult it before proposing one. Full experiment logs live in `docs/benchmark-results.md`,
`docs/historical/44-claude-perf-experiments.md`, and `docs/historical/45-claude-perf-investigation.md`.

---

## 17. Open gaps and future capabilities

The honest current state, organized by subsystem. Everything here is either wired-but-unvalidated,
validated-but-unwired, or deliberately deferred with a known blocker (§14 lesson 5: "forward work" is
legitimate only when a preflight check names what is missing). Nothing here is load-bearing for the
shipped design.

**Backends & boot.** Firecracker UFFD lazy-restore is unwired (single-lineage verbatim-vsock only, §8.4).
QEMU snapshot/restore over the in-kernel `vhost-vsock` transport is shipped, and **concurrent** QEMU zygote
fan-out (`restore_rotates_host_paths: true`) is now shipped too — `restore()` rotates the host-global guest
CID to a fresh `res.guest_cid`, making QEMU the first backend to rotate a *host-global* resource (unlike
CH's per-scratch-dir paths); the migrate-incoming-at-a-new-CID viability was proven live before enabling it
(§2.4). The dedicated `VmConfig::vsock_transport` selector (`Auto | InKernel | ExternalDaemon`) — decoupling
in-kernel vhost-vsock from `snapshotting` so a privileged non-snapshot QEMU can opt into the more-reliable
in-kernel path and shed the ~11% external-daemon bring-up flake — is also shipped, behind the one
`uses_in_kernel_vsock` predicate. Remaining QEMU gaps: QEMU UFFD lazy-restore (`lazy_restore: false`, no
backend wired) and wiring the unprivileged smoltcp NAT (needs the vendored `vhost` patch, §9.6). `mkfs.erofs`
shell fallback is designed but unimplemented — a missing packer input is fail-loud today (§4.2).
Cross-version snapshot pinning: the snapshot stage folds the `cloud_hypervisor` pin into its cache key,
so a CH bump *would* invalidate stale snapshots at build time — but **no `cloud_hypervisor` pin is
committed** in `pins.json` (the fold hashes an empty string), and the README installs CH from git HEAD,
so today the mechanism is wired and idle. Committing the pin is the one-line close; the *runtime*
"restore under the CH it was taken on" advice remains advice either way.

**crosvm (v29).** Boot, lifecycle, vsock/agent, tap networking, sessions, and cgroup limits are **validated
live** (§2.5, the `just test-crosvm` matrix); the CLI flag spellings and the seccomp/jail posture were
confirmed against a source-built crosvm and pinned in arg-builder unit tests. **Snapshot/restore is now
shipped** (§2.5, FC-pattern): `snapshot take`/`run --restore` round-trips the block/net/vsock/serial device
set (USB is the one non-`Suspendable` device, dropped via `--no-usb`), validated by the
`snapshot_restore` + `extra_block_survives_snapshot` + `fork_branch_lineage` matrix legs. What remains open:
(1) **concurrent zygote fan-out** — crosvm bakes+requires the vsock CID on restore, so
`restore_rotates_host_paths` is `false` and only *sequential* lineage works (concurrent restores from one
snapshot collide on the baked CID — exactly FC's single-lineage constraint, §8.4). Lifting it needs a
future crosvm that accepts a rotated `--vsock cid=` on restore. (2) **vsock privilege** — in-kernel
vhost-vsock is validated in the **privileged** mode; whether `/dev/vhost-vsock` is reachable in the
**unprivileged** KVM-group mode (or needs a vhost-user-vsock AF_UNIX alternative) is untested. (3)
**virtio-fs** — validate crosvm's in-process `--shared-dir type=fs` and reconcile its
(non-external-vhost-user) framing with the `config_has_vhost_user_device` eligibility law before flipping
`virtio_fs_shares`. (4) **unprivileged vhost-user-net** for the smoltcp NAT. (5) **disk I/O throttling** —
crosvm's `--block` has no bandwidth/iops key, so `disk_io_throttle` is a hard `false` (§2.6); a future
`blkdebug`-style shim is the only path. (6) **control transport** — the shipped choice re-invokes the crosvm
binary as a client; linking `libcrosvm_control` (lower latency, a build/link step) is the recorded
alternative. **Resolved during v29 validation**: (a) crosvm's own multiprocess sandbox is incompatible with
the single-process supervision model (`/var/empty` jail failure), so it runs `--disable-sandbox` + the
Layer-2 jailer deny-list (on for `Enforcing`) — validated to boot, exec, and do tap/netns networking under
the deny-list (§12.2); (b) snapshot/restore over the virtio device set works (baked-CID reuse). crosvm still
runs its KVM-free gates in `just ci`; `just test-crosvm` is the opt-in live suite (kept out of
`test-privileged` because the binary is absent on CI).

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
The **smoltcp NAT bring-up flake** (recorded 2026-07-15): ~10% of networked boots the vhost-user-net UDS
never binds within its 2 s ceiling because `VhostUserDaemon::start` binds lazily from a background
thread; the named fix owner is making `SmoltcpProcess::start` block until the socket is bound (signal
readiness from the daemon thread), which retires both this flake and the QEMU connect race at the
source — promoted here from the implementation notes so it sits on the register, not in a footnote.
**Segment refinements** (v30 ships §6.5 without them, each a deliberate cut): `Egress::Filtered` on a
segment (a per-segment proxy + nft posture — the variant shape keeps it unrepresentable until designed);
a typed netem/impairment API (blocked on hand-assembled `TcMessage`s — the rtnetlink stack types no
netem options; the shipped mechanism is stable names + the harness's own `tc`); `snapshotting` +
`Segment` (restore-time slot/addressing semantics undefined in v30); the **NAT `host_forwards`
TCP port-forward** (FR-V3's other shape — host listener dialing into the guest over the smoltcp NAT;
not taken in v30 because the vsock dial + segment `dial_tcp` cover the requesting topology without
touching the NAT's six-invariant datapath or its open bring-up flake); and daemon/REST exposure of
segments and the raw dial (new wire surface — the presence-attribute codec rule applies, Appendix A
reversal 10).

**Downstream toolkit (v30 residuals).** The prebuilt bootstrap seed ships no resolved-config sidecar
(there is none to copy — recorded on §5.6; the seed is not a fragment consumer). No loadable-modules
kernel pipeline (fragments build `=y`; explicitly not requested — a modules + rootfs-module-tree item
would be its own design). `vmcell_artifact_validator::validate()` hardcodes the Cloud Hypervisor
backend even though every check is generic over `Vmm` — a backend knob on `ValidationOptions` is the
natural extension when a consumer needs it. `validate()` has **no overall wall-clock budget** — each
check carries its own deadline, but a `Full` run boots several VMs sequentially, so "fails loudly, not by
hanging" holds per check and not per battery (plumbing one touches the exhaustive `ValidationOptions` and
every `checks::*` signature). USB-passthrough guest-side coverage beyond enumeration + one class smoke
(per designated device class) is consumer territory.

**One law, one predicate — the consolidations still open.** Each is a second copy of a rule that has one
designated home, kept on the register rather than in a comment because every duplicate so far has
diverged: `bench-vm` hand-rolls the library's `pub(crate)` workspace-root ascent;
`harness::ch_bin()` duplicates `vmcell::artifact::ch_binary_path()` (same env var, same default); and the
integration harness's `computed_cgroup_name` composes a slice name with a local `format!` instead of
`vmcell::naming` (law F2's own rule, in the tests that check it).

**Daemon.** Capping the guest **exec capture host-side**: an `exec` reply carries the command's whole
captured output, so a large enough capture overflows the bridge frame cap. That is now a typed 500
instead of a request wedged forever on a dropped reply, but the reply still has no size ceiling of its
own. A UDS transport under `XDG_RUNTIME_DIR` (alongside the HTTP bind). A warm-pool manager
(`POST /v1/pools`) — because the registry already owns handles, a pool is a **hand-out policy** over the
existing fan-out capability, not a new primitive (§11.4). JWT bearer tokens + per-key scopes at the
existing auth-middleware seam (§11.6). Pause/resume routes. Artifact GC / quota. Streaming upload (v1
reads the file into memory, §11.7).

**Sessions.** Daemon-side streaming (WebSocket or chunked transfer with a `SessionId` sub-protocol, over
streaming `VmEngine` ops). A raw-mode interactive CLI with `SIGWINCH` forwarding. Per-session backpressure
(a credit/window scheme; today the host queue is trusted-unbounded — a recorded trade). PTY `StdinEof`
half-close. `Session::write_stdin`/`close_stdin`/`resize`/`close` can still return `Ok(())` for a short
window after the reader has closed the registry — they observe only the writer channel, which dies one
transport failure later. It is a no-op write, not a hang (the session's `recv()` is already terminal), but
their docs promise `Error::Agent` "if the connection has closed"; closing it properly means a shared
closed-flag on `Session`.

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
allowlist); a deterministic guest clock API; a structured serial-console fault classifier (v30 ships
its first scoped consumer — the kernel-validation battery's missing-symbol classifier, §5.6; the
general typed-fault surface remains); `netem` network fault injection (v30 ships the segment-side
mechanism — stable names a harness drives `tc` against, §6.5 — the typed API remains); virtio-blk error
injection (QEMU `blkdebug`, the piece `DiskIoLimit` throttling doesn't cover, §4.6); a generic
vsock↔TCP bridge (v30's `dial_vsock` covers host→guest raw dial, §3.2; the persistent port-forward
bridge remains); OTLP tracing export; overlay checkpoint/rollback; `kcov`/`gcov` extraction from the
guest; **multi-host** L2 clusters (the single-host case is §6.5's segments as of v30); a `gdbstub`
debug stub; a CPUID / aarch64 capability matrix; scale-to-zero.

**Explicitly out of scope (naming the boundary is the G1 guard, §13).** These are *consumer* layers built
**on** vmcell, never in it: an MCP frontend, a KUnit/LTP kernel-test runner, `rr`-as-payload
record/replay, run bundles, and billing. The core stays a workload-agnostic micro-VM primitive; domain
policy lives in the crate that consumes it.

---
## 18. Delta register: the downstream-platform pass, as directed by v30 — landed

This section is the record of how the v29 build (`vmcell` 0.12) became the system the body describes.
**All nine items are landed and reconciled**; `vmcell` is 0.13, and the per-delta as-built record —
including the deviations from the sketches below and the premises that turned out empirically false —
is `docs/implementation-notes.md` ("v30 delta 1" … "v30 delta 9"). The items are kept verbatim as the
directed shape so a reader can see what was asked against what the notes record was built; where the
two differ, **the notes win** and the body above already states the as-built fact. The register
conventions below are not historical: they are standing rules for the next register.
(The register before this one — the eleven-item v28 pass — is likewise landed;
implementation-notes "v28 — the 0.9 → 0.10 delta register, as built".)

**Bundling and order, as directed.** Deltas 1–8 were **one breaking release, `vmcell` 0.12 → 0.13**
(the breaking edges: `pack_erofs_with_injection` gains a parameter, `PerVmResources` gains the exhaustive-by-design
`segment` field, `ResolvePinsStage` changes shape), with a changelog entry in the
`crates/vmcell/Cargo.toml` comment ledger. **Delta 9 is separable and deliberately last** — its own
requester ranks FR-V5 "nice-to-have, not a v1 dependency" — so it rides the 0.13 pass only if it happens
to land with it, and is otherwise its own later bump (it adds a field to the exhaustive
`VmmCapabilities`, the 0.11→0.12 `disk_io_throttle` precedent). Internal dependencies: delta 3 builds on
delta 1 (the overlay feeds the labelled build); deltas 4–5 build on 3 (the battery validates what the
toolkit builds; the example exercises 1–4 together); deltas 6–8 are independent of the toolkit
cluster, with one cross-edge among them (below). The P-blocking order for the downstream consumer is 1 → 3 → 4 → 5,
then 2 (documentation can trail the mechanisms by days, not weeks); 6 and 7 in any order — but **delta
8's live gate consumes delta 7's `echo-server` applet** (its segment listener), so land 7 before 8's
live legs (or land the applet with whichever comes first); **delta 9's live leg additionally consumes
delta 3's toolkit** (the `vmlinux-usbhost` label) — a second reason it is last.

**Register conventions — four rules the v24–v28 passes taught** (the implementation-notes records
cited per rule are the evidence; each rule exists because its absence cost real time):

- **Sketched names and signatures are advisory; the behavior and its gate bind.** (`clone_into` had to
  become `clone_tree` for a trait-collision reason no sketch could foresee — the v25 record, item (b);
  `agent()` had to keep a `timeout` the sketch dropped — the v28 record, Delta 1.) A delta below is
  implemented correctly when its *behavior* and *gate* hold; a name or signature may shift for a
  recorded reason, reconciled in the implementation notes — never silently.
- **Premises are verified anchors, not memory.** (The v28 record: delta 5's "no consumer" and delta 6's
  "none is known to use it" were both empirically false. This pass added five more: delta 4's
  `EAFNOSUPPORT` serial signature and its single-clause reading of `VFS: Unable to mount root fs`,
  delta 7's "EOF propagates in both directions", delta 8's bridge-unique member MACs and its
  already-sweeps-segments sweeper, and delta 9's "every backend's `restore()` rejects a non-snapshotting
  config" — each was a *shipped-fact* claim, and each cost a defect.) Every current-state premise below
  carries its symbol anchor, verified against the 0.12 tree on 2026-08-11; if the tree has moved when
  you implement, re-verify the anchor before cutting, and treat a stale premise as a stop-and-check,
  not a nuisance.
- **Filesystem- and process-touching changes name their live gate up front.** `FakeVmm` and the daemon's
  `FakeHandle` are fs-blind — the lineage `create_dir_all` bug was invisible to every fake-driven test
  and caught only live (the v25 record, item (e); Appendix A, reversal 11). Deltas 5–8 each name the
  live leg that is not optional.
- **Any new wire surface carrying serde presence attributes round-trips on the codec it ships over**
  (the postcard trap — the v24-pass-2 record, item (i); Appendix A, reversal 10). v30 adds no new
  cross-process codec — and the §17 note on future daemon exposure of segments/dial restates the rule
  where it will next bite.

Each item: the verified **premise**, **what** changes, **why**, the **migration** for a caller, and the
**gate** that pins it.

1. **The pins overlay** *(FR-V6; §10.2)*. *Premise:* `ResolvePinsStage` has one pub field `pins_file`
   (`artifact/mod.rs:1019`); the workspace-root hardcoding lives in its callers —
   `fast_artifacts_fingerprint` (`artifact/mod.rs:176`), `build_fast_pipeline` (`:215`), and
   `vmcell-cli`'s private `pins_path()` (a near-duplicate of `workspace_root()`); no `--pins` or `VMCELL_PINS` exists;
   `parse_pins_json` silently ignores unknown top-level keys. *What:* `ResolvePinsStage` gains
   `overlay_file: Option<PathBuf>` with key-level overlay-over-embedded-baseline semantics (baseline =
   the committed `pins.json` via `include_str!`); `VMCELL_PINS` (env) and `--pins` (CLI, retiring
   `pins_path()`) set it; the **overlay parser is stricter than the baseline's** — an overlay top-level
   key matching no known pins namespace is a hard error naming it (§10.2; a typo'd *override* would
   otherwise silently resolve from the baseline, the accept-then-ignore class); the stage's `cache_key`
   folds both files' content. *Why:* a downstream extends the registry (fragments, labels) without
   forking `pins.json` or losing the pipeline — the exact forked-pins maintenance FR-V6 retires;
   fallback-to-baseline is the vetted default, and both typo shapes fail loud (a mis-referenced key at
   resolution, a mis-spelled key at overlay parse). *Migration:* none for existing callers (no overlay
   ⇒ baseline behavior byte-identical). *Gate:* overlay-wins / falls-back /
   referenced-but-absent-fails-loud-naming-the-key / **misspelled-override-key-rejected** unit tests;
   an overlay-edit-invalidates-the-key test; the example workspace (delta 5) as the live consumer.
2. **The downstream contract: `VMCELL_*` env table, git-dep guidance, the contract-surface list**
   *(FR-V6; §10.4)*. *Premise:* README has zero consuming-as-a-dependency guidance; the
   `[patch.crates-io]` vendored-vhost stanza (root `Cargo.toml:65-67`) does not propagate to a git-dep
   consumer's workspace; `VMCELL_ROOTFS` is a full ensure-bypass and `VMCELL_KERNEL` a path redirect
   (`artifact/mod.rs:43-69,114-118`) — accurate but undocumented; `cargo semver-checks` covers `-p
   vmcell` only (`justfile:239`, `ci.yml:156-159`). *What:* the §10.4 contract section — the named
   surface list, the env table with specified semantics, the git-dep guidance (patch-stanza replication
   with its when-load-bearing scoping, the path-independent `scripts/check-vendored-vhost.sh`, the
   per-workspace bless note) — plus `cargo semver-checks -p vmcell-artifact-validator`. *Why:* the
   FR-V1 workaround runs entirely on this seam today with no stability promise, and the patch trap is a
   silent-behavior-loss hazard a consumer cannot discover before it bites. *Migration:* none (docs +
   one script + one CI line). *Gate:* the vendor-assertion script both ways — green as the positive
   control in the example workspace (whose manifest replicates the stanza against a vhost-resolving
   feature set; `cargo tree` only) and red on a temp copy with the stanza dropped; the semver-checks
   extension live in CI; the example workspace README section exercised by a fresh-clone CI run.
3. **The labelled-kernel build path, completed** *(FR-V1; §5.5–§5.6, §10.1)*. *Premise:* fragments are
   unreachable from the CLI (`build-kernels` passes `fragments: None`; `main.rs:441-446`); the `kernels`
   registry entries carry only `source_url`/`source_sha256` (`pins.json`); `kernel_stage()` **silently
   drops** label+fragments when the source is Prebuilt (`main.rs:278-301`); label build order is
   sorted today only as an *unpinned artifact* of serde_json's default `BTreeMap` backing (nothing
   asserts it; a transitive `preserve_order` would silently change it); a missing fragment folds
   **empty bytes** in `cache_key()` (the `unwrap_or_default` at `kernel.rs:178-190`) while `run()`
   hard-errors (`kernel.rs:348-358`); neither compiling builder exports the post-`olddefconfig`
   `.config` (host: left behind in the persistent `kernel-build<suffix>` workdir — unaddressed,
   overwritten by the next build, never content-addressed with the vmlinux, `kernel.rs:212-216,397`;
   in-VM: dies with the builder VM, `vmcell-kernel-builder/src/lib.rs:159-219`). *What:*
   `kernels.<label>` entries accept `fragments: [<NAME>, …]`; sorted label order is made explicit and
   pinned; Prebuilt + label/fragments is a typed error; a missing fragment folds a distinct marker in
   the key; both compiling producers emit `vmlinux[-<label>].config` as a content-addressed sibling
   artifact; a labelled build logs which producer ran; a library entry
   (`build_labelled_kernel(label, &env)`-shaped) assembles ResolvePins(+overlay) → the kernel stage for
   git-dep callers — as built `(label, target_dir, overlay_file)`, host-`make` producer only, for the
   acyclicity reason §5.6 records. *Why:* this is FR-V1's build half — the P-blocking item — built
   almost entirely from shipped parts; the resolved-config sidecar is the anti-silent-drop half of "assert against the
   result, not the fragment". *Migration:* none for existing pins (no `fragments` key ⇒ today's
   behavior). *Gate:* a fragment build asserts the sidecar exists and contains a fragment symbol;
   prebuilt-with-label rejects red-on-inverse; the sorted-order and missing-fragment-marker unit tests;
   the example workspace's live fragment build (delta 5).
4. **The validation battery names what a bad kernel is missing** *(FR-V1; §5.6)*. *Premise:*
   `vmcell_artifact_validator::validate(&ArtifactSet, &ValidationOptions)` already runs the named
   check battery against explicit paths and refuses green-by-skip on a KVM-less host
   (`vmcell-artifact-validator/src/lib.rs:validate`); the workspace's only serial classifier is
   `contains_panic`'s three literal panic strings (`vmm/mod.rs:29-63`) — no VFS-mount-failure or
   vsock-family detection exists anywhere; a bogus kernel today fails `boot.kernel_banner` /
   `boot.agent_ready` by raw timeout (the smoke test pins this red path). *What:* a pure serial-log
   classifier mapping the known §5.4 contract-violation signatures into the failing check's message,
   plus `KconfigValues::parse` for resolved-config assertions; the battery is promoted to contract
   surface (delta 2). *As built (§5.6):* the signatures are **keyed on the emitters' real text**, which
   falsified two of this sketch's three examples — `VFS: Unable to mount root fs` is the shared panic of
   a missing root device *and* a missing root filesystem (device signatures are checked first, with
   their own variant and virtio symbol set), and `EAFNOSUPPORT` appears in no serial log (the vsock
   clause keys on the guest agent's own PID-1 lines). The third holds: no banner ⇒ not a direct-boot
   `vmlinux`. Rendering split into `explain_boot_failure(log, base)` and
   `explain_without_serial(base, why)`, chosen by whether console evidence exists, wired at three
   points because a bad kernel fails in three shapes. *Why:* "fails a
   named check loudly, not by hanging" is FR-V1's acceptance bar; the classifier is the §17
   serial-fault-classifier idea shipped at its smallest useful scope. *Migration:* none (additive).
   *Gate:* classifier unit tests red-on-inverse on canned serial logs; the live garbage-kernel red path
   stays; the example workspace consumes `KconfigValues` (delta 5).
5. **The out-of-tree example workspace** *(FR-V1/FR-V6; §5.6, §10.4)*. *Premise:* no downstream-shaped
   consumer exists anywhere in the repo (the only `examples/` is a cargo example inside `vmcell`);
   nothing exercises the git-dep consumption path, which is exactly why it drifted to "semi-public in
   practice". *What:* `examples/downstream-kernel/` — its own workspace outside the vmcell members,
   consuming `vmcell` + `vmcell-artifact-validator` as a consumer does — carrying its own pins overlay
   and the neutral `IKCONFIG`/`IKCONFIG_PROC` fragment; it builds `vmlinux-ikconfig` through deltas
   1+3, asserts the fragment survived via delta 3's sidecar + delta 4's parser, runs the battery,
   proves `/proc/config.gz` **in-guest** (the data-plane assertion that the fragment took), pins the
   **harness getters' downstream contract** (§10.4 — `get_vmlinux`/`get_rootfs` return the named paths
   under the full `VMCELL_*` override set, and fail loud naming the two-step route without it), and
   serves as the vendor-assertion positive control (delta 2). Its CI job builds and runs it — including
   the exact documented CLI invocations (§10.4) — on every push; the KVM leg runs on the self-hosted
   runner (`ci.yml`'s `[self-hosted, linux, kvm]` job). *Why:* the serial-nexus lesson the FR cites verbatim — an
   out-of-repo pattern stays honest only if an out-of-tree consumer builds on every push. This **is**
   the toolkit's gate; without it deltas 1–4 are another unpromised surface. *Migration:* n/a (new).
   *Gate:* itself — plus a deliberate red-on-inverse check during landing (break the overlay resolution
   or drop the sidecar; the example job must redden). **Live leg non-optional** (fs-blind fakes cannot
   see any of this).
6. **Downstream rootfs extra-files on the one pack tail** *(FR-V4; §4.2, F5)*. *Premise:*
   `pack_erofs_with_injection(tar_streams, inputs, out, agent_musl)` has exactly two production callers
   (the OCI tail, `oci.rs:220`; the mmdebstrap stage, `vmcell-rootfs-builder/src/lib.rs:262`) — the
   CLI reaches it only through `RootfsStage`; the injection manifest is fixed (`rootfs/mod.rs:307-327`
   — agent, two CA paths, guest-tools + three symlinks; **no** collision handling: `entries.insert`
   last-wins, and an injected symlink can silently clobber an injected file);
   `fold_rootfs_injection_identity` takes no extra-files argument; the manifest dest type is
   `&'static str`. *What:* `ExtraFile { dest, src, mode }`; the pack tail gains `extra: &[ExtraFile]`
   (dest type widened); insertion after the layer merge, before the unconditional vmcell injections;
   the `is_reserved_injection_path` predicate + duplicate-dest rejection (F5); explicit per-file mode
   (no heuristic inheritance); the identity fold gains sorted `(dest, mode, content-hash)` triples and
   **both** stage `STAGE_VERSION`s bump; CLI `--inject` with a unit-tested parser. *Why:* per-boot
   `put_file` pushes are hot-path latency and break image-is-the-artifact; the collision policy is the
   difference between composition and silent clobbering. *Migration:* existing callers pass `&[]`.
   *Gate:* injection-layer tests (present + mode; reserved/duplicate reject red-on-inverse); cache-key
   invalidation; **live leg**: boot + in-guest `cat`/`stat` before first exec.
7. **The raw vsock dial** *(FR-V3; §3.2)*. *Premise:* the hybrid `CONNECT/OK` prologue is **inline** in
   `AgentClient::connect_framed` (`agent/mod.rs:328-361`; the socket-open `connect_control_stream` and
   dispatch `hybrid_prologue_port` halves are already factored); `ControlStream` is `pub(crate)`;
   `MicroVm` derives the endpoint per call from `instance.vsock_endpoint()`; no fail-fast dead-port
   signal exists (EOF-without-OK and accept-and-hang both fold into retry-until-`Error::Timeout`); the
   CONNECT-write-failure path retries without backoff (a recorded micro-trap); the vsock *device* is
   attached unconditionally — independent of `cfg.init` — in every backend (CH's `ChVsock` in the
   create payload, `cloud_hypervisor.rs:611-613`; FC's vsock PUT; QEMU's device/daemon block in
   `spawn_qemu`; crosvm's `--vsock cid=` in `build_crosvm_run_args`). *What:* extract the
   prologue into one shared fn (fixing the no-backoff retry in passing);
   `MicroVm::dial_vsock(&self, port, timeout) -> Result<VsockDial>` (a public newtype over
   `ControlStream`, AsyncRead+AsyncWrite, unwind-safety preserved) that interprets refusal signals
   typed and fail-fast instead of reusing the boot-wait retry loop; bypasses the custom-init guard
   (documented — the device-unconditional premise above is what makes the bypass sound); a guest-tools
   `echo-server` applet (`--vsock`/`--tcp`; the sync `vsock` crate the agent already uses) + its
   manifest symlink **and** manifest pin-test update. *Why:* FR-V3's cheapest shape — an in-guest listener reachable from the
   host with no IP stack, on every backend and both modes, and independent of the agent. *Migration:*
   none (additive). *Gate:* the KVM-free mock-handshake test (the `exec_vsock.rs` template) for the
   extracted prologue + dead-port EOF interpretation; **live matrix leg**: echo round-trip + EOF both
   directions per endpoint arm + dead-port typed error within the bound; plus a **custom-init variant**
   (boot with `init=` pointing at the `echo-server` applet itself — no agent anywhere — and dial it
   raw), so the guard-bypass claim is validated live, not presumed.
8. **VM-to-VM segments** *(FR-V2, plus FR-V3's privileged host→guest shape; §6.2, §6.5)*. *Premise:*
   nothing creates a bridge or veth anywhere in the tree; each privileged VM is alone in
   `<prefix>-net-<vmid>` with its tap `TUNSETPERSIST`'d and the fd deliberately dropped (single-opener;
   `net/tap.rs:146-242`); the VMM enters its netns via `build_vmm_cmd`'s pre-exec `setns`
   (`vmm/mod.rs:234-280`); `NetConfig` is `#[non_exhaustive]` so a new variant is **not** a compile
   error in the out-of-tree backends — but `PerVmResources` is deliberately exhaustive;
   `VmidAllocator`'s H1 flock claim core is id-space-agnostic but hardcodes its range and dir
   (`orchestrator.rs:171-298`); the sweep keys on `trailing_vmid` against live *vmids*; rtnetlink 0.21
   has typed `LinkBridge` but **no typed netem**; the proxy's capture-root → `setns` → bind →
   re-enter-root pattern is at `proxy/mod.rs:160-310`. *What:* everything §6.5 specifies —
   `NetConfig::Segment { segment }`, `NetSegment`/`SegmentIdAllocator` (extracted, parameterized claim
   core; `/tmp/vmcell-segid`), the segment netns + bridge + enslaved member taps, `segment_ip_math` on
   the disjoint `10.201/16`, `res.segment: Option<SegmentMembership>` on the exhaustive
   `PerVmResources` + the shared `net_uses_tap` predicate, Arc-holder teardown, the `-seg-` naming +
   sweep class with its own live-segid set, `NetSegment::dial_tcp`, and the `build()` rejections
   (`snapshotting`+Segment). *Why:* the true two-kernel client/server topology is structurally
   impossible today; the design reuses the tap machinery so the new surface is where taps *live*, not a
   new datapath. *Migration:* none for existing configs; backends recompile against the new
   `PerVmResources` field (the intended fail-loud). *Gate:* the §6.5 battery — KVM-free math/naming/
   allocator-race/rejection tests plus the **live** two-VM bidirectional TCP + off-segment negative +
   `dial_tcp` + netem-delta + residue + sweep legs (fs/process effects fakes cannot see).
9. **`usb_host_passthrough`** *(FR-V5 — separable, explicitly last; §2.1, §2.4)*. *Premise:*
   `VmmCapabilities` is deliberately exhaustive with five production construction sites + three
   test-fake literals — eight literal constructions a new field breaks, the intended fail-loud (two
   further test fakes stub `capabilities()` with `unreachable!()` and are unaffected); QEMU's argv is
   assembled inline in `spawn_qemu` (`vmcell-qemu/src/lib.rs:534-830`; only the fixed machine flags,
   including `-nodefaults`, are extracted into `push_fixed_qemu_flags` — no pure, goldenable full-argv
   helper exists) with zero USB anywhere; crosvm always passes `--no-usb` because its xhci is not
   `Suspendable` (`vmcell-crosvm/src/lib.rs:230`); CH has no upstream USB; `docs/requirements.md:76`
   lists peripheral passthrough as tie-breaking nice-to-have only. *What:* the ninth capability field (QEMU `true`, others `false`, feature string == field
   name); `VmConfig::usb_host_devices: Vec<UsbHostDevice>`; the QEMU xhci + usb-host argv pair emitted
   by a **pure extracted args helper** (crosvm's `build_crosvm_run_args` precedent — QEMU's inline
   assembly is why its argv was never goldenable); `build()` rejects `snapshotting`+USB and duplicate
   devices; non-QEMU `create()` rejects typed; the opt-in `just test-usb-passthrough` recipe
   (`VMCELL_TEST_USB_DEVICE=<vid>:<pid>`, the `test-crosvm` staging pattern) boots a
   `vmlinux-usbhost` kernel built through the delta-3 toolkit from a vmcell-owned *generic* xhci/USB
   fragment and asserts in-guest sysfs enumeration of the designated device + a class smoke check.
   *Why:* the capability-honesty doctrine turned toward host devices: one backend can do this, so the
   flag says exactly that, and the flag+config+typed-refusal pattern is the reusable part. The
   device-node (`/dev/bus/usb`), `-sandbox`, and jail interactions are empirical questions the opt-in
   live leg answers **before** the flag ships `true` — a capability flag is validated, never presumed
   (AGENTS.md rule 5). *Migration:* every `VmmCapabilities` literal adds the field (compile-driven);
   version bumps per the ledger. *Gate:* the argv golden test, the ninth honesty pin across all four
   backends, both `build()` rejections red-on-inverse, and the opt-in live leg.

---
## Appendices

The per-finding records that the v27 body carried inline (the `M-*`, `H-*`, `EXP-*`, `AGENT-*` IDs)
resolve to the project's working documents and are **not** reproduced here: performance experiments in
`docs/historical/44-claude-perf-experiments.md`, the performance investigation log in
`docs/historical/45-claude-perf-investigation.md`, the code-review findings in
`docs/historical/46-claude-code-review.md` (and the later passes through
`docs/historical/72-claude-code-review.md`), and
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
- **CVE-2026-45782 is fixed in CH v52.0.0** — but vmcell **pins no CH version**: `pins.json` carries no
  `cloud_hypervisor` key and the README installs CH from git HEAD, so what a host actually runs is
  whatever it built (the live matrix ran on 54.0.0). The snapshot cache key's fold of the
  `cloud_hypervisor` pin (§10.2) is the mechanism that would make a bump invalidate stale snapshots;
  committing the pin is what would turn "we are past the fix" from an assumption into a fact.

### Appendix D — Prior art

Projects consulted while designing this, and the one idea taken from each: **cocoonstack / cocoon** (a
micro-VM sandbox shape); **tinylabscom / mvm** (a minimal Rust VMM-driver approach); the **microvm.nix**
write-up (declarative micro-VM composition); **agentkernel / vmexec** (agent-workload VM execution);
**smoltcp + vhost-user-backend** (the in-process userspace-net datapath, §6.2); and the **Kata
`agent-ctl`** tooling (the guest-agent control-protocol shape, §3). None is a dependency; each informed a
boundary or a protocol choice.

### Appendix E — Section map, v27 → v28

The code comments and `docs/` cross-references written against v27's section numbers still point at v27
numbering; when updating them (a delta-register follow-up, §18), use this map. v29 and v30 renumbered
nothing — v29 inserted §2.5 (shifting only the capability matrix to §2.6), and v30's new subsections
(§5.6, §6.5, §10.4) append inside their sections — so this map remains the only translation needed. The rewrite merged the
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
