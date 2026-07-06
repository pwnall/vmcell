# vmcell — Design Document (v24 amendment): privileged-window hardening

> **v24 (this revision) — privileged-window hardening.** A focused amendment layered on the v23 unified
> design (`docs/59-claude-design-v23.md`), in the same shape v21/v22 were amendments on v20: the base
> architecture is unchanged, and this document adds one component — **Part VII / §20**, the
> privileged-window hardening the roadmap named in §17 ("each VMM's own seccomp, a jailer-equivalent, and
> a setup broker — the recommended privilege boundary for the daemon/API mode"). It graduates that item
> from forward-work to **built, in three layers**:
>
> 1. **VMM seccomp** — every backend runs under its own audited seccomp-BPF filter, selected by **one
>    predicate** (`vmm_seccomp_args`) that maps a `VmmSeccomp` policy to each backend's native flag
>    (`cloud-hypervisor --seccomp`, `firecracker --no-seccomp`/built-in, `qemu -sandbox`). This closes a
>    real hole: QEMU was spawned with **no** `-sandbox`, so it ran unconfined.
> 2. **Jailer-equivalent** — a Firecracker-jailer-style pre-exec hardening of the VMM child, applied in
>    the existing `build_vmm_cmd` `pre_exec` window: `PR_SET_NO_NEW_PRIVS`, `RLIMIT_CORE=0` (+ optional
>    `RLIMIT_FSIZE`/`RLIMIT_NOFILE`), an **opt-in** ambient-capability clear, `PR_SET_DUMPABLE=0`, and an **optional**
>    coarse host-side seccomp deny-list built with **seccompiler**. The pure `JailSpec` lives in
>    `vmcell::vmm::jail`; the async-signal-safe `apply_jail` is the only impure edge.
> 3. **Setup broker** — the privilege boundary for the daemon/API mode. The verified Linux constraint
>    (`setns(CLONE_NEWNET)` needs `CAP_SYS_ADMIN` in the netns's owning user namespace, so an
>    unprivileged process can **never** join a broker-created netns) forces the **spawner model**: a
>    minimal privileged `vmcell-broker` child holds the three caps, performs netns/tap/nft/cgroup setup
>    **and** the jailed VMM spawn, and hands a **pidfd** back over a `SOCK_SEQPACKET` socketpair to a
>    **cap-dropped** parent that serves the HTTP surface. Ships as a complete, fake-tested crate +
>    binary + `BrokerClient`; the `vmcelld` cutover (drop-caps-and-broker instead of retain-caps §12.14)
>    is the one **KVM-host-validated** step that remains.
>
> **Licensing (called out because it is load-bearing here).** The seccomp layer uses **seccompiler**
> (`Apache-2.0 OR BSD-3-Clause`, both allow-listed) — the pure-Rust rust-vmm library **Cloud Hypervisor
> and Firecracker themselves** use, so vmcell adopts no second syscall-filter law. Every alternative was
> rejected for licensing: `seccomp` (LGPL-2.1) and `birdcage` (GPL-3.0) carry copyleft crate licenses,
> and `libseccomp`/`syscallz` are the dangerous case — permissive Rust metadata that **links the LGPL-2.1
> libseccomp C library**, so `cargo deny`'s crate-license check passes *green* while the build in fact
> links copyleft (§20.6). That trap is now **machine-enforced**: `deny.toml` bans those crate names by
> policy, since the license gate alone cannot catch a C library pulled in through `build.rs`/`pkg-config`.
>
> **Amends:** **§2.2** (a new "Privileged-window hardening" row), **§10.1** (one new workspace member,
> `vmcell-broker`), **§10.2** (`VmConfig` gains `vmm_seccomp` + `jail`), **§12** (new invariants
> **§12.21–§12.23**), **§14** (new gates), **§16** (the hardening moves from a forward-work bullet to
> "built, with the daemon cutover as the remaining KVM step"), **§17** (privileged-window hardening
> struck from the backlog), and **§18.2** (the setup broker is built; the retain-caps single-process form
> remains the default until the cutover is host-validated). Version bumps: `vmcell` **0.6.0 → 0.7.0**
> (the additive `vmm_seccomp`/`jail` config + the `vmm::seccomp`/`vmm::jail` modules + the `build_vmm_cmd`
> `JailSpec` param), `vmcell-privilege` **0.1.0 → 0.2.0** (the broker parent cap-drop plan), and
> `vmcell-broker` versions from **0.1.0**. `vmcell-daemon` is unchanged this pass — routing its launcher
> through `BrokerClient` is part of the KVM-validated cutover (§20.9). All new library surface is additive
> and `cargo semver-checks`-clean on the existing types.

---

## Part VII — Privileged-window hardening

## 20. Shrinking and confining the privileged window

### 20.1 The problem this solves

vmcell's privileged operating mode (§6.4) and the `vmcelld` daemon (§18.2) run with three real
capabilities — `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE` — held for the life of the process
(§12.14). Two facts make that a security concern worth a dedicated component:

- **The VMM subprocess is the largest attack surface in the system.** Cloud Hypervisor / Firecracker /
  QEMU parse the guest's virtio rings, the guest kernel's device I/O, and (on the egress path) network
  bytes. A VMM escape lands in a process that vmcell spawned; today that process inherits an ambient
  environment and is confined only by whatever the VMM does to itself.
- **The daemon co-locates the caps with the network-facing HTTP surface.** `vmcelld` holds all three
  caps *and* terminates the REST API in one process (§18.2). Any memory-safety or logic bug reachable
  through the request parser executes with the union of the three caps in the initial user namespace.
  §18.2 already records this and names the setup broker as "the recommended hardening … forward work."

The three layers below attack these in order of blast radius: **confine the VMM** (its own seccomp +
a jailer-equivalent), then **separate the daemon's privilege from its network surface** (the broker).
Each layer is independently useful and independently gated; none depends on the next shipping.

### 20.2 The three layers at a glance

```
  ┌─ unprivileged parent (vmcelld) ── HTTP/REST + registry ─────────────────┐
  │   caps: NONE (dropped after fork)   no_new_privs=1                       │
  │        │ typed request / pidfd reply (framed postcard + SCM_RIGHTS)      │
  │        ▼  socketpair(AF_UNIX, SOCK_SEQPACKET|CLOEXEC)                    │
  │   ┌─ vmcell-broker (privileged child) ── the fixed, audited menu ──┐     │  Layer 3
  │   │  caps: NET_ADMIN + SYS_ADMIN + DAC_OVERRIDE (nothing else)     │     │  setup broker
  │   │   SetupNetwork · CreateCgroup · SpawnVmm · Teardown · Sweep    │     │
  │   │        │ fork → setns(netns) → cgroup → apply_jail → seccomp → execve      │
  │   │        ▼                                                       │     │
  │   │   ┌─ VMM child (cloud-hypervisor / firecracker / qemu) ──┐     │     │  Layer 2 (jailer)
  │   │   │  no_new_privs=1 · ambient caps cleared · RLIMIT_CORE=0│     │     │  + Layer 1
  │   │   │  · dumpable=0 · [opt] host seccomp deny-list          │     │     │  (--seccomp true /
  │   │   │  · the VMM's OWN native seccomp filter (Layer 1)      │     │     │   -sandbox on)
  │   │   └───────────────────────────────────────────────────────┘     │     │
  │   └─────────────────────────────────────────────────────────────────┘     │
  └───────────────────────────────────────────────────────────────────────────┘
```

**What ships in v24 vs. what is KVM-validated forward work** (stated up front, honestly — §20.9 expands):

| Layer | Ships now (in `just ci`, gated) | KVM-host-validated forward work |
|---|---|---|
| 1 · VMM seccomp | `VmmSeccomp` config + `vmm_seccomp_args` predicate wired into all three backend spawns; golden-args + `Unsupported`-combo tests | confirm a seccomp'd guest boots on each backend on a KVM host |
| 2 · jailer-equivalent | `JailSpec` + `apply_jail` in `build_vmm_cmd`; a **root-free, KVM-free** gate reads a stand-in child's `/proc/self/status`; **live-validated on a KVM host** (`no_new_privs`+`RLIMIT_CORE=0`+`non_dumpable` non-breaking across all 3 backends' cold/restore/egress paths; `clear_ambient` defaulted OFF after it broke restore-with-tap, §20.9) | the `clear_ambient`/seccomp-deny-list defaults flip only with the fd-passing/uid-drop increment |
| 3 · setup broker | full `vmcell-broker` crate: framed protocol (codec round-trip + over-cap reject), parent **priv-drop plan** (pure, red-on-inverse), broker dispatch against the injected `Netlink`/`NftApplier`/`CgroupFs` seams, socketpair+fork+pdeathsig transport, `BrokerClient` | the `vmcelld` cutover from retain-caps (§12.14) to fork-broker-then-drop; the live spawner path |

### 20.3 Layer 1 — the VMM's own seccomp filter (one predicate, three backends)

Each backend ships an audited seccomp-BPF filter; the job here is to **enable the strictest practical one
on every backend, fail loud when a policy cannot be honored, and never leave a backend unconfined by
default.** One law owns the mapping:

```rust
/// The requested confinement for the VMM subprocess's OWN seccomp filter.
pub enum VmmSeccomp {
    Enforcing,  // default: each backend's audited filter, killing on a disallowed syscall
    Log,        // observe-only (audit), for debugging a filter false-positive
    Disabled,   // no VMM seccomp — must be asked for explicitly; never a silent default
}

/// The ONE function that turns (backend, policy) into the CLI tokens to append.
/// Pure, unit-tested against golden output and against every unsupported combo.
pub fn vmm_seccomp_args(backend: &str, policy: VmmSeccomp) -> Result<Vec<String>>;
```

Per-backend, from the verified native semantics:

- **Cloud Hypervisor** — `--seccomp <true|false|log>` (default `true`). `Enforcing → ["--seccomp","true"]`,
  `Log → ["--seccomp","log"]`, `Disabled → ["--seccomp","false"]`. vmcell passes it **explicitly** rather
  than relying on the default, so a future CH default flip cannot silently disable it (defaults get the
  strictest scrutiny, §12.2).
- **Firecracker** — the built-in advanced filter is on unless `--no-seccomp` is passed. `Enforcing → []`
  (keep the built-in), `Disabled → ["--no-seccomp"]`. FC has **no** observe-only mode, so
  `Log → Error::Unsupported { vmm:"firecracker", feature:"seccomp_log" }` — fail loud, do not silently
  fall back to enforcing (a caller who asked to *debug* a filter must know the mode is unavailable).
- **QEMU** — `-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny`
  (libseccomp-backed; default is **off**, which is the hole this closes — QEMU was spawned with no
  `-sandbox`). `Enforcing →` that token list, `Disabled → []`, `Log → Unsupported` (QEMU has no audit
  mode for `-sandbox`). A QEMU built without libseccomp errors out on `-sandbox on` — which is the
  **desired** fail-loud, not a regression: a QEMU that cannot enforce the sandbox must refuse rather
  than run unconfined.

The predicate returns `Error::Unsupported` (matchable, typed) for the two impossible combos above rather
than degrading — the §7.2 capability-honesty contract applied to seccomp. `VmConfig.vmm_seccomp` defaults
to `Enforcing`; `Disabled` is a deliberate, logged opt-out (the QEMU `spawn=deny` caveat is the one real
reason a workload might need it — a VMM feature that forks). The one-law test builds a cmdline for every
(backend, policy) pair and asserts the golden tokens, so adding a backend without wiring its seccomp flag
goes red — the same discipline as `mac_math` and `config_has_vhost_user_device`.

### 20.4 Layer 2 — the jailer-equivalent (pre-exec hardening of the VMM child)

Firecracker's `jailer` is a privileged pre-exec wrapper: it sets up cgroup + netns, `pivot_root`s into a
per-VM chroot, drops to a confined uid/gid, sets rlimits, and execs the VMM — which then installs its
**own** `PR_SET_NO_NEW_PRIVS` + seccomp (the jailer does *not*; that is a common misconception). vmcell
already owns the equivalent of the jailer's netns + cgroup setup (§6.4). Layer 2 adds the **remaining
hardening the jailer applies to the child**, in vmcell's existing `build_vmm_cmd` `pre_exec` window
(where the netns `setns` already happens), plus the `no_new_privs`+seccomp the *VMM* would otherwise do
for itself — belt-and-suspenders, since we cannot audit every backend's self-hardening.

The split mirrors `plan_privilege_transition`/`apply_privilege_transition` (§18.2): a **pure `JailSpec`**
and a thin **async-signal-safe `apply_jail`** — the only impure edge, integration-tested.

```rust
// vmcell::vmm::jail — seccompiler + libc; the async-signal-safe `apply_jail` is the only impure
// edge. Shared by the in-process spawn (build_vmm_cmd) AND the broker's SpawnVmm (one jail, two
// callers). `JailConfig` (in vmcell::config, serializable, no compiled BPF) is the pure config;
// `jail_spec_from_config` compiles the optional deny-list pre-fork into this runtime `JailSpec`.
pub struct JailSpec {
    pub no_new_privs: bool,        // prctl(PR_SET_NO_NEW_PRIVS, 1) — default true
    pub clear_ambient_caps: bool,  // prctl(PR_CAP_AMBIENT_CLEAR_ALL) — default FALSE (VMM needs CAP_NET_ADMIN, §20.9)
    pub non_dumpable: bool,        // prctl(PR_SET_DUMPABLE, 0) — default true (blocks same-uid ptrace)
    pub rlimit_core: Option<u64>,  // RLIMIT_CORE — default Some(0): no core dump can leak guest RAM (§12.18)
    pub rlimit_fsize: Option<u64>, // RLIMIT_FSIZE — default None (a snapshot writes a guest-RAM-sized file)
    pub rlimit_nofile: Option<u64>,// RLIMIT_NOFILE — default None; set for a tighter fd ceiling
    pub seccomp: Option<Arc<BpfProgram>>, // an optional coarse host deny-list, compiled pre-fork
}

/// Applies the spec in the forked child, pre-exec. Async-signal-safe: raw libc prctl/setrlimit/
/// seccomp on already-allocated inputs — no allocation, no non-reentrant libc, matching the
/// existing `enter_netns` closure's contract. Order is load-bearing (see below).
pub fn apply_jail(spec: &JailSpec) -> io::Result<()>;
```

**Order** (after the existing `setns`, which needs the caps the child still holds pre-exec): rlimits →
`non_dumpable` → `clear_ambient_caps` (if set) → `no_new_privs` → seccomp (`SECCOMP_SET_MODE_FILTER`
requires `no_new_privs` first) → `execve`. `RLIMIT_FSIZE` defaults **unset** because a snapshot-eligible
VM writes a guest-RAM-sized suspend file (setting fsize=0 like a naïve jailer would break snapshot).
`RLIMIT_CORE=0` is the default because a VMM core dump writes guest memory — potentially secrets — to
disk, exactly the §12.18 surface.

**`clear_ambient_caps` defaults OFF — empirically forced (§20.9).** An earlier draft cleared the VMM's
ambient set on the theory that the VMM "already runs with no capabilities." That is **false** in vmcell's
current architecture: on the `vmcell-test-runner` path the three caps live in the **ambient** set (that is
how the test process holds them), so a fork+exec'd VMM **inherits** them — and it **needs**
`CAP_NET_ADMIN`, because a restored Cloud Hypervisor's `TapSetMac` (`SIOCSIFHWADDR`) and Firecracker's tap
re-open both `EPERM` without it (validated on a KVM host — clearing ambient reddened every
restore-with-tap test). Cold boot survived because it does not re-set the tap MAC that way; restore does.
So `clear_ambient_caps` ships **default off**, an opt-in reserved for the fd-passing / uid-drop path where
the VMM is handed a fully-configured tap and genuinely needs no caps (§20.9). The other three hardening
steps (`no_new_privs`, `RLIMIT_CORE=0`, `non_dumpable`) are on by default and validated non-breaking
across all three backends' cold boot, restore, egress, and nested-virt paths.

**Why not chroot/pivot_root/uid-drop in v1.** The jailer's chroot + `mknod` device tree + uid-drop are
the heaviest, most environment-specific steps, and each interacts with vmcell's existing model:
uid-dropping the VMM to a confined uid would break the parent's ability to `connect()` the VMM's api/vsock
sockets and to `pidfd_send_signal` it (the verified caveat: cross-uid signalling needs `CAP_KILL`), and a
chroot would require bind-mounting every artifact + socket path in. They are recorded as the next
hardening increment (§20.9), not shipped half-done.

**The optional seccompiler deny-list.** `JailSpec.seccomp` carries a **coarse, default-allow deny-list**
compiled once (pre-fork, so the allocation is off the async-signal-safe path) with seccompiler: a small
set of syscalls a booting VMM never needs and an escape would want — `mount`, `umount2`, `pivot_root`,
`kexec_load`, `kexec_file_load`, `init_module`, `finit_module`, `delete_module`, `ptrace`,
`process_vm_writev`, `bpf`, `perf_event_open`, `add_key`, `keyctl`, `request_key`, `setns`, `unshare` —
each `→ EPERM`, everything else allowed. A default-allow deny-list is far safer to ship than a
default-deny allow-list (it cannot break the VMM unless the VMM legitimately needs a blocked *dangerous*
syscall), but because it still cannot be **live-validated on a KVM host in this environment**, it ships
**opt-in, default off** — the VMM's own native filter (Layer 1) is the shipped default confinement. Its
gate does not need a VMM: `apply_jail` a stand-in child with the deny-list and assert a denied syscall
(`mount`) returns `EPERM` while an allowed one (`write`) succeeds — red on an empty filter.

**The gate that makes Layer 2 non-theater.** `apply_jail` runs unprivileged (no-new-privs, rlimit
lowering, ambient clear, dumpable, and a default-allow seccomp are all unprivileged), so the integration
test spawns a **stand-in** child (`sh -c 'cat /proc/self/status'`, netns `None` so no caps are needed)
through the jail and asserts `NoNewPrivs:\t1`, `CapEff:\t0000000000000000`, and (with `rlimit_core=0`) a
zero core limit. Delete any prctl and the corresponding assertion reddens — a real red-on-inverse, run in
`just ci` with neither root nor KVM.

### 20.5 Layer 3 — the setup broker (the daemon's privilege boundary)

**The verified constraint that dictates the architecture.** `setns(fd, CLONE_NEWNET)` requires
`CAP_SYS_ADMIN` in **both** the caller's user namespace and the user namespace that **owns** the target
netns (else `EPERM`, verbatim in `setns(2)`); a netns created by an init-userns daemon is **permanently**
owned by the init userns (`user_namespaces(7)`). Therefore a **cap-dropped** parent can *never* `setns`
into a broker-created netns. Handing a bare netns fd to the parent is a dead end. Two models remain:

- **Spawner model** (chosen): the broker `fork`s, `setns`es into the netns, places the child in the
  cgroup, `apply_jail`s, and `execve`s the VMM **inside** the confined netns; it returns a **pidfd** so
  the unprivileged parent can `poll`/signal the VMM with no capability (the VMM runs at the parent's uid,
  so `pidfd_send_signal` passes the `kill(2)` permission check). A VMM escape reaches only the empty guest
  netns, never the host network. This is the jailer/gVisor posture and the right one for the
  snapshot-eligible privileged mode.
- **fd-passing model** (recorded, not built): the broker opens the tap **inside** the netns and passes
  the tap fd; the VMM stays in the host netns and is spawned by the parent with Cloud Hypervisor's native
  `--net fd=`. Lighter, but leaves the VMM in the host netns relying solely on seccomp for network
  confinement. Kept as the documented lighter alternative (§20.9).

**Process topology.** `vmcelld` starts blessed (holds the three caps), creates a Unix-socket pair
(`UnixStream::pair()`; the shipped transport is a length-framed `SOCK_STREAM` pair, with `SCM_RIGHTS`
on the same socket reserved for the future pidfd — `SOCK_SEQPACKET` is an equivalent option), and `fork`s
**before spawning any thread or the tokio runtime** (fork-with-threads is unsafe). The child is
`vmcell-broker` (an in-process fork, no re-exec): it sets
`PR_SET_PDEATHSIG=SIGKILL` (dies with the parent), keeps exactly the three caps, closes the HTTP-facing
fds, and serves the broker protocol on its socket end — no network, no attacker input but the typed IPC.
The parent **drops all three caps** (permitted + effective cleared, bounding set shrunk, ambient cleared,
`PR_SET_NO_NEW_PRIVS=1`), keeps the `kvm` gid, builds the tokio runtime, and serves HTTP — now
unprivileged. The parent's cap-drop is a **pure plan** (`plan_broker_parent_drop`) unit-tested against
its inverses exactly like `plan_privilege_transition`, with the thin syscall edge integration-only.

**The protocol — a fixed, audited menu.** Framed postcard over the SEQPACKET pair (the
`vmcell-protocol` framing discipline: a `MAX_BROKER_FRAME_BYTES` cap enforced identically on both ends,
over-cap rejected before allocation), fds carried as `SCM_RIGHTS` ancillary data alongside the body (≥1
byte of real payload, per the portability rule). Every field is validated at the boundary — honor or
reject, no silent default (§12.2); that validation *is* the broker's security value.

```rust
pub enum BrokerRequest {
    SetupNetwork  { vmid: u32, prefix: String, egress: BrokerEgress },
    CreateCgroup  { vmid: u32, prefix: String, limits: ResourceLimits },
    SpawnVmm      { vmid: u32, argv: Vec<String>, netns: String, cgroup: String, jail: JailSpec },
    Teardown      { vmid: u32, prefix: String },   // reverse-order, residue-gone (§12.10)
    Sweep         { prefix: String, live_vmids: Vec<u32> }, // the start-up orphan sweep (§18.4)
    Shutdown,
}
pub enum BrokerReply {
    NetworkReady { tap: String, netns: String, host_ip: String },
    CgroupReady  { name: String },
    VmmSpawned   { /* pidfd via SCM_RIGHTS */ api_socket: PathBuf, vsock: PathBuf, serial: PathBuf },
    Done,
    Error(String),   // typed at the boundary; the parent maps it to a daemon error
}
```

The broker's dispatch runs the **same** `Netlink` / `NftApplier` / `CgroupFs` / `OrphanScanner` seams the
orchestrator uses (§6.4/§7.3), so its setup/teardown/sweep logic is unit-tested against the recording
fakes with **no root** (assert the netns-create → tap → nft call order; assert `Teardown` reclaims in
netns→cgroup→scratch order and leaves residue-gone; assert `Sweep` reaps only non-live vmids) — the
identical discipline that already tests `sweep_orphans`. `SpawnVmm` reuses `build_vmm_cmd` + `apply_jail`
(one law with the in-process path). The broker links `vmcell` with a **minimal feature set** (the
net-privileged + metrics subset — **not** the axum/hyper server stack, which lives only in the
unprivileged parent), so the code that runs at privilege is exactly the audited netns/nft/cgroup/spawn
core and nothing web-facing.

**What ships and what is the remaining KVM step.** The crate, the protocol + codec, the priv-drop plan,
the dispatch-against-fakes, the socketpair+fork+pdeathsig transport, and `BrokerClient` all ship and are
gated in `just ci`. The **`vmcelld` cutover** — replacing the retain-caps model (§12.14, §18.2) with
fork-broker-then-drop, and routing `MicroVmLauncher` through `BrokerClient` — is deep surgery whose live
correctness (a real seccomp'd VMM booting inside a broker-`setns`ed netns, driven by a cap-dropped
parent) can only be validated on a KVM host, which this environment is not. So v24 ships the broker as a
complete, fake-tested component and a documented opt-in, and records the cutover as the single remaining
host-validated step (§20.9) — the same honest posture §18.9 uses for the daemon's live boot path.

### 20.6 Licensing — why seccompiler, and the LGPL trap made machine-enforceable

The user-facing constraint (AGENTS.md, `deny.toml`): **permissive licenses only**; copyleft is tolerated
only for external *binaries* (QEMU, `nft`), never a linked library. The seccomp layer needs a
syscall-filter library. The audit (all SPDX strings from crates.io + upstream `LICENSE`):

| Crate | Crate SPDX | Links a C lib? | Verdict |
|---|---|---|---|
| **seccompiler** (rust-vmm) | `Apache-2.0 OR BSD-3-Clause` | no (pure Rust) | **CHOSEN** — both terms allow-listed |
| `extrasafe` | `MIT` | no (uses seccompiler) | clean, but a second layer over seccompiler — not adopted |
| `libseccomp` / `libseccomp-sys` | `MIT OR Apache-2.0` | **yes — libseccomp C = LGPL-2.1** | **BANNED** (linked copyleft) |
| `syscallz` | `MIT/Apache-2.0` | **yes — via `seccomp-sys` = LGPL-2.1** | **BANNED** (linked copyleft) |
| `seccomp` | `LGPL-2.1` | yes | **BANNED** (copyleft crate) |
| `birdcage` | `GPL-3.0-or-later` | no | **BANNED** (copyleft crate) |

seccompiler is the right pick on three axes: **license** (`Apache-2.0 OR BSD-3-Clause`, pure Rust, no C
linkage), **provenance/fit** (it is the rust-vmm seccomp library that **Cloud Hypervisor and Firecracker
both use internally**, so vmcell's Layer-2 host filter uses the exact same compiler the backends' own
filters use — no second law), and **advisory hygiene** (pure Rust, actively maintained).

**The trap worth naming.** `libseccomp` and `syscallz` have *permissive Rust metadata* but link the
**LGPL-2.1 libseccomp C library**, pulled in via `build.rs`/`pkg-config` as a system library. `cargo
deny`'s license check inspects the Cargo `license` field of crates in the graph — it would show **green**
while the build links copyleft. The license gate alone cannot catch this. So the policy is
**machine-enforced by name**: `deny.toml` `[bans]` denies `libseccomp`, `libseccomp-sys`, `seccomp`,
`seccomp-sys`, and `syscallz`, each with the rationale "links or is LGPL-2.1 libseccomp; the C-library
linkage is invisible to the license gate." A future contributor reaching for the ergonomic-looking
`libseccomp` wrapper reddens the ban gate immediately instead of silently linking LGPL. This is a defect
class (a licensing hole tooling reports green on) turned into a gate that can go red — the §14 discipline.

### 20.7 Cross-cutting invariants added

Folded into §12 (the numbering continues from §12.20):

- **§12.21 — Every backend spawns under its own seccomp; one predicate decides the flag.** No backend is
  launched without consulting `vmm_seccomp_args`, which is the single place a `VmmSeccomp` policy becomes
  a backend flag, and which returns `Error::Unsupported` (never a silent downgrade) for a policy a
  backend cannot honor. Owner: `vmm::seccomp::vmm_seccomp_args`; consumers are `spawn_ch`/`spawn_fc`/the
  QEMU cmd builder. Gate: the golden-args one-law test (red on a new backend that skips the predicate or
  a wrong flag) + the two `Unsupported`-combo tests (`Log` on FC/QEMU).

- **§12.22 — One jail, applied by every VMM spawn; the pure spec is separate from the syscall edge.** The
  VMM child is hardened by exactly one `JailSpec` through exactly one `apply_jail`, called from both the
  in-process `build_vmm_cmd` and the broker's `SpawnVmm` (never a second copy). The spec is pure data; the
  async-signal-safe apply is the only impure edge, its `SAFETY` comments proving async-signal-safety
  (§B10). Owner: `vmcell::vmm::jail`. Gate: the `/proc/self/status` stand-in test (`NoNewPrivs:1`,
  `CapEff:0`) + the deny-list `mount→EPERM` test — both root-free and KVM-free, both red on the inverse.

- **§12.23 — In the broker model, the network surface never holds the caps; the cap-holder never parses
  network input.** The `vmcelld` parent drops all three caps (pure `plan_broker_parent_drop`, applied
  before the HTTP listener binds) and the broker child serves only the typed, bounded, fd-passing IPC
  menu — no network. The broker validates every request field at the boundary (honor-or-reject). Owner:
  `vmcell-broker` + `vmcelld` main. Gate: the priv-drop-plan inverse tests (parent ends with an empty
  cap set + no-new-privs), the framed-codec round-trip + over-cap-reject test, and the
  dispatch-against-fakes call-order/residue-gone tests. (The live cutover is the §20.9 KVM step.)

### 20.8 Quality gates (added to §14)

- **Unit / pure (KVM-free, in `just ci`):** `vmm_seccomp_args` golden output for every (backend, policy)
  pair + the two `Unsupported` combos; `JailSpec` defaults + clamps; `plan_broker_parent_drop` against
  its buggy inverses (drops all three + bounding + ambient, sets no-new-privs, preserves the `kvm` gid);
  the broker framed-protocol codec round-trip + `> MAX_BROKER_FRAME_BYTES` reject; the broker dispatch
  call-order/residue-gone/sweep-only-dead tests against the recording fakes; the seccompiler deny-list
  compiles to the expected syscall set.
- **Integration (KVM-free, root-free, in `just ci`):** the jailer `/proc/self/status` stand-in gate; the
  deny-list `mount→EPERM`/`write→ok` stand-in gate; the broker socketpair+fork round-trip (parent sends a
  `Sweep{live=all}`/no-op request to a forked broker over the real SEQPACKET pair and reads the reply —
  proves the framing + fd-passing transport without root).
- **Host-validated (KVM, `scripts/review-preflight-priv.sh` + both mode suites, not in this env):** a
  seccomp'd guest boots on each backend; a jailed live VMM boots; the `vmcelld` broker cutover boots,
  execs, and tears down through a cap-dropped parent. Recorded in §20.9 and `implementation-notes.md`.

### 20.9 What ships now, and the honest forward work

**Shipped and gated in v24:** Layer 1 (VMM seccomp) fully wired into all three backends; Layer 2
(jailer-equivalent) fully wired into `build_vmm_cmd` with the root-free `/proc/self/status` gate and the
opt-in seccompiler deny-list with its `mount→EPERM` gate; Layer 3 (the `vmcell-broker` crate + binary +
`BrokerClient`) complete with the protocol, priv-drop plan, dispatch-against-fakes, and transport gates.
The `deny.toml` LGPL-libseccomp ban.

**KVM-host validation of Layers 1–2 (this host, `just test-privileged`).** The privileged suite runs
every VM through the new hardened path (default `JailConfig::hardened()` + `VmmSeccomp::Enforcing`). Cold
boot, `exec`, privileged tap + nft TPROXY egress, host-endpoint, metrics/limits, nested virt, extra
disks, and shares all pass on **CH + FC + QEMU** — so CH `--seccomp true`, FC's built-in filter, QEMU
`-sandbox on,…` (this host's QEMU has libseccomp), and `no_new_privs`/`RLIMIT_CORE=0`/`non_dumpable` are
all non-breaking. **The finding that shaped the defaults:** an initial `clear_ambient_caps: true` reddened
every restore-with-tap test (`snapshot_restore`/`extra_block_survives_snapshot`/`zygote_fan_out` on CH+FC)
with `TapSetMac`/tap-open `EPERM` — a restored VMM needs the `CAP_NET_ADMIN` it inherits via the ambient
set. Defaulting `clear_ambient_caps` off makes the full suite green again (the VMM keeps only the caps it
genuinely needs). This is exactly the "defaults get the strictest scrutiny" + "validate on a KVM host"
discipline catching a regression static review would have missed.

**Forward work (each a real edge, not a hedge):**

- **The `vmcelld` broker cutover (the headline remaining step).** Replace §12.14's retain-caps model with
  fork-broker-then-drop and route `MicroVmLauncher` through `BrokerClient`. Ships opt-in
  (`--setup-broker`) once validated; the retain-caps single-process form stays the default until then.
  Only validatable on a KVM host.
- **The seccompiler deny-list on by default.** Ships opt-in until a KVM host confirms each backend boots
  cleanly under it; a default-allow deny-list is low-risk but unvalidated on a live VMM.
- **`clear_ambient_caps` on by default** — blocked until the VMM no longer needs its inherited
  `CAP_NET_ADMIN`, which requires the fd-passing / uid-drop increment below (the empirical §20.9 finding).
- **The jailer's chroot / uid-drop increment.** `pivot_root` + `mknod` device tree + a confined VMM
  uid/gid (with the cross-uid `pidfd_send_signal`/`CAP_KILL` and socket-permission consequences handled),
  plus handing the tap over fully configured so the VMM can drop `CAP_NET_ADMIN` too.
- **The fd-passing broker variant** (Cloud Hypervisor `--net fd=`) as the lighter alternative to the
  spawner model, for workloads that accept the weaker (host-netns) confinement.
- **`clone3(CLONE_INTO_CGROUP)`** for atomic cgroup placement of the spawned VMM (avoids the
  `cgroup.procs` write race), replacing the post-spawn `add_task`.

---

## Amendments to the base document (v23)

- **§2.2 (key decisions)** — add a row: **Privileged-window hardening** | Three layers (§20): every VMM
  under its own seccomp (`vmm_seccomp_args`, one law), a jailer-equivalent pre-exec hardening
  (`no_new_privs` + rlimits + ambient-clear + optional seccompiler deny-list), and a **setup broker** —
  a minimal privileged `vmcell-broker` child that holds the caps and spawns the jailed VMM into the
  netns, so the cap-dropped `vmcelld` parent serves HTTP with no capabilities. Seccomp uses
  **seccompiler** (Apache-2.0/BSD-3, the rust-vmm library CH/FC use); the LGPL `libseccomp` family is
  banned by name in `deny.toml`.
- **§10.1 (workspace layout)** — one new member, **`vmcell-broker`** (lean privileged spawn helper +
  `BrokerClient`, links `vmcell`'s net-privileged/metrics subset + `vmcell-privilege`, never the daemon's
  web stack). `vmcell` gains a `vmcell-privilege` edge (for the shared `jail::JailSpec`/`apply_jail`) —
  still an acyclic star, since `vmcell-privilege` has no `vmcell` edge.
- **§10.2 (public API)** — `VmConfig` gains `vmm_seccomp: VmmSeccomp` (default `Enforcing`) and
  `jail: JailSpec` (default hardened); both additive, `semver-checks`-clean.
- **§12** — new invariants **§12.21–§12.23** (§20.7).
- **§14** — new gates (§20.8).
- **§16 (open decisions)** — the privileged-window-hardening bullet moves from forward-work to: "Layers
  1–2 built and wired; Layer 3 (broker) built and fake/transport-gated; the `vmcelld` cutover is the
  remaining KVM-validated step (§20.9)."
- **§17 (future capabilities)** — strike "privileged-window hardening (each VMM's own seccomp, a
  jailer-equivalent, and a setup broker)" from the Design-now-build-later list; it is §20.
- **§18.2** — the "§17 setup broker … stays forward work" sentence is superseded: the broker is built
  (§20.5); the retain-caps single-process form (§12.14) remains the **default** until the cutover is
  host-validated, at which point the broker becomes the recommended and then default privilege boundary.
