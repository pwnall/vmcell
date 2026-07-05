# vmcell — Design Document (v21)

> **v21 (this revision) — the control-plane daemon and its client.** Promotes the long-deferred
> **`impd` daemon** (v20 §16/§17: "VMs that outlive their creator, which the single-process `MicroVm`
> ownership model can't provide") from forward-work to a built subsystem, under the concrete names the
> integrator chose: package/library **`vmcell-daemon`**, binary **`vmcelld`**; client package/library
> **`vmcell-daemon-client`**, CLI binary **`vmcelld-ctl`**. The daemon is a **long-lived privileged
> process** blessed exactly like `vmcell-test-runner` (file-caps, refuse-to-start without them) that
> **retains** the three capabilities instead of dropping-and-exec'ing. It **owns** the VMs it starts:
> it holds each `MicroVm` handle, so the VMM process and its netns/tap/cgroup/scratch stay alive while
> held and are **released on `Drop`** in order (v20 §12.10 — the invariant is preserved, not abandoned).
> The VM verbs (`create`/`list`/`exec`/`stats`/`snapshot`/`destroy` — the verbs `vmcell-cli` fails loud
> on, v20 §11) drive those owned handles. A clean shutdown tears every VM down gracefully; a hard kill
> leaks resources, which the **start-up orphan sweep** (`vmcell`'s `sweep_orphans`, run before any VM
> exists) reclaims on the next boot. It serves a **versioned HTTP REST API** with a served **OpenAPI 3.1
> document**, gated by a **bearer API key** (RFC 6750 form), and manages a per-daemon **artifact store**
> (create / list / delete; no update) whose names are a restricted character set mapping directly to
> files, so the VM APIs reference artifacts **by name** rather than by host path. The client offers a
> typed Rust API that mirrors the `vmcell` entry points as closely as the network boundary allows — the
> one forced divergence is that a host **artifact path becomes an upload** (§D8).
>
> **New this revision.** A new lean crate **`vmcell-privilege`** (§D2) extracts the security-critical
> capability/blessing predicates so the daemon and the test-runner share **one** implementation
> (one-law-one-predicate, v20 §12; AGENTS.md "one law, one predicate"). New sections **§D1–§D12** below.
> **Amends** v20 **§10.1** (workspace layout: five new members), **§11** (the CLI's `exec`/`ls`/`rm`/
> `destroy` are no longer "deferred, fail loud" — they **move to the daemon** and the CLI verbs are
> retired), **§16** (the `impd`-daemon gap closes for the core verbs; residuals recorded), and **§17**
> (the daemon graduates from "design-now-build-later" to built; the warm-pool manager and setup broker
> remain future). `vmcell` gains **no** dependency edge (the daemon depends on `vmcell`, never the
> reverse) but does gain one small public surface — a **configurable resource prefix** (§D4.1: `VmConfig
> ::resource_prefix` + the `vmcell::naming` module, replacing the hard-coded `vmcell-*` names used for
> naming and leaked-resource sweeping) — so `vmcell` bumps **0.5.0 → 0.6.0**. New members version from
> **0.1.0**; `vmcell-test-runner` bumps **0.2.0 → 0.3.0** for the `vmcell-privilege` extraction (a
> `cargo semver-checks` non-event — it exports no library API — but the version tracks the refactor).

This document is a **focused amendment** to the v20 design (`docs/historical/49-claude-design-v20.md`),
not a full re-issue. Everything v20 states about the VMM backends (§3), the control plane (§4), the
rootfs/kernel/artifact pipeline (§5/§8/§11), networking (§6), limits (§7), snapshot/zygote (§9), the
`vmcell` library shape (§10), and the cross-cutting invariants (§12) **still governs** and is not
repeated here. Read v20 first; this document adds the daemon/client layer on top of it and calls out the
exact v20 sections it changes (§D11). The house rules from AGENTS.md apply unchanged: every recurring
defect class becomes a gate, every test and gate must be able to fail, security checks anchor on trusted
data and ship with a positive control, teardown is ownership, fail loud.

---

## D1. What this adds, and where it sits

`vmcell` (the library) and `vmcell-cli` (the CLI) are a **single-process** model: a `MicroVm<V>` handle
owns its VM and *is* the lifetime — when the handle drops, ordered teardown destroys the VM (v20 §12.10).
That model is correct and stays the default for tests and for one-shot CLI verbs (`run`/`create`/
`snapshot`/`stats`), but it structurally cannot offer a VM that **outlives the process that created it**:
there is nobody to hold the handle. `vmcell-cli` already names this boundary — its `exec`/`ls`/`rm`/
`destroy` verbs return a typed `Error::Unsupported` "deferred to the `impd` daemon" rather than faking
success (v20 §11, the "skip == pass" anti-pattern in CLI form).

**The daemon is that missing owner.** `vmcelld` is a single long-lived process that **owns** the VMs it
starts: it holds each `MicroVm` handle in an in-process registry (§D4), so a VM's lifetime is decoupled
from any one client request but stays tied to the daemon — and the whole "teardown is ownership, `Drop`
releases resources" invariant (v20 §12.10) carries over unchanged. Clients talk over HTTP and refer to
VMs by an opaque **id**. The one thing owning-and-`Drop` cannot handle by itself is a *hard* kill of the
daemon (SIGKILL, power loss), which skips every `Drop` and leaks the VMs' netns/cgroup/scratch; the
daemon closes that with a **start-up orphan sweep** (§D4), so a crash-and-restart self-heals. This is the
productization seam v20 §17 describes ("`impd` daemon + versioned control-plane API + warm-pool manager").

Two consumers, one daemon:

```
  vmcelld-ctl (CLI)  ─┐                         ┌─ artifact store  (<artifacts-dir>/<name>)  [files]
  your Rust program  ─┤── HTTP/REST (bearer) ──▶ vmcelld ─┤
  (vmcell-daemon-     ─┘   OpenAPI-described    (owning,   └─ VM registry ── holds ──▶ MicroVm … MicroVm
   client)                                       blessed)     (Drop releases; start-up sweep reclaims leaks)
```

The daemon is **the** place the process-global allocators v20 §10.2 mandates finally have a natural
single home: one `VmidAllocator::shared()` and one `Arc<CidAllocator>` per daemon process, handed to
every launch. Under the old model each CLI invocation minted its own hermetic allocators; the daemon
holds the one authoritative pair for its host.

### D1.1 Five new workspace members

Amends v20 §10.1. The workspace gains five members (the `[workspace]` root stays a pure `[workspace]`):

- **`vmcell-privilege`** — a **lean** library crate (`rustix` + `capctl` + `libc` only, never the
  `vmcell` host stack) holding the capability/blessing predicates that were private to
  `vmcell-test-runner`'s `main.rs`. Extracted so the daemon and the runner share **one** copy of
  security-critical logic (§D2). Subject to the same CI lean assertion as the runner: it must not drag in
  `tokio`/`hyper`/`rtnetlink`.
- **`vmcell-daemon`** — the daemon **library** (host stack): the artifact store, the owning VM
  `Registry` (over the `VmLauncher`/`VmHandle` seam), the start-up orphan sweep, the axum router +
  handlers, the auth layer, the OpenAPI document, and the request/response DTOs. This is where the
  well-tested logic lives (AGENTS.md "functionality in well-tested library crate, binary crate wrapper").
- **`vmcelld`** — the daemon **binary**: a thin wrapper that runs the blessing **precondition**
  (refuse-to-start without the three caps in its effective set — whether they came from the runner or
  file-caps, §D2), parses `--artifacts-dir` / `--bind` / `--api-key-file`, runs the start-up sweep,
  builds the server from the library, and serves — tearing every owned VM down gracefully on a clean
  shutdown signal (§D4). In tests and dev it is **launched through the blessed runner**, so it is never
  blessed on the hot path.
- **`vmcell-daemon-client`** — the client **library**: a typed `reqwest` client whose Rust API mirrors
  the `vmcell` entry points (§D7), re-exporting the DTOs from `vmcell-daemon` so a request built by the
  client and decoded by the server share one type (one-law-one-predicate for the wire schema).
- **`vmcelld-ctl`** — the client **CLI**: a `clap` wrapper over `vmcell-daemon-client`.

**Dependency graph (acyclic, a directed star like the builders, v20 §10.1).**

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

`vmcell` has **no** edge to any of these (as with the builders, v20 §10.1). `vmcell-daemon-client`
depends on `vmcell-daemon` **only** for the DTO types (a `client` feature on `vmcell-daemon` that gates
off the axum/server modules, so the client build does not pull the whole server stack) — this keeps the
wire schema single-sourced without making the client link the server. The daemon depends on `vmcell`
with the same features `vmcell-cli` uses (`cloud-hypervisor`, `metrics`, `pipeline`, `cli`).

---

## D2. Privilege and blessing

The daemon needs the **same three capabilities** the privileged operating mode needs
(`cap_net_admin,cap_sys_admin,cap_dac_override`, v20 §6.4/§12.8). There are two ways to give them to it,
and the choice matters for the dev inner loop:

- **Tests and dev — launch `vmcelld` through the blessed `vmcell-test-runner` (the default, no
  per-rebuild blessing).** The runner is a cap-conferring `exec` wrapper: it raises the three caps into
  the **ambient** set and `execvp`s a target confined under the workspace `target/` dir (v20 §12.8). Its
  confinement accepts **any** `target/` binary, not just test binaries — so `vmcell-test-runner
  target/debug/vmcelld …` execs `vmcelld` with the three caps in its effective set, and `vmcelld`'s
  blessing precondition passes **without `vmcelld` itself being blessed**. Because only the runner
  carries file-caps, and the runner rarely changes, `vmcelld` (which changes constantly) rebuilds freely
  with **no `sudo setcap` on every change** — the exact churn `vmcell-test-runner` was introduced to kill
  for the ever-changing test binaries (v20 §12.8), now extended to the daemon. Integration tests spawn
  `vmcelld` this way (§D10); `just daemon` runs it this way for manual poking.
- **Standalone / production — file-caps or systemd ambient caps.** A `vmcelld` run as a long-lived system
  daemon *outside* a test harness gets its caps by being blessed once (`setcap …+ep` on the installed
  binary) or, better for production, via the service manager (`systemd`'s `AmbientCapabilities=`). This
  path is unchanged by the runner shortcut; it just isn't on the dev hot path, so `just bless` no longer
  blesses `vmcelld` (only the runner), keeping the inner loop free of `setcap` prompts.

Either way the precondition below is identical.

**The one deliberate difference from the runner: the daemon retains the caps; it does not drop-and-exec.**
The test-runner is a *transient* wrapper — file-caps → raise ambient → drop to the dev uid → `execvp`
the test binary — so the caps live only across a single `exec` (v20 §12.8). The daemon is a *long-lived
server* that must itself perform privileged VM operations (netns/tap/nft, v20 §6.4) for the whole life
of the process. So `vmcelld` runs the **blessing precondition** (the three caps must be present in the
**effective** set, or `euid == 0`) and then **keeps** them; there is no uid drop, no ambient raise, no
bounding-set shrink, no `exec`. If the precondition fails it prints the same `setcap …+ep` remediation
and exits non-zero — **refuse to start if privileges are missing**, as specified. It never silently runs
degraded: a daemon that came up without `CAP_NET_ADMIN` would fail every privileged VM create at first
use, which is the fail-loud-at-construction rule (AGENTS.md "honored or rejected at construction").

**`vmcell-privilege` — one predicate, two callers.** The precondition logic is security-critical and was
private to the runner's `main.rs`. Copying it into the daemon is precisely the "duplicate load-bearing
logic diverges" trap the rubric bans (AGENTS.md; v20 §12). So it is extracted into `vmcell-privilege`
with the runner's pure, already-unit-tested seams moved verbatim and re-exported:

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
pub struct PrivilegePlan { /* … as v20 */ }
pub fn plan_privilege_transition(/* … */) -> PrivilegePlan;   // pure, unit-tested against buggy inverses
pub fn apply_privilege_transition(plan: &PrivilegePlan) -> Result<(), String>;  // thin syscall edge
```

The daemon uses only `ensure_blessed_or_explain(&PRIVILEGED_CAPS)` + `blessing_remediation`; it never
calls the transition functions (it keeps its caps). The runner keeps its full path but now imports it
instead of defining it. The runner's existing red-on-inverse tests (the `+ep`-not-`+p` remediation, the
`compute_missing` effective-vs-permitted test, the plan tests, the confinement tests) **move with the
code** into `vmcell-privilege` and keep guarding both callers — the extraction is refactor-only and the
unchanged tests prove it. The runner's exec-target **confinement** (`confine_under` /
`trusted_target_root` / `confine_target_under`, v20 §12.8) stays runner-only, and it is exactly what
makes the runner-launch shortcut safe: the runner only confers caps on a binary that canonicalizes to a
descendant of the trusted `<workspace>/target` (derived from the runner's **own** location, never the
argument), so `vmcell-test-runner target/debug/vmcelld` is admitted while an arbitrary path is rejected —
the same boundary that admits a test binary admits `vmcelld`, and a unit test guards that a `vmcelld`
path under `target/` is accepted. The daemon itself execs no target binary, so it has no confinement
obligation of that shape — its analogous "anchor on trusted data" check is the **artifact-name
validator** (§D3), which anchors every filesystem access on the daemon's own `--artifacts-dir`, never on
a client-supplied path.

**Where the daemon runs its privileged work.** Same as the library today: `MicroVm::start`/`restore`
perform the netns/tap/nft bring-up (v20 §6.4) using the caps the process holds. The daemon adds no new
privileged syscalls; it just holds the caps for longer. The v20 §17 "setup broker" (a separate
minimal-privilege helper the daemon talks to, so the network-facing HTTP surface is **not** in the same
process as the ambient caps) is the recommended hardening and stays **forward work** (§D12) — v21 ships
the single-process form with the HTTP surface bound locally and behind auth, and records the broker as
the next hardening step, honestly (v20 §17 already names it the "recommended privilege boundary").

---

## D3. The artifact store

The daemon receives `--artifacts-dir <path>` and manages the files under it with three operations —
**create, list, delete; no update** — exactly as specified. This is deliberately *not* the `vmcell`
artifact *pipeline* (v20 §11, which builds kernels/rootfs/snapshots): it is a flat content store the VM
APIs draw their `kernel`/`rootfs` inputs from. A client `build`s artifacts elsewhere (or with the CLI)
and **uploads** them into the daemon's store; the daemon never fetches from the network on a client's
behalf.

### D3.1 One name predicate, anchored on trusted data

Names map **directly** to files: artifact `k1` is the file `<artifacts-dir>/k1`. That makes the name
validator a **security boundary** of the same class as the runner's exec-target confinement (v20 §12.8)
— a name that path-traverses (`../../etc/passwd`) or is absolute would let a client read or clobber files
outside the store. So there is **one** predicate, pure and unit-tested against its buggy inverses:

```rust
/// The ONLY function that turns a client-supplied artifact name into a path. Every
/// store op and every VM-API artifact reference goes through it. Rejects anything
/// that is not a single safe path component.
pub fn resolve_artifact_path(dir: &Path, name: &str) -> Result<PathBuf, ArtifactError>;
```

Accept rule (allowlist, not denylist — a denylist of "bad" substrings is the divergence trap): a name is
valid iff it is **non-empty**, **≤ 255 bytes**, every byte is in **`[A-Za-z0-9._-]`**, and it is **not**
`.` or `..` and does **not start with `-` or `.`** (a leading `-` would be read as a flag by any tool the
name is later handed to; a leading `.` hides the file and enables the `.`/`..` family). The result is
**always** `dir.join(name)` with `name` a single component — there is no `/` in the accepted set, so no
subdirectories and no traversal are representable. The predicate returns the joined path; callers **never**
construct `dir.join(client_string)` themselves (grep-able gate: `dir.join(` on a client string outside
this function is a review-reject, mirroring v20's "one law, one predicate" for `mac_math`/`MAX_FRAME_BYTES`).

Red-on-inverse tests (each guards a documented buggy relaxation): `..`, `a/b`, `/abs`, `-rf`, `.hidden`,
empty, over-255-bytes, and a NUL byte all reject; a **positive control** (`vmlinux-6.12`, `rootfs.erofs`,
`k1`) accepts and joins to exactly `<dir>/<name>`. This is the AGENTS.md "a negative security result
needs a positive control (the allowed path reaches the same target)" rule.

### D3.2 Operations

- **Create** — `PUT /v1/artifacts/{name}` with the file bytes as the body (or a streamed multipart for
  large images). **No update**: create **rejects an existing name** with a typed `AlreadyExists` (409),
  never a silent overwrite — "no update" is enforced, not assumed. Bytes are written to a
  **temp file in the same dir** then **atomically renamed** into place, so a crashed or truncated upload
  never leaves a half-written artifact that a later VM boot would read (the create-then-write two-step the
  VMID lock file avoids, v20 §10.2, applied to uploads). The write is size-capped by
  `--max-artifact-bytes` (default a generous ceiling), rejected fail-loud past it — an unbounded upload is
  a trivial disk-fill DoS.
- **List** — `GET /v1/artifacts` → `[{name, size_bytes, sha256}]`. The digest is a SHA-256 of the file
  contents, so a client can verify an upload round-tripped intact. Listing reads **only** direct children
  that pass `resolve_artifact_path` (a stray subdir or a name written out-of-band that fails validation is
  skipped, never surfaced as a usable artifact).
- **Delete** — `DELETE /v1/artifacts/{name}` → 204. Refuses to delete an artifact that is **in use** by a
  live VM (a VM booted from `k1` pins `k1`) with a typed `InUse` (409) — the handler asks the registry
  `is_artifact_in_use(name)` (which scans the owned VMs' pinned names, §D4) before deleting, so the
  kernel is never pulled out from under a running VM. Residue check in tests: the file existed before
  delete, then is gone (AGENTS.md residue rule).

Every store op is a pure-ish function over `(dir, name, bytes?)` behind the validator, unit-testable
against a `tempdir` with **no** HTTP and **no** KVM — the axum handler is a thin adapter that maps the
typed store error to a status code (§D5).

---

## D4. The VM registry — owned handles, `Drop`-releases-resources, start-up sweep

The daemon **owns** every VM it starts, holding the `MicroVm` handle in an in-process registry. This
keeps the v20 §12.10 invariant intact end-to-end: while the handle is held the VMM process and its
netns/tap/cgroup/scratch stay alive, and when the handle drops the *same* ordered teardown runs. Two
seams and one recovery hook:

- **`VmLauncher` / `VmHandle`** (the seam) — the registry drives VMs through these traits, not `MicroVm`
  directly, so its logic (id minting, the state machine, ordered teardown, artifact pinning) is
  unit-testable against a recording **fake** with no KVM or root (the v20 §10.6 injectable-seam
  discipline). The real **`MicroVmLauncher`** is a thin adapter: `launch` builds a `VmConfig`, calls
  `MicroVm::start` (bringing the agent up so a returned VM is genuinely ready), and boxes the handle;
  `exec`/`usage`/`snapshot`/`shutdown` forward to the `MicroVm`. Because the daemon holds the handle,
  the real backend needs **no** new vmcell primitive — this is the single-process ownership model kept
  in-process, just held by a long-lived server instead of a one-shot CLI.
- **`Registry`** — a `tokio::sync::Mutex<HashMap<VmId, Arc<VmSlot>>>` where each `VmSlot` holds the
  boxed handle behind its **own** async mutex. Ops on **different** VMs run concurrently; ops on **one**
  VM serialize on its single vsock control channel (correct — one channel per VM). The VM's immutable
  identity (id, vmid, the artifact **names** it pins) is read lock-free for the delete-in-use guard; only
  the handle + state sit behind the per-VM lock. The **id** is an opaque server-minted token
  (`vm-<counter>-<splitmix64>` — readable counter + mixed suffix so ids are unguessable, never reused in
  a process); it is **not** the VMID (the network octet, v20 §10.2).

**Teardown is ownership (v20 §12.10), two paths, one helper.** `destroy` removes the slot from the table
(so no new op finds it), marks it `Destroying`, and runs the graceful `MicroVm::shutdown`; a clean daemon
exit calls `shutdown_all` (each VM's graceful shutdown); and dropping the `Arc<Registry>` runs each
`MicroVm::Drop` — the panic path — with the identical ordered cleanup (kill VMM proc-group → virtiofsd →
tap/netns/cgroup/overlay/scratch). A **hard** kill of the daemon skips all three and leaks the residue.

**Start-up orphan sweep — the crash-recovery counterpart.** Before it owns any VM, the daemon runs
`vmcell`'s `sweep_orphans` (v20 §16) with an **empty** live-vmid set, so every netns/cgroup-slice/scratch
dir whose trailing vmid is not currently owned — i.e. every orphan a previously hard-killed daemon left —
is reclaimed. (Nothing is live at start-up, so the empty set can never sweep a resource in use.) The
sweep needs `CAP_NET_ADMIN` to delete a netns, which the daemon holds (from the runner or file-caps, §D2); per-resource failures are
logged, not fatal. This is what makes a crash-and-restart self-heal without leaking a netns that would
later collide with a reused vmid (the exact between-runs gap v20 §16 records).

**Create flow.** `create` resolves the `kernel`/`rootfs` names to paths (the single validated join, §D3.1),
`launcher.launch`es the VM, mints an id, and inserts the owned handle as `Ready` (the launch only returns
after the guest agent handshakes, so "ready" is derived from the VM, not a hopeful label). With a
`command` it then `exec`s and, if `ephemeral`, `destroy`s — the `run` one-shot, reusing the same
`exec`/`destroy` paths.

### D4.1 The configurable resource prefix — one option for naming *and* sweeping

A VM leaks four host resources if it dies ungracefully: a **netns**, a **tap**, a **cgroup slice**, and a
**scratch dir**. Their names were four hard-coded `vmcell-*` string literals, and the sweep filtered by
three more — seven copies of one prefix that had to stay in lockstep or the sweep would silently miss a
leak. v21 collapses them into **one option**. The new `vmcell::naming` module is the single place that
composes every name from a prefix (`<prefix>-net-<vmid>`, `<prefix>-tap-<vmid>`, `<prefix>-vm-<vmid>`,
`<prefix>-vm-<pid>-<vmid>`) and every sweep filter (`<prefix>-net-`, `<prefix>-vm-`); a unit test pins
that each produced name **starts with** its sweep filter for any prefix (one law, one predicate). The
prefix lives on `VmConfig::resource_prefix` (builder `.resource_prefix()`, default
`DEFAULT_RESOURCE_PREFIX = "vmcell"`, validated `[A-Za-z0-9]`≤6 at `build()` so it is safe in an
interface/netns/cgroup/dir name), and `HostOrphanScanner::new(prefix)` matches by the same value.

In `vmcelld` it is **one CLI flag**, `--resource-prefix` (default `vmcell`), threaded to *both* the
launcher (so its VMs are named with it) and the start-up sweep (so it reclaims exactly those names). Two
daemons with distinct prefixes therefore never sweep each other's resources — validated on KVM: a daemon
run with `--resource-prefix acme` names its VM's netns `acme-net-<vmid>`, reclaims a planted `acme-net-*`
orphan, and leaves a `vmcell-net-*` orphan from another tool untouched (§D10). The default reproduces the
historical `vmcell-*` names exactly, so this is a non-behavioral change at the default. (The VMID lock
dir `/tmp/vmcell-vmid` is deliberately *not* prefixed — it is not swept and is a cross-process rendezvous
that must be stable regardless of prefix.)

---

## D5. The HTTP REST API and its OpenAPI document

### D5.1 Surface (versioned `/v1`)

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
  GET    /v1/vms/{id}/stats        resource usage (== `stats`)           -> ResourceUsageDto
  POST   /v1/vms/{id}/snapshot     write a warm snapshot (== `snapshot`)  body: {artifact_prefix} -> SnapshotInfo
  DELETE /v1/vms/{id}              destroy + teardown (== `rm`/`destroy`) -> 204

Meta
  GET    /openapi.json             the served OpenAPI 3.1 document        (unauthenticated)
  GET    /healthz                  liveness                               (unauthenticated)
```

`CreateVmRequest` carries `kernel` and `rootfs` (artifact **names**), `vcpus`, `mem_mib`, and — additive,
`#[serde(default)]` so old clients keep working — three config knobs plus the run/ephemeral pair:

- **`net: NetMode`** (`none` default | `privileged` | `unprivileged`). The daemon holds the caps, so the
  **privileged** tap path (netns + `/30` + default route) is available; `none` is a no-network VM;
  `unprivileged` is the smoltcp NAT (not snapshot-eligible). Validated: a `privileged` VM gets a host
  `vmcell-net-<vmid>` netns and the guest `eth0` comes up with a `10.200.x/30` and a default route (§D10).
- **`snapshotting: bool`** — boot a **snapshot-eligible** VM (no vhost-user device, design v20 §12.1).
  Rejected fail-loud (`400`) with a non-eligible `net` (e.g. `unprivileged`) *before* launch.
- **`restore_from: Option<String>`** — restore from the snapshot in the store under this prefix instead
  of a cold boot. The daemon restores via **CoW** (`MicroVm::restore_cow`, design v20 §9.4), so the named
  snapshot is **preserved** and re-restorable; `create` then drives the mandatory post-restore resync.
- **`command: Option<Vec<String>>`** — present ⇒ `run` (exec, capture, keep-or-teardown per
  `ephemeral: bool`); absent ⇒ `create` (boot to agent-ready and register).

The daemon resolves `kernel`/`rootfs`/`restore_from` through `resolve_artifact_path` against its
`--artifacts-dir` — a client can only ever name an artifact it uploaded, never a host path (§D8). Errors
map to status by the typed daemon error (§D5.3), never a bare 500-with-string.

Snapshots land **in the artifact store**: `snapshot` writes the CH snapshot dir under
`<artifacts-dir>/<artifact_prefix>/…` and returns the names, so a subsequent `create {restore_from}` can
restore from them by name — the store is the one exchange surface, no out-of-band paths (§D8). Validated
end-to-end: a marker written into a VM's tmpfs before `snapshot` survives a `restore_from` into a fresh
VM (§D10).

### D5.2 The OpenAPI document is generated once and gated for parity

The API is described by an **OpenAPI 3.1** document served at `/openapi.json`. Rather than trust a derive
macro's output (an untested claim) or hand-maintain a separate file (a divergence trap), the document is
**built by one function** `openapi_document() -> serde_json::Value` from the same route table the router
mounts, and a **parity gate** (a plain unit test, KVM-free, always runs) asserts the two agree:

- **every** `(method, path)` the axum router mounts appears in the document, and
- **every** path/method in the document is actually mounted,
- and every request/response `component` schema named by an operation exists.

Red-on-inverse: add a route without a document entry (or vice versa) → the parity test fails. This is the
AGENTS.md "docs state each fact once" and "every claim has a gate that can go red" rules applied to the
spec — the served document cannot silently drift from the routes. The `securityScheme` is declared here
(bearer, §D6) and applied to every operation except `/healthz` and `/openapi.json`; the parity gate also
asserts **no VM/artifact operation is missing its security requirement** (a route that forgot auth is a
red test, not a review hope).

### D5.3 One daemon error type, matchable, mapped to status

Mirrors v20 §10.3 (no `Error::Other(String)` catch-all; the caller-relevant conditions are typed). The
daemon has one `DaemonError` enum with a variant per failure class, each carrying the HTTP status it maps
to in one `IntoResponse` impl (one law, one predicate for the mapping):

```
NotFound        -> 404   (no such vm/artifact)
AlreadyExists   -> 409   (create over an existing artifact — the "no update" guard)
InUse           -> 409   (delete an artifact a live VM pins)
Conflict        -> 409   (op against a VM in the wrong state)
InvalidName     -> 400   (resolve_artifact_path rejected the name)
BadRequest      -> 400   (malformed body / knob)
Unauthorized    -> 401   (missing/blank bearer)  |  Forbidden -> 403 (wrong bearer)
Unsupported     -> 501   (an op the backend does not advertise — wraps vmcell Error::Unsupported)
PayloadTooLarge -> 413   (upload past --max-artifact-bytes)
Internal        -> 500   (a wrapped vmcell::Error with no more specific mapping; body is the Display, never a struct-dump)
```

The 401-vs-403 split is deliberate: **absent** credentials are 401 (per RFC 7235, with a
`WWW-Authenticate: Bearer` header); **present but wrong** are 403. A wrapped `vmcell::Error` renders its
`Display` (the `#[error]` message), never its `Debug` — the same L-BIN-4 lesson v20 §11 records for the
CLI. The error body is a small JSON `{error, message}` documented as a component in the OpenAPI doc, so a
client decodes a structured error, not a bare string.

---

## D6. Authentication — a bearer API key (RFC 6750 form)

The integrator asked: "OAuth bearer token for the API key? Pick the most idiomatic solution." The
idiomatic, minimal, correct choice is a **pre-shared opaque API key presented as an HTTP Bearer token**
(`Authorization: Bearer <key>`, the RFC 6750 "OAuth 2.0 Bearer Token Usage" transport), **not** a full
OAuth 2.0 authorization-server flow. Rationale, stated honestly (AGENTS.md "trade-offs stated honestly"):

- A full OAuth flow (an authorization server, `/token`, grant types, JWT issuance/rotation) buys
  delegated third-party authorization the daemon has no use for — it is a **local, single-tenant control
  plane** for one operator's host. The bearer *transport* is the part of OAuth that carries the
  credential; adopting it (and describing it in OpenAPI as `type: http, scheme: bearer`) gives every
  standard HTTP client and the OpenAPI tooling first-class auth with **zero** custom flow.
- The key is an **opaque high-entropy secret**, not a structured JWT — so there is no signature to verify,
  no clock-skew window, no key-rotation ceremony in v1. Comparison is **constant-time**
  (`subtle::ConstantTimeEq` or a hand-rolled volatile compare) so a timing side-channel can't leak the
  key byte-by-byte — the AGENTS.md "security checks … match normalized input … ship with a positive
  control" discipline, here the positive control being "the correct key reaches the same authorized
  handler."
- The key is loaded from `--api-key-file` (a path, **perms-checked**: the daemon refuses a key file that
  is group/other-readable, the "no secrets in world-readable files" discipline — mirrors "no secrets in
  kernel cmdline / agent output", v20 AGENTS.md). Passing the key as a CLI arg or env var is rejected in
  favor of the file so it never lands in `ps`/serial logs. If no key file is given the daemon **refuses
  to start** (fail loud — a control plane with no auth is never an accident), unless
  `--allow-unauthenticated` is explicitly passed for a loopback-only dev bind, which is logged loudly at
  every request.

The auth check is one tower/axum middleware layer wrapping every route **except** `/healthz` and
`/openapi.json`, so a new route is authenticated **by default** (you opt out, you don't opt in — the
safe default, v20 §12.2 "defaults get the strictest scrutiny"). The parity gate (§D5.2) asserts the
opt-outs are exactly those two. Unit tests (KVM-free): correct key → 200 (positive control); wrong key →
403; absent → 401 with `WWW-Authenticate`; and a **timing** test that the compare is constant-time in
shape (equal-length inputs take a data-independent path) is a red-on-inverse guard against a future
`==` regression.

Future extension (recorded, not built): JWT bearer tokens (the `jsonwebtoken` crate is already in-tree,
v20 dep graph) for short-lived, scoped credentials, and per-key scopes (read-only vs. full). v1 is a
single all-scopes key; the middleware seam is where scopes would attach.

---

## D7. The client library and CLI

### D7.1 `vmcell-daemon-client` — a Rust API that mirrors the entry points

The client offers a typed Rust API that matches the `vmcell` entry points as closely as the network
boundary allows. It is built on `reqwest` (already in-tree, v20 §10.4) and re-exports the DTOs from
`vmcell-daemon` (the `client` feature, §D1.1) so a request the client serializes and the server
deserializes are **the same Rust type** — the wire schema is single-sourced, and a field added to the
DTO is a compile error in the client if it is required, never a silent skew.

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

The mapping to the v20 §10.2 `MicroVm` API is intentionally tight: `run`/`create`/`snapshot`/`stats`
match the CLI verbs of the same name, and `exec`/`ls`/`rm`(`destroy`) are the four verbs `vmcell-cli`
could only fail-loud on — the client is where they finally work, over the daemon's owned VM registry.
The single **forced divergence** the integrator anticipated: a `vmcell run --kernel <path> --rootfs
<path>` becomes `upload_artifact("k", "…/vmlinux")` + `upload_artifact("r", "…/rootfs.erofs")` +
`run("k", "r", cmd)` — a host **path** is replaced by an **upload + name reference** (§D8).
`upload_artifact` accepts either raw bytes or a local path (v1 reads the file into memory; streaming a
large image is a small follow-up, §D12).

The client's error type surfaces the daemon's typed `{error, message}` as a matchable enum (a 409
`AlreadyExists` is `ClientError::AlreadyExists`, not an opaque status), so callers branch on the same
conditions the server names — matchability across the boundary, not stringly-typed status codes.

### D7.2 `vmcelld-ctl` — the CLI wrapper

A thin `clap` wrapper over `DaemonClient`, reading `--daemon-url` (default the local bind) and
`--api-key-file` from flags/env, with subcommands that mirror the client methods:
`vmcelld-ctl artifact put|ls|rm`, `vmcelld-ctl run|create|exec|ls|stats|snapshot|rm`. `run` streams
stdout/stderr and propagates the guest exit code exactly as `vmcell run` does (v20 §11, the exit-code
contract). It is a **wrapper only** — no logic beyond argument marshaling and output formatting lives
here (AGENTS.md "functionality in the library, binary is the wrapper"), so the CLI has nothing to
unit-test that the client library does not already cover, and its tests are argument-parsing shape tests.

---

## D8. Entry-point API changes this effort uncovered

The integrator invited API changes "if this effort uncovers issues." Because the daemon **owns** its VM
handles (§D4) rather than detaching them, it needs **no** new vmcell primitive — the single-process
ownership model is reused in-process. What it uncovered is one forced client-side divergence (paths →
upload), the resource-prefix addition (§D4.1, the vmcell 0.5.0→0.6.0 bump), and two clarifications.

1. **Artifact paths become artifact names + an upload API (the forced client divergence).** `vmcell`'s
   entry points take `kernel: PathBuf` / `rootfs: PathBuf` (host paths, v20 §10.2). Over a network
   boundary a host path on the *client* is meaningless to the *daemon*, and a client-supplied *server*
   path is a traversal hole (§D3.1). So the daemon's VM APIs take artifact **names** resolved against its
   own store, and the client grows an **upload** step. This is the divergence the integrator predicted;
   it is contained entirely in the daemon/client layer — `MicroVm`/`VmConfig` are unchanged.

2. **The process-global allocators finally have their intended single home (a clarification, not a
   change).** v20 §10.2 says the `VmidAllocator`/`CidAllocator` "are process-global … a single shared
   instance per test-runner process." The daemon *is* that process for the productized path, so it holds
   one `VmidAllocator::shared()` + one `Arc<CidAllocator>` and injects them into every `start`/`restore`.
   No API changes; the existing injected-seam signature (v20 §10.2) already accommodates it. This
   validates the seam design rather than forcing a change.

3. **`MicroVm::agent(&mut self, timeout, clock)` is verbose across a request boundary (records an
   existing gap, does not fix it).** The daemon calls `agent()` on every `exec`/`stats`, re-passing a
   timeout and a `RealClock` each time — precisely the M-ORCH-6 "`agent()` still takes a per-call
   timeout/clock" cleanup v20 §16 already lists as deferred. The daemon does not fix it (out of scope),
   but its call sites are a second consumer confirming the cleanup is worth doing; noted so a future
   `agent()`-signature change knows both call sites (CLI + daemon).

---

## D9. Cross-cutting invariants (added / touched)

New invariants this subsystem introduces, in the v20 §12 register style (one predicate, one owner):

- **D9.1 — Every client-named artifact goes through `resolve_artifact_path`.** The single predicate that
  turns a name into a path (§D3.1). Owner: `vmcell-daemon::artifact`. No handler or VM-API path calls
  `dir.join(client_string)` directly. Gate: the red-on-inverse traversal tests + a grep review-reject.
- **D9.2 — The daemon retains caps; it never drops-and-execs, and never runs degraded.** The precondition
  is checked at start-up against the **effective** set (or `euid==0`) and the process refuses to start
  otherwise (§D2). Owner: `vmcelld` main + `vmcell-privilege::ensure_blessed_or_explain`. Gate: the
  moved `compute_missing` effective-vs-permitted test.
- **D9.3 — Authenticated by default; two named opt-outs.** Every route is behind the bearer layer except
  `/healthz` and `/openapi.json`; a new route is authenticated unless it opts out (§D6). Owner:
  `vmcell-daemon::auth` + the router. Gate: the parity test asserts the opt-out set is exactly those two,
  and that every VM/artifact op carries the security requirement.
- **D9.4 — The served OpenAPI document and the mounted routes are the same table.** §D5.2. Owner:
  `vmcell-daemon::openapi`. Gate: the route-parity test.
- **D9.5 — The registry owns its VMs; teardown is ordered and shared; a start-up sweep reclaims crash
  leaks.** `destroy`/`shutdown_all` use the same graceful `MicroVm::shutdown`, and dropping the registry
  runs each `MicroVm::Drop` — the panic path — with the identical ordered cleanup (v20 §12.10); a hard
  kill is covered by the start-up `sweep_orphans` run with an empty live set (§D4). Owner:
  `vmcell-daemon::registry` + `vmcell-daemon::sweep`. Gate: the fake-launcher registry test asserts
  `destroy`/`shutdown_all` run teardown and clear the entry (the recording fake counts shutdowns), and
  `sweep_orphans`'s own v20 unit test proves it deletes only not-live vmids in order.
- **D9.6 — No secrets in process-visible surfaces.** The API key is a perms-checked file, never a CLI
  arg/env/serial line (§D6) — the v20 "no secrets in kernel cmdline or agent output" rule extended to the
  daemon's own credentials. Gate: a start-up test that a group/other-readable key file is refused.

Invariants **inherited unchanged** and now with a second enforcement site: v20 §12.1 (snapshot-eligible
= no vhost-user — the daemon's `snapshot` verb rejects an ineligible config with `Unsupported`, reusing
`config_has_vhost_user_device`, never a second copy), §12.10 (ordered teardown), §12.2 (fail loud on a
missing capability).

---

## D10. Testing and gates

Per AGENTS.md, the whole subsystem is built so its logic is unit-testable **without KVM or root**, and
every recurring defect class has a gate that can go red. The KVM-free core (which is most of it):

- **`resolve_artifact_path`** — red-on-inverse for `..`, `/`, absolute, leading `-`/`.`, empty, oversize,
  NUL; positive control accepts and joins correctly (§D3.1).
- **The artifact store** — create/list/delete against a `tempdir`: create-then-create is `AlreadyExists`
  (the "no update" guard, red if overwrite is ever allowed); delete removes the file (residue check:
  existed-before, gone-after); the atomic-rename path leaves no `.tmp` residue on a simulated mid-write
  failure; oversize upload is `PayloadTooLarge`.
- **Auth** — correct/wrong/absent key → 200/403/401; constant-time compare shape; world-readable key
  file refused at start-up.
- **OpenAPI parity** — routes ⇔ document, every op has a security requirement, opt-outs are exactly
  `/healthz` + `/openapi.json` (§D5.2).
- **The owning registry** — over a recording `FakeLauncher`/`FakeHandle` + a real artifact store
  (`tempdir`): create registers `Ready`; exec returns the data-plane output; `destroy` and `shutdown_all`
  run the graceful teardown and clear the entry (the fake counts shutdowns — RED if teardown is skipped);
  an ephemeral `run` execs and leaves no VM; a missing artifact is a `BadRequest`; `is_artifact_in_use`
  tracks pins and releases them on teardown; `snapshot` writes under a validated prefix and rejects
  `../escape`. (The `MicroVm::Drop` teardown and `sweep_orphans` themselves are covered by v20's tests.)
- **The HTTP wiring** — via `tower::oneshot`: `/healthz` + `/openapi.json` are reachable without a token;
  a protected route is 401 without / 403 with a wrong token / 200 with the right one; an unmounted route
  is 404 (the auth-by-default + parity wiring proof).
- **The daemon error → status map** — each variant maps to its documented code; a wrapped `vmcell::Error`
  renders `Display`, never the `Debug` struct-dump (the L-BIN-4 guard, v20 §11).
- **`vmcell-privilege`** — the runner's moved tests (remediation `+ep`, `compute_missing`, the plan
  tests, the confinement tests) keep passing for both callers, proving the extraction is behavior-preserving.

**Host-facing validation — an automated integration suite** (`crates/vmcelld/tests/integration.rs`, run
by `just test-daemon`). The suite is **inverted** relative to manual use: nextest wraps the **test
binary** with the blessed `vmcell-test-runner` (target-runner), so the *test* holds the caps and spawns
`vmcelld` **directly** (the daemon inherits the ambient caps, §D2). That inversion is deliberate — a
privileged test can plant privileged pre-existing state and inspect host residue, which a
`vmcelld`-via-runner spawn from an unprivileged test cannot. The suite runs under a systemd-delegated
cgroup scope (`with-delegated-scope.sh`) so `limits_enforced` sees real enforcement. It asserts on the
**data plane** (the guest's captured stdout, not a proxy signal — v20/AGENTS.md), never a silent skip
(fail-loud if the runner/artifacts/caps are absent). Manual poking, by contrast, launches `vmcelld`
*through* the runner (`just daemon`).

**Validated on the KVM host (2026-07-04), 11/11 green** (+ the `vmcell` unit suite 326/326 via nextest).
The suite passed: `/healthz` + artifact list;
`POST /v1/vms` **booted a real Cloud Hypervisor micro-VM** and `exec` returned `exit 0` with the guest's
stdout (`id -un`=root, `uname -r`=6.12.94 — genuine data-plane reads); the full
`create`→`list`→`exec`→`stats`→`destroy`→`list`-empty lifecycle; bearer auth 401/403/200 with the
`WWW-Authenticate` challenge; **`limits_enforced` true under the delegated scope** (`mem_current_mib` 64)
and honestly false without (both `limits_enforced` and `mem_read_ok` track delegation — memory metrics are
*unreadable*, not merely unenforced, in a non-delegated slice, §7.2); the **start-up sweep** reclaimed a
planted orphan netns (`vmcell-net-*`); **`destroy` removed the per-VM scratch dir** (`<temp>/vmcell-vm-
<pid>-<vmid>`, the ordered-teardown residue check); **snapshot → restore-by-name** preserved a guest tmpfs
marker across the memory round-trip; **privileged tap networking** gave the VM a host netns and the guest
`eth0` a `10.200.x/30` + default route; the **`vmcelld-ctl` CLI** drove `run`/`ls`/`artifact ls` against a
live daemon; and a **custom `--resource-prefix acme`** named the VM's netns `acme-net-*`, swept only
`acme-*`, and left a `vmcell-*` orphan untouched (§D4.1 isolation). **Still open** (forward work for the
suite): the QEMU/Firecracker snapshot tiers
(v20 §16 already list these as unwired), filtered-egress validation, and a concurrent-load / density run.

**CI gates added** (each can go red): the KVM-free tests above run in the default `just ci`; the
`vmcell-privilege` **lean-tree** assertion (no `tokio`/`hyper`/`rtnetlink`) joins the existing per-member
`cargo tree` checks (v20 §10.5); `cargo deny` re-runs over the new deps (§D11); `cargo semver-checks`
covers the new public library surfaces (`vmcell-daemon`, `vmcell-daemon-client`, `vmcell-privilege`).

---

## D11. Amendments to v20 and to the build system

- **v20 §10.1 (workspace layout)** — add the five members (§D1.1). The "four lean member crates" prose
  gains `vmcell-privilege` as a fifth lean member (lean by the same per-member `cargo tree` property).
- **v20 §11 (CLI verbs)** — `vmcell-cli`'s `exec`/`ls`/`rm`/`destroy` **stay as fail-loud stubs** for now:
  they still return a typed `Error::Unsupported` (no fake success — the `deferred_to_daemon` helper and
  its `daemon_deferred_subcommands_fail_loud` test are retained). The daemon now genuinely owns those
  verbs, so removing the stubs (or repointing them to "use `vmcelld-ctl`") is a straightforward follow-up
  once the daemon path is KVM-validated. `vmcell-cli` keeps its single-process verbs
  (`build`/`build-kernels`/`oci2erofs`/`run`/`create`/`snapshot`/`stats`/`bundle`/`verify-bundle`).
- **v20 §16 (open gaps)** — the "`impd` daemon" gap **closes for the core verbs** (`create`/`list`/`exec`/
  `stats`/`snapshot`/`destroy`). Residuals move to §D12 (warm-pool manager, setup broker, UDS transport,
  JWT/scopes).
- **v20 §17 (future capabilities)** — the "`impd` daemon + versioned control-plane API" line graduates to
  **built**; the "warm-pool manager" and "setup broker … recommended privilege boundary for the
  daemon/API mode" remain future and are re-listed in §D12.
- **`justfile`** — `bless` blesses **only the runner** (not `vmcelld`): the daemon gets its caps at
  launch through the blessed runner (§D2), so blessing it per-rebuild is unnecessary churn. The `daemon`
  recipe builds `vmcelld` and runs it **via the runner** (`{{runner}} target/debug/vmcelld …`) for manual
  poking. **`test-daemon`** runs the integration suite: it wraps the test binary with the runner
  (`CARGO_TARGET_..._RUNNER`) under a systemd-delegated scope, so the tests are privileged and spawn
  `vmcelld` directly (the inversion, §D10). The `vmcelld` integration-test binary auto-joins the
  `serial-host` nextest group (a `package(vmcelld) & kind(test)` override), so its VM-booting tests do not
  race the `vmcell` suite on netns/cgroup/tap. `ci` picks up the new crates via `--workspace`. (A
  standalone/production `vmcelld` is capped by the service manager or a one-off `setcap`, §D2.)
- **`deny.toml`** — the new **linked** deps are `axum` + `tower`/`tower-http` (MIT), `subtle` (BSD-3),
  and (client) nothing new beyond `reqwest` (already in-tree). `axum`/`hyper`/`tower` already resolve in
  the tree (v20 dep graph, via `hudsucker`), so the license allow-list already admits them; the gate
  re-runs and any genuinely new transitive license is added with a rationale (v20 §10.4 "trust
  cargo-deny, not hand-written labels"). No copyleft enters.
- **`AGENTS.md` / `README`** — the crate roster line gains the daemon/client crates and the two operating
  modes note that the **daemon is the third entry surface** alongside the library and the CLI. The soft
  design pointer ("use the latest version you find") already resolves to this v21.

---

## D12. Open decisions and forward work (this subsystem)

Honest edges, in the v20 §16 voice:

- **The real launcher is complete but KVM-unvalidated here.** Because the daemon owns the `MicroVm`
  handle, `MicroVmLauncher` needs no new vmcell primitive — it calls `MicroVm::start`/`agent`/`usage`/
  `snapshot`/`shutdown` directly. The whole registry *logic* is exercised by a recording fake launcher
  (no KVM); the real launcher's live boot/exec/teardown must still be validated on a KVM host (the §D10
  host-facing suite), which cannot run in this environment — so it is written and reviewed, not yet
  empirically green (the AGENTS.md "host-facing claims are validated by executing on a KVM host" rule).
- **VMs do not outlive the daemon (a deliberate consequence of owning-and-`Drop`).** A clean `vmcelld`
  exit tears its VMs down; a hard kill leaks them and the next boot's sweep reclaims the residue. This is
  the opposite of a detached model and is the point: resources are owned and released, never orphaned. If
  daemon-surviving VMs are wanted later, that is the detached variant — explicitly *not* v21.
- **`pause`/`resume` are not in the v1 surface.** The registry + handle support them (the seam has
  `pause`/`resume`), but no HTTP route is mounted yet; adding the two routes + `Paused` state transitions
  is a small follow-up, deferred to keep the v1 surface tight.
- **Single-process privilege (no setup broker yet).** v21 binds the HTTP surface in the **same** process
  that holds the ambient caps. The v20 §17 **setup broker** — a minimal-privilege helper that performs
  the netns/tap/nft bring-up so the network-facing process holds *no* caps — is the recommended hardening
  and is **forward work**. Mitigations shipped now: bind loopback/UDS by default, auth-by-default, the
  key-file perms check, and per-VMM seccomp is orthogonal (v20 §17). This is stated plainly, not hidden.
- **Transport is TCP (loopback default); a `XDG_RUNTIME_DIR` Unix-socket bind is the better local
  default** (filesystem-permission access control, no port, honors the v20 "runtime files under
  `XDG_RUNTIME_DIR`, never bare `/tmp`" rule) and is a small follow-up — axum serves a UDS listener with
  no handler changes. v21 ships TCP because bearer auth + OpenAPI assume an HTTP origin; the UDS bind is
  additive.
- **Warm-pool / zygote manager.** The zygote primitive exists (v20 §9.4) but v21 does **not** ship a pool
  manager (pre-warm N clones, hand one out per request, scale-to-zero) — it is the natural next daemon
  feature (`POST /v1/pools`), gated on the §9.4 fan-out capability. The registry already owns the handles,
  so a pool is an ownership + hand-out policy on top, not a new primitive.
- **Auth is a single all-scopes key.** No JWT, no per-key scopes, no rotation endpoint in v1 (§D6). The
  middleware seam is where scopes/JWT attach; `jsonwebtoken` is already in-tree.
- **Artifact GC / quotas.** The store enforces a per-upload size cap but no total-dir quota or
  unreferenced-artifact GC; a leaked upload lingers until `delete`. A quota + `list`-with-refcounts is a
  small follow-up.
- **CLI stub vs. removal (§D11).** v21 **keeps** `vmcell-cli`'s `exec`/`ls`/`rm`/`destroy` as fail-loud
  stubs; the daemon now genuinely owns those verbs, so removing the CLI stubs (or repointing them to
  "use `vmcelld-ctl`") is a straightforward follow-up.
- **`agent()` per-call timeout/clock (M-ORCH-6).** The daemon is a second consumer that would benefit from
  the deferred `agent()`-signature cleanup (§D8.3); still deferred.
