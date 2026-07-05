# vmcell — Design Document (v22)

> **v22 (this revision) — two config-surface capabilities graduate from forward-work to built.** The
> v20 §17 "cheap, high-value, extend an existing seam" line — *"extra virtio-blk devices … (plain
> virtio-blk composes with snapshot); append-only extra kernel cmdline + optional `init=` override"* —
> ships. `vmcell` gains three additive `VmConfig` fields and one new public type, all `#[non_exhaustive]`-
> compatible (a `cargo semver-checks` non-break): **`extra_disks: Vec<BlockDevice>`** (arbitrary extra
> virtio-blk devices), **`extra_kernel_args: Vec<String>`** (append-only extra boot args), and
> **`init: Option<PathBuf>`** (a genuine `init=` override). The one deviation from the v20 §17 wording is
> recorded in `implementation-notes.md`: an `init=` override *replaces* the vmcell guest agent as PID 1,
> so it forgoes the vsock control plane — vmcell honors that honestly (fail-loud, not a silent hang)
> rather than reinterpreting "custom init" as an agent-supervised entrypoint. **Amends** v20 **§8.3** (the
> shared cmdline builder gains an append-only tail and an init-token override), **§10.2** (`VmConfig` +
> the `BlockDevice` type), **§12.1** (extra plain virtio-blk is explicitly snapshot-eligible — a second
> enforcement note, not a new predicate), and **§17** (both items graduate to built). It adds **no** new
> crate, **no** new dependency, and **no** guest-agent change. The house rules from AGENTS.md apply
> unchanged: one law one predicate, validate-at-construction, fail-loud, every claim ships with a gate.
>
> **Pass 2 (2026-07-05) completes v22's own forward work:** the **daemon-API exposure** of the new knobs
> (§E4, now built) and **disk-I/O fault injection** on the `BlockDevice` seam (§E5, new). `BlockDevice`
> gains an optional `io_limit: Option<DiskIoLimit>` (bandwidth + IOPS throttling, portable across all
> three backends' native rate limiters); the daemon's `CreateVmRequest` gains `extra_disks` (artifact
> names + `io_limit`) and `extra_kernel_args` (a custom `init=` is deliberately *not* daemon-exposed —
> it drops the control plane the daemon owns). Additive only: `vmcell` and the daemon DTO stay
> semver-clean.

This is a **focused amendment** on top of v20 (`docs/49-claude-design-v20.md`) and v21
(`docs/53-claude-design-v21.md`); everything they state still governs and is not repeated. Read v20 §8.3
(the cmdline builder), §10.2 (`VmConfig`), §12.1 (the snapshot-eligibility law), and §17 (the roadmap
line) first.

---

## E1. Extra virtio-blk devices

### E1.1 The shape

A new public type models one extra disk, mirroring `Share`'s ergonomics:

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlockDevice { pub image: PathBuf, pub readonly: bool }
impl BlockDevice {
    pub fn read_only(image: impl Into<PathBuf>) -> Self;   // readonly: true
    pub fn read_write(image: impl Into<PathBuf>) -> Self;  // readonly: false
}
```

`VmConfig` gains `extra_disks: Vec<BlockDevice>` (builder `.with_extra_disk(BlockDevice)`, default empty).
The guest kernel enumerates them as **`/dev/vdb`, `/dev/vdc`, …** in attachment order; the root disk stays
`/dev/vda` (the cmdline hard-codes `root=/dev/vda`, v20 §8.3). vmcell attaches the **raw** block device
only — no partitioning, no filesystem, no mount. The guest workload owns the device (mount it over exec,
`dd` to it, read it raw); **the guest agent does not auto-mount extra disks and needs no change** (an
unknown `/dev/vdX` is invisible to it). This is the deliberately minimal guest contract: raw exposure is
zero new guest code and zero new cmdline token, and auto-mount is a capability the workload can do itself
(if it is ever wanted, model it on `vmcell_share=`/`parse_share_mounts`, best-effort so a bad token never
panics PID 1).

### E1.2 Per-backend wiring — attach *after* the root disk

The root disk must remain device index 0 (`/dev/vda`), so every backend appends extra disks **after** the
rootfs disk:

- **Cloud Hypervisor** (primary): push one `ChDisk { path, readonly, direct: false }` per extra disk onto
  `ch_cfg.disks` after the rootfs arm. CH assigns `/dev/vd{a,b,c}` purely by array order.
- **QEMU**: emit a split-form `-drive file=…,format=raw,id=extra{i},if=none[,readonly=on],file.locking=off`
  + `-device virtio-blk-pci,drive=extra{i}` pair per extra disk, after the rootfs `-drive`. PCI enumeration
  order gives `vdb, vdc, …`. No fixed device cap (PCI slots).
- **Firecracker**: `PUT /drives/extra{i}` with `is_root_device: false, is_read_only: readonly` after the
  rootfs PUT. Each consumes one virtio-mmio slot; FC's MMIO region is finite, so a very large extra-disk
  list eventually exhausts it — that surfaces fail-loud as the backend's typed API error at `create()`,
  never a silent drop. (No arbitrary numeric cap is invented in the library; the exact FC MMIO budget is a
  backend-internal constant this codebase does not mirror.)

### E1.3 Snapshot composition (§12.1) and restore path-stability

Plain virtio-blk is **not** a vhost-user device, so an extra disk is **snapshot-eligible** — it does not
enter `config_has_vhost_user_device` (which keys only on virtio-fs shares/rootfs, unprivileged
vhost-user-net, and an external vhost-user-net socket). This is the "plain virtio-blk composes with
snapshot" claim of v20 §17/§5.1, and it is guarded by a unit test asserting an extra disk does **not** flip
the predicate (a false positive would wrongly disqualify snapshot). A block device's contents live on disk,
*outside* the memory snapshot, so a writable extra disk carries whatever bytes it holds at restore — that
is correct block-device semantics, not a leak. CH restore reconstructs the full `disks[]` array from the
snapshot's `config.json`, and FC restores devices verbatim from the snapshot, both using the **paths
recorded at snapshot time** — so an extra disk's image path must be **stable across a restore** (not inside
the deleted per-VM scratch dir). This is documented on `VmConfig::extra_disks`; the common case (a
caller-owned image at a fixed path) needs no restore-time rewrite.

### E1.4 Validation and gates

`build()` rejects, each with a negative test: an empty or non-absolute extra-disk image path; a duplicate
extra-disk image (two attachments of one backing file — a rw corruption footgun). Existence is **not**
checked (consistent with rootfs/shares — `build()` never stats paths). Capability: all three backends boot
off virtio-blk, so extra virtio-blk is **universally supported** — no new `VmmCapabilities` flag and no
`require_cap!` gating. Gates: the CH `ChVmConfig` serialization unit test is extended to pin that extra
disks serialize into `disks[]` in order with the right `readonly` flag after the root disk; the
snapshot-eligibility predicate test pins extra disks stay eligible; and a KVM host matrix data-plane test
(§E3) attaches a marked image and reads the marker back **in-guest**.

---

## E2. Custom init + append-only extra kernel args

### E2.1 Append-only extra kernel args — the one predicate

`VmConfig` gains `extra_kernel_args: Vec<String>` (builder `.with_kernel_arg(impl Into<String>)`). They are
appended **last**, after every token the shared `build_kernel_cmdline` (v20 §8.3) emits, in caller order.
"Append-only" is the safety contract: an extra arg can **add** a boot parameter but can never **clobber** a
token vmcell owns. It is enforced by one predicate — `is_reserved_cmdline_arg(arg)` — used by `build()`:

- The arg's **key** (text before the first `=`, or the whole bare token) must not be in
  `RESERVED_CMDLINE_KEYS` (`console`, `loglevel`, `root`, `rootfstype`, `rootflags`, `ro`, `panic`, `init`,
  `ip`, `kvm-intel.nested`, `kvm-amd.nested`, `cryptomgr.notests`, `raid`, `random.trust_cpu`,
  `random.trust_bootloader`, `noxsave`), **and** must not start with `vmcell_` (the guest agent *trusts*
  `vmcell_share=`/`vmcell_accept_poll_ms=`/`vmcell_rebind_idle_ms=`, so a caller must not be able to spoof
  one).
- The arg must be a single cmdline token: non-empty, no whitespace, no control characters (a space would
  forge a second token — the cmdline-injection guard; quoted values with embedded spaces are out of scope
  this pass).

The **one-law gate** is a unit test that builds a cmdline exercising every emitted token (block rootfs +
networking + a share + nested) and asserts `is_reserved_cmdline_arg` is `true` for **every** token — so the
reserved set can never silently fall out of sync with what the builder emits (add a new builder token
without reserving its key → red). This is the same "one law, one predicate, pinned by a test" discipline as
`config_has_vhost_user_device` and `mac_math`.

### E2.2 The `init=` override — a genuine PID-1 replacement, honored honestly

`VmConfig` gains `init: Option<PathBuf>` (builder `.init(impl Into<PathBuf>)`). When `Some`, the shared
builder emits `init=<custom>` in place of the fixed `init=/usr/sbin/vmcell-guest-agent` — the **only** place
either token is constructed (one law, one predicate; a backend never string-builds `init=`). `build()`
validates the path: absolute, valid UTF-8, no whitespace/control characters (a single safe cmdline token).

**A custom init replaces the vmcell guest agent as PID 1, so it forgoes the vsock control plane** — no
`Ready` handshake, no `exec`, no post-restore resync (all live in the agent, which is no longer running).
vmcell makes that consequence loud, never silent (§12.2):

- **`MicroVm::agent()` fails loud** with a typed `Error::Agent` naming the custom-init cause, instead of
  hanging for the full connect timeout on a listener that will never answer.
- **`MicroVm::start()` skips the QEMU control-plane health probe** (`verify_control_plane`) when `init` is
  overridden — that probe exists to confirm the *agent's* vsock transport, and there is no agent to
  confirm; without the skip a custom-init QEMU VM would re-spawn to exhaustion and fail to start. (CH/FC
  probes are already no-ops.) `start()` still boots and returns the handle — the caller drives/observes the
  VM out-of-band: the serial log (the custom init's `console=ttyS0` output is captured to `serial.log`), a
  read-write extra virtio-blk device (§E1) or virtio-fs share, or networking.
- **`build()` rejects `snapshotting == true` with a custom `init`** — the mandatory post-restore resync
  (clock, entropy reseed, MAC/IP rotation, §12.4) runs *through the agent*, which a custom init replaces;
  a restored custom-init clone would be stranded on frozen identity with no way to fix it from inside
  (silently dead egress / correlated RNG), exactly the trap §12.4 forbids. Fail-loud at construction.

A caller who wants a program to run at boot *without* giving up the control plane should keep the default
init and `exec` the program over vsock — that is what `exec` is for; the `init=` override is the escape
hatch for booting a genuinely different PID 1 (the fidelity / systems-testing domain), which necessarily
means a different (or no) control plane. A custom init on the read-only erofs root also has no writable
`/` (the agent's tmpfs overlay setup no longer runs), so a custom-init VM typically pairs with a writable
rootfs (`RootfsSource::Block`) or a writable extra disk — a caller responsibility, documented on the field.

### E2.3 Gates

`build()` negative tests (one per case): a reserved-key or `vmcell_`-prefixed extra arg; a whitespace /
control-character extra arg or init path; a non-absolute init path; `snapshotting` + custom init. A golden
`build_kernel_cmdline` test asserts the init override replaces the default (exactly one `init=` token,
`root=`/`vmcell_vmid=` intact) and that extra args appear appended after every reserved token; the existing
"all backends have loglevel" test continues to pin the default init. A KVM host test (§E3) boots a custom
init and asserts the data plane (the kernel ran the overridden init) plus that `agent()` fails loud.

---

## E3. Host-facing validation

Both features are validated on the KVM host (this environment is KVM-capable — `/dev/kvm` rw, CH installed,
runner blessed, artifacts built) per AGENTS.md rule 5. Neither feature changes the guest agent or the
rootfs, so the existing `rootfs.erofs`/`vmlinux` are reused unchanged. New `#[ignore]`-gated tests, run via
`just test-privileged` under a systemd-delegated scope through the blessed `vmcell-test-runner`:

- **`tests/extra_block.rs`** (`vmm_matrix_test!`, CH/FC/QEMU): create a small marked raw image, attach it
  read-only, boot, and assert the marker read back **in-guest** off `/dev/vdb` (a data-plane read, not a
  proxy signal). A read-write variant `dd`s a marker in and reads it back. Self-cleaning (the temp image is
  removed on teardown — no sudo, per the host-hygiene preference).
- **`tests/extra_block.rs :: extra_block_survives_snapshot`** (`vmm_matrix_test!` + `require_cap!
  (snapshot_restore)`, CH/FC): the V:high "composes with snapshot" proof — write a marker to a writable
  extra disk, snapshot, restore into a fresh VM (fresh vmid), and read the marker back off `/dev/vdb`.
- **`tests/custom_init.rs`** (CH primary): boot with an `init=` override at `Verbose` verbosity and assert
  the serial log shows the kernel ran the overridden init; assert `agent()` returns the fail-loud
  custom-init error. Snapshot + custom init is rejected at `build()` (KVM-free).

**Validated 2026-07-05 on this KVM host, all green** (via `just test-privileged` filtered to these tests,
under a systemd-delegated scope through the blessed runner): `extra_block` on **CH + Firecracker + QEMU**
(two extra disks attach after the root — `/dev/vdb` read-only marker read back in-guest, `/dev/vdc`
read-write marker round-tripped); `extra_block_survives_snapshot` on **CH + Firecracker** (the extra-disk
marker survives a real snapshot→restore into a fresh vmid — the headline claim, on the data plane; QEMU
skips, no snapshot); `custom_init` on **CH** (`init=/bin/sh` at Verbose — the kernel serial log shows
`Run /bin/sh as init process`, and `agent()` fails loud). One CH-specific fix landed en route: CH v52
auto-detects an unspecified image as raw and disables sector-0 writes, so every disk is now declared
`image_type=Raw` explicitly (also pre-empting the same latent bug on the writable `Block` rootfs path — see
`implementation-notes.md` v22(b)).

---

## E4. CLI and daemon exposure

- **CLI (`vmcell-cli`)** gains additive flags on `run`/`create`: `--disk <PATH>` (repeatable, read-only),
  `--disk-rw <PATH>` (repeatable, read-write), `--append <ARG>` (repeatable) — thin wrappers over the new
  builder methods at the single `ephemeral_vm` construction site. A custom `init=` is **not** a CLI flag:
  every CLI verb brings the agent up (`run` execs, `create` confirms agent-ready), which a custom init
  precludes — a custom-init VM is a library-only escape hatch.
- **Daemon (`vmcell-daemon`)** — **built (pass 2).** `CreateVmRequest` gains `#[serde(default)]`
  `extra_disks: Vec<ExtraDiskSpec>` and `extra_kernel_args: Vec<String>`, threaded `CreateVmRequest →
  LaunchSpec → VmConfig` (registry resolves + the launcher builds). An `ExtraDiskSpec` is an artifact
  **name** (resolved through `resolve_artifact_path` like `kernel`/`rootfs`, §D3.1) plus an optional
  `io_limit` (§E5). Two deliberate divergences from the library, both forced by the daemon's model:
  - **Extra disks are read-only.** The store is create-only/immutable (§D3.2); a *writable* disk backed by
    a shared store artifact would let one VM mutate an artifact another VM reads. A writable-scratch-from-
    artifact (copy-on-attach) is a small follow-up.
  - **No `init=` override.** The daemon *owns* the VM through the vsock control plane (it brings the agent
    up to mark `Ready`, and serves `exec`/`stats`), which a custom init drops — so it is not exposed; use
    the library for a custom-init VM.
  A live VM **pins** its extra-disk artifacts (the delete-in-use guard, §D3.2, now checks extra disks as
  well as kernel/rootfs). A bad knob (a reserved kernel arg, a `0` io_limit) surfaces as the library's
  `Error::Config`, now mapped to **`BadRequest` (400)** rather than a misleading 500 (a config-validation
  failure is a client error). The OpenAPI document is unchanged — it describes paths + auth, not
  request-body schemas, so the parity gate does not enumerate these additive fields.

---

## E5. Disk-I/O fault injection (the `BlockDevice` seam)

`BlockDevice` gains `io_limit: Option<DiskIoLimit>` (builder `.with_io_limit(DiskIoLimit)`), the disk half
of v20 §17's *"extra virtio-blk devices + disk-I/O fault injection"*. `DiskIoLimit` is a `bandwidth_bytes_
per_sec` and/or `iops` cap — the **portable** form of the fault (a slow/pressured disk, to test a
workload's timeout/retry/backpressure), because every backend has a native per-disk rate limiter, including
the **primary** CH (unlike error-injection, which is QEMU-`blkdebug`-only and stays forward work). `build()`
rejects an `io_limit` that limits nothing, or any `0` cap (a `0` bucket never refills → wedged I/O).

Each backend expresses the cap with its native limiter, and the CH and Firecracker token buckets share
**one** conversion (`IO_LIMIT_REFILL_TIME_MS`, a bucket of `size = rate` refilled every 1000 ms = `rate`/s)
so they can never encode the same `DiskIoLimit` as different rates (one law, one predicate):

- **Cloud Hypervisor** — `ChDisk.rate_limiter_config { bandwidth, ops }` token buckets.
- **Firecracker** — the drive's `rate_limiter { bandwidth, ops }` token buckets (identical shape).
- **QEMU** — `-drive …,throttling.bps-total=<B>,throttling.iops-total=<N>` (the per-second rate directly).

It composes with snapshotting like any plain virtio-blk (§E1.3) and is exposed over the daemon (§E4). Gates:
a unit test pins the CH `rate_limiter_config` bucket (`size = rate`, `refill_time = 1000`); `build()`
rejection tests; and a self-calibrating KVM data-plane test (`extra_block_io_throttle`) reads an
un-throttled disk and a 1 MiB/s-throttled disk of equal size in one VM and asserts the throttled read is
both slow in absolute terms and far slower than the baseline.

**Pass-2 validation (2026-07-05, this KVM host, all green):** `extra_block_io_throttle` on **CH + FC +
QEMU** (the 1 MiB/s cap floors a 4 MiB read at ~3 s on every backend); the daemon
`extra_disk_over_api_data_plane_and_delete_in_use` (`just test-daemon`) drove the full HTTP path — upload a
marked image, `POST /v1/vms` with `extra_disks`, read the marker off `/dev/vdb` in-guest, and confirm the
disk artifact is pinned (delete → **409 InUse**) until the VM is destroyed.
