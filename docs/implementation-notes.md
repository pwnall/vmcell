# Implementation Notes

This is the running log of **justified deviations** from the design (per `AGENTS.md`): a place to
record a deliberate divergence, with its reason, at the moment it is made.

**The log is currently empty.** As of the v18 design rewrite (`docs/47-claude-design-v18.md`) every
prior entry has been reconciled into the design document — either folded into the body as the settled,
present-tense state of the system, or dropped as superseded / dated validation bookkeeping. The design
document now reflects the system *as built*, including the deviations that used to live here. Examples of
what was folded in during the 2026-07 wave (the latency-recovery pass, the tunable-knobs + native-resync
follow-up, the `docs/45` investigation, and the `docs/46` review-fix pass):

- the **Firecracker warm-restore wiring** (now `snapshot_restore: true`, cured host-side — cached-client
  invalidation across FC's connection-severing snapshot, verbatim baked-vsock-path re-bind under the
  `reject_live_baked_vsock` guard, the `PUT /entropy` device, and the AGENT-2 pre-spawn reaper epoch — with
  the `restore_rotates_host_paths: false` single-lineage constraint and `lazy_restore: false` UFFD gap);
- the **"rotate everything" restore identity refresh** (MAC *and* IP + default route, native in-agent,
  zero-netlink) delivered by a **single native `Resync`/`ResyncAck` round-trip** that replaced three
  subprocess execs;
- the tunable **`KernelVerbosity` / `ConsoleMode` / `Timeouts`** knobs and the shared `build_kernel_cmdline`
  builder, the **event-driven `poll(2)` guest accept loop**, and the **adaptive shutdown-grace poll**;
- the `docs/46` recorded gaps now documented in the body/§16: `Egress::Open` has no arbitrary egress, the
  privileged `host_services_port` is rejected fail-loud, the `mkfs.erofs` fallback is unwired, the proxy CA
  is per-artifacts-dir, the mmdebstrap keyring is the base-image's, `limits_enforced` means "memory
  controller delegated", the snapshot cache key folds the pinned CH identity, and the carried `vhost`
  patch is vendored in-tree.

See design §12 ("Cross-cutting invariants") for the rules and §16 ("Open decisions and known gaps") for
what remains forward work.

## v20 — builder extraction (rootfs + kernel in-VM builders out of `vmcell`)

- **(a) Kernel bootstrap gains a prebuilt seed producer (`PrebuiltKernelStage`); host-`make` retained as
  fallback.** The design previously had `vmcell` compile the guest kernel only via host-`make`. We added a
  second bootstrap producer that downloads + sha256-verifies a **digest-pinned prebuilt `vmlinux`** (and,
  when it ships inside a tar such as Kata's, verifies the archive digest and extracts+re-verifies the named
  member). *Reason:* the extracted in-VM kernel builder (`vmcell-kernel-builder`) is a chicken-and-egg — it
  needs a working guest kernel to boot the builder VM in which it compiles a kernel, and that seed must
  already carry EROFS + FUSE/virtio-fs + VSOCK + PVH + overlay to boot vmcell's erofs root. Empirically
  validated: a **Kata Containers** prebuilt `vmlinux.container` (Linux 6.18.35, from
  `kata-static-3.32.0-amd64.tar.zst`) boots under Cloud Hypervisor to PID 1 + overlay; a Firecracker CI
  microVM kernel omits `CONFIG_EROFS_FS`/`FUSE_FS` and panics `VFS: Unable to mount root fs`. Host-`make`
  `KernelStage` is the guaranteed fallback seed. See design §8.3, §8.5, §16.

- **(b) In-VM `mmdebstrap` rootfs source un-deferred, moved to `vmcell-rootfs-builder`, on the privileged
  network path.** v19 recorded this source as "library-present but deferred". It is now wired and lives in a
  **new crate**. *Reason:* `mmdebstrap` + apt need **real outbound egress**, which only the privileged/tap
  path with `Egress::Open` provides. Extraction keeps the heavy in-VM machinery out of the library while
  reusing `vmcell`'s `resolve_builder_base` and the shared `pack_erofs_with_injection` tail (every rootfs
  source is identically injected, §5.4). Selected via `vmcell-cli --rootfs-source mmdebstrap`. §8.2, §10.1, §16.

- **(c) CLI moved out of the `vmcell` package into a new `vmcell-cli` composition-root crate.** *Reason:* the
  builder crates depend on `vmcell`; a CLI *inside* `vmcell` referencing them would form a
  `vmcell → builder → vmcell` **cycle**. `vmcell-cli` depends on `vmcell` + both builders and is the only
  crate that names a builder, keeping the graph a directed acyclic star. Drove the `vmcell` **0.4.0 → 0.5.0**
  bump. See §10.1, §11, §16.

- **(d) `hash_*` / `ch_binary_path` / `resolve_builder_base` / `pack_erofs_with_injection` /
  `fold_rootfs_injection_identity` promoted to `pub` so the builder crates reuse one implementation.** The
  extracted builders must reuse the **exact** erofs inject+pack tail, injected-content identity fold,
  builder-base resolution, CH binary discovery, HTTP client, and content-hash functions — duplicating any is
  where per-builder divergence bugs hide. Exposing one implementation via `pub` makes the reuse structural.
  Other half of the 0.5.0 bump. See §5.4, §10.1.

**When you make a new deviation,** add a short entry here — *what* you diverged from and *why* — and,
once it stabilizes, fold it into the design document and delete it from this log. Keep this file
small: a growing log means the design doc has drifted from the code.
