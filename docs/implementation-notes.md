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

## v21 — control-plane daemon (`vmcelld`) + client

Design: `docs/53-claude-design-v21.md`. New crates: `vmcell-privilege`, `vmcell-daemon`, `vmcelld`,
`vmcell-daemon-client`, `vmcelld-ctl`. Fold the settled entries into the design body and delete them here
as they stabilize.

- **(a) The daemon OWNS its VMs (holds the `MicroVm` handles); it is not stateless.** An earlier draft
  explored a stateless daemon (detached VMs + on-disk descriptors + reattach). *Reason it was dropped:* it
  needed a new vmcell detach/reattach primitive AND abandoned the "`Drop` releases resources" invariant.
  The owning model reuses the single-process `MicroVm` ownership in-process, needs **no** vmcell change,
  and keeps teardown-is-ownership intact; crash recovery is the **start-up `sweep_orphans`** (empty live
  set) instead of reattach. See §D4.

- **(b) `vmcelld` is NOT blessed on the dev hot path — it is launched through the blessed
  `vmcell-test-runner`, which confers the caps via the ambient set.** `just bless` blesses only the runner
  (which rarely changes); `vmcell-daemon`/`vmcelld` rebuild with no `setcap` churn. *Reason:* the same
  file-cap-churn problem the runner already solved for the ever-changing test binaries. Standalone/prod
  `vmcelld` uses systemd `AmbientCapabilities=` or a one-off `setcap`. See §D2.

- **(c) INVERTED launch for integration vs. manual.** Integration tests wrap the **test binary** with the
  runner (nextest target-runner) so the test itself holds the caps, and spawn `vmcelld` **directly** (it
  inherits the ambient caps). *Reason:* a privileged test can plant privileged pre-existing state (an
  orphan netns for the start-up-sweep test) and inspect per-VM teardown residue — things a
  `vmcelld`-via-runner spawn from an unprivileged test cannot. Manual poking (`just daemon`) still launches
  `vmcelld` *through* the runner (no privileged test process to inherit from). See §D10, `just test-daemon`.

- **(d) `mem_read_ok`/`limits_enforced` both mean "the memory controller is delegated into the per-VM
  slice" — memory metrics are UNREADABLE (not just unenforced) without a delegated cgroup scope.** An
  integration test initially asserted `mem_read_ok` unconditionally and reddened without delegation
  (`memory.current` doesn't exist in a non-delegated slice). The test now asserts both flags **track**
  delegation (`stats_limits_enforced_matches_delegation`). Honest §7.2 behavior, not a bug.

- **(e) Snapshot/restore/net knobs on the daemon API.** `CreateVmRequest` gained `net`
  (`none`/`privileged`/`unprivileged`), `snapshotting`, and `restore_from` (a store prefix). The launcher
  maps `NetMode`→`NetConfig`, sets `.snapshotting()`, and dispatches cold-boot vs. **`restore_cow`** (so
  the named snapshot is preserved and re-restorable, design v20 §9.4). *Reason:* the daemon defaulted to
  `NetConfig::None` + no snapshotting, so snapshot/restore and real guest networking were unreachable
  through the API. See §D5.1.

- **(f) Guest-tools `ip route` prints the RAW `/proc/net/route` table (hex, tab-separated), not the
  `default via …` form.** The privileged-net test first asserted `ip route` contained `"default"` and
  reddened. A default route is a row with Destination `00000000` (0.0.0.0) and a non-zero Gateway; the
  test now parses that (`has_default_route`) and asserts `eth0` is `state up` with `inet 10.200.x/30`.

- **(g) One configurable resource prefix for naming AND sweeping (`vmcell` 0.5.0→0.6.0).** The
  hard-coded `vmcell-*` names (netns/tap/cgroup/scratch) and the sweep's three filters were seven copies
  of one prefix. Collapsed into the new `vmcell::naming` module (one law: a test pins each produced name
  starts-with its sweep filter), a `VmConfig::resource_prefix` (default `"vmcell"`, `[A-Za-z0-9]`≤6,
  validated at `build()`), and `HostOrphanScanner::new(prefix)`. `vmcelld` exposes it as one
  `--resource-prefix` flag threaded to both the launcher and the start-up sweep. `NetNamespace::create`
  and `VmTempDir::create` gained a `prefix` param (the 0.6.0-driving API change). The VMID lock dir
  `/tmp/vmcell-vmid` is intentionally NOT prefixed (not swept; a stable cross-process rendezvous). See
  §D4.1.

- **Validated on the KVM host (2026-07-04), this env (KVM rw via ACL, CH at `~/.cargo/bin`, runner
  blessed, artifacts built).** `crates/vmcelld/tests/integration.rs` (run via `just test-daemon`, under a
  systemd-delegated scope) — **11/11 green** (+ `vmcell` unit suite 326/326 via nextest): healthz +
  artifact list; real CH micro-VM boot + `exec` data-plane (`exit 0`, guest stdout, `id -un`=root,
  `uname -r`=6.12.94); full create/list/exec/stats/destroy lifecycle; bearer auth 401/403/200;
  `limits_enforced` true under delegation (`mem_current_mib` 64) and honestly false without; start-up
  sweep reclaims a planted orphan netns; destroy removes the per-VM scratch dir; **snapshot →
  restore-by-name preserves a guest tmpfs marker**; **privileged tap net** gives a host netns + guest
  `eth0` `10.200.x/30` + default route; **`vmcelld-ctl`** drives `run`/`ls`/`artifact ls`; **custom
  `--resource-prefix acme`** names the VM's netns `acme-net-*`, sweeps only `acme-*`, and leaves a
  `vmcell-*` orphan untouched (isolation). A harness bug was fixed en route: `Daemon::Drop` must
  `SIGTERM` (graceful `shutdown_all`) then fall back to `SIGKILL`, else a panicking test orphans its CH
  VMs. (Note: one `vmcell` lib unit test races on `/tmp/vmcell-vm-<pid>-*` under `cargo test --lib`'s
  shared-process model but passes under **nextest**, which is process-per-test — the project's runner.)
  **Still unrun:** the QEMU/Firecracker snapshot tiers (v20 §16: unwired), filtered-egress, concurrent-load.

## v22 — extra virtio-blk devices + custom init / append-only boot-args

Design: `docs/58-claude-design-v22.md`. Graduates the two v20 §17 forward-work items. Fold into the
design body and delete here as they stabilize.

- **(a) `init=` override is a GENUINE PID-1 replacement, not an agent-supervised entrypoint.** v20 §17
  names the item "optional `init=` override". Taken literally, overriding `init=` replaces the vmcell
  guest agent (PID 1), which *is* the vsock control plane — so a custom-init VM has **no** `Ready`
  handshake, `exec`, or resync. We considered reinterpreting "custom init" as an agent-supervised
  entrypoint (`vmcell_init=`, agent stays PID 1, forks the program), which preserves the control plane.
  *Reason we did NOT:* that is a different capability (and `exec` already forks a program under the live
  agent), and the design says `init=` **override**. So we ship the genuine override and honor its
  consequence **fail-loud**, not silently: `MicroVm::agent()` returns a typed `Error::Agent` immediately
  (§12.2) instead of hanging; `MicroVm::start()` skips the QEMU control-plane health probe when there is
  no agent to probe; and `build()` **rejects `snapshotting` + a custom init** (the mandatory
  post-restore resync runs through the agent, §12.4). A custom-init VM is observed out-of-band (serial
  log / writable share or extra disk / net). See design §E2.2.

- **(b) CH disks are declared `image_type=Raw` explicitly (surfaced by the writable-extra-disk test).**
  CH v52 **auto-detects** an unspecified disk image as raw and then **disables sector-0 writes** as a
  qcow2-misdetection safeguard — silently rejecting a guest write to sector 0 of a *writable* raw disk
  (`ReadOnly`). The extra-rw-disk KVM test caught this (the `/dev/vdc` round-trip failed on CH while FC
  and QEMU passed). *Fix:* `build_ch_disks` sets `image_type: "Raw"` on every disk (all vmcell images —
  erofs root, ext4 `Block` root, extra raw disks — are raw). This also removes CH's deprecation warnings
  and pre-empts the **same latent bug on the writable `Block` rootfs path** (a sector-0 superblock write
  would have been silently dropped). One-law: `CH_RAW_IMAGE_TYPE` const, pinned by a serialization
  assertion. See design §E1.2.

- **Validated on the KVM host (2026-07-05, this env).** `tests/extra_block.rs` (`vmm_matrix_test!`) —
  **CH + Firecracker + QEMU all green**: two extra disks attach after the root (`/dev/vdb` read-only
  seeded marker read back in-guest; `/dev/vdc` read-write marker round-tripped), proving attach,
  `vda`-first ordering, the readonly flag, and raw exposure on the **data plane**.
  `extra_block_survives_snapshot` (CH + FC; QEMU skips — no snapshot) — green: a marker written to a
  writable extra disk survives a real snapshot→restore into a fresh vmid and reads back off `/dev/vdb`,
  the data-plane proof of "plain virtio-blk composes with snapshot" (V:high headline). `tests/custom_init.rs`
  (CH) — green: `init=/bin/sh` at Verbose verbosity, the kernel serial log shows `Run /bin/sh as init
  process`, and `agent()` fails loud with the custom-init error. Run via
  `systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh … just test-privileged`
  filtered to these tests.

### v22 pass 2 — daemon exposure + disk-I/O fault injection (2026-07-05)

- **(c) Disk-I/O fault injection is I/O throttling (bandwidth + IOPS), not error injection.** `BlockDevice`
  gained `io_limit: Option<DiskIoLimit>`, wired to each backend's native rate limiter (CH
  `rate_limiter_config`, FC `rate_limiter`, QEMU `throttling.*`). *Reason error injection (EIO) was NOT
  chosen for v1:* it is QEMU-`blkdebug`-only, so it would be a capability the **primary** backend (CH)
  cannot honor — a second-class feature. Throttling works on all three backends including CH, and is the
  portable "slow/pressured disk" fault. CH+FC share one `size=rate`/`refill_time=IO_LIMIT_REFILL_TIME_MS`
  token-bucket conversion (one law). Validated on KVM (`extra_block_io_throttle`, CH+FC+QEMU: a 1 MiB/s cap
  floors a 4 MiB read at ~3 s). Error/latency injection stays forward work. See design §E5.

- **(d) The daemon exposes `extra_disks` (read-only) + `extra_kernel_args`, but NOT `init`, and extra disks
  are read-only.** *Reasons, both forced by the daemon's model:* (i) the daemon owns the VM through the
  vsock control plane (brings the agent up to mark `Ready`, serves `exec`/`stats`), which a custom `init=`
  drops — so exposing it would create un-`exec`-able VMs; it stays library-only. (ii) The artifact store is
  create-only/immutable (§D3.2), so a *writable* extra disk over a shared store artifact would let one VM
  mutate an artifact another reads — extra disks are attached read-only (a copy-on-attach writable scratch
  is a follow-up). A live VM pins its extra-disk artifacts (delete-in-use guard extended). See design §E4.

- **(e) `vmcell::Error::Config` now maps to daemon `BadRequest` (400), not `Internal` (500).** Threading
  `extra_kernel_args`/`io_limit` into the launcher's `VmConfig::build()` meant a client-supplied bad knob
  (a reserved kernel arg, a `0` io_limit) surfaced as `Error::Config` → previously the catch-all
  `Internal` 500. A config-validation failure IS a client error, so it now maps to 400 — also fixing the
  pre-existing case of `vcpus == 0`/`mem_mib` under floor over the API. Pinned by
  `wrapped_config_error_maps_to_bad_request`.

- **Validated on KVM (2026-07-05):** the daemon `extra_disk_over_api_data_plane_and_delete_in_use`
  integration test (`just test-daemon`) drove the full HTTP path — upload a marked image, `POST /v1/vms`
  with `extra_disks`, read the marker off `/dev/vdb` in-guest, and confirm delete-in-use → 409 until the VM
  is destroyed. **Still forward work:** writable-scratch-from-artifact over the daemon (copy-on-attach), and
  disk error/latency injection (QEMU-`blkdebug`).

## Automated quality gates (docs/56) — wire-crate cast lints are `not(test)`-scoped

- **The B10 wire-crate cast lints (`clippy::cast_possible_truncation` / `cast_sign_loss` /
  `cast_possible_wrap`) live in the `#![cfg_attr(not(test), deny(...))]` block, not the unconditional
  `#![deny(...)]` block the `docs/56` preamble template shows.** *Reason:* B10 ("integer narrowing
  **from the wire** is `try_from`, never `as`") is a production decode-surface rule, and the repo
  already relaxes production-strictness lints in tests — `clippy.toml` carries
  `allow-{unwrap,expect,print,dbg}-in-tests` and AGENTS.md states "Tests may unwrap/expect/print/dbg;
  production code may not." Denying casts crate-wide (incl. tests) forced `try_from`/`.cast_signed()`
  churn on test byte-vector construction (e.g. `b'e' as c_char`, `AF_INET as u16` in layout asserts)
  that carries no wire-decode risk. Scoping to `not(test)` keeps the full B10 rigor on the production
  path (the real fix landed at `vmcell-guest-agent`'s framing length-prefix and the `netif` FFI
  narrowings, the latter centralized behind one reasoned `AF_INET_FAMILY` const) while matching the
  established lenient-in-tests idiom. `clippy::multiple_unsafe_ops_per_block` stays **unconditional** —
  it is a safety-discipline lint, not a production-strictness one. Retire this entry if the template
  is updated to say `not(test)`.

**When you make a new deviation,** add a short entry here — *what* you diverged from and *why* — and,
once it stabilizes, fold it into the design document and delete it from this log. Keep this file
small: a growing log means the design doc has drifted from the code.
