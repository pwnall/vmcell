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
- the `docs/46` recorded gaps now documented in the body/§17 (Open gaps and future capabilities): `Egress::Open` has no arbitrary egress, the
  privileged `host_services_port` is rejected fail-loud, the `mkfs.erofs` fallback is unwired, the proxy CA
  is per-artifacts-dir, the mmdebstrap keyring is the base-image's, `limits_enforced` means "memory
  controller delegated", the snapshot cache key folds the pinned CH identity, and the carried `vhost`
  patch is vendored in-tree.

See design §13 (Cross-cutting invariants) ("Cross-cutting invariants") for the rules and §17 (Open gaps and future capabilities) ("Open decisions and known gaps") for
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
  `KernelStage` is the guaranteed fallback seed. See design §5.2 (The config fragment), §5.4 (The guest-kernel contract and the bootstrap seed), §17 (Open gaps and future capabilities).

- **(b) In-VM `mmdebstrap` rootfs source un-deferred, moved to `vmcell-rootfs-builder`, on the privileged
  network path.** v19 recorded this source as "library-present but deferred". It is now wired and lives in a
  **new crate**. *Reason:* `mmdebstrap` + apt need **real outbound egress**, which only the privileged/tap
  path with `Egress::Open` provides. Extraction keeps the heavy in-VM machinery out of the library while
  reusing `vmcell`'s `resolve_builder_base` and the shared `pack_erofs_with_injection` tail (every rootfs
  source is identically injected, §4.3 — The rootfs-construction contract). Selected via `vmcell-cli --rootfs-source mmdebstrap`. §4.2 (Rootfs sources and the one packer), §9.1 (Workspace layout), §17 (Open gaps and future capabilities).

- **(c) CLI moved out of the `vmcell` package into a new `vmcell-cli` composition-root crate.** *Reason:* the
  builder crates depend on `vmcell`; a CLI *inside* `vmcell` referencing them would form a
  `vmcell → builder → vmcell` **cycle**. `vmcell-cli` depends on `vmcell` + both builders and is the only
  crate that names a builder, keeping the graph a directed acyclic star. Drove the `vmcell` **0.4.0 → 0.5.0**
  bump. See §9.1 (Workspace layout), §10 (The artifact build pipeline), §17 (Open gaps and future capabilities).

- **(d) `hash_*` / `ch_binary_path` / `resolve_builder_base` / `pack_erofs_with_injection` /
  `fold_rootfs_injection_identity` promoted to `pub` so the builder crates reuse one implementation.** The
  extracted builders must reuse the **exact** erofs inject+pack tail, injected-content identity fold,
  builder-base resolution, CH binary discovery, HTTP client, and content-hash functions — duplicating any is
  where per-builder divergence bugs hide. Exposing one implementation via `pub` makes the reuse structural.
  Other half of the 0.5.0 bump. See §4.3 (The rootfs-construction contract), §9.1 (Workspace layout).

## v21 — control-plane daemon (`vmcelld`) + client

Design: `docs/59-claude-design-v23.md` §11 (The control-plane daemon — vmcelld) (unified; was `docs/historical/53-claude-design-v21.md`). New
crates: `vmcell-privilege`, `vmcell-daemon`, `vmcelld`, `vmcell-daemon-client`, `vmcelld-ctl`. Fold the
settled entries into the design body and delete them here as they stabilize.

- **(a) The daemon OWNS its VMs (holds the `MicroVm` handles); it is not stateless.** An earlier draft
  explored a stateless daemon (detached VMs + on-disk descriptors + reattach). *Reason it was dropped:* it
  needed a new vmcell detach/reattach primitive AND abandoned the "`Drop` releases resources" invariant.
  The owning model reuses the single-process `MicroVm` ownership in-process, needs **no** vmcell change,
  and keeps teardown-is-ownership intact; crash recovery is the **start-up `sweep_orphans`** (empty live
  set) instead of reattach. See §11.4 (The VM registry and the start-up sweep).

- **(b) `vmcelld` is NOT blessed on the dev hot path — it is launched through the blessed
  `vmcell-test-runner`, which confers the caps via the ambient set.** `just bless` blesses only the runner
  (which rarely changes); `vmcell-daemon`/`vmcelld` rebuild with no `setcap` churn. *Reason:* the same
  file-cap-churn problem the runner already solved for the ever-changing test binaries. Standalone/prod
  `vmcelld` uses systemd `AmbientCapabilities=` or a one-off `setcap`. See §11.2 (Privilege and blessing).

- **(c) INVERTED launch for integration vs. manual.** Integration tests wrap the **test binary** with the
  runner (nextest target-runner) so the test itself holds the caps, and spawn `vmcelld` **directly** (it
  inherits the ambient caps). *Reason:* a privileged test can plant privileged pre-existing state (an
  orphan netns for the start-up-sweep test) and inspect per-VM teardown residue — things a
  `vmcelld`-via-runner spawn from an unprivileged test cannot. Manual poking (`just daemon`) still launches
  `vmcelld` *through* the runner (no privileged test process to inherit from). See §15 (Testing strategy), `just test-daemon`.

- **(d) `mem_read_ok`/`limits_enforced` both mean "the memory controller is delegated into the per-VM
  slice" — memory metrics are UNREADABLE (not just unenforced) without a delegated cgroup scope.** An
  integration test initially asserted `mem_read_ok` unconditionally and reddened without delegation
  (`memory.current` doesn't exist in a non-delegated slice). The test now asserts both flags **track**
  delegation (`stats_limits_enforced_matches_delegation`). Honest §7.2 (The fail-loud capability contract and HostCapabilities) behavior, not a bug.

- **(e) Snapshot/restore/net knobs on the daemon API.** `CreateVmRequest` gained `net`
  (`none`/`privileged`/`unprivileged`), `snapshotting`, and `restore_from` (a store prefix). The launcher
  maps `NetMode`→`NetConfig`, sets `.snapshotting()`, and dispatches cold-boot vs. **`restore_cow`** (so
  the named snapshot is preserved and re-restorable, design §8.4 — The zygote fan-out and the OverlayStore seam). *Reason:* the daemon defaulted to
  `NetConfig::None` + no snapshotting, so snapshot/restore and real guest networking were unreachable
  through the API. See §11.5 (The HTTP REST API and its OpenAPI document).

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
  §11.4 (The VM registry and the start-up sweep).

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
  **Still unrun:** the QEMU/Firecracker snapshot tiers (§17 — Open gaps and future capabilities: unwired), filtered-egress, concurrent-load.

## v22 — extra virtio-blk devices + custom init / append-only boot-args

Design: `docs/59-claude-design-v23.md` §4.6 (Extra virtio-blk devices and disk-I/O throttling) (unified; was `docs/historical/58-claude-design-v22.md`).
Graduates the two §17 (Open gaps and future capabilities) forward-work items. Fold into the design body and delete here as they stabilize.

- **(a) `init=` override is a GENUINE PID-1 replacement, not an agent-supervised entrypoint.** §17 (Open gaps and future capabilities)
  names the item "optional `init=` override". Taken literally, overriding `init=` replaces the vmcell
  guest agent (PID 1), which *is* the vsock control plane — so a custom-init VM has **no** `Ready`
  handshake, `exec`, or resync. We considered reinterpreting "custom init" as an agent-supervised
  entrypoint (`vmcell_init=`, agent stays PID 1, forks the program), which preserves the control plane.
  *Reason we did NOT:* that is a different capability (and `exec` already forks a program under the live
  agent), and the design says `init=` **override**. So we ship the genuine override and honor its
  consequence **fail-loud**, not silently: `MicroVm::agent()` returns a typed `Error::Agent` immediately
  (§13 — Cross-cutting invariants) instead of hanging; `MicroVm::start()` skips the QEMU control-plane health probe when there is
  no agent to probe; and `build()` **rejects `snapshotting` + a custom init** (the mandatory
  post-restore resync runs through the agent, §13 — Cross-cutting invariants). A custom-init VM is observed out-of-band (serial
  log / writable share or extra disk / net). See design §5.3 (The kernel command line).

- **(b) CH disks are declared `image_type=Raw` explicitly (surfaced by the writable-extra-disk test).**
  CH v52 **auto-detects** an unspecified disk image as raw and then **disables sector-0 writes** as a
  qcow2-misdetection safeguard — silently rejecting a guest write to sector 0 of a *writable* raw disk
  (`ReadOnly`). The extra-rw-disk KVM test caught this (the `/dev/vdc` round-trip failed on CH while FC
  and QEMU passed). *Fix:* `build_ch_disks` sets `image_type: "Raw"` on every disk (all vmcell images —
  erofs root, ext4 `Block` root, extra raw disks — are raw). This also removes CH's deprecation warnings
  and pre-empts the **same latent bug on the writable `Block` rootfs path** (a sector-0 superblock write
  would have been silently dropped). One-law: `CH_RAW_IMAGE_TYPE` const, pinned by a serialization
  assertion. See design §4.6 (Extra virtio-blk devices and disk-I/O throttling).

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
  floors a 4 MiB read at ~3 s). Error/latency injection stays forward work. See design §4.6 (Extra virtio-blk devices and disk-I/O throttling).

- **(d) The daemon exposes `extra_disks` (read-only) + `extra_kernel_args`, but NOT `init`, and extra disks
  are read-only.** *Reasons, both forced by the daemon's model:* (i) the daemon owns the VM through the
  vsock control plane (brings the agent up to mark `Ready`, serves `exec`/`stats`), which a custom `init=`
  drops — so exposing it would create un-`exec`-able VMs; it stays library-only. (ii) The artifact store is
  create-only/immutable (§11.3 — The artifact store), so a *writable* extra disk over a shared store artifact would let one VM
  mutate an artifact another reads — extra disks are attached read-only (a copy-on-attach writable scratch
  is a follow-up). A live VM pins its extra-disk artifacts (delete-in-use guard extended). See design §11 (The control-plane daemon — vmcelld).

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

## v24 — privileged-window hardening (VMM seccomp + jailer-equivalent + setup broker)

Design: `docs/60-claude-design-v24.md` §12 (Privilege hardening: confining the VMM) (an amendment on v23, in the v21/v22 shape). New crate:
`vmcell-broker`. Fold settled entries into the design body and delete here as they stabilize.

- **(a) The jailer-equivalent lives in `vmcell::vmm::jail`, NOT `vmcell-privilege`; `vmcell` does not
  gain a `vmcell-privilege` edge.** An earlier design draft placed `JailSpec` in `vmcell-privilege`.
  *Reason it moved:* the jail is only ever applied where a VMM is spawned (`build_vmm_cmd` + the
  broker's `SpawnVmm`), both of which already link `vmcell`'s host stack; putting it in
  `vmcell-privilege` would have forced the seccomp/host-side machinery onto the **lean**
  `vmcell-test-runner` (which links `vmcell-privilege` but never spawns a VMM), breaking its lean-tree
  assertion. `vmcell-privilege` gains only the pure `plan_broker_parent_drop`/`apply_broker_parent_drop`
  (capctl-only, no new dep). `vmcell::vmm::jail` owns `seccompiler`. Design already reconciled.

- **(b) `seccompiler` (Apache-2.0 OR BSD-3-Clause) is a NEW dep on `vmcell` (behind `host-common`), and
  the LGPL `libseccomp` family is banned by NAME in `deny.toml`.** The B9 "privileged window is
  dependency-thin (rustix+capctl+libc)" rule governs `vmcell-privilege`/`vmcell-test-runner`, which stay
  unchanged (lean-tree assertion confirms `seccompiler` is absent from the runner). `seccompiler` is the
  pure-Rust rust-vmm seccomp compiler CH and FC use internally, so it is the sanctioned choice; the
  alternatives (`libseccomp`/`syscallz`) have permissive Rust metadata but LINK the LGPL-2.1 libseccomp
  C library — invisible to `cargo deny`'s license gate, so the ban catches it by name (§12.5 — The licensing constraint on seccomp crates). A defect
  class (a licensing hole tooling reports green on) turned into a gate that can go red.

- **(c) The seccompiler VMM-child deny-list ships OPT-IN, default OFF (`JailConfig::seccomp_deny_list`
  = false).** *Reason:* a host-applied filter on a live VMM cannot be validated on a KVM host in this
  environment, and shipping it enabled-by-default unvalidated would violate "host-facing claims are
  validated by executing on a KVM host". The default confinement is the backend's own native filter
  (Layer 1). The filter-application *mechanism* is fully gated KVM-free: `tests/jail_hardening.rs` forks
  a stand-in, applies the deny-list, and asserts `unshare(0)→EPERM` while `getpid` still works (red on
  an empty filter). Design §12.3 Layer 2 — the jailer-equivalent (JailSpec + apply_jail) / §17 (Open gaps and future capabilities).

- **(d) The broker's `SpawnVmm` (the jailed fork→setns→jail→execve→pidfd path) refuses fail-loud as
  forward work; `vmcelld` is NOT cut over to fork-broker-then-drop this pass.** *Reason:* the setns
  constraint (an unprivileged parent can never join a broker-created netns) makes a half-wired broker
  broken — the cutover is all-or-nothing deep surgery (invert the daemon's launcher through `BrokerClient`)
  best landed as its own change with its own live validation, not bundled here. What ships is the
  complete, fake-tested component: protocol + framed codec (round-trip + over-cap reject), the
  setup/cgroup/teardown/sweep dispatch against the injected `Netlink`/`NftApplier`/`CgroupFs`/
  `OrphanScanner` seams (call-order / residue-gone / sweep-only-dead), the parent cap-drop plan, and the
  socketpair+fork+pdeathsig transport (Health round-trip). The retain-caps single-process daemon (§13 — Cross-cutting invariants)
  stays the default. Design §12.4 Layer 3 — the setup broker (network surface never holds caps) / §17 (Open gaps and future capabilities).

- **(e) QEMU gains `-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny`
  (Enforcing) — it previously ran with NO `-sandbox`, unconfined.** A QEMU built without libseccomp errors
  fail-loud on `-sandbox on`, which is the *desired* behavior (refuse rather than run unconfined). The one
  legitimate opt-out is a QEMU workload whose feature needs `spawn` — `VmmSeccomp::Disabled`, logged.
  `VmmSeccomp::Log` is CH-only; on FC/QEMU it is a typed `Error::Unsupported`, never a silent downgrade.

- **(f) Module-doc (`//!`) intra-doc links to a module's own items need FULL crate paths.** rustdoc under
  `RUSTDOCFLAGS=-D warnings` reports `[\`JailSpec\`]` in `vmm/jail.rs`'s `//!` doc as "no item in scope";
  `[\`JailSpec\`](crate::vmm::jail::JailSpec)` resolves. A rustdoc quirk for inner module docs, not a code
  issue — noted so the next author does not re-hit it.

- **(g) `JailConfig::hardened()` defaults `clear_ambient_caps` to FALSE — a KVM-host finding.** The first
  draft cleared the VMM child's ambient set on the (wrong) theory that the VMM "already runs with no
  caps." On the `vmcell-test-runner` path the three caps live in the **ambient** set, so the exec'd VMM
  **inherits** them and **needs** `CAP_NET_ADMIN`: the privileged suite reddened all six restore-with-tap
  tests (`snapshot_restore`/`extra_block_survives_snapshot`/`zygote_fan_out` × CH+FC) with
  `TapSetMac`(CH)/tap-open(FC) `EPERM`. Cold boot survived (it doesn't re-set the tap MAC that way);
  restore did not. Fix: default `clear_ambient_caps` off (the field stays an opt-in for the future
  fd-passing/uid-drop path where the VMM needs no caps). `no_new_privs`/`RLIMIT_CORE=0`/`non_dumpable`
  stay on — validated non-breaking. This is the "defaults get the strictest scrutiny" + "validate on a
  KVM host" discipline catching a real regression static review would have missed. Design §12.3 Layer 2 — the jailer-equivalent (JailSpec + apply_jail) / §17 (Open gaps and future capabilities).

- **Validated on THIS KVM host (`just test-privileged`, delegated scope; runner blessed, CH at
  `~/.cargo/bin`, artifacts built).** The privileged suite runs every VM through the hardened path
  (`JailConfig::hardened()` + `VmmSeccomp::Enforcing`). First run surfaced deviation (g): **78 passed / 6
  failed** — the 6 the `clear_ambient` bug broke. After the fix, re-run **84/84 green** (CH + FC + QEMU
  cold boot, `exec`, privileged tap + nft TPROXY egress, host-endpoint, metrics/limits, nested virt,
  extra disks/throttle, shares, snapshot→restore, zygote fan-out) — so CH `--seccomp true`, FC's built-in
  filter, QEMU `-sandbox on,…`, and the jailer-equivalent hardening are all confirmed non-breaking on a
  live VMM across all three backends. **`just ci`-equivalent gates also green (no KVM needed):** fmt;
  `clippy --workspace --all-targets --all-features -D warnings`; reduced-host per-backend clippy; `cargo
  deny` (seccompiler allow-listed, LGPL bans clean); rustdoc; lean-tree assertions (agent/runner lean,
  `seccompiler` absent from the runner, broker excludes `vmcell-daemon`/axum); `cargo semver-checks`;
  feature-powerset (204/204); `cargo nextest run --all-features` (482 passed). **Still forward work
  (§17 — Open gaps and future capabilities):** the `vmcelld` broker cutover, the seccompiler deny-list + `clear_ambient` defaults (blocked
  on the fd-passing/uid-drop increment), and the QEMU/FC snapshot tiers already unwired pre-v24.

### v24 pass 2 — the `vmcelld` broker cutover (the §17 — Open gaps and future capabilities headline step)

Design: `docs/60-claude-design-v24.md` §12.4 Layer 3 — the setup broker (network surface never holds caps) (updated). `vmcelld` now forks by default: the broker child
keeps the caps + owns the `Registry`; the cap-dropped parent serves HTTP and forwards VM ops.

- **(h) Shipped the "engine-owning" (fat) broker, NOT the thin `SpawnVmm`+pidfd model §12.4 (Layer 3 — the setup broker — network surface never holds caps) first
  described.** *Reason:* the thin model (broker does only netns/spawn, parent drives the VMM's api
  socket + a passed pidfd) requires splitting `MicroVm` across the process boundary — its `V::Instance`
  owns the VMM `Child`, so "parent drives the VMM" is a deep `MicroVm`/`Vmm` refactor. The fat cutover
  realizes the **same §13 (Cross-cutting invariants) invariant** (caps off the network surface) with **no `vmcell` surgery**: the
  broker child owns the whole `Registry`; the parent forwards `create`/`exec`/`stats`/`snapshot`/`destroy`
  over the new `VmEngine` RPC (`vmcell-daemon::bridge`). The thin broker (shrink the *privileged code*
  surface) is recorded as the remaining refinement (§17 — Open gaps and future capabilities). Both satisfy §13 (Cross-cutting invariants); the fat one is far lower
  risk and validatable now. The `vmcell-broker` thin primitives (SetupNetwork/SpawnVmm/…) stay as that
  refinement's foundation + the reusable `fork_privileged_child` transport the fat cutover uses.

- **(i) The bridge RPC is JSON (`serde_json`), NOT postcard.** First cut used postcard; `create` hung
  while `get`/`list` passed. *Root cause:* the reused daemon DTOs carry `#[serde(skip_serializing_if)]` /
  `default` fields — fine for self-describing JSON but **byte-misaligning** in postcard (non-self-
  describing), so the reply frame was unparseable and the request never resolved. JSON is self-describing,
  handles the attributes, and is the format the HTTP API already speaks. A KVM-free unit test
  (`bridge::tests`) now round-trips every op incl. `create`, so a format regression reddens.

- **(j) The parent drops effective/permitted/inheritable/ambient caps + `no_new_privs`; the bounding-set
  shrink is a warned no-op without `CAP_SETPCAP`.** The runner raises only NET_ADMIN/SYS_ADMIN/DAC_OVERRIDE
  (not SETPCAP), so `apply_broker_parent_drop`'s bounding drop warns — the **same** file-cap-path
  limitation the runner has (B9). Dropping your *own* effective/permitted needs no SETPCAP, so the parent
  still ends with **no usable capabilities** (empty effective set + `no_new_privs`), which is the §13 (Cross-cutting invariants)
  win; the wide bounding set is inert under `no_new_privs`.

- **(k) `destroy_removes_per_vm_scratch_dir` now matches the scratch dir by vmid, not by `d.pid()`.** The
  per-VM scratch dir is `<temp>/vmcell-vm-<pid>-<vmid>`; the fork means the **broker child** (not the
  vmcelld process the test spawned) creates it, so its pid is not `d.pid()`. The test globs
  `vmcell-vm-*-<vmid>` (the `-` delimiter avoids `-45` matching `-145`); the daemon's start-up sweep clears
  any prior same-vmid dir, so exactly this VM's matches. The residue rule (exists-before, gone-after) is
  unchanged — only the discovery.

- **Validated on THIS KVM host (`just test-daemon`, 12/12).** Every VM lifecycle op now runs through the
  cap-dropped HTTP parent → the forked broker: bearer auth (401/403/200), boot + `exec` data plane, full
  create/exec/stats/destroy, snapshot → restore-by-name, privileged tap net + guest default route, extra
  disks + delete-in-use (409), start-up orphan-netns sweep, `--resource-prefix` isolation, per-VM
  scratch-dir residue, and `vmcelld-ctl` — all green with the parent holding no usable caps. KVM-free
  gates green too: `bridge::tests` (RPC round-trip, error-status round-trip, multiplex-not-serialized,
  over-cap reject), `vmcell-broker` fork/transport tests, clippy `-D warnings`.

## v25 — the OverlayStore seam + fork/branch lineage (design §8 — Snapshot, restore, and cloning)

- **(a) The "single-snapshot copy-on-write clone" was already built; v25 adds only the seam + lineage.**
  The roadmap item bundled three things; the reflink CoW clone + zygote fan-out (`Zygote`,
  `MicroVm::restore_cow`, `reflink.rs`, §8.4 — The zygote fan-out and the OverlayStore seam / §13 — Cross-cutting invariants) already shipped. v25 does **not** re-implement it — it
  lifts the CoW copy behind the injectable `overlay::OverlayStore` seam and adds the `lineage::Lineage`
  fork/branch handle on top of `Zygote`. Scoping recorded so a reader does not expect new clone mechanics.

- **(b) The seam method is `clone_tree`, not the design's tentative `clone_into`.** `clone_into` collides
  with the blanket `ToOwned::clone_into(&self, &mut Self::Owned)` on any `Arc<dyn OverlayStore>` call site
  (method resolution picks `ToOwned`'s, a confusing `E0061`). Renamed to `clone_tree` (also clearer — it
  mirrors the internal `clone_tree_cow`). The design doc uses `clone_tree` to match.

- **(c) `restore_inner` folds `overlay_store` + a `cow: bool` into one `Option<Arc<dyn OverlayStore>>`.**
  Adding both as separate params made it an 8-arg fn, tripping `clippy::too_many_arguments` (threshold 7,
  no override, and the codebase carries **zero** `too_many_arguments` suppressions — the convention is to
  not exceed it, never to `#[allow]` it). `Some(store)` = CoW-copy through it, `None` = single-use in
  place; the presence of a store *is* the CoW flag, which is also cleaner than a parallel bool. The public
  `restore_cow` keeps its explicit `Arc<dyn OverlayStore>` param (7 args, at the limit).

- **(d) `Lineage` is the lineage handle; no field was added to `MicroVm`.** A forked VM does not carry a
  back-pointer to its lineage — the `Lineage` value does. `Lineage::branch(child, dir)` takes the running
  descendant explicitly (the git-branch model: the caller says where the branch diverges). This keeps the
  300-line `MicroVm` struct and its nine construction sites untouched, and all CoW/fan-out mechanics
  delegate to `Zygote` (one law).

- **(e) `Lineage::fork_from_vm` / `branch` create the target snapshot dir — a real bug the LIVE test
  caught.** The first draft mirrored `Zygote::suspend`'s "caller creates the dir" contract, so a `branch`
  into a not-yet-created dir fails-loud in the backend: CH `"Destination is not a directory"`, FC
  `"Cannot perform open on the snapshot backing file: No such file or directory"`. Both `fork_from_vm` and
  `branch` are "suspend into a location" verbs, so they now `create_dir_all` the destination first. This
  was **not** caught by the unit tests (the `FakeVmm` snapshot is a no-op that never opens the dir) — only
  by running the real VM suite, which is exactly why the host-run is non-optional (AGENTS.md "Green static
  review proves little"). A KVM-free `branch_creates_a_missing_target_dir` unit gate now guards it (red on
  dropping the `create_dir_all`).

- **KVM validation — DONE on this host (2026-07-06).** Both operating-mode suites green under the delegated
  scope through the blessed runner: **`just test-privileged` 87 passed / 5 skipped** (CH+FC+QEMU; incl. the
  new `fork_branch_lineage` live test on CH+FC, plus `zygote_fan_out`, `snapshot_restore`, and
  `extra_block_survives_snapshot` which exercise `restore_cow` through the new `OverlayStore` seam on real
  micro-VMs) and **`just test-unprivileged` 4 passed**. The new `tests/lineage.rs` boots a VM, roots a
  lineage, forks a live clone (exec on the data plane; guest MAC == `mac_math(vmid)`), writes a marker to
  diverge it, `branch`es it, and proves a fork from the branch **sees** the marker while a fork from the
  root does **not** (a data-plane positive/negative control, not a proxy signal). KVM-free gates also green:
  `overlay`/`lineage` unit tests (each **red-on-inverse verified**: drop generation-increment → chain
  reddens; bypass the store → seam test reddens; drop the allocator guard → cross-family ancestry reddens),
  `clippy -D warnings` (incl. reduced single-backend features), `missing_docs` rustdoc, `cargo
  semver-checks` (0.7.0 → 0.8.0, clean), full `vmcell` lib nextest.

- **(PROCESS NOTE — a recurring mistake to stop making.** I repeatedly framed the privileged suite as
  hard-to-run / "forward work" and deferred it, when in fact **the capability test runner is built and
  blessed, this host is fully KVM-capable, and the environment is entirely set up to run it** —
  `scripts/review-preflight-priv.sh` prints `READY` and
  `systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh just test-privileged`
  just works (no sudo). My own `imp-testing-validation-runbook` memory even says verbatim *"Do NOT assume
  'can't run KVM here' — check first."* I assumed anyway. The diagnosis: the "Done means" phrase
  "validated by executing the suites **on a KVM host**" read as "some other special host" rather than "this
  one," and the design-doc culture of listing "KVM-host validation … forward work" as an honest-hedge
  template trained the reflex to hedge instead of run — something the current framing made feel out of
  reach when it is one command away. **Fix applied (2026-07-06):** hardened `AGENTS.md` rule 5 and the
  "Done means" host-facing bullet — the dev host **is** the KVM host; `scripts/review-preflight-priv.sh`
  `READY` means run the suites now. (Update, v5 bless-only sentinel: the verdict is now three-way —
  `READY`/exit 0 → run; `BLOCKED-ON-BLESS`/exit 2 → ask the maintainer for one `just bless` then run,
  **never** a static-only downgrade; `NOT READY`/exit 1 → a genuinely absent facility, the *only* case
  where "forward work / not validated" is legitimate, naming the failed check.) **This note is kept
  deliberately** (not folded away yet) so future development can show whether the wording change actually
  breaks the reflex.)**

## v26 — persistent interactive sessions (design §3 — The control plane: vsock, the host clients, and the guest agent)

- **(a) The one-shot exec path is byte-for-byte unchanged; sessions are a separate channelized layer.**
  Rather than retrofit a `SessionId` onto `Message::{Exec,Stdout,Stderr,Exit}` (a wire break plus a rewrite
  of the heavily-tested one-shot handler + `AgentClient::exec`), v26 **appends** eight new variants
  (`OpenSession`…`SessionExit`, indices 8–15) and adds a parallel host `agent::session` multiplexer on its
  **own** connection. The one-shot `Exec` stays id-less and synchronous. *Reason:* the one-shot path carries
  the most gates in the repo (desync discipline, reaper epochs, framing interop); a session layer beside it
  keeps all of them intact and makes the wire change purely additive (`#[non_exhaustive]` enum → 0.x minor,
  semver-checks-clean). A discriminant-stability unit test pins the append-only order KVM-free.

- **(b) `ExecRequest.timeout` keeps ONE meaning across both paths ("a deadline, or none").** The one-shot
  *host* still fills `None → DEFAULT_EXEC_TIMEOUT` before sending (a runaway one-shot child cannot outlive
  the abandoned host wait); the session path leaves `None` as `None` — an interactive session is persistent,
  bounded by `CloseSession` / child exit / connection teardown, not a default timeout. This is a policy the
  host applies before the byte leaves, not a second interpretation in the guest, so no field is read two
  ways (§3.3 — Interactive-session wire semantics).

- **(c) One per-connection writer, via `VsockStream::try_clone()` behind a mutex (§13 — Cross-cutting invariants).** The guest
  connection handler was request/response (`handle_connection` drove one exec to completion before the next
  read). It is now a non-blocking dispatch loop owning the read half, with a `try_clone`d write half behind
  `Arc<Mutex<VsockStream>>` that every frame — one-shot output, put-file/resync acks, and all session pump
  output — routes through (`send_msg`). *Reason:* multiplexed session frames from concurrent pump threads
  must not interleave-corrupt on the wire, and one writer is the simplest guarantee. `handle_exec`/
  `handle_put_file`/`handle_resync` keep their exact behavior; they just write through the shared writer.

- **(d) PTY sessions run `setsid`+`TIOCSCTTY`+`dup2` in `pre_exec`; the master is `CLOEXEC`, the slave is
  opened `CLOEXEC` and closed in the parent after spawn.** The child adopts the pty slave as its controlling
  terminal via the canonical `login_tty` sequence (async-signal-safe rustix syscalls only, one SAFETY-doc'd
  `BorrowedFd::borrow_raw`). The parent drops its slave so the master EOFs (`EIO`) when the child exits,
  ending the pump. A pipe session keeps `process_group(0)` + three pipes as before. *Reason:* this is the
  standard, minimal way to give an in-guest program a real terminal (`isatty` true, resizable) without a
  helper binary or netlink.

- **(e) `devpts` is mounted best-effort at `/dev/pts`, NOT in the fatal core-mount set.** PTY allocation
  needs it, but one-shot exec, pipe sessions, and the vsock control plane do not — so a failed mount logs
  and continues (only PTY sessions then fail loud with `SessionExit(127)`), exactly like the sysfs/share/
  loopback mounts. Returning `Err` from PID 1 would kernel-panic the guest.

- **(f) `child_path`/`build_command` extracted as the ONE command-construction law for both paths.** The
  `/vmcell-tools`-augmented PATH and argv/env/cwd assembly are shared by `handle_exec` and `run_session`
  (AGENTS.md "one law"); a `child_path_prepends_vmcell_tools` unit test reddens if a session drops the shim
  dir. `kill_group` is the shared `kill(-pgid)` law (one-shot timeout, session `CloseSession`/timeout,
  connection teardown §13 — Cross-cutting invariants).

- **KVM validation — DONE on this host (2026-07-06).** The new `tests/session.rs` (4 data-plane tests ×
  CH+FC+QEMU = 12, + 2 host demux unit tests) is **14/14 green** through the blessed runner under the
  delegated scope: PTY `isatty`+initial-window+mid-session-resize with a pipe-session negative control
  (§13 — Cross-cutting invariants); streaming stdin round-trip through `cat`+EOF (§3.3 — Interactive-session wire semantics); two ~27 KiB self-identifying streams
  multiplexed over one connection with zero cross-attribution (§13 — Cross-cutting invariants); a persistent `sleep` session's pid
  gone after the mux drops (§13 — Cross-cutting invariants, existed-before/gone-after via `/proc/<pid>/cmdline`). Sessions need only
  the vsock agent (no snapshot), so **no `require_cap!` skips** — every case runs on all three backends.
  `just test-unprivileged` is **4/4 green**. KVM-free gates green: protocol round-trip +
  discriminant-stability + proptest over all 8 new variants; guest `winsize_from`/`child_path`/
  session-frame-codec-interop unit tests; host demux interleave-and-drop-post-exit test; `clippy -D warnings`
  (workspace + each reduced backend + guest-agent lean-tree unchanged), rustdoc, `cargo deny`/`machete`,
  `semver-checks` (vmcell 0.8.0→0.9.0, vmcell-protocol 0.3.0→0.4.0, both clean). Three key gates were
  **red-on-inverse verified** (swap two appended enum variants → discriminant test reddens; id-ignoring demux
  → multiplex test reddens; rows↔cols swap → `winsize_from` test reddens).

- **(g) A pre-existing host-environmental failure cluster, control-proven NOT this change.** The full
  privileged suite showed 6 reds — `nested_virt`/`nested_virt_disabled` (CH+QEMU: `kvm-ok exited 1`,
  nested `/dev/kvm` not exposed) and `snapshot_restore`'s post-restore CSPRNG reseed (CH+FC:
  `reseed_applied: Some(false)`, `/dev/hwrng` unavailable). Both classes are **guest-hardware passthrough**
  (nested-KVM + virtio-rng), share zero code with the session change, and ride the same exec/boot/agent path
  93 other privileged tests (+ all 14 session tests) pass on. Per the rubric ("environmental is a hypothesis,
  not a diagnosis"), I ran the **control**: `git stash` the whole v26 change, rebuild the rootfs from the
  **unmodified** agent, re-run the 6 tests — they **fail identically** (same 6, same `Some(false)`, same
  `/dev/kvm` message). Mechanism, named: the host kernel log shows recurring `kvm_intel` EPT-violation /
  TDP-page-fault traces (48× today, clustered minutes before each run) on this Lenovo host — degraded
  nested-KVM + device passthrough. This is a legitimate `NOT READY` host condition for those capability tests
  (AGENTS.md rule 5: forward-work is legitimate when the host can't run a check and the failed check is
  named), **not** a session regression. It clears on a host with healthy KVM; re-run `just test-privileged`
  there to reconfirm the reseed + nested-virt tiers.

## Automated quality gates (docs/70 v3) — daemon/broker/jail gate reconciliation

The v3 quality-gate doc (`docs/historical/70-claude-fable-automated-quality-v3.md`) writes several gate
bodies against an assumed API/tree; four landed with a justified correction to the built reality (the
doc itself notes this is expected — the `protocol_decode` fuzz target already re-based `decode_frame`
onto the real postcard entry point). All four are green-on-clean and red-on-inverse (self-tested where
a self-test applies).

- **(a) The P3 artifact-path ban is scoped to the daemon crate and allow-lists `name.rs`, not
  `artifact_store.rs`.** *Diverged from:* the v3 script's `root=crates` default + `allow_file=
  crates/vmcell-daemon/src/artifact_store.rs`. *Reality:* `resolve_artifact_path` lives in
  `crates/vmcell-daemon/src/name.rs` (not `artifact_store.rs`), and P3/B12 is specifically about the
  daemon turning a **client-supplied** artifact name into a path — so the scan is scoped to
  `crates/vmcell-daemon/src`, not all of `crates/`. Scanning the whole workspace with the doc's
  `(dir|path|artifacts_dir|base).join([a-z_]` pattern produced **17 hits**, all legitimate: internal
  `dir.join(name)` in vmcell's artifact pipeline (`artifact/rootfs`, `snapshot`, `metrics` test code)
  and `dir.join(format!(…))` / `base.join(crate::naming::…())` computed joins — none is a client
  string. The shipped pattern requires a **bare-identifier** argument closed by `)` (so `format!(…)`,
  `crate::…`, and string literals don't match), a **method-call receiver** exclusion (so
  `store.dir().join(prefix)` — the daemon's own two legitimate sites — doesn't match), and strips line
  comments first. Net: zero hits on the clean daemon tree, fires on the inline `dir.join(name)` bug
  (`scripts/test-ban-artifact-path-join.sh`). `resolve_artifact_path`'s own `Ok(dir.join(name))` is the
  one sanctioned site, exempted by basename.

- **(b) The broker web-stack gate asserts `vmcell-daemon` + `axum` absent, NOT `hyper`.** *Diverged
  from:* the v3/AGENTS.md "assert axum/hyper absent from vmcell-broker" phrasing. *Reality:* `hyper`
  enters `vmcell-broker` **transitively and legitimately** via `vmcell`'s egress proxy (`hudsucker`)
  and HTTP clients (`reqwest`/`oci-client`) — all part of the net/proxy subset the broker needs for
  nft/TPROXY setup — so `-i hyper` is present on the clean tree and asserting its absence reddens CI.
  The **meaningful** P2/§13 (Cross-cutting invariants) boundary ("the network-input HTTP surface must not share the
  cap-holder") is the daemon's HTTP **server**: `axum` + the `vmcell-daemon` crate that owns it. Both
  are absent from the broker (positive control: `vmcelld`, which legitimately links the web stack,
  shows both present), so the gate is green-on-clean and fires if either leaks into the cap-holder.

- **(c) `vmcelld` reclassified print-by-contract → full family (v3): 22 `eprintln!` → `tracing::error!`.**
  The `tracing_subscriber` is installed as the first line of `main`, so every fatal diagnostic
  (blessing, auth, bind, fork, cap-drop; and the post-fork broker child, which already used
  `tracing::info!`) has a live subscriber — the conversion just makes the whole daemon one
  consistently-formatted stderr stream instead of interleaving raw `eprintln` with structured events.
  *Accepted nuance:* unlike a raw `eprintln`, a `tracing::error!` event is `RUST_LOG`-filterable, so
  `RUST_LOG=off` would silence even fatal startup errors — the deliberate consequence of "a daemon
  logs via tracing, not stdout" (v3), and the reason `vmcell-cli`/`vmcelld-ctl` stay print-by-contract.

- **(d) The `broker_frame` fuzz target decodes `postcard::from_bytes::<BrokerRequest>`, not
  `vmcell_broker::decode_frame`.** *Diverged from:* the v3 target's placeholder `decode_frame`/name.
  *Reality:* `vmcell-broker` has no `decode_frame`; its framed codec is length-prefixed **postcard**
  (`recv_msg::<T>` = `read_frame` bounded by `MAX_BROKER_FRAME_BYTES` + `postcard::from_bytes`). The
  target mirrors `protocol_decode.rs`: guard `len ≤ MAX_BROKER_FRAME_BYTES`, then decode the payload
  the privileged child feeds to postcard. (The daemon↔broker *engine* channel is JSON — a separate
  surface in `vmcell_daemon::bridge`, per Appendix A reversal 10 — not this broker-crate codec.)

- **(e) The CI broker check uses `if … then exit 1`, not the doc's `! cargo tree | grep -q .`
  two-liner.** Under `set -e`/`bash -e`, a leading `!` exempts the pipeline from `set -e`, so two
  stacked `! … | grep` lines would let a hit on the first line be masked by a clean second line. The
  `if/then/exit` form (matching the repo's other tree assertions) fails immediately and keeps local ≡
  CI (gate meta-rule 3).

**When you make a new deviation,** add a short entry here — *what* you diverged from and *why* — and,
once it stabilizes, fold it into the design document and delete it from this log. Keep this file
small: a growing log means the design doc has drifted from the code.

## v28 — the 0.9 → 0.10 delta register (design §18 — Delta register: changes from the validated v27 build), as built

The eleven §18 (Delta register: changes from the validated v27 build) deltas landed as one breaking pass. Per-item as-built record, flagging where the
built reality diverged from the delta's stated premise (a divergence is only a finding in the change
that implements the delta — AGENTS.md).

- **Delta 1 (`HostEnv` bundle).** New `crates/vmcell/src/env.rs`: `HostEnv { cids, vmids, cgroups,
  clock, overlay }`, `#[non_exhaustive]`, `Clone`, manual `Debug` (`Clock` is not `Debug`),
  `shared()`/`hermetic()`. `clock` carries `+ RefUnwindSafe` (matching `VmidAllocator`'s established
  discipline so the bundle stays unwind-safe; both `Clock` impls satisfy it) — the §9.3 (The public API surface) sketch elides
  this bound. Threaded `&HostEnv` through `start`/`restore`/`restore_cow`/`setup_env`/
  `Zygote::spawn_clone(s)`/`Lineage::fork`/`fork_many`; `MicroVm` stores one `env` and its teardown
  deletes the cgroup slice through `env.cgroups` (the standalone `cgroup_fs` field is gone).
  `SnapshotStage`/the daemon launcher/the in-VM builders build the bundle at their existing seam
  homes (the launcher via `shared()`, returning `DaemonResult` now; the builders keep their shared
  `cid_alloc` via `env.cids`; `SnapshotStage` keeps its allocator fields — which must stay
  `RefUnwindSafe` — and builds a transient `HostEnv` in `run()`).
  - **Deviation (justified): `agent()` keeps its optional `timeout`.** Delta 1 removes the *clock*
    seam from `agent()` (the gate — "no seam arguments" — is met) but §9.3 (The public API surface)'s "no arguments / 10 s
    floor constant" would drop the per-call connect budget too. `Timeouts` carries **no** overall
    agent-connect budget field, and the artifact-validator legitimately needs 60–180 s connect
    windows for slow builder-VM boots / restore-under-load (`checks.rs`); hardcoding the 10 s floor
    would silently reintroduce the boot flakiness those timeouts were added to fix. So
    `agent(&mut self, timeout: Option<Duration>)` retains the budget (10 s remains the `None`
    default); only the clock seam is gone.

- **Delta 2 (fold `OverlayStore` into `HostEnv`).** `Zygote` lost its `store` field,
  `with_overlay_store`, and `overlay_store()`; `restore_cow`/`restore_inner` take a `cow: bool` and
  materialize the CoW copy through `env.overlay` (invariant S4 — one store per process, no second
  injection path). `Lineage::fork_from_vm`/`from_snapshot_dir` dropped their `store` parameter; a
  whole lineage now shares one store by construction (supplied at fork time via `env.overlay`). The
  `RecordingOverlayStore` fan-out unit tests were re-pointed to route the store through `env.overlay`
  and their "copy source == master, dst is a private dir" assertions preserved — that IS the delta-2
  gate ("the store came from env").

- **Delta 3 (`limits_enforced` → `mem_limit_enforced`).** Renamed the `ResourceUsage` field and its
  doc (dropped the stale "name retained for API stability" line). Also renamed the wire
  `ResourceUsageDto` field (a field-for-field serde mirror; the served OpenAPI enumerates no
  ResourceUsage schema, so no parity-doc churn) and the `vmcell stats` JSON key, for end-to-end
  honesty in this breaking bump. The `CgroupFs`-fake enforcement tests (memory-controller-only
  meaning) are the gate.

- **Delta 4 (`host_services_port` → `Unprivileged` only).** Removed the field from
  `NetConfig::Privileged` (the invalid state is now a compile error), deleted the `build()`
  accept-then-reject block and the `reject_privileged_with_host_services_port` negative test as
  unreachable; kept its Unprivileged-accepts-the-port half as a standalone positive control
  (`unprivileged_host_services_port_is_supported`). Every Privileged construction site dropped the
  (always-`None`) field.

- **Delta 5 (remove `RootfsSource::VirtioFs`).** The variant is gone. It was more woven than the
  delta's "no consumer" claim implied — it appeared in all three backends' rootfs-config match arms
  (each rejecting it), the `config_has_vhost_user_device` S1 predicate, two `build()` checks,
  `check_clone_eligible`, `restore_inner`, and ~10 rejection-verifying tests. All removed; the
  backend matches are now exhaustive over `Erofs`/`Block`; `config_has_vhost_user_device` keeps its
  virtio-fs-**share** and unprivileged-net terms (only the rootfs term dropped). Tests that
  constructed `VirtioFs` to verify rejection were deleted (rejection is now compile-enforced), except
  FC's `restore_rejects_virtio_fs_rootfs` — the only test exercising FC's restore-path vhost-user
  self-guard — which was **converted** to a virtio-fs-**share** rejection so that live coverage
  survives. Grep gate: zero `RootfsSource::VirtioFs` refs remain.

- **Delta 6 (`instance_mut()` → `pub(crate)`).** Demoted. The delta's premise "none is known to use
  it" was empirically false — five integration-test sites called it (four for a hard `kill()`
  fault-injection, one read-only `serial_log()`). Reconciled by adding a safe public
  `MicroVm::kill()` (force-kill now, leaving the rest to `Drop` — the "hard kill reclaimed by the
  daemon sweep" scenario) that the four kill sites use, and pointing the read-only site at the pub
  `instance()`. No legitimate use is lost while the raw `VmInstance` is no longer public.

- **Delta 7 (`EnvSetup` explicit `Drop`).** `EnvSetup` has an explicit `Drop` that routes the
  fragile net teardown (proxy/smoltcp before netns — the reshuffle hazard L1 names) through a shared
  `release_net_before_netns` free function `teardown_post_instance` also calls (one helper, never a
  second copy); the cgroup→cid order stays field-order (`cgroup_guard` before `cid_guard`). Because a
  field of a `Drop` type cannot be moved out, `cid_guard` became `Option<CidGuard>` and the success
  path `take()`s each resource out. Gate:
  `env_setup_drop_releases_netns_before_cgroup_like_the_success_path` builds an `EnvSetup` with
  recording netns+cgroup seams and asserts netns-delete precedes cgroup-delete — the same order
  `assert_full_teardown_order` requires of the success/panic paths.

- **Delta 8 (`HostCapabilities` probed once).** New `crate::hostcaps::HostCapabilities` — a
  single-probe descriptor (`cap_net_admin`/`cap_sys_admin`, `kvm_accessible`, `netns_reachable`,
  `delegated_controllers`, `domain_leaf`) read from `/proc/self/status`, `/dev/kvm`, `/run`, and the
  current cgroup scope's `subtree_control`/`cgroup.type` (via the canonical `cgroup_base_from_proc`).
  Decision methods encode the mode-selection + fail-loud rules: `privileged_net_available`,
  `controller_enforceable`/`memory_limit_enforceable` (undelegated/threaded scope ⇒ unenforceable,
  never silent-unlimited), `virtio_fs_shares_available`, `can_boot_vm`. Consumed at start-up by the
  daemon's `MicroVmLauncher::new` (probe + log). Gate: a fake-host descriptor drives every decision
  (well-provisioned vs no-CAP_NET_ADMIN / undelegated-memory / threaded / no-KVM). The metrics
  `create_slice` keeps its own authoritative EACCES/EINVAL errno split (§7.2 — The fail-loud capability contract and HostCapabilities, rule 2); the descriptor
  is the queryable single source, not a replacement for that per-write typed error.

- **Delta 9 (`FakeVmm` fault menu).** `FakeVmm` gained a `FaultMenu`
  (`fail_create`/`fail_boot`/`fail_restore`/`fail_resume`, `wedge_control_plane_for`,
  `readiness_delay`) + `with_faults`, and a shared `control_plane_probes` counter so a wedge spans the
  respawns `start()` mints from one `FakeVmm`. `FakeVmInstance` carries the menu + counter (both
  `pub`; the five cross-module literals set them explicitly — `..Default::default()` is illegal
  because `FakeVmInstance` has a `Drop`). New orchestrator tests drive each arm: create/boot/restore
  faults leave zero cgroup residue (`created == deleted`), a scripted `fail_resume` after a live
  restore also leaves zero residue (a distinct post-instance-built teardown path the `fail_restore`
  test cannot reach), a `readiness_delay` is driven end-to-end through `start()` (elapsed ≥ delay), a
  wedge-for-2 recovers on the 3rd spawn, a permanent wedge fails loud after the bounded respawns
  (docs/72 M5c — the earlier claim "drives each arm" predated the `fail_resume`/`readiness_delay`
  drivers). The bespoke `CreateFailVmm` fake is now superseded by `fail_create` but kept.

- **Delta 10 (daemon SHA-256 sidecar).** `create()` writes a `<name>.sha256` sidecar (atomic
  temp+rename) alongside the artifact; `info`/`list` take size from `metadata()` and the digest from
  the sidecar (re-hashing the body only for a legacy artifact with no sidecar), making `list`
  O(entries) not O(store bytes); `list` excludes `.sha256` files; `delete` removes the sidecar; a
  client artifact whose name ends in `.sha256` is rejected (`BadRequest`, not the typed
  `InvalidName` enum — the name is well-formed, just reserved) so it cannot shadow a real sidecar.
  Gate: a test corrupts only the sidecar and asserts `info` returns the sidecar digest (proving no
  body re-hash), plus sidecar-matches-hash, list-exclusion, and delete-residue tests.

- **Delta 11 (remove CLI `exec`/`ls`/`rm`/`destroy` stubs).** The four verbs stay recognized by clap
  but redirect: `moved_to_vmcelld_ctl(verb)` returns a typed `Unsupported` error naming the
  `vmcelld-ctl` subcommand that actually exists for that operation, and drives a non-zero exit —
  deleting the stub's pretense, not the recognizability, so the user gets a redirect rather than
  clap's cryptic "unrecognized subcommand". `exec`/`ls`/`rm` name themselves; **`destroy` maps to
  `vmcelld-ctl rm`** (`vmcelld-ctl`'s teardown verb is `rm`, not `destroy` — docs/72 M3 fixed the
  redirect, which had named the non-existent `vmcelld-ctl destroy`). The
  `daemon_deferred_subcommands_fail_loud` test is table-driven and asserts each message names the
  **exact** `vmcelld-ctl` verb that operation exposes (the gate — a bare `contains("vmcelld-ctl")`
  let the wrong-verb `destroy` redirect ship green).

## v28 — the docs/72 review-fix pass, as built

Fixes for `docs/historical/72-claude-code-review.md`. Each lands with its red-on-inverse gate; the
Delta 9/11 notes above were corrected in the same pass. Justified deviations recorded here:

- **(H1) Cross-process VMID reclaim is serialized by a per-vmid `flock`, not an in-place
  steal.** `VmidAllocator::try_claim_fs` now holds an exclusive advisory `flock` on a per-vmid
  coordination file (`{vmid}.coord`) across the whole read→liveness→(re)claim, making that sequence
  atomic against every other claimer (threads *and* processes — `flock` on two distinct open file
  descriptions is mutually exclusive even within one process). *Reason:* the review's proposed
  rename-first "steal" approach still dual-claimed — a stealer removing a live/dead lock momentarily
  frees the path, letting a third racer claim it and the stealer's rename-back then clobber that fresh
  claim (empirically **3 winners** in the new gate). Only a coordination lock across the decision is
  correct. The kernel releases the `flock` on holder death, so a crashed coordinator cannot wedge the
  vmid; a crashed *owner*'s lock still carries its pid for the next claimer's liveness check. Gate:
  `shared_at_concurrent_reclaimers_have_exactly_one_winner` (8 racers × 200 trials on a seeded dead
  lock, exactly-one-winner) — RED on the pre-fix steal/naive variants. The `{vmid}.coord` files
  persist in the lock dir (≤254, harmless mutexes); `release_fs` still removes only `{vmid}.lock`.

- **(M1) The session mux encodes + `MAX_FRAME_BYTES`-checks at the `Session`/`SessionMux` boundary.**
  `write_tx` now carries pre-encoded `::bytes::Bytes`; a new `encode_frame` fails loud
  (`Error::Agent`) on an over-cap frame before enqueue — the host mirror of the guest agent's
  `send_framed` cap (one law). `writer_task` is a pure sink (the encode-error break that silently
  killed host→guest input for every session on the mux is gone). `SessionMux::open` encodes before
  touching the registry and removes its entry on a send failure (no orphan). Gates:
  `oversize_write_stdin_fails_loud_and_does_not_wedge_mux`, `open_failure_leaves_no_registry_orphan`
  (both KVM-free, in `agent::session::tests`).

- **(M5a) The invariant-#5 window-filling NAT gate now exists**: `tests/nat_window_fill.rs` drives a
  >64 KiB host→guest transfer through the smoltcp NAT and digest-compares (live/unprivileged suite;
  RED on the old unbounded `host_read_budget` read). `FORWARD_PORT_POOL` (invariant #4) is now a named
  const with a guard test.

- **(proxy-ca, M-NET-6) The CA `(ca.pem, ca.key)` pair is atomic: a half-committed pair is fail-loud.**
  `CaManager::new_in` regenerates only when BOTH files are absent; exactly one present returns
  `Error::Proxy` rather than silently minting a conflicting CA (which would invalidate an
  already-baked rootfs trust chain — a fresh cert cannot be re-derived from the surviving key). Gate:
  `partial_ca_on_disk_is_not_silently_regenerated`.

- **(metrics-swap) The limit-write classifier distinguishes an absent facility from a permission
  fault.** `classify_limit_write_err` now maps `ENOENT`/`EOPNOTSUPP` (e.g. `memory.swap.max` on a
  kernel without swap accounting / `swapaccount=0`) to `Error::Cgroup` ("fix the host"), not
  `CapabilityUnavailable` ("enable delegation") — the controller is delegated on such a host, so the
  delegation remediation was wrong. Gate:
  `classify_limit_write_err_treats_absent_facility_as_unsupported`.

- **(artifact-hash-root) `hash_output` folds the root directory's own mode**, so a `chmod` on a
  snapshot root is inside the tamper hash (previously only per-entry modes were folded). Gate:
  `test_hash_output_folds_root_dir_mode`.

- **(Accepted limitation) tar2erofs does not preserve PAX `SCHILY.xattr` records** (incl.
  `security.capability`). Rationale: the guest agent and every in-guest `exec` run as root (§4.2), so
  file capabilities are moot; the erofs `Node`/`XattrSpec` plumbing exists but is unused. Pinned by
  `tar2erofs::tests::test_pax_xattrs_are_not_preserved`. Retire if xattr passthrough is implemented.

- **(Accepted assumption) tar2erofs opaque-whiteout (`.wh..wh..opq`) is applied against the flat
  merged map at marker-processing time, not per-layer**: a same-layer child written *before* the
  marker in tar order is also cleared. Accepted because first-party producers (OCI merge, mmdebstrap)
  emit the opaque marker as the directory's first entry. Pinned by
  `tar2erofs::tests::test_opaque_marker_ordering_contract` (case A survives, case B — the footgun — is
  cleared). Retire when per-layer whiteout application lands.

- **(hostcaps doc-comments) corrected to the probe-and-log as-built** already recorded in Delta 8
  (the module + struct doc-comments had overstated the descriptor as wired into per-op checks); the
  design §7.2 and AGENTS.md phrasings were reconciled to match. `netns_reachable()`'s doc now states
  the existence (not writability) signal the body actually implements.

- **(proxy-cassette) `record_to` is request-line logging only** (no response, excludes blocked hosts,
  no replay — replay stays §17 forward work); its previously-uncovered fs-write branch is now gated by
  `doubles::tests::record_to_writes_forwarded_request_to_cassette`, and the design §6.4 over-claim was
  downgraded.

- **(fs-reap) the three open-coded `kill(-pgid)`+`waitpid` teardowns in `fs.rs`** (try_wait error,
  socket-wait timeout, `Drop`) now route through the single-source `crate::vmm::reap_process_group`
  (already gated by the existing `Drop`/readiness-failure reap tests).

- **(M2) Daemon `Registry::snapshot` checks the VM/state before any filesystem mutation.** The
  `NotFound`/`Conflict` (slot + `require_state(Ready)`) checks now precede `create_dir_all(out_dir)`,
  and the just-created dir is removed if empty on the backend-failure path — restoring the "mid-op
  faults leave zero residue" discipline (an early error no longer shadows a later artifact of the same
  name). Gate: `registry::tests::snapshot_on_missing_vm_leaves_no_residue_dir` (real-fs, since the
  `FakeHandle` is fs-blind).

- **(server-toctou) Daemon artifact delete is now one atomic op.** `Registry::delete_artifact_if_unused`
  runs the delete-in-use predicate (`VmSlot::pins`, single-sourced with `is_artifact_in_use` — one
  law) and the store `delete` under one hold of the `vms` lock, closing the check-then-delete TOCTOU
  where a concurrent `create_vm` could pin an artifact in the gap and lose its disk. Forwarded over the
  broker by new wire variants `EngineRequest::DeleteArtifactIfUnused` / `EngineReply::ArtifactDeleted`;
  the server handler makes one atomic call instead of the two-step check-then-delete. Gates:
  `delete_artifact_if_unused_refuses_pinned_then_allows_after_teardown` + the extended bridge
  wire-variant round-trip (Ok and InUse-across-boundary).

- **(launcher-pause, recorded)** The daemon `VmHandle::pause`/`resume` and `VmState::Paused` are
  defined and honored on the handle (mirroring the live library `VmInstance` seam) but have no REST
  route, no registry caller, and `Paused` is never produced — the un-routed half of the design's
  already-registered future-work item **"Pause/resume routes"** (§17). Annotated at-site and kept (not
  removed) to preserve the handle/`VmInstance` mirror; a route would need `EngineRequest` wire variants
  + broker forwarding + OpenAPI parity (P5). No new §17 entry required (already listed).

## Dependency modernization — latest-stable bump pass (2026-07-14)

Every direct dependency with a newer **stable** release was bumped to its latest, keeping the lockfile
advisory-clean and `--locked`-buildable on the pinned 1.96.1 toolchain. `just ci` is green (536 tests,
`cargo deny`, `semver-checks`, the ≤2-feature powerset); all three operating-mode suites were re-run on
the KVM host (`just test-privileged` / `test-unprivileged` / `test-daemon`).

- **Breaking-major bumps applied**, each with the source migration its new API required: `rustix`
  0.38→1.1 (guest agent — `mount` data arg is now `Into<Option<&CStr>>`; `event::poll` takes
  `Option<&Timespec>`; `WaitStatus::{exit_status,terminating_signal}` are `Option<i32>`;
  `Signal::Kill`→`Signal::KILL`), `nix` 0.29→0.31, `netns-rs` 0.1→0.2, `signal-hook` 0.3→0.4,
  `criterion` 0.5→0.8 (`std::hint::black_box`), `axum` 0.7→0.8 (route captures `:id`→`{id}`; the
  now-obsolete `openapi::axum_path` colon-shim and the unused `vmcell` `axum` dev-dep were deleted),
  `reqwest` 0.12→0.13 (feature `rustls-tls`→`rustls`), `sha2` 0.10→0.11 (`finalize()` returns a
  `hybrid_array::Array` with no `LowerHex`, so the seven digest-hex sites format per-byte lowercase),
  `smoltcp` 0.11→0.13 (`RxToken::consume` takes `&[u8]`; `wire::Ipv4Address` is now
  `core::net::Ipv4Addr`), `hudsucker` 0.23→0.24 + `rcgen` 0.13→0.14 **in lockstep**
  (`RcgenAuthority::new` now takes one `rcgen::Issuer` built via `Issuer::from_ca_cert_pem`;
  `ProxyBuilder::with_rustls_client`→`with_rustls_connector`), and `rtnetlink` 0.14→0.21 +
  `netlink-packet-route` 0.19→0.30 **in lockstep** (rtnetlink 0.21 pins `^0.30`, so 0.31 is excluded;
  `link().set()` takes a built `LinkMessage` via `LinkMessageBuilder::<LinkUnspec>`, `route().add()`
  takes a `RouteMessage::default()`). The CA signing identity (M-NET-6) and the emitted netlink bytes
  are preserved across these migrations.

- **Behavioral change worth flagging (compiler-invisible): TLS trust anchor.** `reqwest` 0.13's
  `rustls` feature validates against the **platform certificate store** (`rustls-platform-verifier`,
  aws-lc-rs provider), where 0.12's `rustls-tls` used the bundled webpki-roots. This affects the guest
  `vmcell-guest-tools` "curl" and `vmcell-daemon-client`. The egress/MITM suite drives HTTPS
  interception with `-k` (`danger_accept_invalid_certs`), so the change is inert for those assertions,
  and the baked-CA/system-store trust model matches the guest; `egress_proxy` (all backends) and the
  daemon-client suite pass unchanged. aws-lc-rs + rustls-platform-verifier were already resolved
  transitively, so no new license/C-link surface enters (`cargo deny` green).

- **Held back, with rationale.** `libc` (latest is `1.0.0-alpha`) and `rustls` (latest is `0.24.0-dev`)
  are pre-releases — kept on latest stable (`0.2.x` / `0.23`). The vendored-`vhost` rust-vmm family —
  `vhost`/`vhost-user-backend`/`vm-memory` (`=`-pinned to the carried `[patch.crates-io]`) and
  `virtio-queue`/`vmm-sys-util`/`virtio-bindings` (anchored to what vendored `vhost-user-backend 0.22`
  requires) — stays put: bumping forks the version and silently drops the QEMU-unprivileged
  SET_VRING_ENABLE patch (the `ci` recipe asserts both resolve from `vendor/`).

- **Environmental test-fault note (not a regression).** On this KVM host the `nested_virt::{cloud_hypervisor,qemu}`
  and `snapshot_restore` (post-restore CSPRNG reseed) tests fail because the host's nested-KVM/RNG is
  degraded this session (guest `kvm-ok` reports nested `/dev/kvm` not exposed; the `/dev/hwrng` reseed
  does not apply). Confirmed **not** caused by this bump: a clean (pre-bump) checkout fails the identical
  tests. The privileged runner (`.vmcell-bin/*`) was not rebuilt, so it still validates via its existing
  blessing; a `just bless` re-blesses the new rustix-1 runner binary when convenient (its own runtime
  behavior — cap-raise + exec via unchanged `geteuid`/`getgid` — is unaffected by the bump).

## QEMU suspend/resume — in-kernel vhost-vsock + `migrate`/`-incoming`, as built (2026-07-15)

Wires QEMU snapshot/restore, flipping `snapshot_restore` **false → true** for QEMU (design §2.4 / §2.5).
The Appendix-A-reversal-5 "validated but unwired" QEMU tier is now shipped. The follow-up pass (below,
`docs/qemu-follow-ups.md`) then flipped `restore_rotates_host_paths` **false → true** (Task A: concurrent
zygote fan-out via CID rotation) and decoupled the in-kernel transport from `snapshotting` (Task B:
`vsock_transport`); this section is reconciled to that as-built state. Validated live on this KVM host
through the blessed runner (CAP_DAC_OVERRIDE opens `root:kvm 0660` `/dev/vhost-vsock`): `snapshot_restore`,
`zygote_fan_out` (QEMU now on the concurrent branch), `fork_branch_lineage`, `extra_block_survives_snapshot`,
`qemu_restore_with_rotated_cid_reaches_agent`, `qemu_non_snapshot_in_kernel_vsock_via_transport_knob`, and
`test_benchmark_qemu` all green for QEMU (and unregressed for CH/FC); `just ci` green.

- **(a) The snapshot-eligible transport is the privileged in-kernel `vhost-vsock-pci`, not the external
  `vhost-device-vsock` daemon.** The daemon is a stateless vhost-user backend the VMM can't migrate (the
  S1 eligibility law), and — a gap the shared `config_has_vhost_user_device` predicate can't see, since it
  doesn't know QEMU attaches its *own* vsock daemon — so QEMU's `snapshot()`/`restore()` self-guard on the
  **endpoint transport**: a non-`Vsock` endpoint is a fail-loud `Unsupported`. *Selector:* reuse
  the one private `uses_in_kernel_vsock(cfg)` predicate — explicit and fail-loud, **not** the silent `.ok()`
  daemon→in-kernel fallback commit `c59bb21f` removed (M-VMM-2: the sin was the silence, not the device).
  *Selector (Task B, as built):* the dedicated `VmConfig::vsock_transport` (`Auto | InKernel |
  ExternalDaemon`); `Auto` follows `snapshotting`, `InKernel` lets a privileged **non-snapshot** QEMU opt
  into the deterministic in-kernel transport (shedding the ~11% external-daemon bring-up flake), and
  `build()` rejects `snapshotting` + `ExternalDaemon` (a non-migratable vhost-user device cannot back a
  snapshot). External stays the unprivileged default; in-kernel fails loud at device realize if
  `/dev/vhost-vsock` cannot open (no silent fallback).

- **(b) The host control plane gained an AF_VSOCK transport.** In-kernel vhost-vsock exposes the guest on
  the host AF_VSOCK namespace (dial by CID), not the daemon's AF_UNIX bridge, so `AgentClient`/`SessionMux`
  now ride a concrete `ControlStream { Unix(UnixStream) | Vsock(tokio_vsock::VsockStream) }` enum (kept
  non-generic so it never ripples into orchestrator signatures; `UnwindSafe`/`RefUnwindSafe` re-asserted so
  the public API is unbroken — semver-checks clean). `connect_framed` branches its prologue on a
  `VsockEndpoint` reported per `VmInstance`: AF_UNIX speaks the hybrid `CONNECT/OK`; AF_VSOCK has no bridge,
  so the guest's first frame is already `Ready` (guest agent unchanged — it binds `VMADDR_CID_ANY:5000` and
  never parses `CONNECT`). Adds `tokio-vsock` (design §9.6 already lists it as the host vsock crate).

- **(c) `snapshot()` = QMP `stop` → `migrate file:<dir>/state.bin` → poll `query-migrate` to `completed`
  → resume; `restore()` = `-incoming defer` + `migrate-incoming` polled to completion, returning paused.**
  The URI is `file:` not `exec:` — QEMU's `-sandbox …,spawn=deny` (§12.2) would kill `exec:`. `-incoming
  defer` (not bare `-incoming file:`) so the load completes before the orchestrator's immediate `resume()`
  (a bare `-incoming` races `cont` into an `inmigrate` runstate). Migrate + `query-migrate` poll run on
  **one** QMP connection (no per-poll `qmp_capabilities` re-handshake — the B15 gotcha). A `completed`
  status returns Ok; `failed`/`cancelled`/budget-elapsed is a typed error, never a silent timeout-through.

- **(d) No sidecar — the migration stream (`state.bin`) is the whole snapshot.** `restore()` binds a
  **fresh** `res.guest_cid` (Task A rotation, see (e)), so the source CID is not persisted; the `guest-cid`
  is a QEMU device *property*, not part of the migration stream. A pre-spawn `state.bin` existence check is
  the fail-loud-before-spawn guard (replacing the former sidecar read). Everything else (RAM, vCPUs, rootfs,
  disks, console, net) comes from the caller's congruent `cfg`, exactly as for CH/FC. The default virtio-net
  MAC is deterministic (`52:54:00:12:34:56`), so no MAC is baked — the post-restore resync rotates the
  guest's runtime MAC. *(Before Task A this was a `vmcell_qemu_snapshot.json` sidecar carrying the baked CID
  that restore reused; rotation made it vacuous, so it was removed.)*

- **(e) `restore_rotates_host_paths: true` (Task A) — restore rotates the host-global guest CID.** The
  in-kernel CID is a **host-global** namespace, so single-lineage restore (CID reuse) could not fan out
  concurrently. The experiment that gated Task A (`docs/qemu-follow-ups.md`): snapshot at CID `X`, restore
  with `-device guest-cid=Y` (`Y ≠ X`) — **empirically the migrate-incoming completes AND the guest agent
  answers at `(Y, 5000)`**, even though the guest's cached CID (`X`) lives in migrated RAM (the guest binds
  `VMADDR_CID_ANY:5000`, so its listener is CID-agnostic; the audit's E3 only ever proved *same*-CID
  restore). So `restore()` now passes the fresh allocator-unique `res.guest_cid`; each concurrent clone
  holds its own CID, and `zygote.rs` routes QEMU down the **CH (rotating) branch** — `count>1` fan-out works,
  asserting distinct `guest_cid()` per clone. The kernel's `VHOST_VSOCK_SET_GUEST_CID` `EADDRINUSE` at
  realize is the fail-loud backstop (and the red-on-inverse: a restore that reused the baked CID fails the
  second concurrent clone with exactly this error). The former `reject_live_baked_cid` liveness probe is
  **removed** — rotation makes a live-CID collision unrepresentable (every VM, create and restore, draws its
  CID from the allocator). `lazy_restore` stays `false` (no UFFD).

- **(f) `create()` now attaches virtio-rng on every QEMU launch** (`rng-random`/`virtio-rng-pci`) so the
  guest has `/dev/hwrng`; without it the post-restore CSPRNG reseed reports `reseed_applied: false` and
  restored clones replay frozen RNG state (the same reason FC's create attaches virtio-rng, §2.3). It does
  not shift block-device enumeration (`/dev/vd*` are virtio-blk).

- **(g) Test/consumer fidelity.** With QEMU now rotating, the `snapshot_restore` matrix's identity branch
  is endpoint-aware inside the *rotating* arm: CH asserts its rotated **vsock path** (embeds the new vmid),
  QEMU asserts its rotated **guest CID** (its `vsock_path` is a vestigial per-scratch-dir file); FC stays in
  the verbatim arm asserting its baked **vsock path**. The test reserves the source's CID (symmetric to its
  existing vmid reservation) so the QEMU `assert_ne!(cid, original_cid)` is non-vacuous. `zygote_fan_out`'s
  concurrent branch additionally asserts distinct `guest_cid()` per clone. A focused
  `qemu_restore_with_rotated_cid_reaches_agent` (KVM) pins the rotation end-to-end, and
  `qemu_non_snapshot_in_kernel_vsock_via_transport_knob` (KVM) pins Task B. KVM-free:
  `uses_in_kernel_vsock_reads_transport`, `CidAllocator::reserve`, the `vsock_transport` build-validation
  tests, the flipped `capabilities_are_honest_about_snapshot_restore`, and `restore_checks_state_file_before_spawning`
  (replacing the sidecar-read negative). `bench-vm` — the one downstream consumer keyed off
  `capabilities().snapshot_restore` — sets `snapshotting=true` for the snapshot-taking modes and false for
  cold-boot/footprint/vsock-rtt, so a plain cold-boot benchmark needs no `/dev/vhost-vsock`. Gates: design
  §2.4/§2.5/§3.2/§17 updated.

- **(h) `memory-backend-file,share=on,mem-path=/dev/shm` migrates cleanly** — the restored guest resumed
  with correct RAM (route/clock/MAC all post-restore-correct), so no `x-ignore-shared`/`share=off` was
  needed for the erofs config (retiring a pre-implementation risk).

## Coverage-gap perf probes — egress / zygote / daemon, + a QEMU vhost-user-net readiness gate (2026-07-15)

Adds the three latency probes the 2026-07-15 perf pass named as unreached by the single-VM /
no-network / library-direct `bench-vm` matrix (`docs/benchmark-results.md` coverage caveat), collected
every run via `scripts/perf-matrix.sh`: `bench-vm --mode net-egress` and `--mode zygote` (per applicable
backend, self-skipping where unsupported) and the standalone `scripts/perf-daemon.sh`. `just ci` green;
`just test-privileged` re-run green (the one host-facing change is the QEMU readiness gate below).

- **`net-egress` (CH + QEMU; FC self-skips — no `unprivileged_vhost_user_net`).** Boots with
  `NetConfig::Unprivileged{ egress: Open, host_services_port }` to an in-process host responder (no
  `python3 -m http.server` dependency; owned in a `Drop` guard), then curls it in-guest through the
  smoltcp NAT and **asserts a returned egress byte** (`code==0 && !stdout.is_empty()` — the data-plane
  law, not a proxy signal). Two metrics: NET-START (boot with the NAT on the path) and the in-guest
  round-trip. Deliberately NOT `Privileged` (a directly-invoked bench lacks `CAP_NET_ADMIN` and would
  leave netns residue).

- **`zygote` (CH + QEMU concurrent; FC single-clone control).** Snapshots a base once, then times
  `Zygote::spawn_clones` restoring + resuming N CoW clones, plus time-to-agent-ready across all. Prints
  `probe_cow_support()` — **`FullCopy` on this host** (`$TMPDIR` tmpfs + `target/` ext4, neither
  reflink-capable), so the per-clone figure is the non-reflink ceiling (the whole snapshot is byte-copied);
  it collapses to restore+resume on an XFS/Btrfs/bcachefs pair. `n>1` self-guards on
  `restore_rotates_host_paths` (FC → the single-clone control).

- **`daemon-API` (`perf-daemon.sh`, CH).** *(SUPERSEDED by the 2026-07-15 script-move below: this probe
  is now the freq-pinned Rust `bench-vm --mode daemon-api`; the "NOT freq-pinned" and python-percentile
  notes describe only the retired bash.)* Times `create`/`exec`/`list`/`destroy` with `curl -w %{time_total}`
  through a self-spawned `vmcelld` + broker. `list` (no VMM work) is the clean **bridge floor**; `exec`
  shows the bridge over the raw vsock datapath. NOT freq-pinned — read the `list` floor and deltas, not
  absolutes. Percentiles are nearest-rank (`ceil(n·q)-1`, matching `bench-vm`'s `pcts` — NOT the retired
  `floor(n·q)` estimator, a `<<< '' | pctl`-tested one-liner). Pitfall recorded: `python3 - "$1" <<HEREDOC`
  makes the heredoc python's stdin, so `sys.stdin.read()` reads the *program* not the piped data and every
  sample set reads empty — pass the program via `-c` so stdin stays the data.

- **QEMU vhost-user-net startup race — fixed (readiness gate).** The `net-egress` probe surfaced a real
  QEMU-backend bug the single-VM egress tests never hit: `spawn_qemu` waits for its external
  `vhost-device-vsock` daemon socket (`wait_for_socket`) before launch, but did **not** wait for the
  smoltcp `vhost-user-net` socket. The smoltcp NAT binds that UDS lazily from a background thread
  (`VhostUserDaemon::start`, not `Listener::new`); QEMU's `-chardev socket` connects as a client at `exec`
  with **no retry**, so it raced the bind and died `"-chardev socket …: Failed to connect …: No such file
  or directory"` (~30% of boots). CH's vhost-user-net frontend tolerates a not-yet-bound socket via its own
  client-side reconnect; QEMU does not. *Fix (one law):* `wait_for_socket` now takes `Option<&mut Child>`
  (the smoltcp producer is an in-process thread, not a `Child` to watch for early exit), and `spawn_qemu`
  gates the smoltcp socket the same way it already gates the vsock daemon — a fail-loud `Timeout` instead of
  a raw QEMU crash. Red-on-inverse: `wait_for_socket_process_less_present_ok_absent_times_out`.

- **DISCOVERED — smoltcp `vhost-user-net` bring-up flake (open; needs a dedicated fix).** Beyond the connect
  race, ~10% of boots the smoltcp daemon **never binds its socket within the 2 s ceiling** — the daemon
  thread intermittently fails/errors on start (sibling to the recorded ~11% external-`vhost-device-vsock`
  bring-up flake, §QEMU-suspend note (a)). Latent because the existing egress tests boot a single VM; the
  volume probe (13+ networked boots/run) exposes it. **Not root-caused here (out of scope for the perf pass).**
  Mitigation in the probe: `net-egress` retries a transient boot failure on a fresh VM (bounded
  `NET_BOOT_RETRIES`, like the QEMU vsock re-spawn), printing `recovered N transient smoltcp-bringup boot
  failure(s)` so it is surfaced, not hidden. Follow-up owner: make `SmoltcpProcess::start` block until the
  UDS is bound (signal readiness from the daemon thread) instead of deferring the bind — that would retire
  both the connect race and this flake at the source.

## Coverage-gap perf probes, round 2 — privileged net, TLS-MITM, sessions, daemon restore (2026-07-15)

Closes the four surfaces round 1 left unmeasured (the `docs/benchmark-results.md` coverage caveat). No
shipped lib change — only `bench-vm` modes, a `perf-daemon.sh` addition, and one `Cargo.toml`
required-features bump; `just ci` green. Baseline in `docs/benchmark-results.md` ("round 2").

- **`net-egress` gained `--net-mode {plain|tls|privileged}`.** `plain` is the round-1 smoltcp+`Open`
  datapath (unchanged, kept as its own function for zero regression risk). `tls`/`privileged` route the
  guest's HTTPS through an `Egress::Filtered` MITM proxy: `tls` over the unprivileged smoltcp NAT
  (CH+QEMU), `privileged` over tap + netns + nft (all backends via the blessed runner's `CAP_NET_ADMIN`;
  self-skips via `HostCapabilities::probe().privileged_net_available()`, and sweeps orphan
  `vmcell-net-*` netns at entry/exit). The MITM double (`proxy::doubles::TestDouble`) answers
  `*.probe.local` so no real upstream origin is needed; a **fresh unique host per iteration** forces a
  moka cache-miss → a fresh per-connection cert mint each time (the dominant cost). Key facts learned:
  `Egress::Open` privileged fires **zero** nft and has no reachable endpoint (the host responder is in a
  different netns) — only `Filtered` exercises the nft spawn + gives an in-netns proxy the guest reaches
  via `http_proxy=<gateway>:<vm.proxy().port>`. The **upstream** (proxy→origin) handshake is out of
  scope: hudsucker pins `with_webpki_roots()`, rejecting a self-signed local origin (recorded in the doc).
- **`--mode session`** measures the `SessionMux` layer vsock-rtt never touches: (A) `connect_sessions`
  (a **second** vsock connection + `Ready` handshake, separate from the cached one-shot client) and (B)
  per-session `open`→guest-spawn→exit. **There is no resume-by-id API** — "session persistence" (b7c5db6)
  means *long-lived* sessions, not reattach-across-reconnect (grep for `resume|reattach` on sessions =
  zero); the connect handshake is the closest analogue, so that is what is measured. `open` has no ack, so
  it is timed to `wait()`'s terminal exit, not the fire-and-return `open()` alone. No capability gate;
  all three backends (CH/FC Unix, in-kernel QEMU Vsock).
- **`perf-daemon.sh` gained a `restore` metric**: snapshot one source VM once (`POST
  /v1/vms/{id}/snapshot` → `<artifacts-dir>/<prefix>/`), then time N restores (`POST /v1/vms` with
  `restore_from` → `Registry::create` → `MicroVm::restore_cow`, synchronous to agent-ready). The source
  must be snapshot-eligible (`snapshotting:true` in-kernel vsock, NOT the unprivileged-net path), and
  `kernel`+`rootfs` are required on the restore body too. Restore is **FullCopy** here (the store dir is
  not on a reflink fs), so daemon-restore lands *slower* than daemon-create — the `restore_cow`
  memory-image copy is the tax; it would invert on a reflink fs.
- **`bench-vm` `required-features` gained `proxy`** — the `tls`/`privileged` MITM code constructs a
  `proxy::doubles::TestDouble`, and `cloud-hypervisor` pulls `hyper` but not `hudsucker`/the `proxy`
  module. The default feature set (and the `--features firecracker,qemu` perf build) already enable
  `proxy`, so every real build satisfies it; a proxy-less `cargo hack` combo now skips the bin instead of
  failing to compile.

## Perf-script logic moved into the bench crate — daemon probe → Rust (2026-07-15)

The bash probe scripts had accumulated non-trivial logic; moved it into the `vmcell` bench crate so
the one-law rules apply and it is testable. `just ci` green.

- **`scripts/perf-daemon.sh` (207 lines) → `bench-vm --mode daemon-api`** (`crates/vmcell/src/bin/bench-vm.rs`;
  the `bench-vm` binary later moved to the `vmcell-bench` crate — see the 2026-07-16 backend-extraction note below).
  The script carried an ephemeral-port picker, artifact-store seeding, a daemon spawn/health-poll/
  SIGTERM-teardown lifecycle, `curl -w %{time_total}` timing of five ops, python JSON id-parsing, and
  **a python percentile heredoc reimplementing the Rust `pcts`** (a confirmed second copy of the
  nearest-rank law — the exact "one law, one predicate" violation). The Rust mode collapses all of it
  onto the shared `pcts` (via `report_daemon_op`), spawns/reaps `vmcelld` through a `DaemonChild` Drop
  guard (SIGTERM → bounded wait → SIGKILL, mirroring the `vmcelld` integration harness), and drives the
  HTTP with the async `reqwest::Client` + `serde_json`.
  - **Why `serde_json::Value`, not the typed DTOs:** the DTOs live only in `vmcell-daemon`, and
    `vmcell-daemon` has an (optional, `server`-gated) path dep back on `vmcell`, so
    `vmcell → vmcell-daemon`/`vmcell-daemon-client` is a **cyclic package** (cargo errors even though
    the back-edge is `default-features = false`-disabled). A `Value` mirror (`v["vm"]["id"].as_str()`)
    is the cycle-free path — same shape the bash's `json.load(...)["vm"]["id"]` used.
  - **Now freq-pinned + pooled.** It runs through `run-bench.sh` like every mode (was a standalone,
    un-pinned script), so `vmcelld` inherits the runner's ambient caps by being spawned directly (the
    integration-harness pattern, not a nested runner), and its VM boots are freq-pinned. The pooled
    `reqwest::Client` keeps the connection alive, so `list`/`exec` measure the *pure* per-op bridge cost
    (the bash spawned a fresh `curl` per call, folding in TCP connect + process spawn) — `list` drops
    from ~0.6 ms to ~0.1 ms. Absolute create/restore rise (freq-pinned 2.2 GHz base vs the old
    turbo-on script); the doc numbers are re-measured accordingly.
- **`scripts/perf-baseline.sh` deleted** — dead (a strict subset of `perf-matrix.sh` with no caller;
  the matrix header called it a superset). **`scripts/perf-matrix.sh` slimmed** — the inline daemon
  block (its own tee/grep/`FAILED` copy) became one `run --mode daemon-api` call.
- **What stays shell (irreducible):** `run-bench.sh` (`systemd-run --scope -p Delegate=yes` + the
  blessed runner + freq-pin substrate — a process cannot put itself in a fresh scope or grant itself
  file caps), `with-delegated-scope.sh` (cgroup-v2 subtree_control delegation from inside the scope),
  and the `perf-matrix.sh` backend×mode loop (pure argv orchestration). A `bench-vm --mode all` was
  rejected: per-mode process isolation — fresh address space / tokio runtime / delegated cgroup scope /
  freq-pin, and a contained blast radius per mode — is a feature the shell loop provides for free.

## Secondary VMM backends extracted into their own crates (`vmcell` → `vmcell-firecracker` / `vmcell-qemu` / `vmcell-bench`, 2026-07-16)

`vmcell` now carries only the **primary** Cloud Hypervisor backend. Firecracker and QEMU moved out of
`crates/vmcell/src/vmm/{firecracker,qemu}.rs` into standalone `vmcell-firecracker` and `vmcell-qemu`
crates, and the `bench-vm` binary (which drives all three backends) moved into a new `vmcell-bench`
crate. `vmcell` bumped `0.10.0 → 0.11.0` (the `Firecracker`/`Qemu` re-exports left its public API).

- **No new "helper crate"; the shared plumbing stays in `vmcell`.** The backends depend on `vmcell`
  (the same acyclic pattern as `vmcell-rootfs-builder`/`vmcell-kernel-builder`) and reuse the existing
  `Vmm`/`VmInstance` traits, `jail`/`seccomp` predicates (`vmm_seccomp_args` still keys off the backend
  **string id**, so "one law, one predicate" is untouched), and the spawn/reap/console/eligibility
  helpers. Nine already-shared items were promoted `pub(crate) → pub`: `register_and_await_ready`,
  `reap_process_group`, `reject_unsupported_console`, `has_vhost_user_device`,
  `config_has_vhost_user_device`, `AGENT_VSOCK_PORT` (vmm), `build_kernel_cmdline`,
  `IO_LIMIT_REFILL_TIME_MS` (config), and `AgentClient::connect_endpoint` (agent). No logic was
  duplicated into the new crates.
- **Five shared VMM-contract types made exhaustive (dropped `#[non_exhaustive]`):** `VmmCapabilities`
  and `PerVmResources` (vmm), `RootfsSource`, `ConsoleMode`, `VsockTransport` (config). The extracted
  backends must construct/exhaustively-match each of these; `#[non_exhaustive]` would let a new
  field/variant slip through a backend as an unhandled default. Making them exhaustive turns a new
  field/variant into a **compile error in every backend crate** (fail-loud) — the desired discipline
  for a tightly-coupled backend set. Justified because `vmcell` is `publish = false` (no external
  consumer relied on the non-exhaustiveness). This is the load-bearing reversal of the extraction.
- **`FakeCgroupFs` was NOT exposed.** It is `#[cfg(test)]` and its deliberate `.lock().unwrap()`s would
  trip `vmcell`'s `#![cfg_attr(not(test), deny(clippy::unwrap_used, …))]` if exposed behind a feature.
  All four moved backend tests only pass the fake to a **reject-before-spawn** path (cgroups untouched),
  so each backend crate's test module defines a local no-op `TestCgroupFs: vmcell::metrics::CgroupFs`
  instead. No `test-util` feature, no new `vmcell` public surface.
- **The `firecracker`/`qemu` cargo features were kept as `host-common` aliases.** They no longer gate
  any in-tree module (dropping them would be a semver feature removal, cf. `jip-nftables`); they now
  only gate the FC/QEMU **integration-test legs**, so `just ci`'s `--features firecracker,qemu`
  invocation and the `#[cfg(feature = …)]` `vmm_matrix_test!` arms still compile and run. The matrix
  tests and the three `qemu_*` tests stay in `crates/vmcell/tests/` via a **dev-dependency cycle**
  (`vmcell(dev) → vmcell-firecracker/vmcell-qemu → vmcell`, the same permitted cycle as the validator);
  cargo forbids optional dev-deps, so the backend dev-deps are unconditional but the test arms remain
  feature-gated. `benchmark.rs` moved to `vmcell-bench/tests/` (its `assert_cmd::cargo_bin("bench-vm")`
  resolves a bin only in the same package). `clap`/`anyhow` left `vmcell` with the `bench-vm` binary
  (`cargo machete` verified); the `cli` feature is retained but now only ensures the host JSON stack.
- **Gates.** `just ci`'s `--workspace --all-features` clippy/doc/nextest and the reduced-host-feature
  loop cover the new crates; an explicit `clippy -p vmcell-firecracker -p vmcell-qemu -p vmcell-bench
  --all-targets -- -D warnings` (added to the justfile and `ci.yml`) asserts each backend compiles
  standalone against `vmcell`'s shared surface. The moved unit tests run KVM-free
  (`cargo test -p vmcell-firecracker` = 13, `-p vmcell-qemu` = 15). No backend leg silently dropped to
  a green no-op — the FC/QEMU matrix arms and the `qemu_*` tests still select under
  `--features firecracker,qemu`.

## crosvm — a fourth secondary backend (`vmcell-crosvm`, design v29 §2.5, 2026-07-16)

Added crosvm (the ChromeOS Rust VMM) as a fourth **secondary** backend crate, mirroring the
`vmcell-firecracker`/`vmcell-qemu` extraction pattern (depends on `vmcell`; no production edge back;
`vmcell` dev-depends on it for the matrix). It is **not** a §18 delta-register item (additive, not a
breaking pass). Its boot/lifecycle path was **validated live** against a source-built crosvm on a KVM host
(the maintainer installed it per the README); the validation loop found three real runtime bugs and one
capability divergence — all fixed and re-validated below.

**Live-validation findings (the whole point — these were UNVERIFIED at first draft):** the full
`just test-crosvm` matrix runs **21/21 passing** (boot + agent-exec + put_file, sessions, concurrency,
extra-block, privileged egress/host-endpoint, metrics/cgroup limits) with 5 `require_cap!` skips recorded
to the manifest. Three flag/device fixes were forced by crosvm panics at first boot, each now a KVM-free
arg-builder assertion:

1. **`--disable-sandbox` (not the built-in sandbox).** crosvm's own sandbox is a *multiprocess* minijail
   that `pivot_root`s into `/var/empty`; first boot died `"/var/empty" is not a directory, cannot create
   jail`, and its per-device child forking fights the single-process supervision model. This **reverses**
   the first-draft seccomp posture (see below).
2. **`--no-usb`.** crosvm attaches a legacy xhci USB controller by default which does not implement
   `Suspendable`; the `--suspended`→resume device-wake cycle panicked
   `Suspendable::wake not implemented for XhciController`. Dropping USB (the guest needs none) fixes it.
3. **`crosvm resume --full` for `boot()`.** `--suspended` is a FULL suspend (devices + vCPUs); a plain
   `resume` wakes only vCPUs and crosvm errors `"Trying to wake Vcpus while Devices are asleep"`. `pause()`
   /`resume()` stay vCPU-only `suspend`/`resume`.

**Seccomp posture — REVERSED by live validation (`--disable-sandbox` + Layer-2 deny-list, not the FC
analogue).** The first draft kept crosvm's built-in sandbox on for `Enforcing` (FC-shaped, `Enforcing →
[]`), reasoning it kept the backend confined-by-default. Live validation refuted it (finding 1 above): the
multiprocess minijail can't run under the harness's supervision model. So the `"crosvm"` arm of
`vmm_seccomp_args` is now `Enforcing | Disabled → ["--disable-sandbox"]`, `Log → Unsupported`. To keep the
`seccomp.rs` "never unconfined by default" invariant (the jailer's own deny-list is opt-in/default-off, so
`--disable-sandbox` alone would leave crosvm unconfined), **`Crosvm::create` turns the Layer-2 jailer
deny-list ON for `Enforcing`** (`jail_cfg.seccomp_deny_list = true`) and leaves `cfg.jail` untouched for
`Disabled`. crosvm is thus the one backend whose confinement is Layer-2 rather than its own filter — the
per-backend deny-list enablement the deny-list was designed for. **Validated:** crosvm boots, execs, and
does tap/netns networking under the deny-list (the netns `setns` runs in `build_vmm_cmd`'s pre_exec BEFORE
`apply_jail` loads the filter, so the deny-list's `setns`/`unshare` bans don't break it). The golden test
and the `Log`-unsupported test were extended to crosvm.

**Capability descriptor — `disk_io_throttle` added; `vmcell` 0.11 → 0.12.** crosvm's `--block` has no
bandwidth/iops key (verified against `crosvm run --help`), so it cannot rate-limit disk I/O like CH/FC/QEMU.
`extra_block_io_throttle` had no capability gate and hard-failed on crosvm's fail-loud rejection. The
in-pattern fix is a new `VmmCapabilities.disk_io_throttle` bool (CH/FC/QEMU/Fake `true`, crosvm `false`) +
`require_cap!` on the test + a KVM-free honesty pin. Adding a field to the deliberately-exhaustive
`VmmCapabilities` is a breaking change (cargo-semver-checks `constructible_struct_adds_field` → **requires a
major version**), so `vmcell` bumped **0.11.0 → 0.12.0** and all ten in-workspace `version = "0.11.0"` pins
followed. This is the one place the crosvm addition was *not* purely additive — it revised the first draft's
"no version bump" expectation. `crosvm_capabilities()` (one source of truth for `capabilities()` + the
`snapshot()`/`restore()` self-guards) reports `snapshot_restore`/`virtio_fs_shares`/
`unprivileged_vhost_user_net`/`restore_rotates_host_paths`/`lazy_restore`/`nested_virt`/`disk_io_throttle`
all **false**, only `virtio_console` **true**. `create()` rejects a share / unprivileged net / vhost-user
socket / throttled disk fail-loud (feature strings match the capability field names, N-VMM-1).

**QEMU-shaped structure; a third control transport.** crosvm is CLI-configured (`crosvm run`) like QEMU,
but its control plane is driven by **re-invoking the crosvm binary as a client** (`crosvm
resume|suspend|powerbtn|stop <VM_SOCKET> [--full]`, socket positional before flags) — neither QMP-JSON nor
HTTP-over-Unix. The socket wire protocol is unstable binary and is **never hand-rolled**, so the crate
carries no serde/JSON (zero new `cargo deny` surface). vsock is in-kernel vhost-vsock so `vsock_endpoint()`
overrides to `VsockEndpoint::Vsock{cid, AGENT_VSOCK_PORT}` (host AF_VSOCK; validated in privileged mode).
All flag spellings (`-s`/`--suspended`/`--no-usb`/`-c`/`-m`/`--vsock cid=`/`--net tap-name=,mac=`/`--block
path=,ro=`/`--serial type=file,hardware=`/`-p`/the control subcommands) were confirmed against
`crosvm run --help` and pinned in one testable arg-builder
(`build_crosvm_run_args`/`crosvm_control_args`/`serial_arg`).

**deny.toml / cargo-deny: no change, by design.** crosvm is *spawned as an external binary*, not linked as
a crate, so its BSD-3-Clause license and its minijail/C-libseccomp static linkage never enter the workspace
`Cargo.lock` or the license scan — identical to the external QEMU-binary carve-out. The `[bans]` on the
libseccomp-wrapper crates still bind the `vmcell-crosvm` **Rust** crate; it reaches for none (VMM-child
seccomp goes through `vmcell`'s `seccompiler`). Do **not** add crosvm as a crate dependency.

**Staging: crosvm is OUT of the default privileged/bench sets (the binary is absent on CI).** Adding crosvm
to `just test-privileged` / the CI privileged suite would hard-fail every KVM host lacking a `crosvm` binary
(a missing backend binary is a spawn error, not a skip). So the live matrix is the **opt-in
`just test-crosvm`** recipe (needs KVM + `$VMCELL_CROSVM_BIN`), and `crosvm` is out of `vmcell-bench`'s
`default` feature set (mirrors how `qemu` was staged). The preflight was NOT extended: it probes no backend
binaries (not ch/fc/qemu either), so a crosvm-only probe would be inconsistent.

**README:** the crosvm build-from-source section needs `libwayland-dev` (the maintainer hit it building the
default feature set), and points at `cargo build --release --no-default-features` for a headless build that
skips the whole gpu/wayland/audio dependency chain vmcell doesn't use.

**Gates.** KVM-free and always-on: the in-crate unit tests (arg builders incl. `--no-usb`/`--suspended`/
root-ordering, control args incl. `resume --full`, serial-mode mapping, capability honesty,
unprivileged-net reject, restore-Unsupported) run under `just test-unit` (`--all-features`);
`--workspace --all-features` clippy/doc, the reduced-host-feature loop (`+ crosvm`), and the standalone
`clippy -p vmcell-crosvm` gate the crate; the seccomp golden + the `crosvm`/`disk_io_throttle` honesty pins
run under the `crosvm` feature; `cargo semver-checks -p vmcell` gates the 0.12.0 bump. Live (opt-in):
`just test-crosvm` (21/21 on this KVM host) + `vmcell-bench`'s `test_benchmark_crosvm`. `cargo machete`
clean (the template's `tempfile` dev-dep was dropped — crosvm tests need no tempdir).

## crosvm snapshot/restore — the Firecracker baked-CID pattern (design v29 §2.5, 2026-07-16)

Follow-up to the crosvm addition above (which shipped with `snapshot_restore: false` as the recorded
deferral): snapshot/restore is now implemented and **validated live**. The `snapshot_restore`,
`extra_block_survives_snapshot`, and `fork_branch_lineage` matrix legs pass for crosvm, and the four
backends' `snapshot_restore` legs (CH/FC/QEMU/crosvm) all pass together. No `vmcell` API change (the
capability *values* changed, not the struct), so no further version bump beyond the 0.12.0 above.

- **Mechanism (mirrors QEMU's shape, FC's semantics).** `snapshot()` full-suspends (`crosvm suspend
  --full` — crosvm requires all devices asleep), runs `crosvm snapshot take <dir>/crosvm-snapshot
  <sock>` (single-file artifact), persists a CID sidecar, and resumes the source (best-effort, warn-only).
  `restore()` fail-loud-checks the artifact + sidecar exist, then spawns `crosvm run --suspended --restore
  <snap> …` with a fresh `res` (rotated vmid/tap/MAC); it returns a paused instance (`restored: true`).
  The orchestrator's `resume()` issues the completing `crosvm resume --full` — a one-shot `restored` flag
  consumed only on success (so a transient failure stays retryable). `create` and `restore` share one
  `spawn(cfg, res, cgroups, restore_from, guest_cid)`; the only run-arg delta is `--restore <snap>`.

- **The load-bearing empirical finding: crosvm BAKES the vsock CID and requires it on restore.** First
  attempt rotated the CID (QEMU-style, `res.guest_cid`) and crosvm rejected it fail-loud: `restore failed
  for device pcivirtio-vsock: Virtio vsock incorrect cid for restore: Expected: 4, Actual: 3`. So crosvm
  is the **Firecracker** pattern, not QEMU's: `restore_rotates_host_paths: false`, and `restore()` reuses
  the baked CID carried in a `crosvm-host-cid.txt` sidecar (the AF_VSOCK analogue of FC's
  `HOST_PATHS_SIDECAR` — AF_VSOCK needs only the CID, no host UDS path; plain decimal text, no serde). The
  vmid/MAC/IP still rotate to `res.vmid` via the post-restore resync (validated: the leg asserts
  `post_mac == mac_math(new_vmid)` + rotated default route + injected-clock resync + RNG reseed). Only the
  vsock CID stays baked, so **concurrent** restores from one lineage are unsupported (FC's constraint,
  §17); sequential lineage works.

- **The one non-Suspendable device (already handled).** The `--no-usb` from the boot work doubles as the
  snapshot enabler: crosvm's default xhci controller is the one device that fails `Suspendable`; the
  virtio block/net/vsock/serial set snapshots cleanly.

- **Shared-test change.** `tests/snapshot_restore.rs`'s `restore_rotates_host_paths == false` branch was a
  single AF_UNIX `assert_eq!(new_vsock, original_vsock)` (FC's shape). crosvm introduced a new (AF_VSOCK,
  non-rotating) combination, so that branch now matches on `vsock_endpoint()` — `Unix` → the FC verbatim
  path assert; `Vsock` → `assert_eq!(cid, original_cid)` (baked-CID reuse), symmetric to the rotating
  branch's `assert_ne!`. Re-ran CH/FC/QEMU snapshot legs to confirm no regression.

- **Gates.** crosvm arg-builder unit test extended (`--restore` present + rotated-`--vsock cid=` on the
  restore variant, cold create carries no `--restore`); the restore-Unsupported unit test became
  `restore_checks_snapshot_file_before_spawning` (KVM-free missing-artifact reject); the capability-honesty
  test flipped `snapshot_restore` true / `restore_rotates_host_paths` false with the baked-CID rationale.
