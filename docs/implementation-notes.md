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
  shrink needs `CAP_SETPCAP`.** [SUPERSEDED 2026-08-14 for the runner edge: `just bless` now grants the
  transient `CAP_SETPCAP` (`BLESSED_FILE_CAPS`), so the runner's shrink succeeds and the exec'd test's
  bounding set is exactly `PRIVILEGED_CAPS`. The DAEMON edge is improved but not closed, and the
  numbers are worth stating because they look contradictory: `vmcelld` is launched *through* the
  runner and inherits only the ambient `PRIVILEGED_CAPS`, which deliberately exclude SETPCAP, so
  `apply_broker_parent_drop`'s own bounding drop still fails — and warns **41**, not 38, because that
  plan drops *everything* supported (the parent keeps nothing). It reports 41 failures even though
  only 3 caps are actually present, because `PR_CAPBSET_DROP` checks `CAP_SETPCAP` in the effective
  set FIRST and returns `EPERM` regardless of whether the cap is still in the bounding set. Yet the
  parent's bounding set is now **3, not 41** — measured live, `CapBnd: 0000000000201002` on the HTTP
  parent — because it inherits the set the runner already shrank. So the residual gap is 3 caps
  wide instead of 41, on a process that drops all of its own caps and then only serves HTTP without
  ever exec'ing a file-cap'd binary. An operator who wants the last 3 can grant SETPCAP via systemd
  `AmbientCapabilities` in production. The same live measurement re-confirms P2: parent
  `CapInh/Prm/Eff/Amb` all zero, broker child holding exactly the three.] The runner raised only NET_ADMIN/SYS_ADMIN/DAC_OVERRIDE
  (not SETPCAP), so `apply_broker_parent_drop`'s bounding drop warns — the **same** file-cap-path
  limitation the runner had (B9). Dropping your *own* effective/permitted needs no SETPCAP, so the parent
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
  **[DISPROVEN 2026-08-13, then LANDED 2026-08-14.** The docs/78 review found the routing had never
  landed — all three open-coded copies still shipped and `git log -S reap_process_group --
  crates/vmcell/src/fs.rs` was empty — so the entry stood only as a record of what was *intended*.
  The docs/78 §6 fix (`fs-reap-note-claims-consolidation-that-never-landed`) makes it true: the two
  start-path copies collapsed into **one** readiness-failure wrapper around `vmm::wait_for_socket`
  (which absorbed the `try_wait` arm), and `Drop` calls the same helper — three open-coded copies
  are now two call sites of `crate::vmm::reap_process_group`. Each site re-reads the pgid from the
  **live** `Child`, so the arm where `wait_for_socket` already reaped is a no-op instead of a signal
  to a recycled group (H-HOST-1). Gate:
  `fs::drop_reaps_tests::drop_kills_and_reaps_held_child_process_group`.]

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
`--disable-sandbox` alone would leave crosvm unconfined), **crosvm turns the Layer-2 jailer deny-list
ON for `Enforcing`** (`jail_cfg.seccomp_deny_list = true`) and passes `cfg.jail` through untouched for
`Disabled` — so an operator's explicit opt-in is never force-cleared. [CORRECTED 2026-08-14 —
docs/78 M10: the site is neither `create` nor an inline block in `spawn` but the pure, total
`effective_jail_config(&VmConfig) -> JailConfig` that `spawn` calls, extracted so the flip has a
KVM-free gate: `effective_jail_config_turns_the_deny_list_on_only_for_enforcing`. `Log` never
reaches it — `vmm_seccomp_args` typed-refuses it for crosvm first.] crosvm is thus the one backend whose confinement is Layer-2 rather than its own filter — the
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
**[Bench-default half SUPERSEDED 2026-07-17 (annotated 2026-08-13, the docs/78 review):** crosvm
graduated into `vmcell-bench`'s `default` feature set once it was live-validated
(`vmcell-bench/Cargo.toml` `default = [.., "crosvm"]`; the benchmark doc's 2026-07-17 canonical
matrix). The privileged-suite staging — `just test-crosvm` stays opt-in because CI lacks the
binary — still stands.]

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

- **Gates.** crosvm arg-builder unit test extended
  (`crosvm_run_args_restore_emits_restore_flag`: `--restore <snapshot>` present, the kernel still the
  trailing positional, and `--vsock cid=` programmed from the **`guest_cid` parameter** — which
  `restore()` fills from the snapshot's baked-CID sidecar, never from `res.guest_cid`. The test passes
  `7` while `test_res().guest_cid` is `3`, so the assertion pins that parameter flow non-vacuously and
  reddens if the CID is ever sourced from the fresh `res`; a rotated CID is what crosvm rejects, so
  there is no rotation to assert here. Cold create carries no `--restore`); the restore-Unsupported
  unit test became
  `restore_checks_snapshot_file_before_spawning` (KVM-free missing-artifact reject); the capability-honesty
  test flipped `snapshot_restore` true / `restore_rotates_host_paths` false with the baked-CID rationale.

# v30 — the downstream-platform delta register (design v30 §18), as built

The nine-item register of design v30 (`docs/historical/74-claude-fable-design-v30.md` §18) landed as
`vmcell` 0.12 → 0.13. Each delta below records the as-built shape, every deviation from the §18
sketch and why, every design premise this pass found **empirically false** (with the evidence that
disproved it), and the gate that now pins each claim. Deltas were implemented in the §18 order —
1 → 3 → 4 → 5, then 2; 6 and 7; 8 after 7 (its live gate consumes 7's `echo-server` applet); 9 last.

Every delta went through an adversarial review pass that re-injected the bug each new test claims to
guard and confirmed it goes red; the fixes from those reviews are folded into the sections below
rather than recorded separately, so each section is the as-shipped state, not a history.

## v30 delta 1 — the pins overlay (design §18 delta 1 / §10.2), as built

`ResolvePinsStage` no longer reads a caller-supplied pins path. Its baseline is the repo-root
`pins.json` **embedded at compile time** (`COMMITTED_PINS = include_str!`), and an optional
`overlay_file: Option<PathBuf>` merges over it leaf-wise. `VMCELL_PINS` (via the one
`pins_overlay_path()` resolver) and `--pins` (on `build`, `build-kernels`, `oci2-erofs`; flag beats
env) set it. `run()` publishes the document it actually resolved as `resolved_pins.json`, flattens
that same document into the propagated pin map, and both `ResolvePinsStage::cache_key` and
`fast_artifacts_fingerprint` fold the pins identity through one shared `fold_pins_identity()`
(`STAGE_VERSION` 1→2, fingerprint domain tag `v1`→`v2`, so no pre-overlay output or `.build.stamp`
is served). New public surface (§10.4 contract): `pins_overlay_path`, `resolve_pins`,
`resolve_kernel_labels`.

### Deviations from the §18 sketch

- **`pins_file` was removed, not supplemented.** §18 says the stage "gains `overlay_file`"; §10.2
  makes the baseline the compile-time-embedded `pins.json`. Keeping both a caller path and the
  embedded copy is two sources of truth with no stated precedence, so the field is gone. Cost: two
  `semver-checks` breaking edges (`constructible_struct_adds_field`, `struct_pub_field_missing`)
  instead of one — both inside §18's budgeted "ResolvePinsStage changes shape". Benefit: with no
  baseline path left to compute, `vmcell-cli`'s private `pins_path()` (a near-duplicate
  `workspace_root()` ascent) had nothing to do and was retired, which is what §18 asked for, without
  exporting `workspace_root()`.
- **The merge is a recursive leaf-wise *document* merge, then one flatten** — not flatten-both-then-
  merge-the-flat-maps. Identical for this schema (every pin key is a leaf) and it leaves an honest
  document to publish as `resolved_pins.json`; flatten-then-merge leaves none. Where the schema
  aliases (top-level vs `rootfs`-nested `debian_snapshot_timestamp`), flatten-once gives one rule:
  top-level wins.
- **Three public items beyond the sketch.** `pins_overlay_path()` (the one `$VMCELL_PINS` reader),
  `resolve_pins()` (the flat merged map, minus the workspace-only `guest_agent_src_hash`), and
  `resolve_kernel_labels()`. The last is load-bearing: `vmcell build-kernels` enumerates labels
  *outside* the stage, so without it a downstream-added `kernels.<label>` would be resolvable but
  unbuildable by the exact command the toolkit contract advertises.
- **New `builder_base` namespace** (`builder_base_image` / `_digest`). See the false-premise record
  below.
- **Overlay strictness covers the value's *shape*, not only the key** — a strengthening of the §18
  sketch, forced by the false premise recorded below.
- **Sub-key strictness stays out of scope** (§10.2's own scoping): `kernel.source_ur1` and
  `kernels.<label>.source_sh256` are still ignored at flatten and caught by the existing
  referenced-but-absent hard errors. Stated at the `flatten_pins_namespace` site so it is not
  re-opened.
- **`parse_pins_json` retired from production.** With the baseline embedded, the overlay is the only
  runtime string parse; the schema unit tests now go through a 3-line test fixture that delegates to
  `flatten_pins_document` (a fixture, not a second copy of the law), and the A8 malformed-JSON guard
  moved to `parse_pins_overlay`, where the message additionally names the offending file.
- **`fast_artifacts_fingerprint` split** into an env-reading wrapper plus
  `fast_artifacts_fingerprint_with(overlay)` (the `resolve_artifacts_dir` precedent), so the
  `.build.stamp` short-circuit is unit-testable with no `std::env` mutation and therefore no
  cross-test env race.
- **`vmcell bundle`'s `pins` entry re-pointed** from the repo `pins.json` to
  `<artifacts_dir>/resolved_pins.json`: with an overlay the repo file is not what the artifacts were
  built from, and the baseline is embedded in the binary anyway. `bundle.rs`'s module doc was
  corrected to match (it still scoped the manifest as "`pins.json`" — one fact, two places, already
  disagreeing).
- **`vmcell-cli` lost its `serde_json` dependency.** Its only consumer was `build-kernels`'
  overlay-blind pins re-parse. Landed as part of this delta because `cargo machete` (a `just ci`
  step) was red without it.

### Empirically-false premises found

- **"Top-level *key* strictness closes the accept-then-ignore hole" is false** (design §10.2 / §18
  delta 1 word the guard as key-matching only). Evidence, through the public `resolve_pins`: the
  overlay `{"cloud_hypervisor": {"version": "46.0"}}` was **accepted** and resolved with
  `cloud_hypervisor` absent from the pin map. The object form is the shape a downstream will guess —
  every namespace the committed `pins.json` actually carries is an object — and unlike `kernel.*`
  this pin has no referenced-but-absent backstop: `artifact/snapshot.rs` folds it with
  `.unwrap_or_default()`, so the CH build identity silently drops out of the snapshot cache key.
  That is the M-ART-7 stale-snapshot hazard the pin exists to prevent, reached through the surface
  whose whole purpose is overriding. `virtiofsd` and `debian_snapshot_timestamp` are the same shape.
  **Fix:** the schema dispatch now declares each namespace's shape (`PinsNamespaceShape::Object` /
  `Scalar`), returned by `flatten_pins_namespace` itself so the accept-list, the shape table and the
  flattening remain one law; `parse_pins_overlay` rejects a shape mismatch naming the key and the
  expected shape.
- **"The leaf-wise merge prevents a whole-namespace replacement" was false as written** — the claim
  lived in `merge_pins_documents`' own doc comment while its fallback arm (`_ => *baseline =
  overlay.clone()`) performed exactly that replacement. Evidence: the overlay
  `{"kernel": "https://x/y.tar.xz"}` was accepted and wiped `kernel_source_url`,
  `kernel_source_sha256` **and** `kernel_microvm_config` out of the resolved map (it surfaced much
  later as `Missing kernel_microvm_config pin`, so it was loud but misattributed). The replacement is
  now unreachable from an overlay file because the shape check rejects it at the parse boundary; the
  doc comment says that, instead of claiming an immunity the function does not have. Below the top
  level shapes stay unpoliced by design, and that is now stated rather than implied.
- **"No overlay ⇒ published artifact byte-identical to 0.12" shipped unguarded.** The delta's own
  integration test asserted only parsed-`Value` field equality while its comment claimed it pinned
  byte-identity; re-rendering both arms through `to_string_pretty` (reflowed whitespace, re-ordered
  keys) left all 383 tests green. The assert now compares the published bytes against
  `include_str!("../../../pins.json")`.
- **`builder_base_image` / `_digest` were consumed but had no producer.** `artifact::rootfs::
  resolve_builder_base` prefers them over the `rootfs_*` pair, yet no namespace emitted them — so the
  strict overlay would have *rejected* a legitimate override of a pin production code already reads.
  Added as a namespace; the committed `pins.json` does not carry it, so baseline behavior is
  unchanged.
- **The roster/dispatch pinning was one-directional.** `KNOWN_PINS_NAMESPACES` (the rejection
  message's human-readable list) was tested as roster ⊆ dispatch, never dispatch ⊆ roster, so a new
  arm without a roster entry would have made the error advertise an incomplete list — telling a
  downstream its valid key is unknown — with nothing red.

### Gates

| What it pins | Gate | Proven red by |
| --- | --- | --- |
| Overlay wins per key, baseline siblings survive | `pins_overlay_wins_per_key_and_keeps_baseline_siblings` | baseline-wins merge; namespace-replacement merge |
| Fallback to baseline; a new label is resolvable **and** buildable | `pins_overlay_falls_back_to_baseline_and_admits_new_registry_entries` | overlay-blind `resolve_kernel_labels` |
| Misspelled top-level key rejected, naming it | `pins_overlay_rejects_misspelled_top_level_key_naming_it` | disabling the namespace check |
| Referenced-but-absent overlay fails loud naming the path | `pins_overlay_referenced_but_absent_fails_loud_naming_the_path` | `read_to_string(..).unwrap_or_default()` |
| Non-object overlay rejected | `pins_overlay_rejects_non_object_document` | dropping the `as_object()` guard |
| **Wrong-shaped scalar namespace rejected** (`{"cloud_hypervisor": {…}}`), with the right shape as the positive control reaching the pin map | `pins_overlay_rejects_wrong_shaped_scalar_namespace` | neutralizing `shape.matches(value)` → **RED** (the object form accepted, `cloud_hypervisor` resolving to `None`) |
| **Scalar on an object namespace rejected**, so the whole-namespace wipe is unreachable | `pins_overlay_rejects_scalar_on_an_object_namespace` | neutralizing `shape.matches(value)` → **RED** (the resolved map came back missing `kernel_source_url`/`_sha256`/`_microvm_config`) |
| **Dispatch ⊆ roster** (source-text scan of the `match` arms; the scan's own arm count is asserted so it cannot pass vacuously) | `flatten_dispatch_arms_are_all_advertised_in_the_roster` | adding a `"gremlin"` arm without a roster entry → **RED** naming `gremlin`, while the pre-existing roster test stayed green |
| Roster ⊆ dispatch, and the committed baseline satisfies the shapes the overlay is held to | `known_pins_namespace_roster_matches_the_flatten_dispatch` | a roster name the dispatch does not know |
| Baseline keeps ignore-unknown semantics (the deliberate asymmetry) | `pins_baseline_keeps_ignore_unknown_semantics` | making the baseline parse strict |
| `builder_base` reaches `resolve_builder_base` | `pins_builder_base_namespace_feeds_resolve_builder_base` | removing the arm |
| The one fold separates absent / content / unreadable | `fold_pins_identity_separates_absent_content_and_unreadable` | `unwrap_or_default()` aliasing |
| The `.build.stamp` short-circuit moves with the overlay | `fast_artifacts_fingerprint_moves_with_the_pins_overlay` | dropping the fold call |
| An overlay edit invalidates the stage key (4 distinct states) | `resolve_pins_stage_key_folds_the_overlay` | folding only the baseline |
| The published artifact is the **merged** document, and **byte-identical to `pins.json` with no overlay** | `tests/pipeline.rs::resolve_pins_publishes_the_merged_document` | publishing either input verbatim; **re-rendering the no-overlay arm through `to_string_pretty` → RED** on the byte compare (was green before this fix) |
| `vmcell-cli` carries no dead dependency | `cargo machete` (a `just ci` step) | re-adding `serde_json = "1"` → **rc=1**; removed → rc=0 |

Live legs (`just test-privileged` / `-unprivileged` / `-daemon`) are the orchestrator's. Note for the
first live run after this lands: the `.build.stamp` domain tag moved `v1`→`v2`, so every existing
workspace re-packs the rootfs once. That is the intended cache-key discipline, not a regression.

## v30 delta 3 — the labelled-kernel build path (design §18 delta 3; §5.5–§5.6, §10.1), as built + the review-fix pass

`kernels.<label>` entries now accept `fragments: [<NAME>, …]`, read by one library resolver
(`resolve_kernel_registry`) that both `vmcell build-kernels` and the new library entry point
`build_labelled_kernel` drive. Sorted label order is explicit (`sort_kernel_registry`) and pinned.
Prebuilt + label/fragments is a typed refusal through one predicate (`reject_labelled_prebuilt`),
made reachable by replacing `build-kernels --in-vm` with `--kernel-source
<prebuilt|host-make|in-vm>`. A missing fragment folds a distinct cache-key marker in **both**
compiling producers. Both compiling producers publish `vmlinux[-<label>].config` as a registered
sibling artifact through one law, and `Pipeline::build` now treats a cache hit whose *registered*
artifact vanished as a miss — which is what actually content-addresses the sidecar with its kernel.
A labelled build logs its producer (stage `tracing` + a CLI line).

The adversarial review found five defects in the first landing; each is listed below with the gate
that now pins it. Two were blocking-class: the toolkit entry point could not run from the consumer
position the contract advertises, and the sidecar could become a lying artifact.

### As-built shape

- **One-law extractions in `vmcell::artifact::kernel`** (all additive public surface, all called by
  both compiling producers rather than mirrored): `fragment_pin_key`, `sorted_fragments`,
  `fold_fragment_identity` (with the `FRAGMENT_RESOLVED` / `FRAGMENT_MISSING` markers replacing
  `unwrap_or_default()`), `kconfig_append`, `resolved_config_path`, `config_artifact_key`,
  `reject_labelled_prebuilt`, plus — from the review-fix pass — `kernel_filename_suffix`,
  `kernel_filename`, `kernel_label_from_filename`, `publish_resolved_config` and
  `clear_resolved_config`.
- **The label-filename law and its inverse now live together.** `kernel_filename_suffix` is the
  single `.`→`-` sanitization; `kernel_label_from_filename` is its inverse and the rule `vmcell
  bundle` reads the artifacts dir with. `KernelStage::suffix`, `vmcell-kernel-builder::suffix`,
  `bench-vm::kernel_filename` and the CLI's former private reader all delegate; a round-trip gate
  over the shipped `kernels` roster keeps the two halves from moving apart.
- **The sidecar has one publisher and one clearer.** `publish_resolved_config(config, vmlinux,
  kernel)` copies the post-`olddefconfig` `.config` to `resolved_config_path(vmlinux)` and hard-errors
  naming the kernel; `clear_resolved_config(vmlinux)` removes a stale one. Both compiling producers
  publish through the first; `PrebuiltKernelStage` — which republishes the same `vmlinux` path and
  compiles nothing — calls the second.
- **`ResolvePinsStage` resolves the guest-agent pin only when a vmcell checkout is present.**
  `find_vmcell_source_root` is the one source-tree predicate; `workspace_root` (which must always
  produce a path) and `vmcell_source_root` (which is legitimately `None` downstream) both go
  through it. `resolve_guest_agent_pin` is the one pin law used by `cache_key` and `run`; outside a
  checkout the key folds the distinct `NO_VMCELL_SOURCE_TREE` marker and the pin is absent rather
  than fabricated.
- **`build_labelled_kernel(label, target_dir, overlay_file) -> Result<PathBuf>`** assembles
  `ResolvePinsStage`(+overlay) → `KernelStage` and returns the `vmlinux` path; the sidecar is derived
  via the public `kernel::resolved_config_path`.
- **STAGE_VERSION bumps**: host-`make` `KernelStage` 2→3, `InVmKernelStage` 1→2. Both are correct
  (a v2 output has no `.config` beside it and was keyed by the old fold) and both **invalidate every
  cached `vmlinux*` on every box and CI runner** — a cold host-`make` rebuild (minutes) or in-VM
  rebuild (up to the 7200 s bound) on first use after this lands.

### Deviations from the §18 sketch

- **`build_labelled_kernel(label, &env)` shipped as `(label, target_dir, overlay_file)`.** `vmcell`
  has no dep (not even a dev-dep) on `vmcell-kernel-builder` and §9.1 forbids adding one, so the
  entry point offers the host-`make` producer only; its rustdoc says so and points at the CLI for
  in-VM. With no in-VM producer there is no `CidAllocator` to inject, so `&HostEnv` would have
  carried nothing the function uses.
- **Host-`make`-only producer scope** (the sketch names `InVmKernelStage` too) — same §9.1 reason.
- **`build-kernels --in-vm` (bool) → `--kernel-source <prebuilt|host-make|in-vm>` (enum, default
  `host-make`)**, matching the vocabulary `build` and §9.1 already use. This is what makes the
  prebuilt refusal reachable, and it is a **user-visible breaking CLI change**. No in-repo
  automation used `--in-vm` (justfile / CI / README / bench all clean at the time of the change).
- **`kernels.<label>.fragments` is read at the DOCUMENT layer** (`resolve_kernel_registry`), not
  flattened into a `kernel_<label>_fragments` pin: the fragment set is consumed when the STAGE is
  constructed, not by a stage reading `inputs.pins`, so a flat pin would be a second representation
  nothing reads. It also leaves delta 1's single pin-schema authority untouched. The reader is
  strict (fail-loud) even though sibling sub-keys stay permissive by §10.2 design — a silently
  ignored `fragments` builds an uninstrumented kernel and reports success.
- **`Pipeline::build` gained a registered-artifact existence re-check** (a general cache behavior
  change, not kernel-specific). Without it the sidecar is not content-addressed with its kernel in
  any meaningful sense: the pipeline hash-verifies only `out_path` and never calls `run()` on a hit,
  so a deleted `.config` would be republished as a dangling path forever. Every in-tree stage
  registers only paths under `target_dir`, so the check is safe; the effect elsewhere is that a
  deleted published artifact now forces a rebuild, which is the correct semantics.
- **`kernel_label_from_filename` changed meaning and fixed a pre-existing `bundle` bug in passing.**
  It previously matched `vmlinux-6-12-94.cache_key` and made `bundle` record a cache sidecar as the
  kernel artifact `kernel-6-12-94.cache_key`; the resolved-config sidecar would have joined it.
- **The sorted-label-order pin is honest about its blind spot.** Through the public resolver the
  order is *also* what `serde_json`'s default `BTreeMap` backing yields, so an end-to-end test
  cannot distinguish "sorted on purpose" from "sorted by accident" (verified empirically: dropping
  the sort does not redden it). The order law therefore lives in `sort_kernel_registry` and is
  tested there on a deliberately reversed input; the integration test pins the observable
  COLLATION (byte, not version: `6.12.94` before `6.6.143`) and the roster/registry agreement, and
  says so rather than claiming a red-on-inverse it does not have.
- **`crates/vmcell/examples/blake3_cache_key.rs`** — the documented hand-mint-a-sidecar escape
  hatch — was not updated by this delta. It constructs a `KernelStage` and re-derives the key from
  the shipped code, so it still mints a correct v3 key, but it is worth a look before anyone relies
  on it.

### Review-fix pass: five defects, and the empirically-false premises behind them

- **F1 (blocking). The toolkit entry point could not run from the consumer position it
  advertises.** `ResolvePinsStage::run` called `guest_agent_closure_hash(&workspace_root())?`
  unconditionally. `workspace_root()` ascends for the marker `crates/vmcell-protocol/Cargo.toml`
  and, finding none downstream, returns the *start* dir — so the hash hard-errored on a vmcell
  source file the consumer never had, at **stage 0**, before any kernel work. Every git-dep call of
  `build_labelled_kernel` / `vmcell build-kernels --pins` died there. Evidence (an out-of-tree crate
  path-depending on `vmcell`, run outside the checkout with `CARGO_MANIFEST_DIR` unset):
  `Artifact("guest-agent binary source missing at /tmp/<tmpdir>/crates/vmcell-guest-agent/src/main.rs")`.
  The stage's own rustdoc claimed it had avoided exactly this ("does not ride `ensure_test_artifacts`,
  whose fingerprint hashes the guest-agent source closure out of the vmcell tree and so cannot run
  downstream") while inheriting the identical defect one stage earlier — a comment contradicting
  shipped behavior. **Fix:** the pin is a *rootfs-lineage* pin (`KernelStage` reads only `kernel_*`;
  its only consumer is the rootfs cache key), so it is resolved only when a checkout is present, and
  is absent — never fabricated — otherwise. A rootfs build downstream still fails loud, at
  `GuestAgentStage`, which builds the agent with `cargo build -p vmcell-guest-agent` in that same
  absent tree. H-CACHE-1 is untouched: inside a checkout the full closure is still folded and a
  broken closure is still a hard error. The doc now states the mechanism instead of the aspiration.
- **F2. The resolved-config sidecar became a lying artifact when the prebuilt seed republished the
  same path.** `PrebuiltKernelStage` and the unlabelled `KernelStage` share `out_path` (`vmlinux`)
  and `name()` (`"kernel"`), and `vmcell bundle` picks the sidecar up by **filesystem existence**,
  not from the stage's registered artifacts. Reachable with documented commands: `vmcell build
  --kernel-source host-make` writes `vmlinux` + `vmlinux.config`; a later `vmcell build
  --kernel-source prebuilt` — or `build-kernels --kernel-source in-vm`, which prepends the prebuilt
  seed at that same path — replaces `vmlinux` and left the old `vmlinux.config`, so `bundle`
  digest-pinned a config describing a *different* kernel as this kernel's `kernel-config`. That is
  precisely the "assert against the result, not the fragment" property the sidecar exists for,
  passing silently. **Fix:** `clear_resolved_config` on the non-compiling producer, and the CLI
  comment that asserted the old (false) invariant now describes the clearing.
- **F3. The sanitization law had four copies, one of them the inverse, with nothing cross-checking
  them.** `KernelStage::suffix`, `vmcell-kernel-builder::suffix` and `bench-vm::kernel_filename`
  each re-encoded `.`→`-`, and the CLI's new dotted-remainder rule encoded the *inverse* of that
  law justified only by a comment. Nothing tied them: the CLI test asserted on hardcoded strings, so
  a producer that stopped sanitizing would have made `bundle` **silently drop that kernel** from a
  manifest that reads as "covered everything". **Fix:** one law + one inverse in
  `vmcell::artifact::kernel`, every producer and the CLI delegating, and a round-trip gate composed
  through the producers' own composer over the shipped registry's labels (asserted to still contain
  a dotted one) — so the CLI test can no longer pass while a producer's naming drifts.
- **F4.** This section (the delta had no reconciliation at all).
- **F5. The delta's own named gate was absent.** §18 delta 3 opens its gate list with "a fragment
  build asserts the sidecar exists and contains a fragment symbol"; nothing asserted it, and the
  actual copies (`tokio::fs::copy` in the host producer, `cp /build/.config /vmcell-out/config` in
  the guest) had **zero** test coverage. **Fix:** the copy is now one law with content assertions
  (below), and the compiling half was validated live — see the live leg.

Two further premises are recorded because they were false as worded in §18:

- **"A missing fragment folds empty bytes … so two unresolvable names collide" is false as
  worded.** The count and each NAME were already folded, so two different unresolvable names always
  hashed apart. The genuine `unwrap_or_default()` alias is fragment-**absent-from-pins** ≡
  fragment-**present-with-empty-text** — different builds (the first a hard-error request, the
  second a legal no-op) sharing a key. The marker targets exactly that. §18 also omits that the
  identical hole lived in `vmcell-kernel-builder`; it is fixed there too, and both producers now
  share one fold.
- **`build-kernels --in-vm` was already broken before this delta.** The in-VM producer needs a
  working `vmlinux` published under the `kernel` artifact key, and `build-kernels` publishes only
  `kernel-<label>` keys, so the path died on "needs a seed `kernel` artifact" regardless of what the
  operator had already built. Fixed rather than deferred: **`build-kernels`** prepends
  `PrebuiltKernelStage` when the in-VM producer is selected. [SCOPED 2026-08-14 — docs/78 M3:
  `build-kernels` is the only command that does. `vmcell build --kernel-source in-vm` is now a typed
  `Unsupported` naming `build-kernels` as the route, because a seed prepended *there* would collide
  with the unlabelled in-VM stage on `name()`, `out_path()` and the `vmlinux` cache key — it
  previously ran and died on "needs a seed `kernel` artifact". Gate: the stage assembly moved out of
  `dispatch` into `build_stages`/`build_kernels_stages`, so the roster is asserted through
  `Stage::name()` rather than a proxy.] Note the seed writes `<artifacts>/vmlinux`, so on a tree
  whose default kernel was built with host-`make` this replaces it with the pinned prebuilt seed
  (both are valid bootable kernels; prebuilt is `vmcell build`'s default) — and, since F2, also
  clears that kernel's now-stale `.config`.

### Gates

| What it pins | Gate | Proven red by |
| --- | --- | --- |
| **The toolkit runs from the consumer position** — `ResolvePinsStage::run` succeeds with no vmcell checkout, publishes `resolved_pins.json`, and propagates the `kernel_*` pins | `tests/kernel_toolkit.rs::resolve_pins_runs_outside_the_vmcell_source_tree` (re-execs this test binary with `CARGO_MANIFEST_DIR` cleared and its CWD outside the checkout) + its in-child half `resolve_pins_in_the_consumer_position` | restoring `guest_agent_closure_hash(&workspace_root())?` → **RED**, the child failing with the exact production error: `Artifact("guest-agent binary source missing at /tmp/.tmpAuPvVH/crates/vmcell-guest-agent/src/main.rs")` |
| The same, in-process, on the real `run()` body | `artifact::tests::resolve_pins_into_omits_the_agent_pin_without_a_checkout` | the same mutation → **RED** (`the rootfs-lineage agent pin must be ABSENT outside a checkout, got Some("c1df19…")`) |
| Inside a checkout the closure IS still folded (positive control for the negative above) | the `else` arm of `resolve_pins_in_the_consumer_position` (a direct nextest run) | — |
| The source-tree predicate answers **no** outside a checkout and finds the marker-owning root inside one | `artifact::tests::find_vmcell_source_root_answers_no_outside_a_checkout` | an ascent that falls back to the start dir |
| H-CACHE-1 stays fixed: a checkout with a broken agent closure is still a hard error | `artifact::tests::guest_agent_pin_is_absent_without_a_checkout_and_hard_errors_with_a_broken_one` | making the `Some(root)` arm lenient |
| **A non-compiling producer leaves no stale sidecar**, registers no config artifact, and is idempotent | `artifact::kernel::tests::test_prebuilt_kernel_clears_a_stale_resolved_config` | dropping `clear_resolved_config(out).await?` → **RED** (`the stale resolved config at /tmp/.tmpZcHnzG/vmlinux.config must be gone`) |
| **The sidecar's CONTENT**: a fragment's symbol composed through the real `kconfig_append` law reaches the published sidecar verbatim, registered under its own artifact key | `artifact::kernel::tests::test_publish_resolved_config_carries_the_fragment_symbol` | short-circuiting the copy in `publish_resolved_config` → **RED** |
| A compiling producer with no `.config` is a hard error naming the kernel, and invents no sidecar | `artifact::kernel::tests::test_publish_resolved_config_hard_errors_when_absent` | the same mutation → **RED** (`expected a hard error …, got Ok("…/vmlinux-ikconfig.config")`) |
| **The filename law and its inverse round-trip** over the shipped registry's labels (asserted to still include a dotted one) plus synthetic dotted labels; sidecars are not kernels | `artifact::kernel::tests::test_kernel_filename_round_trips_through_the_label_law` | dropping `.`→`-` in `kernel_filename_suffix` → **RED** (`the on-disk name of 6.12.94 must carry no '.' … got vmlinux-6.12.94`) |
| `bundle` reads labels **through** that law rather than a local copy | `vmcell-cli tests::bundle_reads_kernel_labels_through_the_library_law` | the same producer-side mutation → **RED** (`left: None, right: Some("6-12-94")`) — the cross-check that did not exist before |
| The missing-fragment marker (absent ≠ present-with-empty) in **both** producers | `artifact::kernel::tests::test_kernel_cache_key_missing_fragment_marker`; `vmcell-kernel-builder tests::test_cache_key_missing_fragment_marker` | restoring `.unwrap_or_default()` in `fold_fragment_identity` → both **RED** with identical keys |
| Prebuilt + label/fragments is a typed refusal, reachable from the CLI | `artifact::kernel::tests::test_reject_labelled_prebuilt`; `vmcell-cli tests::kernel_stage_rejects_labelled_prebuilt` | returning `Ok(())` (the pre-v30 silent drop) → both **RED** |
| A vanished registered sibling forces a rebuild and is republished under its own key | `tests/kernel_toolkit.rs::a_vanished_registered_artifact_forces_a_rebuild` | removing the existence re-check in `Pipeline::build` → **RED** (runs stayed 1, expected 2) |
| `fragments` is honored or rejected naming `kernels.<label>.fragments` | `kernel_registry_entry_declares_its_fragments`; `malformed_fragments_are_rejected_naming_the_label` | a reader that returns `Ok(Vec::new())` → both **RED** |
| Sorted label order is a decision, not an accident | `artifact::tests::kernel_registry_is_sorted_byte_lexicographically` | making `sort_kernel_registry` a no-op → **RED** |
| The guest ships its resolved config back | `vmcell-kernel-builder tests::test_build_commands_ordered` | commenting out the `copy resolved config out` step → **RED** |
| Only the in-VM producer needs a seed stage | `vmcell-cli tests::only_the_in_vm_producer_needs_a_seed` | — |

### The live leg (§18 delta 3's named gate)

The compiling half was **run live** on a KVM/dev host, from an out-of-tree consumer crate that
path-depends on `vmcell` (replicating the `[patch.crates-io]` vendored-vhost stanza, §10.4) and
calls `build_labelled_kernel("ikconfig", …)` with a pins overlay adding
`kernel_fragments.IKCONFIG = CONFIG_IKCONFIG=y\nCONFIG_IKCONFIG_PROC=y` and a `kernels.ikconfig`
entry declaring it. It proves F1 and delta 3's named gate together, and it passed
(2026-08-11, 20-core host, cold: source download → extract → `defconfig kvm_guest.config` →
fragment append → `olddefconfig` → `make -j20 vmlinux` → sidecar publish in **346.9 s**):

```
built  …/dsk-target/vmlinux-ikconfig in 346.869618608s
sidecar …/dsk-target/vmlinux-ikconfig.config exists=true
sidecar contains CONFIG_IKCONFIG=y: true
sidecar contains CONFIG_IKCONFIG_PROC=y: true
exit=0
```

The published `vmlinux-ikconfig.cache_key` registers both artifacts (`kernel-ikconfig` and
`kernel-ikconfig-config`), which is what content-addresses the sidecar with its kernel across a warm
build. Note the wall time: a **small, dependency-clean** fragment through the host-`make` producer is
minutes, not the 45–90 min a KASAN build costs — so the example workspace's job can afford this one.

What the in-tree suite still cannot see, and who owns it:

- `make olddefconfig`'s own drops **as a standing gate** — the sidecar exists precisely because
  `olddefconfig` may silently discard a symbol whose dependencies are unmet. The KVM-free gates
  assert the copy and its content; the live run above asserts what `olddefconfig` kept *once*, by
  hand, and nothing in CI re-asserts it. **Owner: delta 5's example workspace**, whose
  CI job builds `vmlinux-ikconfig` through deltas 1+3, asserts the sidecar via delta 4's
  `KconfigValues`, and proves `/proc/config.gz` in-guest.
- The **in-VM** producer end to end (seed stage → builder VM → config on the output share) is
  unvalidated: it needs KVM plus apt egress. Worth one manual `vmcell build-kernels --kernel-source
  in-vm` before the 0.13 tag.
- **Do not** land the live fragment build as a plain `#[ignore]`d test in `-p vmcell`'s integration
  tests: `just test-privileged` runs `--run-ignored all` over `kind(test)` with only
  unprivileged/smoltcp excluded, so it would pull a 45–90 min networked kernel compile into the
  privileged suite. It belongs in the example workspace's own CI job (or its own justfile recipe +
  filter, the `test-crosvm` shape).

### Version ledger

Delta 3 contributes **no** `cargo semver-checks` breaking edge of its own to `vmcell`'s type surface
— every library item it adds is additive (`build_labelled_kernel`, `resolve_kernel_registry`,
`KernelRegistryEntry`, `sort_kernel_registry`, `pins_overlay_or_env`, and the
`artifact::kernel` one-law exports). Its breaking edges are behavioral and belong in the 0.12 → 0.13
changelog entry all the same:

- `vmcell build-kernels --in-vm` **removed**, replaced by `--kernel-source
  <prebuilt|host-make|in-vm>`.
- `ResolvePinsStage` no longer emits the `guest_agent_src_hash` pin when it runs outside a vmcell
  source checkout (in-checkout behavior byte-identical).
- `KernelStage` STAGE_VERSION 2→3 and `InVmKernelStage` 1→2 invalidate every cached `vmlinux*`.

## v30 delta 4 — the serial classifier, as built + the review-fix pass (design §18 delta 4; §5.4, §5.6)

`vmcell-artifact-validator` gained two pure modules — `classify` (serial log → the §5.4 clause it
broke) and `kconfig` (a resolved `.config` parser) — and `checks` now renders every boot failure
through them. What follows is the as-built shape after the adversarial review, which found eight
defects in the first landing; each is listed with the gate that now pins it.

**As built.** `classify::ContractViolation` (`#[non_exhaustive]`, contract surface §10.4) has four
variants — `RootDeviceMissing`, `RootFsMount`, `VsockTransport`, `NoDirectBootKernel` — each with
`clause()` (the §5.4 prose) and `symbols()` (the unconditionally-required `CONFIG_*` set).
`classify_serial(&str) -> Option<ContractViolation>` keys on the emitters' real text. Rendering is
**two** functions, chosen by whether console evidence exists:

- `explain_boot_failure(log, base)` — the console *was* captured (an empty capture is evidence: the
  VM ran and printed nothing);
- `explain_without_serial(base, why)` — there is *no* console evidence (the VMM never started, the
  log could not be read). It names **candidate causes** and keeps the §5.4 pointer instead of
  asserting a clause.

`checks` routes every arm that reports a failed `MicroVm::start` or a failed agent handshake — Core,
Extended and Full — through one of the two, via four helpers: `explain_boot_failure_at(path, base)`
(the fs read + classification, and the one place an unreadable log is turned into "no evidence"),
`explain_boot_failure_for(vm, base)` (the only place a serial-log path is derived from a `MicroVm`),
`failed_start(e)`, and `agent_handshake_base(e)`. `kernel_banner` delegates to
`await_kernel_banner(path, budget)`, whose budget is injected so the failure path is unit-drivable.

### Empirically-false premises found (design §18 delta 4 / §5.6 wording)

1. **`EAFNOSUPPORT` is not a serial signature.** §18 delta 4 names "a vsock `EAFNOSUPPORT` →
   `CONFIG_VSOCKETS`". That mnemonic appears in no serial log: what reaches the console is the guest
   agent's own PID-1 output, `vmcell-guest-agent: boot self-check: AF_VSOCK unavailable (Address
   family not supported by protocol (os error 97))` (`vmcell-guest-agent/src/main.rs:387-391`) and
   later `failed to bind vsock: …` (`main.rs:561`). The classifier keys on those two vmcell-owned
   prefixes. The *rendered* errno prose is deliberately **not** a signature either — the agent prints
   it verbatim for an unrelated `AF_INET` loopback failure (`main.rs:361-366`), which would
   misattribute a non-vsock clause. **Gates:** `classify_vsock_unavailable` (reddens a classifier
   keyed on `EAFNOSUPPORT`, and asserts the fixture does not contain that mnemonic) and
   `classify_unrelated_eafnosupport_is_not_the_vsock_clause`.

2. **`VFS: Unable to mount root fs` is not the erofs signature — it is the shared panic of two
   different failures.** §18 delta 4 maps it to "the erofs/root symbol set". The kernel prints that
   same panic when the root *block device* never appeared (no virtio transport / no virtio-blk), and
   in that case it *also* prints `VFS: Cannot open root device` first; the missing-filesystem case
   prints `No filesystem could mount root, tried:` instead. The first landing folded all three
   strings into one clause, so a kernel built without `CONFIG_VIRTIO_BLK` was told to fix its erofs
   decompressor. As built, `ROOT_DEVICE_SIGNATURES` is checked **before** `ROOT_FS_MOUNT_SIGNATURES`
   and gets its own variant + symbol set (`CONFIG_VIRTIO_BLK`, `CONFIG_VIRTIO_PCI`,
   `CONFIG_VIRTIO_MMIO`). **Gate:** `classify_root_device_missing_outranks_the_mount_panic`, whose
   fixture carries the shared panic line so it proves precedence, not just matching.

3. **"A bogus kernel fails by raw timeout" describes one of three shapes.** (1) A garbage kernel file
   → CH loads the kernel at `vm.boot`, so `MicroVm::start` returns `Error::VmmApi` with no timeout and
   no serial log; (2) boots-but-silent → `kernel_banner`'s genuine budget expiry; (3)
   boots-then-panics-at-root-mount (the design's headline case) → `contains_panic` matches `panic -
   not syncing`, so it surfaces fast as `Error::Agent("Panic detected in serial log")` on the
   agent-handshake arm. A classifier wired only to the timeout branch would never fire on the
   design's own headline signature — hence three wiring points, not one.

4. **§5.6's "every check carries an `Instant` deadline … so 'fails loudly, not by hanging' holds by
   construction" was false in the tree, and is only half-closed.** `grep -rn Instant
   crates/vmcell-artifact-validator/` returned nothing before this pass. `await_kernel_banner` now
   computes a real `tokio::time::Instant` deadline once and bounds its whole loop (which is also what
   makes the failure path unit-testable with a 50 ms budget); the agent budgets remain `Duration`s
   that `AgentClient::connect_framed` turns into an `Instant` one layer down, and there is still **no
   overall wall-clock budget on `validate()`** (a Full run boots ~7 VMs sequentially). Plumbing one
   would touch the exhaustive `ValidationOptions` and every `checks::*` signature — out of scope, and
   recorded here rather than silently left as an unqualified design claim.

5. **`make olddefconfig` semantics: `=m` is not a satisfied clause.** §5.4 requires `=y` (the guest
   has no early userspace to load a module from), so `missing_symbols` filters on
   `KconfigValues::is_builtin`, not `is_enabled`. The first landing used `is_enabled` (y|m), under
   which the exact case the cross-check exists to name — the console says the root mount failed and
   the resolved `.config` says `CONFIG_EROFS_FS=m` — reported "no missing symbols", which the
   function's own doc tells the caller to read as "the config disagrees with the console".
   **Gate:** `missing_symbols_counts_a_module_as_missing`.

6. **The §5.4 symbol roster existed in three uncross-checked copies** — the design prose,
   `pins.json`'s `kernel.microvm_config`, and `classify::symbols()` — which is how (2) went unnoticed.
   **Gate:** `every_named_symbol_is_pinned_builtin` parses the committed `microvm_config` with this
   crate's own kconfig parser and asserts every symbol the classifier names is `=y` there.

### Deviations from the §18 sketch

- **`Tristate` → `KconfigValue`.** The design names `KconfigValues::parse` "→ tristate lookup". A
  real `.config` is full of `CONFIG_CC_VERSION_TEXT="…"`, so the shipped enum is `{Yes, Module, No,
  Other(String)}` with two predicates (`is_enabled` = y|m, `is_builtin` = y). Gate:
  `enabled_and_builtin_differ_on_modules`.
- **Fail-loud parser.** `parse` returns `Result` and rejects any line that is not blank / a comment /
  `CONFIG_<SYM>=<value>` — including a missing `CONFIG_` prefix and a bare `CONFIG_X=`. A silently
  empty parse of the wrong file would make every downstream assertion fail as "symbol absent",
  naming the wrong cause. Duplicate symbols are last-wins (kconfig's own append-a-fragment
  semantics), documented rather than rejected.
- **Report roster widened.** `run_core`'s start-failure arm previously recorded only
  `boot.agent_ready`, so `boot.kernel_banner` vanished from the report on exactly the failure the
  smoke test exercises. It now records both. Gate:
  `run_core_records_both_boot_checks_when_the_vm_never_starts`.
- **Two renderers, not one.** The delta was written as "the ONE renderer every boot-failure arm
  routes through", and the arm for a VM that never started fed it an empty log — so a missing
  `cloud-hypervisor` binary, a netns/cgroup setup error, and a VMM API error all printed "the image
  is not a direct-boot PVH-ELF vmlinux … CONFIG_PVH". Absence of evidence is not evidence, so that
  path became `explain_without_serial`. Gates:
  `explain_without_serial_names_candidates_rather_than_asserting_a_violation`,
  `await_kernel_banner_without_a_console_reports_absence`,
  `explain_boot_failure_at_reports_absence_when_the_console_is_unreadable`.
- **`BANNER_SIGNATURE` is `pub`.** `checks::kernel_banner` polls for the same literal and names it in
  its rustdoc; a `pub(crate)` const cannot be linked from public docs, and re-inlining the string was
  the second-copy defect being fixed. Additive — `cargo semver-checks` reports no update required.

### Gates (all KVM-free; the live leg is `--ignored`)

`cargo nextest run -p vmcell-artifact-validator`: **34 tests, 34 passed, 2 skipped** (the two
`#[ignore]`d smoke tests). 4 were pre-existing before delta 4 (3 in `lib.rs` + `checks::tests::
test_parse_oom_kill`); the delta as landed added 17 (`classify.rs` carried 10 `#[test]`s, not 11 —
both counts in the hand-off report were off by one); this review-fix pass adds 13 more (9 in
`checks.rs`, 4 in `classify.rs`).

The defect class the review exposed was that **none of the delta's tests touched the wiring**: every
one called `classify_serial`/`explain_boot_failure` directly, so mutating `serial_text` to read the
log and discard it (`Ok(_) => String::new()`) left 21/21 green while every classified boot failure
named the wrong clause. The new `checks::tests` drive the real filesystem read and the real
`run_core`/`run_extended`/`run_full` arms over a `FakeVmm`, which needs no KVM. Mutations re-injected
and observed red in this pass:

| mutation | result |
| --- | --- |
| `serial_text`'s success arm discards the text (the reviewer's own mutation) | RED — `explain_boot_failure_at_classifies_the_console_it_read` |
| the banner poll drops the text it read (`last = Some(String::new())`) | RED — `await_kernel_banner_classifies_the_console_it_polled` |
| the start-failure arm stops recording `boot.kernel_banner` | RED — `run_core_records_both_boot_checks_when_the_vm_never_starts` |
| `missing_symbols` back to `is_enabled` (=m counts as satisfied) | RED — `missing_symbols_counts_a_module_as_missing` |
| the root-device signature folded back into the erofs clause | RED — `classify_root_device_missing_outranks_the_mount_panic` |
| a symbol the pinned kernel config does not build in | RED — `every_named_symbol_is_pinned_builtin` |
| a second, diverged copy of the banner literal in the poll | RED — `await_kernel_banner_accepts_the_shared_banner_literal` |
| an inline `Duration::from_secs(60)` agent budget re-introduced | RED — `every_agent_budget_is_a_named_const` |
| an Extended arm back to a bare `Err(format!("boot: {e}"))` | RED — `every_extended_and_full_boot_failure_names_the_missing_evidence` |
| an empty log fed to `explain_boot_failure` on the failed-start path | RED — two tests |
| a 5th `ContractViolation` variant with `clause() => ""`, `symbols() => &[]`, walk untouched | **COMPILE ERROR** in the test module's exhaustive `next_in_walk` |
| the same variant spliced into the walk (the honest growth) | RED — `every_violation_names_a_clause_and_symbols` |

Also green: `RUSTFLAGS="-D warnings" cargo clippy -p vmcell-artifact-validator --all-targets`;
`cargo clippy -p vmcell --tests` (no public check signature changed); `cargo test --doc`;
`RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features`;
`cargo semver-checks -p vmcell-artifact-validator` (196 pass, "no semver update required" — the new
enum variant is minor because the enum is `#[non_exhaustive]`); `cargo machete`; `typos`.

### Residual, deliberately recorded

- **The `#[non_exhaustive]` growth gate is compiler-forced but not airtight.** A new variant cannot
  compile without an arm in `clause()`, `symbols()`, and the test module's `next_in_walk`; the walk
  is a *cycle*, so the honest splice puts the variant under test. An author who instead writes a
  self-terminating arm nothing points at would still evade the per-variant assertions. Rust has no
  stable variant enumeration (`std::mem::variant_count` is nightly) and the crate takes no derive
  dependency, so this is the strongest available shape; the arm's doc says "splice, do not append".
- **One uncovered line:** `explain_boot_failure_for`'s `vm.instance().serial_log()`. Everything
  either side of it is unit-driven (the fs read + classification below it, the FakeVmm-started VM
  above it — `explain_boot_failure_for_reads_the_vms_own_console` asserts the message names *that
  VM's* console path), but a `FakeVmm` cannot be given a serial log with content, so the
  content-through-a-real-VM path is proven only by the live smoke leg.
- **The live smoke leg is still not run by any CI recipe.** `validate_broken_kernel_reports_failure`
  now asserts the *message* (`no serial evidence:` / `contract violation:` plus `CONFIG_PVH`), not
  just the check id — but both smoke tests are `#[ignore]`d and nothing in `justfile`/
  `.github/workflows` invokes `--test smoke -- --ignored`. Delta 4's live half stays unguarded until
  such a recipe exists (it needs built artifacts).
- **Pre-existing, untouched:** `checks.rs` carries 11 bare `let _ = …await` on best-effort
  teardown/shutdown `Result`s, which "fail loud" forbids; fixing them is a class-wide cleanup that
  must land with a `scripts/`-level ban script. **[CORRECTED 2026-08-13 — the docs/78 review: the
  "best-effort teardown/shutdown" characterization is inaccurate for one of the 11.** The cluster is
  10 teardown/shutdown sites plus the deliberately-commented OOM-probe exec discard — and
  `checks.rs:866`'s `let _ = vm.agent(..)` is a **load-bearing** swallow: the `metrics.usage_readable`
  arm passes on a guest that never booted, with the handshake failure reported nowhere (docs/78 §6
  fix item).] **[RESOLVED 2026-08-14 — the load-bearing swallow is gone.** The `metrics.usage_readable`
  arm is now `usage_readable_after_agent_ready(vm, ready_budget, settle)`, which renders a failed
  handshake through `explain_boot_failure_at` like every sibling arm; `agent_handshake_base` takes
  the budget it names, so an injected budget is never misreported, and `concurrency_distinct_ids`'
  second copy of that sentence composes through it. Gate:
  `checks::tests::usage_readable_fails_naming_the_boot_failure_when_the_agent_never_handshakes`
  (KVM-free, `FakeVmm`, 1 s injected budget) — red on the inverse: with the `let _` restored the arm
  reports "memory controller delegated but ResourceUsage::mem_limit_enforced is false" on a guest
  that never booted. The residual cluster is now 10: nine best-effort `shutdown()` teardowns plus the
  deliberately-commented OOM-probe `exec` discard; the class-wide ban script is still the open item.] Same for
  `guest_core_checks`' roster shrinkage when
  the agent is unreachable (the four `rootfs.*` + `agent.put_file_roundtrip` ids vanish rather than
  failing) — the equivalent shrinkage on the arm delta 4 touches *was* fixed.
- **`vmcell-artifact-validator/Cargo.toml` has no comment-changelog block** unlike
  `crates/vmcell/Cargo.toml`, though §10.4 now makes this crate contract surface. semver-checks says
  no bump is required for this change; this is a convention item for the ledger pass.

## v30 delta 5 — `examples/downstream-kernel/`, the living consumer gate (as built)

**What landed.** A second cargo workspace at `examples/downstream-kernel/`, excluded from the vmcell
members (root `Cargo.toml`: `exclude = ["fuzz", "examples/downstream-kernel"]`, the `fuzz`
precedent), consuming `vmcell` + `vmcell-artifact-validator` the way a git-dep consumer does. It
carries its own `Cargo.lock`, its own `[patch.crates-io]`, its own `pins-overlay.json` (the neutral
`IKCONFIG`/`IKCONFIG_PROC` fragment plus a `kernels.ikconfig` label declaring it), a lib+bin crate,
a KVM-free contract test binary, and `ci-check.sh` — the whole KVM-free gate. Two CI jobs:
`example-downstream` (ubuntu-latest, KVM-free) and a live step appended to `test-integration` after
`just test-daemon`.

**Deviations and their reasons, recorded rather than silent.**

1. **Path deps, not `git`+`rev`.** §5.6 says "the way a git-dep consumer does"; a `rev` pin would
   stop the example reddening on *same-commit* contract drift — the entire point — and could not be
   exercised on a PR at all. Everything else is consumer-shaped. Stated in the example's README.
2. **The harness getters' two-step route needed a code change, not just a test.** §10.4 specifies
   that `harness::get_vmlinux`/`get_rootfs` "fail loud with a message naming the two-step route",
   and `crates/vmcell/src/lib.rs`'s crate doc already *claimed* it — but no such message existed:
   the observable refusals were `ensure_test_artifacts`'s "guest kernel missing at …. Build it once:
   `cargo run -p vmcell-cli …`" and (outside a checkout) "guest-agent binary source missing at …",
   both vmcell-checkout-only fixes and a dead end downstream. Landed as one const
   (`TWO_STEP_ROUTE`) + one composer (`fail_loud`) in `crates/vmcell-artifact-validator/src/
   harness.rs`, appended to all three refusal paths (bootstrap failure and the two existence
   checks). It rides *every* failure rather than only downstream-looking ones because there is no
   honest local "am I downstream?" predicate: the example workspace lives **inside** the vmcell
   checkout, so `workspace_root()`'s ascent finds vmcell's tree and any presence test answers
   "in-workspace" for a genuinely downstream-shaped consumer. In the vmcell workspace this only adds
   a sentence to an already-failing path. (This is the delta-5 change the premise report flagged as
   "load-bearing, and it is NOT free".)
3. **The documented CLI verb was wrong in the docs, and the gate found it.** §10.4, §5.6 and
   `README.md` (two places, incl. the CLI table) all documented `vmcell oci2erofs …`; the shipped
   clap verb is **`oci2-erofs`** (kebab-cased from `Oci2Erofs`), and has been since v15 — every
   historical design doc repeats the wrong spelling. The example's documented-CLI leg failed with
   clap's "unrecognized subcommand 'oci2erofs'". Fixed in `README.md` and in the new harness
   message; **design §5.6/§10.4 still carry the wrong spelling and need the same one-word
   correction** (or, if the documented spelling is preferred, a `#[command(alias = "oci2erofs")]`
   on the subcommand — a CLI change, not taken here).
4. **The documented-CLI legs run on their fail-fast boundaries.** §10.4 asks the job to invoke the
   exact documented commands; a real `build-kernels --pins` compiles kernels for minutes and
   `oci2-erofs` pulls an OCI image, neither of which belongs on the ubuntu job. The legs invoke the
   real binary with the real flags and assert the contract boundary each one owns: `--pins` rejects
   a typo'd overlay key **naming it**; `--kernel-source prebuilt` + a label is the §5.6 typed error;
   a well-formed `--inject` triple parses (the command then stops on the un-pinned image digest, so
   the leg needs no network); an unknown `--inject` key is named. The *real* labelled build is the
   live leg. `--inject`'s reserved-dest rejection lives past the image pull and stays covered by
   delta 6's own in-tree tests.
5. **The vendor-assertion red leg mutates the tree, not the manifest.** Deleting `[patch.crates-io]`
   invalidates the example's `Cargo.lock`, so `check-vendored-vhost.sh` — `--locked` on purpose, so
   a "check" can never rewrite a consumer's lockfile — would fail with cargo's stale-lock message
   instead of the dropped-patch verdict under test. The leg strips the `(…/vendor/vhost…)` source
   annotations from **this workspace's real `cargo tree`** and feeds it back through a stub `cargo`,
   which is exactly what a consumer who forgot the stanza sees, anchored on the real resolution.
   A non-vacuity guard reddens if the tree carries no vendored annotation to strip (i.e. if the
   feature set ever stops resolving vhost and the green leg becomes meaningless).
6. **The example resolves its own artifacts dir.** `vmcell::artifact::artifacts_dir()` would resolve
   into the vmcell checkout's `target/vmcell-artifacts` from here (the source-root ascent finds the
   vmcell tree), so `downstream_kernel::artifacts_dir()` defaults under the example's own `target/`
   and the CI live step sets `VMCELL_ARTIFACTS_DIR` explicitly. A downstream build must never write
   into the host project's artifact cache.
7. **`shellcheck`'s glob widened** from `scripts/*.sh` to `scripts/*.sh
   examples/downstream-kernel/*.sh` in **both** the justfile and `ci.yml`'s `lint` job (local ≡ CI).
   docs/76 specifies the script's path, so the gate moved to the script rather than the script to
   `scripts/`.

**Gate meta-rule 2 — the deliberate reds.** Two, both KVM-free and both restored afterwards:
renaming the overlay's `kernels.ikconfig` key to `ikconfg`, and deleting its `fragments` array. Both
reddened `the_overlay_adds_this_consumers_label_and_fragment` and took `ci-check.sh` to exit 101,
naming the cause ("the resolved `kernels` registry has no `ikconfig` label — the overlay … was not
merged; resolved labels: [6.12.94, 6.6.143, ikconfg, usbhost]" / "`kernels.ikconfig.fragments`
resolved to [], expected [\"IKCONFIG\"]"). The sidecar-drop inverse is additionally pinned KVM-free
by `a_missing_resolved_config_sidecar_is_named_not_silently_skipped`.

**Not executed here.** The live leg (`downstream-kernel live`: labelled kernel build → sidecar →
battery → in-guest `/proc/config.gz`) was written but not run — a sibling agent held the serial KVM
host. Its data-plane assertion is a **subset**, not an equality: every symbol/value the sidecar
records must appear identically in the guest's `/proc/config.gz`, because kbuild regenerates the
stored copy and it may carry symbols the copied file did not.

## v30 delta 6 — downstream rootfs extra files (design §18 delta 6 / §4.2, FR-V4, invariant F5), as built + the review-fix pass

`pub struct ExtraFile { dest: String, src: PathBuf, mode: u32 }` ships exactly as §18 writes it (plus
an `ExtraFile::new` ctor), threaded through the **one** inject+pack tail —
`pack_erofs_with_injection(…, extra: &[ExtraFile])` — so both rootfs sources and any third-party
`Stage` get it identically (§4.3 obligation 3). The CLI reaches it as a new `RootfsStage` field:
`vmcell oci2erofs … --inject dest=…,src=…,mode=0755` (repeatable). Insertion order in the packer is
layer merge → extra files → vmcell's manifest injections → vmcell's symlinks, so extras win base-image
content and `.wh.` whiteouts (deliberate composition) and vmcell's own injections stay unconditional
and authoritative. Modes are **explicit**: an extra file does not inherit `injected_file_mode`'s
`bin`/`sbin` heuristic. Cache identity folds `(dest, mode, content-hash)` sorted by dest through the
shared `fold_rootfs_injection_identity`, and **both** source stages bumped
(`OCI_ROOTFS_STAGE_VERSION` 3→4, `MMDEBSTRAP_STAGE_VERSION` 1→2), both hoisted from `fn`-local consts
to module-level consts so the bumps are assertable KVM-free.

**The F5 predicate is derived, not restated.** `is_reserved_injection_path(dest)` is computed *from*
`rootfs_injection_manifest` (called with probe paths that are never read) plus a `vmcell-tools/`
prefix rule, so the reserved list cannot drift from what the packer actually bakes and delta 7's
`echo-server` applet was covered the moment it was added. It compares **normalized** paths through the
packer's own `normalize_path` (promoted `pub(crate)` rather than re-implemented), so the caller's
absolute form, the manifest's relative form, and the `/usr/sbin/./vmcell-guest-agent` and
`//usr/sbin/…` evasion shapes all collapse to one key. Gate:
`is_reserved_injection_path_covers_every_vmcell_dest` (manifest-derived, both forms, the evasion
shapes, the whole-dir rule, and a positive control of legitimate downstream dests) — verified RED on a
raw-string comparison.

**Validation happens at the pack tail, before any I/O.** An `ExtraFile` never passes through
`VmConfig`, so the tail is its only accepted-input boundary. `validate_extra_files` rejects: a relative
dest, a `..` component, a dest that names a **directory**, a reserved dest, a duplicate normalized
dest, and a mode carrying bits outside `0o7777` (validated *then* `u16::try_from` — a full `st_mode`
like `0o100755` is refused, never `as`-narrowed). Gate:
`validate_extra_files_rejects_the_silent_corruption_classes` (two positive controls plus 17 rejection
arms) and `test_pack_erofs_rejects_reserved_extra_dest_before_any_io`, which asserts the reserved-dest
error beats the missing-agent error and that neither `ca.pem` nor the image was written.

### The review-fix pass

**`/opt/.` — a dest naming a *directory* passed the "must name a file" guard and would have replaced a
base-image directory with a regular file.** As first shipped that guard was a raw
`dest.len() > 1 && dest.ends_with('/')` on the **un-normalized** string, while every other rule in the
same loop (reserved, duplicate) keyed on `normalize_path`. `/opt/.` normalizes to `opt` and does not
end in `/`, so it was accepted end-to-end: fed through `build_node_map` over a base shipping an empty
`opt/` directory, the resulting node was `Node::File`. Debian ships `/opt`, `/srv`, `/mnt` and
`/media` **empty**, and an empty directory clears the pre-existing "child under a non-directory
parent" check, so the corruption was silent for exactly the shapes that occur in practice; a *non-*
empty directory happened to trip that other check. A component scan does not catch it either —
`Path::components` folds a trailing `.` away just as it folds a trailing `/`. This was the same
raw-vs-normalized asymmetry that had already been closed one guard below, for the reserved check.

Fixed by deriving the rule from the normalized form: the dest's raw final segment (the text after the
last `/`) must equal the normalized path's final component. That one comparison subsumes the trailing
slash, the trailing `.`, `/.`, `/./` and the bare `/`, and it keeps an *interior* `.` accepted. The
`..` check must stay ahead of it, since `/usr/local/../sbin/acme` has agreeing raw and normalized
leaves. Gate: four new arms in `validate_extra_files_rejects_the_silent_corruption_classes` —
`/opt/.`, `/usr/local/bin/.`, `/opt/./`, `/.` — verified RED on re-injecting the original raw guard
(`trailing '.' on a top-level dir must be a hard Error::Artifact, got Ok([("/opt/.", "/src", 493)])`).

**The contract-surface rustdoc contradicted the shipped accepted-input rule.**
`pack_erofs_with_injection`'s `# Errors` claimed it rejects a dest with "no `.`/`..` component"; `.`
components are deliberately accepted and normalized away, which `ExtraFile`'s own rustdoc stated
correctly — two docs on the same rule disagreeing, with the wrong one on the surface §10.4 names as
downstream contract. Both rustdocs (and `validate_extra_files`') now say the same true thing: a `..`
component is rejected, an *interior* `.` is accepted and folded, and a trailing `/` or `.` names the
parent directory and is refused. A second positive control in the rejection battery pins the accepted
half, so the directory-naming arms cannot later be "satisfied" by rejecting every `.`.

**The live gate was run.** `extra_file_is_present_in_guest_with_its_explicit_mode` boots a real Cloud
Hypervisor VM on a freshly packed rootfs and, as its first execs, `cat`s the injected marker and
`stat -c %a`s it: PASS, non-vacuous on 755-vs-644 (`injected_file_mode` would give 644 for
`/opt/acme/acme-daemon`, which has no `bin`/`sbin` component). Re-run green after the validation-path
fix above. It is selected by `just test-privileged`'s existing filter.

### Deviations from the §18 sketch (behavior and gate bind; a shift is recorded, never silent)

- **The widened injected-file shape is ONE alias, not two.** The sketch implies extras arrive as
  widened `InjectFile`s; as built there is a single
  `pub type vmcell::artifact::tar2erofs::InjectedFile<'a> = (&'a str, &'a Path, Option<u16>)`, aliased
  by `rootfs::InjectFile`, with the mode in the tuple: `None` = vmcell's `injected_file_mode`
  heuristic, `Some` = a caller's explicit mode. Two spellings of one shape is the duplication the
  house rule forbids. Both file loops go through one new `insert_injected_file` helper carrying the
  uid/gid/mtime/type-bit rules and the explicit-mode-else-heuristic rule; `injected_file_mode` and its
  pin test are untouched.
- **`ExtraFile` ships exhaustive with three public fields**, not `#[non_exhaustive]`. The design text
  is explicit and this is a breaking release anyway. Ledger consequence: a later `uid`/`gid` field, or
  `mode` becoming `Option`, is another breaking bump.
- **`MmdebstrapRootfsStage` also gained `pub extra: Vec<ExtraFile>`.** The delta named only the pack
  tail and `RootfsStage`, but §4.3 obligation 3 says the parameter applies to every rootfs source for
  free — an mmdebstrap-produced rootfs that could not carry extras would be a source-dependent
  contract.
- **`--inject` is on `oci2erofs` only, not `build`** (§10.4's documented consumer invocation).
  `vmcell build` produces vmcell's own canonical rootfs and takes no consumer content (G1). Both
  builder-base `build_rootfs` call sites (`vmcell-rootfs-builder`, `vmcell-kernel-builder`) pass `&[]`
  with an at-site G1 rationale.
- **Dest semantics beyond the sketch's "absolute, UTF-8, no trailing slash":** a `..` component is
  rejected outright (because `normalize_path` *pops* it, so the dest would mean something other than
  it reads as), an interior `.` is normalized away rather than rejected (so `/a/./b` and `/a/b` are
  the same dest and therefore the same duplicate — and `/usr/sbin/./vmcell-guest-agent` is caught by
  the reserved check, which is what proves the normalize-before-compare ordering), and a trailing `.`
  is rejected as directory-naming (the review-fix above).
- **`parse_inject` is the parser, not the policy.** It rejects unknown/repeated/missing keys, empty
  values, non-octal modes and comma-bearing paths *by name*, but reserved/duplicate/dest-shape
  rejection stays at the pack tail so every non-CLI caller gets it. Gate:
  `parse_inject_honors_or_rejects_every_field`, RED on each of an ignored unknown key, a decimal mode,
  and a last-wins repeated key.

### Empirically-false premises found in this pass (each now pinned by a gate)

1. *AGENTS.md's one-law roster listed `is_reserved_injection_path` as shipped* (line 112, F5). It did
   **not exist**: `git show HEAD:crates/vmcell/src/artifact/rootfs/mod.rs | grep -c
   is_reserved_injection_path` → `0`. Treated as the stop-and-check §18 requires; the predicate ships
   with this delta and the roster is now true. Pinned by
   `is_reserved_injection_path_covers_every_vmcell_dest`.
2. *The delta's premise pass counted two `build_rootfs` callers.* There are three —
   `vmcell-kernel-builder` also builds a builder-base rootfs. Pinned by the compile: the parameter is
   required, so a missed caller cannot build.
3. *The trailing-slash guard was "the" names-a-file law.* False, per the review-fix above; the raw
   string and the normalized form disagree on `/opt/.`. Pinned by the four directory-naming arms.

### Still open — deliberately not fixed here

The **vmcell-internal** file-vs-symlink clobber in `tar2erofs` is untouched: the injected symlinks are
inserted last into the same `entries` map with plain last-wins `insert`, so a vmcell symlink dest that
collided with a vmcell file dest would silently win. Delta 6 as specified rejects *extra-file*
collisions only, and `is_reserved_injection_path` covers both the file and the symlink manifest
entries, so no downstream dest can reach the clobber. F5's wording could be read as implying the
internal case was fixed — it was not. It is a one-manifest-edit-away hazard with no gate; a future
delta should make `insert_injected_file` and the symlink loop refuse an occupied key outright.

## v30 delta 7 — the raw vsock dial (design §18 delta 7, §3.1/§3.2 — FR-V3), as built + the review-fix pass

`MicroVm::dial_vsock(port, timeout) -> VsockDial` ships: a plain byte stream to an arbitrary guest
AF_VSOCK port, no framing, no `Ready`, no agent. The fragile hybrid `CONNECT <port>`/`OK` prologue was
extracted out of `AgentClient::connect_framed` into the one `hybrid_connect_prologue`, shared by the
framed connect and the raw dial. The in-guest listener is a new `echo-server` guest-tools applet
(`--vsock <port>` / `--tcp <addr>:<port>`), baked into the erofs like the other applets.

**The load-bearing correction: design §3.2's "EOF propagates in both directions (half-close forwards)"
is empirically FALSE on half the backends.** It was written as a property of the dial; it is a property
of each backend's vsock bridge. Measured 2026-08-11 on the full live matrix (cloud-hypervisor 54.0.0,
Firecracker 1.16.0, QEMU 10.2.1, crosvm), writing a request, calling `shutdown()`, then draining the
guest's echo — five connections per backend:

| backend | host-side transport | reply after the host's `shutdown()` |
| --- | --- | --- |
| Cloud Hypervisor | in-VMM hybrid muxer over AF_UNIX | arrives — 5/5 |
| crosvm | in-kernel AF_VSOCK, no bridge | arrives — 5/5 |
| Firecracker | in-VMM hybrid muxer over AF_UNIX | **discarded — 0/5** |
| QEMU | external `vhost-device-vsock` daemon over AF_UNIX | **races the teardown — 2/5** |

On FC and QEMU the host's `SHUT_WR` on the bridge socket becomes a teardown of the whole vsock
connection, dropping whatever the guest had not yet flushed. The loss is **silent**: the host's next
read returns `Ok(0)`, an ordinary clean EOF, never an error — a caller cannot distinguish a complete
reply from a truncated one after the fact. The *guest→host* direction is portable: the host sees EOF
when the guest half-closes or exits, on all four.

Consequences, all landed:

- **The `VsockDial` rustdoc now carries that table verbatim**, dated and version-anchored, plus the
  portable rule it implies: treat `shutdown()` as end-of-conversation, never as an in-band "your turn"
  signal; frame the guest protocol so a reply's end is knowable without an EOF (length prefix,
  delimiter, fixed size), drain it, and only then half-close. The pre-fix rustdoc told a downstream to
  `shutdown()` and drain — which silently loses the reply on FC and QEMU. `MicroVm::dial_vsock` states
  the caveat once and links there (the fact lives in one place).
- **The live gate was red as shipped, and was not run before it was declared complete.** The reviewer
  ran it: `dial_vsock_echo` failed on Firecracker (4/4 tries) and flaked on QEMU. Reproduced here
  before touching anything. The matrix leg now asserts the **portable** contract — write, `read_exact`
  the reply, then half-close and require a prompt clean end — and is green on all four backends with
  `--retries 0` (a retry-masked flake is not a pass), five consecutive runs of the CH/FC/QEMU set.
- **The non-portable direction is not dropped, it is pinned where it holds**:
  `dial_vsock_host_half_close_forwards_on_cloud_hypervisor` and `…_on_crosvm` assert the
  half-close-then-drain idiom positively, so the rustdoc's per-backend claim is a gate rather than
  prose. Non-vacuous by construction: the identical assertion aimed at Firecracker fails
  (`left: []`), which is exactly why it is not a matrix leg.

**Capability honesty (§7.2) — decided: documentation + gates, NOT a `VmmCapabilities` field.** The
difference is real and now live-validated on all four backends, so a `vsock_half_close_forwards` flag
would be honest. It is deliberately not shipped: (a) no operation refuses on it — vmcell cannot detect
or typed-refuse a half-close at dial time, and §7.2's contract is about facilities the library either
provides or refuses with the field's own name; (b) the drain-first order works identically on all four,
so no caller is *forced* to branch — unlike `restore_rotates_host_paths`, where the two behaviors are
mutually exclusive and a test must pick one; (c) the field would be a breaking addition to the
exhaustive `VmmCapabilities`, touching all four backend crates + bench + validator, which §18 assigns
to delta 9's separable bump. **What would change the decision:** a caller that must branch
programmatically (a protocol that cannot self-delimit). The flag's name, values, and evidence are all
in the table above, ready to ship as its own delta.

**Design-text follow-up for v31:** §3.2's sentence "EOF propagates in both directions (half-close
forwards)" should be replaced by the table above. It is not errata against an implementation
deviation — the implementation matches the design; the design's premise was wrong.

### Deviations from the §18 sketch (behavior and gate bind; a shift is recorded, never silent)

- **The applet is hand-rolled on `libc`, not on the sync `vsock` crate the delta text names.** The
  crate already links `libc` for its `ifreq` ioctls, and `socket`/`bind`/`listen`/`accept4` are exactly
  what a wrapper would issue; adding a dep would also mutate a `Cargo.lock` three concurrent agents
  were writing. `libc::sockaddr_vm` is the ABI struct (defined once, by libc). Recorded here rather
  than left implicit, and cited at `vsock_listener`'s own rustdoc.
- **`libc::VMADDR_CID_ANY` is used directly.** The first cut defined a local
  `const VMADDR_CID_ANY = 0xFFFF_FFFF` whose comment claimed "not exported by `libc`" — false against
  the pinned libc 0.2.186 (`VMADDR_CID_ANY` at `linux_like/linux/mod.rs:3034`). Both the second
  spelling of the kernel ABI value and the false comment are gone.
- **The retry-cadence fix covers four sites, not the one the design records.** `connect_framed` had
  four no-sleep `continue`s (CONNECT write, non-decodable first frame, postcard error, non-`Ready`
  message), the last three being the accept-then-EOF shape a dead/half-open bridge produces. The loop
  body became `connect_framed_once` returning a typed `ConnectAttemptError`, so the cadence exists in
  one place. EXP-HOST-BACKOFF-RESET is preserved exactly: only the socket-connect arm grows the
  backoff, every other arm resets to the floor.
- **`VsockDial::connect_endpoint` is public, beyond the sketch** (mirroring `AgentClient::connect_endpoint`):
  it is what lets the KVM-free mock-bridge gates — which live in an integration test, i.e. an external
  crate — drive the dial without a VM, and it is the single place the port override is applied.
- **`dial_vsock` takes a required `Duration`**, not its neighbours' `Option<Duration>` (§9.3): a dial
  has no boot to outwait, so there is no defensible 10 s default to imply.
- **The prologue gained `MAX_PROLOGUE_LINE_BYTES` (256)** on the acknowledgement line, which the pre-v30
  code lacked (unbounded `String` growth from a peer). Validate-before-allocate per §13; an overlong
  unterminated line is a typed `Refused`.
- **`RootfsStage::STAGE_VERSION` was not bumped.** The cache key folds the `guest_tools` artifact by
  on-disk content, and the new applet changes that binary, so the manifest edit cannot produce a stale
  warm hit in this commit. Confirmed live: `vmcell build` re-baked the rootfs and the new `guest_tools`
  contains `echo-server` where the pre-change one did not.
- **The guest-tools multicall roster was collapsed into one `APPLETS` table** (`is_known` + the dispatch
  `match` were two lists). Not requested; a one-sided edit means a custom-`init=` boot exits 2 and
  panics the guest kernel.

### Empirically-false premises found in this pass (each now pinned by a gate)

1. *"EOF propagates in both directions."* False on FC/QEMU — the table above. Pinned by the matrix leg
   (portable order, all four) and the two `…_half_close_forwards_…` legs (the two backends where it
   holds), plus the rustdoc table they check.
2. *"`libc` does not export `VMADDR_CID_ANY`."* False against the pinned libc. Pinned by the constant
   simply being `libc`'s — a re-introduced local copy is a visible second spelling.
3. *"`read_to_end` returning at all IS the server's half-close: without the shutdown it would block
   until the connection dropped."* (A comment on the applet's own unit test.) False: `echo_connection`
   returning drops the only handle, so a full close delivers the same EOF. Measured — deleting
   `shutdown_write` left that unit test **and all four live backends green**. Fixed by adding
   `echo_connection_half_closes_while_the_connection_stays_open`, which holds the connection open with
   a second handle so half-closed and closed differ, and bounds the read with `set_read_timeout` so the
   inverse fails by name instead of hanging. Verified RED on the deletion (`WouldBlock` after 5 s).
4. *"The live matrix leg's EOF assertion goes red if the guest stops half-closing."* My own first
   comment; false for the same reason as (3), and additionally masked on FC/QEMU where the host's own
   teardown supplies the EOF. Corrected to what was actually measured: the assertion catches a guest
   that **never ends the connection** (applet's `Ok(0) => return` replaced by a sleep loop → RED on CH
   and crosvm, GREEN on FC and QEMU), and the comment now states that blind spot explicitly.

### Other review-fix items in this pass

- **The accept loops cannot busy-spin or flood the serial log.** A permanently bad listener fd — the
  §3.2 shape where a restore re-creates the vhost-vsock device and a *user* listener gets no re-bind —
  previously `continue`d with no pause and an unconditional `eprintln!` per iteration; that stdout is
  the serial console, which vmcell persists as a per-VM artifact. Both listeners now route through one
  `accept_error_pacing(consecutive) -> (Duration, bool)` law: the pause grows 50 ms → 1.6 s and caps,
  and only the first three failures plus every fiftieth are logged. Exiting is not an option (PID 1
  returning panics the guest kernel). Gate: `accept_error_pacing_bounds_both_the_retry_rate_and_the_log`,
  verified RED on the pre-fix `(ZERO, true)` shape.
- **`SOCK_CLOEXEC` from birth** on both the listener (`socket`) and each connection (`accept4`, not
  `accept`), so no `exec` in another thread can race an inheritable window.
- **Connect-loop diagnostics are capped, not frame-sized.** `ConnectAttemptError::Ready` eagerly
  `{:?}`-rendered a whole frame (bounded only by `MAX_FRAME_BYTES` = 16 MiB) on **every** failed
  boot-wait attempt. `capped_debug` writes into a sink that returns `Err` at the cap, so `core::fmt`
  **aborts** — the tail is never rendered, not merely never kept. [UPDATED 2026-08-14 — docs/78 §6
  `uncapped-frame-debug-renders`: the helper moved to `vmcell-protocol`, beside `MAX_FRAME_BYTES`, as
  one law for every site on the plane (`MAX_DEBUG_RENDER_BYTES = 256` + `DEBUG_TRUNCATED_MARKER` +
  `capped_debug`), shared by the guest agent and both host clients; the per-site
  `READY_DIAGNOSTIC_BYTES` const is gone. Because the *total* render length is unknowable without
  rendering it — the abort is the point — the marker states truncation and each desync site quotes
  the frame's true **wire** size beside the render, which is the more useful number and free while
  the encoded frame is still in hand. Gates:
  `capped_debug_truncates_over_cap_values_and_leaves_short_ones_verbatim` (which absorbed the former
  `ready_diagnostics_are_capped_not_frame_sized`, counting-`Debug` abort proof included) and
  `capped_debug_truncates_on_a_char_boundary`, plus one per site —
  `unexpected_exec_frame_is_logged_capped_not_frame_sized`,
  `unexpected_guest_frame_is_logged_capped_not_frame_sized`,
  `unexpected_frame_warning_is_capped_not_frame_sized`. The guest agent's `serve_loop` desync arm is
  not unit-reachable (a concrete `VsockStream` read half and a `VsockStream`-typed writer), so its
  line is built by `unexpected_frame_warning()` — the reachable seam the gate asserts on; only the
  arm's one-line call to it is unguarded.]
- **`prologue_non_ok_line_is_refused` now drives both refusal shapes its comment claimed.** Only `ERR`
  was exercised; `OKAY …` — the prefix trap that only the trailing space in `"OK "` rejects — is now
  driven too, so the narrower `starts_with("OK")` mutation goes red.
- **The KVM-free mock-bridge test was renamed** `dial_vsock_round_trips_bytes_and_eof_both_directions`
  → `…_round_trips_bytes_over_the_hybrid_bridge`, switched to the portable order, and carries an
  explicit "what this fake cannot see": a socketpair's half-close is real, so no mock can show the
  bridge teardown that FC and QEMU perform.
- **Rosters re-checked against the tree** (four applets in `APPLETS`, four symlinks in
  `rootfs_injection_manifest`): the guest-tools module doc and the `test-privileged` justfile comment
  said `ip/curl/kvm-ok`. The `test-crosvm` comment's "21/21" is now the measured **23/23**, with the
  note that `metrics_limits::crosvm` needs a systemd-delegated scope (it fails without one and passes
  with — mechanism identified, not filed as "environmental").

### Gates

`RUSTFLAGS="-D warnings" cargo clippy --locked -p vmcell -p vmcell-guest-tools --all-targets`, the five
reduced-feature `-p vmcell` configs, `RUSTDOCFLAGS="-D warnings" cargo doc -p vmcell --all-features`,
`cargo nextest run --locked -p vmcell -p vmcell-guest-tools` (406 passed), and live:
`cargo nextest run --profile integration -p vmcell --features firecracker,qemu --run-ignored all
-E 'kind(test) & test(dial)' --retries 0` → 8/8 (CH, FC, QEMU, the two mock-bridge legs, the CH
half-close leg, the custom-init guard-bypass leg), plus `just test-crosvm` → 23/23 under a delegated
scope. `dial_vsock_echo` was additionally run five consecutive times with `--retries 0` (15/15) to show
the QEMU flake is gone rather than masked.

## v30 delta 8 — VM-to-VM segments (design §18 delta 8 / §6.2, §6.5 — FR-V2 + FR-V3's privileged host→guest shape), as built

`NetConfig::Segment { segment: NetSegmentRef }` ships. A **segment** is one network namespace
(`<prefix>-seg-<segid>`) holding one Linux bridge (`<prefix>-br-<segid>`) on `10.201.<s>.0/24`, with
each member's tap (still `<prefix>-tap-<vmid>`, still `TUNSETPERSIST`'d, still opened only by the
VMM) created *inside that namespace* and enslaved to the bridge. A member has **no per-VM netns**:
`res.netns_name` names the segment, so `build_vmm_cmd`'s pre-exec `setns` needed no change and every
backend's device wiring took the existing tap arm unmodified. The guest still learns its address from
the kernel `ip=` token — zero netlink and zero new guest code in PID 1 (law C6 untouched).

Live-validated on this KVM host under the blessed runner, `--retries 0` (a retry-masked flake is not
a pass): **19/19** across cloud-hypervisor, Firecracker and QEMU (102 s), plus **5/5 on crosvm**
(41 s, `just test-crosvm`'s filter — the fourth backend's first segment validation; CI lacks the
binary, so that recipe stays opt-in). The battery covers the full §6.5 set — two-VM bidirectional
TCP, the off-segment negative against **both** members with the on-segment positive control re-run
afterwards *and* the dialer's own loopback positive control, host `dial_tcp` plus its dead-port
typed refusal, `netem` delay and `netem loss 100%` as separate legs, last-holder residue (namespace
**and** the cross-process segid lock file), the orphan-`seg` sweep, the duplicate-vmid ownership
refusal, and the `setup_tap_on_bridge` cleanup contract.

*(The 2026-08-11 first pass reported "16/16"; the battery was 17 tests then and is 19 now. Counts
are checked against the tree — that first figure was wrong, not the suite.)*

Whole-suite re-validation after the review pass, same host: `just test-privileged` **144/144** (279 s,
no retries consumed — no `TRY`/`FAIL` line in the run), `just test-unprivileged` **4/4**, KVM-free
`cargo nextest run --all-features` **691/691**, `clippy --workspace --all-targets --all-features`
with `-D warnings` clean, `fmt --check` clean. Skip manifest reviewed: 5 capability skips, all
Firecracker's honest absences (`nested_virt`, `unprivileged_vhost_user_net`, `virtio_fs_shares`)
plus QEMU's env-gated `usb_host_passthrough_no_designated_device` — none in the segment battery.
Host after: zero namespaces, zero `vmcell-*` links, no `.lock` files under `/tmp/vmcell-segid` (only
the never-removed `.coord` files, the same pattern `/tmp/vmcell-vmid` leaves) — and those coord
files now span 54 distinct segids where every run used to leave exactly `1.coord`, which is the
seeding fix visible on the host.

### Three premises §6.5/§18 assert as shipped facts that were empirically FALSE

**1. "Guest MACs stay `mac_math(vmid)`, so member MACs are bridge-unique" — false on two of four
backends, including the primary.** `mac_math` was applied only on the *vhost-user* arm.
`build_ch_net`'s tap arm emitted `mac: None` (the guest MAC came from CH's own undocumented
generation), and QEMU's tap arm emitted `-device virtio-net-pci,netdev=net0` with **no `mac=` at
all**, so every QEMU guest carried QEMU's fixed default `52:54:00:12:34:56`. Only Firecracker
(`guest_mac`) and crosvm (`tap-name=…,mac=…`) set it. This was invisible for as long as each
privileged VM owned an isolated `/30` L2 domain; two QEMU members on one bridge is a deterministic L2
collision, and the CH leg would have passed by luck. **Fixed in both backends before the live legs**
(two lines each), each with its own gate over the shape the process actually gets: CH's serialized
`ChNet` and QEMU's *composed* argv. Proven red by reverting each fix — and, decisively, by the live
inverse: with QEMU's `,mac=` dropped, `segment_two_vm_tcp_both_directions::qemu` is red on this host
while the identical code with the fix is green.

**2. "The privileged suite's liveness-blind test-start sweeper already removes every
`<prefix>-`-prefixed netns, segments included" (§6.5, verbatim) — false; nothing reaped a leaked
segment.** Evidence: `clean_vmcell_netns` passed `netns_sweep_prefix(prefix)` == `"vmcell-net-"`
into `cleanup_orphan_netns`, which filters on a literal `starts_with`, and
`"vmcell-seg-1".starts_with("vmcell-net-")` is false; `HostOrphanScanner::scan_netns` used the same
filter. A `vmcell-seg-*` namespace was therefore reaped by **nothing** — not the test-start
sweeper, not the daemon start-up sweep — so an aborted segment test would have poisoned the next
run's segid forever. The sentence is stale in the design and should be corrected there; both code
holes are closed here: the test helper now sweeps the segment class too (its own one-law filter),
and the sweeper grew the class properly (below).

**3. `net_uses_tap` does not exist, and no backend asks the question AGENTS.md says it asks.** All
four backends key tap-vs-NAT on `res.tap_name.is_some()`, never on `cfg.net`. That is *good* news —
a `Segment` variant that populates `res.tap_name`/`res.netns_name` already takes the identical tap arm
with zero backend edits — but it means the rubric's "the device wiring routes through the one
`net_uses_tap(cfg)` predicate" cannot be satisfied literally without giving `build_ch_net(res)` a
`cfg` parameter it does not need, i.e. moving the decision from the exhaustive-struct channel onto a
weaker signal. **Decided deliberately, recorded here:** `net_uses_tap(&NetConfig)` ships in `config`
as the **orchestrator/config-side** predicate (`Privileged | Segment`, exhaustive in-crate so a new
variant is a compile error there), and the backends keep the stronger `res.tap_name` channel. The two
are held in lockstep by a new fail-loud post-condition, `assert_tap_wiring_matches(net, tap_present)`,
run once in `setup_env`: a datapath that claims a tap and was handed none — or the reverse — is an
`Error::Network` at construction, not a guest with an unconfigurable `eth0`.

A fourth, smaller one: AGENTS.md/L1 lists "the registry's `destroy`/`shutdown_all`/`Drop`" — the
daemon `Registry` has **no** `Drop` impl. Not delta 8's to fix; recorded so it is not cited as an
existing teardown path.

### Deviations from the §18/§6.5 sketch (behavior and gate bind; a shift is recorded, never silent)

- **`build_kernel_cmdline(cfg, vmid, backend_extra)` → `(cfg, res, backend_extra)`.** §6.5 says "the
  cmdline builder reads it from the new `res.segment`", but the builder took no `res` at all. It now
  takes the whole `PerVmResources` (reading `res.vmid` and `res.segment`), which ripples to all four
  backend call sites — a breaking change, fine for the 0.12 → 0.13 pass, and itself a useful
  fail-loud: a backend cannot compile while ignoring membership.
- **`segment_ip_math(segid, slot)`, not `(seg_octet, slot)`.** Taking the segid keeps the
  `s = (segid % 254) + 1` derivation written **once** (the same shape `ip_math` uses) instead of
  making every caller compute the octet. `MAX_SEGMENT_ID` / `MAX_SEGMENT_SLOT` are public consts, so
  the 254-segments / 253-members-per-segment limits are named rather than inlined.
- **`NetSegment::dial_tcp` does not re-enter the root netns.** §6.5 cites the §6.4 proxy's
  capture-root → `setns` → socket → re-enter-root pattern. The proxy re-enters because its thread goes
  on to originate *upstream* sockets; `dial_tcp`'s dedicated thread exists only for this one connect
  and terminates immediately after handing the socket back, so there is no later socket that could be
  trapped. Re-entering would only add a failure mode (a good socket discarded because a dying thread
  could not move back). The connected socket keeps its segment binding — a socket's netns is fixed at
  `socket()` time — so `set_nonblocking(true)` + `tokio::net::TcpStream::from_std` on the caller's
  runtime is sound. It is a **dedicated `std::thread`**, never `spawn_blocking`: `setns` moves the
  calling thread, and a pooled worker would keep the segment namespace for every later blocking task.
- **The two `setns` calls live in `crate::net_sys`, not in `net::segment`.** `vmcell::net` is
  `#![forbid(unsafe_code)]`; `net_sys` exists for exactly this. `setns_net(fd)` joins
  `set_tun_persist` there, one operation per `unsafe` block with its own `SAFETY:`.
- **`NetSegment` implements `PartialEq`/`Eq` by `Arc::ptr_eq`.** Forced, not chosen: `NetConfig`
  derives `PartialEq, Eq`, and dropping those derives would be a `cargo semver-checks` break. The
  semantics are handle **identity** — two handles to one segment are equal; two distinct segments
  holding equal ids from independent allocators are not (the same discipline `Lineage`'s
  cross-allocator ancestry check uses for S5). Pinned by
  `distinct_segments_with_equal_ids_are_not_equal`.
- **`setup_tap_on_bridge` owns its own failure cleanup** (review pass, R1). The trait states it: on
  error it leaves behind exactly what it found — it deletes the tap it created, and deletes nothing
  when the create itself failed. The caller cannot make that call, because the namespace is shared
  and an interface of that name may be a live sibling's.
- **`SegmentInner::slots` is a `BTreeMap<slot, vmid>`, not a `BTreeSet<slot>`** (review pass, R1):
  the occupant's vmid is what lets `claim_member` refuse a duplicate before touching host state.
  `active_slots()` keeps its `BTreeSet<u32>` signature (it returns the keys).
- **The `Netlink` trait grew three methods, not two.** `create_bridge` and `setup_tap_on_bridge` were
  foreseen; `delete_link(netns, link)` was not. It is load-bearing: a member's tap is persistent in a
  namespace that **outlives the member**, so without deleting it on teardown a reused vmid collides
  with a leftover tap. `setup_tap_on_bridge` deliberately assigns **no** address (the sketch's
  "distinct trait method is mandatory, not cosmetic" — reusing `setup_tap` would have put a stray
  `10.200.<n>.1/30` on a bridge port, a silent second subnet on the segment). Four impls updated
  (`RtNetlink`, the `net::tap` fake, the broker's fake, and the segment module's recording fake) plus
  the orchestrator's three test fakes; all in-workspace, all compile-time fail-loud.
- **`sweep_orphans` grew `live_segids` and `OrphanScanner` grew `scan_segment_netns`; `trailing_vmid`
  was renamed `trailing_id`.** The rename is the point: the helper parses `vmcell-seg-7` as `7` just
  as happily as `vmcell-net-7`, so an id-space-neutral name is what stops a future reader from
  checking one class against the other's live set. `SweepReport` gained `segment_netns` (it is
  `#[non_exhaustive]`, so that half is additive). The signature change ripples to the broker's
  `BrokerRequest::Sweep` / `BrokerReply::SweepDone` (postcard-safe — plain `Vec<u32>`/`Vec<String>`
  with no presence attributes, so the Appendix A reversal-10 trap does not apply; parent and broker
  child still ship together) and to the daemon's `startup_sweep`, which passes **both** sets empty.
- **`SegmentMember` is public.** The sketch names only `NetSegment`. The RAII guard that owns a
  member's slot + tap is held by `MicroVm` and by `EnvSetup`, and `MicroVm::segment()` /
  `segment_membership()` are the accessors the netem legs need (`MicroVm::netns()` is `None` on this
  path — worth knowing before reaching for it).
- **`NetSegment` exposes `prefix()`, `segid()`, `netns_name()` and `active_slots()`** beyond the
  sketch's four methods: `prefix()` is what `build()`'s prefix-equality refusal compares against, and
  the other three are what the live residue/impairment legs assert on.

### As-built shape, in one place

- **Ownership.** `NetSegment(Arc<SegmentInner>)`; `SegmentInner::Drop` deletes the namespace, and its
  `segid_guard` field is declared last so the id is released *after* the namespace is gone. Every
  member `MicroVm` holds a clone, so "never delete a netns under a live VMM" is **structural**: a
  member's teardown necessarily precedes the segment's.
- **Teardown (law L1).** The segment member is released through the **one** ordered helper —
  `release_net_before_netns` grew a `segment` parameter and drops it after the netns take, so the
  success path (`teardown_post_instance`), the mid-`start()` error path (`EnvSetup::drop`), and
  `Drop` cannot diverge. A member releases its **slot and tap only**; it never touches the namespace.
  The segment path leaves `netns == None`, so the ordering gate learned a new recorded event
  (`segment_slot_release:<tap>`) rather than reusing `netns_delete`.
- **Ids.** Two laws, each written once and shared by both allocators: the H1 **claim** core
  (`flock` coordination file + liveness check + `hard_link` atomic claim) and the **search order**
  (`seeded_id_order`, clock-seeded so two processes do not both start at 1 — added by the review
  pass, R3). The claim core was extracted verbatim into a private, id-space-agnostic `FsIdClaim`
  parameterized by lock directory. `VmidAllocator` and the new `SegmentIdAllocator`
  (`/tmp/vmcell-segid`, the same recorded bare-`/tmp` cross-process-rendezvous exception) both route
  through it, and the exactly-one-winner race gate now drives the shared core, so it covers both.
  `env.segids` is an additive `HostEnv` field.
- **Refusals, typed, at `build()`.** `snapshotting` + `Segment`; and a member whose `resource_prefix`
  differs from its segment's (one prefix must name and sweep every resource in the domain, law F2).
  `Egress`/`host_services_port` are unrepresentable on the variant. Two further boundaries:
  `restore_inner` refuses a segment member with `Error::Unsupported` (the resources-in-hand re-check),
  and `zygote::check_clone_eligible` refuses it at the config-only gate so a fan-out fails before
  minting N copies rather than after.

### The adversarial-review pass: five verified defects, each fixed with its gate

Three reviewers took independent lenses (correctness / teardown-residue / gate-honesty) against the
landed delta and verified their findings live. All five are fixed here, and every fix's gate was
re-run with the bug **re-injected** and observed red.

**R1 (L1 ownership, the severe one) — a failed `claim_member` deleted a LIVE SIBLING member's
tap.** The cleanup on the enslave-failure path deleted the tap **by name**, and unlike every other
cleanup-on-failure in the tree it ran inside a namespace that **pre-exists and is shared**: a
member's tap is not provably its own. `claim_member` accepted any vmid without checking the segment
already held one, and the tap name is `<prefix>-tap-<vmid>`, so two members with equal vmids name
**one** interface in **one** namespace. Reproduced live: B's tap create fails `EBUSY` (correctly
fail-loud, because A's VMM holds that interface open) and the cleanup then deleted A's running tap,
severing A's datapath with nothing logged — the `tracing::debug!` fired only when the cleanup
*failed*. The rationale comment ("delete whatever half of the tap came up") was false on that arm:
on `EBUSY` no half came up.

Fixed on both axes the reviewer offered, because either alone leaves a sharp edge:

1. **Fail loud on the accepted input, before any host state.** `SegmentInner::slots` is now
   `BTreeMap<slot, vmid>`, and `claim_member` refuses a vmid the segment already holds with a typed
   `Error::Config` naming the conflict — no netlink call at all. (`active_slots()` keeps its
   `BTreeSet<u32>` signature; it returns the keys.)
2. **Cleanup belongs to the creator.** `claim_member` no longer deletes anything; the half-created
   tap is reclaimed inside `Netlink::setup_tap_on_bridge`, the only party that knows whether it
   created one, and the trait now states that contract: on error it leaves behind exactly what it
   found — it removes the tap it created, and removes **nothing** when the create itself failed.
   The caller cannot make that distinction in a shared namespace.

The old recording fake could not see any of this (it never touched the kernel, so a pre-existing tap
was unrepresentable and the gate could only assert that `delete_link` *was called*). It now carries
a **live-link set** per namespace and models the two kernel behaviors that matter — a create whose
name is taken fails, a delete of an absent link fails — which is what makes the axis testable
KVM-free at all.

**R2 (gate honesty) — the off-segment negative control was vacuous on the dialer axis.** An
off-segment `Privileged` VM holds only its `/30` tap (no veth, no uplink), so it can reach *nothing*
by construction: "the probe reached nothing" and "isolation held" were the same observation. Proven
by the reviewer with a probe mutated to `sh -c "exit 1"` — a dialer that never opens a socket — which
left the leg green. The rubric wants a positive control **the same dialer** passes, so the outsider
now runs `echo-server --tcp` itself and must echo through `127.0.0.1:<port>` via the identical
`echo_probe_until_ok` before its refusals count. Re-verified both ways on this host.

**R3 (cross-process hazard) — segment ids were deterministic per process.** `SegmentIdAllocator::allocate`
scanned `1..=MAX` with no seed, while its sibling `VmidAllocator` carries an injected clock
explicitly to spread the first-tried id; every process therefore chose segid 1, named its namespace
`vmcell-seg-1`, and another run's liveness-blind start-up sweep reaped it (reproduced, including the
resulting mid-test `netns get failed: Can not open netns /var/run/netns/vmcell-seg-1` — the real
mechanism behind the one flake seen under retries; **not** "environmental"). Both offered fixes
taken:

- The search-order seeding is now **one law** — `seeded_id_order(clock, max)` — used by both
  allocators; `SegmentIdAllocator` grew the same injected-`Clock` seam (and a manual `Debug`, since
  `Clock` is not `Debug`). Three existing unit tests silently depended on "allocators are
  deterministic"; each now asks for a fixed `FakeClock` explicitly, which is the honest form.
- The **live battery** now builds its `HostEnv` with `SegmentIdAllocator::shared()`, so the
  `/tmp/vmcell-segid` claim law this delta extracted actually arbitrates on a real host (it was
  exercised only against unit-test temp dirs), and the residue leg asserts that lock file's whole
  lifecycle — present while the segment lives, gone when the last holder drops.

Residual, recorded and deliberately out of scope: `clean_vmcell_netns` is still liveness-blind by
design for **both** id classes (it reaped a live `vmcell-net-207` too). That is the pre-existing
posture for vmids, and the fixes above restore segments to parity with it rather than fixing a
hazard the suite has always carried; concurrent `test-privileged` runs remain unsupported.

**R4 (gate gap) — Firecracker had no KVM-free MAC gate.** Replacing `mac_math(res.vmid)` with a
constant MAC left the whole KVM-free suite green; the other three backends each pin theirs through a
composed-argv/serialized-config test, but FC built its `NetworkInterface` inline inside `spawn_fc`,
so nothing pure was testable and only the live matrix caught it (73 s in). Since "member MACs are
bridge-unique" is this delta's load-bearing premise, the request is now a pure
`build_fc_network_interface(tap, vmid)` with its own gate over the identity, the per-vmid
distinctness, the serialized body FC actually receives, and the out-of-range refusal.

**R5 (records)** — the fake-blind-axis pointer in `orchestrator.rs` named a test that does not
exist (`segment_teardown_leaves_no_residue`); it now names the real
`segment_last_holder_teardown_leaves_no_residue` plus the new ownership leg. The "16/16" count is
corrected above. crosvm's segment legs are recorded above. The fourth false premise is recorded
with its evidence above.

**R6 (found while gating R1) — every live residue check was blind to a DOWN interface.**
The presence helper read `tc qdisc show`, which lists only interfaces that are **UP** — and a leaked
tap is typically down (nothing brought it up, or its VMM is gone). Verified on this host: a tap left
behind by a failed enslave is absent from `tc qdisc show` and plainly present in `ip -o link show`.
So the `!present` half of the residue leg — the half that exists to catch exactly that residue —
passed vacuously, and the new cleanup-contract leg passed even with the cleanup disabled. All
presence assertions now go through one `links_in_segment` + `link_listed` helper over `ip -o link
show`, matching the whole name **token** (the prefix-confusion property the old helper had, plus a
new one: a name appearing only as another link's `master` is not a link of that name). `tc` remains
for what it is good at — adding and removing the `netem` qdiscs.

### Gates

| What it pins | Gate | Proven red by |
| --- | --- | --- |
| The tap-arm MAC is `mac_math(vmid)` on **CH** (was `None`) | `vmcell vmm::cloud_hypervisor::tests::build_ch_net_shapes_tap_and_vhost_user_branches` | restoring `mac: None` → **RED** |
| …and on **QEMU** (was absent entirely), over the *composed* argv | `vmcell-qemu tests::qemu_tap_argv_carries_the_vmid_derived_mac` | dropping the `,mac=` splice → **RED** |
| …and that it matters: two QEMU members on one bridge | live `vmcell::segment segment_two_vm_tcp_both_directions::qemu` | dropping the same splice → **RED on this host** |
| The `-seg-` class is swept against **segids**, not vmids (fails *open* if miswired) | `vmcell orchestrator::tests::test_sweep_orphans_reclaims_only_dead_ids_in_order` (plants `vmcell-seg-7` with vmid 7 live + `vmcell-seg-9` with segid 9 live) | checking the class against `live_vmids` → **RED** (`left: ["vmcell-seg-9"]`) |
| …end to end over the broker's postcard wire | `vmcell-broker tests::dispatch_sweep_reaps_segments_against_live_segids` + the `Sweep`/`SweepDone` round-trip | swapping the two live sets |
| A member's `ip=` is the segment `/24` with the bridge gateway, and F3 still holds on that path | `vmcell config::tests::build_kernel_cmdline_emits_the_segment_subnet_for_a_member` | falling back to the `/30` branch → **RED** |
| A member releases its tap + slot and **never** the namespace | `vmcell net::segment::tests::member_teardown_releases_its_tap_and_slot_but_never_the_namespace` | adding a `delete_netns` to `SegmentMember::Drop` → **RED** |
| …in the L1 order: instance → slot release → cgroup | `vmcell orchestrator::tests::segment_member_teardown_releases_its_slot_between_instance_and_cgroup` | the same edit → **RED**; reordering the helper |
| The namespace dies with the **last** handle, and frees the segid | `vmcell net::segment::tests::namespace_dies_with_the_last_handle_and_frees_the_segid` | deleting on every clone's drop |
| `segment_ip_math` range, injectivity, disjointness from `ip_math` | `vmcell net::tests::segment_ip_math_range_injectivity_and_disjointness` | reusing `10.200`; allowing slot 0 (aliases the gateway) or 254 |
| The `-seg-` naming joins the F2 lockstep, pairwise-distinct from `-net-`/`-vm-` | `vmcell naming::tests::prefix_matches_its_names`, `default_prefix_reproduces_the_historical_names` | a `-net-`-stemmed segment name |
| Slot claim / free / exhaustion at 253, and the address each slot maps to | `vmcell net::segment::tests::slots_are_claimed_freed_and_exhaust_at_the_documented_limit` | a free-list that never returns a released slot |
| Both allocators claim through the one extracted core, in their own dirs; exactly-one-winner under 8×200 concurrent reclaimers | `vmcell orchestrator::tests::both_allocators_claim_through_the_one_cross_process_core`, `segment_id_allocator_exhausts_typed_at_the_limit`, `shared_at_concurrent_reclaimers_have_exactly_one_winner` (now over `FsIdClaim`) | an in-process-only segid allocator |
| The prefix goes through the **one** validator | `vmcell net::segment::tests::segment_rejects_an_invalid_prefix_through_the_one_validator` | skipping `validate_resource_prefix` |
| A failed bridge creation does not leak the namespace | `vmcell net::segment::tests::failed_bridge_creation_cleans_up_the_namespace` | returning the error without the cleanup |
| A failed member enslave leaks neither the half-created tap nor the slot (asserted on the resulting STATE — no tap in the namespace — not on who called what) | `vmcell net::segment::tests::failed_member_enslave_releases_the_slot_and_the_tap` | dropping the creator-side cleanup → **RED** |
| **R1** — a duplicate vmid is refused *before* any netlink call, and the live sibling's tap and slot survive; a different vmid still joins (positive control) | `vmcell net::segment::tests::a_duplicate_vmid_is_refused_and_the_live_siblings_tap_survives` (over the now-stateful `RecordingNetlink`) | restoring the shipped code (accept the duplicate + delete by name) → **RED**, on the typed refusal *and*, with that assertion relaxed, on "the live sibling's tap must survive" |
| **R1, live** — the same, against a real running VMM: the refusal is typed, member A's tap is still there, and A's datapath still echoes through `dial_tcp` | live `vmcell::segment segment_duplicate_vmid_is_refused_without_touching_the_live_member` (CH; the mechanism is host-side) | the same re-injection → **RED**: `got Network("tap create fail: Device or resource busy")`, and with that relaxed, `the refused claim must not delete the live member's tap vmcell-tap-77` — with cloud-hypervisor logging `failed reading from tap: File descriptor in bad state` / `NEEDS_RESET` as its datapath was pulled out from under it |
| **R1** — `setup_tap_on_bridge` reclaims the tap **it** created when the enslave fails, and leaves an existing one alone (positive control: the same call against the real bridge keeps the tap) | live `vmcell::segment segment_setup_tap_on_bridge_reclaims_the_tap_it_created_when_enslaving_fails` (no VM at all) | disabling the internal cleanup → **RED** |
| The residue helper matches whole interface names (`vmcell-tap-1` ≠ `vmcell-tap-11`), over `ip -o link show` so a **DOWN** leaked tap is visible at all, and a `master <bridge>` mention is not a link | `vmcell::segment link_listed_matches_whole_interface_names_only` (KVM-free) | reverting it to a bare `contains` → **RED** |
| **R3** — the segid search start is clock-seeded through the ONE `seeded_id_order` law the vmid search uses, and the seeded order is still a permutation of the whole space | `vmcell orchestrator::tests::segment_id_search_start_is_clock_seeded_like_the_vmid_search` | restoring the unseeded `1..=MAX` scan → **RED** (`left: 1, right: 1`) |
| **R3, live** — the shared `/tmp/vmcell-segid` claim arbitrates on a real host: the lock file exists while the segment lives and is gone after the last holder drops | live `vmcell::segment segment_last_holder_teardown_leaves_no_residue::{…}` | reverting the battery to the hermetic allocator → **RED** (`a shared segid claim must leave its cross-process lock file: /tmp/vmcell-segid/8.lock`) |
| **R4** — FC's network-interface request carries `mac_math(vmid)`, distinct per vmid, in the JSON FC is actually PUT, and refuses an out-of-range vmid | `vmcell-firecracker tests::fc_network_interface_carries_the_vmid_derived_mac` (the pure builder extracted for it) | a constant `52:54:00:12:34:56` → **RED** (this is the mutation that previously left the ENTIRE KVM-free suite green) |
| `net_uses_tap` covers exactly the tap datapaths, and config↔resources stay in lockstep | `vmcell config::tests::net_uses_tap_covers_exactly_the_tap_datapaths`, `assert_tap_wiring_matches_rejects_both_mismatches` | a `Segment` arm answering `false` |
| Both `build()` refusals, each with a positive control | `vmcell config::tests::build_rejects_snapshotting_with_a_segment`, `build_rejects_a_member_whose_prefix_differs_from_its_segment` | disabling either arm |
| A `Zygote` over a segment config fails at the config-only gate | `vmcell zygote::tests::segment_config_rejected_at_zygote_construction` | dropping the `Segment` arm from `check_clone_eligible` |
| **Live** — two members exchange bytes both ways; a third off-segment VM reaches neither — after **that same dialer** echoes off its own loopback (**R2**: without it the leg passed with a dialer that never opened a socket), with the on-segment control re-run afterwards | `vmcell::segment segment_two_vm_tcp_both_directions::{cloud_hypervisor,firecracker,qemu,crosvm}` | the QEMU MAC inverse above; and the dead-dialer mutation (`sh -c "exit 1"` for the outsider's payloads) → **RED**: `the in-guest echo probe to 127.0.0.1:7100 never succeeded` |
| **Live** — host `dial_tcp` echoes through a member, and a dead port is a bounded typed error | `vmcell::segment segment_host_dial_tcp_reaches_a_member::{…}` | — |
| **Live** — `netem delay 50ms` on both member taps measurably shifts the guest↔guest round trip | `vmcell::segment segment_netem_delay_shifts_the_round_trip::{…}` | — |
| **Live** — `netem loss 100%` partitions the link, and it heals when the qdisc goes (its own leg: a bridge that silently healed would pass a delay-only gate) | `vmcell::segment segment_netem_loss_partitions_and_heals::{…}` | — |
| **Live** — the namespace exists before the last holder drops and is gone after; a departing member's tap goes while its sibling's survives | `vmcell::segment segment_last_holder_teardown_leaves_no_residue::{…}` | — |
| **Live** — a planted `vmcell-seg-*` is reclaimed and a foreign-prefix segment is left alone | `vmcell::segment segment_orphan_sweep_reclaims_leaked_namespaces` | — |

### One defect the full suite found in this battery (in the test, not the product)

The residue leg first ran green under an isolated `-E test(segment)` invocation and then went red once
inside `just test-privileged`. The cause is a mechanism, not "environmental": the leg asserted tap
presence with a bare `contains(&tap_name)`, and `tc qdisc show` prints `dev vmcell-tap-11 root …`.
When the clock-seeded vmid allocator handed the two members **1** and **11** — an ordinary pair, and
exactly the one the isolated run had not drawn — `"…dev vmcell-tap-11 …".contains("vmcell-tap-1")` is
`true`, so the departed member's tap was reported as still present. The mirror assertion is worse: it
would have passed **vacuously** in the other ordering. Recorded because it is the recurring shape — a
residue assertion satisfied by a *different* resource's name — not because the fix is interesting.

The first fix (one `tap_listed(out, tap)` helper matching the `dev <tap> ` token) was itself
insufficient, which the review pass then caught: `tc qdisc show` lists only interfaces that are
**UP**, and a leaked tap is typically DOWN. Presence now goes through `links_in_segment` +
`link_listed` over `ip -o link show` — same token discipline, on a view that can actually see
residue (see R6 above).

**What the fakes cannot see, and what covers it.** `FakeNetlink`/the segment module's
`RecordingNetlink` never touch the kernel: the real bridge creation, the tap enslavement, the
*absence* of an address on a bridge port, the namespace removal under a live VMM, the `netem`
qdiscs, and `/var/run/netns` residue are all invisible to them. Every one of those is covered by a
named live leg in `crates/vmcell/tests/segment.rs`; §18 marks that battery non-optional, and it was
run. The review pass moved one axis from that list into the fake: `RecordingNetlink` is no longer a
pure call recorder but keeps a **live-link set** per namespace, because "the cleanup deleted a link
it did not create" is unrepresentable when no link can pre-exist — a call recorder can only assert
that `delete_link` *was called*, which is precisely what made the shipped L1 defect invisible. It
still models nothing about addressing, carrier, or enslavement; those stay live-only.

**The in-guest data plane needs no new guest code.** The listener is delta 7's `echo-server --tcp`
applet; the client is bash's `/dev/tcp` net-redirection, which the Debian rootfs's bash has compiled
in (verified in-guest before the battery was written). Law C6 is untouched, and no rootfs rebuild was
required.

### Residual, deliberately recorded

- **Segments are not exposed over the daemon REST** (§17). The daemon's own `NetMode` enum maps
  exhaustively to `NetConfig`, so the new variant needed no DTO change; when segments *are* exposed,
  the presence-attribute round-trip rule bites there.
- **`tc netem` is names, not a typed API.** rtnetlink 0.21 / netlink-packet-route 0.30 type only
  fq_codel and ingress, and `QDiscNewRequest` has no generic kind/options seam (its `TcMessage` is
  private with no `message_mut()`), so a typed `SegmentImpairment` means hand-assembled messages —
  §17 forward work. Tests shell out through `nsenter`; production code does not.
- **Per-segment filtered egress** is unrepresentable by design in v30 (§17).
- **`clean_vmcell_netns` stays liveness-blind, for both id classes.** The review pass fixed segment
  ids being *deterministic*; it did not make the test-start sweeper liveness-aware. Two concurrent
  privileged runs still reap each other's namespaces — the pre-existing posture for `-net-`
  (a live `vmcell-net-207` was observed reaped), now shared symmetrically by `-seg-`. The suite is
  `serial-host` within a run; concurrent runs remain unsupported. The `/tmp/vmcell-segid` lock files
  would make a liveness-aware sweep possible and are the obvious future fix.
- **Version ledger.** `PerVmResources` gains `segment` (`constructible_struct_adds_field`),
  `NetConfig` gains a variant, `build_kernel_cmdline` and `sweep_orphans` change signature, `Netlink`
  gains three methods, `HostEnv` gains `segids` (additive, `#[non_exhaustive]`). The review pass adds
  no public surface: `SegmentIdAllocator`'s new clock is a private field (its derived `Debug` became
  a manual one, since `Clock` is not `Debug`), `claim_member` is `pub(crate)`, and FC's
  `build_fc_network_interface` is private. All belong to the pass's single 0.12 → 0.13 bump; this
  change deliberately did not touch the version or the ledger comment.

## v30 delta 9 — host-USB passthrough (design §18 delta 9 / §2.4 — FR-V5), as built + the review-fix pass

The ninth `VmmCapabilities` field (`usb_host_passthrough`: QEMU `true`, CH / Firecracker / crosvm
`false`, feature string == field name), `VmConfig::usb_host_devices: Vec<UsbHostDevice>` with both
`build()` rejections, one shared refusal predicate (`vmcell::vmm::reject_usb_host_devices`) wired
into all four `create()` paths, QEMU's `qemu-xhci` + `usb-host` argv, the committed `usbhost` kernel
label its live leg boots, and the opt-in `just test-usb-passthrough` recipe.

The adversarial review of the first landing found five defects; what follows is the as-shipped state
after that fix pass, not a history. Three of them were structural and are the reason this section is
long: the argv splice had **no gate at all**, the live leg's guest kernel **did not exist**, and the
`true` was **presumed rather than measured**.

### As built

- **`vmcell` core.** `UsbHostDevice { vendor_id, product_id }` (`#[non_exhaustive]`, `Copy`),
  `VmConfig::usb_host_devices` + `VmConfigBuilder::with_usb_host_device`, `build()` rejecting
  `snapshotting`+USB (a passed-through device is not in the migration stream) and zero/duplicate ids,
  and `vmm::reject_usb_host_devices(vmm, caps, devices)` — the one refusal law, beside
  `reject_unsupported_console`. `restore()` is deliberately **not** wired: `build()` rejects
  `snapshotting`+USB and every backend's `restore()` rejects a non-snapshotting config, so USB cannot
  reach it. **[CORRECTED 2026-08-13 — the docs/78 review (M4): the second half of that rationale is
  empirically false.** No backend's `restore()` reads `cfg.snapshotting`; QEMU's only restore gate is
  `uses_in_kernel_vsock`, which a `{VsockTransport::InKernel, snapshotting: false}` config passes —
  so a non-snapshotting USB config reaches `Qemu::restore()` and is spawned with the USB argv but
  without the `require_usb_host_devices` precheck, while CH/FC/crosvm restores silently drop the
  accepted devices. The fix (docs/78 M4) is a `usb_host_devices` rejection at the `restore_inner`
  boundary; until it lands, this entry must not be cited as settling the restore question.]
- **QEMU argv, two layers.** `build_qemu_usb_args` (pure, per-fragment: one
  `-device qemu-xhci,id=vmcell-xhci` regardless of device count, one
  `-device usb-host,vendorid=0x%04x,productid=0x%04x` per device, empty-in/empty-out) **and**
  `build_qemu_command` — a new I/O-free composer holding the **whole** QEMU argv, which
  `Qemu::spawn_qemu` now calls. `spawn_qemu` keeps the I/O (stale-socket cleanup, the
  `vhost-device-vsock`/`virtiofsd` starts, and the smoltcp vhost-user-net readiness wait, hoisted out
  of the `-chardev` branch it gates); `finish_qemu_spawn` keeps the launch tail (spawn → cgroup
  register → QMP readiness → `SpawnedQemu`). Two small carriers make the split honest:
  `QemuSpawnPaths` (the per-VM socket/log paths; virtio-fs daemons enter as *socket paths*, never as
  live `Child` handles) and `SpawnedDaemons` (the helper daemons `finish_qemu_spawn` must reap).
  A `fs_daemon_sockets`/`shares` length mismatch is a typed error rather than a `zip` truncation.
- **A fail-loud host-device precheck.** `Qemu::create()` now calls `require_usb_host_devices`, which
  resolves every requested `(vendor_id, product_id)` through `/sys/bus/usb/devices` to its
  `/dev/bus/usb/BBB/DDD` node and proves that node opens **read-write**. Absent, ambiguous (two host
  devices carrying the ids — every host's root hubs do) and unopenable are three named errors. Both
  roots are parameters, so the resolution is unit-testable against a fixture tree.
- **The `usbhost` guest kernel.** Committed `pins.json` gained `kernels.usbhost` (the 6.12.94 source,
  `fragments: ["USBHOST"]`) and `kernel_fragments.USBHOST` — `CONFIG_USB_SUPPORT/USB/USB_PCI/
  USB_XHCI_HCD/USB_XHCI_PCI/USB_ANNOUNCE_NEW_DEVICES` plus `HID`/`HID_GENERIC`/`USB_HID` as the one
  class-smoke driver, and nothing else. It is built by the delta-3 toolkit path
  (`vmcell build-kernels`, or `build_labelled_kernel("usbhost", …)`) to `vmlinux-usbhost`, which is
  what the recipe tells the operator to point `VMCELL_KERNEL` at. Per G1 this is vmcell's **own**
  capability-gate infrastructure (the IKCONFIG example-fragment shape) and carries **none** of the
  consumer usbip/`vhci_hcd`/gadget/`dummy_hcd` closure FR-V5 withdrew — asserted, not just intended.
- **Tests.** `crates/vmcell/tests/usb_passthrough.rs` (four-backend honesty pin; the KVM-free
  `create()` refusal battery with the QEMU positive control; the pins/label gate; the absent-device
  refusal; the `#[ignore]`d live leg) plus the in-crate QEMU gates listed below.

### Deviations from the §18 sketch (behavior and gate bind; a shift is recorded, never silent)

- **The sketch's "pure extracted args helper" was necessary but not sufficient, so the extraction
  went one level up.** §18 asks for the fragment helper (the `build_crosvm_run_args` precedent). That
  precedent works only because crosvm's helper **is** the whole argv; QEMU's fragment helper leaves a
  `cmd.args(...)` seam, and that seam is where the defect lived (see the false premise below). The
  full-argv `build_qemu_command` is the shipped shape; the fragment helper stays as the token-level
  golden.
- **A host-device precheck the design does not name.** §2.4 expects QEMU's own open error to surface;
  it does not exist (below). The precheck is the honor-or-reject rule applied to an accepted input.
- **The live leg is a plain QEMU-only `#[ignore]`d test, not a `vmm_matrix_test!`.**
  `require_cap!` **panics** ("SKIP == PASS ERROR") when the *primary* backend lacks the capability,
  and cloud-hypervisor is honest-`false` here — `usb_host_passthrough` is the first flag whose
  primary-backend stance is `false`, so a matrix leg would hard-fail `usb_passthrough::
  cloud_hypervisor` on every KVM host. **This is a recorded deviation from AGENTS.md's "skips go
  through `require_cap!` only".**
- **…and from it, an env-gated recorded skip.** `test-privileged` selects
  `kind(test) & !(test(unprivileged) | test(smoltcp))` with `--run-ignored all`, so the live leg is
  compiled and selected there. With `VMCELL_TEST_USB_DEVICE` unset it records
  `SKIP qemu usb_host_passthrough_no_designated_device` through the same `record_capability_skip`
  recorder `require_cap!` uses (so it lands in `$VMCELL_SKIP_MANIFEST` for the mandatory review); a
  **set but malformed** value is a hard panic naming the variable. The airtight alternative — adding
  `| test(usb_passthrough)` to `test-privileged`'s filter — is left to the orchestrator, since the
  recipe text is quoted verbatim from the gates doc.
- **A zero-id rejection the design does not name.** QEMU's `usb-host` treats a `0` `vendorid`/
  `productid` as *unset* (match-any), so `vendorid=0x0000` would attach an **arbitrary** host device.
  Rejected at construction, documented at both the type and the check.
- **Argv slot: the LATE edge of §2.4's window.** The design says "after the extra-disk block, before
  `-kernel`"; the virtio-fs and net blocks sit inside that window. USB goes immediately before
  `-kernel` so the PCI enumeration order of every pre-existing device is untouched (`/dev/vd*` and
  the NIC cannot shift). Migration congruence does not constrain the slot — `build()` rejects
  `snapshotting`+USB.
- **Naming.** The pins fragment is `USBHOST` (the registry's uppercase convention, beside
  `KASAN`/`KCOV`/`LOCKDEP`/`SLUB_DEBUG`); the `kernels` label is `usbhost`, which is what produces the
  design's `vmlinux-usbhost`.
- **`vmcell build-kernels` now builds a third kernel.** The `usbhost` label lives in the committed
  registry, so the roster command that builds "every kernel in the registry" includes it. That is the
  price of "the label alone determines the build" (§5.5) and of the gate being runnable at all.
- **Cross-delta touch (flagged for merge).** `crates/vmcell/tests/kernel_toolkit.rs` (delta 3) pinned
  the committed roster as exactly `["6.12.94", "6.6.143"]` and asserted *every* committed entry
  declares no fragments. Both are stale the moment delta 9's entry lands; they were updated minimally
  — the roster gained `"usbhost"`, and the no-`fragments`-key promise is now asserted over the two
  entries that carry no `fragments` key, which keeps the migration promise it was written for.
- **`UsbHostDevice` is now root-re-exported** (`vmcell::UsbHostDevice`), together with `RootfsSource`
  and `Egress`, in the docs/78 §9.4 `crate-root-reexport-roster-inconsistent` fix: the root set has
  to be *callable*, and those three are the types a consumer cannot avoid naming to reach the
  re-exported builder. Additive (minor-compatible), ledgered in `crates/vmcell/Cargo.toml`'s comment
  changelog, and gated by `lib.rs`'s `root_reexport_tests`, which builds a full `VmConfig` importing
  only from the crate root — a dropped re-export is a compile error.

### Empirically-false premises found in this pass (each now pinned by a gate)

- **"A pure fragment helper makes the QEMU device argv goldenable" (§18 delta 9) is false as a
  *gate*.** Evidence: replacing `cmd.args(build_qemu_usb_args(&cfg.usb_host_devices))` with
  `let _unused = build_qemu_usb_args(&cfg.usb_host_devices);` left `cargo test -p vmcell-qemu`
  (17 passed, including the token golden **and** the capability-vs-argv test) and
  `-p vmcell --test usb_passthrough` fully green: QEMU advertised host-USB passthrough while emitting
  **no USB argv at all**. Nothing in the suite could distinguish "advertises and attaches" from
  "advertises and silently drops", because QEMU's argv was observable only by spawning. **Fix:**
  `build_qemu_command` composes the entire argv without I/O, and the gates assert over
  `cmd.as_std().get_args()`. Re-injecting the same deletion after the fix reddens
  `qemu_full_argv_splices_the_usb_fragment` *and* `qemu_usb_capability_matches_the_emitted_argv`
  (observed, then reverted).
- **"An absent/unopenable host device surfaces QEMU's own fail-loud open error" (§2.4) is false.**
  Measured on QEMU 10.2.1 (Debian 1:10.2.1+ds-1ubuntu3.2), 2026-08-11: launching
  `qemu-system-x86_64 -M q35 -m 128 -nodefaults -display none -S -sandbox on,obsolete=deny,
  elevateprivileges=deny,spawn=deny,resourcecontrol=deny -device qemu-xhci,id=vmcell-xhci -device
  usb-host,vendorid=0xdead,productid=0xbeef -qmp stdio` reaches QMP `prelaunch`, prints **nothing**,
  and exits 0 on `quit`. The same is true for a device that is present but whose node this user
  cannot open (`27c6:609c`, node `0664 root:root`). So the capability degrades **silently** into an
  empty xhci bus — the exact failure mode a capability flag exists to prevent. **Fix:**
  `require_usb_host_devices` in `create()`; gates `usb_device_node_resolution_is_fail_loud` (unit,
  fixture tree) and `qemu_refuses_a_usb_device_absent_from_the_host` (integration, real `create()`).
- **"The `-sandbox …` Enforcing filter may not tolerate usbfs" (§2.4, stated as an open question) —
  answered NO conflict.** The launch above carries vmcell's own `QEMU_SANDBOX_SPEC` verbatim and
  realizes both USB devices, so **no sandbox downgrade is owed**. Recorded so the question is not
  re-opened as speculation.
- **"A QEMU built without libusb would report `true` and drop the device" — the failure is loud, not
  silent.** `-device usb-host-nonexistent,…` exits 1 with
  `'usb-host-nonexistent' is not a valid device model name`; a libusb-less build has no `usb-host`
  model and dies the same way at spawn. Measured the same session. This is why the flag stays a
  static `true` rather than a per-binary probe.
- **"The empirical questions are answered *before* the flag ships `true`" (§18) is unsatisfiable as
  written.** With the flag `false`, `create()` refuses every USB config through the shared predicate,
  so the live leg cannot run — the ordering is circular. Resolved by validating out-of-band against
  the real binary (the three runs above) and by making the one remaining unknown loud rather than
  presumed. What the `true` now rests on is written at the flag itself, evidence and date included.
- **The live gate was un-runnable, not merely un-run.** `just test-usb-passthrough` pointed
  `VMCELL_KERNEL` at a `vmlinux-usbhost` build that no pins entry could produce (`kernel_fragments`
  held only KASAN/KCOV/LOCKDEP/SLUB_DEBUG; `kernels` only the two versions), so the live leg would
  have died at its own `NOBUS` guard on every host. That is why the argv defect above had no
  backstop. **Fix:** the committed label + fragment, gated by
  `usbhost_kernel_label_and_fragment_are_pinned`.
- **usbfs permissions, measured:** `/dev/bus/usb/*/*` on this host are `0664 root:root`; as the
  unprivileged test user a read-only open succeeds and a read-write open fails `EACCES`. QEMU needs
  read-write to claim a device, so an unprivileged run genuinely cannot pass one through — which the
  precheck now says out loud, naming the node, instead of booting a guest with an empty bus.

### Gates

| What it pins | Gate | Proven red by |
| --- | --- | --- |
| The USB fragment actually **reaches the `Command`**, contiguously, inside §2.4's window, and adds nothing else | `vmcell-qemu tests::qemu_full_argv_splices_the_usb_fragment` | deleting the `cmd.args(build_qemu_usb_args(...))` splice → **RED** (was green before this pass) |
| The advertised capability matches the **composed** argv | `vmcell-qemu tests::qemu_usb_capability_matches_the_emitted_argv` | the same deletion → **RED**; flipping the flag → RED |
| Token-level argv rendering (one controller, `0x%04x` ids, call order, empty-in/empty-out) | `vmcell-qemu tests::qemu_usb_args_golden` | per-device controller; `{:x}`/decimal ids |
| An absent / ambiguous / unopenable host device is refused, with the present-unique device as the positive control | `vmcell-qemu tests::usb_device_node_resolution_is_fail_loud` | returning `Ok` on no match; taking the first of several matches; skipping the read-write open |
| …and that the refusal is **wired into `create()`** | `vmcell::usb_passthrough qemu_refuses_a_usb_device_absent_from_the_host` | neutralizing the `require_usb_host_devices` call in `Qemu::create()` → **RED** |
| The live leg's guest kernel is buildable from the committed pins, produces `vmlinux-usbhost`, carries xhci/USB-core/one class driver, and carries **no** consumer usbip/gadget closure (G1) | `vmcell::usb_passthrough usbhost_kernel_label_and_fragment_are_pinned` | dropping the entry's `fragments` key → **RED** (`left: []`) |
| The ninth capability flag across all four backends | `vmcell::usb_passthrough capability_honesty_usb_host_passthrough` | flipping any backend's literal |
| Non-QEMU `create()` refuses typed, feature string == field name, with QEMU as the positive control | `vmcell::usb_passthrough incapable_backends_refuse_a_usb_config_at_create` | dropping a backend's `reject_usb_host_devices` call; renaming the feature string |
| The refusal predicate refuses only incapable backends **with** devices | `vmcell vmm::tests::reject_usb_host_devices_refuses_only_incapable_backends_with_devices` | keying on the flag alone |
| Both `build()` rejections (`snapshotting`+USB; zero/duplicate ids) with the accept-valid control | `vmcell config::tests::reject_usb_host_device_with_snapshot`, `reject_bad_usb_host_device`, `accept_valid_usb_host_devices` | disabling either arm |
| The `spawn_qemu` split changed no launch behavior | live: `boot::qemu`, `shares_ro_rw::qemu`, `extra_block::qemu`, `qemu_in_kernel_vsock_boot_and_exec`, `lifecycle_unprivileged_smoltcp::qemu` (the hoisted readiness wait), `snapshot_restore::qemu`, `zygote_fan_out::qemu`, `session_multiplexed_exec::qemu` — all green on this KVM host | — |
| In-guest enumeration of a designated device | `just test-usb-passthrough` (opt-in; `VMCELL_TEST_USB_DEVICE=<vid>:<pid>` + `VMCELL_KERNEL=<…>/vmlinux-usbhost`) | **not run: this host has no designated, disposable USB device** |

### Residual, deliberately recorded

- ~~**In-guest enumeration is still unproven.**~~ **CLOSED 2026-08-12 — see the live-validation
  record below.** The live leg has now run against two real devices; the flag's `true` is validated
  end to end.
- **The precheck runs in the vmcell process, not in the jailed child.** They share uid and, with
  `clear_ambient_caps: false` (the default, Appendix A reversal 9), ambient capabilities. A jail that
  cleared them could still leave the child unable to open a node this process opened, and QEMU's
  silence would again be the only signal. Stated at the function; it is the standing argument against
  flipping that default without fd-passing.
- **Version ledger.** `VmmCapabilities` gains a field → `constructible_struct_adds_field`, a breaking
  change to an externally-constructible exhaustive struct; it belongs in the pass's single
  0.12 → 0.13 bump. `VmConfig`/`VmConfigBuilder` are `#[non_exhaustive]`, so the config half is
  purely additive — do not conflate them.

### Live validation of the flag (2026-08-12) — the last open question, closed

`just test-usb-passthrough` ran on a KVM host (QEMU 10.2.1, guest `vmlinux-usbhost` built through
the delta-3 toolkit) against **two** designated devices, deliberately chosen to be different shapes:

| Device | Host driver at start | Result |
|---|---|---|
| Goodix fingerprint reader `27c6:609c` | none (`Driver=[none]`) | enumerated in-guest, 2/2 at `--retries 0` |
| Realtek 2.5G NIC `0bda:8156` | **`r8152` bound** | enumerated in-guest, 3/3 at `--retries 0` |

The second is the case that matters: QEMU must unbind a *live* kernel driver to claim the device.
It does. So `usb_host_passthrough: true` is now measured, not presumed.

**Passthrough is not transparent to the host driver — measured, and the reason the recipe demands a
*disposable* device.** After the guest exits the device reappears on the host bus, but in the USB
configuration the guest left it in: `0bda:8156` came back at `bConfigurationValue=2` (of 3) with
**no driver bound to either interface**, so `r8152` did not re-bind and the host lost that netdev
until the configuration is reset (write `1` to the device's `bConfigurationValue`, or replug). The
no-driver device (`27c6:609c`) has nothing to lose and is unaffected. A first reading of this run
mistook the *other* Realtek NIC's netdev (`0bda:8153`, on a different hub, never passed through) for
the test device's return — the check that settles it is which USB interface backs the netdev
(`readlink -f /sys/class/net/<dev>/device`), not the netdev's presence.

**The defect this run found.** The leg scanned guest sysfs **once**, immediately after the agent
became reachable. Guest USB enumeration is asynchronous to agent readiness, and the driver-bound
device needs the extra unbind+reset — so the single scan failed **3/3** on the NIC at `--retries 0`,
while passing on a retry only because the *previous* run had left the device unbound. (That is the
retry-masked pass AGENTS.md rules out.) The scan is now a bounded poll —
`USB_ENUMERATION_BUDGET` 10 s at `USB_ENUMERATION_POLL` 250 ms — the same shape
`lifecycle.rs` already uses for virtio-net `operstate`. Non-vacuity re-proven WITH the poll in
place: deleting the `cmd.args(build_qemu_usb_args(…))` splice reddens the leg in 10.98 s with
`guest did not enumerate 0bda:8156 within 10s`, so patience did not buy silence.

**A false premise this run also corrected.** Two comments (the pins test's rationale and the
justfile recipe) said the stock vmcell kernel "has no USB driver at all" and that the fragment "is
what adds it". Measured: `make olddefconfig` inherits `CONFIG_USB_XHCI_PCI=y` from the x86_64
defconfig, so `vmlinux-6-12-94` and `vmlinux-6-6-143` — which declare **no** fragments — carry xhci
too. The assertion (the baseline `microvm_config` names no USB symbol) stands and is worth keeping,
but its reason changed: the fragment **pins** the symbols rather than adding them, so an upstream
defconfig change cannot silently drop USB out from under a capability that advertises it. Both
comments now say that.

# The docs/78 code-review pass (2026-08-13)

A comprehensive post-landing review of the 0.13 tree (`docs/78-claude-fable-code-review.md`; live
gates re-run green on this host: ci, privileged 144/144, unprivileged 4/4, daemon 12/12, crosvm
28/28). Its findings are reported there, not here; this section carries only the **ledger actions**
the review is obligated to make in this file — three entry corrections applied in place above
(the v28 (fs-reap) routing that never landed; the v30 delta-9 restore-premise; the delta-4
`let _` cluster mis-characterization), the crosvm bench-staging supersession annotation, and the
three new records below.

## Recorded (justified): post-snapshot resume is warn-and-Ok on all four backends

`snapshot()` on CH, FC, QEMU, and crosvm resumes the source **best-effort, warn-only** after the
snapshot completes: a successful snapshot with a failed resume returns `Ok`. *Reason it is Ok, not
Err:* a completed snapshot is a valid, restorable artifact — failing the call would misreport the
artifact's state — and design §2.2's "or stay paused if the VM is about to be killed" flow depends
on a snapshot's success being determined by the snapshot alone. Previously recorded only for crosvm
(and stated at-site on FC/QEMU); this generalizes it to the policy it already was. CH's
implementation site is the one missing the at-site rationale comment (docs/78 fix item). The
consequence stays visible: a wedged post-snapshot source surfaces on the next agent op's timeout,
not from `snapshot()`.

## v30 delta 2 — the downstream contract (§18 delta 2 / §10.4), as built (retroactive record)

Recorded retroactively by the docs/78 review — the register convention (each delta reconciled here)
was met for deltas 1 and 3–9, but delta 2's pieces landed without a record. Where each landed:

- **The §10.4 contract section + the `VMCELL_*` env table + git-dep guidance** → `README.md`
  ("Consuming vmcell as a dependency", the env table with the specified `VMCELL_ROOTFS` full-no-op /
  `VMCELL_KERNEL` path-redirect / `VMCELL_PINS` overlay semantics) and design §10.4.
- **`scripts/check-vendored-vhost.sh`** — the path-independent, consumer-runnable vendored-patch
  assertion; the `ci` recipe's two inline M-VEND-3 greps were replaced by one call to it (one law).
  Its gate legs (green positive control, red stanza-dropped inverse, not-applicable exit-0, and the
  non-vacuity guard) landed with delta 5's example workspace and are recorded in that section.
- **`cargo semver-checks` over both contract crates** → `justfile` (the baseline-rev invocation,
  `-p vmcell -p vmcell-artifact-validator`) and `ci.yml`'s PR job.
- **Deviation:** the README's git-dep patch guidance documents the **git-form** stanza (a
  `[patch.crates-io]` entry pointing at the vmcell repo) as the primary route rather than a literal
  copy of the `=`-pinned path stanza — both sanctioned shapes the script accepts; the path form
  additionally requires copying the `vendor/` trees, which the README states.

## v30 delta 8 addendum — naming the live coverage of the hostcaps probe

Rule-4 enumeration the delta-8 record omitted: the `HostCapabilities` **probe body** (CapEff parse,
`/dev/kvm` open, netns reachability) has no injection seam and no unit tests — the recorded gate
("a fake-host descriptor drives every decision") covers only the decision methods. The live test
that covers what the units cannot: the privileged **segment suite** — `require_privileged_net`'s
independent CapEff parser plus `NetSegment::new(..).expect(..)` (which gates on
`HostCapabilities::probe()`) — reddens on a blessed host if the CapEff/netns probe half regresses;
the independent parser is what makes it non-vacuous. The **cgroup half**
(`probe_delegated_controllers`/`probe_domain_leaf`) remains genuinely uncovered; its as-built blast
radius is the daemon's boot-log line only (`controller_enforceable` is consulted nowhere
load-bearing today). An injectable probe root (the `SysfsCpuFreq::with_root` pattern) is the fix if
that ever changes.

## The two docs/78 fix waves (2026-08-14), as built

Wave 1 landed B1 and the majors (`0acf129`), wave 2 the §5–§8 minors (`87dbb8b`). Live after both:
`just ci` green, `just test-privileged` 149/149, `just test-unprivileged` 4/4, `just test-daemon`
14/14, `just test-crosvm` 29/29, 16 honest capability skips. The findings and their gates are
reported in `docs/78-claude-fable-code-review.md`; this section carries only what the waves changed
about the **record** — the deliberate deviations, the behavior changes a caller can see, and the
traps measured on the way.

### The jail deny-list carries three syscalls beyond the design §12.3 roster

`vmm::jail::DENIED_SYSCALLS` ships `reboot`, `swapon` and `swapoff` on top of the roster §12.3
lists. Kept deliberately, not trimmed to match the doc: `reboot(2)` reboots or halts the **host** (a
guest reboot is a VMM-internal transition, never this syscall), and `swapon`/`swapoff` reconfigure
host swap. All three are dangerous-and-never-needed-by-a-booting-VMM in exactly the sense every
roster entry is, so the honest reconciliation is to widen the doc; the design folds them into §12.3
at its next revision. The const's at-site comment cites this record. Gate:
`jail::tests::deny_list_is_exactly_the_documented_set_and_compiles`, whose expected set is the
§12.3 roster verbatim plus these three, pinned as exact membership in both directions. It is
written out from the **design text**, not derived from the const: the version that had pinned a
copy *of the const* stayed green while the shipped list silently lacked `process_vm_readv`
(docs/78 M15).

### `build_vmm_cmd` installs its `pre_exec` unconditionally — the `posix_spawn` trade

The closure now resets SIGINT/SIGTERM to `SIG_DFL` before joining the netns and applying the jail,
so it is installed for **every** spawned VMM (M9): an ignored disposition survives `execve`, and
`vmcelld`'s broker child ignores both signals so a terminal Ctrl-C cannot kill the cap-holder before
its ordered teardown — without the reset the VMM would inherit that deafness and an operator's
`kill` would stop working. *The trade:* a VMM spawned with neither a netns nor jail work no longer
takes std's `posix_spawn` fast path and pays a `fork`+`exec` instead. Accepted, and **not measured**
— it is expected to be noise beside a VMM boot, but it is a real change to the unprivileged/no-jail
spawn path and is named here so a boot-latency regression has a candidate cause.

*Why the gate is `vmcell`-side and not in the daemon suite:* cloud-hypervisor **re-arms** its own
INT/TERM handlers at start-up — measured under a parent ignoring both, the VMM's `SigIgn` is `0x4`
— so a VMM-side `SigIgn` assertion in `group_sigint_tears_down_vms_leaving_no_orphan_vmm` would pass
with or without the reset. That test therefore asserts the broker child's disposition (the half it
*can* observe) and states the omission at-site; the reset's own gate needs a spawn, through
`build_vmm_cmd`, of a program that keeps its inherited dispositions. **That gate is not yet
committed** (see the open items below) — the reset ships proven only out-of-tree.

### One config-only eligibility predicate — and the delta-9 restore premise corrected in code

The delta-9 record's premise "every backend's `restore()` rejects a non-snapshotting config" was
empirically false (no backend's `restore()` reads `cfg.snapshotting`), and docs/78 §10 annotated it.
The correction is now **code**: `orchestrator::clone_ineligible_feature` is the one config-only
snapshot-eligibility predicate, with five arms — unprivileged (vhost-user-net) networking, segment
membership, a virtio-fs share, a custom `init=`, and host USB passthrough. The last two are new:
a custom init replaces the guest agent that the mandatory post-restore resync (§8.2) runs through,
and a passed-through host USB device is host state living outside guest RAM. `MicroVm::restore_inner`
calls the predicate; `MicroVm::snapshot` refuses a custom-init VM at the earlier boundary (the one
that refuses the bad artifact instead of the N restores of it) and names `vmm: "orchestrator"`,
following the `zygote` / `in-process-virtiofsd` precedent that a non-backend boundary blames itself.
Gates: `clone_ineligible_feature_covers_every_config_only_arm`, `restore_rejects_a_custom_init_config`,
`restore_rejects_usb_host_devices_on_a_non_snapshotting_config`, `zygote_clone_rejects_a_custom_init_config`.

**Completed in the same pass:** `zygote::check_clone_eligible` now *wraps* `clone_ineligible_feature`
instead of open-coding the older, narrower three-arm list. Until it did, the two had already drifted —
the custom-init and host-USB arms existed only in the orchestrator's copy — so a custom-init `Zygote`
was accepted, its copy-on-write copies minted, and the refusal surfaced N clones later at the
per-clone restore boundary. Gate: `zygote::tests::custom_init_and_usb_configs_rejected_at_zygote_construction`
(KVM-free; red on restoring the open-coded list, with an eligible-config positive control so it
cannot pass vacuously). The backends' own `restore()` paths remain
permissive about host USB (none runs the `create()`-side precheck): the orchestrator boundary covers
every in-tree production path, but `Vmm` is a **public trait**, so a downstream consumer calling
`vmm.restore()` directly bypasses it. Backend-side defense in depth is the open half — crosvm's
`reject_disk_io_throttle`, now called from both `create()` and `restore()`, is the shape the rest
should take.

### The daemon suite is 14 tests

`just test-daemon` was 12 at the docs/78 baseline and is 14 now (`cargo nextest list -p vmcelld
--run-ignored all`): `group_sigint_tears_down_vms_leaving_no_orphan_vmm` (M9 — a group Ctrl-C must
leave no orphan VMM, asserting the broker child's `SigIgn` as the fast mechanism check beside the
slower orphan check) and `broker_parent_serves_with_no_capabilities_child_keeps_them` (M12 — the P2
posture, with the still-capable child as its positive control). The harness grew what those need:
`Daemon::pid()`, `wait_exit()`, `start_in_own_process_group()`, and a `Drop` that returns early when
the child was already reaped so it cannot signal a recycled pid — behavior every other daemon test
inherits.

### The guest `curl` shim, and what it costs to change a guest applet

The shim now honors-or-rejects every accepted input (an unknown flag, a garbage `--max-time`, a
discarded `-o`/`-H`/`-A`/`-X`, an unparseable `--resolve` all used to be swallowed). Why this
mattered beyond the fail-loud rule: **the M13 guest→host NAT gate could not be written until the
shim could POST.** `/vmcell-tools` is first on the guest PATH (`child_path`) and `vmcell-tools/curl`
is a symlink onto the multicall shim, so an in-guest `curl` in any test resolves to the shim
whatever the base image carries — and `nat_window_fill_upload` needs `--data-binary @file`, `-o`,
`-w '%{http_code}'` and `-H 'Expect:'`, every one of which the old parser accepted and ignored.
Rejection *is* the faithful emulation: a flag the shim cannot honor exits 2 naming the offender,
exactly as a missing real-curl feature would. Gates:
`parse_curl_args_rejects_every_input_it_cannot_honor` plus its positive control
`parse_curl_args_honors_the_flags_it_accepts` (a blanket "reject everything" passes the first and
fails the second).

Two operational facts this pass paid for, recorded so the next change does not:

- **Changing `vmcell-guest-tools` or `vmcell-guest-agent` requires rebuilding the rootfs before any
  live suite means anything.** The applets are baked into `rootfs.erofs` by `vmcell build`, not by
  `just test-*`; a warm rootfs runs the *old* binary and the suite reports on code that is not the
  code under test. The `justfile` states this for a **new** applet (a missing `/vmcell-tools` path
  fails loudly); a **changed** applet is the silent case, and is the one that bit here.
- **That rebuild must pass `--kernel-source host-make`.** `vmcell build` defaults to
  `KernelSource::Prebuilt` (only `build-kernels` defaults to `host-make`), so a bare `vmcell build`
  swaps the locally built guest kernel for the prebuilt seed and reddens `nested_virt` and
  `snapshot_restore`. Measured this pass; it cost a full privileged suite run to diagnose.

### Config boundary hardening — including one fail-loud behavior change

Three "honored or rejected at construction" holes closed in `VmConfig::build()`:

- **Four cmdline *aliases*** join `RESERVED_CMDLINE_KEYS`: `rw` (inverts the owned `ro` — a Block
  root would mount writable with `rootflags=noload` still suppressing journal replay) and
  `quiet`/`debug`/`ignore_loglevel` (override the owned `loglevel=`, because caller args are
  appended last). The `extra_kernel_args_cannot_clobber_reserved_tokens` coverage test compares
  emitted *keys*, and an alias shares no key with the token it overrides, so it structurally cannot
  discover one: the list is hand-maintained and guarded by
  `reserved_cmdline_keys_cover_owned_token_aliases`, which checks both the predicate and the
  boundary's actual refusal.
- **`RootfsSource::effective_image()`** is the one law for which host file backs `/dev/vda`.
  `build()` seeds the duplicate-backing-file set with it, so an extra disk can no longer alias the
  effective root image — two attachments of one image is the rw corruption that guard already named.
  Gate: `extra_disk_cannot_alias_the_root_disk_backing_file`, which recomputes the expected path
  through the predicate rather than a test-local literal.
- **A share tag must be exactly one `Component::Normal`.** `fs::VirtioFsDaemon::start` names the
  vhost-user socket `<vm_tmp>/<tag>.sock`, so a tag carrying a path separator created and truncated
  a caller-chosen file outside the per-VM scratch dir — outside what teardown sweeps.

**The behavior change:** the rootfs image and overlay now get the same non-empty/absolute boundary
checks every other host path input gets, so `VmConfig::build()` **rejects an empty or relative**
rootfs path with `Error::Config` instead of failing late as a VMM "cannot open image". Existence
stays unchecked, as for shares and extra disks. Two callers pass user-supplied paths straight
through and are now fail-loud on a relative path: `vmcell-cli`'s `ephemeral_vm` and the validator's
`base_cfg` (a §10.4 contract-surface crate). Accepted rather than papered over with a
`canonicalize` at those boundaries — the message names the constraint, and a silently
cwd-relative VM image is worse than a refusal. Gate: `rootfs_paths_are_validated_at_the_boundary`.

### Firecracker restore rebinds the tap — and needs FC 1.8+ for a tap-bearing restore

M1: FC's `restore()` sends `network_overrides` on `PUT /snapshot/load` so the restored VM binds the
**fresh** `res.tap_name` instead of re-opening the tap name the snapshot baked (which is an orphan
in the new netns — a dead data plane that no liveness proxy could see). Two things this does not
change, stated because both invite the wrong inference: `restore_rotates_host_paths: false` is about
the **vsock/serial host-socket identity**, not about the tap being baked; and the host tap name is
not in QEMU's or crosvm's migration stream at all (both rebuild their argv from the fresh
resources), so neither has an M1 analogue. *The cost:* `network_overrides` needs **Firecracker
1.8+** — validated here on v1.16.0. An older FC would 400 on the unknown field; the tapless shape is
unaffected because the key is a presence attribute (`skip_serializing_if`) and is omitted, which is
also why it is round-tripped on the JSON codec FC actually ships over.

### Recorded (justified): the guest-tools ↔ `netif` kernel-ABI duplication stays duplicated

`vmcell-guest-tools` keeps its own `#[repr(C)]` `IfReq` + link-ioctl stack beside the audited copy in
`vmcell_guest_agent::netif`, against "kernel ABI structs are defined once". docs/78 §6 offered
consolidation or a recorded deviation; this is the deviation, and the at-site comments cite it.
*Why not fold into the agent's lib:* `netif` exports exactly what PID 1 calls
(`set_loopback_up`/`set_mac_bytes`/`set_ipv4`), while guest-tools also needs `set_link_up(dev, up)`
and `read_ipv4` (`SIOCGIFADDR`/`SIOCGIFNETMASK`) — code PID 1 never executes. Consolidating grows the
audited PID-1 surface, and its `unsafe` blocks, with dead-for-PID-1 code, which is backwards for C1;
it would also make guest-tools link the agent's whole production graph to reuse ~60 lines of `libc`.
(The lean-agent gate is *not* the objection — it reads `cargo tree -e no-dev -p vmcell-guest-agent`,
a subtree a dependent cannot enter.) The honest consolidation is a third `libc`-only crate both
depend on, which is a workspace-layout change, not a review-fix side effect.

*What landed instead*, so the copies cannot drift silently: the request numbers are `libc`'s
(`SIOC*`/`ARPHRD_ETHER`/`IFF_UP`, never a second local spelling of a kernel ABI value — the rule this
file already applied to `VMADDR_CID_ANY`); the union sub-offsets are named constants mirroring
`netif::HWADDR_{FAMILY,MAC}_OFFSET`; `ifreq_is_pinned_field_by_field_to_the_kernel_abi` pins both
field offsets, both field sizes, the total size, the sockaddr-fits check and the three sub-offsets
against `libc::ifreq`/`sockaddr`/`sockaddr_in`; and
`ioctl_requests_match_the_kernel_abi_values_netif_hardcodes` pins the request numbers to the literals
`netif` hardcodes. The error types now agree (`std::io::Result`, with `InvalidInput` for an overlong
device name); one difference is deliberate and stated at its site — guest-tools tags each errno with
the ioctl name, because its errors land on the persisted serial console, a restored guest's only
observable. *Limit of the guard:* no guest-tools test can observe an edit to the agent's copy. Both
are anchored to the same `libc` ABI, so a copy that drifts from the ABI reddens in its own crate; a
*semantic* drift (a different ioctl order) is caught only by the live MAC-rotation legs of the
restore suites. Retire this entry when the shared crate lands.

### Validator, daemon-store and virtiofsd reconciliations

- **`Level::Full`'s rustdoc is gated prose.** It no longer promises an egress-proxy check or §8.2
  restore state-rotation assertions — neither ever shipped in `run_full`; it names the shipped roster
  by check id and points at vmcell's own suite for the two absent legs.
  `level_full_rustdoc_names_exactly_the_shipped_checks` parses the backticked ids out of the doc
  block (`include_str!` of `lib.rs`) and asserts set-equality with the ids `run_full` records against
  a `fail_create` `FakeVmm`. Deliberately scoped to `Level::Full`: each Full arm records or skips its
  id on every path, so a fake run enumerates the whole roster, whereas the Core/Extended guest-facing
  ids exist only after a real agent handshake — those rosters stay ungated, recorded here rather than
  faked.
- **Daemon snapshot prefixes are create-only, like every other name in the store.**
  `Registry::snapshot` uses `create_dir` and maps `EEXIST` to `AlreadyExists` (409) instead of
  silently overwriting. Because a prefix would otherwise be unfreeable, `ArtifactStore::delete` also
  removes a snapshot prefix directory; one-shot prefixes were rejected as a permanent namespace leak.
  Prefixes are deliberately **not** covered by the `pins()` delete-in-use guard: `restore_from`
  copies via CoW at launch, so a booted VM holds no pin, and a DELETE racing an in-flight restore
  falls under the already-recorded narrow `create` window in `delete_artifact_if_unused`. The
  `.sha256` reservation is one predicate, `is_reserved_sidecar_name`, consulted by create (400), list
  (skip) and info/delete (404) — the reaction differs per op, the law does not. Related:
  `--allow-unauthenticated` is warned **per request** in `server::auth_layer`, driven by the pure
  `AuthDecision::UnauthenticatedBypass` (so `authorize` stays log-free and unit-testable against its
  inverses), with `vmcelld`'s one-time boot warn kept as the complementary signal.
- **virtiofsd readiness is paced by the caller's profile, with one narrowing.**
  `VirtioFsDaemon::start_paced(share, vm_tmp, &Timeouts)` drives the shared `vmm::wait_for_socket`
  with `api_socket_poll` as the cadence and a named `SOCKET_READY_TIMEOUT_MS` ceiling (unchanged
  total budget) instead of a hand-copied 20 ms grid. **All three shipped sites pass `&cfg.timeouts`**
  (CH create + restore, QEMU create), so §9.4's "every daemon readiness wait" is true on the shipped
  path — the extraction alone left it false, because the unit gate exercises only the pure
  `socket_wait_budget` and is structurally blind to a call site that never reaches it; the call-site
  property is therefore gated by its own source scan in each backend. The unpaced `start` survives as
  a `#[deprecated]` shim, not because it is wanted but because removing a `pub fn` is an API break
  that belongs to a ledgered version bump rather than a defect fix — and, measured rather than
  assumed, `cargo semver-checks` would *not* have caught the removal (for a `0.x` crate it assumes
  the minor bump that is allowed to break), so the ledger rule is the only thing holding it. Under
  `-D warnings` the deprecation makes any new caller fail to build, which is what keeps the shim from
  becoming the accidental twin. Delete it at the next `vmcell` version bump. *Deliberate narrowing:*
  the shared helper folds a
  failing `try_wait` into the deadline, so a poll error now surfaces as the readiness failure **with**
  the daemon's stderr rather than as its own message — nothing is swallowed, and the alternative was
  keeping a second copy of the readiness loop alive to phrase one sentence. virtiofsd also now spawns
  through `helper_daemon_pre_exec`, which arms `PR_SET_PDEATHSIG(SIGKILL)` after `setpgid(0,0)` and
  refuses to exec if `getppid()` shows the parent died inside the fork→prctl window; its gate asserts
  the *behavior*, not the flag, because `pdeath_signal` is per-task and `clone` zeroes it. The same
  gap remains in QEMU's `vhost-device-vsock` helper and in `build_vmm_cmd`.

### One-law consolidations completed in the same pass

- **`RootfsSource::effective_image()` reaches all four backends.** The predicate landed at the
  config boundary first; cloud-hypervisor, Firecracker, QEMU and crosvm now each derive the
  `/dev/vda` backing file through it instead of inlining `overlay.as_ref().unwrap_or(image)`, so the
  duplicate-backing-file guard and the wiring cannot diverge. Each backend gates it on its own
  composed device config (e.g. `fc_root_drive_uses_the_effective_image_law`), because the argv/API
  body is the only place a backend can silently attach the wrong file.
- **`scripts/ban-inline-setns.sh` + its self-test** give S2's "one home for `setns`" a gate that can
  go red: the two proxy sites had already been routed through `net_sys::setns_net`, but nothing
  stopped a third inline `libc::setns` appearing. Allowed sites are `net_sys.rs` and the
  `vmm/mod.rs` `pre_exec`; wired into `just ci` and the CI lint job beside the other ban scripts.
- **Test scratch paths are owned, not swept.** `common::TempTree` (RAII, with
  `VMCELL_KEEP_TEST_TEMP=1` for post-mortems) replaces the trailing
  `let _ = std::fs::remove_dir_all(&dir)` idiom, which every panicking assertion skipped — and which
  a nextest retry then leaked once per attempt. `tests/snapshot_restore.rs` had no removal at all,
  so guest-RAM-sized snapshot dirs accumulated per run per backend until the host temp filesystem
  hit its quota and the daemon suite went red on `Disk quota exceeded`. Names are unchanged (tests
  and operators grep for them); only the ownership moved.

### Still open after these two waves

Named here so the next pass does not rediscover them, and so nothing above reads as complete when
it is not:

- On the backends, host USB is the remaining half of the eligibility law: crosvm's restore now runs
  `reject_disk_io_throttle` like its create (gated by `restore_rejects_disk_io_throttle_like_create`),
  but no backend's `restore()` runs the USB precheck its `create()` runs — QEMU splices `usb-host`
  devices that were never capability-checked nor proven openable, and CH/FC/crosvm drop an accepted
  `usb_host_devices` list silently. The orchestrator boundary covers every in-tree production path;
  `Vmm` is a public trait, so a downstream consumer calling `vmm.restore()` directly bypasses it.
- `vmcell-bench`'s `workspace_root()` is a third copy of the workspace ascent, and its backend-binary
  table parallels the validator's `harness::*_bin` getters (held to the contract by a parity gate,
  not by sharing code) — `vmcell`'s own resolvers are `pub(crate)`, so both collapse only via a
  `vmcell`-side export. Same shape as the recorded `harness::ch_bin()` consolidation item.

### Closed before this pass shipped

Three items were on the list above when it was written and were closed in the same pass; recorded
here so the ledger is not read as a to-do that was never done:

- **The `build_vmm_cmd` SIG_DFL reset has its gate.** `tests/jail_hardening.rs`'s
  `build_vmm_cmd_resets_inherited_ignored_signals_for_the_vmm_child` ignores INT/TERM in the test
  process, asserts that as its positive control (so a green result cannot come from the parent never
  having ignored them), spawns `/bin/cat /proc/self/status` through `build_vmm_cmd`, and asserts the
  child's `SigIgn` bits for both signals are clear. KVM-free and root-free — `cat` installs no
  handlers of its own, which is exactly what cloud-hypervisor does do, and why the daemon suite
  cannot host this assertion. Red on deleting either `libc::signal(…, SIG_DFL)`, verified.
- **`tests/common/mod.rs::computed_cgroup_name` recomputes through `vmcell::naming`** (F2). It is
  consumed by residue checks whose whole purpose is to catch a naming change; a second copy of the
  composer would have kept passing through the drift it exists to catch.
- **The `+ep` runner-blessing predicate has one home.** `scripts/review-preflight-priv.sh` grew a
  `--check-runner <path>` mode (exit 0 blessed / 2 bless-remediable) that dispatches to the same
  `check_runner` the full preflight uses, and `just bless`'s idempotence skip calls it instead of
  restating the caps test — the two copies had already diverged once on strictness. While fixing
  that, a **latent flaw in `bless` itself** surfaced and was fixed: it copied the freshly-built
  runner over the live stable path *before* `sudo setcap`, so a declined or unavailable sudo
  (`sudo: a terminal is required to authenticate` in a non-interactive shell) destroyed a working
  blessing and flipped the preflight from READY to BLOCKED-ON-BLESS. It now stages the copy under a
  temp name, setcaps that, and renames it into place only on success (a rename preserves file
  capabilities); a failed setcap removes the temp, says so, and leaves the previous blessing
  untouched. The failure is handled explicitly rather than by a `RETURN` trap, because under
  `set -e` a bare failing command exits the whole shell and the trap never fires.

### The completeness audit, and the six halves it caught (2026-08-14)

The three fix waves above were followed by an **adversarial completeness audit**: five reviewers took
disjoint slices of docs/78's 83 findings and were told to *disprove* the claim that each was
addressed, then a sixth independently re-checked every non-green verdict. Seventy-seven came back
fully addressed; six came back PARTIAL, all six correctly. Every one had the same shape — the fix
landed and the *second half* of the finding did not — which is exactly the failure mode a
self-review misses, and the reason the audit is recorded here rather than treated as ceremony.

- **M6's named live gate did not exist.** The stdin writer thread shipped with two good KVM-free
  gates, but nothing in `crates/vmcell/tests/` moved more than a couple of KiB of stdin, so the two
  consequences the fix exists to prevent — an undispatched `CloseSession` and a skipped C3 teardown —
  were unmeasured on the data plane. Worse, a comment in the guest agent *claimed* that coverage.
  Closed by `session_stdin_flood_does_not_wedge_the_connection` (four backend arms), which floods
  512 KiB at a non-reading child and then asserts both consequences, and by making the comment name
  the real leg. Code that documents coverage it does not have is the one thing rule 4 forbids.
- **The virtiofsd pacing never reached production.** `start_paced` existed with three passing unit
  gates and *zero* production callers: all three shipped sites still used the default-profile
  `start`. The gate could not catch it, because it tested the extracted helper rather than the claim.
  Closed above.
- **`OverlayStore::probe` still had no production caller.** The side-effect half of
  `overlay-probe-not-side-effect-free` was fixed; the seam half was not, leaving dead public trait
  surface and an S4 bypass. Closed by `Zygote::probe_cow_support_in(&HostEnv)`, gated by an injected
  store configured with the *opposite* answer to the real filesystem's — the only assertion that can
  tell "the seam answered" from "the filesystem happened to agree".
- **Three doc halves** (design §10.4's non-executable downstream bless route contradicting the fixed
  README, the ledger bullet still describing crosvm's *rotated* restore CID, and §5.6 + the example
  README omitting `source_url`/`source_sha256`) were text-only and are closed.

The transferable lesson, recorded because it recurs: **a gate that tests the extracted helper is not
a gate on the claim.** Two of the six were invisible precisely because a green unit test stood next
to an unchanged call site. When a fix extracts a predicate, the gate has to bind the *call sites*,
not just the predicate — a source scan is an acceptable last resort and is what both backends carry
for the virtiofsd pacing.

### `CAP_SETPCAP`: the bounding-set shrink stops being a warned no-op (2026-08-14)

Every privileged run printed `could not drop 38 bounding-set capabilities (PR_CAPBSET_DROP needs
CAP_SETPCAP in the effective set)` — 38 being the 41 caps this kernel supports minus the 3 the runner
held. Nothing failed, which is why it survived: the effective/permitted trim (the load-bearing half)
always worked, and the design recorded the shrink as an acceptable no-op. But it meant the bounding
set stayed at the kernel's full width, so a child that later exec'd a file-cap'd or setuid binary
could still gain capabilities Layer 2 is supposed to have made unreachable.

**As built.** A new `BLESSED_FILE_CAPS` = `PRIVILEGED_CAPS` + `CAP_SETPCAP` is what `just bless`
grants the runner *file*. `PRIVILEGED_CAPS` is deliberately unchanged, and the split is the whole
point: that constant is the set the runner **delivers** (inheritable → ambient → the exec'd test) and
the daemon **retains**, so putting SETPCAP in it would ride the cap into every test and VMM *and* —
because `bounding_drop` is `supported − need` — pin SETPCAP in the bounding set permanently, the
exact opposite of the intent. As a file cap it is transient: the transition drops it out of the
bounding set at step 3 and out of permitted/effective at step 5's trim to exactly `need`.

**No transition code changed.** `shrink_bounding_set_live` already raised SETPCAP from permitted when
held; it simply never was. Worth stating because it is the reason this was cheap: the plan was
correct all along and every syscall failed. SETPCAP drops *itself* in step 3 without disarming the
remaining drops — `PR_CAPBSET_DROP` is gated on the **effective** set, and leaving the bounding set
does not leave effective.

**Gates.** `setpcap_is_a_transient_file_cap_never_delivered_to_the_test` pins the split (SETPCAP in
the file set, absent from `ambient_raise`/`final_caps`/`inheritable_add`, present in `bounding_drop`),
with the delivered caps as the positive control. `setcap_arg_renders_the_blessed_set_verbatim` pins
the operator-facing string. `the_shell_copies_of_the_blessed_set_match_this_constant` `include_str!`s
the `bless` recipe and the preflight probe and fails if either stops naming exactly the set — the cap
list had been spelled out by hand in **five** places, and those two copies had already drifted once
(the `*ep*` substring vs the `=ep`/`+ep` field). `setcap_arg` is now the one composer, and
`blessing_remediation` prints the whole file set rather than the missing subset, because `setcap`
*replaces* a file's set and echoing a subset would strip the rest.

The live gate is the one that matters: `the_bounding_set_is_shrunk_to_exactly_the_delivered_caps`
(privileged, `#[ignore]`d) reads its own `/proc/self/status` and asserts `CapBnd` **equals** the
delivered set, with a `CapEff` precondition so it cannot pass on a process that never went through
the transition. Asserting the plan would have been theater here — a correct plan whose syscalls all
fail is precisely the state that shipped.

`vmcell-privilege` became a **dev-dependency of `vmcell`** so those gates name caps through the one
crate that owns the privileged vocabulary instead of re-deriving `CAP_*` numbers (`libc` exports
none; `jail_hardening.rs` had a hand-written `12` for `CAP_NET_ADMIN`). Dev-only, so `cargo tree
-e no-dev` — what the lean-tree CI invariants traverse — is unaffected.

**Measured, on this host.** Through the blessed runner: `CapBnd` `000001ffffffffff` (41 caps, the
kernel's full width) → `0000000000201002` (exactly `DAC_OVERRIDE|NET_ADMIN|SYS_ADMIN`), with
`CAP_SETPCAP` (bit 8) absent from all five sets — the transient cap is fully shed before the test
runs. The runner-edge warning that had appeared in every privileged run is gone.

**A measurement trap worth recording.** "No warning appeared in the suite output" is NOT evidence
here, twice over: nextest captures and discards child output on an all-pass run, and the daemon
harness redirects `vmcelld`'s stderr into a log inside a `TempDir` that is deleted with the test. A
first pass at verifying this read zero warnings from both and concluded the daemon edge was fixed;
it is not. The honest measurements are the ones above — reading `/proc/<pid>/status` of the live
processes, and running `vmcelld` through the runner with its stderr attached.

**Operational note.** Because the blessing precondition is now four caps, an already-blessed
three-cap runner reads as NOT BLESSED and `just bless` re-blesses it (one sudo). That is the
`M-BIN-2` caps-check path doing its job: the stamp matches but the caps do not, so it falls through
rather than reporting a false no-op.

### Host USB drivers are restored at teardown (2026-08-14)

Validating delta 9 live surfaced a real leak that the passing test could not see: after
`just test-usb-passthrough`, the designated device was left **driverless on the host**. Passing the
laptop camera removed `/dev/video*` and left `Driver=[none]` on both of its interfaces, and it
stayed that way — the kernel does not re-attach on its own. QEMU's `usb-host` detaches each
interface's driver (libusb `detach_kernel_driver`) to claim the device, and it never re-attaches on
the paths vmcell drives: teardown ends in a process-group SIGKILL, and a killed QEMU runs no
release path at all. The graceful QMP `quit` that precedes it is bounded at 500 ms and did not
change the outcome.

**Ownership owns cleanup.** vmcell caused the detach, so vmcell puts it back.
`require_usb_host_devices` now also captures the interface→driver map — at the last moment it
exists, since the sysfs `driver` symlink is gone once QEMU has claimed the device — and one helper,
called by BOTH `QemuInstance::kill()` and `Drop`, re-binds exactly that set after the VMM is reaped.
Ordering is load-bearing at both ends: capture before the spawn, restore after the reap (re-binding
while QEMU still holds the device would race it).

**Restore what we displaced, never "make the device work".** Only interfaces that *had* a driver at
capture time are recorded. An operator who blacklisted a driver, wrote a udev rule, or keeps a
device permanently unbound for passthrough gets that state back — vmcell never attaches a driver it
did not itself displace. Interfaces of the device only: `3-7:1.0` is ours, `3-7.1` is a different
device behind a hub at the same port and is not.

**No new privileged binary, and `modprobe` is the wrong lever.** The only permission needed is write
access to `/sys/bus/usb/drivers/<driver>/bind` (`0200 root:root`), i.e. `CAP_DAC_OVERRIDE` — which
every context that can spawn a passthrough VM already holds (the blessed runner; the daemon's broker
child, which owns VM teardown). Measured: the same write is `EACCES` unprivileged and `OK` through
the blessed runner. A second privileged helper would re-acquire, from a new attack surface, a
capability the caller already has. `modprobe` would also be the wrong operation and a much wider
one: the module never unloaded — only the interface binding was removed — so nothing needs loading,
and re-binding one named interface to one named driver is as narrow as this gets.

**The retry is not defensive padding.** Measured: a bind issued immediately after `wait()` on the
QEMU leader FAILS, and the interface is still driverless ten seconds later; a write from the
slightly-later `Drop` path succeeds. Closing the usbfs fd starts an asynchronous release/reset, and
until it settles the interface cannot be bound — a single write at t=0 is not enough, while a retry
100 ms later is. Hence a bounded deadline (5 s, 100 ms poll), bounded because teardown must never
hang, entered only for a VM that used passthrough and only while a binding is still missing. A
restore that still fails is WARNED with the interface, the driver, and the exact manual command —
never swallowed, and never promoted to an error that would abort the rest of the ordered teardown.

**Gates.** KVM-free: `capture_records_only_this_devices_bound_interfaces` (this device's interfaces
only; driverless ones not recorded; stable order) and
`restore_rebinds_only_what_is_still_detached_and_reports_what_it_cannot` (re-binds the detached one,
skips the one already back, reports the unrestorable one), the latter driven with a zero budget so
it pins the decision logic instantly. Live: `usb_passthrough_qemu` now captures the host bindings
before the VM starts — asserting they are non-empty first, so the check cannot pass vacuously on a
device the host never drove — asserts passthrough actually detached them, and asserts teardown gives
them back, with a bounded retry because the driver probe and udev's node/ACL work are asynchronous.
Red on the inverse, verified: with the restore stubbed out the live gate fails with
`before [("3-7:1.0", "uvcvideo"), ("3-7:1.1", "uvcvideo")], after []`.

**Where it lives.** `usb_host_passthrough` is a *capability*, so the split follows the crate's usual
one and the whole unified law sits in `vmcell::vmm::usb`: resolving a `vid:pid` to its usbfs node,
proving that node openable, capturing the interface→driver map, and re-binding it. The backend owns
only what is backend-shaped — QEMU's `-device qemu-xhci` + `-device usb-host,…` argv — plus *when* to
claim (before its spawn) and *when* to restore (after its reap). The public surface is one function
and one type: `claim_usb_host_devices(vmm, devices) -> UsbHostClaim`, and `UsbHostClaim::restore()`.
A second backend gaining the capability inherits all of it and writes only its argv; there is no
second copy to keep in step. It was briefly implemented inside `vmcell-qemu` and moved on review —
recorded because the moved version is the one to reason from.

`UsbHostClaim` deliberately has **no `Drop` impl**, which is the one place this departs from
"teardown is ownership". The restore has to run *after* the VMM process is gone (re-binding while it
still holds the device races it) and *before* a graceful `kill()` returns (the live gate asserts
immediately after `vm.kill()`), so the ordering belongs at the call site with the rest of the
backend's ordered teardown — visible, rather than implied by struct field-drop order.

**Explicit detach** has no implementation because no shipping backend needs one: QEMU's libusb
detaches implicitly as it claims the device. If one ever does, `claim_usb_host_devices` is its
designated home, so the detach and the restore stay one law instead of drifting apart across two
crates.
