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
  and forestalled what was then the same latent bug on the `Block` rootfs path. (v33 delta 8 later
  ratified that root as **read-only** at the device level too, so that half of the rationale now
  describes a path that no longer exists; the fix itself stays right, because extra disks are
  genuinely writable.) One-law: `CH_RAW_IMAGE_TYPE` const, pinned by a serialization
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
  caught.** *(Stale in the good direction as of the docs/81 pass: the creation law moved INTO
  `Zygote::suspend`, whose one `prepare_snapshot_dest` predicate creates the destination with its
  parents, accepts an existing but empty one, and refuses a populated one. `fork_from_vm` and `branch`
  delegate and keep no `create_dir_all` of their own — so this is no longer a deviation from
  `suspend`'s contract, it IS `suspend`'s contract.)* The first draft mirrored `Zygote::suspend`'s
  then-"caller creates the dir" contract, so a `branch`
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

- **(RETIRED 2026-08-17 — the entry met its own retirement condition) tar2erofs does not preserve
  PAX `SCHILY.xattr` records.** It ended "Retire if xattr passthrough is implemented"; v33 delta 7
  implemented it, so the limitation is empirically disproven and what survives is a pointer.
  `XattrPolicy` is now a per-artifact parameter of the one inject+pack tail: the default `Strip`
  drops every record (which is what keeps the canonical artifact byte-identical), and `Preserve`
  folds each one into the erofs namespace index `mkfs.erofs` uses — through the `Node`/`XattrSpec`
  plumbing this entry called unused. The named test moved with the behavior, which is the drift
  docs/90 D8 reports: it is now the pair
  `tar2erofs::tests::pax_xattrs_are_stripped_under_the_default_policy` /
  `…_preserved_under_the_preserve_policy` (`crates/vmcell/src/artifact/tar2erofs.rs:1339,1361`), and
  the `Strip` leg is no longer waiting to be retired — it is what pins the canonical bytes. See
  "v33 delta 7" below for the as-built record, including the one route where `Preserve` is refused
  rather than honored (`mkfs.ext4 -d <tarball>` silently drops every namespace but
  `security.capability`, so the ext4 producer fails loud naming the member and the attribute).
  **The neighbour below was spot-checked in the same pass and stands**: the opaque-whiteout
  assumption is still the shipped behavior (`tar2erofs.rs:404-419` clears the parent subtree in the
  flat merged map at marker-processing time), its named test
  `tar2erofs::tests::test_opaque_marker_ordering_contract` still exists under that name (`:1799`),
  and its retirement condition — per-layer whiteout application — has not landed.

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
  smoltcp `vhost-user-net` socket. ~~The smoltcp NAT binds that UDS lazily from a background thread
  (`VhostUserDaemon::start`, not `Listener::new`)~~ — **that mechanism is false and is withdrawn; see
  the flake entry below.** The observed failure is real: QEMU's `-chardev socket` connects as a
  client at `exec`
  with **no retry**, so it raced the bind and died `"-chardev socket …: Failed to connect …: No such file
  or directory"` (~30% of boots). CH's vhost-user-net frontend tolerates a not-yet-bound socket via its own
  client-side reconnect; QEMU does not. *Fix (one law):* `wait_for_socket` now takes `Option<&mut Child>`
  (the smoltcp producer is an in-process thread, not a `Child` to watch for early exit), and `spawn_qemu`
  gates the smoltcp socket the same way it already gates the vsock daemon — a fail-loud `Timeout` instead of
  a raw QEMU crash. Red-on-inverse: `wait_for_socket_process_less_present_ok_absent_times_out`.

- **DISCOVERED — smoltcp `vhost-user-net` bring-up flake. The flake is real; its mechanism is OPEN.**
  ~10% of boots, the VMM's wait for the smoltcp `vhost-user-net` UDS does not succeed within its 2 s
  ceiling (sibling in shape to the recorded ~11% external-`vhost-device-vsock` bring-up flake,
  §QEMU-suspend note (a)). Latent because the existing egress tests boot a single VM; the volume probe
  (13+ networked boots/run) exposes it. Mitigation in the probe: `net-egress` retries a transient boot
  failure on a fresh VM (bounded `NET_BOOT_RETRIES`, like the QEMU vsock re-spawn), printing
  `recovered N transient smoltcp-bringup boot failure(s)` so it is surfaced, not hidden.

  **The recorded mechanism and its named fix are WITHDRAWN (docs/81 §7.3, re-verified here against the
  tree).** This entry read "the daemon thread intermittently fails/errors on start", with the owner
  named as "make `SmoltcpProcess::start` block until the UDS is bound instead of deferring the bind".
  `Listener::new` **is** the bind — `vendor/vhost/src/vhost_user/connection.rs`'s `UnixListener::bind`
  — and `SmoltcpProcess::start` calls it synchronously on the **caller's** thread before spawning
  either worker, returning only after (the at-site comment says exactly that). So the named fix would
  retire nothing: the code already does it. It was never true of this codebase either — `git log -S`
  on the bind expression puts it on the caller's thread since `7715f21` (2026-06-30), two weeks before
  this entry was written. The premise was carried, not measured.

  No replacement mechanism is asserted. AGENTS.md governs — *"environmental" is a hypothesis, not a
  diagnosis* — and what a real diagnosis has to explain is why a socket that is bound before `start`
  returns is nonetheless not connectable within 2 s. Same withdrawal in design v32 §17.

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
- ~~**`FakeCgroupFs` was NOT exposed.**~~ **RETIRED (docs/81 pass, 2026-08-15) — the obstacle was
  removable.** The entry read: it is `#[cfg(test)]` and its deliberate `.lock().unwrap()`s would trip
  `vmcell`'s `#![cfg_attr(not(test), deny(clippy::unwrap_used, …))]` if exposed behind a feature, so
  each backend crate's test module defines a local no-op `TestCgroupFs: vmcell::metrics::CgroupFs`
  instead. The `unwrap` class now routes through **one** `FakeCgroupFs::state()` helper carrying a
  single `#[expect(clippy::unwrap_used, reason = …)]` (AGENTS.md "route repeated legitimate sites
  through one helper"), so the fake compiles clean outside `cfg(test)`; it is `pub` behind the
  non-default `test-support` feature, which every backend crate and the validator take as a
  **dev**-dependency. All four `TestCgroupFs` copies are gone. See the docs/81 section below.
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
  `Qemu::spawn_qemu` now calls. *(Renamed `qemu_launch_plan` in the docs/81 pass, where it also
  started returning the shared `vmcell::vmm::LaunchPlan` — see that section.)* `spawn_qemu` keeps the
  I/O (stale-socket cleanup, the `vhost-device-vsock`/`virtiofsd` starts, and the smoltcp
  vhost-user-net readiness wait, hoisted out of the `-chardev` branch it gates); `finish_qemu_spawn`
  keeps the launch tail (spawn → cgroup register → QMP readiness → `SpawnedQemu`). Two small
  carriers make the split honest:
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
  full-argv `build_qemu_command` (now `qemu_launch_plan`) is the shipped shape; the fragment helper
  stays as the token-level golden.
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
  `build_qemu_command` (now `qemu_launch_plan`) composes the entire argv without I/O, and the gates
  assert over the composed argv (`cmd.as_std().get_args()` then; `LaunchPlan::argv()` now).
  Re-injecting the same deletion after the fix reddens
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

### ~~The jail deny-list carries three syscalls beyond the design §12.3 roster~~ — RETIRED

**Retired in the docs/81 pass (2026-08-15): superseded, nothing left to deviate from.** The design
folded `reboot`/`swapon`/`swapoff` into §12.3 at v31 and v32 carries them; `DENIED_SYSCALLS` and the
roster now agree name-for-name in both directions, and the at-site comment in `vmm/jail.rs` says so
instead of describing a gap. The full retirement is in the docs/81 section at the end of this file.
The original record, kept for provenance:

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
  property is therefore gated by its own source scan in each backend. ~~The unpaced `start` survives as
  a `#[deprecated]` shim… Delete it at the next `vmcell` version bump.~~ **DONE** on the 0.22 → 0.23
  edge (2026-08-20 loose-end pass, Tier C): both shims are deleted under both `experiment-fuse` arms,
  so reaching for the shorter name is a compile error rather than a deprecation warning. The recorded
  measurement held on the real edge — `cargo semver-checks --baseline-rev origin/main -p vmcell`
  reports "no semver update required", skipping all 254 checks because a `0.x` minor bump is the slot
  allowed to break — so the ledger entry and one new gate are the only things carrying it. See the
  wave-3 entry at the end of this file. *Deliberate narrowing:*
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

- ~~On the backends, host USB is the remaining half of the eligibility law.~~ **CLOSED** by the
  2026-08-20 loose-end pass (Tier A): `vmcell::vmm::reject_usb_host_devices_on_restore` is the one
  predicate all four `restore()` bodies now call, in two arms — the descriptor-keyed delegation, and
  the capability-independent refusal that closes QEMU, where the descriptor says `true` and the argv
  splice was real. See that pass's entry at the end of this file.
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
the operator-facing string. The copy-drift gate — landed as
`the_shell_copies_of_the_blessed_set_match_this_constant`, which `include_str!`d the `bless` recipe
and the preflight probe, and **superseded in the docs/81 pass** by
`every_setcap_copy_in_the_tree_matches_this_constant`, which walks the tree at run time (pruning
`target/`, `.git/` and the frozen `docs/historical/`) over an exact file→count roster — fails if any
copy stops naming exactly the set. The hand-listed pair claimed to read "every copy" and did not:
the cap list is spelled out by hand in **five** places, and two of them had already drifted once
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

## The CI-repair pass (2026-08-14): four red jobs, and the two gates that were quietly not gates

Every job of the `ci` workflow was failing, three of them for causes that had nothing to do with the
code under test. Recorded here because two of the four are *classes*, and because repairing one of
them would have converted three security-adjacent gates from visibly-broken into confidently-false.

### `CARGO_TERM_COLOR: always` silently disarms every pattern that parses `cargo tree`

`.github/workflows/ci.yml` sets `CARGO_TERM_COLOR: always` at **workflow** level, so it reaches
every job and every `run:` block. `cargo tree` then dims the tree glyphs — `\e[2m├──\e[0m tokio
v1.49.0` — and the reset escape, which ends in a lowercase `m`, sits between the glyph and the crate
name. Every pattern anchored on that boundary stops matching. Measured against `vmcell-daemon`,
which genuinely links tokio and hyper: **28 matches uncoloured, 0 coloured, 28 coloured with
`--color never`.** `NO_COLOR=1` does not help — `CARGO_TERM_COLOR` outranks it (still 0).

Two instances shipped, and the reason neither was noticed is the same: `just ci` does not export the
variable, cargo auto-detects the non-TTY, and the identical predicate works locally. Local ≢ CI by
construction, which is the shape AGENTS.md rule 3 exists to prevent.

- **`examples/downstream-kernel/ci-check.sh`** built its "vhost absent from the graph" fixture with
  `grep -vE '^[^a-z]*vhost(-user-backend)? v'`. Under colour that filter removed **0 of 3** lines, so
  the fixture was byte-identical to the real tree, the predicate found the patched vhost in it, and
  the leg failed with `output does not match /check not applicable/` — a message that names the
  assertion rather than the broken setup. This was the whole of the `example-downstream` failure.
- **The three lean-member host-stack bans** (guest PID-1 agent, the capability-holding test-runner,
  and `vmcell-privilege`, which the runner *and* the daemon link) matched nothing in CI. They passed
  while proving nothing, from 2026-06-25 until this pass. The tree is in fact clean — verified by
  hand at this commit — but anything that leaked in during that window would have shipped unnoticed.

**Fixed at the producer, not the consumer.** A regex taught to skip ANSI would leave the next derived
fixture to rediscover the trap, so `--color never` goes on the `cargo tree` invocation instead. The
six inline copies of the lean-member pipeline (three in `ci.yml`, three in the `justfile`) collapse
into one `scripts/check-lean-tree.sh`, which both callers now invoke — one law, and `just ci` ≡ CI
by construction. Its self-test, `scripts/test-check-lean-tree.sh`, **exports
`CARGO_TERM_COLOR=always`** and asserts the predicate still rejects `vmcell-daemon`: a self-test run
in a plain dev shell would have passed against the broken predicate, which is exactly how six copies
stayed green while proving nothing. `scripts/ban-uncolored-cargo-parse.sh` is the class gate.

`.github/workflows/fuzz.yml` was **checked and deliberately left alone**: it sets no such env, and
`cargo fuzz list` prints through cargo-fuzz's own `list_targets()`, not cargo's renderer. It also has
no `--color` flag to add — `List` carries only `--fuzz-dir` — so a defensive one would abort the loop
on an unexpected argument and fuzz nothing. The empty-list hazard is covered by a target-count
assertion instead.

### The broker's P2 web-stack exclusion could not fail

`cargo tree -i <pkg>` exits **101** with `did not match any packages` on **stderr** when the package
is absent. Both copies of the exclusion (`ci.yml`, `justfile`) tested only whether stdout was
non-empty, with `2>/dev/null`. "Absent" and "cargo could not answer" were therefore indistinguishable:
a rename, a stale lockfile, or an ambiguous spec (`-i tokio` really is ambiguous in this workspace)
all read as GREEN. A negative security gate guarding P2 — the rule that the network-input server
stack never shares the cap-holding process — with no way to fail.

`scripts/check-broker-lean.sh` separates absent / present / cargo-could-not-answer, and carries the
positive control AGENTS.md requires beside a negative security result: the same `-i axum` probe must
find axum in `vmcell-daemon`, which links it by definition. Its self-test drives all four arms, and
reddens against the old inline form on two of them.

### `actionlint` is not an install-action tool, at any version

The `lint` job died at `taiki-e/install-action` with exit 76 and **skipped all 20 gates below it**,
from 2026-07-05 until this pass — so `clippy`, `cargo-deny`, `rustdoc`, the ban scripts, the
feature-powerset and the rest have never run in GitHub Actions on this repo. install-action has no
`manifests/actionlint.json` at v2.82.8, at v2.85.13, or at any tag (absent from the recursive tree,
from `TOOLS.md`, and from the CHANGELOG); `actionlint` is a Go binary from `rhysd/actionlint`, not a
crates.io crate, so the default `fallback: cargo-binstall` resolves nothing.

**The pin bump is not the fix** — a stale premise worth recording, because it is the obvious one and
it is wrong. Dependabot PR #20 (v2.85.11) was already run: run `31583296437` printed the identical
`install-action does not support actionlint … actionlint is not found`. actionlint is now installed
from its own release, version- and **sha256-pinned**, with `--version` as the fail-loud presence
check. `fallback: none` on the install-action steps is the class fix: an unsupported tool name now
fails *at the name* instead of detouring through binstall — and the action stops being handed
`github.token`, which it only forwards for that fallback. It is applied to the three `ci.yml` sites
and deliberately **not** to `fuzz.yml`, whose `cargo-fuzz` has no manifest either and reaches
crates.io through the binstall fallback successfully.

### `public-API semver` could never have run

The lint job's checkout took the default `fetch-depth: 1`, so `--baseline-rev
${{ github.event.pull_request.base.sha }}` names a commit that is not in the object store and
`cargo-semver-checks` exits 101 on `couldn't parse revision`. Invisible until now because the step is
PR-only and the job died at the tool install on every PR. Fixed with `fetch-depth: 0`.

### The fuzz workflow has never fuzzed anything

`rust-toolchain.toml` pins `channel = "1.96.1"`, and a toolchain **file** outranks `rustup default`,
which is all `dtolnay/rust-toolchain@nightly` sets. Every run since the workflow landed — 41 of 41,
from 2026-07-05 — therefore invoked `cargo fuzz` on stable rustc and died on `-Zsanitizer=address`
before building a target. `RUSTUP_TOOLCHAIN: nightly` is the env-var override that outranks the file,
and a one-second `rustc -vV | grep -q '^release: .*-nightly'` assertion now names the cause instead
of leaving it to a sanitizer error wall. Expect the first genuinely-nightly run to surface real work:
nothing in `fuzz/` has ever been compiled by CI.

### `test-integration` had never run at all — and did not need a self-hosted runner

`runs-on: [self-hosted, linux, kvm]`, and `gh api repos/pwnall/vmcell/actions/runners` returned
`total_count: 0` — no such runner was ever registered, in any of the runs GitHub retains. The job was
never assigned, sat queued for the 24-hour limit, and reported as cancelled. The entire privileged /
daemon / unprivileged / live-downstream matrix was CI-invisible for the repo's whole history.

**It now runs on a plain `ubuntu-24.04` hosted runner.** The premise that it could not was never
tested; probing it took one workflow. What a hosted runner actually provides (image
`ubuntu-24.04 20260810.271.1`, 2026-08-14):

| facility | hosted runner | what it took |
| --- | --- | --- |
| `/dev/kvm` | present, `root:kvm 0660` | a udev rule (`MODE="0666"`), then assert openability |
| nested virt | `kvm_intel.nested = Y` | nothing — the `nested_virt` legs are real |
| sudo / `setcap` | passwordless, works | nothing — `just bless` is unmodified |
| cgroup delegation | own cgroup NOT delegated | `systemd-run --user --scope -p Delegate=yes` |
| user namespaces | `unshare -Urn` blocked by AppArmor | nothing — same as the dev box; the product does not use them |
| filesystem | ext4, no reflink | nothing — `reflink_or_copy` treats a full copy as success |
| backends | only `qemu` | install CH + FC (pinned static releases), `virtiofsd`, `vhost-device-vsock` |
| host shape | 4 cores, 15 GiB RAM, 87 GiB free | cold kernel + rootfs build measured at **14m46s** |

Measured on the first green run: unprivileged **4/4**, privileged **156/156 in 312 s**, daemon
**14/14**, downstream live green (`/proc/config.gz` round-tripped 4373 symbols in-guest). Identical
counts to the maintainer's box (156/156 in 300 s there), with **8 recorded capability skips, all
backend honesty** — Firecracker's `unprivileged_vhost_user_net` ×4, `nested_virt` ×2,
`virtio_fs_shares`, and QEMU's no-designated-USB-device — and none from a missing host facility.
Zero coverage loss.

Two findings the move surfaced, both of which the self-hosted runner had been hiding:

- **`just test-privileged` never carried a delegated-scope wrapper.** `test-daemon`'s recipe has one;
  the privileged recipe and the CI step did not, so they silently depended on the runner's own cgroup
  being delegated. That is the most self-hosted-shaped assumption in the job, and it fails as three
  `metrics_limits` panics deep in a run rather than as a stated precondition. Every live suite is now
  wrapped in CI.
- **`vhost-device-vsock` is not optional.** It is spawned by bare name from `vmcell-qemu` and is the
  *default* QEMU vsock transport (`uses_in_kernel_vsock` returns `cfg.snapshotting` on `Auto`), so
  every non-snapshotting QEMU leg needs it. The README filed it under "only needed for the QEMU
  unprivileged-vsock path"; corrected there.

Also corrected while establishing this: the artifact build does **not** use a builder micro-VM — the
CLI defaults to `RootfsSourceKind::Oci`, which is host-native, so that step needs no KVM at all.

Still local-only, and now stated in the README rather than implied: `just test-crosvm` (no prebuilt
crosvm binary or Debian package, so it is a source build) and `just test-usb-passthrough` (needs a
designated physical device via `VMCELL_TEST_USB_DEVICE`; without one the privileged suite records the
capability skip counted above).

### `HostEnv::hermetic()` is hermetic in its allocators, not in its host effects

The `test-unit` job's 21 failures were all one line: `hermetic()` wires the real sysfs
`DefaultCgroupFs`, so every fake-VMM `MicroVm::start` through it reaches `setup_env`, which composes
`<base-from-/proc/self/cgroup>/<prefix>-vm-<vmid>` and `create_dir_all`s it under `/sys/fs/cgroup`.
A systemd **user** session is delegated, so that succeeds on a developer box; a GitHub hosted runner
sits under `system.slice/hosted-compute-agent.service`, which is not, so it returns
`Cgroup("create cgroup …: Permission denied (os error 13)")`. 9 lineage + 6 orchestrator + 4 zygote
+ 2 validator tests were red there and green here, for weeks.

**`hermetic()` is left semantically untouched, and that is the load-bearing decision.** It is not a
test-only constructor: 15 of its call sites are shipping code — `vmcell run`, both artifact builders,
`bench-vm` (9 modes), and `vmcell-artifact-validator`'s `try_start_vm`, which is named contract
surface. Defaulting it to an in-memory cgroup seam would silently un-confine every VM those five
binaries start, and would turn the validator's `metrics.usage_readable` check into a fabricated PASS
(`FakeCgroupFs::read_stats` returns modelled counters, `mem_limit_enforced: true` among them). A
feature that silently changes semantics is exactly what AGENTS.md forbids; this would have changed
them for out-of-repo consumers too, invisibly to `cargo semver-checks`.

Instead `vmcell` gains a `#[cfg(test)] pub(crate) HostEnv::for_unit_tests()` — `hermetic()`'s
allocators over the existing `#[cfg(test)] FakeCgroupFs` — and the 48 in-crate unit-test sites use
it. The other two host seams stay real deliberately: `ReflinkOverlayStore` really writes (the lineage
`create_dir_all` was invisible to every fake-driven test until it wasn't), and `RealClock` is what
the post-restore resync reads. Only the cgroup seam is swapped, because it is the only one that
needs a *privilege* the host may not have granted.

**`hermetic()` is `#[cfg(not(test))]`, which is the gate.** A future lib unit test that names it is a
compile error pointing at `for_unit_tests()`, rather than a green-here/red-in-CI landmine. Integration
tests under `crates/vmcell/tests/`, doctests, and every downstream crate link the non-test lib and are
unaffected, so the public API and `cargo semver-checks` do not move.

The two `vmcell-artifact-validator` failures could not be fixed at the test site: both went through
`harness::try_start_vm`, which builds `hermetic()` internally and exposes no cgroup seam. `try_start_vm`
is deliberately unchanged — the live battery needs the real seam — and the two tests call
`MicroVm::start` over a local no-op `TestCgroupFs`. *(Stale as of the docs/81 pass: the local copy
was the recorded shape only while exposing `FakeCgroupFs` was believed impossible. All four copies
are gone — the fake is `pub` behind the non-default `test-support` dev-feature. See the retirement
above and the docs/81 section below.)*

**Gates, both proven red-on-inverse before landing.**
`orchestrator::tests::unit_test_env_start_creates_no_slice_in_the_host_cgroup_tree` starts a VM on
`for_unit_tests()` and asserts no directory by the composed slice name exists under `/sys/fs/cgroup`,
with a `RecordingCgroupFs` control proving the product really would have created one (absence of a
path nobody names proves nothing). It fails in *both* environments on the un-fixed code: on a
delegated box the slice really appears (verified: it named
`…/tmux-spawn-….scope/vmcell-vm-232`), and on a non-delegated one `start` fails outright.
`just test-unit-undelegated` is the local mirror of the runner condition — `bwrap` binds an
unwritable directory over `/sys/fs/cgroup` while `/proc/self/cgroup` still reports the real base.
Measured: 782 tests, 21 failures before, 781/781 after, with exactly one test excluded by name
(`apply_jail_sets_no_new_privs_and_the_core_rlimit`, whose own red-on-inverse control is defeated by
bwrap's process-wide `no_new_privs` — a harness artifact, green unwrapped and on CI).

**One law, and the coverage that moved.** The `{base}/{leaf}` composition moved out of `setup_env`
into `metrics::vm_slice_name` so the gate can name the slice without holding a second copy of the
rule it exists to police. And the effect those 21 tests were *incidentally* covering — a real,
nested `create_dir_all` of a `{base}/{leaf}` name — is now explicit and delegation-free in
`metrics::tests::test_create_slice_at_creates_a_nested_sibling_slice` (red on `create_dir`, and red
if the delegation check stops reading the leaf's parent). Real `/sys/fs/cgroup` enforcement and
readback remain where they always were: the live `tests/metrics_limits.rs` battery,
`tests/lifecycle.rs`'s residue check, `just test-daemon`'s `limits_enforced` leg, and the validator's
`metrics.usage_readable` Extended arm.

Not fixed here, and worth naming: `MicroVm::start` refuses to boot on a non-delegated host even when
`ResourceLimits::default()` requests no limit at all. That is a real product restriction — `vmcell
run` cannot work on a hosted runner — but tolerating `EACCES` would make a *requested* limit silently
unenforced, which is the §7.2 failure the fail-loud contract exists to prevent. The two questions are
kept separate.

### The rootfs cache-key flake: a named mechanism, not "environmental"

`artifact::rootfs::tests::test_rootfs_cache_key_order_independent` failed once on a hosted runner
with two unequal hashes, having passed locally and on the previous CI run. AGENTS.md's rule applies —
a flake explanation without a mechanism stays open — so here is the mechanism, confirmed by
reproducing it deterministically.

Every rootfs cache key folds the deployment CA's PEM (`fold_rootfs_injection_identity`), and
`CaManager::new()` reads it from the process-**global** artifacts dir, minting it when absent. Its
cache and lock are process-global; nextest gives every test its own **process**; so on a cold
artifacts dir hundreds of test processes race to materialize the same pair. The pair is published as
**two renames** (`tls.rs`: `rename(key_tmp, ca.key)` then `rename(cert_tmp, ca.pem)`), and a process
that looks between them sees `cert_exists != key_exists` and gets the deliberate

    partial CA in <dir>: ca.key present but ca.pem missing

refusal. The fold turns that into `ca-read-error:…`, and errors are **not** cached — so the very next
call in the same process folds the real PEM instead. Two keys computed either side of that window
differ for a reason that has nothing to do with what the test asserts. Reproduced exactly by seeding
an artifacts dir with only `ca.key`.

The same race then reddened a SECOND test on the next run — `oci::tests`'s
`test_oci_pull_cache_hit_reverify_and_tamper`, as a bare `Io(NotFound)` out of the pack tail. That
test's own comment had already named the cause and called it out of scope ("the pre-existing NET-4
TOCTOU in `tls.rs`"), mitigating it by consolidating into one test — which stops that test racing
*itself* and nothing else. Two symptoms, one cause: chasing them per-test is whack-a-mole that
leaves CI flaky.

**Fixed at the source: `new_in` now takes a cross-process `flock` on `<dir>/.ca.lock`** for the whole
generate-or-load. The process mutex above it serializes threads; this serializes processes, which is
the half that was missing. With writers serialized, the partial-CA refusal keeps exactly the meaning
it was written for — a pair still half-present once the lock is held was left that way by a crash,
not by a racer mid-publish — so the fail-loud is preserved, not weakened.

The lock is `crate::fs::FileLock`, extracted from `artifact`'s `BuildLock` so there is **one**
cross-process file lock rather than two copies of the same primitive; `fs` is gated on `host-common`,
exactly the feature set that brings in `nix`, so both callers reach it without widening any
dependency. Lock order is process-mutex → flock, and `.build.lock` is always acquired outside this
one, never within it, so they cannot cycle.

**Proof, both directions.** The natural window is two renames wide, so racing real processes at it is
not a reliable gate: 12 concurrent processes against a cold dir produced 0 failures with or without
the lock. Widening the window artificially (a temporary sleep between the renames) made it decisive —
**6 of 12 processes took the refusal without the lock, 0 of 12 with it.** The permanent gate asserts
the mechanism instead of the timing: `ca_publish_is_serialized_across_processes_by_the_ca_lock` holds
`.ca.lock`, proves `new_in` blocks, releases, and proves it then completes. Deleting the
`FileLock::acquire` line fails it immediately.

`stabilize_ca()` in the rootfs tests is kept as well. It is now belt-and-braces rather than the fix,
and it still earns its place: it turns a *genuinely* half-committed CA into a named failure at the
top of the test instead of a mystified hash mismatch further down.

# The docs/81 review pass (2026-08-14)

`docs/81-claude-opus-code-review.md` reviewed the tree at `7499cba` across fourteen disjoint areas
with a separate adversarial verifier per area; 76 unique defects survived verification (13 major, 48
minor, 15 note), and every live suite was run on this host (privileged 156/156, unprivileged 4/4,
daemon 14/14, crosvm 30/30, `just ci` green). The review itself appended three entries here — places
where the **code is right and a document is stale** — plus one prior entry the design had superseded.
Everything from "As built" onward is the **fix waves'** reconciliation. The defects themselves are in
docs/81 and are not repeated here; this file records the deviations, the shape shifts, and the gaps
left open.

**The three review-appended entries below are now CLOSED as design-text items.** Design v32
(`docs/82-claude-opus-design-v32.md`) folded all three corrections into §3.2, §11.2/§15.5 and §11.4,
so nothing in the document still disagrees with the code. They are kept for provenance — a reader who
finds the old text in `docs/historical/79-claude-fable-design-v31.md` needs the reconciliation — not
as live deviations.

## Recorded (justified): the session mux's writer is a channel, not an `Arc<Mutex<SplitSink>>`

Design §3.2 sketches `SessionMux { /* writer sink (Arc<Mutex<SplitSink>>) … */ }` and `Session { … a
clone of the writer sink }`, and states in prose that "Writes from all `Session` handles + the mux go
through one `Arc<Mutex<SplitSink>>`". The shipped mux holds no mutex over the sink:
`agent/session.rs:149-156` is `SessionMux { write_tx: mpsc::UnboundedSender<Bytes>, registry,
next_id, reader, writer }`, `Session::send` is a `write_tx.send(frame)`, and the sink is owned
**solely** by `writer_task(mut sink: FrameSink, …)`.

**The code is right and should not move.** A single owning writer task satisfies law C4 (one writer
per connection) exactly as a mutex would, without holding a lock across an `await` — and the pure-sink
`writer_task` shape is what the docs/78 M1 fix depends on. The notes name `write_tx`/`writer_task` in
passing but never record the departure from the sketch, so a reader reconciling §3.2 against the code
finds an unexplained mismatch in the one place law C4 lives. Recorded here; design §3.2's two sites
(the struct sketch and the prose sentence) are corrected at the next reissue.

## Recorded (justified): the runner's transition drops uid BEFORE raising ambient

Design §15.5 states the runner as "file-caps → raise the three caps into the **ambient** set → drop to
the invoking uid → `execvp`", and §11.2 repeats it as "file-caps → raise ambient → drop to the dev uid
→ `execvp`". **The shipped order is the inverse, deliberately.**
`vmcell-privilege/src/lib.rs:414-478` sequences uid drop (`setresgid`/`setgroups`/`setresuid`) →
inheritable add → `shrink_bounding_set_live` → `capctl::ambient::raise` → trim, and the doc comment at
`:414-416` declares that ordering security-critical: on the `setuid`-root fallback path, raising
ambient before the uid change would carry capabilities across a uid boundary that
`setresuid` is entitled to clear.

The design text is backwards, not the code. Also worth stating because §15.5 implies otherwise: on the
**default file-cap path** there is no uid to drop to — the runner already runs as the invoking user —
so the drop is a no-op there and the ordering matters only for the `setuid` fallback. That fallback is
never provisioned by this repo (`just bless` grants file caps), which is why the ordering has no live
gate; docs/81 m26 records the missing gate as a separate, latent item.

## Recorded (justified): the daemon's start-up sweep is cross-process liveness-blind

Design §11.4 says of the start-up sweep: "(Nothing is live at start-up, so the empty set can never
sweep a resource in use.)" That parenthetical is false on a host running **more than one process with
the same `resource_prefix`**. `vmcell-daemon/src/sweep.rs:24-32` drives `sweep_orphans` with two empty
`BTreeSet`s, and `sweep_orphans` (`orchestrator.rs:2120-2206`) deletes every scanned
netns / segment-netns / cgroup-slice / scratch-dir whose trailing id is absent from those sets — it
consults no `/tmp/vmcell-vmid` claim file, and `scan_scratch_dirs` filters on the `<prefix>-vm-` name
prefix only, **discarding the pid embedded in the name**. So a starting daemon reaps a concurrently
live sibling's resources if they share a prefix.

**The behavior is acceptable and stays.** The design's own answer to multi-tenancy is `F2`'s prefix
isolation — "two daemons with distinct prefixes never sweep each other's resources", validated on KVM —
and the sweep is what makes a hard-killed daemon self-heal, which is worth more than same-prefix
concurrency. The sibling blindness in `clean_vmcell_netns` is already recorded; this call site was not.
What is recorded here is the scope: **the guarantee is per-prefix, not absolute**, and §11.4's
parenthetical over-claims. The obvious future fix is the one already named for the test sweeper — seed
the live sets from the two claim dirs (an id whose `<id>.lock` names a live `/proc/<pid>` is live) and
skip a scratch dir whose embedded pid is alive — but note it can only ever cover `HostEnv::shared()`
callers, since a hermetic allocator writes no claim file.

## Retired: the jail deny-list's three "carry-over" syscalls are no longer a deviation

`vmm::jail::DENIED_SYSCALLS`' `reboot`/`swapon`/`swapoff` were recorded as deliberate additions
*beyond* the design §12.3 roster, to be folded in "at the next revision". **The design already folded
them in** — v31 did, v32 carries it — so there is nothing left to deviate from. Both the at-site
comment and the earlier entry in this file are retired; that entry is marked in place, under "The two
docs/78 fix waves (2026-08-14), as built", with its original text kept for provenance.

Verified against the tree, not from the review: the const and §12.3's roster block are the same 21
names in both directions (a `diff` of the two sorted extractions is empty), and
`jail::tests::deny_list_is_exactly_the_documented_set_and_compiles` proves it the way that matters —
it **parses** the roster out of whichever non-historical `docs/*.md` carries the §12.3 heading, so it
is neither comparing the const to a second transcription of itself nor pinned to the design's
filename. `cargo test -p vmcell --lib vmm::jail` → 4 passed. The version that had pinned a copy *of
the const* stayed green while the shipped list silently lacked `process_vm_readv` (docs/78 M15); the
sibling `the_roster_parser_errors_rather_than_reading_an_empty_table` is what keeps the parse from
passing vacuously.

The at-site comment now states the roster agreement and keeps the "never drop one to match a doc"
instinct, which is still the right one.

---

# As built: the docs/81 fix waves (2026-08-15)

The waves landed as one breaking release. **The changelog is not here**: every consumer-visible edge
is ledgered in the crates' own `Cargo.toml` comment changelogs, which is where the version fact is
produced (§10.4) — `crates/vmcell/Cargo.toml` and `crates/vmcell-artifact-validator/Cargo.toml` are
the two contract-surface ledgers, and `vmcell-protocol` and `vmcell-broker` bumped alongside. Read
them for *what changed for a caller*. What follows is what those ledgers cannot carry: the choices
between two admissible fixes, the shifts away from a sketched name or shape, and the gaps left open.

## The `Egress::Blocked` decision: HONOR it, not reject it

docs/81 M1 offered two fixes and required the choice be recorded. **(a) was chosen: `Blocked` is
honored on both datapaths.** The rejected (b) — refuse the variant at `build()` — would have made
`Egress` a two-variant enum in practice while leaving a public, `#[non_exhaustive]`, DTO-carried
variant that every consumer can still name; a config surface whose third option is a typed error is
worse documentation than one that works.

Two predicates carry it, each `match`ing exhaustively so a future variant is a compile error rather
than a fall-through into the most permissive arm — which is precisely how the defect happened
(`Blocked` shared `Open`'s empty else-path):

- `orchestrator::privileged_egress_rules` → `PrivilegedEgressRules::{Tproxy, Blocked, NoRules}`.
  `Blocked` emits the accepts-nothing ruleset (the TPROXY shape minus both accept rules).
- `orchestrator::nat_egress_plan` → `(forward_ports, NatEgressPolicy)`. `Blocked` registers **no**
  forward port and passes `NatEgressPolicy::Deny`, so the NAT never dials a host target.

Both were split out of `setup_env` *for testability*, and that is the deviation worth naming: neither
decision is reachable from a unit test in place — `setup_env`'s privileged arm builds its namespace
through the real `RtNetlink`, and its unprivileged arm cannot be driven with a recording NAT. A law
that can only be observed live is a law with no KVM-free gate, and the M1 defect was exactly a
routing decision.

**A partial (b) landed as well, and is the smaller, honest half of it.** `VmConfigBuilder::build`
rejects `NetConfig::Unprivileged { egress: Egress::Blocked, host_services_port: Some(_) }` naming
both fields: the port names a host endpoint the guest dials *out* to, which `Blocked` refuses, so the
pair is unhonorable rather than merely unusual (F1). Making it *unrepresentable* — the stronger move
delta 4 made for the privileged arm — would mean moving the port onto the `Egress` variants, and
`Egress` is public, `#[non_exhaustive]`, shared by both datapath arms and matched in the CLI, the
daemon DTOs, the bench harness and the example workspace, none of which have a port to give. A
contract break across the whole consumer surface to encode one pair is the trade that was declined;
the boundary check is what shipped, with the rationale at the site.

## Shape shifts from a sketched name or signature

- **`Netlink::setup_tap` returns `Result<()>`, not `Result<Option<tun_tap::Iface>>`.** The old return
  was always `Ok(None)` and read by nobody, while forcing every out-of-tree implementor of this
  ledgered seam to depend on `tun-tap` (which `vmcell` does not re-export, so the pin had to be
  guessed) and teaching them to hold the tap fd open — the one thing that breaks single-opener
  discipline. Breaking, and invisible to `cargo semver-checks` (it has no return-type lint), which is
  why it is hand-ledgered. **Retired half:** this entry, and the `0.13.0 → 0.14.0` ledger edge in
  `crates/vmcell/Cargo.toml`, both said `vmcell-broker`'s zero-dev-dependency posture was *the*
  living gate against the type coming back. That was true while `vmcell` still carried the
  dependency — the broker's fake was then the only thing that could not name it. Since the `tun-tap`
  removal the crate is out of the graph entirely, so `cargo check -p vmcell` fails first and
  `deny.toml`'s by-name ban keeps it out transitively; the broker's posture is still worth holding
  for the *next* type a seam might leak, but it no longer discriminates. The ledger edge is a record
  of a shipped release and stays as written; this entry is the live one, so it is corrected here.
- **The QEMU argv composer is `qemu_launch_plan`, returning `vmcell::vmm::LaunchPlan`** — not
  `build_qemu_command` returning a `Command`. Command and jail posture now travel together from
  composition to exec, so no step can substitute either half; `LaunchPlan::jail` is private, so the
  two-line defeat (`plan.jail = …`) is a **compile error**, not a gate failure. FC and CH return the
  same shared type. **crosvm deliberately keeps its own `CrosvmLaunchPlan`**: it must wrap
  `effective_jail_config` (crosvm's `Enforcing` turns the Layer-2 deny-list on instead of a minijail),
  which the shared type has no place for. Two production `jail_spec_from_config` call sites remain,
  one inside each plan constructor (`vmcell::vmm::LaunchPlan::build`, `CrosvmLaunchPlan::build`) —
  verified by grep across all four backends; every other match is inside a `#[cfg(test)]` scan module.
  All four backends carry both halves of the treatment (a plan constructor holding the whole composed
  command, plus a source scan pinning the call-site counts); crosvm's scan is named for its own plan
  type rather than `jail_composition_gate`.
- **`reject_unadvertised_capabilities` is one shared law with per-backend name-binding wrappers.** It
  landed as three byte-identical copies differing only in the `vmm` string. The hoisted
  `vmcell::vmm::reject_unadvertised_capabilities(vmm, caps, cfg)` covers `nested_virt` and
  `lazy_restore`; all four backends keep a private one-line wrapper whose only job is binding their
  own name once. Both branches key off the `VmmCapabilities` value **handed in**, never a hardcoded
  `false` at the refusal site, so flipping a flag flips its refusal with it. Called from `create()`
  **and** `restore()`.
- **`Zygote::suspend` owns the snapshot-destination law** through one `prepare_snapshot_dest`:
  create-with-parents when absent, accept an existing but empty directory, refuse a populated one.
  `Lineage::fork_from_vm` and `branch` delegate and keep no `create_dir_all` of their own — see the
  retirement of entry (e) above, which recorded the opposite arrangement.
- **`metrics::vm_slice_name` is `pub` and re-exported as `naming::vm_slice_name`.** It is the **full**
  slice name; `naming::cgroup_slice_name` is only its leaf. (docs/81 §7.3 names the wrong one of the
  two for the harness — the harness routes through `vm_slice_name`; the tree wins.)
- **`FakeCgroupFs` is `pub` behind the non-default `test-support` feature**, taken as a
  **dev**-dependency by the three backend crates and the validator, replacing four hand-rolled
  `TestCgroupFs` copies. The blocker recorded in this file — the fake's `.lock().unwrap()`s tripping
  `deny(clippy::unwrap_used)` outside `cfg(test)` — was removable: the class routes through one
  `state()` helper carrying a single `#[expect(…, reason = …)]`. Feature unification is the real
  hazard here (under `--all-targets` the fixtures become visible to the lib target too), so
  `scripts/ban-test-support-in-production.sh` is the backstop, not the `cargo build` behavior.

## Deadline budgets that became named constants

- **`vmcell::vmm::VMM_SOCKET_READY_TIMEOUT_MS`** is the one VMM control-socket readiness ceiling. It
  is deliberately **not** a parameter: `register_and_await_ready` lost its `timeout_ms` argument (a
  breaking edge) so a backend cannot spell the ceiling as a literal again. The genuinely per-VM half,
  `interval_ms`, is still a parameter.
- **QEMU's `SMOLTCP_SOCKET_READY_TIMEOUT_MS`** is QEMU's one readiness wait that is *not* on that
  ceiling, named for the same reason rather than folded into it: the producer differs in kind (an
  in-process NAT thread, no child to fail fast on) and the wait is wider.
- **The snapshot budget is adopted as `max(own_floor, shared_predicate)`, not as a replacement.**
  crosvm: `control_budget.max(vmcell::vmm::snapshot_request_timeout(mem_mib))`. QEMU:
  `MIGRATION_BUDGET.max(snapshot_request_timeout(mem_mib))`, and QEMU's 120 s floor deliberately
  stays — its migration is not a single dense write but iterative dirty-page passes with a
  `query-migrate` poll round-trip per iteration, which a pure write-throughput model does not capture.
  QEMU's crossover is 7361 MiB (≈7.19 GiB) — the smallest `mem_mib` for which
  `CONTROL_REQUEST_TIMEOUT + ceil(mem_mib / SNAPSHOT_MIN_WRITE_MIB_PER_SEC)` exceeds the 120 s floor,
  i.e. `5 + ceil(7361/64) = 121 > 120`. Above it the shared predicate takes over, which is the
  multi-GiB case the shared predicate exists for. (Recompute from the three constants rather than
  quoting this figure if any of them moves.) Ordinary control ops keep the short flat budget on
  both backends, so a wedged `powerbtn`/`system_powerdown` cannot delay the force-kill behind it.

## Residual gaps, deliberately left open

- **`VmConfig`'s fields are `pub`, so `build()`'s validations bind the BUILDER, not the struct.** A
  caller can reach the rejected `Unprivileged { egress: Blocked, host_services_port: Some(p) }` state
  by assigning `cfg.net` on a built config — `#[non_exhaustive]` blocks the out-of-crate struct
  literal, not field assignment. This is stated in the ledger and exercised, not merely admitted: the
  M1 live leg assembles `cfg.net` directly, precisely so the two legs differ in exactly one field
  **and** so the datapath's own refusal (no forward port, `NatEgressPolicy::Deny`) is what is
  observed rather than the boundary check. Defense in depth is the answer here, not a stronger type.
- **Under `Egress::Open` with `host_services_port: None`, an in-guest dial to the host gateway does
  not reach the host.** `Open` grants no *arbitrary* outbound on this datapath: reachability comes
  from a registered forward port, and `nat_egress_plan` registers only `host_services_port` and the
  proxy port. Empirically confirmed by the live leg's own recorded inverse — flipping only
  `NatEgressPolicy` to `Allow` does **not** redden it, because with no forward port there is no
  mapping for the NAT to dial through. So the M1 positive control needs `Some(port)`, and a reader
  must not infer "`Open` ⇒ the guest can reach the host".
- **The QEMU launch-plan conversion has no live validation in this pass.** It is argv+jail composition
  only, and every KVM-free gate is green (`cargo test -p vmcell-qemu` → 37 passed, including the
  composed-argv `-sandbox` assertion, now reading `LaunchPlan::argv()`). But `apply_jail` runs in a
  post-fork `pre_exec` window that no KVM-free test can observe — which is why the class exists — so
  the runtime claim is **unverified** until the QEMU live matrix runs.
- **Two QEMU comment sites still assert the withdrawn lazy-bind mechanism**
  (`crates/vmcell-qemu/src/lib.rs`: the `SMOLTCP_SOCKET_READY_TIMEOUT_MS` rustdoc, and the
  `wait_for_socket` call's line comment). The *ceiling* they justify is right for an independent
  reason — the producer is a thread with no early exit to fail fast on — but the "binds lazily"
  clause is the same false premise withdrawn above and should go with it.

  **Taken (2026-08-15), and the count was wrong.** Both reconciliations landed ahead of the delta
  pass. The lazy-bind claim sat at **three** comment sites, not the two quality-gates v5 counted:
  besides the `SMOLTCP_SOCKET_READY_TIMEOUT_MS` rustdoc and the `-chardev` composer comment, the
  `spawn_qemu` readiness-wait block carried a parenthetical naming `Listener::new` as explicitly
  *not* being the bind — exactly backwards, and the most misleading of the three. The mechanism was
  re-verified at the source before editing: `SmoltcpProcess::start` calls `Listener::new` on the
  caller's thread (`net/smoltcp.rs:883-885`) before the vhost worker is spawned. The constant and
  the wait stay, on the independent reason. The steward's core-mount comment said "EXACTLY
  {overlay, /proc, /dev}" at three sites while four mounts return `Err`; all three now state the
  four, matching design v33 §3.4.

## v33 delta 1 — the steward rename (design §18 delta 1), as built

Landed first and alone, as the register directs, so every later delta writes new API in the new
vocabulary instead of minting `Agent*` names that would immediately rename again.

**What moved.** A scripted, sentinel-protected sweep over every tracked file except `docs/` and
`AGENTS.md`, plus five `git mv`s: crate `vmcell-guest-agent` → `vmcell-steward` (lib
`vmcell_guest_agent` → `vmcell_steward`), module `vmcell/src/agent/` → `vmcell/src/steward/`,
`vmcell/src/artifact/guest_agent.rs` → `artifact/steward.rs`, `AgentClient` → `StewardClient`,
`MicroVm::agent()` → `MicroVm::steward()`, `Error::Agent` → `Error::Steward`, `GuestAgentStage` →
`StewardStage`, `AGENT_VSOCK_PORT` → `STEWARD_VSOCK_PORT`, `DEFAULT_INIT`
`/usr/sbin/vmcell-guest-agent` → `/usr/sbin/vmcell-steward`, `--agent-musl` → `--steward-musl`,
`guest_agent_src_hash`/`guest_agent_closure_hash` → `steward_src_hash`/`steward_closure_hash`, and
the validator check ids `boot.agent_ready` → `boot.steward_ready`, `agent.exec_roundtrip` →
`steward.exec_roundtrip`, `agent.put_file_roundtrip` → `steward.put_file_roundtrip`. Ledgered as
`vmcell` 0.14.0 → 0.15.0 and `vmcell-artifact-validator` 0.2.0 → 0.3.0, each entry carrying the
identifier list a consumer `sed`s.

**The gate.** `scripts/ban-legacy-terms.sh` gained seven awk branches covering fourteen retired
spellings, including `AgentPlacement` and `AgentOptions` — names that never existed, banned
**pre-emptively** so deltas 4 and 5 mint `StewardPlacement`/`StewardOptions`. `test-ban-legacy-terms.sh`
gained one MUST-flag fixture per branch and six MUST-PASS fixtures for the kept words (`AGENTS.md`,
"agentic", `AGENT-2`, `agent-ctl`, `User-Agent`/`Proxy-Agent`/`user-agent`, and an
`allow-legacy-term:` exemplar). Each of the seven branches was verified **load-bearing** by deleting
it and confirming the self-test reddens — the meta-rule, run rather than asserted. Two of the three
apparent failures on the first run of that probe were bugs in the *probe's* escaping, not gaps; the
probe was rewritten to match branch lines as fixed strings.

**Recorded deviations from a naive sweep** — each one a place where "agent" legitimately survives,
which is why the ban is identifier-shaped and not a bare-word ban:

- `vendor/vhost/docs/vhost_architecture.drawio` was **corrupted and reverted**. Its `agent=`
  attribute is draw.io's own XML slot holding the diagram author's browser User-Agent. Two rules
  caught it: the sentinel list covers `User-Agent`/`user-agent` but not a bare `agent=`, and
  `vendor/vhost*` is pinned exactly (`scripts/check-vendored-vhost.sh`). `vendor/` belongs in the
  exclusion set beside `docs/` for any future sweep of this shape.
- `.claude/review-workflow.js` and `.claude/staleaudit-workflow.js` were **reverted whole**. Their
  `agent(...)` is an undeclared workflow-runtime global — the AI sub-agent spawner, beside
  `parallel`/`phase`/`log` — so renaming it left both files throwing `ReferenceError: steward is not
  defined`. JS is not compiled, so `cargo check --workspace --all-targets` structurally could not
  see it. This is the "enumerate what the suite cannot reach" rule applied to a non-Rust file kind.
- `scripts/review-preflight-priv.sh` and its self-test say "an **agent** must ask for the bless" —
  the reviewing AI agent, one clause away from a citation of AGENTS.md rule 5.
- `crates/vmcell/src/zygote.rs`'s "a fan-out of **agent** sandboxes" is the agentic-execution use
  case, one inflection from the protected `agentic`.
- `scripts/ban-legacy-terms.sh`'s own "a hypothetical **agent-harness** testing project" is the
  replacement phrasing for the retired origin-harness name; `README.md` and the historical designs
  state it verbatim. The sweep had made the ban script quote a phrase existing nowhere, inside the
  very block that declares the ban identifier-shaped.
- The `vmcell` ledger's 0.2→0.3 and 0.3→0.4 entries still say `AgentClient`, **deliberately**: they
  record what a consumer saw *at those versions*, and rewriting them would make them false. The
  0.14→0.15 entry is the one place the old→new mapping lives, and says so.

**Shape shift from the directed sketch:** `scripts/ban-agent-ip-shellout.sh` keeps its name; only
the directory it scans moved (`crates/vmcell-guest-agent/src` → `crates/vmcell-steward/src`). It is
not one of delta 1's retired identifiers, `scripts/` is deliberately outside the ban's roster, and
two just-issued specs (rubric v7 Part E, quality-gates v5's landed-baseline roster) enumerate the
gate by that name — renaming it would put a stale roster into two live specs for no gate benefit.

**Not swept, deliberately:** `docs/` history and this file's own earlier entries. An entry naming
`artifact::tests::guest_agent_pin_is_absent_…` or quoting the old `"guest-agent binary source
missing at …"` message records what was true when written; this section is the pointer that says
every such name now reads `steward`. `docs/benchmark-results.md` **was** swept — three production
comments cite one of its headings by quoted title ("QEMU agent-timeout flake"), so leaving it would
have left three dangling pointers; its `AGENT-2` finding id survived.

**Operational trap, restated:** `DEFAULT_INIT` moved, so any `rootfs.erofs` or snapshot built before
this commit will not boot. Rebuild with `vmcell build --kernel-source host-make` — the bare default
is `prebuilt`, which silently replaces a locally built `vmlinux`.

## v33 delta 2 — the feature vocabulary and the intersection (design §18 delta 2, §7.4, F6), as built

**What landed.** `vmcell::feature` — `Feature` (nine backend variants name-for-name with
`VmmCapabilities`, plus `ControlPlane`/`XattrPreserved`/`ProcConfigGz`), `Source`, `Removal`,
`FeatureDeclaration`, `FeatureSet`, `HostDeclaration`; `Error::unsupported` and
`Error::from_removal`; `VmConfigBuilder::require(Feature)` resolved at `MicroVm::start` **and**
`restore_inner` before any resource is allocated; `MicroVm::features()`; and
`orchestrator::resolve_cell_features`, the one computation site.

**Shape shifts from the §7.4 sketch**, each for a stated reason:

- `Source::Backend` carries a `String`, not the sketch's `&'static str`. `Vmm::id()` returns a
  borrowed `&str` and every sibling axis already carries an owned label, so one representation is
  one fewer lifetime in every signature that touches a `Removal`.
- `Error::Unsupported`'s **`vmm` field is "who says so"**, not strictly the backend. §7.4 asks for
  two things that pull against each other — the shape stays two fields, *and* the removal's
  provenance is in the error — and the message template is literally `"Unsupported feature in
  {vmm}: {feature}"`, so `vmm` is the provenance slot. `from_removal` renders the bare backend name
  when the backend is the remover, which is **byte-identical to every pre-v33 site** (pinned by
  `a_backend_removal_renders_exactly_as_it_did_before_v33`), and names the artifact or host
  otherwise — because "Unsupported feature in cloud-hypervisor" would blame the backend for a
  rootfs's declaration, the exact dishonesty §7.4 exists to retire.
- `clone_ineligible_feature` returns `Option<Removal>` rather than `Option<&'static str>`, and its
  five arms became **named consts** (`INELIGIBLE_SEGMENT` and siblings). That is what let the
  zygote suite's `.contains("segment")` / `.contains("custom init")` / `.contains("USB")` become
  arm-identity equalities — see the vacuity note below.
- The sidecar's **emission** is not here. `FeatureDeclaration::load_beside` consumes
  `<artifact>.features` (the `.cache_key` sidecar's naming law, which yields §7.4's
  `rootfs-<label>.features` exactly), and an absent sidecar is the **stated baseline**. Emission is
  delta 6's, because §7.4 makes the registry entry the one authority and the sidecar its travel
  form — there is nothing to emit *from* until the registry exists. Recorded so the absence reads
  as sequencing, not as a gap.

**The vacuity trap this delta walks into, and how each leg stays discriminating.** Retiring the
prose strings means "the backend cannot snapshot" and "this config carries a vhost-user device" now
BOTH produce `feature == "snapshot_restore"`. An exact matcher alone therefore discriminates less
than the substring matcher it replaced — the substring was a weak assertion, but it was not a
*vacuous* one. Every converted leg was given back its discrimination explicitly:

- the zygote legs assert **arm identity** against the named const
  (`clone_ineligible_feature(&cfg) == Some(INELIGIBLE_SEGMENT)`), so deleting the segment arm and
  letting a sibling catch the config reddens them;
- the qemu legs pin the **two different** shared consts through a `#[track_caller]`
  `assert_is_removal` helper, compared on the rendering so editing a const moves both sides;
- the CH and FC vhost-user legs assert `vmm` carries config provenance **and** the feature is
  `snapshot_restore`, so re-keying the guard onto the descriptor reddens them;
- where neither applies, the leg is explicitly paired with the positive control that already
  existed (the eligible config on the same capable backend must be ALLOWED), and a comment at the
  site says that the refusal/success pair is now what makes it non-vacuous.

**The two gates, both verified red-on-inverse rather than asserted.**
`the_feature_intersection_has_exactly_one_computation_site` and
`no_production_site_hand_spells_a_feature_string` are Rust source-scan tests in `vmcell::feature`,
per quality-gates v5 ("call-site scans are Rust source-scan tests, not shell scripts"), so the
`gates` recipe roster — and `ban-ci-script-handcopy.sh`'s both-direction assertion over it — does
not grow. They **walk `crates/*/src` at run time** rather than `include_str!`-ing a fixed list,
because a fixed list is itself a roster that can go stale: a new backend crate would be invisible
to a hardcoded scan while being exactly where the law is most likely to be broken. Planting a prose
feature string reddens the first; planting a second `FeatureSet::intersect(` call reddens the
second; both were run and reverted.

**The sweep found a crate the survey missed.** The first run of
`no_production_site_hand_spells_a_feature_string` flagged eleven sites in `vmcell-firecracker`,
which the hand grep that scoped this delta had not turned up (its refusals are formatted
differently). That is the gate doing the job the survey could not — and it is the reason the scan
walks the tree instead of naming files.

**Deliberately NOT given `Feature` variants** (§7.4 clause 4 fixes granularity up front; a variant
that later splits breaks every declaration in every overlay): `vhost_user_socket` (a per-VM
resource, not a descriptor field), `vmm_seccomp`/`seccomp_log`, and `boot_after_restore` — the last
being an API-state refusal, not a capability absence. Each keeps a **single snake_case token**,
never prose, so a caller matches it exactly; the sweep enforces that shape on them too, and each
site carries a comment saying not to "fix" it into a variant.

## v33 delta 3 — the two-directional conformance kit (design §18 delta 3, §10.6), as built

**What landed.** `CheckStatus` grew `Warn(String)` and `Unverified(String)`;
`ValidationReport::warnings`/`unverified`; a new `conformance` module (`ArtifactId`,
`ConformanceSubject`, `ProbeOutcome`, the `FeatureProbe` seam + `LiveProbe`, `probe_plan`,
`conformance_check_id`, `Substrate`, the pure `judge`, `ConformanceOptions`, the typed
`ConformanceError`, `run_battery`); the records-or-skips-on-every-path refactor with
`CORE_CHECK_IDS`/`EXTENDED_CHECK_IDS`/`FULL_CHECK_IDS` and a `fill_unrecorded` tail per level; the
rustdoc roster gate extended to Core and Extended through one shared helper; and `Warn`s routed
through the classifier (`explain_underclaim`, `explain_broken_claim`, `explain_undecidable`).
Ledgered `vmcell-artifact-validator` 0.3.0 → 0.4.0 — a bump `cargo semver-checks` **caught rather
than a consumer did**, which is the §10.4 rule working exactly as written.

**`into_result()` is unchanged, and that is now pinned.** The two new variants would be worthless if
they quietly moved a consumer's pass/fail decision, so `into_result_is_fail_only_across_all_five_states`
asserts a report carrying Warns and Unverifieds but no Fail still returns `Ok(())`, with a Fail added
as the positive control.

**Resolved conflicts between §10.6's text and the tree**, each a decision rather than a drift:

- **"substrate cannot exercise it → Skip" vs "declaring on an incapable backend → Fail naming the
  backend."** These read as contradictory and are not: they differ *by direction*. A
  declared-**present** feature the backend's own descriptor removes is decidably contradicted →
  `Fail` with §7.4 provenance (the four-leg matrix's leg 2). A declared-**absent** claim on a
  substrate that cannot exercise it is unmeasurable → `Skip`, exactly as §10.6 says. Both arms are
  tested.
- **The probe had to become a seam.** The shipped probe (`snapshot_restore_roundtrip`) needs a real
  guest handshake, so against `FakeVmm` it burns its budget and can only ever answer "does not
  work" — it structurally *cannot* express `Works`, so the four-leg matrix is not expressible
  through it. The matrix therefore runs a recording `ScriptedProbe` through the real `run_battery`,
  while `FakeVmm`'s **descriptor** supplies the capable/incapable substrates; `LiveProbe`'s own
  mapping is unit-gated with `fail_create` and its *execution* by the live leg. A shift from the
  directed "drive it with `FakeVmm`", recorded here per the register's convention.
- **"Deleting the control reddens the roster" needed a second mechanism.** With the control and the
  probe sharing ONE check id, deleting the control leaves the roster byte-identical — and
  `fill_unrecorded` would likewise turn a deleted *level* check into a permanent, innocuous `Skip`.
  That is the roster gate's own silent-weakening shape. So control deletion is caught by the leg-3
  and control-failed tests (both deletion shapes verified), and `every_roster_id_has_a_recording_site`
  — a source scan with its own scanner self-test — makes a deleted check redden instead of
  degrading to a Skip.
- **A fifth row beyond the design's four legs:** control fails → `Unverified`, never leg 3's `Pass`.
  This is what makes the pair *structural* rather than a convention: an absence probe whose control
  is broken cannot certify anything.
- **`Unverified`'s shipped instance is `Feature::NestedVirt`**, reusing the lesson recorded at
  `crates/vmcell/tests/nested_virt.rs:123-196`: `-cpu host` exposes VMX unconditionally, so the
  causal signal is the guest module parameter — which answers about the *cell's config*, not the
  artifact. There is no `/dev/kvm` check anywhere in the kit.
- **Stale-expectation scope.** An `expected_warnings` entry whose Warn no longer fires is an error
  (the unfulfilled-`#[expect]` rule one level up), but judged only against the artifact *this run
  tested* — otherwise every per-artifact run would redden on its siblings' entries.

**Report-content change a consumer will see.** Every run now also carries `boot.config` on the
success path (it was error-only, and therefore invisible to enumeration — which is what kept the
Core roster ungateable), and a stopped run emits Skips for the ids it never reached, naming the
check that stopped it. A consumer diffing a report against a stored baseline sees ids appear.

**Gates.** Seventeen red-on-inverse experiments, each run and reverted: `into_result` widened to
count Warn; leg 2 → Skip; leg 4 → Pass; the control deleted **two ways**; the budget timeout removed
(the test failed in 5.00 s on its own harness bound rather than hanging — the property the budget
exists for); a Core check's call site deleted; an id dropped from `CORE_CHECK_IDS`; each of the
three `Level` rustdocs ceasing to name an id; promotion disabled; stale-expectation detection
disabled; a hand-spelled check id; `NestedVirt` given a probe; both roster fills removed; a
no-stance judged as Pass; and `LiveProbe` mapping Undecidable → DoesNotWork.

**Live-validated:** `just test-validator` under the delegated scope, 3/3, including the new
conformance leg with real snapshot round-trips on both sides of the pair.

## v33 delta 4 — steward placement (design §18 delta 4, §3.5, invariant C8), as built

**What landed.** `config::StewardPlacement` with its two C8 methods (`steward_port`,
`resync_reachable`); `VmConfig::steward_placement`, resolved at `build()` from a derived default
(`Pid1` when `init` is `None`, `None` when `Some`); the `Pid1`+custom-init reject; AF_VSOCK reserved
port validation; the `vmcell_steward_port=` cmdline token; `STEWARD_VSOCK_PORT` single-sourced in
`vmcell-protocol`; and the seven-site re-key, health gate included.

**The port is one literal now.** `vmcell-protocol::STEWARD_VSOCK_PORT` is the only `5000` in the
workspace. `vmcell::vmm::STEWARD_VSOCK_PORT` is a `const` **bound to** it rather than a `pub use` of
it, and that is a deliberate shape shift: `cargo semver-checks` reads a const replaced by a
re-export as `pub_module_level_const_missing` — a removal — even though the path still resolves for
every consumer. Ledgering a breaking change that breaks nobody is worse than the binding, which
keeps the single literal. The steward binary imports the same const privately, retiring its
`VSOCK_PORT`.

**`MicroVm` retains the placement *beside* `control_plane_disabled`, not instead of it.** C8 is a
two-method law and a live cell needs both answers: `control_plane_disabled` is the derived
availability answer that `steward()`/`connect_sessions()` read on every call, and the retained
placement is what `snapshot()` asks `resync_reachable()` of. Collapsing them back into one field is
the violation — they differ exactly at `Service`, which has a port but no measured post-restore
resync.

**Two messages re-word, as §3.5 records.** `steward()`'s fail-loud now names
`StewardPlacement::None` instead of the init spelling, and `build()`'s snapshotting reject names the
placement. The snapshotting rule is strictly **narrower**: `Service` is refused explicitly where it
was previously unreachable via `init`, and `Pid1`+`init: None` is unchanged — worse for nobody.

**THE DISCRIMINATING LEG WAS THEATER ON ITS FIRST CUT, AND THIS IS THE RECORD OF IT.** §3.5 says the
only leg that catches a re-key back onto `cfg.init` is `Service{port}` + a custom `init`, asserting
refusal **identity**. The first version hand-built the `MicroVm` and derived
`control_plane_disabled` itself — so when the exact regression it exists to catch was planted
(`start()` re-keyed to `cfg.init.is_some()`), it stayed **green**. A green unit test standing beside
an unchanged call site: precisely the completeness-audit defect the §18 register promoted to a
convention, reproduced by the very test written to honor it. It was only visible because the plant
was run rather than the test trusted. Routed through `MicroVm::start` it reddens on the assertion
naming the derivation. Both forms were run; the comment at the site records which is which so the
next reader cannot re-introduce the hand-built shape as a "simplification".

**Two independent gates catch that same plant**, which is the point of a call-site scan existing
beside a behavioral test: the behavioral leg reddens on the wrong error, and
`c8_call_site_gate::cfg_init_is_read_only_where_init_identity_is_the_question` reddens naming the
offending line. The scan enumerates the *surviving* `init` readers individually rather than counting
them, so adding one is a review event rather than a number that drifts; after the re-key exactly
three production sites read `init`, and each is genuinely about which binary is PID 1.

**The second C8 method has its own leg.** `service_cell_snapshot_returns_the_typed_placement_refusal`
runs a `Service` cell — availability `Some`, eligibility `false` — through `snapshot()` and requires
the typed refusal, with a `Pid1` cell's successful snapshot as the positive control. Planting
`snapshot()`'s guard onto `control_plane_disabled` (the availability field) reddens it: that is the
near-miss the design's own review caught, made structural.

**Byte-identical floor, gated.** `default_placement_emits_a_byte_identical_cmdline` asserts a cell
that names no placement emits the same cmdline as one that names `Pid1` explicitly, and that the
`vmcell_steward_port=` token is **absent** rather than merely equal by luck. The token is emitted
only for a non-default port, which is what makes the floor hold; F3's `vmcell_` prefix rule already
reserves it against caller spoofing, so `RESERVED_CMDLINE_KEYS` needed no edit.

## v33 delta 5 — the steward as a library; service mode (design §18 delta 5, §3.5, invariant C1), as built

**What landed.** `vmcell-steward`'s ~2,100-line `main.rs` became a library (`options`, `assembly`,
`serve`, `exec`, `session`, `run`) plus a thin binary; `StewardOptions`/`run`; `GuestPlacement`
selected by `getpid()`; `PR_SET_CHILD_SUBREAPER` under `Service`; per-mode `SigtermPolicy`; the
`Pid1`-scoped assembly; the tracing/tools-dir/port/tuning seams; the guest-side
`vmcell_steward_port=` parse; the `mini-init` applet; and `main_is_thin_gate`.

**The code was sliced, not retyped.** Every moved body came out of `main.rs` by line range, so the
diff is a move plus the seams. That is why the 25 tests `main.rs` carried are the same 25 tests, in
`tests.rs`, and why the reservation/epoch suite the delta's gate says must "carry over intact" did.

**THE DESIGN'S OWN GATE FOR THE SUBREAPER BIT DOES NOT REPRODUCE, AND THIS IS THE RECORD OF IT.**
§18 delta 5 specifies the leg as "the double-fork exec leg **red-on-inverse by removing the
subreaper call** (the test hangs — bounded by its harness timeout — instead of returning the exit
code)", and §3.5 explains it as `wait_for` blocking on a status that will never be recorded. Built
and run both ways: **it does not hang, and `exec` returns the right code with the bit removed.** The
steward only ever waits on its own *direct* child — `handle_exec` reserves and waits the pid it
spawned — and that child is reaped in either placement. What the bit actually decides is who
inherits the *grandchild*. So the leg was rebuilt around the observable that really moves: an
orphaned descendant's `PPid`. With the bit it is the steward's pid; without it, `1` (mini-init).
Verified by planting: the `Service` leg fails naming both pids, the `Pid1` twin stays green. The
new form is also a **better** gate than the specified one — it *fails* rather than stalling, and a
stalled leg is indistinguishable from a slow box.

**Two more assertions rested on observables that do not exist**, found the same way — by running
them. The steward logs at `tracing::info!`, the guest has no `RUST_LOG`, and `tracing_subscriber`'s
default filter drops everything below `error`; so "listening on vsock port 5100" and "received
SIGTERM; powering off" never reach the serial console however much they read like console output.
Both legs now assert real data-plane facts instead: a `dial_vsock` to the default port that must
find nobody (the negative control proving the steward *moved* rather than bound both), and the
kernel's own `reboot: Power down`, which is better evidence anyway — it says the syscall was issued,
not that the steward meant to issue it. `mini-init`'s own lines are `println!` and do reach the
console, which is what leg 2 reads.

**Recorded shift: `run()` reads `/proc/cmdline`, not the binary.** §3.5's sketch says the binary
parses it. It cannot: under `Pid1` nothing has mounted `/proc` when the binary starts — the assembly
mounts it — so a binary-side read returns the empty string and would silently disable share mounts,
the tuning tokens, and the declared port. The *parse* is pure and public
(`StewardOptions::apply_cmdline`, `parse_steward_port`), which is what the sketch's testability
intent was after.

**Recorded shift: `mini-init` supervises a declared program.** §3.5 describes it as starting the
steward and nothing else. Its argv now names the program (default `/usr/sbin/vmcell-steward`),
which is *more* generic — an init that supervises a named program is the shape law G1 says a
consumer copies — and is what makes the rapid-failure cap live-testable at all: the gate boots
`mini-init -- /bin/false`, which no fixed-program init could express without a test-only hook in
PID 1.

**`mini-init` reuses the steward's assembly rather than copying it.** `assemble_guest_root` is `pub`
for exactly one caller. The alternative was a second copy of the mount sequence in guest-tools — the
duplicate-law shape AGENTS.md bans, and the tree's one deliberate guest-side duplication (the
`ifreq` layout) needed a divergence guard to stay honest. The consequence is the point: a
service-placement cell's filesystem is byte-for-byte a `Pid1` cell's, so the two placements' legs
differ in one variable.

**Two mechanisms had to be built, not parameterized.** `serve_vsock` was an unconditional `loop {}`
whose `JoinHandle` was dropped, and the `Sessions` table is per-connection and reachable from
nowhere else — so `Service`'s "stop accepting, tear down live sessions, exit" had nothing to hook.
The shutdown flag is checked at **both** loop levels (one alone leaves shutdown wedged behind the
other) and the handle is now retained and joined; `ConnectionRegistry` publishes each connection's
table under an RAII ticket. Planting `teardown_all` out reddens the C3 residue assertion naming the
surviving pid.

**Both SIGTERM arms obey the policy**, not just the primary one. The degraded fallback (registration
failed → polling reaper) converges on the same terminal `match`; covering only the primary arm would
leave a `Service` steward powering the machine off whenever handler registration happened to fail,
which is not a rare path but the path a constrained guest takes.

**Not covered, recorded:** the `Service` post-restore question stays unmeasured — `resync_reachable()`
is still `Pid1`-only (§17), and nothing here changes that. ~~`mini-init`'s restart loop has no pacing
on the *exit* path (only on the spawn-failure path), so a program that exits instantly burns the cap
in microseconds; bounded and fail-loud, but not rate-limited.~~ **CLOSED** by the 2026-08-20
loose-end pass (Tier A) — both call sites now sleep what `mini_init_restart_after` returns; see that
pass's entry at the end of this file.

**Live-validated** on the CH backend: the 6-leg `service_steward` battery green, each of the three
load-bearing gates confirmed red under a planted regression (subreaper removed, `teardown_all`
removed, `parse_steward_port` removed) and green again after restoring.

## v33 delta 6a — the registry core and the rootfs kind (design §18 delta 6, §10.5, invariant F7), as built

**Landed in three commits, not one.** §18 treats delta 6 as one item; it is a multi-thousand-line
change touching the pins schema, three producers and every fixture that seeds a rootfs pin. Splitting
it into 6a (the shared core + the rootfs kind), 6b (the `handlers` kind) and 6c (laziness + F7's
verified fetch + `features`) makes each half reviewable and independently gated, and all three land
before delta 7 so the register's ordering is intact.

**What landed in 6a.** `artifact::registry` — the one merge/sort/collision law, parameterized by
kind — with `resolve_kernel_registry` re-pointed through it; the `rootfs` map namespace with its
loud legacy-shape reject; `RootfsRegistryEntry`/`resolve_rootfs_registry`/`resolve_rootfs_labels`;
the four rootfs key/name composers; `RootfsStage`'s label; `vmcell build --rootfs-label`; the
`bundle` walk's rootfs arm; `scripts/ban-rootfs-key-composers.sh` + its self-test; and the
eight-leg `crates/vmcell/tests/rootfs_registry.rs` battery.

**The decision that made the whole reshape cheap: `rootfs.default` flattens to the UN-suffixed
keys.** `rootfs_pin_key(None, "image")` is `rootfs_image` — the exact key every pre-v33 reader
already uses. So §10.5's "the canonical artifacts stay byte-identical for a cell that names no
label" is a property of the *data* rather than a promise about the code, and the handoff's recorded
blocker — that reshaping `rootfs` would silently repoint `resolve_builder_base`, which picks the
image that builds **kernels** — evaporates instead of needing a fix. `default` is a real registry
entry, not a special case beside the registry.

**The legacy reject runs on the MERGED document, and that is load-bearing.**
`merge_pins_documents` merges leaf-wise, so an overlay adding a label over a singleton baseline
produces a *hybrid* holding `image`/`digest` leaves beside label keys — and that hybrid passes
`parse_pins_overlay`'s shape check, which is top-level only. Checking the overlay alone would pass
the gate leg and miss the real case. `a_hybrid_of_the_two_shapes_is_rejected_too` is that leg, and
it asserts the baseline's `default` really is present in the merged document so a reject keyed on
"the namespace has no labels" could not satisfy it.

**Retired: the `rootfs.debian_snapshot_timestamp` nesting.** Under a label map that path names a
registry entry, not a pin, and honoring both readings is the ambiguity the reject exists to refuse.
The test that pinned the nesting now pins its *retirement* rather than being deleted — the top-level
namespace, the only form the committed baseline ever carried, is untouched.

**`RootfsStage`'s fields went private.** `Stage::name` returns a `&str`, so a labelled stage must
read a precomputed name; public `label` and `stage_name` side by side would let a caller set one
without the other and get a stage whose identity disagrees with its output path. The constructor
pair (`new` / `labelled`) plus three `with_*` setters is the invalid-state-unrepresentable form, and
it is a ledgered break.

**Two helpers died in the extraction**, and the tests that drove them moved rather than being
deleted: `sort_kernel_registry` and `reject_sanitized_label_collision` are now the shared core's,
whose own unit suite drives the reversed-input ordering law and the both-labels-named collision
message. What stayed kernel-side is the property the generic test cannot see — that a fragment set
rides along with its label rather than being re-paired by index.

**Verified:** `just gates` exit 0 (the meta-gate accepts the new script pair in both directions, 31
gate-shaped scripts), the workspace unit suite green, `rootfs_registry` 8/8, and the byte-identity
claim confirmed **red** under a planted `registry_label` that suffixes the default — both the
battery leg and the core's own unit leg.

**Not yet, and refused rather than ignored meanwhile:** a `rootfs` entry's `xattrs` and `features`
keys are rejected naming the delta that adds them. That is the F1-clean seam the delta-5 notes
recorded: the key is refused here and honored there, never accepted-and-ignored in between.

## v33 delta 6b — the handler kind (design §18 delta 6, §10.5, invariant F7), as built

**What landed.** `artifact::handler` — the third kind's entry type, its three exhaustive
registration shapes and its four key/name composers; the `handlers` pins namespace with the
committed `default` naming the workspace build; `GuestToolsStage` as a *handler producer* rather
than a hardcoded one; `PackOptions`; `vmcell build --handler-label`;
`scripts/ban-handler-key-composers.sh` + self-test; and the seven-leg
`crates/vmcell/tests/handler_registry.rs` battery.

**The applet roster stopped being a const read and became a parameter.** §10.5 scopes it exactly:
the `GUEST_TOOLS_APPLETS` const-assert binds the **default** handler, because that const is what
the guest binary's dispatch table is compile-time asserted against. A registered consumer handler
has no such const, so its roster is data — strict-parsed at the registry (bare names only; a
`sub/dir` or `..` would inject a symlink outside the tools dir), and reaching the manifest through
`HandlerRegistryEntry::applet_roster` / `PackOptions::applet_roster`. Those two are where the
rosters meet, so no injection site has to know which kind it is holding, and an *empty* roster can
never reach the manifest — which would inject the binary with no symlinks and turn every
custom-`init=` target in the suite into a guest kernel panic.

**`pack_erofs_with_injection` takes one options struct now, and that is the point.** It is §10.4
contract surface, and v33 alone hands it two new facts (this delta's applet roster, delta 7's xattr
policy). Two more positional parameters would be two more ledgered breaks and the third would be
somebody else's, so the tail took the `HostEnv` idiom AGENTS.md prescribes: `PackOptions`,
`#[non_exhaustive]`, grown by field. Delta 7 adds `xattrs` to it without breaking a caller.

**`build` is legal, `digest` is legal, a path is neither.** F7's "nothing else parses", enforced:
both shapes at once is refused (they could disagree about which bytes the label means), neither is
refused naming the digest route, and `path` is rejected as an unknown key. A workspace `build` may
not carry an `applets` roster either — its roster is the const, and a second one could only
disagree with it.

**Not covered by this delta, and deliberately:** the `unpinned` dev path-override and `bundle`'s
refusal of it are 6c's, along with laziness and the `features` declarations. A registered handler's
*live* leg — a consumer handler booting and its applet answering in-guest — needs an artifact to
register, which the systemd proof cell (delta 9) is the natural home for; the KVM-free half is the
verify/cache-hit pair in `guest_tools.rs`'s own unit suite.

**Found while validating, fixed separately:** `vmcell-firecracker`'s `reject_live_baked_vsock`
treats a 100 ms probe *timeout* as "no live listener owns this path" and then unlinks it. Under a
full `cargo test --workspace` a local Unix connect to a live listener can exceed that, which is how
its unit test flaked once during this pass — and it is the unsafe direction to fail in. Recorded as
its own fix rather than smuggled into this commit.

## Firecracker's baked-vsock guard failed OPEN on a slow probe (2026-08-16)

**Found by a flake, diagnosed to a mechanism, fixed in the safe direction.**
`reject_live_baked_vsock` (`crates/vmcell-firecracker/src/lib.rs`) exists so a restore cannot
unlink a baked host vsock path a **live** VM still owns — FC re-binds that path verbatim, so
unlinking it severs the running VM's steward transport. It probed the path with a 100 ms connect
and grouped three outcomes into two: a connect that *failed* and a connect that *timed out* both
read as "no live listener owns the path: a stale leftover", and both unlinked.

Under load they are not the same thing. A full `cargo test --workspace` made a local Unix connect
to a **live** listener exceed 100 ms, and the guard's own unit test went red — reporting, correctly,
that the guard had classified a live socket as stale. On a real restore that is a silent sever
followed by a restore that proceeds anyway.

The fix is the direction, not the budget: a probe that cannot **prove** the path dead now refuses.
Refusing is loud, retryable and costs a re-run; unlinking is silent and costs a running VM. The
budget moved 100 ms → 2 s as well, and the trade inverted with the direction — too small now costs
a spurious retry, too large costs wall clock on the already-rare stale-path route.

**THE FIRST VERSION OF THE GATE PASSED WITH THE REGRESSION PLANTED, AND THIS IS THE RECORD OF IT.**
It tried to produce a real timeout by saturating a listener's accept backlog. The backlog is 1024
deep, the loop gave up at 512, every connect succeeded, the *live-listener* arm fired, and the
assertion passed — with the timeout arm restored to its fail-open form. A test that cannot reach
the arm it names is theater, and reading it would not have shown that; only planting the regression
did. The decision is now a pure predicate (`probe_permits_unlink`, over a three-outcome
`BakedVsockProbe`), driven directly over all three inputs — the `classify_poll` idiom, one crate
over. Planting `Inconclusive => true` reddens it naming the arm.

One message re-worded with it ("still in use" → "may still be in use"), and the sibling test's
assertion moved to `"accepted a probe connection"` — which keeps it *discriminating*: the
inconclusive arm can no longer satisfy the live-listener leg.

## v33 delta 6c — laziness, declarations, and the `unpinned` override (design §18 delta 6, §10.5, §7.4, invariant F7), as built

**What landed.** The rest of delta 6: `build-kernels <label>…` / `--all`; the `unpinned_path` dev
registration on both kinds with `bundle`'s refusal of it; `features` declarations on rootfs entries;
the `.features` sidecar producer; and the `registry_entry` fuzz target. Delta 6 was landed in three
commits — 6a (the shared core + the rootfs kind), 6b (the handler kind), 6c (this) — because one
commit carrying all of it would have been unreviewable. The register treats delta 6 as one item;
the split is a landing decision, not a scope change, and each third shipped its own gates.

**`build-kernels` names its selection, and the consumer gate caught what the notes missed.**
Selection lives in one predicate (`select_kernel_labels`) called from the CLI handler *between*
the resolver and `build_kernels_stages` — deliberately not inside `build_kernels_stages`, whose
three assembly tests take a hand-built registry slice and would have stayed green while asserting
nothing about selection. That is the "green test beside an unchanged call site" shape the register's
own conventions name. The handoff notes recorded the migration's blast radius as "four prose sites";
it was not. `examples/downstream-kernel/ci-check.sh` makes **two executable** `build-kernels --pins`
invocations that `.github/workflows/ci.yml` runs, each matching a specific substring — so the change
reddens the living consumer gate, which is the intended failure mode of contract drift. Both legs
gained `--all` in this commit, and a third leg was added asserting the bare-verb refusal itself.
`reject_seed_needing_source_for_build`'s remedial advice moved with it: it had been telling the
operator to run a command that is now a refusal.

**One law, one predicate, four times over.** The pass collapsed four duplicated laws rather than
adding a fifth: the unknown-label refusal (three CLI copies plus `build_labelled_kernel`'s, now one
`registry` composer), the `sha256:<64 hex>` registry-digest check (two copies with two messages, and
F7 *is* that rule), the registration-shape exclusivity reject, and the `"unpinned_path"` spelling
(one const, `UNPINNED_PATH_KEY`). The last two earned grep-bans with red-on-inverse twins, per the
rule that a law whose drift is not a compile error carries one.

**Uppercase digests were accepted at registration and could never verify.** The digest check
admitted either hex case while `sha256_hex` emits lowercase and the blob comparison is
case-sensitive, so `sha256:ABCD…` registered cleanly and then failed at fetch time with a digest
mismatch — an accepted input that cannot be honored. The shared predicate is lowercase-only now,
and refuses at registration naming the case.

**`unpinned_path` is an entry key, not a reserved label.** §10.5 says "one explicitly named override
key" without saying which namespace it lives in. The entry-key reading is what the rest of the
paragraph forces: it frames every shape as a property of an entry ("Three registration shapes exist,
exhaustively … Nothing else parses"), and a reserved *label* would have to be re-reserved on every
verb that names a label — the reserved-suffix defect class, re-armed for nothing. The override is
honored, not merely parsed: both stages publish the pointed-at bytes and fold the file's **content**
hash into their cache key, because an unpinned registration means "whatever is at that location
today" and its identity has to be read from the file rather than from the registration.

**`bundle` refuses by reading `resolved_pins.json`, and stays flag-free.** The alternative was a
`--pins` flag, which would judge a bundle of a previously-built directory against *today's* overlay —
the wrong fact. The resolved-pins document is already a bundle candidate and already carries the
resolved registry into the artifacts dir, so the refusal is reachable from a bare artifacts dir. The
negative result ships with the positive control the rules require: the same fixture bundles cleanly
with the unpinned pin removed.

**The declaration sidecar is its own stage, and that is §7.4's requirement rather than a preference.**
§7.4 splits cache identity: a build-affecting property folds into the *image* identity and re-packs,
while a declaration-only edit re-emits the *sidecar* — "content-addressed on its own" — and leaves
the image key unmoved. A single-key stage cannot express that, so folding `features` into
`RootfsStage::cache_key` would have made every declaration edit re-pack the image it describes.
`RootfsFeaturesStage` folds only its stage version, its label and the declaration. The gate asserts
both halves: the sidecar key moves and the image key is byte-identical.

**The sidecar stage collided with the cache sidecar, invisibly and expensively.** `Pipeline::build`
derived every stage's metadata path as `out_path.with_extension("cache_key")`, so `rootfs.erofs` and
`rootfs.features` both resolved to `rootfs.cache_key`: the two stages overwrote each other's key,
every build missed, and the multi-minute OCI re-pack would have run on **every** build forever with
every functional test still green. `Stage` grew a provided `cache_sidecar_path` used by both
`Pipeline::build` and `Pipeline::reset_to` — writer and remover cannot disagree — which the
declaration stage overrides to *append*. Found by building it, not by reading it.

**Two sidecar-naming laws now coexist deliberately.** `feature_manifest_path` **replaces** the
extension (`rootfs.erofs` → `rootfs.features`), matching the dominant `.cache_key` law and the
dot-sanitizing filename suffixes that exist to make it safe; `kernel::resolved_config_path`
**appends**, because a dotted kernel label's trailing `.NNN` would otherwise be eaten and point two
labels at one config. Each states its rationale at its own site, and `load_beside` now routes
through the composer so producer and consumer cannot drift.

**The sidecar is emitted even when nothing is declared.** The alternative — emit conditionally, plus
a `clear_*` counterpart like the kernel's — leaves a build that *stops* declaring with a stale
sidecar that `load_beside` would read forever and `bundle` would pin. An empty manifest round-trips
to empty stances, which is what "absent" already means, so unconditional emission costs nothing and
removes the whole stale class.

**The canonical rootfs now declares what its packer actually does.** `rootfs.default` declares
`xattr_preserved: false`. Before this, no sidecar existed on disk, `FeatureDeclaration::baseline`
returned empty stances, nothing removed `Feature::XattrPreserved`, and every cell reported the
feature **present** for an artifact whose packer strips every xattr. This is the F1-clean seam in the
other direction: 6c *honors* an explicit `xattr_preserved` token, and delta 7 adds the `xattrs` key
that `XattrPreserved` is derived from — at which point an explicit token beside `xattrs` becomes a
hard error naming the derivation. The seam is recorded at the parse site so the migration is a
decision rather than a discovery.

**Two pre-existing defects closed because 6c made them reachable or inconsistent.** The OCI pack
tail registered its output under the hardcoded artifact-map key `"rootfs"` regardless of label —
the M-PIPE-4 collapse that `rootfs_artifact_key`'s own rustdoc describes — and the new unpinned
publish path used the correct law, so the two publish paths disagreed for a labelled entry. And
`vmcell build --rootfs-label default` died on `Missing rootfs_default_image pin`, because the CLI
passed `default` through verbatim while the flattener normalizes it to the un-suffixed keys. The
label reaches the pack tail as a **`PackOptions` field**, not as a parameter: that is the growth
seam 6b built the options struct for, and using it keeps §10.4's `pack_erofs_with_injection`
signature — ledgered as breaking exactly once, one delta ago — intact.

**The third digest check kept its own law, and got the same fix.** `vmcell-cli::validate_oci_digest`
backs the `oci2erofs --digest` flag: no pins namespace, no registry label, an operator-typed
reference rather than a registration. Folding it into the registry predicate would mean a message
saying "pins `…`" about a CLI flag, so it stays separate and `ban-registry-digest-check.sh` names it
(and `vmcell-daemon`'s upload-sidecar hex check) in its header as deliberately out of scope. It did
carry the identical uppercase hazard, and that is fixed at the flag with its own message.

**`OCI_ROOTFS_STAGE_VERSION` 4 → 5.** The identity fold gained the unpinned registration, and
AGENTS.md states the every-new-fold-bumps rule categorically. The cost is real — the first build
after this re-packs every warm OCI rootfs once.

**Recorded gaps.** The `tracing::warn!` announcing an unpinned resolution runs on every resolution
but its *content* is unasserted: `vmcell` has no tracing-capture harness and `tracing-subscriber` is
an optional feature, so building one for a single line was out of proportion. And an `mmdebstrap`
rootfs carries no declaration by construction (it reads no registry entry), so an artifacts dir that
held an OCI build first keeps that build's `rootfs.features` beside it — harmless today, since both
packers strip, but an honest gap rather than a covered case.

## v33 delta 7 — external repacking and the per-artifact xattr policy (design §18 delta 7, §4.2, §4.7), as built

**What landed.** `XattrPolicy` on the one inject+pack tail, declared per artifact and defaulting to
`Strip`; `Feature::XattrPreserved` derived from it; the `xattr` guest-tools applet; `oci2-erofs
--tools` / `--work-dir`; the `Preserve` twin, the pack-twice determinism gate, the cache-key
invalidation gate, and the live in-guest readback battery.

**The strip was never a law; it was a premise about one base image.** Six tar-derived node sites now
populate xattrs from the tar's PAX headers under `Preserve`, through **one** decode. The four
injected/synthesized sites stay empty under **both** policies, and each carries a comment saying so
is not a miss: invariant F5 makes vmcell's own injections unconditional and authoritative, and an
injected file has no source header to read. The eleventh site — the hardlink arm, which §4.7's
"ten node-construction sites" does not count — keeps the merged target's xattrs, because xattrs are
an inode property and a hardlink shares its target's inode, so it cannot legitimately carry a
different set. That is now pinned rather than incidental.

**`XattrPolicy` is defined where the ungated types can see it.** It began in `tar2erofs`, which is
behind `am-fs-erofs`, and had to move: `RootfsRegistryEntry` is compiled in the empty feature set —
`cargo hack --feature-powerset` builds that row — so a field of it cannot have a feature-gated type.
The §10.4 contract path `vmcell::artifact::rootfs::XattrPolicy` is preserved as a re-export, so no
consumer sees the move.

**"Migration is free" cannot mean "the cache key is unmoved", and the gate says which it means.**
The identity fold gains the policy, so `STAGE_VERSION` bumps and every key moves — that is the rule,
not a regression. What is actually asserted is the pair that carries the meaning: a pack declaring
no policy produces **byte-identical image bytes** to the pre-delta packer (captured as a literal by
running the previous commit's packer), and an undeclared policy folds to the same key as an explicit
`"strip"`. Asserting equality with the pre-delta key would have been asserting something the bump
makes false.

**One fact, one key — including the direction that says nothing.** The derivation runs at a single
site, so every consumer of an entry's declarations gets the stance without a per-call-site thread,
and an explicit `xattr_preserved` token in a vmcell-built entry is refused **unconditionally** —
including when it *agrees*, since a second spelling of one fact is a desync waiting for an edit.
The refusal is scoped to a vmcell-built entry, as §4.7 words it: an `unpinned_path` registration
points at bytes vmcell did not pack, so it derives nothing and **may** declare the token, while the
`xattrs` key is refused there because there is no vmcell pack for a policy to govern. Without that
scoping a foreign image that genuinely preserves xattrs had no way to say so, and carried a derived
`false` vmcell could not support.

**`oci2-erofs` deliberately has no `--xattrs` flag.** It names an explicit image, not a label, so it
resolves no registry entry and always packs under the default. A flag would be a second place to
state a per-artifact property, which is the shape §10.5 exists to prevent; a consumer wanting
`Preserve` registers a label and builds it.

**`--work-dir` names the staging *parent*, not the staging directory.** `oci2-erofs` `remove_dir_all`s
its staging tree at both ends, so a flag naming the tree itself would make
`vmcell oci2-erofs --work-dir /home/me/build` an `rm -rf` of the operator's directory. The
per-invocation `oci2erofs-stage-<pid>` leaf stays vmcell-composed: the only directory vmcell ever
deletes is one it built the name of. The tree is now owned by an RAII type, so the failure path
sweeps it too — it used to leak on any pipeline error.

**What the consumer-position gate can and cannot afford, stated rather than implied.** The example
workspace's `ci-check.sh` forbids network, and a complete pack needs a real OCI pull, so the green
half asserts the *discriminating* fact instead: with `--tools` the same command no longer fails on
the handler at all — it proceeds past that stage and dies fetching a deliberately unresolvable
image. One variable changes between the pair. A complete consumer-position pack was run by hand and
is recorded; it is not in CI, and that gap is the trade rather than an oversight.

**A `PackOptions` field nobody folds is now a compile error.** `fold_rootfs_injection_identity`
takes `&PackOptions` and destructures it **exhaustively**, so adding a field without folding it is
`error[E0027]` at the fold site. That closed a live defect delta 6b had shipped: `applets` was never
folded, so two registered handlers with different applet rosters over the same multicall binary
shared one cache key and produced different images — the warm cache served the first roster's
symlink set, and every custom-`init=` target the second declared resolved to nothing. The class is
structural now instead of remembered.

**The validator's `xattr_preserved` check stopped being undecidable.** Its probe plan was
`NO_PROBE_YET` only because nothing could read an xattr inside a guest. The applet is that, so the
plan is a real in-guest walk: a **complete** walk finding nothing is a decided `DoesNotWork` — which
makes a `Strip` artifact **pass** rather than skip — while a walk that hits its cap is `NotRun` →
`Unverified`, and the verdict reports the cap rather than implying completeness.

**Delta 7's live input had to be synthesized, and that is a finding about the base.** The pinned
Debian base carries **zero** PAX xattr records — verified against the cached layer — so a `Preserve`
leg has no input from the canonical artifact. The battery synthesizes one tar layer carrying a
`security.capability` record and merges it over the base. Using delta 9's full-Debian image instead
would have made delta 7's live gate depend on delta 9's unresolved image provenance.

## The Firecracker baked-vsock guard, part two: a second fail-open, and why its test flaked

**The flake was not the timeout, and "environmental" was not the answer.**
`reject_live_baked_vsock_rejects_live_listener_and_clears_stale` failed on cold first runs and
passed warm. Setting the probe budget to **1 ns** leaves it green — `tokio::time::timeout` polls the
inner future first and a local AF_UNIX `connect` resolves on its first poll — so the timeout arm is
unreachable from that test in either direction. Eighty-way CPU load reproduced nothing.

**Concurrency reproduced it: 2 failures in 96 runs**, always at the *stale-path* arm. Instrumenting
the probe caught the cause directly — the socket file whose listener had been `drop`ped was still
bound and still accepting. Isolated measurement: 0 anomalies in 96 000 sequential bind/drop/connect
cycles; 1–4 per 3000 under 24-way concurrency, with a plain `std` connect succeeding on them too, so
it is the kernel's answer and not a runtime artifact. **A listening fd open in one thread is
duplicated into every `fork` another thread performs in that instant, and stays bound until that
child reaches `execve` and `CLOEXEC` closes it.** The guard was right; the *fixture's* premise —
"bind then drop yields a provably stale socket file" — was false. The fixture now confirms the path
answers `ECONNREFUSED` before handing it over, and converges rather than re-rolling. After: 0
failures in 96 runs. **This is a law about test fixtures, not about this guard**: in a process that
forks, a closed listener is not immediately a dead one.

**Found en route: the guard's sibling arm was still fail-open.** `c5a01a1` fixed the *timeout* arm
and left `Ok(Err(_)) => Refused` — any `connect` failure read as proof of death — while its own
rustdoc claimed a narrow `ECONNREFUSED`/`ENOENT` set. It is not narrow: `connect` also fails
`EMFILE`/`ENFILE` under fd pressure, `EAGAIN` when a **live** listener's backlog is full, `EACCES`
and `EINTR`. Each made the guard unlink a live VM's steward transport and let the restore proceed —
the same class, on the arm nobody looked at. Reproduced under `ulimit -n 32`: the live-listener leg
returned `Ok` for a socket a listener was sitting on. Only `ECONNREFUSED` and `ENOENT` prove absence
now, through one pure predicate beside `probe_permits_unlink`, with the errno truth-table measured
on this host rather than assumed — a leftover regular file, a directory and an unlistened stream
socket all answer `ECONNREFUSED`; a bound dgram socket answers `EPROTOTYPE`.

## v33 delta 10 — daemon placement exposure (design §18 delta 10, §11.5), as built

**What landed.** `CreateVmRequest` grows `init` and `steward_placement`, the launcher honors both,
and a placement with no steward is a 400 that names why.

**The DTO mirrors the config enum because it structurally must.** `vmcell` is an *optional*
dependency behind the `server` feature and `vmcell-daemon-client` links `default-features = false`,
so `dto.rs` cannot name a `vmcell` type at all — `cargo check -p vmcell-daemon
--no-default-features` is the proof. The mirror is a compile constraint, not a style choice. Nesting
`init` inside the `Service` variant was considered and rejected: §3.5's whole reframe is that
placement and init *identity* are two facts, and folding them back together would undo it.

**`None` is representable and refused, not unrepresentable.** §18 delta 10 says the fields express
"`Service{port}` with a custom init only"; the gate row demands a `None`-rejected-400 arm, which
needs `None` on the wire to refuse. The gate row wins: an unrepresentable variant makes the rule
leak as serde's "unknown variant" parse error, which names nothing and teaches the client nothing.
§11.5's "stays unexpressible" holds either way — no `None` cell can be created over REST.

**`build()`'s derivation is made unreachable rather than mirrored.** `VmConfigBuilder::build()`
derives `StewardPlacement::None` when `init` is `Some` and no placement is named, which is exactly
the one placement REST must not produce. The daemon never reaches it: `LaunchSpec::steward_placement`
is **not** an `Option` and `vm_config()` calls `.steward_placement(…)` unconditionally. Re-deriving
the rule daemon-side would have been a second copy of a law, and this tree's history is that every
duplicate diverges. Everything the library already refuses typed — `Pid1` + init, a zero port,
snapshotting beside a non-`Pid1` placement — reaches the client as a 400 through the existing
`Error::Config` mapping, with no daemon-side copy.

**Two fakes discarded their arguments, not one.** `FakeEngine::create(_req)` was the known one;
`FakeLauncher::launch(&self, _spec)` was not, so the field's path had **two** unobserved hops and
adding fields would have shipped two green blind tests. Both capture now and compare field-for-field
with one field `Some` and a sibling `None`. The demonstration is on the record: under a planted
request-dropping bug the new gate reddens while `engine_rpc_round_trips_every_op` still prints `ok`.

## v33 delta 9 — the systemd proof cell (design §18 delta 9), as built

**What landed.** `debian-systemd` registered by digest, a cell booting **real systemd as PID 1**
with the steward as a unit under `Service` placement, the §10.6 conformance kit run over the
composition, and `just test-systemd` — the opt-in recipe AGENTS.md had been describing in the
present tense at three sites.

**The design's example image does not exist, and this is the deviation.** §10.5 registers
`debian-systemd` against `docker.io/library/debian`, and no digest of that repo ships systemd — it
is the base/slim variant, verified against the cached layer (no `usr/lib/systemd/systemd`, no
`systemctl`, no `/sbin/init`). The cell registers `docker.io/jrei/systemd-debian` instead, pinned to
its **amd64 sub-manifest** rather than the multi-arch index: the fetcher resolves an index fine, but
pinning the sub-manifest matches `rootfs.default`'s convention and pins the architecture. It is a
third-party repo, which the digest discipline makes mechanically safe and which a reviewer should
still see named here.

**The entry declares `xattrs: "strip"`, and that is a measurement.** All four layers were scanned
for `SCHILY.xattr` records: there are none. Declaring `preserve` would have derived a claim the
§10.6 kit then correctly reports as broken.

**The unit is enabled by a drop-in, not a symlink and not a cmdline token.** `ExtraFile` is
regular-files-only, so a `multi-user.target.wants/` symlink cannot be baked. `systemd.wants=` would
have worked — and that is the argument against it: `systemd.*` is unreserved, so the token would be
*accepted*, which under F3's alias law is precisely the shape that lets a guest-visible knob collide
with an owned one later. A `multi-user.target.d/*.conf` drop-in is a plain regular file and needs no
reservation.

**The gate as specified is unreachable, and the shipped one says why.** §18's leg expects a
placement refusal from a `Service` cell whose steward never starts. It cannot happen: for
`Service{port}` `steward_port()` is always `Some`, so `MicroVm::steward` never takes the placement
fail-loud arm and the cell yields `Error::Timeout`. The leg asserts the timeout, that the message
does **not** name `StewardPlacement::None` (the refusal-identity half), and a wire-level dial — with
systemd's own console output as corroboration.

**A vacuous serial assertion, caught by measuring rather than reading.** The first needle was
`"systemd"`, which the kernel itself echoes in `Command line: … init=/usr/lib/systemd/systemd …`
before systemd runs at all. The shipped needle is two halves — `"Reached target "` and
`"multi-user.target"` — matched across systemd's ANSI escapes.

**The kit found a real under-claim, and it is a finding about the design.** The artifact declares
`snapshot_restore: false`, but booted the ordinary `Pid1` way it snapshots and restores fine; what
cannot snapshot is this cell's `Service` **placement**, which is a per-op eligibility arm rather than
an intersection axis. §10.6's definition makes that an under-claim, so the honest verdict is a
dispositioned `Warn` and the test asserts exactly that — including that the message names the
positive control, so the paired probe demonstrably ran twice. The two halves of §18 delta 9's *What*
are in tension here: dropping the artifact-level stance would make the delta's own
`why_absent(SnapshotRestore) → Source::Rootfs(…)` assertion unsatisfiable. The shipped test
satisfies both by dispositioning the warning.

**Opt-in had to be enforced, not merely recipe-shaped.** A filter like `test(systemd_cell)` is also
selected by `test-privileged`'s `!(test(unprivileged) | test(smoltcp))`, so writing the recipe would
have started a 59 MB pull on every privileged run. The legs carry a compile-time opt-in token whose
absence is `error[E0423]`, and under `test-privileged`'s exact filterset they finish in 8 ms
recording a capability skip. The `usb_passthrough` self-skip is the precedent.

**`Source::Rootfs` carries a filename, not a label — the test asserts the code.** §18 delta 9's text
and `feature.rs`'s `axis_rank` doc both say `Source::Rootfs("debian-systemd")`, while
`resolve_cell_features` builds it from `image.file_name()`. Three landed delta-6c gates already pin
the filename form, so changing the constructor is a behavior change that reddens a landed delta's
gates — its own delta with its own sweep, not delta 9's. The assertion recomputes the name through
`rootfs_filename` and records the divergence at the site.

**Recorded, pre-existing, and sharper on a full distro:** vmcell's injection manifest overwrites
`etc/ssl/certs/ca-certificates.crt` on every image, so a consumer booting this artifact *with*
networking inherits vmcell's proxy CA in place of Debian's. The cell runs `.network_disabled()`, so
nothing here notices.

## v33 delta 8 — the ext4 producer (design §18 delta 8, §4.7), as built

**What landed.** An ext4 rootfs producer behind the same `Stage`, a `format` key on the registry
entry, a format-aware filename law, the version-probe refusal, the mount-and-diff live battery — and
the read-only ratification that had to come with it.

**The writability contradiction is resolved: the ext4 root is READ-ONLY.** §4.7 pitched the producer
as serving "workloads that need a **writable**, POSIX-complete root" while §5.2 said the same root
"mounts **strictly read-only** without journal recovery" — and it was four-way, not two-way, since
all four backends attached the device read-write and `RootfsSource::Block`'s own rustdoc said
"Writable or read-only". Read-only wins on the design's own words: §4.7 closes with "**the ext4
producer adds an artifact; it does not move the root**" and §18's *Migration* clause is "additive",
which writability is not. It would have required rewriting F3's reserved-cmdline alias law (`rw` is
reserved *because* `rw` + `rootflags=noload` is corruption, and both its gates redden), growing
`clone_ineligible_feature` a `RootfsSource` arm it does not have, and dropping `noload` — and it
would not even have worked, because under the default `Pid1` placement the steward unconditionally
overlays tmpfs with `lowerdir=/` and pivot_roots, so every guest write lands in the tmpfs upper.
Writability would have scoped to `Service`/`None`, making delta 8 depend on deltas 4 and 5. **The
surviving motivation is the real one**: POSIX-completeness — device nodes, xattrs, ACLs — and
workloads asserting on ext4 semantics, which is exactly what the mount-and-diff gate measures. The
reasoning is written onto `RootfsSource::Block` and `root_device_read_only`, so a later reader finds
it at the type.

**The writable-root claim lived at THREE design sites, not one** (docs/90 D10). This entry named only
§4.7's, and a reissue that fixes one and leaves two is exactly the failure the widening prevents, so
all three are named here — with what each now says, since all three were corrected together on
2026-08-17:

* **§4.7**, the producer's own pitch, was "workloads that need a **writable**, POSIX-complete root".
  It now pitches POSIX-completeness and says outright "**Not a writable one:** the ext4 root is
  attached and mounted **read-only**, like the erofs one", naming `root_device_read_only` as the one
  law and keeping the reasoning above for why writability was declined.
* **§4.6**, the per-backend extra-disk wiring bullet, called CH's sector-0 auto-detect bug one that
  "also lurked on the writable `Block` rootfs path". It now scopes that to the past — the bug "lurked
  on the `Block` rootfs path **back when that path attached the root read-write**; it is read-only on
  every variant now" — so the historical measurement keeps its record without asserting a present
  writability, and it says which disk kind can still meet the bug (a writable **extra** one).
* **§5.3**, the custom-init paragraph, told a caller that a custom-init VM "typically pairs with a
  writable `Block` rootfs (§4.7's producer fills it)" — the one of the three that sent a reader to
  build something the product refuses. It now states the true rule for both variants ("A custom init
  has no writable `/` under **either** root variant") and gives the honest pairings: its own tmpfs, a
  writable **extra** disk, or a read-write share.

The authority in all three cases is `RootfsSource::root_device_read_only`, gated in both directions.

**Booting `RootfsSource::Block` for the first time in this repository's history found two real
defects.** The variant had been consumable since v22 with no producer, so no test had ever booted
it, and every runtime claim about it was unverified. Both were found by running it, not by reading:

* **All four backends attached the root read-write beneath an `ro` mount.** Not a theoretical
  mismatch: under the old attach a guest `dd if=/dev/zero of=/dev/vda bs=512 count=1` **succeeds**
  and writes 512 bytes into the image N zygote clones share. Four per-variant matches were four
  copies of one decision and all four had drifted the same way; they are deleted, and
  `RootfsSource::root_device_read_only` is the one law, gated in both directions so the device's
  writability can never again exceed the mount's.
* **`mkfs.ext4 -d <tarball>` silently drops every extended attribute except `security.capability`.**
  The first live run packed a `user.` attribute under `XattrPolicy::Preserve`, the pack reported
  success, and the guest's `getxattr` answered `ENODATA`. Isolated on the host afterwards:
  `security.selinux`, `trusted.*` and `user.*` are all dropped, while the *directory* form of `-d`
  has no such limit — so it is a property of the tarball route, not of ext4. `Preserve` is a §10.4
  contract promise the erofs route keeps for every namespace, so the ext4 route was silently
  changing the semantics of an accepted input. It refuses now, naming the member, the attribute and
  both ways forward. `security.capability` — the case `Preserve` exists for — is unaffected.

**There was no merged tar, so one emitter was added downstream of the one merge.** The tail merged
layer streams straight into an erofs node map, and `mkfs.ext4 -d` needs a tar. The merge is now
`merged_node_map` with `nodes_to_erofs` and `nodes_to_tar` beside it, which is what makes §4.7's
"injections, `libc6` scan, xattr policy, reserved-path law all inherited for free" true **by
construction** rather than by assertion — there is still exactly one merge, and a gate says so.

**Determinism needed three knobs the design does not name.** Delta 7 shipped a pack-twice
byte-determinism gate and delta 8 inherits it. `mkfs.ext4` is not deterministic unless
`SOURCE_DATE_EPOCH`, `-U <uuid>` and a non-null `-E hash_seed=<uuid>` are **all** set — measured
both ways on this host. All three are derived from the merged tar's own hash, never from the clock.
`-O ^has_journal` is emitted as well: the root mounts `ro` with `rootflags=noload`, so the journal is
the only thing `noload` guards and omitting it makes the image smaller. `noload` stays emitted, so
F3 is untouched.

**The libarchive half of the version probe is a build, not a version string.** The gate demands a
classified refusal for "e2fsprogs < 1.47.1 **or no libarchive**", and libarchive is `dlopen`'d rather
than linked — so `mke2fs -V` is structurally blind to its absence. The probe does a real trial
tarball build instead. A probe that cannot see the thing it claims to check is theater.

**The crate route was evaluated first, as §18 directs, and rejected with a named candidate.**
The recon's premise that no permissive pure-Rust ext4 *writer* exists is stale — several do, and
`am-fs-ext4` 0.4.0 is a genuine candidate: MIT, the same author family as the `am-fs-erofs` this
tree already trusts for its only packer, `am-fs-core` already in the lock, and a complete write API
down to `apply_mknod` / `apply_link` / `apply_setxattr`. It is rejected for this cut because it
first published 2026-06-21, shipped three releases in ten days, its own docs call its ext3 dialect
"not yet `e2fsck`-clean", and §17's qualifier — *if* a permissive writer passes the mount-and-diff
gate — could not be met by a gate that did not exist until this delta. **Now it can be**: the gate
exists, the swap is contained to `Ext4Producer`'s body behind the `Stage` boundary, and graduating
would remove the xattr refusal above outright. That is the recommended next experiment.

**Two measured surprises worth carrying.** The boot root mount is **absent from `/proc/mounts`** in a
`Pid1` cell — the steward lazily unmounts it after `pivot_root` — so the battery mounts `/dev/vda` a
second time, read-only, and diffs *there*; a first draft asserted on the boot mount and reddened.
And the pinned Debian base carries **zero** device nodes and zero xattrs, so the battery packs a
fixture layer supplying every POSIX shape the base lacks, rather than asserting on a tree that
cannot exercise the claim.

**Hardlinks are materialized to copies by the merge**, which predates this delta and is unchanged;
`st_nlink` is therefore asserted nowhere, and the one hardlink in the base is excluded from the
sampled manifest rather than silently passing.

## Recorded: a closed fd is not a dead one in a process that forks

Two independent flakes this pass had the same root cause, and it is worth stating once as a law
about **test fixtures** rather than twice as an anecdote. A file descriptor open in one thread is
duplicated into every `fork` another thread performs in that instant, and stays alive in the child
until it reaches `execve` and `CLOEXEC` closes it. So in a multi-threaded test binary whose siblings
spawn processes:

* a `drop`ped `UnixListener` can still be **bound and accepting** — which made
  `reject_live_baked_vsock`'s fixture hand the guard a socket that was not actually stale (measured:
  0 anomalies in 96 000 sequential cycles, 1–4 per 3000 under 24-way concurrency);
* a file being written can still be **busy for `execve`** — which made the ext4 probe's stub binary
  answer `ETXTBSY`, surfacing as an `Error::Io` where the test expected `CapabilityUnavailable`.
  The product was right (a present-but-unrunnable binary is a *broken* facility that keeps its
  errno); the fixture's premise was wrong.

Both fixtures now **verify** the state they assume rather than assuming it. Neither was a product
defect, and both read as one — which is the class AGENTS.md names when it says a leaked fixture
"reads as a product defect and is not one".

## Where the v33 pass stands

Deltas 1–5 of the §18 register are landed, pushed and live-validated. **6a and 6b were live-validated
at this pass's start** — privileged 177/177, unprivileged 4/4, daemon 14/14, validator 3/3, seven
capability skips, all Firecracker. (`docs/88`'s stated bar of "privileged 162/162" was itself the
*delta-5* figure; 6a/6b's two new registry batteries account for the other fifteen.) **All ten
deltas of the v33 register are now landed, and the register is closed.**

`docs/89-claude-handoff-notes-v5.md` is the pick-up point. `docs/88` and `docs/87` are superseded;
they are kept for the per-delta detail v5 amends rather than repeats, and both carry premises that
did not survive contact — read them only through v5's corrections.

**The tally the register keeps** ("every register so far has carried at least one shipped-fact
premise that was empirically false") is now well past a curiosity. The 6c–8 pass added, among
others: `build-kernels`'s migration blast radius stated as "four prose sites" when two of them were
**executable CI-gated legs**; delta 7's premise that `GuestToolsStage` "had no prebuilt escape
hatch", which 6b had already retired; and design §4.7's count of "ten node-construction sites" when
there are eleven. Every one was found by grepping the claim, not by reading around it.

**Three defects this pass were invisible to every green test, and all three were found by running
something.** A `.cache_key` stem collision that would have re-packed the OCI image on **every**
build forever, with every functional test still green. An applet roster that was never folded into
the rootfs cache key, so two handlers with different rosters shared a key and produced different
images. And a `Block` root attached read-write beneath an `ro` mount, on a code path no test had
ever booted, where a guest `dd` wrote into an image N zygote clones share. Static review would not
have surfaced any of them.

**The delta 6 / delta 7 ordering conflict, decided.** §10.5's registry entry sketch carries
`"xattrs": "preserve"` while `XattrPolicy` is delta 7's deliverable, and the register orders 6 before
7 without listing "6 needs 7". Landing 6 with the key would mean an accepted-then-ignored
declaration — an F1 violation for however long 7 took. So **delta 6 lands the registry with a strict
entry parse that rejects `xattrs` as an unknown key, and delta 7 adds the key together with
`XattrPolicy` and the pack tail that honors it.** Every point in between is F1-clean: the key is
rejected, then honored, never accepted-and-ignored.

## Where the design lives now

**v33 (2026-08-15):** `docs/82-claude-opus-design-v32.md` moved to `docs/historical/` (frozen at its
published bytes) and the current design is the v33 revision — the serial-nexus consumer-platform
pass, whose §18 opens a new ten-delta register (the steward rename; R1–R7). Both discovery gates
were re-run green against the reissued tree at reissue time (`vmm::jail` 4/4;
`vmcell-privilege` 23/23 — after pruning six orphaned pre-rename `.claude/worktrees/` checkouts
whose stale 3-cap justfile copies the tree-walk gate correctly refused). Before that:
`docs/79-claude-fable-design-v31.md` moved to `docs/historical/` and
the v32 revision followed it. **No reference in this file names the current
design by path** — nor should a new one: two gates find it by **discovery**, and a third mechanism
pinned its filename and broke on this very reissue. `vmcell::vmm::jail`'s deny-list test parses
§12.3's roster out of whichever non-historical `docs/*.md` carries that heading;
`vmcell-privilege`'s blessing-copy scan locates §10.4's `setcap` line by finding the one `docs/*.md`
whose first line is the design's title, and splices that row into an otherwise fixed roster. Both
**error** rather than pass vacuously when they find nothing, and both prune `docs/historical/`,
whose older two- and three-cap grants are the record rather than drift. `cargo test -p vmcell-privilege
--lib` → 23 passed.

---

# As built: the docs/90 review pass (2026-08-16)

A comprehensive review of the tree at `c276da7` — the closed v33 register — recorded in
`docs/90-claude-opus-code-review.md`. That document carries the divergences that should be
**fixed**. What follows is the other half AGENTS.md asks for: the divergences that are **justified
and stay**, and the coverage gaps this pass chose to record rather than close, each written here so
the next reader finds a decision instead of an unexplained mismatch.

Every suite was executed on this host during the review, not presumed: `just ci` green
(1142 tests, 298-config powerset, 19 gate self-tests), `test-privileged` 228/228,
`test-unprivileged` 4/4, `test-daemon` 16/16, `test-validator` 4/4, `test-crosvm` 30/30,
`test-systemd` 2/2, nine capability skips matching the recorded roster.

**The fix pass landed the next day.** Entries below that it superseded carry a dated superseding note
at their own end; the two whose shape was already right record that the justification now lives in the
ledger, the design and the README as well, which is what was missing. The as-built record of what was
built — and where the shipped fix deliberately deviates from what docs/90 directed — is the section
that follows this one ("As built: the docs/90 fix waves").

## Recorded (justified): `pack_rootfs_with_injection` is the general pack tail, and `pack_erofs_with_injection` is its erofs door

Delta 8 needed the one inject+pack tail to emit two formats. Rather than widen the §10.4-listed
`pack_erofs_with_injection` into a function whose name lies about half its outputs, it kept that
name as a **format-checking wrapper** — it refuses any `PackOptions::format` other than
`RootfsFormat::Erofs` with a typed error naming the general door — and put the format-honoring tail
behind a new `pub async fn pack_rootfs_with_injection`
(`crates/vmcell/src/artifact/rootfs/mod.rs:1294`, with the ungated arm at `:1615`).

**The shape is right and stays.** A door that packs erofs by name should keep doing exactly that,
and a caller that passes `format: Ext4` to it has made a mistake worth a message rather than a
surprise. What was missing is the record: the new entry point appears in **neither** the
`crates/vmcell/Cargo.toml` ledger, this file, design §10.4's "one named list", nor the README's copy
of it, so the only route to an ext4 artifact through the pack tail is a public function the contract
does not name. Adding a `pub fn` is additive, so `cargo semver-checks` is silent by construction —
which is the whole reason §10.4 asks for a ledger entry rather than trusting the tool. This entry is
that record.

**The record is no longer only here (2026-08-17).** The `0.19.0 → 0.20.0` edge in
`crates/vmcell/Cargo.toml` now carries the split — ledgered late, and saying so — naming
`pack_rootfs_with_injection` as "the entry point to call from here on" and
`pack_erofs_with_injection` as the erofs-only door onto it; and README's contract-surface list names
the pair the same way, with the trade stated (a caller packing erofs needs no edit; a caller passing
`Ext4` to the door gets a typed refusal). The shape recorded above is unchanged — this is the missing
record arriving, not a decision moving. What no gate can supply is the part that was missing: a new
`pub fn` inside an existing edge is invisible to `cargo semver-checks` *and* to
`tests/contract_ledger.rs`, which gates the chain's shape and never an entry's content, and says so
in its own header.

## Recorded (justified): there is no `build_labelled_rootfs` / `build_labelled_handler` — the labelled constructors are the shipped shape

Design §10.5's "where selection lives" paragraph and §10.4's contract list both name
`build_labelled_rootfs` / `build_labelled_handler` as the library-side selection entry points,
mirroring `build_labelled_kernel`. Neither function exists. What shipped instead is a **constructor
pair** on the stages themselves — `RootfsStage::labelled(label)`
(`artifact/rootfs/mod.rs:547`, `:939`) and `GuestToolsStage::labelled(label, source)`
(`artifact/guest_tools.rs:62`) — which a consumer composes into its own `Pipeline` beside
`ResolvePinsStage`, plus the `vmcell build --rootfs-label / --handler-label` verbs.

**The constructors are the better shape and stay.** `build_labelled_kernel` exists because a kernel
build is a fixed two-stage assembly (`ResolvePinsStage → KernelStage`) with nothing for a caller to
vary; a rootfs or handler build composes with injections, extra files, a pack format and an xattr
policy, so a thin assembler would either hide those or grow a parameter per knob — the shape
`PackOptions` was created to avoid. The register's own convention governs the rest ("sketched
names/signatures are advisory; the behavior and its gate bind; a shift is recorded, never silent"):
delta 6 landed the behavior and its gates and did not record the shift. This is that record.

The consequence worth stating: a git-dep consumer building a labelled rootfs today writes more code
than one building a labelled kernel, and §10.4 tells it to call a function that is not there.

**Closed on the documentation side (2026-08-17), and the record is no longer only here.** All three
places a consumer or a maintainer looks now name the shipped shape: §10.4's contract list names "the
**labelled rootfs/handler stage constructors** — `RootfsStage::labelled(label)` and
`GuestToolsStage::labelled(label, source)`"; §10.5's "where selection lives" paragraph records the
second shift explicitly — that there is deliberately no `build_labelled_rootfs`/`…_handler` thin
assembler, with the reason (a kernel build is a fixed two-stage assembly; a rootfs or handler build
composes with injections, extra files, a pack format and an xattr policy, so an assembler would either
hide those or grow a parameter per knob) and a pointer back to this file; and README's list says the
same, "**rather than as free functions**". So the register's convention is satisfied at last — the
behavior bound, the shift is recorded, and nothing sends a consumer to a symbol that does not exist.
The constructors stay.

## Recorded (justified): delta 3's battery budget is the conformance battery's, not `validate()`'s

Design §17 lists "`validate()` has **no overall wall-clock budget** today … **directed closed by
§18 delta 3** (`ConformanceOptions.battery_budget`)". Delta 3 landed `battery_budget` on
`ConformanceOptions` (`vmcell-artifact-validator/src/conformance.rs:284`) and bounds `run_battery`
with it. It did **not** touch `validate()`: `ValidationOptions`
(`vmcell-artifact-validator/src/lib.rs:167`) still carries exactly one field, `level`, and
`validate()` never calls `run_battery` — the two are parallel entry points, and every in-tree
`run_battery` call site is a test.

**The scoping is defensible and stays.** R4's argument was that a kit which doubles its check count
doubles the visibility of "fails loudly per check, hangs per battery", so the budget belongs to the
battery R4 added. `validate()`'s per-check deadlines are unchanged and each one still fails loud.
What is not defensible is §17 reading as though the older entry point were fixed: it is the
documented downstream conformance route (§9.1, §10.4), a `Level::Full` run boots several VMs
sequentially, and a wedged boot there is still bounded only by the sum of the per-check deadlines.
Recorded here so the gap is not lost when §17's line is read as closed.

**SUPERSEDED 2026-08-17 by a later decision, not by disproof.** The fix pass took the one-field
option: `ValidationOptions` now carries `run_budget: Option<Duration>`, defaulting to
`Some(DEFAULT_RUN_BUDGET)` (20 minutes), and it bounds the **whole** run across every level
(`crates/vmcell-artifact-validator/src/lib.rs`). Per-check deadlines are untouched and each still
fails loud; exceeding the budget is `Error::Timeout` naming the budget, the level that outran it and
the checks that completed first — never a hang and never a green report with its tail missing. `None`
opts out explicitly, for a caller that bounds the run itself. So the scoping recorded above was
defensible and is no longer the shipped shape; what stays true is the reason it was defensible. §17
now records the gap as closed **by its own field, not by delta 3's**, and §10.4 records the addition as
the breaking, ledger-owing edge it is. **The two budgets stay two constants on purpose** —
`DEFAULT_RUN_BUDGET` and `conformance::DEFAULT_BATTERY_BUDGET` bound different rosters, and one const
for both would silently re-budget one when the other's roster grew.

~~One design sentence outside §17 still states the old fact…~~ **FIXED** by the 2026-08-20 loose-end
pass (Tier A10): the toolkit paragraph said "there is deliberately **no overall wall-clock budget on
`validate()`**", which the shipped `run_budget` field made false, and it now states the field, its
default, its `Error::Timeout` shape and its explicit `None` opt-out. §18's delta-register premise
record still describes the pre-delta state, correctly and deliberately — that is what a recorded
premise IS, and editing it would falsify the register's own history.

## Recorded (AGENTS rule 4 — "cover it or record it"): the shipped-knob live-coverage gap

Rule 4 asks for the enumeration of what the suite structurally cannot reach. This pass measured it
for the config surface; every item below is *shipped, documented, and never exercised by a live
boot in any gate*. The rendering half of each is unit-tested — what is missing is evidence that the
value reaches the kernel, the VMM or the guest and does anything.

- **`ResourceLimits`: three of four fields.** `crates/vmcell/tests/metrics_limits.rs:38` sets
  `mem_max_mib` and nothing else; `cpu_max_pct`, `pids_max` and `io_max` appear in no integration
  test in the tree. `io.max` is the sharp one — its `device` field is a caller-supplied
  `"major:minor"` string and the kernel's rejection of an unsupported device has never been
  observed — and §7.3's own history (a `memory.max` that did not bind until `memory.swap.max=0` and
  `memory.oom.group=1` joined it) is the record of why a rendered limit is not an enforced one.
- **`ConsoleMode::VirtioConsole`.** `console_mode` appears zero times under `crates/*/tests/`. Three
  backends advertise `virtio_console: true`; the honesty pin at `tests/nested_virt.rs:45-53` says in
  its own comment that the flag "has no dedicated matrix integration leg". The only live evidence on
  record is the `bench-vm` console table (CH and QEMU); crosvm's claim rests on an arg-builder unit
  test alone.
- **`Timeouts::low_latency()` / `throughput()`.** Constructed only in one `config.rs` clamp test and
  in `bench-vm`; no integration test boots a VM under a non-default profile. See the next entry for
  why that matters more than it looks.
- **`ksm_mergeable`.** Builder and rejection tests exist; nothing asserts the coupling
  `cloud_hypervisor.rs:719-720` implements (`shared: !ksm_mergeable, mergeable: ksm_mergeable`).
  §8.3 calls that coupling mandatory and records the measurement that makes it so — KSM merges
  **zero** pages of a `shared=on` guest — so a regression that set `mergeable` and left `shared` on
  would deduplicate nothing, silently, which is the F1 shape.
- ~~**`RestoreMode::Eager` / `Lazy`.** Present in backend unit tests as refusal/argv assertions; no
  gate performs a restore under either mode.~~ **CLOSED** 2026-08-21 (loose-end pass, Tier D) — a live restore is now
  performed under each non-default mode, with the `--restore` value read off the LIVE VMM process's
  argv and an egress byte asserted afterwards. See the wave-4 entry at the end of this file.


Recorded rather than closed because each costs a live boot in an already-long suite and none is a
correctness risk to the default path. The two worth closing first are `ksm_mergeable`'s coupling (a
KVM-free serialization assertion on the CH payload, the `CH_RAW_IMAGE_TYPE` shape, costs nothing)
and a `cpu_max_pct` leg (the one limit whose enforcement mechanism differs from memory's).

**SUPERSEDED IN PART, 2026-08-17 — the true remaining state, and the legs that now exist.** The fix
pass closed most of this enumeration, so the list above is history; what follows is the record rule 4
actually asks for.

*Closed, each with the leg that closes it:*

- **`cpu_max_pct`** — `metrics_cpu_quota`, a matrix leg
  (`crates/vmcell/tests/metrics_limits.rs`): `cpu.max` reads back the exact `(quota, period)` pair a
  25% request renders to, **and** the same in-guest load the un-throttled leg runs measures inside a
  band whose ceiling sits below that leg's floor — so the two legs cannot both be green on a host
  where the quota is a no-op.
- **`pids_max`** — `metrics_pids_max`, matrix. The subject is the **host** tasks in the VM's slice,
  not the guest's processes, so the load is a helper shell that moves itself into the slice and forks
  until the kernel refuses; the data plane is `pids.events`' `max` counter going 0 → nonzero, with the
  booted VM's own `max 0` as the positive control. The cap is 64, and the figure is measured, not
  guessed: `pids.peak` on a booted VM is 9/4/7/**18** for CH/FC/QEMU/crosvm and transient device
  activation runs higher, which reddened a 32 once in four runs.
- **`ConsoleMode::VirtioConsole`** — `virtio_console`, matrix (`crates/vmcell/tests/nested_virt.rs`),
  two data-plane assertions for the two halves of the desync it guards: the guest's *active* console
  is `hvc0` (`/sys/class/tty/console/active`, so the cmdline token took effect) and a marker the guest
  writes to `/dev/console` arrives in the host's `serial.log` (so the attached device sinks there).
  `require_cap!` makes the FC skip honest, and the KVM-free honesty pin beside it is what keeps that
  skip from going dark. Recorded at the leg: CH, QEMU **and crosvm** pass it; crosvm's
  `--serial hardware=virtio-console` claim previously rested on an arg-builder unit test alone.
- **`ksm_mergeable`** — `ch_memory_payload_couples_ksm_mergeable_to_unshared_memory`
  (`crates/vmcell/src/vmm/cloud_hypervisor.rs:1217`), the KVM-free serialization pin this entry asked
  for, both ways. The arm also moved out of `create()`'s body into a named function so the string
  `ksm` appears in the file at all.
- **`DiskIoLimit::iops`** — `extra_block_iops_throttle`, matrix
  (`crates/vmcell/tests/extra_block.rs`): two disks in one VM, one un-throttled as the in-VM baseline,
  and 300 4 KiB **`iflag=direct`** reads so the guest page cache cannot coalesce 300 requests into a
  handful and hide a 50-IOPS cap. Recorded at the leg: CH 10 ms/5067 ms, FC 9 ms/4362 ms,
  QEMU 13 ms/5882 ms; crosvm records `SKIP crosvm disk_io_throttle`.
- **The daemon's `ExtraDiskSpec.io_limit`** — `extra_disk_io_limit_over_api_throttles_the_guest_read`
  (`crates/vmcelld/tests/integration.rs`), same self-calibrating shape over REST, which is what makes
  the DTO → `vmcell::DiskIoLimit` translation observable (swapping `DiskIoLimit::new`'s two positional
  arguments used to keep every gate green).
- **`NetMode::snapshot_eligible`** and the daemon's snapshot-ineligibility refusal (docs/90 T5) —
  `snapshotting_on_an_ineligible_net_mode_is_refused_at_the_daemon_boundary`
  (`crates/vmcell-daemon/src/registry.rs:961`), KVM-free with its positive controls, plus
  `snapshot_eligible_is_exactly_the_net_modes_with_no_vhost_user_device` on the predicate itself.
- **The confinement state of a running VMM** (docs/90 T6) — `crates/vmcell/tests/vmm_confinement.rs`,
  which resolves the live CH pid through `naming::scratch_dir_name` (never a test-local `format!`)
  and reads `/proc/<pid>/status`, with a `VmmSeccomp::Disabled` boot as the red-on-inverse control.
  Everything the `/bin/cat` stand-in cannot reach — CH re-arming handlers, installing its own filters,
  spawning vcpu/api threads — happens after the stand-in's last assertion.

*Still open, and now stated precisely:*

- **`io_max`'s enforcement half.** What landed is the **refusal** path:
  `requested_io_max_is_refused_loudly_and_never_silently_unenforced` proves a requested `io.max` that
  cannot be applied refuses the boot rather than reporting isolation the VM does not have, with the
  same config minus `io_max` as the positive control, and it asserts *which* of two errors specifically
  — decided by a measured host fact (`io` in the parent's `cgroup.controllers`) rather than "either
  error will do". **Which arm runs is measured, and it is the not-delegated one**: a default systemd
  *user* session delegates `cpu memory pids` and not `io`, all the way down, so the kernel's own
  `ENODEV` verdict on a bad `major:minor` — the sharp half this entry named — stays unobserved on this
  host class and that arm is written-but-dead here. And no leg anywhere measures an `io.max` actually
  *throttling* a guest, because the controller it needs is not delegated to reach.
- **`Timeouts::low_latency()` / `throughput()` as presets.** No suite boots either one. What the fix
  pass added is the property the presets differ in: `crates/vmcell/tests/guest_tuning.rs` boots a cell
  whose `guest_rebind_idle` is 16× the default and catches the guest honoring it (see the next entry),
  and `every_shipped_timeouts_profile_is_honored_by_the_guest_verbatim` pins KVM-free that each
  shipped preset's values sit inside the shared clamp window, so a preset would be honored verbatim
  rather than clamped. The other fields of a preset still reach no live boot.
- ~~**`RestoreMode::Eager` / `Lazy`.** Unchanged: refusal and argv assertions only; no gate performs a
  restore under either mode.~~ **CLOSED** 2026-08-21 (loose-end pass, Tier D) — a live restore is now
  performed under each non-default mode, with the `--restore` value read off the LIVE VMM process's
  argv and an egress byte asserted afterwards. See the wave-4 entry at the end of this file.


## Recorded: the guest tuning-token channel has no falsifiable end-to-end gate

`vmcell_accept_poll_ms=` / `vmcell_rebind_idle_ms=` are hand-spelled on both sides of the process
boundary — host at `config.rs:429`, guest at `vmcell-steward/src/options.rs:200,207` — with no
shared const, because `vmcell` does not depend on `vmcell-steward` (the same asymmetry
`STEWARD_VSOCK_PORT` solved by moving to `vmcell-protocol`, which both link). On its own that is
survivable. What makes the channel **unfalsifiable** is that the guest's compiled fallbacks are
byte-identical to the host's emitted defaults: `ACCEPT_POLL = 20 ms` / `REBIND_IDLE = 250 ms`
(`options.rs:130,140`) against `guest_accept_poll: 20 ms` / `guest_rebind_idle: 250 ms`
(`config.rs:358-359`). Rename either literal, or delete the guest's parse block outright, and every
suite stays green — the steward falls back to exactly the numbers the host meant to send.

The user-visible consequence is narrow but real: a caller selecting `low_latency()` (5 ms / 150 ms)
gets the compiled 20 / 250 cadence, and nothing reports that the request was ignored — including the
post-restore re-bind window, which bounds how long a restored guest stays unreachable after CH
re-creates the vhost-vsock device.

**SUPERSEDED 2026-08-17: both halves landed, and one narrow half of the unfalsifiability remains.**

- **The spelling drift is closed at compile time.** Each token is now **one** value in
  `vmcell-protocol` — the crate both sides link — carrying the four facts the two ends must agree on
  together: `TuningToken { token, default, floor, ceiling }`, as `STEWARD_ACCEPT_POLL` and
  `STEWARD_REBIND_IDLE`. The host renders through `TuningToken::render` and derives
  `Timeouts::default()`'s values and `clamped()`'s floors from the same consts
  (`crates/vmcell/src/config.rs:385,409,473`); the guest's fallbacks are `= token.default` and its
  untrusted-input parse takes the floor and ceiling from the same place
  (`crates/vmcell-steward/src/options.rs:137,150,213`). So "the guest's fallback equals the host's
  default" is now true **by construction** rather than by coincidence — which is the point worth
  keeping: the two being equal was never the defect, and making them deliberately different would turn
  an omitted token into a silent behavior change for every already-packed rootfs. The `token` string is
  a compatibility surface (the parser is baked into `rootfs.erofs`), so it is pinned as a literal by
  `the_tuning_tokens_are_the_wire_spelling` in `vmcell-protocol` while renaming the *const* is a
  compile-time move on both sides at once.
- **The unfalsifiability is closed for the re-bind window**, by a live boot rather than a shared const:
  `crates/vmcell/tests/guest_tuning.rs` boots a `Pid1` cell whose only non-default property is
  `guest_rebind_idle` at 16× the default and **counts the distinct `socket:[…]` targets under
  `/proc/1/fd`** over a fixed in-guest sampling window — a fresh `bind` gets a fresh inode, so the
  count *is* the honored cadence, read out of the kernel's own bookkeeping with no guest-side code
  added for the test (law C6's spirit). Paired in one test against a default-window cell on the same
  rootfs, because the number alone means nothing: a guest that ignores the token produces the *same*
  count for both, which is the pre-fix behavior said out loud. The elapsed seconds are asserted too,
  so a `sleep` that did not sleep cannot make the low-churn half pass vacuously. The serial log is
  deliberately not the observable — the steward logs at `info`, the guest carries no `RUST_LOG`, and
  `tracing_subscriber` keeps everything below `error` off the console, the trap the declared-port leg
  already fell into.
- **What remains: `guest_accept_poll` has no live observation.** Its cadence is not the connect
  latency — the accept path blocks in `poll(2)` and wakes sub-millisecond — so it is load-bearing only
  on the failure paths (the `bind` retry, and everything `recovery_backoff` rate-limits), and no live
  suite drives those. Its spelling, default, floor, ceiling and rendering are all shared and pinned;
  what is unobserved is a guest *acting* on a non-default value of it. Left open deliberately: the boot
  that would close it has to induce a steward failure path, which is a different fixture from the one
  above.

## Recorded: `review-preflight-priv.sh`'s READY answers "can the suites run", not "is the runner current"

The preflight checks that the blessed runner carries the four capabilities with the effective bit
and that its mode is 0700. It does **not** compare the blessed copy against the current source — the
staleness check is the content-hash `.blessed` stamp, and that lives only in the `bless` recipe,
which needs one sudo and therefore cannot run in a non-interactive session.

Measured during this review: the preflight printed READY while the blessed copy
(`.vmcell-bin/debug/vmcell-test-runner`, 2026-08-14 11:24) predated `d02527b`'s rewrite of the
privilege transition into a step-list executor. The probe is decisive — `strings` finds **0**
occurrences of `PrivilegeStep` in the blessed copy and **84** in the current build — so every
privileged run since 2026-08-15, including this review's 228/228 and the v33 handoff's stated bar,
executed through the pre-rewrite binary. `bless` detected it correctly and refused to replace a
working blessing when sudo was unavailable, which is the stage-then-swap design working as written.

**CI is unaffected and that is why this is recorded rather than urgent**: `.github/workflows/ci.yml`
runs `just bless` between building the artifacts and the privileged suite, so a CI runner is always
current. The exposure is the local reviewer path, which AGENTS rule 5 sends through the preflight,
and the v5 handoff's reproduction sequence omits the bless step. No behavioral difference between
the two binaries has been demonstrated — the risk is that the live gate on the runner's *own*
posture (`the_bounding_set_is_shrunk_to_exactly_the_delivered_caps`) certifies whichever binary
happens to be blessed.

**SUPERSEDED 2026-08-17 — the preflight now answers both questions, and the answer is clearable.**
`scripts/review-preflight-priv.sh` gained a **blessing-freshness** verdict beside its capability and
mode checks, and it decides freshness the way a non-interactive session can: sha256 of the stable copy
against the `.blessed` stamp, plus `find -newer` over the runner's whole in-tree source closure
(`crates/vmcell-test-runner/src`, `crates/vmcell-privilege/src`, `Cargo.lock` — overridable through
`VMCELL_RUNNER_SRC_PATHS`, and a root that does not exist is skipped so a partial checkout cannot make
the probe fail). No cargo, so it takes no build lock. A stale blessing maps onto the **existing**
BLOCKED-ON-BLESS exit (2) rather than a new verdict, so nothing that consumes the exit code needs to
learn a third one — the agent contract is unchanged: block and ask for one `just bless`, never
downgrade to static-only on a capable host.

**One anti-wedge rides with it, and is the deviation worth naming.** The freshness probe's inputs are
timestamps, and `just bless`'s own hash check legitimately takes a *skip* path when the runner's bytes
are unchanged — which would leave the copy un-re-dated and the preflight blocking forever on a
blessing it cannot clear. So `bless` `touch`es the stable copy and its stamp at both exits where it
*knows* the hash matches (`redate_for_freshness_proxy`). That is deliberately a timestamp-only move: it
never re-runs `setcap` and never changes what the copy contains, so it cannot manufacture a blessing —
it only lets the one command that authoritatively knows the verdict is spurious clear it. The
anti-wedge has its own gate, a harness that runs the real recipe against the real preflight in fixture
repos (`scripts/test-bless-redates-blessed-copy.sh`) and asserts this checkout's own `.vmcell-bin` was
not touched.

The measurement above stands as the record of what was true on 2026-08-16, and the documented
reproduction sequence in the rubric now carries the bless step. `docs/historical/89-claude-handoff-notes-v5.md`
is deliberately left as written — see the docs/90 fix-wave section below for why a retired handoff is
not corrected.


---

# As built: the docs/90 fix waves (2026-08-17)

Three lanes landed the code half of `docs/90` in one pass: the correctness findings, the gates that
could not go red, and the coverage legs. **The per-fix record is at the fix** — each one ships its
red-on-inverse and its rationale in the source it changed, and the gate roster's own record is
`just gates` plus each script's header. What follows is what those cannot carry: the places the
shipped fix **deliberately deviates** from what docs/90 directed, and the reason. Where a finding was
fixed the way it was directed, it is not here.

## The health-gate window is selected PER ATTEMPT, and the caller's budget enters as its default (M2)

docs/90 M2 directed "select the budget on the placement, keeping the 4 s constant for `Pid1` and
deriving the `Service` window from the caller's connect budget **threaded into `start()`**". The
selection landed; the threading did not, and the window is per-attempt rather than overall. Both are
deliberate.

`orchestrator::control_plane_probe_budget(placement)` is the one policy site — exhaustive on
`StewardPlacement`, so a new placement is a compile error rather than a silent inheritance — and it
answers `CONTROL_PLANE_PROBE_BUDGET` (4 s) for `Pid1` and `None` and `DEFAULT_STEWARD_CONNECT_BUDGET`
(10 s) for `Service`.

* **Per attempt, not overall.** §3.5 said "the gate's overall window"; this bounds one probe, and a
  re-spawn buys a fresh one. The re-spawn loop exists for QEMU's vhost-user vsock bring-up race, which
  is **placement-independent**, so collapsing the gate into a single overall window would shrink a
  `Service` cell's recovery from four re-spawns to one — trading the failure §3.5's sizing exists to
  prevent for a different one.
* **The caller's budget is its default, because `start()` has no other access to it.** `Timeouts`
  carries no connect-budget field — §9.3 says so deliberately — and the real per-call window is
  `steward(timeout)`'s argument, which arrives *after* `start()` has returned. Giving `MicroVm::start`
  a budget parameter would be a breaking signature change on a contract crate (§10.4), taken to move a
  bound the default already sizes correctly. So `DEFAULT_STEWARD_CONNECT_BUDGET` is named once and read
  by three sites — the two connect entry points' `unwrap_or` and the selector — which keeps a change to
  the default from moving the gate out from under it.

**Both narrowings are now in §3.5 itself**, named as narrowings of the wording it used to carry, so the
design and the code agree and this entry is the reasoning rather than an erratum. The comment above the
call site — which used to restate the unimplemented sentence almost verbatim, asserting it as shipped —
now says the sizing is a branch and points at the selector.

The gate is a call-site scan with its own red-on-inverse:
`the_health_gate_is_handed_the_window_the_placement_selects` requires the one
`.verify_control_plane(` site to pass the selector, and requires `CONTROL_PLANE_PROBE_BUDGET` to
appear **exactly twice** in production text (its `const` and the selector's `Pid1` arm) — a third
mention is a second policy site, which is how the branch got lost the first time.
`the_window_predicate_rejects_a_bare_constant_and_a_second_policy_site` drives the predicate against
the M2 defect itself, an inline literal, a bypassing second probe, and no probe at all.

## The restored VM reserves its ancestor's vmid when free, and WARNS when it is already claimed (M9)

docs/90 M9 directed "reserve the ancestor's vmid across the restore". It is reserved — but a
conflicting reservation is accepted with a warning, not propagated, and that is the deviation.

`MicroVm::restore` asks `vmm::adopted_scratch_vmid(prefix, own_dir, instance.vsock_path())` whether
the backend adopted somebody else's scratch directory (Firecracker does: `PUT /snapshot/load` has no
override for the baked vsock UDS), and on `Some(ancestor)` calls `VmidGuard::adopt_lineage(ancestor)`
**before** the resume — a squatting VM must not be brought back up. The guard carries the ancestor as
a second `Option<u32>` field, released in the same `Drop`, so the `m2` teardown order holds for free.

**Why not unconditional.** The property wanted is "no *other* VM may draw `ancestor` while we live in
its directory", not exclusive ownership of the claim — and two live restore suites deliberately hold
the source's vmid across the restore precisely to force rotation
(`crates/vmcell/tests/snapshot_restore.rs:356` and `crates/vmcell/tests/extra_block.rs:407`, each with
the same recorded reason: without the reservation the freed vmid can be re-handed and the rotation
assertions pass on a no-op). Failing a restore for being in the state the reservation exists to create
would be backwards. So an already-claimed id satisfies the property and is accepted with a warning
saying whose claim it is; `self.lineage` is set **only** when the claim is ours, so `Drop` can never
hand a live VM's identity back to the pool — a worse version of the defect being fixed. The
destructive shape (a *live* VM in the ancestor's directory) is still refused one layer down, by the
backend's own `reject_live_baked_vsock` probe the restore already ran. Non-conflict errors do
propagate: an out-of-range id is `Error::Config`, an unusable lock directory is `Error::Io`, because an
unusable lock directory is not a conflict.

Gates: `adopted_scratch_vmid_names_the_ancestor_and_only_a_real_scratch_path` and
`a_restore_holds_the_ancestor_vmid_its_adopted_paths_are_keyed_on`
(`crates/vmcell/src/vmm/mod.rs:1755,1820`).

## The NAT's guest→host queue is bounded, which means a stalled poll tick TAIL-DROPS guest frames (M7)

Two changes in one module, and the second is a behavior change worth stating plainly.

* **A refused avail ring costs one pass, never the vring worker.** `process_tx_queue` returns a
  `TxPass` value (`Drained` / `Unreadable`) instead of `io::Result`, because an `Err` out of
  `VhostUserBackendMut::handle_event` is **terminal** in the vendored framework: the worker thread
  returns and `VhostUserHandler::drop` discards that value at `join` (it only reports a panic), while
  the device stays attached — so the guest keeps seeing a live link that never drains again, the B1
  silent-wedge shape one error path over. `virtio-queue` refuses the ring for three guest-reachable
  reasons (its own misbehaviour detection, a not-ready queue, an unmappable ring address), and the NAT
  exists to survive a hostile guest. `Unreadable` ends the tick and re-arms the kick, so a guest that
  re-initializes its ring is served again; re-polling a refused ring would spin on the state mutex the
  net thread needs. Gate: `a_refused_avail_ring_costs_one_pass_not_the_vring_worker`, whose comment
  records the two ways it goes red — restore the `?` and `handle_event` returns `Err`; re-poll and it
  never terminates.
* **THE BEHAVIOR CHANGE: `tx_queue` is bounded at `MAX_TX_QUEUE_FRAMES` (4 × `QUEUE_SIZE`, ≈6 MB at
  the 1512-byte frame cap), and a full queue tail-drops.** The queue's only consumer is `run_network`'s
  poll tick, and that tick legitimately stalls — one mapping's host dial owns the single datapath task
  for up to `HOST_DIAL_BUDGET` — so an unbounded queue handed a guest that keeps kicking its TX ring
  during such a stall unbounded *host* memory. Per-frame bytes were bounded by `MAX_FRAME_LEN`; the
  frame **count** was not. Dropping is the only correct answer at that site: the alternative, blocking
  the vhost worker until the net thread catches up, holds the state mutex the net thread needs to drain
  the queue. The descriptor is still returned to the guest so its ring never stalls, and TCP
  retransmits what was dropped — which is why the depth is four ring-depths rather than one: the vhost
  worker can drain the guest's whole 1024-descriptor ring several times between two 5 ms poll ticks, so
  only a genuinely stalled consumer ever reaches the bound. A legitimately bursty guest is not dropped;
  a guest that outruns a wedged consumer loses frames instead of the host losing memory. Gate:
  `push_tx_frame_bounds_the_queue_depth`.

## Inputs `VmConfigBuilder::build` used to accept are now REJECTED (M3 and its siblings)

A deliberate boundary tightening, observable by a consumer, so it is recorded here as well as in the
`build()` rustdoc's own error list — which is the authoritative roster; these are the three classes it
grew.

* **A `"` in an `init` override, an append-only extra kernel arg, a share `tag`, or a share
  `guest_path`.** One law, `config::is_cmdline_unsafe_char` (whitespace, control characters, `"`),
  shared by all four surfaces because all four land in the kernel's whitespace-separated token list.
  `"` breaks F3 two different ways: `next_arg` strips a **leading** quote *before* taking the parameter
  name, so `"rw` runs `__setup("rw")` and clears `MS_RDONLY` under the owned `ro` + `rootflags=noload`
  (silent filesystem corruption), and a quote anywhere else toggles `in_quote`, so whitespace stops
  separating parameters and every token emitted after it — `panic=1`, `init=`, `vmcell_vmid=` — is
  swallowed into that token's value. The first was reachable from any authenticated REST client
  (`CreateVmRequest::extra_kernel_args` threads straight to `with_kernel_arg`).
  **Two independent layers landed, not one**: the character rejection above, and
  `normalize_cmdline_key` now folding a leading `"` the way it already folded `-` → `_`, so
  `is_reserved_cmdline_arg` answers about the token the *kernel* reads even on a caller path that never
  met the first guard. The single-token guard runs **before** the collision check, so a quoted token is
  refused outright rather than keyed.
* **A relative `kernel` path.** Every other host path this config names was checked for absoluteness
  at the boundary (rootfs image and overlay, extra-disk images, share host paths); the kernel was the
  one that was not, so a relative path resolved against whatever CWD the VMM child inherited — the
  daemon's, not the caller's — and surfaced three layers down as a VMM "cannot open kernel".
  Existence stays unchecked, as for every other artifact path.
* **`host_services_port: Some(0)`.** Port 0 is `bind`'s wildcard, never a reachable service, and the
  NAT registers this port as a **permanent** forward listener whose re-arm discards its `Result` on the
  stated grounds that "forward ports are non-zero". That precondition was nobody's job to enforce, so
  `Some(0)` built a VM with a listener that could never come up, silently; enforcing it here is what
  makes the discard honest (F1).

Gates: `extra_kernel_args_cannot_clobber_reserved_tokens` (`crates/vmcell/src/config.rs:4609`) carries
the quoted-reserved-key legs **and** an assertion on the *composed* line that no emitted token carries
a `"` — the alias class the emitted-token coverage gate structurally cannot discover;
`test_reject_relative_kernel_path` pairs the refusal with a positive control on the same shape (the
absolute path builds, and a non-existent one still builds), because over-rejecting here would break
every caller. The fuzz oracle moved with the predicate
(`fuzz/fuzz_targets/kernel_cmdline_args.rs`) — it had shared the blind spot by modelling the key the
same way.

## The euid-0 short-circuit is gone, deviating from §11.2's letter — and the letter moved with it (M5)

§11.2 stated the blessing precondition as "the three caps present in the **effective** set, **or**
`euid == 0`". The `or` is deleted: `vmcell_privilege::blessing_verdict(euid, effective, need)` refuses
whenever a cap is missing, at any euid — a deliberate deviation from the design as written, and §11.2
now reads "unconditionally, with **no euid exemption**", carrying the reasoning below and the
short-circuit's history as the fail-open it was. So the two agree; what follows is why the code, not
the design, was the side that was right.

**Why the design's letter was wrong rather than the code.** Real root with a narrowed effective set is
the *common* production shape, not an edge case: default container root holds neither `CAP_NET_ADMIN`
nor `CAP_SYS_ADMIN`, and a systemd unit with `User=root` plus a `CapabilityBoundingSet=` that omits one
of the three is the documented deployment. Under the short-circuit `vmcelld` started cleanly there,
printed its precondition as satisfied, and then failed every privileged create at first use — the
"degraded server" outcome law P1 exists to forbid, arrived at through the one function the daemon and
the runner share. A genuine full-authority root process still passes, because it holds the caps in its
effective set, so nothing that legitimately worked stops working.

**The euid did not become unused — it moved from deciding the verdict to selecting the remediation**,
which is the reason it is still read. `BlessingRefusal::Unblessed` prints the `setcap …+ep` line;
`BlessingRefusal::NarrowedRoot` deliberately does **not**, because a file capability is masked by the
process's own bounding set, so telling a container root to run `setcap` is advice that cannot work — it
names the container runtime's `--cap-add` and the unit's `AmbientCapabilities=` instead. Splitting the
verdict out as a **pure** function is what makes P1's start-up gate testable at all: the euid-0
narrowed shape is unreachable on a host the suite runs on. Design §13's named gate for P1 did not
exist and now does — `blessing_precondition_gate::a_narrowed_root_cannot_start_this_daemon` in
`crates/vmcelld/src/main.rs`, beside a prose gate on the call site's own comment so the comment cannot
go on claiming an exemption the code no longer grants. Breaking for a caller: `blessing_remediation`
takes a `&BlessingRefusal` where it took a `&[Cap]`.

## A destroy-in-progress VM is refused by STATE (409) where it used to 404 (M6)

`Registry::destroy` removed the slot from `self.vms` **before** awaiting the per-VM handle lock, and
the delete-in-use scan reads pins — kernel, rootfs, extra disks, and the snapshot prefix being written
right now — only through that table. So for the whole duration of a multi-second guest-RAM snapshot the
VM was unpinned: a concurrent `DELETE /v1/artifacts/<prefix>` found a pin-free table, returned 204, and
`remove_dir_all`'d the directory the VMM was still writing into.

The order is now mark `Destroying` in place → take the handle lock → remove from the table, in one
private `teardown_slot` that `destroy` and `shutdown_all` share (teardown is ownership, through one
ordered helper — `shutdown_all` clones the slot list instead of draining it, for exactly this reason).
Lock order is `inner` → `vms`, and no path holds `vms` across an `await` on `inner`.

**The consumer-visible change:** an op racing a teardown used to see the VM *gone* (404 `NotFound`) and
now sees it *doomed* (409 `Conflict`) until the teardown completes, then 404. That is the better
answer — a VM whose teardown is still running has not been destroyed — and it is promptly given rather
than queued behind the teardown, which the gate asserts with a timeout. A teardown **cancelled** while
parked (an HTTP client that disconnects) leaves the slot in the table as `Destroying` with its handle
intact: accounted for in `GET /v1/vms`, refusing new ops, and completed by a retried `DELETE` or by
`shutdown_all` — recovery stays retryable rather than silently dropping a live VM out of the registry.
Gate: `a_destroy_parked_on_the_handle_lock_keeps_the_snapshot_prefix_pinned`
(`crates/vmcell-daemon/src/registry.rs:1264`), red on the pre-fix order in two places at once.

## The labelled handler reaches the pack tail, and the stage version moves with every existing key UNMOVED (H1/H2/M10)

The three findings are one wiring hole and its identity consequence.

* **One key, composed once.** `PackOptions::handler_key()` is the single place the rootfs side composes
  a handler artifact key, read by the two consumers that must agree: the pack tail (which reads the
  binary) and `RootfsStage::cache_key`'s consumed-artifact fold (which hashes what it consumes). The
  fold's `consumed` set is `["steward", options.handler_key()]` off the **same** `PackOptions` value the
  tail packs with, not a hardcoded `["steward", "guest_tools"]` — two spellings of "which handler is
  this?" is precisely how the identity and the bytes come to disagree.
* **`OCI_ROOTFS_STAGE_VERSION` 7 → 8, and every key that can exist today is bit-for-bit unmoved.** The
  default handler's key *is* `guest_tools`, and until this fix a labelled handler never reached the tail
  at all — so no cache key moves. The bump is the identity-fold discipline applied anyway (the same
  reasoning delta 6c's conditional arm was bumped under): one re-pack is harmless, and a fold whose
  inputs changed shape gets a bump whether or not any existing input's value did. The const stays
  module-level so the bump itself is assertable KVM-free
  (`rootfs_stage_version_pins_the_identity_fold_bumps`).
* **`default` is normalized at the one intake.** `PackOptions::with_handler_label` runs the label
  through `registry::registry_label`, so the reserved `default` spelling collapses to `None` — because
  §10.5's byte-identity rule is a claim about the *artifact*, and `Some("default")` composed
  `guest_tools-default`: a different stage name, artifact key, output file and cache key than the
  omitted spelling. Normalizing at the intake rather than at each composing site is what keeps the two
  readers from disagreeing about which handler the pack meant. The CLI now normalizes **both** labels
  (it normalized only the rootfs one), which is M10.
* **H2 is the one-line change the general tail was created for:** `oci::build_rootfs_with` calls
  `pack_rootfs_with_injection`, not the erofs-only door, so a registry entry declaring `format: ext4`
  can be built at all.

The gate is the live leg delta 6b deferred to delta 9 and delta 9 shipped without:
`crates/vmcell/tests/handler_cell.rs` registers a `handlers` entry, builds the rootfs that bakes it,
boots it, and asks **that handler's own `xattr` applet** — which answers with a real `listxattr(2)` —
so one applet proves its own liveness plus the presence of the multicall binary at the dest the
manifest names. Its sharpest leg is a negative with a control: `/vmcell-tools/curl` must be **absent**,
because `curl` is in `GUEST_TOOLS_APPLETS` but not in this entry's declared roster, which is what proves
the emitted symlinks came from the registry entry (data) rather than from vmcell's const.

## The ext4 battery's absent-facility answer is ONE law, CI obtains the facility — and the discovery behind both (G3)

**The discovery first, because it is the lesson.** The delta-8 commit's ext4 legs `panic!`ed on an
absent producer, on the argument that `e2fsprogs` is `Priority: required` everywhere vmcell builds. The
*package* is; the *version* is not. `mkfs.ext4 -d <tarball>` — the form the whole producer is built on
— landed in e2fsprogs 1.47.1, GitHub's `ubuntu-24.04` image ships **1.47.0**, and this workstation
ships **1.47.2**. So the review pass that introduced the panic validated every suite locally, green,
while — as recorded at the fix — `test-unit` and `test-integration` were red on the runner for four
commits (four failing tests, each retried four times by the integration profile).
**Validating only where you are is not validating**:
the tree's own preflight discipline is about probing the host you run on, and this is its complement —
a host-facility premise needs the *other* host's version, not just a passing local run. A permanently
red job is a job nobody reads, which is a worse outcome than a recorded skip.

**One law, three call sites.** The three delta-8 files answered "this host cannot pack ext4" three
different ways and two were wrong: `ext4_producer.rs` panicked (above), and
`repack_outside_checkout.rs` printed a bare `println!("SKIP")` and returned — the green PASS AGENTS.md
names — under a doc comment claiming to record a skip, with no `record_capability_skip` call anywhere in
the file. `common::probe_ext4_or_record_skip` is now the one answer for all three
(`crates/vmcell/tests/common/mod.rs`): `Some(producer)` is the product's own unforgeable receipt (the
type's fields are private to `vmcell`, so only a probe mints one), `None` **after** appending
`SKIP cloud-hypervisor ext4_producer` to the run's manifest when the probe classifies the facility as
*absent*, and a **panic** when it classifies it as *broken* — §7.2 rule 3, and skipping on that would
be the green-PASS defect wearing the probe's clothes. `every_ext4_battery_asks_the_one_law` is the
call-site scan that keeps a fourth answer from appearing, and
`the_one_skip_law_records_the_gap_rather_than_only_printing_it` is the law's own gate — which needed
two seams (the probe verdict and the manifest sink as parameters) because the arm that matters is
unreachable on any host that can run the battery. The scratch sink is not fastidiousness: appending a
synthetic `SKIP` to the run's own manifest would put a capability gap that does not exist in front of
the next reviewer.

**A recorded skip is not coverage, so CI obtains the facility instead.** Both jobs that run these legs
build a **pinned** e2fsprogs 1.47.2 from source ahead of the suites — checksum-verified against
upstream's published digest, cached on a key that includes the digest (so a re-pin can never be served
the tree built from the bytes it replaced), `libarchive-dev` first because `mke2fs` *dlopen*s
libarchive and `-V` is therefore blind to its absence — and the step is **non-gating**: with the
facility the battery runs, without it the law above records the skip, and a red job is the outcome that
was just removed. 1.47.2 rather than the newest release, because every measured constant in
`vmcell::artifact::ext4` was measured against 1.47.2, so CI agrees with the constants by construction.
The step's own gate is `ci_obtains_the_ext4_facility_rather_than_living_with_the_skip` in
`crates/vmcell/tests/ext4_producer.rs`: it asserts the ordering, the pin `>=` the producer's
`MIN_E2FSPROGS_VERSION`, the checksum, the non-gating flags, and that the two jobs' copies are
**byte-identical** (a `run:` step cannot be shared between jobs, so the identity assertion is what
keeps a fix to one copy from missing the other). `test-unit` also gained `VMCELL_SKIP_MANIFEST` plus the
reset/show steps, because a recorded skip nobody surfaces is the invisible pass one level up.

## Recorded (justified): the `mmdebstrap` handler selection is REFUSED, not honored (`vmcell-cli:906`)

docs/90 asked for the dropped `applets` roster to be **honored**; the shipped answer refuses instead —
`reject_unbakeable_handler_for_mmdebstrap` in `crates/vmcell-cli/src/main.rs`, called from the one
composition root (`build_stages`). Refusing is right, and the honoring half is not deferred work:

* **There is no reachable input to honor.** An `applets` roster beside a workspace `build` is refused by
  the handler parser itself (`crates/vmcell/src/artifact/handler.rs`), the overlay merge is leaf-wise,
  and the baseline's `default` entry carries that workspace leaf — so no overlay produces a default
  handler declaring a roster. Honoring it would add a second `PackOptions` producer no test can drive,
  which AGENTS rule 2 forbids.
* **The stage carries no field for either half, deliberately.** `MmdebstrapRootfsStage::pack_options`
  (`crates/vmcell-rootfs-builder/src/lib.rs`) is the single producer that both `run` and the identity
  fold read, which is what keeps the image and its cache key naming one handler. Threading a label
  through it gives this source a second answer to "which handler is this?" — the shape H1 hid behind for
  a release.
* **Refusal is F1's other half, and it is the actionable one.** The message names the entry, what cannot
  be baked, and the fix (`--rootfs-source oci`). A labelled handler's alternative failure is a
  missing-`guest_tools-<label>` artifact error stages later: advice the operator cannot act on.

Trade-off: this source cannot bake a labelled handler at all, and a consumer that wants one changes
rootfs source. The unreachability premise carries its own gate from the other side —
`the_baseline_default_handler_declares_no_roster_of_its_own` reddens the day the baseline registers a
digest-shaped default handler, which is the day the clause becomes reachable and the honoring question is
worth re-opening. The refusal's own gate is
`build_refuses_a_handler_registration_mmdebstrap_cannot_bake`.

## Recorded: a failed digest-sidecar write ROLLS THE ARTIFACT BACK, best-effort — and the one residual burn

`ArtifactStore::create` is all-or-nothing across both files it writes: a failed `write_sidecar` removes
the persisted artifact before returning the 500, so the error reply describes the store's actual state
(`crates/vmcell-daemon/src/artifact_store.rs`). Gate:
`a_failed_sidecar_write_rolls_the_artifact_back`, which injects the failure out-of-band the way a real
one arrives — a directory at the sidecar path, so the `rename` fails `EISDIR` — and asserts the name is
free again afterwards.

* **docs/90 §11's row for `artifact_store.rs:114` describes the pre-fix behavior as the fix.** It says
  the create "keeps the name taken rather than rolling the artifact back" and quotes the warn string that
  is only the *rollback's own* failure path. The code rolls back; that row is what is stale. Correcting
  it belongs to that document.
* **The rollback is best-effort, and that is the deliberate part.** If `remove_file` itself fails, the
  name stays taken for the daemon's lifetime — the store is create-only, so the client can neither
  re-create the name nor delete bytes it was told were rejected — and the only record is a `warn` naming
  the artifact. The client already holds its 500, and a second error class for "the rollback failed too"
  says nothing it can act on; the operator-visible consequence is that one log line plus a 409 on the
  next `create` of the same name. The deterministic instance the finding named cannot reach this at all:
  a name whose `<name>.sha256` would overrun `NAME_MAX` is a 400 at the boundary, because
  `MAX_ARTIFACT_NAME_LEN` is `NAME_MAX` minus the suffix (`crates/vmcell-daemon/src/name.rs`), gated by
  `create_rejects_a_name_whose_sidecar_would_not_fit`. What remains is a genuine `ENOSPC` or permission
  failure, where a burned name is the honest report of a host the daemon cannot write to.

## Recorded (justified): `run_battery`'s `fill_unrecorded` tail is DELETED, not repaired — and stays where it is live

docs/90 `conformance.rs:633` reported a tail that could never fire, under a comment claiming a
red-on-inverse it could not have. It is gone rather than made reachable: the battery's roster is complete
**by construction** — `battery_inner` judges every `Feature::ALL` variant, `apply_warning_lifecycle`
always pushes its own id, and `battery_check_ids` is composed from that same array — so no path returns
`Ok` with a short roster (`crates/vmcell-artifact-validator/src/conformance.rs`). Repairing the tail
would have meant inventing the path that reaches it. The property it claimed is real and is gated where
it lives: `the_battery_reports_its_whole_roster_whatever_is_declared`, red on a `battery_inner` arm that
`continue`s instead of judging.

`fill_unrecorded` itself is **not** deleted. It is the tail of `validate()`'s level runners
(`crates/vmcell-artifact-validator/src/checks.rs`, three call sites), where a level check genuinely can
go unrecorded because the run stops early. Two batteries, one helper, one live caller — what was deleted
is a call, not the mechanism.

## Recorded (justified): two docs/90 deviations that are documentation, not code (A1, D4)

* **A1 — `Cache` keeps its parameter and gains honest rustdoc.** The defect was the promise ("Cache for
  previously built artifacts"), not the argument: caching is the per-stage `.cache_key` sidecar, and
  nothing about a hit or a miss travels through the handle. `crates/vmcell/src/artifact/mod.rs` now says
  exactly that. Dropping the parameter is the other half and is deliberately not done: `Pipeline` is named
  §10.4 contract surface, so removing it is a ledgered break out-of-repo consumers are versioned
  through — a release's work, not a review pass's. Gate:
  `cache_handle_is_the_inert_placeholder_its_rustdoc_promises` — zero-sized, no inherent `impl`, every
  `&Cache` parameter `_`-prefixed — so the day the handle starts carrying anything the rustdoc reddens
  instead of going stale.
* **D4 — the stale rosters are DELETED, not corrected.** `README.md`'s applet roster and the `justfile`'s
  applet figure now point at what produces them (`vmcell_protocol::GUEST_TOOLS_APPLETS` and the recipe),
  per AGENTS.md's pointer-over-figure rule. The trade-off is real: a reader opens a const or runs a
  recipe instead of reading a number. A second copy that goes stale silently is worse, and both of these
  had.

## Recorded (justified): `config.rs`'s `fn_body` is a second copy, with its retirement condition

Two `#[cfg(test)]` helpers extract "the `{ … }` body of the function with this signature" by brace
counting, in different crates: `crates/vmcell-daemon/src/auth.rs` (the shipped idiom — the constant-time
compare's shape gate) and `crates/vmcell/src/config.rs` (C8's `resync_reachable` definition gate). The
bodies agree today. Kept duplicated because the two share no law and assert about different functions in
different crates, and the alternative — a `pub` source-scanning test helper — puts a scanning utility on
a contract crate's public surface to serve two callers. It is recorded here rather than in the one-law
roster because that roster names laws with a single implementation, and this is a deliberate duplicate —
AGENTS.md sends those to this file.

**Retirement condition, and the reason it is written down at all: a third copy consolidates the class.**
The condition is at the `config.rs` site too; it is here as well so the third copy meets it instead of
quietly joining a pair, which is how every duplicate this tree has since consolidated started out.

## Two pre-existing defects the new gates fired on when they arrived

Each gate was written for a *different* instance of its class and reddened on a site nobody had gone
looking for, which is the argument for gating the class rather than the instance:

* **Another `VMCELL_CH_BIN` resolver, in `vmcell-artifact-validator`'s harness.** docs/90 A2 reported
  the CLI's copy — the *third* — and named this one among the two §17's consolidation register listed at
  the time; the CLI's was closed in the same pass and this was not (§17 now records both as delegating).
  `harness::ch_bin()` now delegates to `vmcell::artifact::ch_binary_path()` — same variable, same
  default, no behavior change — which matters because a change to the law (a second variable, a
  fallback list, a `PATH` probe) would otherwise have moved the library and left the **conformance
  battery** booting whatever the old body resolved. The CLI's in-source gate can only ever see
  `main.rs` (`include_str!` is its whole universe), which is why the repo-wide scanner exists.
* **A dangling `§12.12` in `zygote.rs`.** §12 has only 12.1–12.5 in v33. The law it cited — "a clone
  must never restore from the master" — is invariant S3, with the mechanism in §8.4, and the assertion
  message now says so. A reader who follows a dead pointer concludes the fact is unwritten and either
  re-derives it or re-argues a settled reversal.

## Three new grep-bans, and the law each one now states

Each is a scan rather than a type because the drift it catches is not a compile error, and each ships
its red-on-inverse self-test in the same `just gates` roster (AGENTS rule 3: added to that recipe and
nowhere else).

* **`ban-ch-binary-resolver-copies.sh` (A2).** The law: `vmcell::artifact::ch_binary_path()` is the one
  reader of the §10.4 contract variable `$VMCELL_CH_BIN`. It flags the **quoted variable name** anywhere
  under `crates/` (line comments stripped, so prose naming `$VMCELL_CH_BIN` is not a false positive)
  against a roster of exact per-file counts **in both directions** — an extra read cannot hide behind an
  entry, and a count that fell to zero means the entry is stale. A parity assertion was the first draft
  and cannot fail: with the variable unset both spellings answer `cloud-hypervisor`, and `set_var` is
  banned here. Scope is stated rather than implied: `VMCELL_FC_BIN`/`_QEMU_BIN`/`_CROSVM_BIN` have no
  `vmcell`-side law to route through, so banning their spellings would name no home to send the reader
  to; when one is added this gate grows an arm rather than a sibling script.
* **`ban-dangling-design-ref.sh` (D2).** The law: every `§<id>` and `Appendix <letter>` under
  `crates/*/src` names a real heading of the newest design document, discovered by
  `scripts/design-headings.sh` (one home for "which document is the design and what headings does it
  have"). It resolves ~2000 references, which is the point — the design is cited in the rustdoc of
  nearly every law, so a renumbering can invalidate any of them silently, and prose is not compiled.
  Comments are deliberately **not** stripped (a dangling pointer in rustdoc is the whole defect, and
  D2's own instance was a string literal in a document the daemon *serves* to clients). Its one escape
  hatch is self-documenting rather than a roster: a reference into another numbering must say which
  (`v30 §9.4`, `docs/78 §5`) and is skipped, with the skip count reported. The honest cost, stated at
  the gate: `Appendix X` is this repo's metavariable and is not resolved, so a citation that *meant*
  `Appendix A` and typed `X` goes unflagged.
* **`ban-inline-netns-path.sh` (`net/tap.rs`'s own claim).** The law: the `/var/run/netns/<name>`
  layout is spelled once, in `NETNS_DIR`, and composed through `netns_path`/`netns_dir`.
  `netns_path`'s rustdoc claimed "exactly one place" while four production sites spelled the literal —
  the §6.4 proxy's namespace entry, `build_vmm_cmd`'s pre-fork NUL-terminated C string, and the orphan
  scanner's two `read_dir`s — and the claim aged into fiction because nothing could see it age. All
  four now compose from the law, `tap.rs`'s `netns_layout_gate` pins the in-crate roster in both
  directions, and this script is its **complement, not a second copy**: it scans every *other* crate's
  `src` (where `pub(crate)` visibility means a netns path has nowhere to come from except a fresh
  literal) and **delegates** `crates/vmcell/src` to the in-source gate, failing loud if that gate or
  the const is gone. It bans the alias too — `/var/run` is conventionally a symlink to `/run`, the
  same alias class F3's reserved-cmdline law names — and derives the alias from the law rather than
  typing it, so nothing in the gate spells the layout either.

Both of the first two are **parked at the end of the `gates` recipe** with a comment explaining why:
they were red on arrival (each named the single site it fired on), and a red gate in its thematic
position would cost the verdicts of every gate below it in a `set -e` recipe. Their sites are now
fixed, so each is green and belongs back beside its sibling — the note at both homes says so.

## `docs/historical/89-claude-handoff-notes-v5.md` is deliberately NOT edited

The v5 handoff's reproduction sequence omits the `just bless` step, which is how a reviewer reached
docs/90's 228/228 through a stale runner (G9). The step was added where a reader is *sent* — the
current rubric — and **not** to the retired handoff. A retired document is the record of what was true
when it was written; editing it would rewrite the history of the pass that produced the defect, which
is the same rule that keeps `docs/historical/**` out of the pointer gate's scan while leaving it a
resolution target. Recorded here so nobody "fixes" it later.

## The public and contract surface this pass moves, and what §10.4 asks of it

Stated here because the ledger is where the *version* fact is produced (§10.4) and this is the list a
ledger edge has to cover:

* **`vmcell`, additive, on §10.4's named list:** `PackOptions::with_handler_label` /
  `PackOptions::handler_key` — `PackOptions` is listed surface, and it grows by field/setter by design
  so the pack tail's signature stops moving.
* **`vmcell`, additive, public but not on the list:** `RootfsStage::with_handler_label`,
  `artifact::handler::handler_label_from_artifact_key`,
  `feature::HostDeclaration::from_host_capabilities` (D5's code fix: the host axis is now derived from
  the one probed descriptor, so §7.2's one-probe law holds instead of a second nested-virt read), and
  `vmm::FakeVmm::adopting_baked_vsock` (the seam that makes M9's ancestor-vmid reservation drivable
  without Firecracker).
* **`vmcell`, additive, and the one §10.4 cares about most: `pub use hudsucker;` / `pub use hyper;`
  from `vmcell::proxy::doubles`** (E1). The `Matcher`/`Responder` aliases are `Fn`s over third-party
  types vmcell neither owns nor versions, so a git-dep consumer writing a test double — the thing
  §1.3 calls the proxy "the natural home" for — had to add both crates to its own manifest at exactly
  vmcell's resolved versions and discover those versions by reading vmcell's lockfile. Re-exporting
  them means the consumer names one version, through vmcell, and a bump moves the aliases and the
  re-exports together. That bump has already happened once (hudsucker 0.23 → 0.24) and
  `cargo semver-checks` cannot see it, because the aliases' *shape* does not move — exactly the case a
  ledger entry exists for, which is why §10.4's list now carries "the proxy doubles seam's `hudsucker`
  and `hyper` re-exports (§1.3)" as listed surface: a bump inside vmcell is now a ledgered fact rather
  than a type mismatch a consumer discovers from the lockfile. The documented spelling is a
  **doctest**, so it is compiled rather than asserted, and `just test-doc` is the gate that now runs it
  at all (G1).
* **`vmcell-artifact-validator`, breaking:** `ValidationOptions::run_budget` — which §10.4 already
  names, along with the ledger entry it owes. The struct is not
  `#[non_exhaustive]`, so adding a `pub` field breaks every struct-literal construction, and
  `cargo semver-checks` reports it. `DEFAULT_RUN_BUDGET` is additive beside it.

Neither list is a behavior surprise for a caller who does nothing — the additions are additive and the
validator's new field defaults to the finite budget — but both are edges §10.4 wants findable in the
ledger rather than at a consumer's build.

## Green locally, red on CI — twice in one pass, and what a host-facing claim owes the other host

The docs/90 fix pass validated every suite on this workstation, green, and CI contradicted it twice for
two unrelated reasons. Each mechanism is recorded at its own site; the practice they share is stated
once, here.

* **A host FACILITY the two hosts version differently** — the ext4 batteries' `mkfs.ext4 -d <tarball>`
  premise. The mechanism and its two fixes are in "The ext4 battery's absent-facility answer is ONE
  law" above; the numbers are the whole point: 1.47.1 is the gate, this workstation carries 1.47.2,
  GitHub's `ubuntu-24.04` image 1.47.0.
* **A host STATE the two hosts do not share**, in two of the three test defects below: a *built
  artifact pair* (a fresh checkout has none) and a *delegated cgroup subtree*, which decides which
  seam refuses a start first and therefore what the error string says — down to the *allocated vmid*
  inside it.

The third test defect is **not** in that class and is worth separating rather than folding in: the
`typos` collision reddens `just ci` on this box too (`typos` is a step of the `ci` recipe,
`justfile:803`, and of ci.yml's lint job, `:166-167`). Nothing about the runner was involved — the
fixture simply landed without the recipe being re-run against it.

The practice, in two rules:

* **A host-facing claim owes the CI host's differences, enumerated.** "Both suites green" is a claim
  about the host that ran them. AGENTS.md's rule 5 says probe the host you are on; its complement is
  that a claim about *another* host needs that host's versions and its starting state named, not a
  passing local run generalized. `.github/workflows/ci.yml` is readable from here, and every one of
  the differences above is visible in it.
* **A new recipe is not a gate until it has run once.** `just test-bench` closed docs/90 G2 — the
  finding that a live battery was selected by no recipe — and then failed all five of its tests on the
  first CI run (below). Reading its text could not have caught that: the failure is in the privilege
  transition the recipe composes, not in the argv. One local invocation would have.

Neither rule is a mea culpa about a missed step. Both name the same standing shape — a **premise about
a host you are not on** — which has now cost this tree four red commits on the runner (the e2fsprogs
premise, recorded above) and five tests that never executed once (the recipe, below).

## A live fuzz finding: two bytes that named nothing, and the locator composer that answers them

`fuzz-nightly` (`.github/workflows/fuzz.yml`, non-blocking by construction) had been red for two
consecutive runs on the `feature_manifest` target, with a two-byte reproducer: **`=z`**. Recovered from
the workflow's own `fuzz-artifacts` upload (Actions run 32017582821), which is the mechanism working —
the job is scheduled, a crash uploads its reproducer, and nothing gates a PR on it.

**The defect was one arm out of four that forgot the line number.** `FeatureDeclaration::parse_manifest`
composed each refusal itself, and three of its arms hand-attached `idx + 1` while the
`Feature::parse(key.trim())?` arm propagated the token error unchanged (the arm now reads
`Feature::parse(key).map_err(|e| reject(e.to_string()))?`, `crates/vmcell/src/feature.rs:433`).
`Feature::parse` answers about a **token** and knows
nothing about where it came from, so for `=z` — where the key before the `=` is the empty string — the
message opened with `unknown feature` followed by an **empty** pair of quotes and then the whole
vocabulary: no line, no number, and not one byte of the input in it anywhere. The target's stated
property is that a rejection must name something *from the input*,
and it was the only thing in the tree that could have found this, because every unit test stood on an arm
that remembered.

**Why a closure rather than a fifth hand-attachment.** A rule each arm must remember is a rule a *new*
arm can forget, and this one already had. The fix is two private composers plus a per-line binding:
`manifest_locator(line_number, line)` (`feature.rs:366`) is the one spelling of the locator,
`manifest_line_error` (`:374`) prefixes it to a detail, and the parser binds
`let reject = |detail| manifest_line_error(idx + 1, line, detail)` once per line (`:417`) so every arm is
`reject(…)` and no arm can attach the wrong line either. Both halves of the locator are load-bearing and
the rustdoc says which does what: the **number** answers "which of the three identical lines", the
**text** survives a consumer who cannot see the numbering (a here-doc, a generated sidecar, a body
assembled in memory). The line is quoted at full length deliberately — this is local build config, not a
guest-controlled frame, so `capped_debug`'s truncating render would defeat the property being asserted.

**The empty key is now its own arm, not `Feature::parse`'s.** `if key.is_empty()` (`:422`) refuses with
"no feature name before the `=`" and lists the vocabulary. Nothing was misspelled, so reporting it as an
unknown feature with an empty name sends a consumer looking for a token that is not in their file — the five
malformed shapes are kept distinct because the *fix* differs per shape. `Feature::names_joined()`
(`:157`) was extracted in the same change so this refusal and `Feature::parse`'s cannot come to list two
different rosters; it is composed from `Feature::name()`, which is what makes F6's "refusal feature
strings are `Feature::name()` by construction" true of the *list* as well as of the single name.

**The property was strengthened from a disjunction to a conjunction.**
`fuzz/fuzz_targets/feature_manifest.rs` asserted `names a line OR quotes a token`, and `=z` slipped
through only because it has no token the message happened to contain — a message reading `line 7` and
nothing else used to pass, and so did one quoting a token while pointing nowhere. It now requires **one
candidate line** to be named by number *and* quoted, reducing each candidate exactly as the parser
reduces one, so it cannot demand a locator for a line the parser would have skipped. Existence over the
candidates is all that is checkable from outside: which line offended is the parser's own answer, and
re-deriving it would mean reimplementing the parser inside its own fuzz target.

**Three gates, none covering another's half** (`mod manifest_locator_gates`, `feature.rs:1240`, ungated
on `host-common` because `parse_manifest` is the boundary a *consumer* reads a sidecar through and must
be gated in every configuration `cargo hack` builds):
`every_refusal_arm_carries_the_line_number_and_the_offending_line` (`:1298`) — the behaviour per arm,
asserted against the composed locator rather than a typed sentence, with a table that must drive all
five arms and a distinctness check so no two arms share a detail;
`every_manifest_refusal_goes_through_the_one_locator_composer` (`:1561`) — the **call sites**, a source
scan over the parser's own body that fails on any bare `Error::` in it, because a green per-arm test
beside a new hand-rolled arm is exactly the completeness-audit failure shape; and
`the_two_byte_fuzz_crash_input_is_locatable` (`:1476`) — the discovered input, re-asserting the fuzz
target's property verbatim, with the pre-fix message reconstructed from `Feature::parse("")` as the
proof that the check can say no.

**Recorded (justified): the reproducer bytes live in an in-crate constant, not in a committed corpus
file.** `FUZZ_CRASH_INPUT` (`feature.rs:1248`) holds `b"=z"`, named with the run and the crash file it
came from. This repo's `fuzz/.gitignore` commits `seed-*` corpus files for six of the seventeen targets
and scopes that mechanism, in its own prose, to **reachability and speed** — five seeds are a
correctness dependency (random bytes cannot reach the parser inside a nightly window; the measured
`oci_layer_zstd` figures are there) and one is a measured speed-up — while `/corpus/*` and `/artifacts`
stay ignored and the workflow *uploads* reproducers instead. Adding a crash-regression corpus would be a
second, differently-scoped use of the same directory, and a corpus file is not a gate: nothing in `just
ci` reads `fuzz/corpus`, and `cargo fuzz` is not on the CI critical path at all. The constant is driven
through the target's own property by a test that `just test-unit` runs, which is the same bytes with a
gate attached. The trade-off is real and one-directional: `cargo fuzz run feature_manifest` on a fresh
checkout does not start from these bytes. It does not need to — the input is two bytes wide and the
property is now a conjunction, so the shape is reachable again in seconds.

## `just test-bench` shipped unable to run what it selected: the double wrap, and the EPERM it earns

docs/90 G2 was that `vmcell-bench`'s three `#[ignore]`d live legs — the composition root wiring all four
backends — were selected by no recipe in the tree. The recipe that closed it then failed **all five** of
its tests on CI at ~0.008 s each, with a bare `Operation not permitted (os error 1)` and no cause in it.

**The measured mechanism, because a plausible wrong story fits the symptom.** It was **not**
`no_new_privs`: the blessed runner's transition emits `DropUid` → `AddInheritable` → `ShrinkBounding` →
`RaiseAmbient` → `TrimCaps` and no `PR_SET_NO_NEW_PRIVS` step at all
(`PrivilegePlan::steps`, `crates/vmcell-privilege/src/lib.rs:525`), and `NoNewPrivs = 0` was read from
`/proc/self/status` *inside* the window — the value the diagnosis gate's fixture now carries
(`crates/vmcell-bench/tests/common/mod.rs:523`). It was the **double wrap**: `just test-bench` wraps the
test binary through nextest's `CARGO_TARGET_<TRIPLET>_RUNNER` hook, nextest passes its environment
through, and `assert_cmd`'s `Command::cargo_bin` reads that same variable family and re-composed
`<runner> <bench-vm>`. The first wrap's `ShrinkBounding` step drops the **transient** `CAP_SETPCAP` that
the runner *file* still carries in its `+ep` set, so the second `execve` of that file computes
`pP' = (X & fP) | (pI & fI)` with `fP ⊄ X` and the effective bit set, and the kernel answers **EPERM**
("insufficient to execute correctly") rather than degrading. No blessing, rebuild or KVM probe changes
that: the second exec cannot succeed from inside the window the first one opened.

**The fix is to wrap exactly once and inherit** — the shape `just test-daemon` already documents for
`vmcelld`. `common::bench_vm()` (`:64`) spawns the child directly from
`env!("CARGO_BIN_EXE_bench-vm")` (`:54`), compile-time and therefore not redirectable by the
environment, and the caps arrive through the **ambient** set, which `execve` preserves across a file
carrying no capabilities of its own. `assert_bench_vm` (`:75`) is the one spawn site, so a future EPERM
here reports its cause instead of its errno (`explain_spawn_failure`, `:114`, pure over
`/proc/self/status` text and silent on any non-EPERM failure — the cry-wolf inverse is its own leg).
Four KVM-free gates hold it, all in `just test-unit`, the invocation that had no way to see this:
`the_harness_never_re_wraps_bench_vm_in_the_target_runner` (`:291`, the ban plus the one-resolver and
one-spawn-site counts), `the_child_is_spawned_directly_into_the_inherited_privilege_window` (`:373`,
whose wrapped legs are the positive controls — `assert_cmd`'s door really does compose the runner under
this recipe's environment, and `bench-vm` must carry no file capabilities or execve would clear the
ambient set that delivers the caps),
`the_test_bench_recipe_still_wraps_and_still_selects_the_ignored_legs` (`:457`), and
`a_spawn_eperm_is_reported_as_the_privilege_transition_it_is` (`:520`). The
justfile (`:279`) and `ci.yml`'s step both carry the "wrapped once, and only once" note, because the
next reader's instinct on an EPERM is to add a wrapper.

**A premise corrected by measuring, not reasoning.** The recipe's features-list guard was justified on
the claim that a list omitting `cloud-hypervisor` makes `Command::cargo_bin("bench-vm")` panic, since
`bench-vm` carries `required-features = ["cloud-hypervisor"]`. It does not: cargo sets
`CARGO_BIN_EXE_bench-vm` for the integration test **even when the bin's required features are unmet**
(measured — `cargo build --tests --no-default-features --features firecracker` compiles the test target
and leaves `target/debug/bench-vm` untouched). So the real hazard is worse than a panic: the harness
would exercise whatever **stale** binary an earlier, differently-featured build left there and report it
as this run, or, on a clean tree, fail at spawn with ENOENT. Neither is an answer about the features
asked for. The up-front rejection in the recipe (`justfile:312`) is what prevents it, and the corrected
reasoning is at that site.

## Three CI failures in this pass's own tests, and the lesson each one carries

Each was a defect in the **test**, not in the product — which is the class a review pass is most likely
to ship, because a test that passes locally looks finished.

* **A KVM-free premise check that required a built artifact** (`crates/vmcell/tests/guest_tuning.rs`).
  G7's live leg has a vacuity guard beside it: the window it declares must be non-default and honored
  verbatim, checked without KVM. It reached `common::get_vmlinux()` / `get_rootfs()` through the shared
  config builder, and those getters do not hand back a path — they **require** a built artifact, failing
  loud with `guest kernel missing at …/vmlinux`. Every box that has run `vmcell build` satisfies that;
  no fresh checkout does. So the leg was green here and red in CI's artifact-free `test-unit` job.
  **The lesson is in which fix was chosen.** `#[ignore]`ing it would have been one line and would have
  removed the file's only artifact-free assertion — the guard that keeps the live leg from measuring a
  default value it calls non-default, and the only part of that file a reviewer on a KVM-free box can
  check at all. The artifact pair is a **parameter** of `tuned_cell_cfg` instead (`:113`): the live leg
  passes the real pair, the premise check passes a scratch pair, and a `Duration` surviving the builder
  has nothing to do with which kernel image the cell would boot. "Runs everywhere" is a claim about the
  **host**, not about an attribute list; the module header records the CI condition and how to reproduce
  it locally (`VMCELL_KERNEL=/nonexistent/vmlinux just test-unit`).
* **A gate asserting whole-string equality on a message that embeds an allocated vmid**
  (`crates/vmcell-artifact-validator/src/checks.rs`). M8's leg compared the conformance probe's
  undecidable reason against the level check's, `assert_eq!` on the rendered strings. Both calls
  allocate their own vmid and `MicroVm::start`'s error text names it, so the two differ in exactly that
  number — and *which* setup step refuses first is the host's business too: on a delegated developer box
  the fake's `create` fault stops the start, on an undelegated hosted runner the real cgroup seam is
  refused one step earlier. The fix asserts the **classification plus the composed stage prefix**:
  `SETUP_STAGE_PREFIXES` / `EXERCISED_STAGE_PREFIXES` (`:2418`) and `stage_named_by` (`:2435`), which
  requires a reason to name exactly one stage the probe can stop at *and* to carry a cause after it — a
  bare stage label says where and not why, and "why" is the payload `Unverified` exists to deliver. The
  rosters are non-vacuity-checked against the probe's own source
  (`the_stage_prefixes_are_the_ones_the_probe_composes`, `:2466`) so a renamed arm reddens the roster
  instead of silently classifying nothing. What was deleted is a whole-string comparison; the property
  it was reaching for — that both callers render a stop's text identically — is `into_why`'s own law and
  is gated purely, one module over.
* **Deliberate misspelled-token fixtures colliding with the `typos` gate**
  (`examples/downstream-kernel/tests/contract.rs`). Two legs declared `snapshot_restore` **with its
  trailing `e` dropped** — deliberately, to prove F6 clause 1 refuses an unknown feature name. `typos`
  knows that truncation and corrects it, so a fixture spelled that way turns the lint red for being
  exactly as wrong as it means to be. (This one was reproducible locally: `typos` runs in the `ci`
  recipe as well as in ci.yml — see the section above. This very entry had to be written around it, which
  is the point made twice.) **The fix is a wrong WORD, not a misspelling**:
  `BOGUS_FEATURE_TOKEN = "snapshot_restored"` (`:74`), spelled once so fixture and needle cannot drift.
  Adding a `_typos.toml` entry was the other option and is worse — that file's own header says every
  exception is a permanent blind spot — and so was exempting the file, which would have
  unspell-checked a living consumer gate.
  **It also closed a real vacuity, which is why the near miss is the better fixture and not merely the
  legal one.** The truncation is a **prefix** of the real token, and `Feature::parse`'s refusal echoes
  the whole vocabulary through `Feature::names_joined()`, so a `contains` on it was satisfied by the
  roster echo alone: the assertion held whether or not the refusal named the offending
  token. No dictionary corrects `snapshot_restored` and no valid token contains it, so the `contains`
  can only pass on a refusal that really echoes what it refused — and the leg now *proves* that with
  `OTHER_BOGUS_FEATURE_TOKEN` (`:78`): a refusal about a different unknown token must not contain this
  one. The near miss is also the tighter probe, since a resolver that accepted any token *starting with*
  a valid name would take it and still reject the truncation.

  **Residual, recorded rather than fixed here: the same vacuity is still live in-crate.**
  `unknown_feature_token_is_a_hard_error_naming_it` (`crates/vmcell/src/feature.rs:800`) *derives* its
  typo (`&real[..real.len() - 1]`), which dodges the `typos` gate — that half is right and predates this
  lane — but both of its `contains` assertions (`:810`, `:814`) are matched by the roster echo the
  refusal composes at `:187-191`, so neither can fail on a refusal that dropped `{token}`. Its positive
  control is the only non-vacuous part. Left as it is because a live suite was running against this tree
  when it was found and because the property is covered from the consumer position by the leg above;
  the honest fix is the same one — a needle no valid name contains — and it belongs to the next pass
  that owns that file.

## M7's fix left four notification toggles discarding, and its new bound dropped frames silently

The docs/90 pass fixed M7 (a `handle_event` error killing the NAT's only vring worker) and its sibling 20
(an unbounded `tx_queue`). The fix restructured the drain loop and shipped two things AGENTS.md bans one
page over: a discarded `Result` and a data-plane behavior change nothing surfaces. Recorded here because
"the fix for a fail-loud finding carries a discard through the restructure" is the shape worth naming,
not the individual lines.

* **The notification toggles.** `TxPass::Unreadable`'s arm re-armed the kick with
  `let _ = vring_state.enable_notification();` — a `let _ =` the fix itself added — beside a pre-existing
  `let _ = …disable_notification()` and two `…enable_notification().unwrap_or(false)`. All four now route
  through one reporting helper each: `mask_tx_notifications` (`crates/vmcell/src/net/smoltcp.rs:511`) and
  `rearm_tx_notifications` (`:534`). The two directions are deliberately **not** symmetric, and the
  reason is at the sites: masking is advisory (a failure costs one extra wakeup on a ring this loop is
  about to read anyway) so it is a `warn`; re-arming is not, because the flag being lifted is what tells
  the *guest's* driver it may kick again, so leaving it set is the same silently wedged link `TxPass`
  exists to prevent — reached through the error path of the fix for it — and it is an `error` plus a
  caller that stops polling this tick. Neither becomes an `Err`, which the vendored epoll loop treats as
  terminal.
* **The tail drop.** Sibling 20's bound made the NAT lossy under a stalled consumer and said so at
  `trace!` — one `RUST_LOG` away from silence, on a data-plane behavior change. Frames are counted in
  `VhostUserNetBackend::tx_drops` (an `AtomicU64` on the backend rather than in the `pub`-fielded
  `SharedState`, so a counter nobody outside the module reads is not a breaking change to a downstream
  constructor) and reported at `warn`, flood-capped by `tx_drop_is_reportable` (`:198`): the **first**
  drop always, then one line per queue-depth. The first is unconditional because "it happened at all" is
  the interesting bit — a NAT that reaches a four-ring-deep queue has a stalled consumer, which is a bug
  report and not a tuning hint.

The gates are KVM-free and the error paths are reached the only way they can be without a guest: by
re-pointing the used ring at an unmapped guest address (`TxRing::break_used_ring`, `:2671`), which is
what a driver that programmed a bogus `SET_VRING_USED` does.
`a_failed_notification_toggle_is_reported_not_discarded` (`:2906`) drives both helpers with a healthy
ring first as the positive control and asserts the **level**, since `tracing_test` captures TRACE and up
and mere presence would accept the shape that shipped.
`every_notification_toggle_routes_through_its_reporting_helper` (`:3486`) is the call-site half —
restoring a discard *at a call site* is invisible to the behavioural leg by construction — with its own
red-on-inverse over four fabricated bodies.
`the_first_tail_drop_reports_and_a_sustained_one_does_not_flood` (`:2796`) pins the cadence, and the
depth-bound leg now asserts the count and the level together.

## Two gates this pass shipped were narrower than the class they named (D1, G3)

Both were written for the instance in front of them and both were then found blind to a site nobody had
pointed them at — the same discovery, twice, and the same widening: **derive the roster, do not list
it.**

* **D1's prose reader saw two files; it now reads every crate's `src`.** The C8 gate grew a second
  reader over `config.rs` + `orchestrator.rs` so a comment block asserting the retired
  `init`-decides-the-control-plane derivation could go red. That is precisely the two-file scope whose
  blindness let QEMU bake the steward port for a whole release on the *code* side of the same law (M1),
  and four of D1's seven sites were public rustdoc — which is just as wrong in `vmcell-qemu`'s rustdoc
  as in this crate's. The prose half now stands on the same workspace walk the port half already used:
  one directory walk, `workspace_source_files` (`crates/vmcell/src/config.rs:5611`), with three readers
  over it (whole text, production-only, code-only) so there is no second scope to keep in sync. Its
  floors are the part worth copying: blocks **and** bytes, and then **per crate** against a roster read
  independently of the walk (`crates_with_src`, `:5127`), because `vmcell` alone carries over half the
  workspace's prose and a whole-workspace floor is met with every backend crate missing — the exact
  blindness being fixed. The widened *scan* has its own red-on-inverse against a fabricated backend
  file (`the_prose_scan_reports_the_retired_derivation_in_a_backend_crate`, `:5314`), distinct from the
  per-block predicate's, and the gate's stated limit is honest: the unit is the **block**, so a retired
  sentence appended to an already-anchored rustdoc block is absorbed by that block's anchor. Reading
  sentences instead would re-open the split-across-lines hole that made per-line reading find nothing.
* **G3's ext4 call-site scan enumerated three files, and the fourth was already wrong.**
  `every_ext4_battery_asks_the_one_law` (`crates/vmcell/tests/ext4_producer.rs:1455`) named
  `ext4_producer.rs`, `ext4_cell.rs` and `repack_outside_checkout.rs`. `rootfs_registry.rs`'s
  `format: ext4` leg was the fourth answer to an absent `mkfs.ext4` — a hand-spelled
  `record_capability_skip("cloud-hypervisor", "ext4_producer")` plus its own `println!("SKIP: …")`,
  which is *exactly* the pair of shapes that scan's arms 4 and 5 exist to catch — and both arms stayed
  green for a whole review pass because the scan never opened the file. The law gained a second door
  rather than a second copy: `classify_ext4_refusal` (`crates/vmcell/tests/common/mod.rs:332`) is the
  same core entered from the refusal side, which that leg needs because pre-probing would skip past the
  erofs-only door the leg exists to assert. The new scan **discovers** its roster —
  `ext4_answer_findings` (`:537`), any test file whose code names `RootfsFormat::Ext4`, with an empty
  roster and an empty tree each a `gate misconfigured` — and is driven from
  `every_ext4_battery_answers_an_absent_facility_through_the_one_law`
  (`crates/vmcell/tests/rootfs_registry.rs:1877`) beside `the_ext4_answer_scan_goes_red_on_every_shape_it_bans`
  (`:1891`), which drives every arm against fixture trees rather than the checkout, because the arms
  that matter are the ones no file here has.
  Two details from that self-test are worth carrying forward: it matches **whitespace-free**, because
  rustfmt had wrapped the offending `println!(` across two lines and a line-wise `println!("SKIP`
  needle would have stayed green even once the file entered the roster; and it scans the **in-crate**
  half too, where a printed SKIP can never reach the manifest at all (docs/90's `oci.rs` leg).

  **Two residuals, recorded so a later pass consolidates deliberately rather than deleting the wrong
  one.** (1) The enumerated scan is still there and still asserts two things the discovered one does
  not — a floor on the total number of call sites that ask the law across its three files, and the
  structural arm that the direct probe and the recording call both live in `common/mod.rs` — while the
  discovered one adds the two in-crate arms. Their five test-side arms are the same five, so neither is
  a superset of the other. (2) `probe_ext4_or_record_skip`'s rustdoc still says "the call-site scan in
  `ext4_producer.rs` is what keeps a fourth answer from appearing"
  (`crates/vmcell/tests/common/mod.rs:270-271`), a sentence the fourth answer disproved; the claim now
  belongs to the discovered scan. Both belong to the next pass that owns those files.

  The same lane also corrected the `oci.rs` seam leg that H2's own gate had shipped: its absent-facility
  arm matched the refusal's **wording** (`needed.contains("e2fsprogs")` and two siblings) and returned
  green, so on any host that cannot produce ext4 the leg reported PASS for a claim — real ext4 bytes —
  that nothing had checked, and it is an in-crate unit test, so the skip law is unreachable from it and
  the reviewer's only instrument said nothing. It now asks the one format→emitter law directly and
  requires the pack's outcome to **match that route**: a route yielding a producer means ext4
  superblock bytes, a route that refuses means the caller got that same refusal verbatim
  (`crates/vmcell/src/artifact/rootfs/oci.rs:820-869`). Both arms are then unenterable on the wrong kind
  of host, no wording is matched at all, and the ext4-bytes claim is left to the batteries that can
  record the gap — which the comment names.

## Dependency modernization — the 2026-08-20 latest-stable pass

Second full bump pass (the first is the 2026-07-14 entry above). Everything with a newer **stable**
release moved; everything held back is recorded here with the blocker that was *measured*, not the one
that was assumed. `docs/91-claude-opus-workaround-inventory.md` is the companion register — it answers
"is this workaround still load-bearing?" per row and is where the two replaced rationales live.

### Toolchain

Rust **1.96.1 → 1.98.0** (latest stable, released 2026-08-20). The MSRV is one fact in five files plus
`clippy.toml`; `scripts/check-msrv-sync.sh` gates all of them and its red-on-inverse self-test still
drives every arm. **The bump was clean**: `cargo build --workspace --all-features` and
`cargo clippy --workspace --all-targets --all-features`, both under `RUSTFLAGS=-D warnings`, passed with
zero source changes. No new default-on lint fired — worth recording, because a new lint is the usual
cost of a toolchain bump in a `-D warnings` tree, and the pass budgeted for it.

### Breaking-major bumps applied

`base64` 0.22 → 0.23, `serial_test` 3 → 4, `smoltcp` 0.13.1 → 0.14, `rtnetlink` 0.21 → 0.23 with
`netlink-packet-route` 0.30 → 0.33 **in lockstep** (0.23 requires `^0.33`), and `hudsucker`
0.24 → 0.25. All five needed **no source migration** — notable for `smoltcp`, whose 0.11 → 0.13 move in
the previous pass required two, and whose 0.14 is mostly TCP congestion-control and RFC-compliance work
plus TSO. The netlink pair, whose whole API surface lives in `net/tap.rs`, compiled untouched.

The netlink bump also removed `paste` from the graph, retiring `RUSTSEC-2024-0436`; the ignore was
deleted rather than left as a dead entry (`deny.toml`'s header forbids exactly that shape). 15 ignores
remained at the close of *this* pass, 14 of them the `tun-tap` subtree — see the inventory, row A1,
for why that count was one crate and one ioctl rather than fourteen problems. The follow-up pass below
took the ioctl in-tree and the count is now 1.

### The hudsucker bump is a contract edge, and it broke an in-tree consumer

`proxy::doubles` re-exports `hudsucker` and `hyper` at the versions its `Matcher`/`Responder` aliases
are built from, so 0.24 → 0.25 moves types a downstream names. `cargo semver-checks` is blind to it
(the alias *shapes* are unchanged) — the module docs already said so, citing the previous pass's
0.23 → 0.24 move as precedent. Hand-written ledger entry `0.21.0 → 0.22.0` added; all fourteen sibling
path-dep requirements moved with it (a rollback in one manifest is a workspace-wide resolution error).

The predicted consumer break happened **inside this workspace**: `vmcell-bench` carried its own
`hudsucker = "0.24"` and `hyper` requirements, used only to build a `TestDouble`, and failed with
`expected vmcell::proxy::doubles::hudsucker::Body, found hudsucker::Body` — the module docs' exact
example. Both requirements were **deleted** rather than realigned and the call site now names the
crates through the re-exports, so the duplicate-version break is unrepresentable rather than repaired,
and the composition root demonstrates the documented rule instead of contradicting it.

### Held back — the vendored rust-vmm family, for a different reason than the one on record

`vhost`/`vhost-user-backend`/`vm-memory`/`virtio-queue` stay at `=0.16.0`/`=0.22.0`/`=0.17.1`/`0.17.0`.

**The recorded rationale was empirically wrong** — the register convention's own failure mode, found by
testing it. It said bumping "silently drops the patch"; that is a hazard, not a blocker, and
`check-vendored-vhost.sh` reads the pinned version out of the vendored manifest *precisely* so a pin
bump is supported. The pass performed the whole re-vendor onto 0.17.0/0.23.0 — extracted the crates,
re-applied both patch hunks and the carried `set_vring_enable_quirk_gating` test, moved the pins — and
the gate stayed green.

**The real blocker is `experiment-fuse`.** `fuse-backend-rs` 0.14.0 (latest) requires `virtio-queue
0.17` and pins `vm-memory = "=0.17.1"` exactly, while `vhost` 0.17 / `vhost-user-backend` 0.23 both
require the 0.18 pair — so the four move as one set, and `fs/in_process.rs` bridges a
`virtio_queue::DescriptorChain` straight into `fuse-backend-rs`. Default features compile;
`--features experiment-fuse` (selected by `--all-features` and the `cargo hack` powerset) does not.
The trade was judged the wrong way round: vhost 0.17's headline fix is the `SHMEM` feature-bit position
(21 → 22), and vmcell negotiates no SHMEM on any device it ships, so it is inert here while the cost is
breaking a shipped feature. Reverted; the pin-site comment now carries this. **Unblocks when**
`fuse-backend-rs` publishes on `vm-memory 0.18`.

Upstream was re-checked while there and still carries the unconditional
`check_feature(PROTOCOL_FEATURES)` on `set_vring_enable` — on published 0.17.0/0.23.0 **and** on `main`
at `c96c3722`. The patch is still load-bearing; `vendor/` cannot be deleted.

Also held: `libc` (latest is `1.0.0-alpha.4`) and `rustls` (0.23.43 is latest stable) — pre-release and
already-latest respectively, unchanged from the previous pass's reasoning.

### `lzma-rs` → `lzma-rust2` for the kernel-tarball XZ decode

Swapped on the one call site that decodes the kernel source tarball
(`artifact/kernel.rs`). The prompt for it was operational: during this pass's artifact rebuild the
decompress phase looked like a wedged download — one thread pinned at 100% CPU, no socket traffic,
an empty `kernel-build/` — and it was simply `lzma-rs` grinding through a 142 MiB `.xz` into a
1.5 GiB tar. (Diagnosis note for the next person: `linux.tar` growing is the progress signal; the
process being in `futex_do_wait` with an idle keep-alive socket is not evidence of a stall.)

Measured, same session, interleaved, release build, idle box, on the real
`linux-6.12.104.tar.xz` (142 MiB in, 1,549,117,440 bytes out):

| decoder | time | throughput |
|---|---|---|
| `lzma-rs` 0.3.0 | 15.97 s | 92.5 MiB/s |
| `lzma-rust2` 0.19.0 | 9.76 s | 151.3 MiB/s |

**1.64×**, reproducible across rounds to within 0.1%, and the output is **byte-identical**
(sha256 `4b93c9f0…` both ways) — the acceptance condition for a codec swap.

Why this crate specifically:

- **Maintained.** `lzma-rs` 0.3.0 is the newest release and dates to **2023-01-04**; `lzma-rust2`
  0.19.0 shipped **2026-08-16**, on a roughly fortnightly cadence.
- **Licence.** Apache-2.0, already on `deny.toml`'s allow-list. (`lzma-rs` is MIT; both fine.)
- **`unsafe` is opted OUT, and the opt-out is compiler-enforced.** The crate carries an
  `optimization` feature that enables `unsafe`, and it is ON by default — so the dependency is
  declared `default-features = false, features = ["std", "xz"]`. With `optimization` off the crate's
  own `#![cfg_attr(not(feature = "optimization"), forbid(unsafe_code))]` applies, which makes
  unsafe-freedom a property `rustc` checks rather than one the README asserts. That is the whole
  reason a crate with an `unsafe`-bearing feature is admissible here. Dropping `encoder` and `lzip`
  as well keeps the compiled surface to the one thing vmcell does: decode XZ.
- **No new crate in the graph.** The `xz` feature pulls `sha2` (for the stream integrity check),
  which this crate already depends on.
- **Streaming.** `XzReader` is a `Read`, so the 1.5 GiB tar is `io::copy`'d through a fixed buffer;
  the `lzma-rs` entry point took `&mut impl Write` but buffered the entire output first.

**`lzma-rs` does not leave the lockfile** — `am-fs-erofs` 0.1.1 (the erofs writer) still depends on
it transitively. So this is a hot-path and maintenance win on vmcell's own call site, not a
dependency removal; do not expect the crate to disappear from `cargo tree`.

### External binaries, and a local-vs-CI divergence the pass found

- **Cloud Hypervisor.** CI's `v53.0` pin **is** latest — no v54 tag exists. But this host had a
  `cloud-hypervisor v54.0.0`, because the README said `cargo install --git`, which installs an
  unreleased `main` build reporting the *next* version. Design Appendix C had already recorded "the
  live matrix ran on 54.0.0" without noting that no such release exists. `main` is ~237 commits past
  v53.0 and three of them touch surfaces the suites assert on: vsock local-port ownership / RST-reply
  behavior, CH API errors remapped 500 → 404/400/409, and additions to CH's own seccomp filter (which
  the confinement battery reads off a *running* CH). The README now installs the checksum-verified
  pinned release, and the live suites were run against a locally installed v53.0 via `$VMCELL_CH_BIN`.
- **`pins.json` now commits `cloud_hypervisor: "v53.0"`** — design §17's named "one-line close". The
  snapshot cache key's fold of that pin was wired and hashing an empty string; it now hashes a real
  value, so a CH bump invalidates stale snapshots at build time. §17 and Appendix C updated.
- **Firecracker.** CI's `v1.16.1` is latest; the README was stale at v1.16.0 (five occurrences) and now
  matches CI, verifying against the published `.sha256.txt` rather than a digest copied into the file.
  The dev box had 1.16.0, which matters more than a patch bump usually does: 1.16.1's two fixes are a
  jailer `O_NOFOLLOW` revert and — squarely on a path the suites exercise — *"vsock guest-to-host
  connections time out after snapshot restore, triggered by taking a snapshot with a TX descriptor
  in-flight"*. The live suites for this pass were therefore run against 1.16.1, installed per-user and
  selected through `$VMCELL_FC_BIN` (the same trick used for CH), so both backends matched CI's pins
  exactly rather than approximately.
- **QEMU.** No version is pinned anywhere — the backend spawns by name and CI takes the runner's
  package — so nothing to bump. Recorded in the README because the question recurs: upstream is at
  **11.1.0** (2026-08-11), but Ubuntu 26.04 resolute has **10.2.1** in *both* the base and the `-hwe`
  stacks (`1:10.2.1+ds-1ubuntu3.2` vs `…-1ubuntu4.3` — same upstream, forked at parity, differing only
  in SRU patches), and no 11.x is packaged for resolute in any pocket nor in any PPA. `-hwe` is
  intended to become a rolling channel but has not refreshed yet; `ubuntu-helper-virt-hwe` is only the
  switching helper and installs no QEMU at all. The QEMU legs remain validated on 10.2.1.
- **`virtiofsd` 1.14.0 / `vhost-device-vsock` 0.3.0** are already latest; so are all six cargo dev
  tools and `actionlint` 1.7.12. Nothing to do.
- **crosvm** still has no tagged release (git `main` only), so nothing to pin. Noted for a future pass:
  a `--nested` flag landed upstream 2026-07-15, which is what crosvm's honest-`false` `nested_virt`
  was waiting on — a capability-flag change re-validates empirically (`just test-crosvm`), never in the
  descriptor, so it is out of scope here.

### Artifact pins

Guest kernel **6.12.94 → 6.12.104** and the alternate **6.6.143 → 6.6.152** — security-patch moves
within the same two LTS lines, not line changes. Checksums came from kernel.org's `sha256sums.asc`;
the method was proved by recomputing the *existing* pins from the same file and matching both exactly.
`usbhost` follows the default. `e2fsprogs` 1.47.2 → 1.47.4 in CI (recomputed locally; the old digest
reproduced exactly).

Renaming the two registry labels reddened **four** tests that assert against the committed baseline,
each of which had been written with an explicit "fixture premise" assertion — so the rename failed
*there*, naming the reason, instead of the collision test quietly ceasing to test a collision. That is
the premise-assertion convention paying out, and the comment at the collision test now says so.
The byte-vs-version collation the roster test pins stays non-vacuous across the rename: byte order puts
`6.12.104` before `6.6.152`, version order the reverse.

**`kata-containers` 3.32.0 held at 3.32.0** though 4.0.0 exists. The `kernel_prebuilt` pin is the anchor
of a recorded empirical comparison (design §5, the Kata `vmlinux.container` finding, Linux 6.18.35);
a major bump changes the kernel *under* that comparison, so re-pinning without re-running it would
silently invalidate a validated finding. Bump it in a change that re-runs the comparison.

### Operational finding: `just ci` grows an unbounded `target/`

Not a dependency fact, recorded because it **stopped this pass** and will stop the next one. `just ci`
failed at `rustc-LLVM ERROR: IO failure on output stream: No space left on device`, with `rust-lld`
dying on `signal 7 [Bus error]` a few crates earlier — both symptoms of a full disk, neither naming
one. `target/` had reached **1.7 TB**: 803 GB across 59,392 `debug/incremental` directories, 733 GB
and 133,624 files in `debug/deps`, plus 83 GB under `semver-checks`.

The driver is the `cargo hack` feature powerset: every feature combination fingerprints as a distinct
unit and nothing evicts the old ones, so the directory grows monotonically with the number of `just
ci` runs. CI never sees it — a hosted runner starts each job on a clean disk — so it is strictly a
long-lived-dev-box failure, which is also why it presents as a mysterious linker crash rather than as
anything a gate would catch.

Periodic `cargo clean` is the remedy. Note that plain `cargo clean` also deletes
`target/vmcell-artifacts`, which costs a full kernel rebuild; removing `target/debug`,
`target/semver-checks`, `target/release`, `target/doc` and the per-triple directory keeps the
artifacts and the (out-of-`target/`) blessed runner intact.

### GitHub Actions

Dependabot owns these pins but had not landed them: `actions/checkout` v4 → v7.0.1, `actions/cache`
v4.3.0 → v6.1.0, `actions/upload-artifact` v4 → v7.0.1, `Swatinem/rust-cache` → v2.9.2,
`taiki-e/install-action` → v2.86.4, `dtolnay/rust-toolchain` re-pinned to the current `nightly` branch
head. All to full commit SHAs. Their breaking changes are Node-24 runtime bumps (hosted runners are
past the runner floor) and `checkout`'s `allow-unsafe-pr-checkout`, which applies to
`pull_request_target` — this workflow uses `pull_request`, so it does not apply.

## Removing `tun-tap` — one ioctl in exchange for a dependency subtree (2026-08-20, follow-up)

The A1 item the dependency pass deferred, taken as its own change because it is a source change to the
privileged tap path rather than a bump, and needs live privileged validation.

**What landed.** `vmcell::net_sys::create_tap_in_current_netns` opens `/dev/net/tun` and issues
`TUNSETIFF` with `IFF_TAP | IFF_NO_PI`; `net/tap.rs`'s `create_persistent_tap_in_ns` calls it inside
the same `in_netns` closure as before and still `TUNSETPERSIST`s and drops the fd. The dependency, the
`tokio 0.1` subtree behind it (47 lock packages) and 14 of the 15 advisory ignores are gone;
`deny.toml` bans the crate by name so it cannot return, transitively included.

**Deliberate deviations, each with its reason:**

- **`libc::ifreq`, not a third `#[repr(C)] IfReq`.** The tree carries two hand-rolled copies
  (`vmcell-steward::netif`, `vmcell-guest-tools`) under recorded deviation D5, each with a
  field-by-field divergence guard. They exist because they need *sub-offset* access into the
  `ifr_ifru` union (`SOCKADDR_*`, `SIN_ADDR_OFFSET`); this site needs only the `ifru_flags` arm. Using
  the kernel's own struct means there is no layout to drift and D5 does **not** grow a third member.
  What can still drift — the request number, the flag word, the narrowing into the 16-bit union arm —
  is pinned by `net_sys`'s `tunsetiff_abi_is_pinned_to_the_kernel`.
- **The name is rejected, not truncated.** `tun-tap`'s shim did `strncpy(…, IFNAMSIZ - 1)`.
  `naming.rs`'s `MAX_INTERFACE_NAME_LEN` rustdoc had named that silent truncation as an open hole for
  as long as the dependency was carried; the boundary now enforces the bound the composers honor.
  This is a behavior change on an error path no caller could previously reach.
- **The open and the ioctl are one function on purpose.** A tap's namespace is captured at
  `open("/dev/net/tun")`, not at the ioctl: `tun_chr_open` stores the opener's netns on the
  `tun_file`'s socket and `__tun_chr_ioctl` reads it back from there, never from `current`. Splitting
  them would let the open be hoisted out of `in_netns` — the natural tidy-up now that two statements
  are visible where one opaque call used to be — and every tap would be created in the **host**
  namespace, silently: the call returns `Ok` and the failure surfaces one step later at an
  in-namespace `rtnetlink` lookup. `tests/tap_create.rs`'s
  `tap_lands_in_the_target_netns_and_not_the_host` is the gate.
- **`std::fs::OpenOptions`, never `libc::open`.** std sets `O_CLOEXEC` unconditionally and C's `open`
  does not. `vmcelld` fork/execs VMMs and forks the broker concurrently with this call, and a leaked
  `/dev/net/tun` fd is an *attached tap queue* — the VMM's own `TUNSETIFF` then fails `EBUSY`, which is
  verbatim the failure the persist-then-drop dance exists to prevent. Byte-identical to what `tun-tap`
  did; recorded because a "tidier" raw-`libc` port would regress it invisibly.
- **No `IFF_MULTI_QUEUE`.** No backend requests a multi-queue tap today, and the kernel rejects a
  queue-flag mismatch with `EINVAL` when the VMM re-attaches. Adding `queues=N` to QEMU's `-netdev` or
  `num_queues` to `ChNet` means adding the flag here in the same change; the coupling was undocumented
  anywhere before this and is now stated at the flag const.

**Open item, found by this change and deliberately NOT taken: `TUNSETIFF` is create-or-attach.**
Issued against a name that is already a persistent-but-unattached tap, it **succeeds**, silently
adopting that interface. So a stale tap left by a crashed prior run under the same name is taken over
rather than reported, `TUNSETPERSIST` is a no-op on it, and `setup_tap_on_bridge`'s cleanup contract
then treats it as one this call created — its `name_for_cleanup` path would delete a device this call
did not make. The live-sibling case is safe: that one gives `EBUSY`. This is **pre-existing** —
`tun-tap`'s shim passed the same flags — and only became legible when the ioctl came in-tree.
`IFF_TUN_EXCL` is the one-flag fix, but it also makes re-adopting our *own* stale tap fail, so it has
to land with whatever reclaims it (the daemon's start-up sweep), and it is a behavior change on a
privileged path that needs its own live validation. Left open rather than bundled.

While confirming the above, the `setup_tap_on_bridge` comment claiming an `EEXIST` here meant "the
interface is someone else's" was corrected: `EEXIST` is not reachable from this call site at all — the
kernel returns it only for a second `TUNSETIFF` on the *same* fd.

**Two things checked so the next reviewer need not re-derive them.** The error text `Error::Network`
wraps is unchanged (`"tap create fail: {e}"`), but the inner message is now vmcell's own rather than
`tun-tap`'s — nothing in the tree matches on the old text, and `net/segment.rs`'s `RecordingNetlink`
fake imitates the kernel's `EBUSY` in the same shape, so it stays honest. And there is **no**
production path that puts a tap in the host namespace: a correctly created tap lives inside a netns
and dies when `cleanup_orphan_netns` removes it, so a crashed privileged run leaves nothing the sweep
misses. The host-namespace residue below is reachable only from a deliberately broken build.

**Gates.** `scripts/ban-raw-fd-open.sh` (+ its self-test) holds the O_CLOEXEC law, which is the one
law here that is neither a compile error nor test-observable: `libc::open` compiles fine and the tap
still comes up, and the failure needs a concurrent fork/exec to race the open while
`create_tap_in_current_netns` is `pub(crate)`, so no live leg could hold it. The ban is anchored on
the file and refuses as *misconfigured* if that file moves or stops opening through `OpenOptions` —
an exemption that outlives its site is a widened blind spot, not a pass. Beside it, `net_sys`'s four
KVM-free unit tests (the ABI pin, the name law, the read-back helper, the device path) and
`tests/tap_create.rs`'s four live legs — no VM, `CAP_NET_ADMIN` only, so they run on
the blessed runner and close the gap that `Netlink::setup_tap`, reached on every privileged boot, had
no live leg of its own. Plus `deny.toml`'s by-name ban and `unused-ignored-advisory = "deny"`, which
turns a stale advisory ignore from a `warning[advisory-not-detected]` that exits 0 into a red gate —
the reason every stale ignore this repo has carried was caught by review or not at all.

**Two of those gates only exist because the mutation pass refused to take the first answer**, which is
the part worth recording:

- The live truncation leg's *stated* inverse was wrong. Restoring `tun-tap`'s `strncpy` truncation
  alone leaves it **green**: the read-back then refuses, and it refuses *before* `TUNSETPERSIST`, so
  the truncated interface dies with the fd and no residue exists to assert on. Only removing the
  length check **and** the read-back — which is exactly the shape `tun-tap` shipped, since its shim
  had neither — turns it red, with `vmcell-tap-far-` present in the namespace. The comment now says
  that, instead of claiming a tighter inverse than the leg has.
- That in turn exposed a law with **no** gate: dropping the read-back on its own was invisible to
  every test in the tree, because the length check refuses first. The reachable input that slips past
  the length check is a name the kernel *expands* — `"vmcell-tap-%d"` is 13 bytes, and
  `dev_get_valid_name` substitutes the first free index, so the caller asks for one interface and
  silently gets another. `a_tap_name_the_kernel_expands_is_refused_and_leaves_nothing_behind` is that
  gate; it asserts the typed error names both spellings *and* that nothing but `lo` remains, because
  `TUNSETIFF` really does create `vmcell-tap-0` and only the refuse-before-persist ordering removes
  it. Asserting on the error alone would pass while leaking an interface per call.

**A test-fixture residue hole, found the same way.** `NetnsFixture` cannot clean the host namespace,
and the host namespace is precisely where a broken build puts the tap — so proving the namespace leg
can go red left a persisted `vmcell-tap-231` on the host, which then made the *next* run report a
pre-existing interface instead of the defect. One red run poisoned every later one. `HostTapReaper`
reaps it on the way out including the panic path, and the leg sweeps-then-asserts at entry.

### The preflight's STALE verdict overstated its own remedy

Surfaced by this change and worth separating from it, because the first reading — "the preflight
false-alarmed" — is wrong and the real defect is one level over.

Removing `tun-tap` moved `Cargo.lock`, and `Cargo.lock` is one of the three mtime roots
`review-preflight-priv.sh`'s freshness proxy compares the blessed runner against. So it reported
STALE. That is the probe **working as designed**: signal 2 is explicitly "conservative in the safe
direction — it can call a touched-but-unchanged tree stale; it cannot call a genuinely stale blessing
current", and the alternative (a false CURRENT) is the recorded incident where a whole privileged
review certified a binary nobody was reviewing. `Cargo.lock` is a broad root for a runner whose
closure is only `vmcell-privilege` + `rustix`, but narrowing it cargo-free would mean hand-parsing the
lockfile's dependency graph in shell, and a parser wrong in the permissive direction buys exactly the
catastrophic failure the conservative choice avoids. Left as is, deliberately.

What was actually wrong is the **remediation text**: it said "run `just bless` (one sudo)", and
`AGENTS.md` said the same. In this case — and in the common case, since a dependency bump anywhere in
the workspace moves `Cargo.lock` while the thin runner closure rarely moves — the recipe hashes the
build it just made against the stable copy, finds them identical, takes its idempotence skip,
re-dates the stamp and **sets no caps at all**. No sudo occurs. Promising one either way is how STALE
gets read as routine noise, which erodes the signal the probe exists to give. Both the script's
message and the `AGENTS.md`/`docs/86` pair now scope the claim, while keeping "do not skip it"
unambiguous.

**And the first attempt at that fix was itself the same defect.** It (a) said "sudo-free unless the
binary changed" against a trigger list of which only ONE arm is sudo-free — the recipe's idempotence
skip needs five conjuncts, so a missing runner, a missing stamp, or stripped caps all still fall
through to `setcap` — and (b) claimed the sweep was complete while four live statements of "one sudo"
survived, in `review-preflight-priv.sh` itself (twice, one of them directly above the
`BLOCKED-ON-BLESS` verdict), in `docs/84`'s rubric bullet, and in `guest_tuning.rs`'s runbook. Both
are now fixed; the accurate rule is **a sudo happens whenever `bless_one` falls through its
idempotence skip**, and the mtime proxy is the one arm that does not. `README.md`'s first-bless and
`implementation-notes`' caps-mismatch mentions are correct as written and were left alone.


---

# The 2026-08-20 loose-end pass — Tier A (defects) and Tier B (gate holes)

Directed by `docs/92-claude-opus-loose-end-inventory.md`, which swept every register for
specified-but-unbuilt work and put each candidate through an adversarial verifier whose default was
to assume it had already shipped. What follows reconciles what that pass actually changed. Items the
inventory records as Tier E (features) or Tier F (roadmap) are **not** here: they stay on the
register with their blockers, which is the difference between a scheduled cut and a forgotten one.

**The session closed-flag (design §17, Sessions).** `Session::write_stdin`/`close_stdin`/`resize`/`close` observed only the writer channel, which dies one transport failure *after* the reader task closes the registry, so each returned `Ok(())` for a no-op write across that window while its own `# Errors` rustdoc promised `Error::Steward`. The fix adds no new flag: the registry's `Option` — already the closure `SessionMux::open` reads — *is* the shared closed-flag, and a `Session` now holds a clone of that `Arc` and reads it in `Session::send`, the one helper all four mutators route through. Check-closed and enqueue occupy one critical section against the same lock the reader's terminal step closes the registry through, so the window closes rather than narrows: either the flag is `None` and the call fails loud, or the frame enqueues while the connection is genuinely open. The gate is six KVM-free in-crate legs: one refusal leg per method, each on its own connection with the writer asserted alive (a shared connection would make legs 2–4 vacuous through the older send-failure branch), a live-connection positive control that the four frames still reach the peer, and a call-site scan pinning `self.write_tx` to exactly one site inside `send` — red, respectively, on deleting the flag check, on a flag hardwired closed, and on inlining an enqueue into a mutator.


The §7.4 declaration sidecar is found by filesystem existence beside the image path, never through the artifact map, so a rootfs producer with no `RootfsFeaturesStage` beside it inherited whatever the last producer left there: `vmcell build --rootfs-source mmdebstrap` over an artifacts dir that held an OCI build republished `rootfs.erofs` under the OCI entry's `rootfs.features`, and every cell read that declaration — with the other artifact's provenance on every removal it caused — as this image's. `vmcell::feature::clear_feature_declaration` is the counterpart the register recorded as missing, sitting beside `feature_manifest_path` and composing the name through it, so a labelled image (`rootfs-acme.ext4` → `rootfs-acme.features`) is correct for free and the default image's live declaration beside it is untouched; a removal that fails is `Error::Artifact` naming the path, never a swallow. It is called from `pack_rootfs_with_injection`, the one inject+pack tail every rootfs source meets, rather than mirrored into the mmdebstrap arm, which covers the in-VM builder, `oci2-erofs` and any downstream producer on the listed surface in one site. That does not race the declaration stage's unconditional emission: the CLI pushes `RootfsFeaturesStage` after the image stage and `Pipeline::build` treats a vanished payload as a MISS, so the declaring pipeline re-emits the same bytes on the same build (the "a deleted sidecar comes back" leg of `the_sidecar_is_emitted_and_readable_including_for_an_empty_declaration` already pins that from the other side), and the worst case for any other ordering is the baseline rather than a foreign claim. The gate is the KVM-free `republishing_an_image_clears_another_producers_feature_declaration`: non-vacuity through `FeatureDeclaration::load_beside` before the pack, the positive `baseline` identity plus on-disk absence after it, and the default-image positive control that reddens on a hand-formatted name. The recorded-gap entry naming this mmdebstrap case is retired.


The `tar2erofs` file-vs-symlink clobber recorded as "still open" is closed, and it was worse than the note said: `rootfs_injection_manifest` injects the guest-tools multicall binary as a FILE at `{VMCELL_TOOLS_DIR}/{GUEST_TOOLS_MULTICALL_BIN}` and one applet SYMLINK per roster entry into that same directory, and since v33 delta 6 the roster is registry DATA — a handler entry naming `vmcell-guest-tools` as an applet replaced the binary with a dangling self-symlink under the tail's plain last-wins `insert`, so the image shipped with no multicall binary and every applet dangling while the pack reported success (the docs/90 H1 shape). `build_node_map`'s injection tail now claims each dest exactly once through the one `claim_injection_dest` predicate, keyed on the normalized path because that is the merged tree's own key, and refuses a second claim with a typed `Error::Artifact` naming the dest and both claimants. The scope is deliberate and stated in its rustdoc: EVERY duplicate inside vmcell's own manifest is refused, identical kinds included — matching the F5 duplicate-dest law `validate_extra_files` already applies to downstream extras rather than restating it more weakly — while the two collisions the packer resolves by design keep their existing behavior and their existing tests (a layer entry an injection overwrites, H-ART-3; an `ExtraFile` an injection overwrites, F5's structural backstop), and an injection whose dest is another injection's parent stays `nodes_to_erofs`'s L-ART-6 refusal rather than a second copy of it. `fuzz_node_paths` is unchanged and still reaches the production predicate through `build_node_map`. The gate is four in-file unit tests that drive `build_node_map`, each proven red by deleting the claim call in the loop it guards, by keying the ledger on the raw dest string, and — for the anti-over-reach control — by extending the ledger over the layer-merge keys.


**`mini-init`'s restart loop is paced, by the predicate that already owned the cap.** The v33 delta-5 record's own "not covered" entry — pacing on the spawn-failure arm only, so a program that exits instantly burns the cap in microseconds — is closed, and the entry is retired. The defect was one law spelled two ways: a `Duration::from_millis(200)` literal at the spawn-failure call site and no pause at all on the exit path, which is the path `/bin/false` (and any service that dies at start-up) actually takes; bounded and fail-loud, but with the retries so close together that no transient a retry exists for could clear between them, and with every console line written into the persisted serial artifact as fast as the guest CPU could emit it. `mini_init_next_failure_count` is now `mini_init_restart_after`, returning the pause *together with* the strike count — one predicate for "how many" and "how fast", because they answer the same question — and both call sites sleep what it returns. The shape is clamped exponential backoff charged to the strike (250 ms doubling to a 4 s ceiling, ~3.75 s across a whole burst: real time for a transient, still far inside the 30 s failure window so fail-loud stays prompt), while a program that *stayed up* is charged neither a strike nor a pause, which keeps the service SIGTERM leg as quick as it was. The arithmetic is the binary's one `retry_backoff`, which `accept_error_pacing` now also rides with its own two named constants — its curve is unchanged, and its pre-existing test proves it. Two gates, because the unit test alone cannot see the regression return: `every_rapid_restart_is_paced_and_the_whole_burst_stays_inside_the_window` (KVM-free, sleep-free — the predicate takes the measured run duration rather than reading a clock) holds the curve, red on an unpaced strike and red again on a window-sized one; `scripts/ban-unpaced-guest-retry.sh` holds the call sites, banning any `thread::sleep` in guest-tools production text that builds its duration on the spot, with its delegate named and its zero-file, sleep-free-tree, and missing-delegate scans all reported as `gate misconfigured`.


**The USB half of the restore-side eligibility law is closed.** No backend's `restore()` ran the USB precheck its `create()` ran: CH/FC/crosvm accepted a `usb_host_devices` list and dropped it silently, and QEMU — whose `usb_host_passthrough` is `true`, so `reject_usb_host_devices` passes it — spliced `-device usb-host,…` into the restored VM's argv through the shared `spawn_qemu` while handing the instance a `UsbHostClaim::default()`: devices never resolved to a usbfs node, never proven openable, never put back at teardown. The orchestrator boundary covered every in-tree path, but `Vmm` is public, so a consumer calling `vmm.restore()` directly bypassed it. `vmcell::vmm::reject_usb_host_devices_on_restore` is the one predicate all four backends now call before any spawn, in two arms: it delegates to `reject_usb_host_devices` (keyed off the descriptor handed in, so an incapable backend owes restore the identical refusal its create gives), and then — capability-independently, because no descriptor field can answer "re-attach a host device across a migration stream" — refuses with `USB_PASSTHROUGH_BLOCKS_RESTORE`, a `const` initialized from `orchestrator::INELIGIBLE_USB_PASSTHROUGH` rather than a second literal, so the backend and orchestrator boundaries cannot drift into two near-miss prose strings. Copying create's precheck alone would have been a no-op on the one backend that actually splices USB into its argv, which is why the second arm exists. Five KVM-free gates hold it: the predicate's own two-arm test in `vmm::tests` (red on either arm deleted) and one per-backend test driving the real `restore()` (red on the call site deleted, each landing on the next error down — the missing `config.json`/sidecar/snapshot artifact, or QEMU's in-kernel-vsock refusal). The QEMU leg additionally asserts that the cold path is untouched: `create()` still travels past the descriptor precheck into `claim_usb_host_devices`.


**§17 crosvm item 7 — the baked guest CID is now held by the restored VM's `CidGuard`.** crosvm's `restore()` re-programs the snapshot's baked `--vsock cid=` (it refuses a rotated one) while `restore_inner` allocated a fresh CID whose guard held only that one, so the baked CID — a host-global in-kernel AF_VSOCK identity, not a per-scratch-dir path — was free for same-process reallocation the moment the ancestor was torn down, and a later VM drawing it collided with the live restored VM; the M9 vmid fix could not reach it, because that one keys on the host *path* a backend adopted and crosvm spawns into its own scratch dir. `CidGuard` now carries a private `baked: Option<u32>` and the one predicate `CidGuard::adopt_baked_cid`, shaped after `VmidGuard::adopt_lineage` on the vmid axis: `restore_inner` calls it with `instance.guest_cid()` — what the backend says it actually answers on, so a rotating backend takes the no-op arm and no call site branches per backend — immediately after the vmid adoption and **before** the resume, an already-reserved CID is a warning rather than a refusal and is never adopted into the guard, and an out-of-range baked CID fails loud as `Error::Vmm`. A second copy of the law is not writable: `CidGuard`'s fields are private, so no backend crate can construct a guard, and inside `vmcell` there is one restore path — the drift is a compile error, so this law earns no grep-ban. The gate is the `snapshot_restore` matrix leg, which now holds the lowest CID across block 1 and releases it just before the restore (instead of holding the source's, which made the reservation unobservable — one allocator, one set entry, no refcount) and asserts that the CID the restored VM answers on cannot be reallocated while it lives, with the crosvm branch proving two distinct CIDs are held so the assertion is not the VM's own guard; it is red on the inverse live under crosvm ("the guest CID 4 the restored VM answers on must not be reallocatable while that VM is live"), and three KVM-free orchestrator tests over a purpose-built `BakedCidVmm` pin the adoption, the fail-loud out-of-range arm together with the before-the-resume ordering, and the never-took-it-never-releases-it arm, because CI has no crosvm binary and a live-only gate is a gate CI cannot run.


**The e2fsprogs cache key could not fall behind its pin any more, because it no longer restates it.**
`ci.yml`'s `actions/cache` key spelled `e2fsprogs-1.47.2-7a959221c1b1cc6e-…` against a `1.47.4` /
`da274408…` pin — so the very re-pin the digest-in-the-key existed to protect would have been served
the tree built from the bytes it replaced, and the key's own comment asserted that this could not
happen. A comment cannot hold two numbers equal. The pin moved to **job scope** in both jobs and the
key now interpolates `${{ env.E2FSPROGS_VERSION }}` / `${{ env.E2FSPROGS_SHA256 }}`, which makes the
restatement unrepresentable rather than merely repaired. The durable half is arm 8 of
`ci_obtains_the_ext4_facility_rather_than_living_with_the_skip`, which asserts the *coupling* rather
than the equality: the key must interpolate both halves, must not spell the pinned version
literally, and the step must not carry a second pin beside the job-scoped one. Proven red three
ways — the exact key that shipped, a half-interpolated key, and a re-added step-scoped pin. Arms 1–4
were rewired for the move (the build step is now located by its own `obtain_e2fsprogs` marker rather
than by `PIN`, which since the hoist matches in the job preamble; the step chunks are collected from
`steps:` onward so the job-scoped pin is not counted as a third chunk).

**`just example-downstream` exists, so the CI job can invoke a recipe instead of restating one.**
The `example-downstream` job hand-copied `cargo build --locked` and `./ci-check.sh` — AGENTS.md rule
3's drift class — and the reason the class had no home is that there was no recipe to call. There is
now, and the job is one `run: just example-downstream` behind the same pinned `taiki-e/install-action`
every other `just`-invoking job uses. `ban-recipe-body-handcopy.sh` covers it from that moment on.

**`cargo semver-checks` now runs on every event, not only on pull requests.** It was
`if: github.event_name == 'pull_request'`, and the only PRs this repo has ever had are dependabot's,
so the contract-surface gate had **never once run against a change to vmcell's own public API**:
every such change lands as a direct push to `main`, precisely the event the condition excluded. The
gate was structurally unable to fire on the path changes actually take. One baseline expression now
covers both events (`pull_request.base.sha` or `event.before`) — a second step with the opposite
`if:` would have been the hand-copy class one file over — and an all-zero baseline is fail-loud
rather than a silent comparison against nothing, which is the shape that hid this for so long.

**`test-unit-undelegated` proves its own premise before trusting a green run.** The recipe exists to
mirror the hosted runner's undelegated-cgroup condition, and its whole premise — that
`/sys/fs/cgroup` is *unwritable* inside the sandbox — was asserted nowhere. On a host where the
operator can write the bind source, the bind still succeeds, `create_dir_all` still succeeds, and a
green run reads as "the undelegated condition passes" when it never held. It now probes with an
actual `mkdir` through `bwrap` (a permission-bit reading would miss an ACL or a group) and reports
`gate misconfigured` rather than running — this repo's zero-file-scan doctrine one level out. Proven
both ways on this host: green against root-owned `/srv`, red against a writable bind source.

**`scripts/ban-orphan-recipe.sh` closes the orphan class one level above the scripts.**
`ban-ci-script-handcopy.sh` ARM 4 already holds the `gates` roster equal to the gate-shaped scripts
on disk in *both* directions; the identical argument about `just` recipes had no gate, and a recipe
nothing invokes rots exactly the way the three ci.yml hand-copies rotted — silently, because a thing
nobody runs cannot go red. It is a two-way roster rather than a bare "every recipe has a caller",
because some recipes legitimately have none: the opt-in live suites keep a *named* absent facility
(no crosvm binary, a full-Debian pull, a designated USB device) and the operator verbs are typed by
a human by design; demanding a caller would force a fake one. So an un-called recipe must be
rostered with its reason, and a rostered recipe that has since acquired a caller is a stale
exemption. Bodies are read back through `just --show`, which is also how the self-test caught a real
bug in the gate on its first run: `just --show` normalizes `{{just_executable()}}` to
`{{ just_executable() }}`, so the original needle found no recursive caller at all.

**`scripts/with-delegated-scope.sh` finally has a red-on-inverse self-test — and one arm out of
family.** It is the sole entry of `ban-ci-script-handcopy.sh`'s exemption allowlist and every live
suite runs through it, with four warn-and-continue arms on which `set -euo pipefail` is inert (each
being `if !`-guarded), so a regression there degrades every cgroup leg in the tree to "ran without
delegation" without reddening anything. The self-test fabricates a cgroup tree under `bwrap` —
`/proc/self/cgroup` is untouched, so the wrapper computes exactly the `cg_base` it would in
production and meets whatever the fixture put there — and drives all four arms, the
`exec "$@"` contract, and three mutated copies. Writing it surfaced the inconsistency: `mkdir -p
"$cg_base/supervisor"` was **unguarded**, so it was the one arm that aborted under `set -e` instead
of degrading, and it aborts the whole suite it was invoked to wrap. It is guarded like its four
siblings now.

**`just install-hooks` performs the deploy step `scripts/git-pre-commit` had only described.** The
hook's own header said "symlink into `.git/hooks/pre-commit`" and nothing performed it, so it was
installed in no checkout including this one — a deploy step written as prose is a deploy step that
does not happen. A symlink, never a copy: a copy is the hand-copy class one directory over, and it
silently keeps running the version it was copied from.


## Tier C — specified, small, unbuilt

`Stage` now carries a worked doctest and `Pipeline` an intra-doc link into the module's assembly example instead of a copy of it. The link's fragment needed its own gate: `rustdoc::broken_intra_doc_links` resolves the item half of `[text](crate::artifact#anchor)` and hard-errors on a bad path, but appends the `#fragment` verbatim without checking it, so a reworded module heading would silently land the reader at the top of the page. `artifact::tests::module_doc_anchors_name_headings_the_module_actually_renders` is that complement — it slugs this module's fence-aware `//! # ` headings, asserts every `crate::artifact#…` fragment in the file names one, and treats both an empty heading scan and an empty link scan as `gate misconfigured` rather than a clean pass. It names the rustdoc gate as its delegate so neither reads as a second copy of the other. The doctest is deliberately runnable rather than `no_run`: it touches no filesystem, so it also asserts cache-key purity and the default `cache_sidecar_path` extension-replacement law at test time, which a `no_run` example cannot.


§17's daemon gap "the reply still has no size ceiling of its own" is closed. `bridge::MAX_EXEC_CAPTURE_BYTES` is that ceiling, derived from `MAX_BRIDGE_FRAME_BYTES` less a reply-envelope reserve, times base64's 3/4; `enforce_exec_capture_ceiling` applies it in the broker-side `impl VmEngine for Registry` — both arms that can return an `ExecOutcomeDto`, `exec` and `create`'s inline `command`. An over-ceiling capture is `DaemonError::PayloadTooLarge`, a 413 through the one status mapping, naming the measured size, the ceiling and the remedy.

Three placements were rejected, each for a reason worth not re-arguing. `write_reply` is too late: all that survives there is a byte count, so the refusal cannot say the true cause and the outcome keeps reading as a server bug — that is the defect, not the fix. `dispatch` runs only under the broker, so the single-process daemon (`vmcelld` main.rs:383 hands the `Registry` straight to `AppState`) would enforce nothing and a client's limit would depend on the transport the operator chose; it would also have flipped the shipped `over_cap_exec_reply_surfaces_internal_instead_of_hanging` leg from 500 to 413, retiring a gate that still guards a live class. The engine adapter is the one seam both deployments traverse, so the limit is a property of the daemon's exec API rather than of its wiring, and `write_reply`'s fallback survives untouched as the backstop for a reply that is over-cap for some other reason.

Refuse rather than truncate-and-flag, and this is the recorded deviation from the item's own "truncate-and-flag versus refuse" framing. Flagging needs a presence-attribute field on `ExecOutcomeDto`, which is single-sourced with `vmcell-daemon-client` and rides this JSON channel precisely because `skip_serializing_if` does not survive postcard (Appendix A reversal 10): a wire change owed to every consumer, for an outcome that is still lossy — and a client that ignores the flag reads a prefix as the whole capture, the accepted-but-ignored hazard the `curl` shim exists to refuse. Refusal keeps the bytes in the guest, where a re-run redirecting to a file recovers them intact.

The gate is four in-file tests. Two are the boundary against the shipped constants (at the ceiling accepted, one byte over refused as 413, both driven off one grown allocation so the pair costs one ceiling-sized string) and the codec leg (the refusal survives the JSON channel and reconstructs as a 413 with its explanation intact, in a frame under 4 KiB — the refusal must not itself carry what it refused). The third measures the widest real reply envelope — a `Created` whose `VmInfo` names two artifacts at `MAX_ARTIFACT_NAME_LEN` — against the reserve, so the derivation is checked rather than asserted, and no figure is quoted in prose. The fourth is the call-site scan: the adapter block must contain exactly two `enforce_exec_capture_ceiling(` calls, because a green predicate beside an unchanged call site is the shape two of the six completeness-audit PARTIALs wore.

The ledger is owed and unapplied: `vmcell-daemon` 0.4.0 → 0.5.0 does not compose inside one crate — `vmcelld` and `vmcell-daemon-client` both pin `version = "0.4.0"` on the path dependency, so cargo refuses the workspace until all three manifests move together.


**The `am-fs-erofs`-off pack arm is typed, and its gate is a source scan because nothing compiles it** (docs/92 C5). The off arm of `pack_rootfs_with_injection` returns `Error::CapabilityUnavailable` — an emitter compiled out is an absent facility (§7.2), and a feature gate removes a capability rather than changing semantics — phrased like the `ext4-producer`-off `ext4_route()` so a caller matches one shape for both. `pack_erofs_with_injection`'s off arm delegates and carries no refusal of its own: its enabled form checks `PackOptions::format`, and with the packer compiled out no format is packable, so a format check there answers the wrong question.

That arm is unreachable by the compiler, not merely by the test suite. `rootfs` is gated on `pipeline`, `pipeline` enables `am-fs-erofs`, so `cfg(not(am-fs-erofs))` beneath it is unsatisfiable in every configuration cargo can build — demonstrated by a `compile_error!` in that body surviving `cargo check -p vmcell --lib --no-default-features --features pipeline` green. It is the exact inverse of the `ext4-producer` arm one emitter over, whose feature lives in `default` precisely so its refusal gets compiled, and it means the `ci` recipe's `--lib --no-default-features` line cannot cover this one. The gate is therefore `artifact::rootfs::tests::the_erofs_off_pack_arm_is_a_typed_capability_refusal`, an in-crate scan of the file's own text with both arms named and a two-hit non-vacuity assertion. Its honest limit, recorded on the test: a scan cannot see whether that arm still compiles. Re-adding the `mkfs.erofs` shell fallback is not the alternative — design Appendix B row 1 records it as graduated and §17 records the fallback as unimplemented and fail-loud today (§4.2); the rustdoc says so at the site so the reversal is cited rather than re-argued.

**A `#fragment` in an intra-doc link is unchecked, so `PackOptions`' pointer at the module example carries its own gate.** The contract-surface examples live on the `artifact` module doc; `PackOptions` links to the repacking one rather than repeating it. rustdoc resolves the item half of such a link and would redden on a misspelled module path, but never the anchor — the two pre-existing `#assembling-a-pipeline` links have the same silent hole — so `the_pack_options_example_pointer_lands_on_a_real_module_heading` slugifies `artifact/mod.rs`'s out-of-fence `//! # ` headings the way rustdoc does and asserts the fragment is one of them; it reddens from either side, the fragment or the heading.


README benchmark section and external-tool roster (docs/92 C2). The README carries no measured number: `### 10. Benchmarks` names the *shape* of a run — backend × mode, iterations after warmup, percentiles through the one `pcts` helper, the header's echo of the knobs and the `$VMCELL_*_BIN`-resolved binary — and points at what produces the numbers (`scripts/perf-matrix.sh` over `scripts/run-bench.sh`, `docs/benchmark-results.md` as canonical, design §16). The mode roster is not copied; it points at `VALID_MODES`, the same treatment `GUEST_TOOLS_APPLETS` already gets in this file. `just test-bench` is described as the wiring gate rather than the matrix, including that its argument is a features list and why crosvm is opt-in there. `scripts/ban-benchmark-figure-in-readme.sh` is the class's gate: a performance unit anywhere in the README, and any unit-bearing number inside the benchmark section, are both refusals; the section is discovered rather than hardcoded, so a rename or deletion reads as a misconfiguration rather than a pass. Its proof of life is a canary per arm plus a collapse check, because a clean README yields zero hits and a broken extractor looks identical.

The external-tool list is enumerated from the tree's actual spawns rather than from the previous list. Five entries were missing and are added with what needs each: `e2fsprogs` (production — the ext4 producer spawns `mkfs.ext4`; the batteries read back with `dumpe2fs`/`debugfs`/`e2fsck`), `iproute2` (`ip` for the suites' host-side residue assertions, `tc` for the segment netem legs), `util-linux` (`nsenter`), `python3` (the host-side data-plane peer), and `bubblewrap` (`just test-unit-undelegated`). The nftables bullet's claim that `iproute2` is not needed is corrected: it holds for production host networking, which uses `rtnetlink` directly, and not for the suites. §7 gains the five lint gates that `just ci` runs and the README never told anyone to install; `actionlint`, being neither a Debian package nor a crate, points at ci.yml's pinned step rather than copying its URL and digest.


Design §17 sketches the validator's backend knob as "a knob on `ValidationOptions`". It ships as a parameter instead — `validate_with(&vmm, &artifacts, &opts)` — and `ValidationOptions` gains no field. The sketch is not implementable: `Vmm::create`/`restore` are `async fn`, so `dyn Vmm` is `error[E0038]` and no field can hold an erased backend or an erased factory over one; the enum-of-backends rustc suggests would make a contract crate depend on `vmcell-firecracker`/`-qemu`/`-crosvm`, inverting the layering, and would still exclude the out-of-tree backend the knob exists for; and a generic `ValidationOptions<V>` routes the same type parameter through the configuration type for no gain, at the cost of every signature that carries one. The parameter form is what `vmcell-bench`'s composition root and this crate's own `conformance::LiveProbe` already use, and it keeps `ValidationOptions` plain `Clone + Debug` data, which is what makes the change additive rather than breaking. §17's second question — one door or both — answers itself: `conformance::run_battery` never had the hardcode, so the `run_budget` asymmetry does not repeat; `only_the_default_door_names_a_concrete_backend` gates that rather than restating it. One deviation of its own: `validate_with` does not probe `/dev/kvm`, because the caller who chose the backend is the one who knows whether it needs one — `validate` probes for the Cloud Hypervisor it picks, `harness::has_kvm()` is public for a caller doing the same, and a test double needs nothing; refusing on the double's behalf would put the knob's own gate behind the facility the knob exists to be testable without. Artifact existence does move into `validate_with`, through the one `ensure_artifacts_exist` predicate both doors call, so a path typo is a typed refusal at either entry point. `validate`'s observable behavior, refusal order included, is unchanged. Note for whoever maintains the review record: `docs/90-claude-opus-code-review.md`'s C5 row names the now-public `validate_on` by its old private name.


## Wave 3 — the remaining Tier A defects and Tier C items

C9 — the parser-recognized-but-uncommitted pins. `KNOWN_PINS_NAMESPACES` recognized ten namespaces; `pins.json` committed seven. The gap was three, not the two design §10.2 names: `builder_base` (deliberate — a downstream override pair whose absence is `resolve_builder_base`'s `rootfs_*` fallback), `debian_snapshot_timestamp`, and `virtiofsd`.

`debian_snapshot_timestamp` is now COMMITTED as `20260801T000000Z`, validated live against snapshot.debian.org (resolves to Debian 13.6 `trixie`, `Date: Sat, 11 Jul 2026` — and `trixie` is `vmcell-cli`'s `DEFAULT_RELEASE`). The gap was not merely a cold cache key: `vmcell-rootfs-builder`'s `MmdebstrapRootfsStage::run` hard-errors `Missing debian_snapshot_timestamp pin`, so the shipped verb `vmcell build --rootfs-source mmdebstrap` could not run off the committed baseline at all — only under a `$VMCELL_PINS` overlay — and that stage's `cache_key` folded `unwrap_or_default()`, an absence, so a re-pin could not invalidate a stale rootfs. The fold now hashes a value.

`virtiofsd` stays UNCOMMITTED, deliberately, and the decision is now gated rather than tacit. Nothing in the tree reads the pin; `artifact/snapshot.rs:43-44` records why nothing may fold it (a snapshot-eligible VM attaches no vhost-user device, §8.1, so the snapshot never runs virtiofsd); and `ci.yml`'s `cargo install virtiofsd --locked` pins no version at all, so a committed value would be an unenforced substrate claim — one that has ALREADY drifted three ways in prose (host 1.14.0 / README "1.14.0 at the time of writing" / docs/benchmark-results.md 1.13.3). `every_recognized_pins_namespace_is_committed_or_declared_uncommitted` holds the exception table in both directions: committing the pin without wiring a reader now goes red naming the recorded reason. The fully-honest end state — deleting the namespace so an overlay naming it is rejected loud — is a breaking change to listed contract surface (§10.4) and is left to a pass that may touch `crates/vmcell/Cargo.toml`.

Design §10.2's sentence "the CH/virtiofsd and snapshot-timestamp pins are recognized-when-present but not currently committed — so the snapshot stage's CH-build-identity fold arms only once that pin is added" was ALREADY stale before this pass (`cloud_hypervisor: "v53.0"` landed in the 2026-08-20 dependency pass, so the fold has been armed); it is now stale on the timestamp half too. Fold the correction in at the next design reissue rather than as errata.


C4 — bench-vm's workspace-root ascent, design §17's last open "one law, one predicate" consolidation, is CLOSED. `vmcell::artifact::workspace_root()` is `pub` (it was `pub(crate)`, which is exactly why the third copy existed); `bench-vm`'s `workspace_root()` is now a one-line delegation, the shape `harness::ch_bin()` and the CLI's `ch_bin()` already use. The export stayed in `crates/vmcell/src/artifact/mod.rs`: the ascent's private core `find_vmcell_source_root` and its two other public answers (`artifacts_dir`, `vmcell_source_root`) are already there, so moving the law would have created the second home the item exists to prevent. `artifacts_dir()` had exposed this ascent's result joined with `target/vmcell-artifacts`; a caller wanting the bare anchor had nothing, which is the whole gap.

The coupling §17 named — the `crates/vmcell-protocol/Cargo.toml` marker — is now spelled in one production line and gated by `scripts/ban-workspace-root-ascent-copies.sh`. The gate's needle is UNQUOTED, unlike its `$VMCELL_CH_BIN` sibling, because the marker also appears inside a user-facing string (`guest_tools.rs`'s "no vmcell checkout (no `…` above {})") and that mention is a real coupling: if the marker moved, the message would send an operator hunting for a file that no longer marks anything. It is rostered with its count and reason rather than excluded.

THE SECOND HALF OF THE NOTES ENTRY IS NOT OPEN, and was left alone as instructed. `bench-vm`'s four-backend `VMM_BIN_RESOLVERS` table is held by a gate that CAN fail: `vmm_binary_matches_validator_contract_getters` pins all four DEFAULTS against `harness::{ch,fc,qemu,crosvm}_bin` (a bench-local `"qemu"` for QEMU reddens it), the var-name half is pinned by the injected-lookup test, the CH leg additionally equals `vmcell::artifact::ch_binary_path()`, and `ban-ch-binary-resolver-copies.sh` carries the file as a rostered entry at count 2. Collapsing further would need `fc_binary_path`/`qemu_binary_path`/`crosvm_binary_path` on the library, which §17 explicitly scopes out ("no `vmcell`-side law to route through, so banning their spellings would name no home to send the reader to; when one is added this gate grows an arm"). Not touched.

Two observations for whoever writes the register next, neither acted on:
* `crates/vmcelld/tests/integration.rs::workspace_root()` is a fourth spelling of "the root", but it walks two `parent()`s from its own `CARGO_MANIFEST_DIR`. Deliberately OUT of the new gate's scope, stated in its SCOPE section rather than left implicit: it cannot drift with the marker, it knows its own depth, and it breaks loudly if the crate moves. It answers a different question than the library's ascent ("where is the root from an ARBITRARY start dir, and what if there is none").
* `bench-vm` carries several pre-existing bare `let _ = std::fs::remove_dir_all(&snap_dir)` (≈ lines 287/315/382/1510/1522/1530), an AGENTS "fail loud" violation inside my file budget but outside this item. Left for a pass that owns it rather than folded in.


For `docs/implementation-notes.md` — I did not edit it (orchestrator-owned). The "virtiofsd readiness is paced by the caller's profile, with one narrowing" entry contains a now-discharged sentence; suggested replacement for the passage running from "The unpaced `start` survives as a `#[deprecated]` shim…" through "…Delete it at the next `vmcell` version bump.":

  The unpaced `start` shims are **deleted**, on the `0.22 → 0.23` edge, under both `experiment-fuse`
  arms — the ledgered bump that entry was waiting for. `start_paced` is now the only entry point, so
  reaching for the shorter name is a compile error rather than a deprecation warning. The recorded
  measurement held on the real edge: `cargo semver-checks --baseline-rev origin/main -p vmcell`
  reports "no semver update required" (for a `0.x` crate it treats the minor bump as the
  allowed-to-break slot and skips all 254 checks), so the ledger entry and one new gate are the only
  things carrying the break. That gate is
  `fs::one_start_entry_point_gate::virtiofsd_declares_exactly_one_start_entry_point`, which scans
  `fs.rs` for the roster of `pub async fn` declarations and reddens on a second one. It exists
  because the two backend scans gate CALL SITES and the shim was declared-and-never-called in-tree:
  its mispacing was reachable only by a downstream consumer and structurally invisible to this repo
  — the same blind spot that let the shim survive ten releases. Adding a `pub async fn` is neither a
  compile error nor a signature semver-checks reads, so a scan is the only thing that can go red on
  it.

Also for the orchestrator: `docs/92-claude-opus-loose-end-inventory.md` line 72 ("The deprecated unpaced `VirtioFsDaemon::start` shims are past their recorded delete-at-next-bump date") is now discharged and should come off the Tier C list.


**C7 — `Egress::Open` forwards what its mode admits, and refuses the rest (the smoltcp NAT half).** Design §17 recorded `Egress::Open` as providing no *arbitrary* outbound egress, closable "by real re-origination or a typed `Unsupported`". Neither was the right close, and the recorded framing understated the defect: on the unprivileged NAT, "not implemented" was implemented as *answering with something else*. `run_network` sets `set_any_ip(true)` — load-bearing for `Filtered`'s transparent L4 interception — under which smoltcp's `process_ipv4` accepts a frame for any destination (`has_ip_addr` returns `true` unconditionally when AnyIP is on), and a permanent forward armed on a bare port matched every destination address (`TcpSocket::accepts` reads `listen_endpoint.addr == None` as `addr_ok = true`). A guest dialing `93.184.216.34:<host_services_port>` was therefore accepted and spliced onto `127.0.0.1:<host_services_port>` — the host's own service. A silent destination substitution standing in for the egress the mode does not provide.

Real re-origination was rejected: `Open` is the default, so it would hand every existing test VM whatever the host can reach, on the datapath §17 records an open bring-up flake against. A construction-time typed refusal was rejected as *unavailable*, not as too small: there is no input by which a caller asks for arbitrary outbound — `Open` is the default and the only spelling — so refusing it at `build()` breaks every shipped configuration, and a new always-`CapabilityUnavailable` variant would be a knob nobody boots plus an unwarranted public-API addition. The request is expressible only as a guest SYN, so that is where the refusal now lives.

Landed: `net::smoltcp::backend::nat_forward_endpoint(host_gw, port)` is the one law for a permanent forward's destination scope — this VM's own `/30` gateway, the §6.3 endpoint address the guest is given. `rearm_or_release_closed` takes a whole `IpListenEndpoint` rather than a `u16`, so the NAT's only permanent `listen` site cannot spell the scope itself. An unadmitted destination now falls through to smoltcp's `rst_reply`: refused, not mis-originated. `admit_syn`'s dynamic mappings deliberately keep the unpinned form — that asymmetry is the difference between `Open` (refuse) and `Filtered` (intercept). One consequence is recorded at the composer: a `Filtered` VM's SYN to a foreign address on a *forwarded* port is now refused rather than intercepted; it was never intercepted before either (it was mis-originated), so the refusal removes a wrong answer without removing a right one.

Gates: `open_admits_the_gateway_endpoint_and_refuses_an_arbitrary_destination` drives the real smoltcp stack with hand-built ARP/SYN frames and asserts on the frames that come back (negative first, then the positive control on the same socket) — red on the bare-port form with `syn=true rst=false`; and `every_permanent_forward_is_armed_on_the_composed_gateway_endpoint`, an in-source call-site scan, because the two spellings compile identically and no signature can see the drift — red on a dropped composer with "expected exactly 1 `nat_forward_endpoint(` call site; found 0". Its self-test carries the empty-text leg.

Live: `test_egress_proxy_unprivileged`, `host_endpoint::cloud_hypervisor`, `nat_window_fill::cloud_hypervisor`, `nat_window_fill_upload::cloud_hypervisor` all pass, skip manifest empty — every one dials the gateway through `vmcell::net::ip_math`, which is exactly what the scoping admits.

**Still open (deliberately out of this change's file scope):** the privileged arm. `Egress::Open` → `PrivilegedEgressRules::NoRules` installs no nft table at all, leaving the per-VM netns at the kernel's default `accept` — "whatever the datapath natively provides" is unpinned rather than enforced. Same honesty argument, but the predicate lives in `orchestrator.rs`. §17's Networking entry should be narrowed to that remaining half rather than retired.

Also corrected: `Egress::Open`'s rustdoc pointed at `implementation-notes.md (§16, H-NET-4)`; `H-NET-4` survives only under `docs/historical/`, so the pointer was dangling and no gate could see it (`ban-dangling-design-ref.sh` resolves `§16` against the *design*, where it means "Performance"). Now cites design §6.2/§17.


## As built: A6 (both orphan sweeps were liveness-blind) + A9 (`TUNSETIFF` adopted a stale tap)

**Landed as ONE change, because A9 is unsafe without A6's other half.** The recorded open item said
`IFF_TUN_EXCL` "belongs with the daemon start-up sweep that would have to reclaim it"; this is that
pairing. Both recorded entries are hereby RETIRED — `clean_vmcell_netns` and the daemon's start-up
sweep are no longer liveness-blind, and `TUNSETIFF` no longer adopts.

**The liveness test is the id-claim lock, not a new notion.** `FsIdClaim::owner_is_live` was
extracted out of `try_claim` and is now shared with both sweeps: one law, one predicate, and the
gate on its drift is `scripts/ban-id-claim-law-copies.sh`. Three alternatives were weighed and are
recorded at `orchestrator::IdClaim` so nobody re-derives them: a process in the netns (false for
every healthy VM — the VMM runs in the host pid namespace), a tap carrier/attached owner (false for
the whole window between our create and the VMM's open), and a `/proc/*/fd` scan (racy, and answers
about the namespace rather than the id). `IdClaim` is three-valued and only `NoLiveOwner` permits a
removal; an unreadable registry RETAINS.

**Two shapes worth recording.** (1) `cleanup_orphan_netns` receives a `starts_with` filter, not an
id space, so it asks both registries and keeps the strongest retention (`host_id_claim_any_space`).
That is sound because it can only ever retain MORE than the id-space-precise check; the cost is a
coincidence (a dead `-net-7` kept while segid 7 is live) and the alternative is deleting a running
VM's network. The per-space check stays the rule wherever the space is known. (2) The sweep now
removes something from INSIDE a resource it declined to remove: a segment netns outlives any single
member, so a SIGKILLed member's persistent `<prefix>-tap-<vmid>` is residue that no netns deletion
reaches once the namespace is (correctly) retained for its live members. Member taps are recognised
through `naming::tap_name` equality, never a `-tap-` prefix — the bridge and `lo` are then out of
reach by construction.

**A stale-premise check that paid off.** The note's claim that `TUNSETIFF` silently adopts was
verified, not assumed: with the flag removed, the live leg reports `setup_tap` returning `Ok(())`
against a pre-existing `ip tuntap`-planted tap.

**Deliberate scope limit, recorded rather than hidden.** A hermetic allocator registers nothing, so
the sweeps cannot protect it and behave exactly as before. The protection is real for every
`HostEnv::shared` caller. Also unchanged: `vmcell-broker`'s `BrokerReply::SweepDone` does not carry
the two new `SweepReport` lists (`member_taps`, `retained`) — the sweep still performs the work over
the broker, the reply just does not report it; adding them is a wire-DTO change for a later pass.

**Gates.** `scripts/ban-id-claim-law-copies.sh` (+ self-test) for the law's two halves; seven KVM-free
unit tests including the allocator↔sweep join and the two cross-space legs; and three live legs in
`crates/vmcell/tests/tap_create.rs` (no VM, `CAP_NET_ADMIN` only): the exclusive-create refusal with
its untouched-interface residue check and a positive control, the sweep keeping a live sibling's
namespaces while reclaiming our own stale member tap AND the reclaimed name becoming creatable again
(the join between the two halves), and the test-start sweeper honoring a held `VmidAllocator::shared`
claim with the release-then-reclaim non-vacuity leg.


## Wave 4 — Tier D: the shipped knobs no test applied in a live boot

For `docs/implementation-notes.md` — the existing "**`io_max`'s enforcement half**" bullet (around line 5034) should be SUPERSEDED rather than deleted, since its refusal-half record still stands:

**SUPERSEDED 2026-08-21: the enforcement half is now a probing leg, and the gap is a recorded skip that can change.**

`a_requested_io_max_actually_throttles_the_guests_block_io` (`crates/vmcell/tests/metrics_limits.rs`) closes the entry above the way AGENTS.md rule 4's second half asks. It PROBES the facility — `io` in the VM slice parent's `cgroup.controllers`, and a whole block device under the scratch tree — and either measures the throttle or records a reviewable capability skip, in `common::probe_ext4_or_record_skip`'s shape including its absent-versus-broken distinction: a cgroup-v2 placement whose `cgroup.controllers` cannot be read PANICS (a broken mount is a misconfiguration), while a host that simply lacks `io`, or whose scratch is on a tmpfs, records `SKIP cloud-hypervisor io_max_enforcement_no_io_delegation` / `…_no_block_backed_scratch`. Two tokens, because the two absences have two different remediations.

The measured host fact, 2026-08-21: the cgroup ROOT lists `io` in `cgroup.controllers` but enables only `cpu memory pids` in its `cgroup.subtree_control`, so `io` is absent from `user.slice`, `user-1000.slice`, `user@1000.service` and every scope below — a user session cannot enable it, and `/sys/fs/cgroup/cgroup.subtree_control` is root-owned. `std::env::temp_dir()` is a tmpfs (`0:48`) on top of that, so the leg takes the delegation skip first and the block-device skip second. **The measurement half has therefore never run anywhere**: its `IO_MAX_WBPS` / `IO_WRITE_MIB` / floor constants are derived from the cap, not observed, and the leg's comment block says so rather than implying a measurement.

What is falsifiable today is `the_io_max_enforcement_probe_resolves_whole_disks_and_per_device_counters` — KVM-free, not `#[ignore]`d, so `just test-unit` runs it on every host. It pins the three laws the measurement rests on: `whole_block_device_of` resolves a partition to its parent disk (the kernel's `blkg_conf_open_bdev` refuses partitions with the same `ENODEV` the refusal leg classifies) and a whole disk to itself, and the `io.stat` readers match device and key WHOLE-token (decoy lines `1259:0 …` and `rwbytes=99` are what make a `contains` implementation go red).

One consolidation came with it: the "is `io` delegated?" question is now `IoDelegation::measure()`, one measurement shared by the refusal leg and the enforcement leg. Two spellings would have had one leg asserting the kernel-`ENODEV` arm while the other recorded an absent facility on the same host, with nothing to notice.

And for `docs/todo.md`, the T1 entry ("`metrics_limits.rs`'s `io_max` refusal leg … kernel-`ENODEV` arm is dead on a default systemd user session") stays true as written, but should gain: the enforcement half is no longer missing-and-invisible — it is a probing leg whose absence shows up as a line in the skip manifest, and the T2 bullet claiming `io_max` reaches no live boot at all should be retired in favour of "its measurement half is written and gated behind a facility probe; no host has yet run it".


docs/implementation-notes.md carries the same recorded deviation TWICE and both copies are now false; the orchestrator owns docs/, so here is the replacement text.

At line ~4977 and again at ~5050, this entry:
  "- **`RestoreMode::Eager` / `Lazy`.** Present in backend unit tests as refusal/argv assertions; no gate performs a restore under either mode."
  "- **`RestoreMode::Eager` / `Lazy`.** Unchanged: refusal and argv assertions only; no gate performs a restore under either mode."

RETIRE both (empirically disproven) and record instead:

  - **`RestoreMode::Eager` / `Lazy` — CLOSED (2026-08-21, docs/90 T2 / docs/todo D1).** Two halves.
    KVM-free: `cloud_hypervisor.rs`'s `every_restore_mode_reaches_the_composed_argv_as_its_prefault_modifier`
    pins ALL THREE variants — `Default` included, the least-tested arm — on the COMPOSED
    `LaunchPlan::argv()`, driven from a real `VmConfig`'s `restore_mode` rather than from a
    hand-written argument, plus pairwise distinctness. Live: `tests/snapshot_restore.rs`'s
    `non_default_restore_modes_ship_their_prefault_argument_and_restore_a_live_guest` restores
    twice from private `env.overlay` copies of one snapshot, differing in exactly `restore_mode`,
    and for each mode asserts the `--restore` value on the argv of the LIVE `cloud-hypervisor`
    process (read from `/proc`, selected by scratch dir, never by the token under test) and then
    the same host->guest->host egress byte the matrix leg asserts, with the pre-snapshot exchange
    as its positive control. Its `/proc` scan has its own KVM-free gate,
    `the_scratch_dir_process_scan_finds_exactly_the_right_argv`, with a prefix-collision decoy.
    **Deliberately NOT proven, and stated at the test:** nothing here observes the *paging*
    behavior `prefault` selects — a leg showing the VM boots under the flag would read identically
    if CH ignored the token. The argument is pinned exactly; that CH honors it is CH's contract,
    measured (not asserted) by `bench-vm`'s `--restore-mode` sweep.
    **Deliberately CH-only.** `prefault=on|off` is a CH `--restore` modifier with no equivalent
    selector on the other three backends; `Lazy` is a typed `Unsupported { feature: "lazy_restore" }`
    there via the one shared `vmm::reject_unadvertised_capabilities`, and `Eager` is what those
    three already do. Restoring three more backends to watch `Eager` change nothing would cost
    three snapshot+restore cycles for no assertion.

And in docs/todo.md, the bullet "Both non-default `RestoreMode`s: shipped, documented, and applied
in no integration test …" is closed and should be struck, with `Timeouts::low_latency()` as a
preset left as the remaining T2 survivor.


docs/implementation-notes.md (orchestrator owns the file): "docs/90 T2, `Timeouts::low_latency()`/`throughput()` as booted presets — closed in `crates/vmcell/tests/guest_tuning.rs`. The preset is booted unmutated and its `guest_rebind_idle` measured through the /proc/1/fd listener-churn technique against a control that is the SAME preset with only that field restored to the shipped default: one variable by construction, rather than a `Timeouts::default()` twin differing in seven fields. Only that field is on the measured path — `guest_accept_poll` paces failure recovery only (`recovery_backoff(IdleWindowElapsed, _) == Duration::ZERO`), and the other five knobs are host-side. `throughput()` is covered as ARRIVAL only (its own rendered tokens read back from the guest's `/proc/cmdline`): its 200 ms window against the default's 250 is a 1.25x separation inside the measurement's noise, so a churn leg for it would be a coin-flip. `throughput()`'s distinctive knob `shutdown_grace` is host-side and has no in-guest observation — deliberately uncovered, recorded here rather than gated. The live legs' verdict arithmetic is extracted into predicates and driven KVM-free with both outcomes' counts, because a bound loose enough to admit an ignoring guest is invisible to a green live run."


For `docs/implementation-notes.md` (I could not touch docs/):

**`nested_virt` is a cmdline-only lever, and the L2-boot leg is a requirement proof, not a flag proof (2026-08-21).** `cfg.nested_virt`'s entire effect in the tree is the `kvm-intel.nested=0|1 kvm-amd.nested=0|1` pair emitted by `config.rs`'s cmdline builder; no backend reads the field except `reject_unadvertised_capabilities`. That module parameter governs whether the **L1's** KVM exposes VMX to *its own* guests (an L3), not whether the L1 can run an L2 — the L1's ability to run an L2 comes from the L0's nested KVM plus the backend's unconditional VMX exposure (`-cpu host` on QEMU, CPUID passthrough on CH). Consequences, recorded so they are not rediscovered: (a) `checks::nested_kvm_ok` / `kvm-ok` can only ever fail because of the *host's* nested support, which is what `nested_virt_disabled`'s comment already says about `/dev/kvm`; (b) a `nested_virt = false` twin of the L2-boot leg would still boot an L2 and must NOT be written as a negative control; (c) the flag's causality is pinned by the module-parameter differential only — `nested_virt_l2_boot` asserts `Y`/`1`, `nested_virt_disabled` asserts `N`/`0`, both through the one extracted `read_guest_kvm_nested_param`.

**The L2 payload is Firecracker, carried in over virtio-fs, and this is deliberate.** `nested_virt_l2_boot` boots a real L2 inside the L1 using the host's `firecracker` binary as an in-guest payload (`static-pie`, 3.4 MB, needs only `/dev/kvm` + two files); CH and crosvm are dynamically linked and QEMU is not a single file. `vmcell-firecracker` is not involved and FC's own arm skips through `require_cap!`. The kernel and rootfs are exported from the artifact directories rather than copied into the test's TempTree: 150 MB per run under the host tmpfs is the shape that produced the `EDQUOT` daemon-suite red. Alternative deliberately not taken: a guest-tools KVM-ioctl applet (`KVM_CREATE_VM`/`KVM_CREATE_VCPU`/`KVM_RUN`) — it would prove less (no L2 kernel, no L2 userspace) and would couple this leg to a `vmcell build --kernel-source host-make` rebuild, which the shipped route needs none of.

**Also update** `docs/92-claude-opus-loose-end-inventory.md` Tier D ("Nested virtualization is validated by opening `/dev/kvm` in the L1 guest; no L2 guest is ever booted") and the `docs/todo.md` entry pointing at `crates/vmcell/tests/nested_virt.rs` once the live legs pass.


## docs/92 Tier B, B1 — the fail-loud class gets a gate (as built)

**What landed.** `clippy::let_underscore_must_use` is now denied in the `#![cfg_attr(not(test),
deny(…))]` block of all **20** crate roots, closing AGENTS.md's "Fail loud" rule — *no bare `let _ =`
on a `Result`* — which until now had no lint, no script and no test that could go red. The 268 sites
the lint reported (the 259 in docs/92, re-measured) split 166 production / 102 test.

**Four real defects, which is what the item was worth.**
1. `vmcelld::shutdown_signal` turned a signal-**registration** failure into an immediate shutdown:
   both arms discarded the registration result, so a handler that could not be installed *completed*,
   `select!` fired, and `serve` returned the instant it started. Now `unregistered_signal(..) ->
   Infallible` logs at `error!` and parks; the uninhabited return type makes falling out of it a
   compile error. Latent under `#[tokio::main]`, severe when it fires. Gate:
   `vmcelld::shutdown_signal_gate` (never-resolves leg + resolving positive control), red on the
   inverse.
2. `vmcell-guest-tools`' `curl` shim (`probe_connect`) discarded both socket deadlines, so the
   `--max-time` its own comment promises to honor did not bound the read loop — a quiet proxy hung
   the shim past any deadline. Now `bound_stream_by` refuses loud. Gate:
   `a_socket_deadline_that_cannot_be_applied_is_reported` (injects `Duration::ZERO`, a real
   `setsockopt` refusal per `std`'s documented contract, plus a positive control).
3. The same function discarded its response-body write to stdout while its rustdoc contracts "body to
   stdout" and the egress battery asserts on that body — exit 0 with no output. Now `emit_body`
   refuses loud. Gate: `a_body_that_cannot_be_written_is_reported`.
4. `vmcell-cli`'s interactive session discarded `write_stdin`/`close_stdin`, so a dead transport ate
   keystrokes in silence while the arm stayed re-armed. Now reported, and forwarding stops — the same
   handling the local-read-error arm beside it already had.

**One consolidation.** `vmcell-qemu`'s external `vhost-device-vsock` daemon was the last copy of the
negated-pgid kill law outside `vmcell`, hand-rolled in both `kill()` and `Drop`. It now travels as a
`vmcell::vmm::VmmProcessGroup`, which also gives it the M-VMM-1 reaped-flag guard the copies lacked.
Validated live by `test-unprivileged`'s QEMU leg, with no daemon orphan afterwards.

**Eleven helpers** absorb 88 legitimate sites, and nine of them **report** rather than discard
(`best_effort::{shutdown,discard_dir}`, `shutdown_after_check`, `publish_startup`,
`send_msg_best_effort`, `join_pump`, `publish_chunk`): the class went from silent to observable,
which is what "fail loud" is reaching for where propagation is impossible. 62 statements keep a
per-statement `#[expect(…, reason = "…")]`, each stating that site's own reason.

**Scoping, deliberately.** `not(test)` — the same visible mechanism that already scopes
`unwrap_used`/`panic`/`print_stdout`. Test code's discards are dominated by idempotent `try_init()`
and Drop-guard reaps; 102 forced reasons there is the hollow-suppression theater rule 2 forbids. The
lint is broader than the rule on one axis (any `#[must_use]`, e.g. a detached `JoinHandle`) and that
breadth is kept: it is the same defect one step out, and it is the narrowest instrument clippy has.

**The roster's own gate.** A per-crate lint leaves one hole — a **new crate**, born without the line,
with every existing gate green. `crates/vmcell/tests/lint_roster.rs` closes it: it scans every crate
root (conventional paths plus section-aware `[lib]`/`[[bin]]` `path =` declarations), requires the
lint *inside* a `not(test)` deny block (a prose mention or a per-statement `#[expect]` does not
count), and carries both the zero-file-scan guard and a scanner positive control. It is a test rather
than a `scripts/ban-*.sh` because `ban-ci-script-handcopy.sh` ARM 4 fails on an orphan script and the
`justfile` was out of scope for this change; an in-source scan needs no roster entry at all.

**Deliberately NOT done, and why.** No new public API: a cross-crate `besteffort` module for the
~13 fs-unlink sites in FC/QEMU/crosvm/CLI would have grown contract surface, required a ledger entry,
and rippled a `vmcell` version bump through 14 sibling manifests — for an internal cleanup. Those
sites carry per-statement suppressions instead. `cargo semver-checks` reports no update required for
either contract crate.

**Residual, recorded rather than implied.** (a) The rule's other half — "or on an accepted input" —
is not covered: `let _ = cfg.field;` is not `#[must_use]` and no clippy lint sees it. (b) The lint has
a one-token bypass (`drop(expr)`, `.ok();`); the tree carries neither idiom today, and nothing gates
that. (c) `examples/downstream-kernel/` is out of scope by design (it is the consumer workspace).
(d) `vmcell-qemu`'s `nix` dependency is now used only by its test module; moving it to
`[dev-dependencies]` is a lockfile-touching follow-up, and `cargo machete` is silent on it.

**Verification.** `just ci` green end to end (including the 298-config feature powerset, machete,
actionlint, zizmor, typos, semver-checks, 1356 unit tests, doctests, and the whole `gates` roster).
`just test-unprivileged` 4/4 with zero capability skips. The privileged suites were **not** run:
`scripts/review-preflight-priv.sh` reports KVM/artifacts/cgroup-delegation all OK but
**BLOCKED-ON-BLESS** — this change edits `vmcell-test-runner/src/main.rs` and
`vmcell-privilege/src/lib.rs` (both crate roots took the preamble line), so the blessed runner is
stale and needs `just bless` before `test-privileged`/`test-daemon`/`test-validator` can certify the
tree under review.


## Wave 6 — Tier E, the first four designed features

For docs/implementation-notes.md (I may not edit docs/**):

**PTY `StdinEof` is a typed refusal, not the design's "no-op" (E2, design §17 Sessions; §3.3 deviation).** Design §3.3 specifies `StdinEof` as "a no-op for a PTY session … a half-closed-input refinement is §17". As built, that no-op was worse than documented: `route_stdin_eof` enqueued `StdinItem::Eof` and the stdin writer thread discarded it for a PTY sink — an accepted input neither honored nor rejected, with the host's `Session::close_stdin` returning `Ok(())`. §17's refinement is now landed as a **refusal**, and §3.3's "no-op" wording is superseded: `Session::close_stdin` returns `Error::CapabilityUnavailable` for a PTY session (decided host-side from the `SessionSpec`, before `encode_frame`, so no frame reaches the wire), and `route_stdin_eof` refuses one loud in-guest for a non-conforming client. Option (a) — deliver the termios `VEOF` — was implemented, measured, and rejected: VEOF means end-of-input only to a reader in canonical mode at that instant and is a literal `0x04` data byte to any other, and the mode can change between the check and the write, so no mode-discriminating variant is sound. §7.2 governs: an absent facility is refused, not approximated. Two predicates hold the one law, one per side of the wire (they cannot be single-sourced without touching `vmcell-protocol`): `Session::supports_stdin_close` (host) and `SessionHandle::accepts_stdin_eof` (guest, one call site — `session_stdin_route`), each with an in-file call-site scan. **Recorded honest boundary:** the guest's refusal is a `tracing::warn!`, because the protocol's only guest→host session frames are `SessionStdout`/`SessionStderr`/`SessionExit` — an in-band report would inject steward prose into the caller's terminal stream, and a per-frame error reply would be a wire-protocol addition. It is unreachable through vmcell's own host API by construction.


For `docs/implementation-notes.md` (I could not edit docs/ — please land this, it is a justified deviation from a design statement):

### E5: the netns-scoped net-usage read is netlink, not sysfs (§7.1 / §17 premise corrected)

§7.1 ("Per-VM egress bytes belong in a future *network*-scoped usage type that reads
`/sys/class/net/<if>/statistics` inside the VM netns") and §17's Networking register state the
mechanism as fact. The mechanism does not work. sysfs's net subsystem is namespace-tagged **per
superblock**, captured at mount time — `kernfs_super_info->ns` — so `setns(CLONE_NEWNET)` moves the
calling thread and leaves the inherited `/sys` describing the namespace it was mounted in. That is
why iproute2's `netns_exec` unshares the mount namespace and re-mounts `/sys` at all ("Mount a
version of /sys that describes the network namespace").

Observed on this host, no privileges needed:

    $ bwrap --unshare-net --unshare-user --dev-bind / / -- \
        sh -c 'ls /sys/class/net; ip -o link show'
    enx9cbf0d000d07 enxa0cec8fb6e0c lo wlp170s0     # sysfs: the ROOT netns
    lo                                              # netlink: the new netns

A sysfs read after a bare `setns` therefore answers about the **root** namespace: `ENOENT` for a tap
that exists only inside the VM's namespace (which `tests/lifecycle.rs` already notes never appears
under the root `/sys/class/net`), and — the dangerous arm — the **host's** counters for any name
that collides. Making the sketch literal needs `unshare(CLONE_NEWNS)` plus a fresh sysfs mount per
read, i.e. new `unsafe` in `net_sys.rs` and a mount namespace on an observation path.

AS BUILT: `net::usage::NetUsageTarget::read` issues one `RTM_GETLINK` for the named interface and
decodes `IFLA_STATS64`, on a netlink socket created **after** the namespace move — a socket's netns
is fixed at `socket()` time, which is `net_sys::setns_net`'s own documented rationale. `IFLA_STATS64`
carries the same `rtnl_link_stats64` struct sysfs renders as text, so nothing is lost. The move goes
through the existing `net::tap::in_netns`; there is no second `setns`.

Do not "fix" this back to sysfs. `net::usage::counter_reader_gate` reddens on a production
`"/sys/class/net` read and on a second `LinkAttribute::Stats64` decode, in both directions.

Also worth folding into the design when it is next reissued: §7.1's and §17's sentences should say
"a netlink `IFLA_STATS64` read inside the VM netns" rather than the sysfs path.

SECOND ENTRY — a scoping deviation, smaller:

### E5: no `MicroVm::net_usage()` convenience method (yet)

The per-VM entry point is `NetUsageTarget::for_vm(vm.netns(), vm.segment_membership())?.read()`.
`orchestrator.rs` was outside this change's file allowlist, so the one-line delegation
`MicroVm::net_usage()` is not there. It is a two-line addition against a law that already exists and
is already gated; adding it is safe and needs no new test beyond routing the live leg through it.


For `docs/implementation-notes.md` (I could not edit docs/**):

**Tier E3+E4 landed (daemon pause/resume routes; streaming artifact upload).** §17's "Pause/resume
routes" and "Streaming upload (v1 reads the file into memory)" are closed; §17 and docs/92's Tier E
list should be rewritten as closed.

E3. `POST /v1/vms/{id}/pause` and `/resume`, added to the ONE `API_ROUTES` table so the router fold
and the served OpenAPI document pick them up by construction (P5). The state machine is
`Registry::drive_vcpus`, one core shared by both verbs through a `VcpuVerb` carrying the three facts
that differ (required state, published state, handle call). It reuses the shapes `exec`/`snapshot`
already had, for the reasons they had them: state checked before queueing on the handle lock (prompt
409), re-checked under it, and the result published only on success and only through
`VmSlot::transition_from`. That helper GENERALIZES the old `leave_snapshotting` — the one-way
`Destroying` door is now one law rather than a snapshot-specific special case, which is what stops a
pause landing behind a parked teardown from re-advertising a doomed VM. Both a runtime gate and a
call-site scan hold it. `snapshot` of a paused VM is refused deliberately: the backend's own snapshot
pauses and RESUMES internally, so allowing it would restart the guest behind the daemon's state.
RECORDED RESIDUAL, at the call site: a backend that pauses the guest and then fails its reply leaves
the daemon reporting `Ready` for a stopped guest. The alternative — recording the state a failed call
asked for — makes the label a wish on every path; the client's remedy is retry or destroy.

E4. The upload streams on both ends. `ArtifactStore::create_streaming` returns an `ArtifactWriter`
fed chunk by chunk; `ArtifactStore::create` is now literally that path with one chunk, so create-only,
atomicity, the digest sidecar, the rollback and the cap are stated once and cannot drift between the
buffered and streamed doors. The handler takes the raw `axum::body::Body` — note that
`DefaultBodyLimit` is an EXTRACTOR-side limit and so does not apply to it; the ceiling is the store's
own `max_bytes` (from `vmcelld --max-artifact-bytes`, default 4 GiB), checked BEFORE each chunk is
written, which bounds the disk as well as the memory. Abandoning a writer publishes nothing because
the name is claimed only by the `persist_noclobber` inside `finish` and the `NamedTempFile` removes
itself on `Drop`; the handler therefore has no cleanup path that could itself be wrong. Client side,
`UploadBody::Path` is `tokio::fs::File` -> `reqwest::Body` (reqwest's `stream` feature), which sends
chunked with no `Content-Length` — that framing difference is the only externally observable
discriminator between reading a file and streaming it, and it is what the client's gate asserts.


For docs/implementation-notes.md (docs are outside my scope; supplied as text):

E1 — structured serial fault capture (panic/oops/KASAN/lockdep → typed Error). Landed. Three judgements are recorded because each is a road not taken:

(a) THE TWO CLASSIFIERS STAY TWO. `vmcell::vmm::fault` (host-side, "did the guest kernel die, and should this lifecycle op say so instead of reporting its own budget") and `vmcell-artifact-validator::classify` (conformance, "which §5.4 artifact contract clause did this boot break") are not merged. Their needle sets are disjoint and the boundary was already drawn in the validator's own source (classify.rs:647 records that it does not claim `Kernel panic` because the host owns it). What WAS folded is the duplicate that existed: `RealSerialLog::contains_panic`'s three inline panic literals now come from `GuestFault::Panic.signatures()`. Any future unification must go validator → vmcell, never back, because that is the only direction the dependency edge allows; the module rustdoc says so, so the next reader does not re-derive it.

(b) ONLY A **STOPPED** KERNEL ABORTS A WAIT; every class RE-LABELS an expiry. `classify_serial_fault` returns a `kind` (the cause, by one precedence list) and a `halted` flag (a panic signature is present) computed INDEPENDENTLY. The connect loop aborts on `halted`, which is byte-for-byte today's fast-fail condition, and relabels on expiry for any class. An oops or a KASAN report therefore does NOT cut a boot short: the kernel keeps running after both, and §5.5 ships KASAN/LOCKDEP kernels deliberately, so aborting on them would fail boots that would have succeeded. Being wrong that way costs a fabricated failure; being conservative costs only latency on a boot that was already going to fail. Do not "tighten" this without measuring.

(c) A HOST PROBLEM MUST NOT BECOME A GUEST-FAULT REPORT, and the mechanism is `RealSerialLog::read()` returning `None` (not `Some("")`) for an absent or unreadable console. Absent evidence and empty evidence mean opposite things — the validator learned the same lesson from the other direction with `BootKind::Restored` — so a wedged `vhost-device-vsock`, a missing socket, or a busy host still reports itself as `Error::Timeout`. The negative controls (`a_real_healthy_boot_is_not_a_guest_fault`, `a_healthy_console_still_reports_the_hosts_own_timeout`, `an_absent_console_is_not_a_guest_fault`) are the load-bearing tests, and the healthy fixture is a REAL captured vmcell boot whose cmdline echo contains `panic=1` — which is what disqualifies the obvious needle by evidence rather than by argument.

GATE DEFECT WORTH REMEMBERING (a new instance of the vacuity class, found by the gate's own self-test): a source-scanning ban that extracts its needles from a Rust const array must JOIN the file before matching. rustfmt decides per-const whether the array fits on one line; the line-at-a-time extractor silently dropped every literal of a collapsed const and then ran past the array picking up unrelated strings, so the gate printed `ok: 11 signatures` while guarding the wrong 11 and letting a real inline `contains("Kernel panic")` through. Both rustfmt shapes plus a decoy literal outside every array are now pinned in the self-test.

STALE COMMENT LEFT BEHIND (validator crate was off-limits to this lane): `crates/vmcell-artifact-validator/src/checks.rs:1177` still says the erofs root-mount panic "surfaces only as \"Panic detected in serial log\"". That string no longer exists; the failure now arrives as `Error::GuestKernelFault` carrying the kernel's own panic line, which the validator still overlays its §5.4 clause on. Comment-only; nothing depends on it.


## Wave 7 — the rest of Tier E

FOR docs/implementation-notes.md (docs/** is off-limits to me — please land this, or hand it to whoever owns the reconciliation):

**§17 Networking / Segment refinements — G4, the 2026-08-21 pass.**

*The typed netem/impairment API (LANDED, with its blocker re-verified).* §17's recorded blocker — "the rtnetlink stack types no netem options" — was checked against the lockfile, not assumed: `netlink-packet-route 0.33.0` types exactly `fq_codel` and `ingress`, and `TcOption::Other(DefaultNla)` is the only remaining door, i.e. precisely the hand-assembled `TcMessage`s the register names. THE BLOCKER STANDS. What shipped is the typed **surface** over the shipped **transport**: `vmcell::net::Impairment` (delay / jitter / whole-percent loss, all validated at construction), `Impairment::netem_args` as the one composer, and `NetSegment::impair_member` / `clear_impairment` running `tc` inside the segment netns via the crate's one `in_netns` setns helper. Recorded deviation from a "typed API" read as "typed transport": the transport is a subprocess, costing a fork/exec per call, an iproute2 dependency (absent `tc` is a typed `CapabilityUnavailable`, never a silent no-op), and stderr diagnostics instead of a kernel errno. `MAX_IMPAIRMENT_DELAY` is 4 s because netem's classic `tc_netem_qopt.latency` is u32 psched ticks (≈4.295 s at 1 ns/tick). The netem argv law is guarded by `scripts/ban-inline-netem-argv.sh`; the two live legs in `tests/segment.rs` are its real call sites. **Still open:** the in-process netlink path, which needs the netem TLVs hand-assembled with `#[repr(C)]` + size asserts and psched scaling — bounded work, but it must be executed live at least once before it can be believed, and this pass had no CAP_NET_ADMIN.

*The ≈254-VM-per-`/16` ceiling (NOT widened — and the register's framing needs a correction).* Two findings make the item worth re-scoping before anyone widens anything:
(1) **The address map is not the binding ceiling.** `MicroVm::start` allocates a guest CID unconditionally and `CidAllocator` is `3..=254`, so **252 concurrent VMs per host** is the real cap — below the map's 254. Widening the `/16` map alone raises the concurrent-VM count by exactly ZERO. §17's Networking entry should say so, or the item reads as higher-value than it is.
(2) **IFNAMSIZ caps any ceiling at four decimal digits.** `<prefix>-tap-<vmid>` at `MAX_RESOURCE_PREFIX_LEN = 6` is `11 + digits` against `IFNAMSIZ - 1 = 15`, so a ceiling above 9999 costs prefix budget or a new tap-name scheme.
What landed instead of a widening: `net::MAX_VMID` names the ceiling once (replacing four inline `254`s); a separate `THIRD_OCTET_SPACE` names the codomain; two `const _: () = assert!(…)` blocks make the bijection precondition a COMPILE error for both the per-VM and the segment map; an exhaustive bijection/disjointness proof; and `the_vmid_ceiling_is_one_law_with_four_other_homes`, the executable roster of the ceiling's five homes. The headroom for a future widening is recorded in-source and is real: each third octet holds 64 disjoint `/30`s (`10.200.<octet>.{0,4,…,252}/30`) of which the map uses one, so a two-dimensional map reaches 16256 — but 3 of the 5 homes must move in the same change, and (1) says the CID space must move first or nothing changes.


FOR docs/implementation-notes.md AND THE DESIGN (all under docs/**, which I may not edit — the parent must land these):

1. RECONCILIATION — §4.5 read-only enforcement, landed. The in-process `fuse-backend-rs` backend enforces read-only through `in_process::backend::ReadOnlyFs`, a `FileSystem`/`BackendFileSystem` decorator that answers `EROFS` to every mutating FUSE operation. The one law is `read_only_disposition`, an exhaustive no-wildcard `match` over `Opcode` (so a dep bump that adds an opcode is a compile error), paired with a source scan requiring the refusal call sites to equal the classification. Bind mounts were rejected: `CAP_SYS_ADMIN` is absent in the unprivileged mode this backend exists to serve, and a mount is namespace-global in a process that is one orchestrator with many shares.

2. THESE THREE DOC STATEMENTS ARE NOW STALE AND MUST BE UPDATED:
   * design §4.5 (line ~1396): "An in-process `fuse-backend-rs` alternative (Appendix B) is gated behind `experiment-fuse`; **it does not enforce read-only, so a read-only share on that backend is rejected fail-loud with a typed `Error::Unsupported`**" — the second clause is now false in the code.
   * design §17 "Storage & shares" (line ~5100): "`fuse-backend-rs` as an in-process share backend ... **must enforce read-only before it can graduate (today a RO share on it is a typed `Unsupported`, §4.5)**" — the blocker is cleared. What remains before graduation is a LIVE recipe, not enforcement (see 4).
   * design Appendix B row 6 (line ~5682): "`virtiofsd` → in-process `fuse-backend-rs` | **underway**, blocked on read-only enforcement before it can graduate (§4.5)" — the recorded blocker is retired.

3. RETIRE workaround-inventory row V1 as EMPIRICALLY DISPROVEN. It records that `--features experiment-fuse` fails to compile because `fuse-backend-rs` 0.14 pins `vm-memory =0.17.1` against the vendored vhost's 0.18. It compiles today: the 2026-08-20 dependency pass held the pins back at =0.16.0/=0.22.0/=0.17.1/0.17.0 for exactly this reason, and `crates/vmcell/Cargo.toml:990-1005` records that decision. AGENTS: "Retire an entry when it is empirically disproven."

4. WHAT STILL BLOCKS GRADUATION, honestly stated: no recipe in the tree selects `experiment-fuse` for a live suite, so no test has ever BOOTED this backend. `test-unprivileged` builds `--features qemu` over the defaults. Enforcement is proven at the layer that decides (real syscalls, real host directory, data-plane before/after, positive controls); the guest-visible half is unproven. Graduating the backend needs a live recipe (`just test-fuse`, opt-in like `test-crosvm`) that boots a cell with a read-only share and asserts an in-guest `write` returns EROFS while a `cat` succeeds. That recipe touches the justfile, which was outside my file set.

5. TWO ADJACENT FINDINGS, NEITHER MINE, NEITHER FIXED:
   * PRODUCT DEFECT (experiment-fuse arm): `VirtioFsDaemon::drop` HANGS FOREVER if no frontend ever connected. `VhostUserDaemon::start` blocks in `accept()` (vendor/vhost-user-backend/src/lib.rs:170-188) and the kill eventfd is only watched by the epoll worker AFTER a connection is accepted; `Drop` then does `h.join()`. So `start_paced()` succeeding followed by a failed VM launch wedges teardown. I hit this live — my first draft of `ro_share_tests` hung at 0% CPU in accept — and worked around it in the TEST by connecting a stand-in frontend and hanging up (which is also a stronger assertion: the daemon really is accepting, not merely holding a bound socket file). No test had ever started an in-process daemon before, which is why nothing had exercised it. The product fix belongs to the teardown owner: the accept needs to be interruptible (non-blocking listener + epoll on the kill eventfd), or the join needs a bound.
   * PRE-EXISTING BUILD BREAK, NOT MINE: `cargo check -p vmcell --no-default-features --features experiment-fuse` fails at `crates/vmcell/src/feature.rs:433` — "use of unresolved module or unlinked crate `tracing`". `feature.rs` is unmodified in the working tree and my code is unreachable in that config (`mod fs` is gated on `host-common`). `cargo hack --feature-powerset --depth 2 -p vmcell` in `just ci` should be hitting this.

6. HOUSEKEEPING: the tree's literal `TODO` count is now ZERO (`grep -rn "TODO" crates/*/src --include=*.rs` returns nothing outside `clippy::todo`/`todo!`). I reworded my own historical references to "deferral marker" so the property holds.

7. PROCESS NOTE: I ran `cargo fmt -p vmcell` twice early on, which formats every file reachable from the crate root — including other agents' in-flight files. rustfmt is idempotent and CI requires it, so this is benign, but it is a file-discipline edge worth knowing. I switched to `rustfmt --edition 2024 <my two files>` for the rest of the pass.


For docs/implementation-notes.md (I did not edit docs/ — it is off-limits for this pass):

**§17 daemon gaps, three closed (periodic sweeper, UDS transport, artifact quota + GC).** Three deliberate shape shifts from the register's sketch, each recorded because a later reader will otherwise re-open them:

1. *The periodic sweep DEFERS rather than sweeping with a best-effort live set.* §17 asks only for "a fully-automatic periodic orphan sweeper". The liveness-aware `may_reclaim` that landed this pass covers cross-process siblings, but `vmcell` records at `IdClaim` that it covers nothing for a hermetic allocator, and it cannot cover this process's own in-flight `create` in any allocator-independent way. So the registry counts launches in flight and a pass that starts inside that window is skipped whole. Cost: one cadence of retained residue. Alternative rejected: sweeping with the incomplete set, which reaps a booting VM's netns.

2. *The artifact GC is start-up-only and collects ONLY daemon-owned residue.* §17 says "Artifact GC / quota" without naming a policy. The policy chosen: client artifacts are never collected (the daemon cannot distinguish a stale kernel from one a nightly job boots), so a full store refuses loudly instead of evicting; and the only collectable classes are the two that are provably the daemon's own crash residue. Because neither class can be a valid artifact name, the pass needs no consultation of the VM-table pins — that is a structural argument, gated, not a lock. The §11.3 delete-in-use residual is therefore untouched and unaffected by this pass.

3. *The quota gates the START of a snapshot, not its size.* A snapshot's size is unknowable in advance and refusing mid-write would leave a partial prefix (which §11.3 deliberately keeps for diagnosis). Both writers ask the one predicate; the accepted, recorded consequence is that a snapshot may carry the store past its quota by one snapshot, after which every further write is refused. Recorded alongside: two uploads opened concurrently each see the same headroom, so together they can overshoot by the smaller of the two — bounded, non-destructive, visible in `GET /v1/store`, and cheaper than a reservation table the single-tenant model does not earn.

Also worth recording: the UDS auth decision (the API key is required on the socket; 0700/0600 are defence in depth under it, never a substitute) belongs in §11.6's neighbourhood, and the reasoning is written out in `vmcell_daemon::uds`'s module rustdoc so it does not have to be re-derived.


For `docs/implementation-notes.md` (docs/** is off-limits to me — please land this):

**G2 — §6.4's two recorded gaps close; the transparent path no longer only *constrains* egress.** Design §6.4 documents the transparent redirect of raw 80/443 as "observe/filter the destination" and cassettes as §17 forward work. Both statements are now false and the design body should be reissued, not errata'd. What landed: `proxy::transparent::serve_intake` sits in front of hudsucker for BOTH `start` and `start_transparent`, classifies each connection on its first byte, and recovers the destination — the `Host` header for an origin-form request, the ClientHello's SNI for raw TLS (handed on behind a synthesized `CONNECT`, the explicit-proxy intake hudsucker does understand). Two consequences worth recording beyond "it works": (1) the deny list now applies to transparent traffic, which it structurally could not before — `is_blocked` had no host to test on an origin-form request — so this was a security gap wearing a feature-gap's label; (2) the privileged suite's `egress_privileged_filtered` had an assertion (`!stdout.starts_with("MITM SUCCESS!")`) whose whole content was the limitation, so the fix and the test inverted together. That leg is UNRUN by the change that wrote it (no blessed runner) and needs a privileged run.

**Two boundaries kept rather than papered over.** A ClientHello split across TLS records, or larger than `MAX_INTAKE_PREFIX_BYTES` (8 KiB), is refused and logged `TRANSPARENT REFUSED` — never guessed at, because a guessed authority means minting a certificate for a host the guest never named. And a TLS intake with no SNI falls back to the kernel-preserved original destination only where there is one (TPROXY); under the unprivileged NAT the socket's local address is the proxy's own loopback port, so there is nothing to fall back to and the connection is refused.

**A cassette is a persisted artifact, so the key is the secrets boundary.** `interaction_key` is method + canonical absolute URI and nothing else: no request header, no request body. That single choice answers both design questions at once — determinism (a nonce/`Date`/`Authorization` cannot make replay miss) and hygiene (a credential cannot reach the file). Repeated calls under one key replay in recorded ORDER, which is what body-matching would otherwise have been for. Query params in `REDACTED_QUERY_PARAMS` drop out of the key entirely; response headers are allowlisted to `content-type`. The one hole is stated in the module docs rather than implied: a secret in a URI *path* is not redacted, because no general rule tells a secret path segment from a resource id.

**One implementation note a future reader will want.** The new stages compose AROUND `ProxyHandler` (`proxy::handler::EgressHandler`) instead of adding fields to it. That is not aesthetics: `ProxyHandler` is public with all-public fields, so ANY added field is `constructible_struct_adds_field` — a major break, which at 0.x means 0.24.0, which would strand fourteen sibling manifests pinning `^0.23.0`. The wrapper also buys the ordering (reconstruct → deny-list/doubles → cassette) explicitly instead of by statement order inside one function.

**A rustdoc trap, recorded because it cost a debugging cycle.** Writing an outer `///` doc on a `pub mod foo;` declaration whose file also has `//!` inner docs moves the *inner* docs' intra-doc link resolution into the PARENT module's scope: every `[`ItemInThisModule`]` link in `cassette.rs` failed with "no item named … in scope" until the outer doc was removed. `doubles`/`tls` survive it only because their inner links are fully qualified or name extern crates.


Two findings worth carrying forward, both discovered by trying to break my own gates:

1. A fixture that cannot tell a half-close from a close makes the whole `EndOfStream` battery decorative. My bridge's first `saw_eof` flag was set on any `read()==0`, which also happens when the relay is torn down at end of connection — so the `ForwardHalfClose` leg PASSED against a build whose `ForwardHalfClose` arm did nothing. The fix is a probe write after EOF (AF_UNIX: succeeds after the peer's SHUT_WR, EPIPE after its close). Any future fixture asserting about half-close needs that discrimination.

2. rustdoc resolves a module's intra-doc links in TWO scopes if the module has both an outer `///` doc on `pub mod x;` and inner `//!` docs in `x.rs` — the failures surface as "unresolved link" with the CRATE ROOT's span (lib.rs:150, the deny attribute), naming no file. Keep module docs in one place; `steward/mod.rs` now carries a plain `//` comment saying so.

Also recorded in-code: the pump's count law needs an ASYMMETRIC test pipe (roomy source, tiny sink). My first cut used 64 bytes on both sides, which made every read exactly 64 bytes and every write whole — and BOTH count inverses passed against it. That note is in the test's own comment so the next person does not re-introduce the symmetric shape.


## Wave 8 — the two Tier E items that were blocked on scope

For `docs/implementation-notes.md` (docs/** is forbidden to me — hand this to whoever owns the reconciliation):

**H2 — the ≈254-VM-per-/16 ceiling is retired; §17's Networking entry should be struck.** The concurrent-VM ceiling per host moved 252 -> 9999. Recorded specifics a future pass must not "fix":

1. **The order was load-bearing.** The binding ceiling was NOT the address map. `CidAllocator` was `3..=254` = 252 CIDs, and `MicroVm::start` allocates one unconditionally, so the CID space bound the host a notch BELOW the map's own 254. Widening the /16 first would have raised the concurrent-VM count by exactly zero. `vmm::MAX_GUEST_CID` is now DERIVED from `net::MAX_VMID`; do not re-literalise it.

2. **The map is a strict superset, not a renumbering.** `sub = (vmid-1)/254`, `base = 4*sub`. For every vmid in 1..=254 `sub` is 0 and the addresses are byte-identical to the pre-widening map, so design §9.3's statement, every pinned golden, and every already-running host stay true. `the_widened_map_agrees_with_the_one_dimensional_map_it_replaced` is the gate, and it deliberately contains the ONLY sanctioned second copy of the old formula in the tree — the property under test is equality with a formula production no longer has.

3. **9999 is the IFNAMSIZ ceiling, not a round number.** `<prefix>-tap-<vmid>` at `MAX_RESOURCE_PREFIX_LEN = 6` is exactly 15 bytes = `IFNAMSIZ - 1` at four digits — zero slack. A fifth digit costs prefix budget or a new tap-name scheme. Two `const` asserts hold it: the codomain bound (254 x 64 = 16256, so the address space is NOT what stops the next widening) and the four-digit bound. `naming::MAX_RESOURCE_PREFIX_LEN`'s rustdoc was rewritten from "6 lands on 14, one byte inside the limit" to record the new zero-slack situation.

4. **The roster found a SIXTH home the prior analysis missed** — `config::VmConfigBuilder::build`'s `vmid > 254`, on the caller-pinned-vmid path. It refused loudly rather than wrapping, so it was never a data-plane defect, which is precisely why five review passes walked past it. It is now home 6 with its own roster leg.

5. **`CidAllocator` gained a search hint** (`CidPool { active, next_free }`, invariant: every CID below `next_free` is live). Not a micro-optimisation — a rescan-from-`MIN_GUEST_CID` per call is quadratic at 10^4 wide, and filling the pool is what the exhaustion gates do. `release` restores the invariant; skipping that restore leaks the freed CID and reddens four tests. `VmidAllocator::allocate` needed no such change: `seeded_id_order` re-seeds from the clock per call, so the expected contiguous run is short (n·H_n total, ~92K steps for a full drain) rather than quadratic — measured, not assumed.

6. **`orchestrator::segment_id_search_start_is_clock_seeded_like_the_vmid_search` was rewritten, not just renumbered.** It used to assert the vmid and segid allocators return the SAME first id, which only ever held because both spaces were 254 wide. They now differ by a decimal digit. The shared law is asserted where it actually lives: each allocator's first id equals `seeded_id_order`'s first id over that allocator's OWN ceiling. Do not restore the equality form.

7. `vmcell::vmm::{MIN_GUEST_CID, MAX_GUEST_CID}` are new public consts; not on the §10.4 contract surface, no ledgered bump taken (see `ledger_touched`).


FOR docs/implementation-notes.md (I could not write it — docs/** is off-limits in my brief). Suggested entry:

"H1, copy-on-attach writable scratch disks (landed). The daemon's read-only-extra-disk limitation is retired; §11.5's and §17's records of it, and AGENTS.md's 'Daemon extra disks are read-only (recorded, don't re-flag)', are now stale and must be rewritten to the copy-on-attach rule: the client asks with `ExtraDiskSpec.writable`, the STORE ARTIFACT IS STILL NEVER ATTACHED WRITABLE, and what the guest gets is a private per-VM copy made through `OverlayStore::clone_file` and deleted with the VM.

Two recorded deviations from the sketched design worth carrying:
(a) `OverlayStore::clone_file` ships with a DEFAULT body (a typed `CapabilityUnavailable`) rather than as a required method. Not a softening of S4 — the refusal is what forbids an injected store from having a host-filesystem copy improvised behind its back — but a deliberate consequence of the pin arithmetic: a required method forces 0.24.0 and strands fourteen `^0.23.0` sibling requirements.
(b) The per-VM copies live under `<artifacts-dir>/.vmcell-scratch/`, inside the store directory, NOT under `$XDG_RUNTIME_DIR`. Reflink is filesystem-local, so any other location makes every writable disk a full byte copy — and on tmpfs, a copy in RAM. The leading `.` makes the directory unnameable by `validate_artifact_name` on every verb. `ArtifactStore::usage` skips it, with the trade-off stated at both ends: those bytes are real and NOT counted, so `--max-store-bytes` bounds uploads only and an operator provisions quota + (concurrent cells × their writable disks). A per-VM or per-daemon writable-disk ceiling is the obvious next knob and is NOT shipped.

Open for a future pass: these copies are keyed on the daemon's pid (they are minted before the VM has a vmid), so `vmcell::orchestrator::sweep_orphans` structurally cannot see them; `scratch::reclaim_orphan_scratch` is their start-up counterpart and is retain-on-doubt — a recycled pid that now belongs to another process leaves a bounded leak rather than risking a live daemon's copies."
