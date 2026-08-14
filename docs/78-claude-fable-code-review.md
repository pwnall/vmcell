# vmcell — Code Review (docs/78)

A comprehensive review of the tree at `main` @ `5bda3c0` (`vmcell` 0.13.0 — the landed v30
delta-register pass), against design v30 (`docs/74`), rubric v6 (`docs/75`), quality gates v4
(`docs/76`), `AGENTS.md`, and `docs/implementation-notes.md`. Dated 2026-08-13.

**Method.** Twelve independent area reviews (core config, orchestrator/teardown, net, vmm/jail/CH,
agent/protocol/guest, secondary backends, artifact pipeline, daemon tier, validator/bench/example,
gates/CI/scripts, docs accuracy, extension points), every finding then adversarially re-traced by a
separate verifier against the shipped code and the recorded-deviation ledger. 93 findings were
verified — 83 confirmed, 9 adjusted, 1 already-recorded, none refuted — spanning 1 blocking, 15
major, 45 minor, and 32 note; items already recorded in implementation-notes or design §17 were
excluded up front. Where a finding corrects a recorded
implementation-notes entry, the correction has been applied to that file in this pass (§10).

**Live validation (AGENTS rule 5 — executed, not presumed).** Preflight printed READY; every suite
was run on this host during the review:

| Gate | Result |
|---|---|
| `just ci` | green (482 s, incl. the 221-config feature powerset) |
| `just test-privileged` (delegated scope) | **144/144**, 5 capability skips, 279 s, no retries consumed |
| `just test-unprivileged` | 4/4 |
| `just test-daemon` | 12/12 |
| `just test-crosvm` (delegated scope) | **28/28** |
| Skip manifest | 14 records, all honest capability absences (FC/crosvm `nested_virt` / `unprivileged_vhost_user_net` / `virtio_fs_shares`, crosvm `disk_io_throttle`, QEMU `usb_host_passthrough_no_designated_device`) |

**Verdict.** The v30 landing is in strong shape: every delta is implemented with its gate, the live
matrix is green, and the one-law/teardown/capability-honesty disciplines hold almost everywhere they
are claimed (§11). The defects that matter cluster in exactly the places the project's own doctrine
predicts: paths the suite structurally cannot reach (the guest→host NAT direction, FC's post-restore
data plane, restore-boundary re-checks), gates that cannot go red (crosvm's only confinement, QEMU's
`-sandbox` splice, P2's cap-drop), and recorded reconciliations that drifted from the tree (three
implementation-notes entries were empirically false). One finding is blocking (§1).

---

## 1. Blocking

### B1 — The guest→host NAT pump panics on a wrap-crossing transfer, silently wedging the link
`crates/vmcell/src/net/smoltcp.rs:1049` · correctness · *(finding `nat-guest-to-host-wrap-panic`)*

The guest→host drain pairs `socket.peek_slice(&mut buf)` with `socket.recv(|_| (written, ()))`. In
smoltcp 0.13.1, `peek_slice` performs a **two-part copy that crosses the RX ring wrap** (so `n` can
exceed the contiguous span), while `recv` → `dequeue_many_with` computes
`max_size = min(len, capacity − read_at)` — the contiguous span only — and `assert!(size <= max_size)`
(a real assert). On any sustained >64 KiB guest→host stream, the tick where queued data straddles the
65536-byte ring boundary returns a `written` larger than the contiguous span and trips the assert.
The panic kills only the `run_network` thread; the vhost thread survives, so the device stays
attached while zero packets flow — the exact silent-wedge class design §6.2's five invariants exist
to prevent, on a line whose own comment reads "NET-1/C2: guest-driven; never panic." Reachable from
any unprivileged VM doing a large upload (a `host_services_port` POST, a body through the Filtered
egress proxy).

**Fix:** consume only the contiguous span — do the write inside the `recv` closure (or peek via the
contiguous `peek(n)` slice) so `written ≤ max_size` by construction; the wrapped remainder drains on
the next tick with no data loss. **Land with M13 (§4)** — the guest→host window-filling gate — so
re-introducing `peek_slice` goes red (non-negotiable rule 1). The suite never saw this because no
test moves >~1 KiB guest→host through the NAT (the M5a window gate is host→guest only).

---

## 2. Major — correctness

### M1 — FC restore re-binds the baked tap name: post-restore egress is silently dead
`crates/vmcell-firecracker/src/lib.rs:873` · *(`fc-restore-rebinds-baked-tap-name-dead-data-plane`)*

FC's `SnapshotLoad` body carries only `snapshot_path`/`mem_backend`/`resume_vm` — no
`network_overrides`, and `res.tap_name` is never referenced on the restore path — so Firecracker
re-opens the snapshot's baked `host_dev_name` (`vmcell-tap-<oldvmid>`). The orchestrator meanwhile
allocates a fresh vmid and plumbs `vmcell-tap-<newvmid>` in the new netns. Under the runner's ambient
`CAP_NET_ADMIN`, `TUNSETIFF` on the old name silently **creates a fresh, down, unbridged tap**, so
restore succeeds (which is why the live leg is green — the project's own v24 record of `tap-open (FC)
EPERM` during restore proves this re-open happens), the guest's resync rotates its IP/route onto the
new /30, and every post-restore packet drops into an unplumbed orphan tap. No test can see it:
`snapshot_restore.rs` asserts `/proc/net/route` text over vsock, and the egress probes self-skip FC.
Design §8.2 names the `net[].tap` rewrite for CH only; §2.3's three FC restore accommodations cover
agent-client/vsock/entropy — the tap was missed.

**Fix:** add FC 1.8+'s `network_overrides: [{iface_id: "eth0", host_dev_name: res.tap_name}]` to the
snapshot-load DTO (populated only when `res.tap_name` is Some); this does **not** flip
`restore_rotates_host_paths` (the vsock UDS stays baked-verbatim; scope the flag's comment to
vsock/serial). Gate: a post-restore **data-plane egress byte** leg in the snapshot battery, run
across the snapshot matrix (it also retro-covers CH's rewrite), red on today's FC behavior. Verify
crosvm's congruence rather than assuming it (its `run --restore` re-passes `--net tap-name=` from the
fresh `res`, so it is likely already correct).

### M2 — Custom-init configs slip every restore/zygote eligibility boundary
`crates/vmcell/src/orchestrator.rs:1301` · *(`custom-init-slips-restore-and-zygote-eligibility`)*

`build()` rejects `init` + `snapshotting`, but nothing rejects **restoring** a custom-init config:
`restore_inner`'s boundary-2 re-checks (Unprivileged/Segment/shares) and `check_clone_eligible`
never test `cfg.init`, and `MicroVm::snapshot()` itself has no snapshotting/custom-init guard. So a
custom-init VM can be snapshotted and restored/fanned-out, producing clones whose **mandatory S2
resync is structurally unreachable** (no agent): frozen clock, correlated CSPRNG, stale MAC/IP —
silently, with no typed refusal. **Fix:** add a `cfg.init.is_some()` arm to the shared config-only
eligibility predicate (see S1 in §8 — `restore_inner` currently duplicates the arms), with
red-on-inverse tests at both boundaries.

### M3 — `vmcell build --kernel-source in-vm` structurally cannot succeed
`crates/vmcell-cli/src/main.rs:395` · *(`build-in-vm-seed-never-staged`)*

The recorded delta-3 fix ("the CLI prepends `PrebuiltKernelStage` when the in-VM producer is
selected") was applied only to the `BuildKernels` arm. `Commands::Build` wires `InVmKernelStage`
with no seed stage, and the stage reads its seed from the pipeline **artifact map**, not the disk —
so the flag's documented value is accepted and can never be honored, even after the operator follows
the error's own remedial advice. **Fix:** make Build + in-vm a typed refusal naming the working
route (`build-kernels --kernel-source in-vm`) — do *not* copy the seed staging into Build: the
unlabelled in-VM stage shares `out_path`/`name()` with the seed stage, so their sidecar keys would
alternate and every `vmcell build` would re-run the up-to-2 h compile. Scope the delta-3 notes
sentence accordingly (done in this pass, §10).

### M4 — USB (and other create-only inputs) reach `restore()` unguarded; the recorded premise was false
`crates/vmcell-qemu/src/lib.rs:1278`, `crates/vmcell/src/vmm/cloud_hypervisor.rs:642` ·
*(`restore-paths-accept-inputs-create-rejects-recorded-premise-false`, `ch-restore-silently-drops-usb-request`)*

The delta-9 record's rationale — "every backend's `restore()` rejects a non-snapshotting config, so
USB cannot reach it" — is false by inspection: **no** backend's `restore()` reads
`cfg.snapshotting`. A `{VsockTransport::InKernel, snapshotting: false}` config carrying USB devices
builds (only `snapshotting`+USB is rejected), passes QEMU's restore gate
(`uses_in_kernel_vsock`), and is spawned with the USB argv **without** the `require_usb_host_devices`
precheck — the measured silent-empty-xhci failure mode the precheck exists to prevent. On
CH/FC/crosvm the accepted `usb_host_devices` are silently dropped instead of typed-refused (and
crosvm's restore also silently drops `io_limit`, which its create rejects). **Fix:** reject non-empty
`usb_host_devices` at the one orchestrator boundary (`restore_inner`, beside the existing
Unprivileged/Segment/shares re-checks), plus crosvm's `io_limit` restore rejection mirroring its
create; KVM-free red-on-inverse gate over the `InKernel`+non-snapshotting+USB combination. The notes
entry is corrected in this pass (§10).

---

## 3. Major — reliability

### M5 — `SessionMux::open` after reader exit returns a session that hangs forever
`crates/vmcell/src/agent/session.rs:223` · *(`sessionmux-open-after-reader-exit-hangs`)*

`reader_task`'s only teardown is its terminal registry `clear()`; `open()` afterwards inserts a
fresh sender into the abandoned registry and the write still enqueues (the writer dies only on its
*next* transport failure), so `recv()`/`wait()` pend forever with no timeout and no error — despite
the doc contract "Returns `Error::Agent` if the underlying connection has already closed." **Fix:**
make the registry closable in one critical section (`Option<HashMap<..>>` taken to `None` by the
reader's terminal step); `open()` on `None` is the documented typed error. KVM-free red-on-inverse
gate: peer-close (and garbage-frame) then `open()` must be `Err`.

### M6 — A session child that stops reading stdin wedges the guest's whole connection
`crates/vmcell-guest-agent/src/main.rs:1673` · *(`guest-dispatch-blocking-stdin-wedge`)*

The dispatch loop performs session stdin writes inline and blocking (`write_all`, no `O_NONBLOCK`,
no writer thread). A full 64 KiB pipe (or PTY buffer) blocks the connection thread: `CloseSession`
is never dispatched and — worse — on host disconnect `serve_loop` never returns, so
`teardown_sessions` (the C3 kill-every-pgroup law) never runs; the child outlives its connection.
**Fix:** a per-session stdin writer thread fed by a channel (unbounded is consistent with the
recorded host-trusted trade; silent-drop is not acceptable), with `StdinEof` sequenced through the
same queue so buffered bytes are not truncated. Gate: a KVM session leg that floods >64 KiB at a
non-reading child, then asserts `close()` still yields `SessionExit` and the C3 pgroup residue leg
under stdin pressure.

### M7 — QEMU's migration budget does not bound wedged QMP I/O
`crates/vmcell-qemu/src/lib.rs:316` · *(`qemu-migration-budget-does-not-bound-wedged-qmp-io`)*

`MIGRATION_BUDGET` is checked only between poll iterations; the connect, handshake reads, every
`write_all` and `read_qmp_result` are unbounded. A QEMU that stops answering QMP (wedged main loop,
stalled snapshot filesystem) hangs `snapshot()`/`restore()` forever — the exact wedge the const's
own doc claims it converts into a typed error (contrast `qmp_command`, which timeout-wraps its whole
body). **Fix:** wrap the entire `drive_migration` body in `timeout_at(deadline, …)`, mapping elapse
to the existing typed error; KVM-free gate over a fake QMP server that goes silent after `migrate`.

### M8 — A broker reply that fails to serialize or exceeds the frame cap wedges the request forever
`crates/vmcell-daemon/src/bridge.rs:303` · *(`bridge-reply-drop-wedges-request`)*

`serve_engine` drops a `to_vec` failure or an over-`MAX_BRIDGE_FRAME_BYTES` `write_frame` error with
a comment-less `let _`, and the parent's `rx.await` has no timeout — so the HTTP request hangs
indefinitely. Reachable: exec stdout accumulates across frames host-side, so a guest command
emitting ≳192 MiB produces a base64+JSON reply frame over the 256 MiB cap. **Fix:** on either
failure, log and send a compact fallback `EngineReply::Err` frame for the same id (its own write can
only fail on a dead socket, where dropping is fine — annotate that residual `let _`). Gate: an
over-cap exec reply must surface `DaemonError::Internal` instead of hanging. Capping exec capture
host-side is a recorded follow-up, not part of this fix.

### M9 — Ctrl-C kills the broker child at default disposition, orphaning live VMMs
`crates/vmcelld/src/main.rs:169` · *(`broker-child-dies-to-terminal-signals-orphaning-vms`)*

Only the HTTP parent installs a signal handler; the forked cap-holding broker child stays in the
foreground process group with SIGINT/SIGTERM at `SIG_DFL`. A terminal Ctrl-C kills the child (its
registry `Drop` never runs) before the parent's graceful `ShutdownAll` can arrive; the CH VMMs sit
in their own process groups with no PDEATHSIG, so they survive as orphans pinning guest RAM and
`/dev/kvm` — and the *next* boot's sweep deletes their netns/cgroup/scratch out from under the
still-running processes. **Fix:** SIG_IGN INT/TERM in the child arm before the runtime is built
(PDEATHSIG + ShutdownAll/EOF already govern its lifetime), and reset to SIG_DFL in `build_vmm_cmd`'s
`pre_exec` so spawned VMMs keep normal behavior. Gate: a pgroup-delivery leg in the daemon harness
(SIGINT to the group, then zero surviving `cloud-hypervisor` processes).

---

## 4. Major — gates that cannot go red

Load-bearing properties whose stated gate cannot fail (non-negotiable rule 2):

- **M10 — crosvm's only confinement has no gate.** `crates/vmcell-crosvm/src/lib.rs:353`
  *(`crosvm-layer2-denylist-wiring-has-no-gate`)*. The `Enforcing` → Layer-2 deny-list flip in
  `Crosvm::spawn` is crosvm's sole seccomp confinement (it always runs `--disable-sandbox`), and
  deleting it leaves every KVM-free gate *and* the whole live `test-crosvm` matrix green.
  **Fix:** extract a pure `effective_jail_config(cfg)` and pin both directions KVM-free.
- **M11 — QEMU's `-sandbox` splice is unasserted on the composed argv.**
  `crates/vmcell-qemu/src/lib.rs:927` *(`qemu-sandbox-splice-not-asserted-on-composed-argv`)*.
  Deleting `cmd.args(&seccomp_args)` leaves everything green while QEMU runs unconfined — the exact
  fragment-vs-composed hole the delta-9 pass documented and fixed for USB, still open for the
  sandbox flag. **Fix:** a `windows(2)` contiguous-pair assertion on `composed_argv` for Enforcing,
  and a no-`-sandbox`-token assertion for Disabled.
- **M12 — P2's "serving parent cap-dropped" is never asserted.**
  `crates/vmcelld/tests/integration.rs:57` *(`p2-parent-capless-has-no-red-able-gate`)*. No test
  reads the spawned parent's `/proc/<pid>/status`; removing `apply_broker_parent_drop` keeps 12/12
  green. **Fix:** assert CapEff/CapPrm/CapInh/CapAmb all zero + NoNewPrivs 1 on the parent (not
  CapBnd — the warned no-op is recorded), with the broker child's retained caps as the positive
  control.
- **M13 — no guest→host window-filling NAT gate.** `crates/vmcell/tests/nat_window_fill.rs:19`
  *(`nat-no-guest-to-host-window-gate`)*. The M5a gate is host→guest only; nothing moves >64 KiB
  guest→host, which is why B1 shipped. **Fix:** a live upload leg (digest-compared, with a
  backpressuring host server so partial `try_write` returns occur) plus a pure unit pin that the
  consumed amount equals the partial write.
- **M14 — CI's unprivileged suite drops `--features qemu`.** `.github/workflows/ci.yml:247`
  *(`ci-unprivileged-suite-drops-qemu-feature`)*. The KVM job's raw cargo step omits the feature the
  justfile recipe passes, so the QEMU smoltcp-NAT leg is never even compiled in CI — an invisible
  coverage loss (no skip recorded; the tests don't exist in the binary), on exactly the path the
  vendored vhost patch exists for. **Fix:** replace the raw step with `run: just test-unprivileged`
  (the job already installs and uses `just` elsewhere) — local ≡ CI by construction.
- **M15 — the jail deny-list diverges from the design roster, and its "exactly the documented set"
  test pins the divergent copy.** `crates/vmcell/src/vmm/jail.rs:39`
  *(`deny-list-diverges-from-design-roster`)*. `DENIED_SYSCALLS` omits `process_vm_readv` (in the
  §12.3 roster across v28/v29/v30 — the read-half of the attach-to-another-process primitive, left
  open on the crosvm Enforcing path where this list is the only confinement) and adds three
  undocumented entries (`reboot`, `swapon`, `swapoff`). **Fix:** add `process_vm_readv` (+ the test
  entry); keep the three carry-overs and record them (this pass records the deviation, §10; fold
  into §12.3 at v31). The next `test-crosvm` run doubles as the live validation of the widened
  filter.

---

## 5. Deviations from design/notes to fix (minor)

| Finding | Where | What / fix |
|---|---|---|
| `virtiofsd-socket-wait-hardcoded-cadence` | `fs.rs:144` | `VirtioFsDaemon::start` polls on a hard-coded 50×20 ms grid, contradicting §9.4's "`api_socket_poll` paces **every** readiness wait", and hand-copies `wait_for_socket`'s loop. Thread the pacing through `vmm::wait_for_socket` (keeping the stderr-log + kill/reap wrapper) — or scope §9.4's "every" and record the exception. |
| `allow-unauthenticated-not-logged-per-request` | `vmcell-daemon/src/auth.rs:89` | §11.6, P4's rubric text, and the rustdoc all say the dev flag is "logged loudly at every request"; only a one-time startup warn exists. Add the per-request warn in `server.rs`'s auth layer (keep `authorize` pure) — or change all three doc sites and record. |
| `broker-parent-bounding-drop-failure-is-silent` | `vmcell-privilege/src/lib.rs:444` | §12.4 and notes (j) say the failed bounding shrink is *warned*; the code discards every failure silently. Mirror the sibling `apply_privilege_transition`'s counted one-shot eprintln. |
| `snapshot-prefix-silent-reuse` | `vmcell-daemon/src/registry.rs:297` | A second snapshot to an existing prefix writes into the populated dir — a silent overwrite in a create-only store (§11.3), and a racing `restore_from` copy can read a torn mix. Reject an existing prefix with 409; note `delete()` cannot currently free a snapshot dir (`is_file` check), so the same change must extend delete or record one-shot prefixes. |
| `ci-yml-missing-lean-privilege-gate` | `ci.yml:88` | `just ci` runs the `vmcell-privilege` tree-ban + standalone clippy; CI never has (the ban is only caught transitively/misattributed via the runner edge, and the standalone clippy not at all). Mirror the two steps into the lint job. |

## 6. Fail-loud, one-law, and boundary violations (minor)

**Accepted inputs not honored-or-rejected:**

| Finding | Where | What / fix |
|---|---|---|
| `f3-alias-clobber-gap` | `config.rs:455` | F3 blocks key-equal collisions only; `rw` inverts the owned `ro` (a Block root mounts read-write, journal replay suppressed by `rootflags=noload`), `quiet`/`debug`/`ignore_loglevel` override `loglevel=`. Add the four alias keys to `RESERVED_CMDLINE_KEYS` with the at-site rationale (the coverage gate structurally cannot discover aliases) + negative tests. |
| `rootfs-image-escapes-boundary-validation` | `config.rs:1614` | The duplicate-backing-file guard covers extra-disk-vs-extra-disk only: an extra disk sharing the Block rootfs image builds — the exact two-attachments corruption the guard's comment names — and rootfs image/overlay paths skip the empty/relative checks every other path input gets. Seed the duplicate set with the effective root path; validate the rootfs paths. |
| `sanitized-label-collision-unrejected` | `artifact/mod.rs:1004` | `6.12.94` and `6-12-94` sanitize to one filename; nothing rejects the collision — silent overwrite of vmlinux + both sidecars, and a permanently ping-ponging warm cache. Reject in `resolve_kernel_registry` naming both labels. |
| `share-tag-path-separator-escapes-scratch-dir` | `fs.rs:45`, `config.rs:1558` | Share tags are validated only against `:`/whitespace/empty/dup; a tag with `/` (`../../…`) makes `fs.rs` create/truncate a caller-chosen file **outside** the scratch dir, unswept. Require exactly one `Component::Normal`. |
| `sidecar-suffix-guard-is-create-only` | `vmcell-daemon/src/artifact_store.rs:172` | `.sha256` is reserved only in `create()`; `info()`/`delete()` accept sidecar names, so a client can GET or DELETE an artifact's internal digest sidecar. Reject with 404 in both. |
| `bench-ignores-contract-bin-resolvers` | `vmcell-bench/src/bin/bench-vm.rs:480` | bench-vm hardcodes the four binary names and ignores the §10.4-contract `VMCELL_*_BIN` resolvers — `perf-matrix.sh:12` even (wrongly) documents `$VMCELL_CROSVM_BIN` as working. Route through the validator harness getters it already links. |
| `curl-shim-silently-ignores-unknown-flags` | `vmcell-guest-tools/src/main.rs:850` | The curl applet ignores unknown flags, garbage `--max-time`, and `-o` — a test invoking a real-curl feature silently loses its property (the `-k`-class hazard one step removed). Exit 2 naming the offender (rejection *is* the faithful emulation); honor or reject `-o`. |

**Silently discarded Results / missing helper-daemon discipline:**

| Finding | Where | What / fix |
|---|---|---|
| `kernel-workdir-purge-swallowed` | `artifact/kernel.rs:495` | The stale-tree purge is `let _ =` — a failed purge leaves `Makefile`, extraction is skipped, and a bumped pin compiles the **old** source tree under the new cache identity. Ignore only `NotFound`; same at `:572`. |
| `teardown-cgroup-delete-silently-discarded` | `orchestrator.rs:1736` | The success-path `delete_slice` discard is the one teardown site with no log (every sibling warns); `FsIdClaim::release`'s discard can wedge an id for the process lifetime. Warn (or comment the deliberate silence). |
| `virtiofsd-missing-pdeathsig` | `fs.rs:108` | virtiofsd's `pre_exec` sets only `setpgid` — no `PR_SET_PDEATHSIG(SIGKILL)` per the AGENTS helper-daemon rule; a SIGKILLed orchestrator leaks a live daemon holding the shared dir (the sweep reclaims directories, never processes). Add the prctl; the QEMU helper daemons and the smoltcp process lack it too — fix or record the class. |
| `usage-readable-swallows-agent-handshake` | `vmcell-artifact-validator/src/checks.rs:866` | The one member of the recorded 11-site `let _` cluster that is **not** best-effort teardown: a failed agent handshake is discarded and `metrics.usage_readable` passes on a guest that never booted. Route through `explain_boot_failure_at` like every sibling arm. (Cluster record corrected, §10.) |
| `cache-sidecar-serialize-silently-dropped` | `artifact/mod.rs:1509` | A `to_string(&metadata)` failure writes no sidecar and logs nothing → a permanent, undiagnosed cache miss re-running the expensive stage every build. Add the Err arm's warn. |
| `apply-jail-error-path-allocates-post-fork` | `vmm/jail.rs:240` | The seccomp arm's error path calls `format!` in the forked child, violating the module's own no-allocation contract — a child that races the allocator lock deadlocks and `create()` hangs. Use `from_raw_os_error` (note: `io::Error::new` also allocates). |
| `failed-create-slice-leaves-partial-cgroup-dir` | `metrics.rs:404` | A mid-sequence limit failure leaves a partially-configured cgroup dir (the guard arms only after `Ok`); `FakeCgroupFs` is structurally blind to it. Best-effort `remove_dir` of the just-created leaf on error + a real-fs red-on-inverse test. |
| `uncapped-frame-debug-renders` | `vmcell-guest-agent/src/main.rs:866` (+ host `agent/mod.rs:933`, `session.rs:450`) | Three desync log sites render whole frames `{:?}` uncapped — the guest one can print ~16 MiB onto the persisted serial artifact. Share `capped_debug` (host it beside `MAX_FRAME_BYTES` in vmcell-protocol). |

**One-law second copies:**

| Finding | Where | What / fix |
|---|---|---|
| `ifreq-stack-duplicated-guest-tools` | `vmcell-guest-tools/src/main.rs:665` | A full second copy of the kernel-ABI `IfReq` + link-ioctl stack beside the agent's audited `netif` module (already diverged in error type), against "kernel ABI structs defined once", unrecorded. Consolidate via the agent's lib target — or record the deviation with the two size-pin tests as the divergence guard. |
| `qemu-crosvm-snapshot-restore-missing-capability-selfguard` | `vmcell-crosvm/src/lib.rs:124`, QEMU | CH and FC self-guard `snapshot()`/`restore()` on `capabilities().snapshot_restore` (rubric B3); QEMU and crosvm never do — and crosvm's rustdoc claims they do. Factor the CH shape with the false-branch unit test. |
| `test-local-scratch-name-format` | `tests/snapshot_restore.rs:329` (+ `lifecycle.rs:297,532`) | Three test-local `format!("vmcell-vm-{}-{}")` copies instead of `vmcell::naming::scratch_dir_name` — the exact F2 recompute-through-naming rule. Sweep all three. |
| `fs-reap-note-claims-consolidation-that-never-landed` | `fs.rs:166` | The v28 (fs-reap) notes entry records the three open-coded `kill(-pgid)`+`waitpid` teardowns as routed through `reap_process_group` — **the routing never landed** (`git log -S` confirms). Land it (all three sites can take the helper), making the entry true. (Entry annotated, §10.) |

## 7. Test-coverage gaps (beyond M10–M13)

| Finding | Where | What / fix |
|---|---|---|
| `jail-gate-narrower-than-design-claims` | `tests/jail_hardening.rs:54` | §12.3 claims the stand-in gate asserts caps/NNP/dumpable; it asserts NNP + RLIMIT_CORE + the seccomp leg only — `non_dumpable` and `clear_ambient_caps` have no behavioral test. Add `PR_GET_DUMPABLE` both ways (KVM-free); for ambient-clear either a privileged leg or scope the design sentence (note: `/proc/self/status` has no `Dumpable` field — the sentence is unimplementable as written). |
| `ip-shellout-selftest-multiword-half-cannot-fail` | `scripts/test-ban-agent-ip-shellout.sh:17` | No fixture exercises the two M-BIN-3 multi-word patterns; deleting those scanner branches stays green. Add the two MUST-flag fixtures (the PRIV-4 precedent). |
| `hostcaps-probe-body-untested` | `hostcaps.rs:112` | The probe body has no injection seam. The CapEff/netns half *is* live-covered (the segment suite's independent parser + `NetSegment::new` — unnamed until now; recorded in §10); the cgroup half (`probe_delegated_controllers`/`probe_domain_leaf`) is genuinely uncovered, blast radius = the daemon boot log. Either an injectable root (the `SysfsCpuFreq::with_root` pattern) or record the enumeration. |
| `usb-recipe-skip-manifest-not-exported` | `justfile:158` | The only suite recipe not exporting the run-scoped `VMCELL_SKIP_MANIFEST`, contradicting the justfile's own H-TEST-3 header (latent today; a future skip lands where nobody looks). Add the export. |
| `fuzz-loop-first-crash-short-circuits` | `.github/workflows/fuzz.yml:34` | One `bash -e` loop: the first crashing target starves the other of its whole nightly window until fixed. `|| rc=1` per target, exit `$rc`. |
| `vhost-check-presence-matches-any-version` | `scripts/check-vendored-vhost.sh:27` | Presence matches *any* `vhost v…`, so a consumer whose only vhost is an unrelated registry 0.15 (e.g. direct fuse-backend-rs) gets a false exit-1 instead of not-applicable — the accept-then-reject shape the three-way split exists to avoid (vmcell's own lockfile proves mixed-version graphs are real). Anchor presence on the pinned minor family. |
| `bless-ep-substring-weaker-than-preflight` | `justfile:49` | The bless skip-check matches a bare `*ep*` substring — the exact laxness the preflight hardened away (L-BIN-2); a second, weaker copy of the one predicate, latent until a runner path contains "ep". Use the field-precise form. |
| `smoke-fixed-tmp-fixture` | `vmcell-artifact-validator/tests/smoke.rs:32` | A fixed-name, never-removed fixture in shared `/tmp` — cross-user EACCES spuriously reddens the smoke leg. Use `NamedTempFile`. |

## 8. Simplification

- **S1** *(`eligibility-subset-duplicated-restore-inner-vs-check-clone-eligible`,
  `orchestrator.rs:1296`)*: `restore_inner`'s boundary-2 checks duplicate `check_clone_eligible`
  arm-for-arm; the pair has already needed lock-step edits (delta 5's record), and M2's new arm
  would be a third. Extract one `clone_ineligible_feature(cfg) -> Option<&'static str>` both call.
- **S2** *(`proxy-inline-setns-duplicates-net-sys`, `proxy/mod.rs:206,302`)*: two inline
  `unsafe { libc::setns }` blocks duplicate `net_sys::setns_net` (delta 8's designated home);
  route through it (leave the `vmm` pre_exec site alone — its safety proof is site-specific).
- **S3** *(`bench-workspace-root-third-copy`, `bench-vm.rs:673`)*: bench-vm hand-rolls the library's
  `pub(crate)` workspace ascent; the at-site comment names the collapse but no register lists it.
  Export one anchor or add it to §17's consolidation list beside `harness::ch_bin()`.
- Also counted here: `overlay-probe-not-side-effect-free` (`reflink.rs:150`) — `probe_reflink`
  writes sentinels into the probed dir while documented "side-effect-free"; for
  `Zygote::probe_cow_support` that dir is the **immutable master** (misreports FullCopy on a
  read-only master; can race a concurrent fan-out's tree walk; and `OverlayStore::probe` is left
  with no production caller). Probe in a sibling scratch dir and route through the seam.

## 9. Documentation debt

### 9.1 Post-landing staleness (the highest-leverage doc fix)

**AGENTS.md / docs/77** *(`agents-md-post-landing-staleness`)* still describes the pre-landing
world: "Current version: `vmcell` 0.12", a delta register "specified but not yet built" (which now
actively mis-instructs reviews by excusing divergences that are no longer excusable), the stale
"21/21" crosvm count (justfile says 28/28, dated), the future-tense USB recipe, and "the registry's
`destroy`/`shutdown_all`/`Drop`" (the daemon `Registry` has no `Drop` impl — already recorded).
Cut AGENTS v7: version 0.13; register in past tense with the register-conventions kept as standing
rules; counts by pointer, not embedded figure.

### 9.2 The v31 design-edit worklist *(`v31-design-edit-worklist` + individual findings)*

Recorded follow-ups the design still contradicts, plus stale text this review found:

1. §3.2 "EOF propagates in both directions" → replace with the delta-7 four-backend table (recorded).
2. §6.5 sweeper sentence ("already removes every prefixed netns, segments included") and the
   MAC-uniqueness premise → correct to the as-built fixes (recorded).
3. §6.2/§6.5 "device wiring routes through `net_uses_tap(cfg)`" → as built the backends key on
   `res.tap_name`, held in lockstep by `assert_tap_wiring_matches` (recorded, delta-8 premise 3).
4. `oci2erofs` → `oci2-erofs` at the CLI-verb occurrences (design lines ~890, 902, 2114, 2542,
   2640, 2692, 2734 — the delta-5 record's own "§5.6/§10.4" site list is itself incomplete), or land
   the clap alias.
5. §5.6 `build_labelled_kernel(label, &env)` → the shipped `(label, target_dir, overlay_file)`;
   §18-delta-4 classifier signature sketches → the shipped emitter-keyed signatures (recorded).
6. §12.3 deny-list roster → fold the three carry-overs once M15 lands; fix the "stand-in gate
   asserts …dumpable" sentence (§7).
7. §15.4 nextest filter → the shipped workspace-glob `package(~vmcell)` form
   *(`design-15-4-stale-nextest-filter`)*.
8. §9.2 module map: add `hostcaps.rs` *(`design-9-2-module-map-omits-hostcaps`)*; §9.1 guest-tools
   roster: four applets *(`design-9-1-guest-tools-roster-stale`)*; §7.2 consumer roster: the three
   real probe consumers *(`hostcaps-consumer-roster-overstated`)*.
9. Appendix C's "pinned CH v52.0.0" CVE claim — no CH pin is committed, README installs from git
   HEAD, validation ran on 54.0.0 *(`pinned-ch-version-claim-drift`)*. Commit the §10.2 pin (the
   schema and the snapshot-key fold already support it) or reword both sites.
10. §11.4 "registry `Drop`" wording (see 9.1).

### 9.3 README, benchmarks, todo

| Finding | Fix |
|---|---|
| `readme-cli-wrong-package` (README:20) | The first documented CLI command names the wrong package (`-p vmcell` has no binary); `-p vmcell-cli` (the file's own §8 gets it right). |
| `readme-stale-counts-and-crossref` (README:176, 295, 33) | crosvm "21/21" → dated 28/28 (or pointer); "102/102" → 144/144 dated; daemon "§18" → §11. |
| `downstream-privileged-bless-route-not-executable` (README:96, §10.4 item 5) | "bless your own workspace's runner copy via `just bless`" is not executable downstream (no recipe, no member); document the real route: build the runner from the vmcell checkout, install under the consumer's `.vmcell-bin/<profile>/`, setcap, wire nextest's target-runner — the runner's confinement anchors on its own installed location, which is *why* the copy must live in the consumer workspace. |
| `benchmark-doc-dangling-references` (benchmark-results.md:674 …) | Three refs to the nonexistent `docs/perf-experiments-log.md` (now `docs/historical/44-…`), a footer pointing at a reconciled-away notes section, same stale path in `.config/nextest.toml:21`. |
| `benchmark-doc-missing-estimator-caveat` (benchmark-results.md:706) | The doc carrying the canonical numbers nowhere states the load-bearing "tails before 2026-07-03 use the broken floor(n·q) estimator — not comparable" caveat while retaining pre-fix p95 columns. One sentence in the header blockquote. |
| `todo-md-stale-vs-v30` (todo.md) | Segments / netem / vsock bridge / serial fault capture are filed as untouched candidates; v30 shipped each fully or as the scoped first cut. Annotate with the existing PARTIAL/DONE pattern. |
| `git-pre-commit-unlinted-and-unlocked` (scripts/git-pre-commit) | Outside the shellcheck glob and the repo's only cargo call without `--locked` (can silently regenerate Cargo.lock). Add `--locked` + list the file explicitly in both shellcheck invocations. |

### 9.4 Rustdoc / comments contradicting shipped behavior

| Finding | Where | What |
|---|---|---|
| `seccomp-module-doc-describes-reversed-crosvm-posture` | `vmm/seccomp.rs:20`, `vmm/mod.rs:16` | The module doc states the *pre-reversal* crosvm posture the live validation refuted; "three backends" → four. |
| `crosvm-restore-test-comment-claims-cid-rotation` | `vmcell-crosvm/src/lib.rs:874–899` | The restore arg test's comments/assert-message describe **rotated**-CID semantics — the exact design crosvm empirically rejected — in the backend-template crate (the assertion itself is fine: it pins parameter flow). Also fix the notes' Gates-bullet phrasing. |
| `level-full-rustdoc-claims-absent-checks` | `vmcell-artifact-validator/src/lib.rs:103` | Contract-surface rustdoc promises an egress-proxy check and restore state-rotation assertions `run_full` does not run. Reword to the shipped roster (or register the gap). |
| `vmm-rustdoc-stale-backend-rosters` | `vmm/mod.rs:679` etc. | Five rosters (trait, `PerVmResources`, `VmmCapabilities`, `virtio_console`, `vsock_endpoint`/`VsockEndpoint`) + the Cargo.toml dev-dep comment omit crosvm; the endpoint docs miss its always-AF_VSOCK arm. |
| `kernel-verbosity-kern-emerg-drift` | `config.rs:718` | "(contains_panic, KERN_EMERG)" — the exact phrasing §5.3 retired as drift. |
| `crate-root-reexport-roster-inconsistent` | `lib.rs:148` | Leaf types are re-exported while `RootfsSource`/`Egress` — required to call the re-exported API at all — are not (same class as the recorded `UsbHostDevice` residual). Add both in the same one-line pass. |
| `max-frame-len-comment-overstates` | `net/smoltcp.rs:79` | "a frame never legitimately exceeds this" conflates smoltcp's frame-inclusive MTU with the guest's IP MTU; full-MTU non-TCP frames are legitimate and silently dropped (inert today — the NAT forwards TCP only). Comment fix, not a cap raise. |
| `artifacts-dir-downstream-fallback-undocumented` | `artifact/mod.rs:43` | The rustdoc documents only the in-checkout default; the downstream fallback (CARGO_MANIFEST_DIR/CWD) is undocumented — the example crate had to discover and work around it. One sentence citing §10.4. |
| `cargo-toml-three-backends-comment` | `vmcell/Cargo.toml:72` | "bench-vm drives all three backends" — it wires four. |
| `daemon-api-header-misnames-backend` | `bench-vm.rs:431` | `--backend firecracker --mode daemon-api` prints a firecracker header while benchmarking the CH-backed daemon (H-BIN-1). Print the ignored-knob line or bail. |
| `labelled-kernel-missing-source-pins-guidance` | `artifact/kernel.rs:456` | A fragments-only `kernels.<label>` overlay entry (exactly as §5.6 reads) fails naming the flattened internal key (`kernel_<label>_source_url`), not the overlay key to add. Name the `kernels.<label>.source_url` route in the refusal; add the two keys to §5.6/example README. |

### 9.5 Notes-ledger items

`impl-notes-missing-delta-2-record` — the register convention ("each delta reconciled") was met for
1 and 3–9 but delta 2 had no as-built record; **added in this pass** (§10).
`impl-notes-crosvm-bench-staging-disproven` — the crosvm staging entry's bench-default half was
empirically false since 2026-07-17; **annotated in this pass** (§10).

## 10. Implementation-notes actions taken by this review

Applied to `docs/implementation-notes.md` in this pass (AGENTS: record justified deviations; retire
entries that are empirically disproven):

1. **Corrected (fs-reap):** the recorded `reap_process_group` consolidation never landed — entry
   annotated as disproven; the fix is §6's item.
2. **Corrected v30 delta 9:** "every backend's `restore()` rejects a non-snapshotting config" was
   empirically false — annotated with the true mechanism and a pointer to M4.
3. **Annotated the crosvm staging entry:** the bench-default half was superseded 2026-07-17 (crosvm
   graduated into `vmcell-bench`'s default feature set); the opt-in `test-crosvm` half stands.
4. **Corrected the delta-4 residual:** the 11-site `let _` cluster is 10 best-effort
   teardown/shutdown sites + one commented OOM-probe discard + **one load-bearing swallow**
   (`checks.rs:866`, §6's fix item).
5. **Recorded (new, justified):** post-snapshot resume is warn-and-Ok on **all four backends** — a
   deliberate cross-backend policy (a completed snapshot is a valid, restorable artifact; `Err`
   would misreport it and break the stay-paused-for-kill flow). CH is the one site missing the
   at-site comment (fix item).
6. **Recorded (new):** the delta-2 as-built record (retroactive), naming where each piece landed and
   the git+rev-template deviation from a literal `=`-pin stanza.
7. **Recorded (new, delta-8 addendum):** the live coverage that names what the hostcaps probe's
   unit tests cannot see (the segment suite's independent CapEff parser + `NetSegment::new`), and
   the cgroup half's log-only blast radius.

Already-recorded finding confirmed as such (no action): the FC T2-probe socket under
`std::env::temp_dir()` — covered by the deliberate `temp_dir` non-ban (clippy.toml + rubric B1's
recorded trade).

## 11. What was checked and held

Beyond the findings above, each area's reviewer verified its load-bearing properties directly; the
highlights (full lists in the review transcript):

- **Config/build:** every builder field honored-or-rejected (vcpus/mem floors, vmid range, limits,
  shares, extra disks, init, prefix via the one validator); variant scoping (delta 4/8) holds; F3
  covers every emitted token on both ip= branches; the USB/vsock-transport/snapshot-eligibility
  refusal matrix is complete with positive controls; all seven `Timeouts` knobs are consumed with
  re-clamping at every layer; `error.rs` matches §9.5.
- **Orchestrator:** L1 one-helper teardown converges from success/error/Drop/registry paths;
  `FsIdClaim` is the one claim law (flock + liveness + hard_link) with `seeded_id_order` shared;
  S3/S4/S5 hold (grep-verified single CoW site through `env.overlay`; fan-out master-immutability;
  cross-allocator ancestry); `restored`/desync one-shots are consumed only on success;
  `spawn_clones` is all-or-nothing; the sweep liveness-checks each class against its own id space.
- **Net/segments:** the five NAT invariants hold on the host→guest side (the guest→host side is B1);
  segment claim/cleanup contracts, Drop order, `dial_tcp`'s dedicated-thread netns discipline, and
  `segment_ip_math` bounds all as recorded; proxy CA atomicity and normalized host matching with
  positive controls.
- **VMM/jail:** pre_exec ordering (setns before jail) and the apply_jail sequence match §12.3
  (modulo M15/§7); `vmm_seccomp_args` is the one law; CH `image_type: Raw` everywhere; metrics
  errno split and the §7.3 cgroup edges as designed; capability literals match §2.6 on all four
  backends (all nine flags — grep-verified).
- **Agent/protocol/guest:** append-only discriminants pinned; MAX_FRAME_BYTES enforced both
  directions with `try_from` narrowing; backoff-reset rule intact across the four retry sites; C1
  never-exit (modulo the `oldroot` note), reaper epochs, C4 one-writer, C5 exactly-one-exit, C6
  zero-netlink (structural gate) all hold; the classifier literals match the agent's emitter strings
  byte-for-byte today.
- **Daemon/broker:** P3 anchoring with the ban script; P4 auth wrap/perms/constant-time; P5 parity
  table; store create-only + atomic + sidecar discipline (modulo the delete/info gap in §6);
  delete-in-use atomicity under one lock; bridge JSON codec round-trips every op; broker forked
  before the runtime with PDEATHSIG and bounded frames; the startup sweep passes both live sets.
- **Pipeline/toolkit:** the five F4 cache-key rules on every stage; the pins overlay shape table is
  bidirectionally pinned; F5 is derived from the manifest with normalize-before-compare; the packer
  insertion order and `validate_extra_files` rules as recorded; the example workspace's legs are
  non-vacuous (contract drift reddens it).
- **Gates:** docs/76 conformance is otherwise faithful — every named gate exists with a red-able
  self-test (the exceptions are §7); `ci.yml` mirrors the justfile (exceptions M14, §5's
  lean-privilege row); MSRV single-sourcing, SHA-pinned actions, `--locked` discipline, deny.toml
  bans, and the three docs/76 one-time reconciliations all verified done.

## 12. Suggested landing order

1. **B1 + M13** (one change: the NAT consume fix with its gate).
2. **M1** (FC `network_overrides` + the post-restore egress-byte matrix leg) and **M2/M4 + S1**
   (one consolidated eligibility predicate gaining the custom-init and USB arms, notes corrected).
3. **M5–M9** (each is a contained reliability fix with a KVM-free gate).
4. **M10–M12, M14, M15** (gate holes — small tests/CI edits; M15 adds one syscall + a notes record).
5. §5–§7 minors opportunistically, §8 as a cleanup pass.
6. §9: AGENTS v7 + the README/benchmark one-liners now; the design-text items batch into v31.

Fixes are deliberately **not** applied by this review (it is a review, not a fix pass) except the
implementation-notes ledger actions in §10, which are the review's own obligation under AGENTS.
