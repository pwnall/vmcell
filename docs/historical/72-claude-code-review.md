# 72 — Code review: the vmcell implementation (2026-07-13)

A full-implementation review of the `vmcell` workspace (≈50k Rust LOC across 15 crates) against
design v28 (`docs/68-claude-fable-design-v28.md`), the recorded deviations
(`docs/implementation-notes.md`), and the measured performance envelope
(`docs/benchmark-results.md`, `docs/historical/45-claude-perf-investigation.md`). It covers the
seven axes the review was scoped to: correctness, code quality, over-complicated API design, test
coverage gaps, performance opportunities that **do not** regress the documented latencies,
insufficient/incorrect documentation, and Rust-idiom deviations.

## Method

- **Baseline validated on this KVM host first** (so review is against a known-good build, not a
  static read): `just`-equivalent unit suite **510/510 pass** (88 KVM-skipped); privileged suite
  **93/99 pass, 5 skipped**. The 6 failures are the *documented environmental cluster* —
  `nested_virt*` (CH+QEMU: nested `/dev/kvm` not exposed to guests) and `snapshot_restore` reseed
  (CH+FC: guest virtio-rng passthrough) — reproducing identically on unmodified code, i.e. this run
  **is** the baseline control per implementation-notes v26(g) and the host `kvm_intel`-fault memory.
  They are host-hardware conditions, **not** code regressions.
- **Fan-out sub-review**: 15 subsystem reviewers read the actual source + tests, each finding was
  **adversarially verified** by a second agent that re-read the cited code and defaulted to
  refutation. 43 findings survived verification (10 explicitly CONFIRMED at medium+; 2 refuted).
  `config.rs` (build-time validation, the shared cmdline builder, S1/F3) was re-reviewed by a fresh
  dedicated pass and found clean of correctness bugs (3 low/nit coverage notes).
- **Independent corroboration**: the load-bearing cores were read first-hand — L1 teardown ordering,
  `VmidAllocator` reclaim, the `ReaperCoordinator` epoch race fix, `host_read_budget`, the bench
  percentile estimator, the wire-variant ordering, and `resolve_artifact_path` — and the top
  findings (VMID reclaim race, `destroy` redirect, unused fault arms, snapshot residue) were traced
  by hand against the real code.

## Verdict

**This is a mature, unusually disciplined codebase.** The load-bearing invariants (S1 snapshot
eligibility, L1 ordered teardown through one helper, C-family control-plane discipline, F-family
fail-loud/naming, P-family privilege boundaries) are implemented correctly, single-sourced, and —
in the great majority of cases — pinned by red-on-inverse tests. Nothing found is a critical defect,
a security escape, or a data-loss bug on a routine path. The findings concentrate exactly where a
codebase this well-tested leaves gaps: **crash-recovery-under-contention**, **error/over-cap edge
paths the fakes are structurally blind to**, **wired-but-undriven surface**, and a **cluster of
stale or over-claiming doc-comments** — several of which assert that a gate or consumer exists when
it does not.

| Severity | Count | Nature |
|---|---:|---|
| High | 1 | A cross-process allocator TOCTOU that can dual-claim a vmid (host-global isolation) |
| Medium | 8 | A fail-loud violation, an error-path residue leak, a broken CLI redirect, an over-claiming doc, and 4 missing/absent-but-design-claimed test gates |
| Low / nit | 36 | Fail-loud paper-cuts, stale docs, untested error branches, extractable-law cleanups |

---

## High severity

### H1 — Cross-process VMID reclaim has a TOCTOU that can dual-claim a vmid
`crates/vmcell/src/orchestrator.rs:194` · correctness · **CONFIRMED**

`VmidAllocator::try_claim_fs` decides a stale lock is reclaimable from a `read_to_string` snapshot
(line 177) and its `/proc/<pid>` liveness check (182–189), then **unconditionally** `rename`s
whatever inode is at `lock_path` *now* (194) — by path, not by the inode it inspected. Between the
read and the rename, a second claimer can legitimately reclaim the same stale lock and `atomic_claim`
a **fresh, live** lock carrying its own pid. The first claimer then renames that live lock away and
removes it, loops, `atomic_claim`s the now-free path, and returns `true` — so **two processes both
return `true` and both insert the same vmid** into their in-process `active` sets.

Two live VMs then share one vmid ⇒ the same netns/tap/cgroup/CID and the same
`mac_math(vmid)` / `10.200.<octet>.x` — the exact host-global collision this allocator exists to
prevent. The `hard_link` in `atomic_claim` makes the *claim* mutually exclusive but does **not** make
the read→rename reclaim *decision* atomic, and the winning claimant never re-checks, so there is no
self-healing.

- **Trigger**: a pre-existing dead/empty lock (a crashed prior run) **plus** ≥2 concurrent reclaimers
  landing on the same vmid — precisely the "several runner processes share host-global resources"
  case `shared()`/`shared_at()` exist for (and that nextest's process-per-test model creates). Narrow
  window, but a real host-global isolation defect on a real path.
- **Also a documentation lie**: the doc-comment (159–163) asserts "reclaim … is serialized by an
  atomic `rename`, so two racing processes cannot both pass the liveness check and dual-claim." The
  rename serializes *who wins the steal*, not the *decision* that led to it — the claimed property is
  false.
- **Coverage gap**: `shared_at_reclaims_empty_and_dead_locks` and `shared_at_conflict_between_live_owners`
  are both single-threaded and cannot exercise a concurrent read→rename interleave.

**Fix**: make the decision and the mutation act on the *same* inode — rename the stale lock to the
unique `steal` path **first**, then read `steal` and check owner liveness, and only remove `steal`
(freeing the vmid) if the owner it carried is actually dead; otherwise a live lock written by a racer
is preserved because its pid is read from the very file that was renamed. Add a multi-process/thread
concurrent-reclaimer test asserting exactly one winner (the missing red-on-inverse gate).

---

## Medium severity

### M1 — An over-cap `Session` write silently kills the whole mux writer while the caller gets `Ok(())`
`crates/vmcell/src/agent/session.rs:390` · correctness · **CONFIRMED**

`Session::{write_stdin,close_stdin,resize,close}` and `SessionMux::open` funnel a `Message` into an
**unbounded** `write_tx` channel, whose `send` returns `Ok(())` as long as the writer task is alive —
it never encodes, so payload size is irrelevant to the caller. The length-delimited encode happens
later in `writer_task`, whose codec caps frames at `MAX_FRAME_BYTES` (16 MiB). A single `>16 MiB`
`write_stdin` (streaming a large file to an interactive session's stdin, or an oversized argv/env in
`OpenSession`) makes `sink.send` return an encode error, which the `Err` arm handles with only
`tracing::debug!` + `break` — **silently terminating the writer task and killing host→guest input for
every session on that mux**, while the offending call already returned `Ok(())`.

This contradicts the method's own `# Errors` doc ("Returns `Error::Agent` if the connection has
closed") and the AGENTS.md fail-loud / handle-counts rules. The one-shot `AgentClient` path is the
correct contrast: an over-cap frame there surfaces as `RequestFailure::Transport` and fails loud
(`agent/mod.rs:362,431`). Cross-session blast radius; not data corruption or an escape, hence medium.

**Fix**: validate payload length against `MAX_FRAME_BYTES` at the `Session` boundary and return a
typed error before enqueueing, or have `writer_task` distinguish an encode over-cap (a caller error,
propagate it) from a genuine transport EOF; at minimum log the encode break at `warn`/`error`.

### M2 — Daemon `snapshot()` creates the output dir before the VM/state checks, leaking residue
`crates/vmcell-daemon/src/registry.rs:280` · correctness · **CONFIRMED (first-hand)**

`std::fs::create_dir_all(&out_dir)` (line 280) runs **before** `self.slot(id).await?` (284, →
`NotFound`) and `require_state(&inner, VmState::Ready, id)?` (286, → `Conflict`), and neither error
path removes the just-created directory. A `POST /v1/vms/<missing>/snapshot {artifact_prefix:"snap-x"}`
returns 404 yet leaves an empty `<artifacts-dir>/snap-x/` behind; likewise for a VM in
Booting/Paused/Snapshotting/Destroying. The backend-failure path (`result?` at 290) can also leave a
partial dir. This violates the "mid-op faults leave zero residue" discipline, and the leftover dir
**shadows** a later artifact of the same name (`ArtifactStore::create` rejects an existing path;
`restore_from` passes its `is_dir()` gate but finds no snapshot files). Structurally invisible to the
`FakeHandle`-driven unit test (the fake never opens the dir).

**Fix**: resolve the slot and assert `Ready` first, then create the dir (ideally under the per-VM
lock); remove an empty just-created dir on the error/enumerate paths.

### M3 — `vmcell destroy` redirects to a non-existent `vmcelld-ctl destroy` subcommand
`crates/vmcell-cli/src/main.rs:548` · correctness · **CONFIRMED (first-hand)**

Delta 11's redirect exists to replace clap's cryptic "unrecognized subcommand" with a *working* next
command. `moved_to_vmcelld_ctl` interpolates the same verb name, so `Commands::Destroy =>
Err(moved_to_vmcelld_ctl("destroy"))` tells the user to run `vmcelld-ctl destroy` — but `vmcelld-ctl`
has no `destroy` subcommand; its teardown verb is `rm` (confirmed: its `Command` enum is
Create/Run/Ls/Get/Exec/Stats/Snapshot/**Rm**). The user gets exactly the cryptic failure delta 11
set out to remove. The CLI's own `Destroy` doc-comment already says "Use `vmcelld-ctl rm`", so the
runtime message contradicts the in-code doc, and implementation-notes claims the redirect names
"where the real verbs live" — false for this one verb. `exec`/`ls`/`rm` are fine because those names
coincide across both tools.

**Fix**: `Commands::Destroy => Err(moved_to_vmcelld_ctl("rm"))`, and strengthen the delta-11 gate
`daemon_deferred_subcommands_fail_loud` to assert the message names a verb `vmcelld-ctl` actually
exposes (e.g. `contains("vmcelld-ctl rm")`), not merely the substring `vmcelld-ctl` (see L-gate below).

### M4 — `dto.rs` doc says the broker channel uses postcard; it deliberately uses JSON
`crates/vmcell-daemon/src/dto.rs:393` · docs · **CONFIRMED**

The `ErrorKind` doc-comment states its `Serialize`/`Deserialize` are "used only by the internal
setup-broker `WireError` (**postcard** over the broker socket, §12.4)." This is factually wrong and
contradicts a load-bearing invariant: the daemon↔broker engine channel is length-prefixed **JSON**
precisely because the reused DTOs carry `#[serde(skip_serializing_if)]`/`default` presence attributes
that postcard corrupts (Appendix A reversal 10, implementation-notes item (i), and the recorded
`create`-hang that motivated it). `vmcell-daemon` has no `postcard` dependency at all;
`bridge.rs` uses `serde_json` exclusively. A maintainer trusting this comment could rationalize
reintroducing postcard on the broker channel and silently re-trigger the documented corruption. Fix:
change "postcard over the broker socket" to "JSON over the broker socket".

### M5 — Design-claimed gates that do not actually exist (a cluster of testing gaps)

Four separate gates are asserted by the design/AGENTS.md but are absent in code, so a regression on
each ships green. Each was independently **CONFIRMED**.

- **M5a — No window-filling data-plane test through the smoltcp NAT** (`net/smoltcp.rs:991`,
  testing). Design §6.2 says invariant #5 (the `host_read_budget` tail-drop) is "pinned by a
  window-filling test that reddens on the old unbounded read." No such test exists — only the pure
  helper `host_read_budget_bounds_read_to_free_tx_room`. Every test that moves real bytes through the
  NAT sends tiny payloads (`host_endpoint`, `egress_proxy`'s 13-byte body, `lifecycle`); session.rs's
  ~27 KiB stream is over the vsock mux, not the NAT, and is under the 64 KiB TX window. If line 1002
  regresses to an unbounded read, a host→guest transfer larger than the guest receive window silently
  drops its tail and **no test reddens**. (The `debug_assert_eq!(enqueued, n)` guard fires only under
  a window-filling load, which nothing generates.) *Fix*: a host→guest transfer of `>64 KiB` with a
  digest compare, red-on-inverse against the unbounded read.

- **M5b — `restore_inner`'s unprivileged-net rejection branch has no red-on-inverse test**
  (`orchestrator.rs:1045`, testing). The §2.5 boundary-2 check rejecting `NetConfig::Unprivileged`
  on restore is reachable *without* `snapshotting=true` (so the `build()` guard never fires), yet no
  test constructs an unprivileged-net config and calls `restore()` — only its sibling data-share arm
  is guarded (`test_restore_rejects_data_shares`). A regression weakening this arm reddens nothing.

- **M5c — `FaultMenu::fail_resume` is wired but driven by no test** (`vmm/mod.rs:755`, testing).
  AGENTS.md requires "each FakeVmm fault-menu arm (delta 9) is driven." `fail_resume` is honored in
  `FakeVmInstance::resume` but has zero constructions workspace-wide (confirmed by grep). It uniquely
  covers restore→resume failure (`orchestrator.rs:1118`) where a *live* instance already exists with
  cgroup/netns side effects and the guard is still armed — a distinct teardown path the `fail_restore`
  test cannot reach (there no instance is ever built). `readiness_delay` (`mod.rs:763`) is likewise
  undriven (see L-list). implementation-notes' delta-9 entry claims "New orchestrator tests drive each
  arm" then enumerates only create/boot/restore/wedge — the note itself is inaccurate here.

- **M5d — No `>MAX_FRAME_BYTES` session write test** (`tests/session.rs`, testing) — the missing
  red-on-inverse gate for M1. AGENTS.md mandates over-cap payloads on *every* data-plane test; the
  session suite's largest host→guest write is `b"more data\n"`. The one-shot path *does* test the
  boundary (`host_codec_accepts_frame_above_default_8mib`); the session path is the omission.

---

## Cross-cutting themes

Several findings are instances of the same shape and are worth addressing as classes:

1. **Wired-but-undriven surface, sometimes with docs claiming it is exercised.** `FaultMenu::fail_resume`
   and `readiness_delay` (defined, honored, zero drivers); `VmHandle::pause`/`resume` (implemented,
   no route, no registry caller, `VmState::Paused` never produced); the egress-proxy `record_to`
   cassette hook (public, never called, its fs-write branch untested). Each is either an unfinished
   feature that belongs in the §17 register or dead surface to remove — and in two cases the design
   docs assert the opposite (delta-9 "drives each arm"; §6.4 "record/replay cassettes").

2. **Effect-classes the fakes are blind to, without a live gate** — exactly the AGENTS.md rule-4
   class. The `RecordingOverlayStore`/`FakeVmm`/`FakeHandle`/`FakeNft` fakes never touch the
   filesystem, network bytes, or xattrs, so: the CH net-device JSON builder (`ChNet` tap vs
   vhost-user branches) is built inline in `create()` with no unit gate unlike its four extracted
   siblings; the restored `guest_cid()`←baked-CID wiring has no live assertion (the live test accepts
   any in-range CID); the daemon snapshot residue (M2) and cassette fs-write are fake-invisible; the
   smoltcp window-fill (M5a) needs a live device. Extract the law or add a live gate.

3. **A cluster of stale / over-claiming doc-comments.** Beyond M4: `hostcaps.rs` (delta 8) —
   `probe()` is called, logged, and dropped; four of its five decision accessors have **zero**
   production callers and `metrics::try_apply_limit_at` re-reads `cgroup.subtree_control` per write,
   so the AGENTS.md/§7.2 claim "per-op checks read the descriptor, never re-probe" overstates the
   as-built (the descriptor is effectively probe-and-log). `netns_reachable()`'s doc promises a
   *writability* check the body does not do (`/run` `is_dir()` only). The libc6-scan comment claims a
   `lib*`-dir restriction the code does not implement. `oci2erofs` has two contradictory comments
   about whether its staging dir is under the artifacts dir or the system temp dir. The kernel-builder
   missing-seed error cites §8.5 (Lineage) instead of §5.4 (bootstrap seed). Each is a small
   correctness-of-documentation defect that will mislead a maintainer.

4. **Fail-loud paper-cuts** (each a `let _ =`/`unwrap_or_default` on a meaningful `Result`, against
   the "no bare swallow" rule): the thin broker child discards `serve()`'s error and `_exit(0)`
   (`broker/lib.rs:641`); `SetupNetwork` masks `host_ip()` with `unwrap_or_default()`, potentially
   emitting an nft rule with an empty gateway (`broker/lib.rs:382`); `BrokerChild::reap` latches
   `reaped=true` even when `waitpid` fails on EINTR, risking a zombie (`broker/lib.rs:543`); the
   guest's `replace_default_route` swallows a `/proc/net/route` read error into an empty vec, which
   can leave a *stale* default route and intermittently blackhole post-restore egress
   (`guest-agent/netif.rs:262`); and the guest-tools `curl` fallback can collapse a post-CONNECT TLS
   verify failure to exit 0 and does not bound the fallback connect by `--max-time`
   (`guest-tools/main.rs:566,625`).

---

## Low severity and nits (by subsystem)

All below are verified low/nit — real, but bounded impact, off the hot path, or cosmetic. Grouped
for triage.

**Config / build-time validation** — `config.rs` is otherwise a model file (S1's four rejections all
present and unreachable-around; `RESERVED_CMDLINE_KEYS` covers every emitted token, verified
token-by-token; `Timeouts::clamped` floors correct; no `let _ =`/accept-then-ignore). Residual notes:
- `config.rs:1216` (testing): the `io.max` device-key validator has a negative test only for a
  missing colon; the empty-maj/empty-min/non-digit sub-branches (`":0"`, `"8:"`, `"8:x"`) are
  undriven. A "simplification" to `split_once(':').is_some()` would accept `io_max{device:"8:x"}`,
  which hits the cgroup write as an EINVAL — the very "masquerades as a missing-capability error"
  case the M-HOST-4 boundary exists to prevent — with the KVM-free suite green. Also
  `validate_init_path`'s non-UTF-8 branch has no test. Add the three device strings + a non-UTF-8
  `OsStr` case.
- `config.rs:384` (testing): no KVM-free assertion on the *content/placement* of the `ip=…::…::eth0:off`
  token or of `rootflags=noload` present-for-`Block`/absent-for-`Erofs` (the explicit `nested=0` case
  *is* covered by live `tests/nested_virt.rs`). A refactor emitting `rootflags` unconditionally, or
  dropping the `ip=` netmask, boots-breaks `Erofs`/networking but passes the whole KVM-free suite. The
  one-law gate at `config.rs:2705` already builds a suitable config to assert against.
- `config.rs:1443` (nit): `build()` doesn't itself `.clamped()` `timeouts` — clamping is on the
  setter + the orchestrator re-clamp (intentional and documented; the re-clamp is the real guard
  against post-`build()` mutation of the `pub` field). Optionally add a one-line comment so the
  omission reads as deliberate, not a bug to "fix."

**Networking**
- `net/smoltcp.rs:793` (code-quality): the load-bearing per-port pool size for invariant #4
  (~16 sockets/port, the keep-alive-wedge guard) is a bare inline `16` — every other NAT quantity is
  a named, documented const with a test. A "simplify to `0..1`" refactor would silently reintroduce
  the keep-alive wedge with the whole suite green. Extract `const FORWARD_PORT_POOL` + a guard test.

**Snapshot / artifact pipeline**
- `artifact/tar2erofs.rs:66` (correctness): the packer sets `xattrs: vec![]` unconditionally and
  never reads PAX records, so `security.capability` xattrs are dropped — `/usr/bin/ping` etc. lose
  file caps in-guest. Not a spec violation (guest agent runs as root), but a real behavioral
  difference from a normal unpack; preserve them or record the accepted limitation with a test.
- `artifact/tar2erofs.rs:185` (correctness): opaque-whiteout (`.wh..wh..opq`) `retain` also clears
  same-layer children added *before* the marker in tar order; OCI semantics clear lower layers only.
  Needs a hand-crafted (digest-pinned) layer to trigger. Apply whiteouts per-layer, or add a
  `[child, opaque]`-ordered test and document the "producer emits opaque first" assumption.
- `artifact/mod.rs:206` (correctness): `hash_output` on a directory never folds the **root**
  directory's own mode (only per-entry modes), so a `chmod` on the snapshot root is outside the
  tamper hash; the L-ART-5 test only chmods a subdirectory.
- `artifact/tar2erofs.rs:216` (nit): injected files all get `0o755`, so the CA cert data file is
  marked executable (cosmetic; `update-ca-certificates` ignores the x-bit).
- `artifact/tar2erofs.rs:256` (nit, docs): the libc6-scan comment describes a `lib*`-dir restriction
  the code does not implement (matches `libc.so.6` anywhere).

**Metrics / hostcaps**
- `hostcaps.rs:71` (code-quality): the delta-8 descriptor is probe-and-log; four of five decision
  accessors are dead outside tests (see theme 3).
- `metrics.rs:404` (correctness): a missing `memory.swap.max` (kernel without swap accounting /
  `swapaccount=0`) hits the `else` arm of `classify_limit_write_err` and is misreported as
  `CapabilityUnavailable` "delegation" — sending the operator chasing the wrong remediation on a host
  where the controller *is* delegated. Distinguish ENOENT/EOPNOTSUPP from EACCES/EPERM/EROFS.
- `hostcaps.rs:138` (docs): `netns_reachable()` doc promises a writability signal the body doesn't
  check.

**Daemon / broker / privilege**
- `server.rs:117` (correctness): `delete_artifact` has a TOCTOU between `is_artifact_in_use` and
  `delete` — a concurrent `create_vm` pinning the same artifact can interleave, deleting a file out
  from under a just-booted VM. Narrow (single-tenant), but the two-step check-then-act isn't atomic;
  re-check in-use under the create lock, or record the accepted race.
- `launcher.rs:54` (code-quality): `VmHandle::pause`/`resume` and `VmState::Paused` are dead on the
  wire (theme 1).
- `broker/lib.rs:382,543,641` (correctness): the three fail-loud paper-cuts (theme 4).
- `broker/tests.rs:50` (testing): the broker fakes have no fail-arm, so `SetupNetwork`'s nft-emit
  error branch (and its netns-reclaim-on-failure residue), the `Teardown` error-aggregation path, and
  the `CgroupReady`/`SpawnVmm` codec round-trips are untested.
- `dto.rs:6` (docs, nit): the module doc says "every field carries `#[serde(default)]`"; required
  fields (`kernel`/`rootfs`/`argv`) correctly do not — reword to avoid implying required fields
  default on an old client.

**Agent host / sessions**
- `agent/session.rs:180` (correctness): `SessionMux::open` inserts the registry entry *before*
  sending `OpenSession`; on send failure it returns `Err` but leaves the orphaned entry (bounded —
  ids are monotonic and the registry dies with the mux). Send-first, insert-on-success.

**Guest agent**
- `guest-agent/netif.rs:262` (correctness): stale default route on `/proc/net/route` read failure
  (theme 4).
- `guest-agent/main.rs:438` (nit): the degraded polling-reaper fallback discards a SIGTERM-registration
  error with `let _ =`; on a doubly-degraded host the poll loop could never observe SIGTERM (teardown
  force-kills anyway). Log it.

**VMM (CH/FC)**
- `vmm/cloud_hypervisor.rs:582` (code-quality): `ChNet` built inline in `create()` — extract a pure
  `build_ch_net` with a shape test for both branches, like its four extracted siblings (theme 2).
- `vmm/cloud_hypervisor.rs:663` (testing): restored `guest_cid()`←baked-CID wiring has only a
  pure-parser test; the live test accepts any in-range CID (theme 2).
- `vmm/mod.rs:763` (testing): `readiness_delay` fault arm undriven (theme 1 / M5c).
- `vmm/firecracker.rs:388` (correctness): the T2-template probe leaks its `/tmp` API-socket file on
  the `wait_for_socket`-failure branch (no `FcInstance` owns it there, so `Drop` never unlinks it);
  every transient probe timeout orphans another `vmcell-fc-probe-*.socket`. Add a `remove_file` before
  the early `T2Probe::Failed` return.

**Guest-tools / fs / proxy / cli**
- `fs.rs:166` (code-quality): the `kill(-pgid)`+`waitpid` teardown is open-coded three times
  (try_wait error, socket-wait timeout, `Drop`) instead of the existing single-source
  `crate::vmm::reap_process_group` — the exact "never write a second copy" class (that helper's own
  docstring records a prior divergence).
- `guest-tools/main.rs:566` (correctness): `curl` fallback can turn a post-CONNECT TLS-verify failure
  into exit 0 (real curl → 60); `-k` state isn't threaded into the probe.
- `guest-tools/main.rs:625` (correctness): `--max-time` doesn't bound the fallback probe's TCP
  connect (blocking `TcpStream::connect`, OS default timeout).
- `proxy/tls.rs:140` (correctness): CA generation publishes key then cert as two renames; a crash
  between them leaves `ca.key` without `ca.pem`, so the next run regenerates the CA and invalidates an
  already-baked rootfs trust chain. Narrow (crash between two renames + pre-existing baked rootfs);
  treat "key present, cert absent" as recoverable rather than regenerate.
- `proxy/mod.rs:428` + `proxy/doubles.rs:133` (docs + testing): the cassette `record_to` hook records
  only request lines (no response), can't support replay, excludes blocked requests, is never called,
  and its fs-write branch has zero coverage — the doc/§6.4 "record/replay cassettes" wording
  overstates what ships.
- `cli/main.rs:806` (docs): contradictory staging-dir comments in `oci2erofs` (theme 3).
- `cli/main.rs:859` (testing): the delta-11 gate only asserts `contains("vmcelld-ctl")`, which is why
  M3 ships green — assert the exact ctl verb.
- `kernel-builder/lib.rs:318` (docs): missing-seed error cites §8.5 (Lineage) instead of §5.4.
- `broker/lib.rs:596` (nit, api-design): `fork_privileged_child`'s "call before any runtime"
  precondition is unenforceable in the signature; the shipped `fork_transport` test forks from a
  multi-threaded harness sharing an `Arc<Mutex>` recording log (safe today, footgun-shaped).

---

## Considered and dismissed (refuted on verification)

Two plausible-sounding findings were traced and refuted — recorded so they are not re-derived:

- **FC T2 probe socket "escapes the scratch-dir discipline" into bare `/tmp`** — *refuted*. `VmTempDir`
  and the probe use the **same** base (`std::env::temp_dir()`, documented as `/tmp/vmcell-vm-…`); the
  probe is not less-disciplined than the real per-VM sockets. (The *separate* leak on the probe's
  failure branch — `firecracker.rs:388` above — is real and kept.)
- **Daemon `snapshot()` doesn't reject an existing prefix, mixing two snapshots' files** — *refuted*
  for the only wired backend: CH writes a **fixed** filename set (`config.json`/`state.json`/
  `memory-ranges`) into the dir, so a reused prefix cleanly overwrites rather than mixing. (The
  *residue-on-error* aspect — M2 — is the real, kept part.)

---

## Performance

No latency-regressing change is recommended, and the `docs/45` 12-item reject table was respected (no
re-derivation of parallel-virtiofsd-via-`try_join_all`, ACPI shutdown, `mitigations=off`, persistent
QMP, or the already-refuted cmdline trims). Two observations that are *not* regressions:

- The smoltcp `send_slice` correctness guard is a `debug_assert_eq!` (compiled out under `--release`;
  the suites run debug so it is live in CI but delivers zero coverage because nothing fills the
  window — see M5a). Promoting it to an unconditional error+log would surface a real production
  tail-drop at negligible cost, off the hot path.
- No hot-path allocation or redundant-syscall issue was found in the connect/accept/teardown budgets
  that dominate the measured numbers; the optimization narrative in §16 has already harvested the
  large levers.

## Validation performed for this review

- Unit suite (all features): **510/510 pass**, 88 KVM-skipped.
- Privileged integration suite via the blessed runner under a delegated scope: **93/99 pass, 5
  skipped**; the 6 failures are the documented environmental cluster (nested-virt passthrough +
  virtio-rng reseed on this host's `kvm_intel` fault), reproduced on unmodified code = baseline
  control, **not** regressions.
- First-hand code reads of the load-bearing cores (L1 teardown, allocators, reaper epochs, NAT read
  budget, path validator, percentile math, wire ordering) — all correct as designed.
