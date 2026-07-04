# Imp Testing — Code Review (Review 37)

*Date: 2026-06-29. Scope: the full `imp-testing` implementation (`src/` ≈ 13.7k LOC across 36
files, `tests/` 14 files, and the quality-gate infrastructure). Reviewed against the v13 design
(`docs/35-claude-design-v13.md`), the v2 rubric (`docs/36-claude-code-review-rubric.md`), the
requirements (`docs/requirements.md`), and the recorded deviations (`docs/implementation-notes.md`).*

## How this review was produced

This was a delegated multi-agent review. 17 sub-reviewers each took one coherent file-slice plus
the rubric items and design contracts for that subsystem, read the **real source** (not the
design's claims), and emitted structured findings. Every Critical/High/Medium finding was then put
through adversarial verification — an independent agent re-read the cited code and tried to
**refute** it (Critical/High got three lenses: correctness, "does the test actually stay green?",
and "is this already justified?"); majority-refute dropped the finding. 78 raw findings →
46 survived verification, 31 Low/Nit passed through, **1 was refuted** (a claim that `shutdown()`
deletes the netns before reaping the proxy socket — the cited `shutdown()` ordering was misread;
note, however, that a *different*, real ordering bug in `shutdown()` did survive — see M-ORCH-2).

**This pass changed no code and fixed nothing.** It is review-only. Every finding cites `file:line`
and is independently re-checkable; a sample of the highest-severity findings was spot-read against
source during synthesis and confirmed.

**Empirical validation added (Review 37a, 2026-06-29).** After the static review, the maintainer
blessed the capability runner, so the host-facing paths were then **actually executed**: the full
privileged suite across all three backends and the rootless suite were run on this KVM host (see the
**Empirical validation** section). This turned several static findings into empirically-confirmed
ones, confirmed others as genuine untested-path gaps, surfaced **three new findings the static pass
could not see** (E1–E3), and let one prior assumption be retired (CH warm restore now passes). A
reusable preflight gate (`scripts/review-preflight-priv.sh`, wired into the review workflow as a
block-and-ask Phase 0) now refuses a privileged-aware review unless the suites can actually run.

Four findings that are **defensible, intended deviations** were moved to
`docs/implementation-notes.md` (per the review request) rather than reported here; they are listed
in the appendix. The vendored `vendor/vhost*` crates were out of scope except the carried
QEMU-unprivileged patch (see the note at the end).

---

## Executive summary

The codebase is mature and, in most subsystems, faithfully implements the v13 design and survives
its own rubric. The injectable-seam discipline is real (`FakeVmm`, `FakeNetlink`, `FakeClock`,
`CgroupFs` fakes exist and several are driven), the teardown `Drop` order is correct on the happy
path, the cache-key/determinism trio runs on real stages, and most of the recorded prior-pass
defects stay fixed. The lint header, `deny.toml` rationale discipline (for the older advisories),
and nextest timeouts are in place.

But the review found one **Critical** gate failure and a cluster of **High** correctness/contract
gaps, and — most importantly — the rubric's own headline failure mode (**"a green CI can be a
lie"**) **recurs literally**:

- **The CI lint job and `just ci` both short-circuit at a known-red step**, so `cargo deny`,
  `cargo semver-checks`, the lean-agent build, the global-state ban, and (in `just ci`) the unit
  suite **never run**. The supply-chain and API-break gates are silently dead. (C-GATE-1)
- **The fail-loud capability contract (design §7.1) is essentially unimplemented.** A *requested*
  cgroup limit on an undelegated controller is `warn!`-and-skipped, `create_slice` returns `Ok`,
  there is **no** `Error::CapabilityUnavailable` variant, **no** `HostCapabilities` probe, and
  **no** `limits_enforced` flag anywhere in `src/`. This is exactly the "silent degradation is the
  default bug" class the rubric names as its highest-leverage target. (H-FAILLOUD-1)
- **Several guest-/network-driven paths have real correctness bugs**: a trivially bypassable egress
  deny-list (case + trailing dot), a smoltcp NAT that reuses stale host streams and leaks
  unreclaimed mappings (defeating the NET-5 cap it was built for), `put_file` silently ignoring the
  desync protocol it documents, and the rootfs cache key missing the agent implementation it bakes
  in (stale-agent-in-rootfs — the exact tell the rubric calls out).
- **The privileged transparent-proxy path (a *mandatory* requirement) is non-functional and
  untested**: the proxy listener is not `IP_TRANSPARENT`, no test boots Privileged+Filtered, and
  every privileged test uses `Egress::Open`.

Severity distribution of reported findings (after merges/elevation, excluding the 4 relocated
deviations): **1 Critical, 9 High, ~19 Medium, ~40 Low, ~7 Nit** — plus **2 High + 1 Low** added by
the empirical run (E1: memory cap doesn't bound guest RAM; E2: FC warm restore broken; E3: `/tmp`
per-VM dir leak). See the **Empirical validation** section.

The throughline is the rubric's Part-A/Part-D thesis: the remaining defects are overwhelmingly in
**paths no test executes** and **gates that don't run**. The code is good; the *evidence that the
code is good* is weaker than it looks.

---

## Empirical validation (Review 37a — privileged + rootless run, 2026-06-29)

After the static review, the capability runner was blessed (`just bless`), so the host-facing
suites were executed on this KVM host (CH 0.15-era + Firecracker + QEMU all installed; runner
`+ep`; artifacts in `target/imp-artifacts`). Both suites ran under a freshly delegated domain scope
(`systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh …`); the privileged
suite was run with **all three backends** (`--features firecracker,qemu`) to also cover the
"FC/QEMU never exercised in CI" gap (P30). `fail-fast=false`, so per-test failures are isolated.

| Suite | Backends | Result |
|---|---|---|
| Privileged (`test-priv`) | CH + FC + QEMU | **124 run: 120 passed, 4 failed, 8 skipped** (85 s) |
| Rootless (`test-rootless`) | CH / smoltcp | **8 passed, 0 failed** (99 unit tests filtered) |

**What passed (host paths now empirically validated):** boot, concurrency (distinct
CID/VMID/socket), `egress_proxy`, `put_file`, `host_endpoint`, `force_kill`, **`panic_residue`
(zero netns/cgroup/tap/socket/CID/VMID residue)**, `nested_virt`, `shares_ro_rw` across CH/FC/QEMU;
**`snapshot_restore::cloud_hypervisor`** (create → restore → CID/MAC/vsock rotation → clock resync →
CSPRNG reseed); the rootless smoltcp NAT + MITM proxy. The CH happy paths are solid.

**Retired assumption:** the do-not-re-report list carried "warm snapshot/restore vsock re-bind is a
known gap on CH." **CH `snapshot_restore` now passes end-to-end** — that gap appears resolved for CH;
update the impl-notes accordingly.

### Three new findings the static pass could not see

#### E1 — [High, confirmed-by-test] The per-VM `memory.max` does not bound guest RAM: `metrics_limits` fails on all three backends
*correctness / A2·§7 · `tests/metrics_limits.rs:200`, `src/vmm/cloud_hypervisor.rs:285`, `src/metrics.rs:181–206`*

`metrics_limits::{cloud_hypervisor,firecracker,qemu}` all FAIL identically. The test's earlier
preconditions **pass** — the per-VM cgroup is created, the controller is delegated, and
`memory.max` reads back as the **256 MiB** cap — but the OOM assertion fails:

```
memory bloat exec exit code: 137
panicked at tests/metrics_limits.rs:200:
  cgroup memory.max (256 MiB) must be the BINDING limit: expected memory.events oom_kill > 0
  at .../imp-vm-222/memory.events, got 0
```

The guest was given **512 MiB** guest RAM under a **256 MiB** cap; it touched ~512 MiB and was
killed by its **own** in-guest OOM (clean exit 137) while the host cgroup's `oom_kill` stayed **0**.
That is conclusive: ~512 MiB of guest pages were faulted without the 256 MiB cgroup cap ever firing,
so **guest RAM is not charge-bound by the per-VM `memory.max`.** The limit is *configured* but
*ineffective* — the density/isolation guarantee the limit is meant to provide does not hold.

This reproduces on CH, FC, **and** QEMU (three different memory backends), so the cause is host-side,
not per-VMM. The leading hypothesis is the default guest-RAM backing: `cloud_hypervisor.rs:285` sets
`shared: !cfg.ksm_mergeable` → **`true`** by default, so guest RAM is shmem/memfd-backed; cgroup v2
reclaims shmem under `memory.max` pressure rather than OOM-killing, so the cap throttles but never
hard-bounds the guest. (Distinct from H-FAILLOUD-1, which is the *un-delegated-controller* path —
still untested because here the controller *was* delegated.)

*Direction:* verify the guest-RAM charge path (sample `imp-vm-*/memory.current` peak during the
bloat); for a hard cap, either back guest RAM with anonymous memory when a `mem_max` limit is
requested, or charge the memory backing to the per-VM cgroup, or set `memory.swap.max=0` +
`memory.oom.group=1`. Until then, the documented memory cap is not a hard limit — and the
`metrics_limits` "limits enforced" guarantee is currently **red** on a correctly-delegated host.

#### E2 — [High, confirmed-by-test] Firecracker warm restore is broken: connection dropped on the first post-restore exec
*correctness / §9.2 · `tests/snapshot_restore.rs:139`, `src/vmm/firecracker.rs:462–531`*

`snapshot_restore::firecracker` FAILS (1.0 s): `called Result::unwrap() on an Err value:
Agent("Connection dropped during exec")` on the first post-restore exec, whereas CH passes the same
test. The guest agent's vsock connection does not survive FC restore (or the post-restore resync
exec dies immediately). This is the empirical manifestation of the FC restore path that ignores
`_cfg`/`restore_mode` (M-VMM-1) and the broader restore-resync fragility (M-RESTORE-1: the first
post-restore exec is exactly where the freshly-rebound listener is flakiest, and a failure there is
unrecovered). FC warm restore does not work end-to-end on this host; the capability is advertised
(`capabilities().snapshot_restore` for FC) but the path fails.

*Direction:* investigate the FC vsock device re-creation on `/snapshot/load` and the guest
re-bind/reconnect handshake (mirror whatever makes CH pass); make the first post-restore exec
recoverable (see M-RESTORE-1) so a transient reconnect failure retries instead of dropping. Either
fix it or gate FC `snapshot_restore` off until it does.

#### E3 — [Low, confirmed-by-test] Per-VM `/tmp/imp-vm-{pid}-{vmid}` directories leak on teardown
*correctness / B1 · `src/vmm/mod.rs:130`*

After a clean run (no orphan processes, no leftover netns/cgroups), **36 `/tmp/imp-vm-{pid}-{vmid}`
directories remained**, each holding `serial.log` (+ `api.sock.lock` for CH). `vmm/mod.rs:130`
creates the per-VM dir with a bare `std::env::temp_dir().join(format!("imp-vm-{}-{}", pid, vmid))` —
not a `tempfile::TempDir` — and nothing removes it on teardown. The ordered `Drop` removes the vsock
*socket* but not its parent *directory*, so `/tmp` accumulates one dir per VM, unbounded across runs.
The passing `panic_residue` test asserts the socket is gone but never checks the directory, so it
stays green while the leak grows.

*Direction:* own the per-VM dir as a `tempfile::TempDir` on the instance (auto-removed on `Drop`), or
add an explicit `remove_dir_all` to the teardown sequence; extend the panic-residue assertion to the
directory. If `serial.log` is intentionally retained for post-mortem, write it outside the per-VM
dir under a capped, swept location.

### Empirical status of the prior findings

- **Validated happy-paths:** B1 ordered teardown (panic-residue zero residue, minus E3); N-VM
  concurrency; CH snapshot/restore + rotate/reseed/resync; the rootless egress proxy + smoltcp NAT.
- **Confirmed as genuine untested-path gaps** (a green run never exercises them, which *is* the
  finding): H-QEMU-1 (vsock-daemon leak — error path; no orphan procs after a *successful* run),
  H-NET-1/H-NET-2 (the rootless reclaim test uses `stream=None`, so the live-stream leak path stayed
  untested), H-PROXY-1 (every privileged egress test sets `http_proxy` or uses the rootless NAT — the
  transparent TPROXY path was never hit), H-PROXY-2 (deny-list bypass), H-CACHE-1, H-TEST-1.
- **Still unverified by tests:** H-FAILLOUD-1's undelegated-controller no-op (the run had the
  controller delegated, so the silent-`Ok` failure path did not execute) — E1 is the related, *now
  empirical*, enforcement gap.

---

## Critical

### C-GATE-1 — `just ci` and the CI lint job short-circuit at the known-red feature-powerset step; the supply-chain, API, lean-target, and (locally) unit gates never run
*Category: test-gap / Part D · `.github/workflows/ci.yml:34–56`, `justfile:36–41`*

The lint job runs steps in this order: `rustfmt` → `clippy --all-features` → **`cargo hack
--feature-powerset` (line 34, no `continue-on-error`, no `if: always()`)** → `cargo deny` (37) →
lean-agent invariant (40) → `ban-global-state` (51) → `semver-checks` (54). The powerset step is a
**documented, accepted-debt RED** (the `host-common` module-gating problem; confirmed: `cargo check
--no-default-features --features cloud-hypervisor` exits 101). GitHub Actions stops the job at the
first failed step, so **`cargo deny`, the lean-agent build, the global-state ban, and
`semver-checks` never execute in CI.** In the `justfile`, `just` halts on the first failing line, so
`just ci` dies at line 36 and never reaches `cargo deny` (37), the lean-agent tree grep (39), the
ban script (40), or `cargo nextest` (41) — **the local "ci" gate runs neither the supply-chain
checks nor the unit suite.**

**Why it's the worst finding:** for a project whose entire quality thesis is "green must mean
something," this makes green meaningless for the very gates the rubric's Part D exists to enforce. A
GPL/unvetted crate, an un-ignored advisory, a `#[non_exhaustive]`-omission API break, or a
re-coupled lean agent all merge while CI shows the *expected* "red on powerset."

**Red test it lacks:** add a GPL crate or an un-ignored advisory — `cargo deny` would fail, but its
step is unreachable, so the violation lands with CI showing its usual powerset red. Nothing guards
this.

**Direction:** move the accepted-debt powerset step to the **end** of the job (or give it
`continue-on-error: true` / a separate non-blocking job), and reorder/guard the `justfile` `ci`
recipe so the reachable gates actually run and report their true status independent of the powerset
debt.

---

## High

### H-FAILLOUD-1 — The fail-loud capability contract (§7.1) is unimplemented: requested cgroup limits silently no-op; no typed error, no host probe, no `limits_enforced` flag
*Category: divergence / A2·B2·B8 · `src/metrics.rs:106–131, 181–206`, `src/error.rs:6–88`, `src/orchestrator.rs:426,758`*

This is the rubric's #1 named target and the design's §7.1 hard contract, and it is absent:

- `try_apply_limit` (metrics.rs:112) is doc-commented "Best-effort"; on a failed
  `std::fs::write(memory.max/cpu.max/pids.max/io.max)` it only `tracing::warn!`s, then
  `create_slice` returns **`Ok(())` unconditionally** (line 206). A VM whose requested
  `memory.max` was rejected (EOPNOTSUPP on an undelegated controller) runs **unlimited** while the
  caller gets `Ok`. Per §7.1 rule 2 / rubric B2, a *requested functional* limit must fail loud.
- `error.rs` has only `Unsupported { vmm, feature }` (backend-feature-shaped). There is **no**
  `Error::CapabilityUnavailable { op, needed }`. Grep confirms `CapabilityUnavailable`,
  `HostCapabilities`, and `limits_enforced` appear **nowhere** in `src/` or `tests/`.
- `ResourceUsage` has **no `limits_enforced`** flag (§7.1 rule 3 / design line ~624 specifies one),
  so the observational side cannot surface that enforcement was absent; `usage()` even returns
  `Ok(ResourceUsage::default())` (all zeros) when no cgroup is attached.
- `ResourceUsage::net_rx_bytes`/`net_tx_bytes` are **always 0** (metrics.rs:253) — never read,
  which rubric B8 and design §7 explicitly forbid ("an unread counter is the same lie as a missing
  one"). (The *architectural* reason — `read_stats` only has the cgroup name, not a netns handle —
  is defensible and is recorded in impl-notes; the always-zero public field is not.)

**Red test it lacks:** `FakeCgroupFs::create_slice` hardcodes `Ok`, and `DefaultCgroupFs` can't be
unit-driven against `/sys`. A `CgroupFs`/integration test asserting `create_slice` returns
`Err(CapabilityUnavailable)` on an undelegated `memory` controller would go red on today's code.

**Direction:** add a matchable `Error::CapabilityUnavailable { op, needed }`; make a *requested*
limit that cannot be enforced (after confirming the controller is in the parent's
`subtree_control`) return it rather than warn-and-`Ok`; add a `limits_enforced` flag for the read
path; populate net counters or delete them. `cpufreq`/KSM stay best-effort (they must keep their
visible `warn!`). impl-notes (~line 921, 1278) flags this as "pending migration"; v13 §7.1 now makes
it a hard contract, so it is a reportable gap, not a closed item.

### H-NET-1 — smoltcp permanent forward-port listener reuses a stale host `TcpStream` after a guest-side close, cross-wiring subsequent connections
*Category: correctness / B1 · `src/net/smoltcp.rs:663–676, 735–738`*

On `!socket.is_open()` for a permanent mapping the code re-arms the listener (`socket.listen(port)`)
**without clearing `tcp_stream`**; `*tcp_stream = None` is reached only inside the active block on
`closed`. A guest RST / guest-first close drives the smoltcp socket to `Closed` with the host stream
still `Some`, so the next accepted connection reuses the **old** host stream.

**Red test:** establish a permanent `NatPortMapping`, close the smoltcp socket via guest RST,
re-listen, accept a new connection, assert it dials a **fresh** host stream. `test_egress_proxy_rootless`
passes only coincidentally (<16 connections, server-closes-first).

**Direction:** on any transition to `!is_open()` (both the re-listen and `continue` branches),
`tcp_stream.take()` + `shutdown()` before re-arming.

### H-NET-2 — smoltcp closed *dynamic* mapping with a live host stream is never reclaimed; defeats the NET-5 cap and permanently wedges new-port interception
*Category: correctness / B1 · `src/net/smoltcp.rs:668–672, 336–352`*

The `else { /* NET-5: leave closed so it can be reclaimed */ continue; }` branch does **not**
`take()`/close `tcp_stream`. Reclaim eligibility is `let live = stream.is_some() ||
socket.is_open();` — so a closed dynamic mapping whose stream is still `Some` is counted **live** and
never freed. After 256 such mappings the pool is full and growth is refused forever, so new
destination ports silently stop being intercepted (A2 silent degradation) — the exact DoS the
NET-5 cap was meant to prevent, now self-inflicted by a leak.

**Red test:** in `reclaim_and_has_room`, push a closed dynamic mapping with `stream = Some(..)` and
assert the pool shrinks. The existing `reclaim_removes_closed_dynamic_sockets_but_keeps_permanent`
only uses `stream = None`, so the leak path is untested.

**Direction:** same root cause as H-NET-1 — `take()`/shutdown the stream when a dynamic socket goes
`!is_open()` before `continue`; add the `stream = Some` reclaim case to the unit test.

### H-PROXY-1 — Privileged TPROXY egress front-end is non-functional and untested (listener is not `IP_TRANSPARENT`; hudsucker has no transparent intake)
*Category: divergence / A3·B7 · `src/proxy/mod.rs:131–132`, `src/orchestrator.rs:347,357`*

The proxy binds a plain `TcpListener` with no `IP_TRANSPARENT`, yet the privileged orchestrator
path emits `nft ... tcp dport {80,443} tproxy to :<port>`. hudsucker is an explicit-proxy MITM
(expects `CONNECT`/absolute-form), so transparently-redirected packets won't be intercepted —
TPROXY without `IP_TRANSPARENT` on the listener cannot recover the original destination.
Requirement #4 ("the VM's web access goes through a transparent proxy; tests can filter and log all
web access") is **mandatory**, and **no test exercises it**: every Privileged-path test
(`lifecycle.rs:266`, `snapshot_restore.rs:58/180`) uses `Egress::Open`.

**Red test:** a Privileged+Filtered boot that `curl`s a host **without** setting `http_proxy`
(the real transparent scenario) would fail (connection refused / not MITM'd).

**Direction:** set `IP_TRANSPARENT` on the listening socket (e.g. via `socket2` before bind) and
recover the original destination from the transparent socket, **or** document that the privileged
mode is an explicit-proxy MITM and must steer the guest to the proxy explicitly. Either way, add a
Privileged+Filtered integration test.

### H-PROXY-2 — Egress deny-list match is case-sensitive and ignores a trailing dot — trivial filter bypass
*Category: correctness / B7 · `src/proxy/doubles.rs:46–49`*

`is_blocked` does `host == domain || host.ends_with(&format!(".{domain}"))` with no normalization.
The doc claims label-boundary matching (and it correctly avoids the `notexample.net` over-block),
but a guest reaches a blocked domain by **upper-casing** the host (`EXAMPLE.NET`) or **appending the
FQDN root dot** (`example.net.`). For a filter that is a mandatory security requirement, this is a
real bypass.

**Red test:** `assert!(is_blocked("EXAMPLE.NET", &["example.net".into()]))` and
`assert!(is_blocked("example.net.", &["example.net".into()]))` — both return `false` today.

**Direction:** lowercase both sides and strip a single trailing `.` on the host before the existing
label-boundary check; extend `is_blocked_matches_label_boundaries` with these cases.

### H-CACHE-1 — `guest_agent_src_hash` covers only the bin wrapper, not the agent implementation it links → a stale agent is baked into the rootfs
*Category: correctness / B4·B5 · `src/artifact/mod.rs:227,242–245,432`, `src/artifact/guest_agent.rs:25–32`, `src/bin/imp-guest-agent.rs:4–5`*

`guest_agent_src_hash()` hashes only `src/bin/imp-guest-agent.rs`, but that binary links the real
logic (`use imp_testing::agent::{ReaperCoordinator, exit_code_from_termination}` and
`agent::protocol`). `ResolvePinsStage` folds only that one file into the pins, and the
`GuestAgentStage`/`RootfsStage` cache keys fold only that pin. Editing `src/agent/mod.rs` (e.g. the
reaper or the post-restore vsock re-bind) leaves the hash unchanged → all three cache keys hit →
the agent stage is skipped → a **stale agent binary is re-baked into `rootfs.erofs`.** This is
precisely the "stale agent baked into the rootfs is the tell" case rubric B4 names.

**Red test:** mutate `src/agent/mod.rs`, assert the rootfs cache key changes. Existing tests only
mutate a temp file's bytes or compare pin strings, so none catch the multi-file gap.

**Direction:** hash the full source closure the binary compiles from (`src/agent/**/*.rs` +
`src/bin/imp-guest-agent.rs`, ideally + the agent's `Cargo.lock`), or hash the built binary's input
closure; add an e2e "edit `agent/mod.rs` → rootfs key changes" test.

### H-AGENT-1 — `AgentClient::put_file` bypasses the documented desync fail-loud protocol (neither checks nor sets `desynced`)
*Category: correctness / A1·A6 · `src/agent/mod.rs:378–415` (field doc 166–171; `exec` guard 309–372)*

The `desynced` field is documented "a desynced stream may still hold a late frame… further requests
fail loud until `reconnect()`," and `exec()` honors it (early-`Err` if set; sets it on
timeout/error). **`put_file` does neither** — it neither returns early when `self.desynced` nor sets
`self.desynced = true` on its own send/decode error or timeout. So after an `exec()` timeout,
`put_file` proceeds on the desynced stream and can read a stale `Exit(0)` frame as its ack
(wrong `Ok`); symmetrically, a `put_file` timeout leaves `desynced = false` so the next `exec()`
misreads the stale `put_file` ack as its result.

**Red test:** after an `exec()` timeout, assert `put_file` returns `Err`; after a `put_file`
timeout, assert the next `exec()` returns `Err`. Both go red today.

**Direction:** mirror `exec()` — early-`Err` when `desynced`, set `desynced = true` on any
send/decode error or timeout. Better: a shared helper so every request method participates.

### H-QEMU-1 — `spawn_qemu` leaks the `vhost-device-vsock` daemon on every error path after it spawns
*Category: correctness / A4 · `src/vmm/qemu.rs:137–154,156–160,289–310`*

`vsock_daemon` is a tokio `Child` with **no `kill_on_drop`**; `vsock_pgid` is captured (line 144)
but **never used at any reap site**. After the daemon is healthy, three reachable error paths
(`fs`-daemon `?` at 158, `add_task` fail at 301, `qmp` `wait_for_socket` fail at 307) call
`reap_process_group(process, pgid)` — which kills **only QEMU's** group — then drop `vsock_daemon`
without SIGKILL. Since `QemuInstance` (whose `Drop` reaps the vsock group) is never constructed on
these error paths, the `vhost-device-vsock` process group is orphaned. The in-code comment at
295–297 even states "any error must reap the spawned VMM group" yet omits the second daemon. (Three
independent verifiers confirmed.)

**Red test:** force `wait_for_socket(qmp)` (or the fs-daemon step) to fail after the vsock daemon is
healthy; assert no orphaned `vhost-device-vsock` process / that `vsock_pgid` was reaped.

**Direction:** own the `vhost-device-vsock` `Child` in an RAII guard (or reap via `vsock_pgid`)
**before** the subsequent fallible steps. *Siblings of the same A4 class (Medium):* CH `create()`
leaks the CH VMM if a `virtiofsd` share fails to start after `spawn_ch` (cloud_hypervisor.rs:242–258);
`NetNamespace::create` leaks the netns + persistent tap if `setup_tap` fails after `add_netns`
(net/tap.rs:358–373).

### H-TEST-1 — The false-127 reaper coordination (`ReaperCoordinator` + `exit_code_from_termination`) has zero unit tests
*Category: test-gap / A7·A9 · `src/agent/mod.rs:35–44,73–142`, `tests/exec_vsock.rs:8–86`*

`exit_code_from_termination` and `ReaperCoordinator` (record_exit / wait_for / prune) are pure,
KVM-free seams — exactly the §4.3/AGENTS.md "PID-1 reaper must not steal the child's exit status
(false 127)" contract — yet **nothing drives them**. The one mock (`test_exec_vsock_mock`) never
exercises the reaper, multi-pid claim ordering, or timeout.

**Red test:** change `128 + signal` to `127`, or make `wait_for(pid)` return any recorded status
(the steal), or make `exit_status.unwrap_or(1)` be `unwrap_or(127)` — **no existing test goes red.**

**Direction:** add a default-suite `#[cfg(test)]` module in `src/agent/mod.rs`:
`exit_code_from_termination` across signal/exit/indeterminate (signal 9 → 137), `ReaperCoordinator`
no-steal on out-of-order pids, bounded-prune, and waiter-protection. (Related Low: P14 — a status
can be pruned before its waiter registers under a >1024-reap flood; self-heals via host timeout.)

---

## Medium findings, by area

### Snapshot / restore correctness (§9.2)

- **M-RESTORE-1 — the `restored` flag is cleared *before* the resync runs, so a transient
  first-exec error permanently skips clock/RNG/MAC resync.** (`src/orchestrator.rs:646,654–682`;
  reported from two domains, same root cause.) `self.restored = false` is set up front, then the
  first post-restore `agent.exec("date -s …")` uses a hard `?`. If that exec errors (and the
  freshly-rebound guest vsock listener is flakiest exactly then), the next `agent()` call returns
  the cached client with `restored == false` and performs **no** clock resync, **no** entropy
  reseed, **no** MAC rotation — though §9.2 requires all three "on every restore." *Direction:*
  clear `restored` only after the full resync block succeeds (or make it idempotent and keep the
  flag set on failure). No test guards it.
- **M-RESTORE-2 — Firecracker `snapshot()` writes the mandatory restore sidecar best-effort and
  returns `Ok` even when the write fails.** (`firecracker.rs:645–663`; `restore()` hard-requires it
  at 481–483.) A snapshot reported successful can be unrestorable; the failure only surfaces later
  as a confusing `restore()` error. *Direction:* the sidecar is part of the artifact — propagate
  the write error.
- **M-RESTORE-3 — the snapshot-eligibility law's third boundary is incomplete.** `config::build()`
  rejects snapshotting + virtio-fs rootfs and + any data share but **not** + `NetConfig::Rootless`
  (the rootless vhost-user-net is a vhost-user device) — third §3.3 case unenforced at the first
  boundary, no negative test (`config.rs:375–390`). FC `restore()`/`snapshot()` have **no**
  vhost-user self-guard and FC `snapshot()` also omits the `capabilities().snapshot_restore` check
  (`firecracker.rs:462–476,623–643`), where CH has both. CH `snapshot()` also omits the
  `snapshot_restore` capability self-check and CH `restore()` guards data shares but not a
  virtio-fs *rootfs* (`cloud_hypervisor.rs:483–492,390–399`). Not exploitable today (FC can't
  attach vhost-user), but §3.3 explicitly requires every backend to self-guard. *Direction:* mirror
  CH's `has_vhost_user_device` guard on FC; add the missing capability checks; add the Rootless
  negative test at `build()`.
- **M-TEST-RESTORE — the `snapshot_restore` MAC/vsock "rotation" assertions are flaky and can pass
  on a no-op.** (`tests/snapshot_restore.rs:254–260,280–284`.) Both `assert_ne!` compare against a
  pre-restore value, but MAC (`mac_math(vmid)`) and vsock path (`imp-vm-{pid}-{vmid}`) are pure
  functions of `vmid`; the original VM is shut down (freeing its vmid) before restore, and
  `allocate()` picks a pseudo-random start that can re-hand the same vmid → identical MAC/path →
  spurious failure ~1/254, **and** the test can pass even if rotation didn't run when a different
  vmid happens to be handed out. The CID assertion was already relaxed for this reason; MAC/vsock
  were not. *Direction:* assert `post_mac == mac_math(new_vmid)` and that the rotation command
  actually ran, or hold the original vmid across restore.

### VMM backends

- **M-VMM-1 — Firecracker advertises `lazy_restore: true` (UFFD) but `restore()` ignores
  `restore_mode` and hardcodes `backend_type: "File"`** (`firecracker.rs:536–544,462–468,506–531`).
  A dead/lying capability flag: `RestoreMode::Lazy` silently degrades to eager on FC. The CH
  lazy-restore plumbing fix (impl-notes ~783) was CH-only; FC was left advertising the same flag.
  Effect is a misleading benchmark + silent config drop (not a crash), and nothing currently
  consumes FC's `lazy_restore`. *Direction:* wire a real UFFD backend for `Lazy`, or set FC
  `lazy_restore: false` and record it.
- **M-VMM-2 — QEMU silently swallows a `vhost-device-vsock` spawn failure (`.ok()`) and falls back
  to a root-only internal vsock** (`qemu.rs:137–142,193–197`), with no `warn!`. A missing/broken
  daemon binary re-emerges only as a later agent-handshake timeout — the "checked before a timeout
  masks it" A1 rule. *Direction:* surface a typed `Err` or at least a visible `warn!`.
- **M-VMM-3 — QEMU's single-line QMP read can capture an async `{"event":…}` instead of the command
  return, masking a command error** (`qemu.rs:81–87,94–98`); `check_qmp_reply` also uses
  `contains("\"error\"")` (brittle substring). *Direction:* loop reads skipping `event` lines until
  the `return`/`error` reply (ideally correlate by id); parse JSON for a top-level `error`.

### Config

- **M-CONFIG-1 — the documented `ksm_mergeable ⊥ vhost-user` incompatibility is not enforced at
  `build()`** (`config.rs:33–38,333–339,416–429`). `builder().ksm_mergeable(true)` combined with a
  VirtioFs rootfs / Rootless net / shares builds `Ok` and fails late at the VMM
  (`cloud_hypervisor.rs:285–286` sets `shared: !ksm_mergeable` while attaching a vhost-user device).
  *Direction:* enforce in `build()` with a negative test, or record the backend as the intended
  enforcement point in impl-notes (currently neither).

### Pipeline, cache & provenance

- **M-PIPE-1 — `reset_to` silently ignores `remove_file` failures (`let _ =`), so it can report
  success while leaving a valid cached artifact** (`artifact/mod.rs:391,394`) — the next `build()`
  then serves the stale artifact. `reset_to`'s contract is to invalidate; a failed removal must not
  be `Ok`. *Direction:* propagate the error (or `warn!` + justifying comment).
- **M-PIPE-2 — the mmdebstrap builder base falls back to a hardcoded `debian` image + digest,
  masking a missing Stage-0 pin** (`rootfs/mmdebstrap.rs:32–43`); image and digest default
  *independently*, so a half-specified pin set yields a mismatched reference. The kernel input
  already errors on a missing pin. *Direction:* treat a missing builder base as `Error::Artifact`;
  pair image+digest atomically (B5 "no fallback masking a missing upstream").
- **M-PIPE-3 — `parse_pins_json` swallows malformed-JSON errors → empty pins** (`artifact/mod.rs:168`),
  so a tampered/garbled `pins.json` degrades to an empty map and only fails later with a misleading
  "Missing X pin." *Direction:* make pin ingestion fallible (A8 — verify what you ingest).
- **M-PIPE-4 — labelled `KernelStage`s all share `name() == "kernel"` and register under a generic
  `"kernel"` key, so a multi-kernel `Artifacts` map collapses to one entry** and `reset_to` can't
  target one (`kernel.rs:88,290`, `bin/imp-testing.rs:102`). Currently masked because callers read
  by filename, but the public `Pipeline::build` contract silently loses entries. *Direction:* derive
  `name()` and the artifact key from the label.

### Privileged window (cap runner)

- **M-RUN-1 — the `test-runner` feature pulls `tracing` + `tracing-subscriber`, violating the
  "rustix+capctl only" dependency-thin contract** (`Cargo.toml:184`, `imp-test-runner.rs:64` says
  "No tracing-subscriber here" and uses `eprintln` only). The deps look copy-pasted from the
  `agent` line. *Direction:* drop them; add a lean-runner CI invariant mirroring lean-agent
  (see C-GATE-1 / the gate section). `libc` is defensible if `rustix` lacks `setres*/setgroups` —
  confirm or record.
- **M-RUN-2 — `ensure_under_cargo_target_dir` confinement is near-meaningless**
  (`imp-test-runner.rs:51–61,234–238`): it accepts any path with a component literally named
  `target` — `/home/target/evil`, `/tmp/x/target/../../usr/bin/sh` — with no `canonicalize()` and
  no `..` rejection, then execs with the three ambient caps. Design calls this defense-in-depth (so
  not Critical), but it currently provides essentially none. *Direction:* canonicalize, reject
  `..`/symlink escapes, verify the resolved path is a descendant of the real cargo target dir.

### API hygiene & error type

- **M-API-1 — `Pipeline` leaks internals via `pub stages`/`pub target_dir` and most artifact public
  types omit `#[non_exhaustive]`** (`artifact/mod.rs:248–253,61,71,81,106`). `Pipeline` has no
  constructor and is built by struct literal; a caller can mutate `pipeline.stages` to bypass the
  "Stage 0 resolves pins" invariant undetected. Rubric B8 names `pub Pipeline.stages` specifically.
  *Direction:* private fields behind `Pipeline::new` + `add_stage`; `#[non_exhaustive]` on the
  growable `StageInputs`/`StageOutputs`/`Artifacts`/`CacheKey`.

### FS / virtio-fs

- **M-FS-1 — virtiofsd runs under `SUDO_UID`/`nobody`, not a dedicated per-share uid**
  (`fs.rs:73–78`). Two real risks: the `nobody` (65534) fallback (root without `SUDO_UID`, e.g. CI
  `su`) can `EACCES` on a root-owned share; and dropping to `nobody` before exec may strip the
  privilege needed to enter `--sandbox=namespace`. The design (line ~221) and rubric B9 require a
  dedicated low-priv uid per daemon so it "can reach only its one directory." (The inline comment
  references a non-existent impl-notes seam.) *Direction:* allocate a reserved service-uid range
  alongside CID/VMID, or record the deviation.
- **M-FS-2 — the in-process FUSE backend panics via `expect()` on guest-driven queue dispatch, and a
  thread panic leaves a false-ready daemon** (`fs/in_process.rs:196,272,259`). `handle_event` is
  invoked by the vhost-user framework on a guest queue kick — `vrings.first().expect(...)` is a
  guest-drivable panic (A1). Worse, `Listener::new(socket_path, true)` creates the socket
  synchronously *before* the thread runs, so a thread-panic at `VhostUserDaemon::new` still leaves
  `socket_path.exists() == true` and `fs.rs::start()` returns `Ok` with a dead daemon. *Direction:*
  typed `io::Error` on the dispatch path; readiness must confirm the daemon is actually serving, not
  trust socket existence. (`experiment-fuse`-gated.)

### Networking (privileged) & CLI/bench

- **M-NET-3 — `NetNamespace::delete` is not idempotent; `Drop` re-deletes after an explicit
  `delete()`, logging a spurious teardown WARN on every VM teardown** (`net/tap.rs:379–383,429–441`,
  `orchestrator.rs:799–801`). The false warning defeats the NET-8 rationale and masks genuine
  teardown failures. *Direction:* a `deleted` guard.
- **M-CLI-1 — `bench-vm` exits 0 (silent success) on an unknown/feature-disabled `--backend` and on
  an unknown `--mode`** (`bin/bench-vm.rs:319–322,341–344`) — `println!` then `Ok(())`. A
  CI/script typo or a feature-gated build reads as success. *Direction:* `bail!`/typed `Err` →
  non-zero exit. (Related Low: P22 — `bench-vm` `.expect()`s on a `--mem-mib` below the documented
  floor with a misleading "benchmark invariant" message.)

---

## Low & Nit (condensed)

Reported but lower-impact; grouped. Full per-item detail (location, evidence, red-test, direction)
was captured during the review; the high-signal ones:

- **smoltcp:** `process_tx_queue` allocates a guest-controlled `vec![0; desc.len()]` (up to
  ~4 GiB) unbounded — bound it to MTU+hdr (smoltcp.rs:169–174); `exit_event` `.expect()`s on
  event-fd clone on a VMM-driven path (smoltcp.rs:237–242).
- **proxy:** the rootless proxy binds `0.0.0.0` on the host though the NAT only dials
  `127.0.0.1:<port>` — bind loopback in rootless mode (proxy/mod.rs:131).
- **cache/provenance:** cache-key fields are concatenated without delimiters (non-injective hash —
  kernel.rs:104–118, mod.rs:428); kernel-tarball extraction doesn't sanitize `..` components
  (defense-in-depth — kernel.rs:206–222); OCI layers with an unrecognized media type are silently
  skipped, risking an incomplete rootfs (oci.rs:40–49).
- **guest agent:** asymmetric frame caps — host `LengthDelimitedCodec` defaults to ~8 MiB, guest
  accepts 16 MiB (mod.rs:252, imp-guest-agent.rs:372–385).
- **cap runner:** the setuid form `setgroups(1,[gid])` drops the `kvm` group, so `/dev/kvm` access
  relies solely on incidental `CAP_DAC_OVERRIDE` (imp-test-runner.rs:113).
- **fs/cleanup hygiene:** `fs.rs` `try_wait().unwrap_or(None)` swallows an io error (line 123); a
  stale `// process: Child,` comment + duplicated `#[cfg]` (line 23); the `pre_exec` SAFETY comment
  overclaims async-signal-safety because `Error::other` heap-allocates on the error branch
  (lines 80,87).
- **docs:** `agent()` rustdoc has duplicate `# Errors` blocks and a stray mid-doc summary
  (orchestrator.rs:612–622); `config::build()` `# Errors` describes path-existence checks it never
  performs and omits every validation it does (config.rs:348–361); `tap.rs` docs still reference the
  `ip` CLI though the impl uses rtnetlink/netns_rs (tap.rs:99–104,378).
- **Error type:** ~12 per-subsystem variants carry `String` payloads rather than typed sources
  (error.rs:17–76). Mitigating — they *are* per-subsystem and there is **no** `Error::Other`
  catch-all — so this is reported as a code-quality opportunity, and the deliberate part is recorded
  in impl-notes (appendix).

---

## Test-discipline assessment (Part C)

**Overall:** the suite is much healthier than the prior passes — `vmm_matrix_test!`/`require_cap!`
correctly keep the CH primary path **unexempted** (a CH cap miss panics; others skip-with-reason),
`FakeVmm`/`FakeNetlink`/`FakeClock` exist, the ordered-Drop-on-panic tests assert a real sequence,
and the pipeline tamper/cache-hit/determinism trio runs on **real** stages with a golden key. But
several tests can pass on their own inverse, and one whole class is untested:

- **No test guards the false-127 reaper** (H-TEST-1) — the recurring class, still uncovered.
- **`tests/shares_ro_rw.rs` bypasses the mandated harness**: hand-rolled per-backend fns with a
  bare `return` skip for FC/QEMU instead of `vmm_matrix_test!`+`require_cap!` — the per-backend
  divergence the rubric says to eliminate (shares_ro_rw.rs:7–36).
- **Flaky / can-pass-on-no-op rotation assertions** (M-TEST-RESTORE) and a **coincidental-pass
  CSPRNG-reseed assertion**: `assert_ne!(pre_urandom, post_rng)` infers reseed from two independent
  `/dev/urandom` reads while the reseed itself is best-effort warn-and-continue
  (snapshot_restore.rs:320–356). Isolate the actual reseed signal (control vs. treatment, or a typed
  "reseed applied" result).
- **`egress_proxy` plain-HTTP host-service assertion checks only exit code, not body**
  (egress_proxy.rs:203–226) — weaker than the MITM/blocked assertions in the same file.
- **No-reason `#[ignore]`s** on `lifecycle.rs` force_kill/panic_residue and all of `shares_ro_rw.rs`
  (vs the harness's `#[ignore = "needs KVM"]`) — add reason strings so the skip rationale shows in
  `nextest --ignored`.
- **`tests/benchmark.rs` uses ad-hoc `#[serial_test::serial]`** though nextest's `serial-host`
  group already covers `binary(benchmark)` (Part C "serial from the group, not ad-hoc").
- **Coverage holes flagged for unit tests that should exist:** `--sandbox=namespace`/uid-drop/
  in-process-FUSE-RO-refusal (P18); `FakeNetlink::setup_tap` discards the `vmid` arg so
  wrong-vmid-into-tap-IP is untestable (tap.rs:468–479).

---

## Gate assessment (Part D)

| Gate | Status | Note |
|---|---|---|
| `clippy --all-features` + `fmt --check` | **Present** | ci.yml:28–32, `-D warnings` via RUSTFLAGS (line 14). |
| Build **and** clippy each target (host + agent + test-runner + guest-tools) | **Partial — gap** | Only `agent` is built+clippy'd+tree-asserted (ci.yml:40–49). **No** `test-runner` or `guest-tools` build/clippy/tree step exists anywhere (M-GATE: ci.yml:40–49, justfile:39). The review-34 broken-lean-build class is unguarded for two of three lean targets. |
| Lean-tree assertion (∌ tokio/hyper/rtnetlink) | **Partial / contradictory** | Present for `agent` only. For `guest-tools` the design §12.2 wording is *unimplementable* — `reqwest` pulls hyper+tokio — and the carve-out is unrecorded (relocated to impl-notes, appendix). |
| `cargo deny` (licenses + advisories + sources) | **Present but UNREACHABLE in CI** | C-GATE-1. Also **bulk-suppressed advisories**: deny.toml:33–48 has 16 `RUSTSEC-2026-xxxx` ignores with *identical* boilerplate naming no crate — the exact bulk/stale-but-unremoved pattern Part D forbids (the 2020/2023/2024/2025 entries are properly per-crate). |
| `cargo semver-checks` | **Present but UNREACHABLE in CI** | C-GATE-1 (and `just ci` omits it entirely). |
| nextest per-test timeout | **Present** | `.config/nextest.toml` (30s default, 120s integration). |
| `--ignored` integration matrix selects >0 | **Present (CH only)** | ci.yml:84–95 run both rootless and privileged with `--run-ignored all` and non-empty filters. **But** the recipes use **default features only**, so the `#[cfg(feature="firecracker")]`/`qemu` tests are compiled out — **only CH is ever exercised by integration CI** (P30). |
| Global-state grep ban | **Present, weak** | ci.yml:52 / `scripts/ban-global-state.sh`. The line-based regex is bypassable via a multi-line `static` decl or a `use … as` type alias, and scans only `src/` (P31). |
| Lint header (`lib.rs`) | **Present, matches rubric** | The required deny set + per-module `#![forbid(unsafe_code)]` on the I/O-free modules; `net_sys.rs`/`fs.rs` correctly carry the unsafe. |
| `just ci` == CI lint job | **Diverges** | justfile claims "everything the lint CI job runs" but only greps the agent tree (never compiles it), omits semver, and applies `-D warnings` via a clippy arg vs CI's RUSTFLAGS env (not equivalent for path-deps) — S28. |

---

## Rubric coverage matrix

| Part | Verdict | Summary |
|---|---|---|
| **A1** Fail loud/typed/early | **Concern** | Several silent-`Ok`/swallowed paths: M-VMM-2, M-PIPE-1, M-PIPE-3, M-CLI-1, fs.rs `try_wait`. |
| **A2** Best-effort is the rare declared exception | **Gap** | H-FAILLOUD-1 — the central violation; cgroup limits silently no-op. |
| **A3** Capabilities probed/reported (host too) | **Gap** | No `HostCapabilities` probe; H-PROXY-1 mode not validated up front. |
| **A4** Ownership cleans up on post-acquire failure | **Concern** | H-QEMU-1 + CH/netns leak siblings. |
| **A5/A6** Contracts self-guard; validate at boundary | **Concern** | M-RESTORE-3 (law not enforced at every boundary); M-CONFIG-1; M-FS-2 guest-drivable `expect`. |
| **A7** Determinism tested | **Pass-with-concern** | Trio runs on real stages; H-CACHE-1 (agent hash gap) + P9 (non-injective concat). |
| **A8** Verify what you ingest | **Concern** | M-PIPE-2/3 (fallbacks/malformed pins); P10/P11. |
| **A9** Fakes driven, not just present | **Concern** | H-TEST-1; FakeNetlink drops `vmid`. |
| **B1** Lifecycle/teardown | **Concern** | Happy-path Drop order correct; H-QEMU-1, H-NET-1/2, M-NET-3, P2. |
| **B2** Failure visibility | **Gap** | H-FAILLOUD-1; guest-drivable `expect`s (M-FS-2, P7). |
| **B3** Capability/input contracts | **Concern** | M-RESTORE-3; M-VMM-1 (dead flag); M-CONFIG-1. |
| **B4/B5** Determinism/caching/provenance & staging | **Concern** | H-CACHE-1; M-PIPE-1/2/3/4. |
| **B6** Concurrency/injected state | **Pass** | Injected allocators, no module-global state; ban script exists (if weak). |
| **B7** Module boundaries/duplication | **Concern** | H-PROXY-1/2; M-VMM-3 (QMP parser not shared). |
| **B8** Public-API hygiene | **Concern** | M-API-1; always-zero net fields; String error payloads (recorded). |
| **B9** Privileged window | **Concern** | M-RUN-1 (deps), M-RUN-2 (confinement), M-FS-1 (uid). |
| **Part C** Tests that can fail | **Concern** | See the Part-C section. |
| **Part D** Gates that run | **Gap** | C-GATE-1 (short-circuit) + the lean-target/advisory/CH-only-integration gaps. |

---

## Appendix — justified deviations relocated to `implementation-notes.md`

Per the review request, the following verifier-confirmed, defensible deviations were **recorded in
`docs/implementation-notes.md`** rather than reported as defects:

1. **Per-deployment MITM CA minting** — the freshly-generated CA makes `rootfs.erofs` non-byte-identical
   across independent builds; a reproducible CA *private key* would itself be a security defect, so
   per-deployment minting is correct. The §12.4 byte-identical-erofs claim is scoped to a fixed
   artifacts dir/CA.
2. **`Error` uses stringly per-subsystem payloads** (no `Error::Other` catch-all) — a deliberate,
   accepted shape; typed sources are a future refinement only where a real source exists.
3. **`guest-tools` legitimately uses `reqwest`** (pulls tokio/hyper) — the dependency-thin / lean-tree
   rule is scoped (per `AGENTS.md`) to `imp-guest-agent` + `imp-test-runner`, **not** the guest
   userspace helper; design §12.2's tree-assertion wording for `guest-tools` should be reconciled.
4. **Concurrent restore from a single snapshot is forward-work** — CH rewrites the shared
   `config.json` in place and FC rebinds the single baked vsock UDS path; per-clone COW + path
   allocation is the future fix. (Recorded as a known limitation, not a regression.)

These are documented there with their rationale; they are **not** counted among the reported
findings above.

## Note on the vendored `vhost*` crates

`vendor/vhost` and `vendor/vhost-user-backend` are the rust-vmm crates carrying the
QEMU-unprivileged `SET_VRING_ENABLE` protocol-features relaxation (design §10.5). They were not
line-reviewed. The carried patch is appropriately scoped (QEMU-unprivileged only, Apache-2.0,
covered by `cargo deny`); confirm the vendored revision is pinned to an exact upstream rev and the
patch delta is documented where the workspace references it.
