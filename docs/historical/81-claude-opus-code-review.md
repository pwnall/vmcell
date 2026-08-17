# vmcell — Code Review (docs/81)

A comprehensive review of the tree at `main` @ `7499cba` (`vmcell` 0.13.0 — the landed v30 delta
register plus the docs/78 fix waves, the completeness audit, the USB-teardown pass and the CI-repair
pass), against design v31 (`docs/79`), rubric v6 (`docs/75`), quality gates v4 (`docs/76`),
`AGENTS.md`, and `docs/implementation-notes.md`. Dated 2026-08-14.

**Method.** Fourteen independent area reviews over disjoint slices of the tree (config/naming,
orchestrator/teardown/zygote/lineage, privileged net + segments, the smoltcp NAT + proxy,
vmm-core/jail/CH/USB, host control plane, guest agent + guest-tools, the three secondary backend
crates, the artifact pipeline, the daemon tier, the privileged tier, the contract-surface consumers,
the gates themselves, and docs accuracy). Every finding was then handed to a **separate adversarial
verifier** instructed to refute it — to re-read the cited code, hunt for the missing check elsewhere
on the path, test the failure scenario for reachability, and check the item against
implementation-notes and design §17 before allowing it to stand. Items already recorded as justified
deviations or on the §17 register were excluded up front.

81 raw findings resolved to **76 unique defects** after merging four pairs that two disjoint areas
found independently (see "Convergent findings" below). Verdicts: **41 confirmed, 31 adjusted, 2
already-recorded, 2 refuted** — spanning **13 major, 48 minor, 15 note**. There is **no blocking
finding**: the one raised as blocking was adjusted to major on verification (its blast radius is one
backend/mode pair, and it fails loud rather than silently).

**Live validation (AGENTS rule 5 — executed, not presumed).** `scripts/review-preflight-priv.sh`
printed **READY**. Every suite was run on this host during the review:

| Gate | Result |
|---|---|
| `just ci` | green (incl. the 221-config feature powerset) |
| `just test-privileged` (delegated scope) | **156/156**, 299–304 s over two runs, no retries consumed |
| `just test-unprivileged` | **4/4** |
| `just test-daemon` | **14/14** |
| `just test-crosvm` (delegated scope) | **30/30**, 92 s |
| Skip manifest | **8 capability skips for `test-privileged` alone** — measured against a reset manifest, so the count is attributable: FC `unprivileged_vhost_user_net` ×4 / `nested_virt` ×2 / `virtio_fs_shares`, QEMU `usb_host_passthrough_no_designated_device`. All honest backend absences; none from a missing host facility. This is exactly the roster `ci.yml:281-283` and implementation-notes:3400-3404 record for the hosted runner. |

(The `5 skipped` in nextest's own summary line is a *different* quantity — tests the filter deselected
— and is not the capability-skip count. Conflating the two is how README's figure went stale; see
§7.2.)

`just test-usb-passthrough` was not run (it needs a designated `VMCELL_TEST_USB_DEVICE`; without one
`test-privileged` records the capability skip counted above, which it did). The working tree was
verified clean before and after the review.

**Verdict.** The tree is in strong shape and the disciplines it claims mostly hold where it claims
them — the area reviewers spent as much effort confirming invariants as breaking them, and §11 records
what they proved. The defects that matter cluster in four places, each one predicted by the project's
own doctrine:

1. **Accepted inputs that no datapath reads** — `Egress::Blocked` is a third spelling of `Open`;
   `nested_virt`/`RestoreMode::Lazy` are accepted on backends that advertise `false`. This is law F1
   ("honored or rejected at construction"), and it is the one place the *config* surface still lies.
2. **Unbounded waits at a control-plane edge** — crosvm bounds one of seven control ops; CH's
   guest-RAM-proportional `vm.snapshot` rides the generic 5 s ceiling; `connect_framed`'s deadline
   bounds the gaps between attempts, not an attempt. Design §9.4's "deadlines bound the whole
   operation" is the rule; these are its exceptions.
3. **Gates that cannot go red** — the OpenAPI parity gate compares the document to the table it was
   generated from and never to the router; crosvm's only confinement can be deleted with the whole
   opt-in matrix green; `ban-legacy-terms.sh` prints `scanned: crates justfile` while scanning zero
   bytes of the justfile. The CI-repair pass found five of these; the class is not exhausted.
4. **The daemon's `Registry`**, which is the youngest owning-lifetime code in the tree and carries
   four of the thirteen majors — three of them proven by the verifier with a *running probe*, not by
   inspection.

The doc debt is concentrated and mostly mechanical: the hosted-runner CI move landed in the README and
the job definitions but not in the design, the gate-spec doc, or four `ci.yml` comments.

---

## Convergent findings (independent confirmation)

Four defects were reported by two area reviewers who never saw each other's work. Convergence from
disjoint slices is the strongest evidence this method produces, and all four survived verification:

| Defect | Found independently by |
|---|---|
| `Egress::Blocked` is never matched in production | config review · privileged-net review |
| The P5 OpenAPI parity gate never reads the router | daemon review · gates review |
| crosvm's `effective_jail_config` **call site** is ungated | backends review · gates review |
| `RestoreMode::Lazy` / `nested_virt` accepted where the capability is `false` | vmm-core review · backends review |

---

## 1. Major — correctness

### M1 — `Egress::Blocked` is a silent no-op: a third spelling of `Egress::Open`
`crates/vmcell/src/config.rs:1079` · `crates/vmcell/src/orchestrator.rs:955,992`
*(CONFIRMED — both reviewers, both verifiers)*

`Egress` has three variants and `Blocked`'s rustdoc reads "All egress traffic is blocked." The only
two sites in the tree that consume `egress` are `setup_env`'s two arms, and both are
`if let Egress::Filtered(proxy_cfg) = egress { … }`. `Blocked` and `Open` therefore take the identical
empty else-path. On the privileged arm that means `ns.emit_proxy_rules(...)` (`orchestrator.rs:978`)
is never reached, so **no nft table is installed at all** and the per-VM netns keeps the kernel's
default `accept` policy — while `Filtered` installs `policy drop` admitting only tcp/80,443-via-TPROXY
and `gateway:proxy_port` (`net/tap.rs:657-671`). On the unprivileged arm, `host_services_port` is
still registered as a permanent NAT forward (`orchestrator.rs:1019-1021`).

`rg 'Egress::Blocked' crates/` returns the variant declaration and two constructions in the
root-re-export round-trip test (`lib.rs:208,221`) — which even asserts the `Blocked` config *builds*
and the value lands, so the variant reads as live. `VmConfigBuilder::build` does not reject it.

**Scope correction from verification:** `10.200.<n>.1` lives only inside the per-VM netns, so this is
not an arbitrary-egress leak. What `Blocked` exposes is exactly design §6.3's privileged
host-endpoint mechanism — a host process placed in that netns — which `Filtered` would drop. So
`Blocked` is strictly *more permissive than `Filtered`* and indistinguishable from `Open`.

**Fix — pick one, explicitly.** (a) Honor it: emit an accepts-nothing ruleset on the privileged path
(the `render_tproxy_rules` shape minus its two accept rules) and refuse to register
`host_services_port`/proxy forwards on the NAT path. (b) Refuse it at `VmConfigBuilder::build()` with
a typed error naming the variant, per F1's honored-or-rejected law. Either way the rustdoc must stop
claiming a property the code does not have, and the choice is recorded beside the `Egress::Open` /
H-NET-4 entry.
**Gate:** live — an in-guest dial to `10.200.<n>.1:<host_port>` fails under `Blocked` with the
identical dial under `Open` succeeding as the positive control (red today: both succeed). Under (b),
a KVM-free `config` test asserting the typed refusal with `Open`/`Filtered` building as the control.

### M2 — A QEMU + unprivileged control-plane re-spawn can never succeed
`crates/vmcell/src/net/smoltcp.rs:729-745` *(ADJUSTED from blocking — the failure is loud, and scoped
to one backend/mode pair)*

`SmoltcpProcess::start` binds the vhost-user UDS on the caller's thread (`:729`) and moves the
listener into a worker (`:732`) that runs `vu_daemon.start(&mut listener)` then `vu_daemon.wait()`.
The verifier read the vendored source: `start()` is `BackendListener::new(...)` + **one** `accept` +
`start_daemon` — there is no re-accept loop, and `BackendListener` `.take()`s the backend `Arc` on the
first accept, so a second accept could not be served even if one were attempted. `wait()` maps
`HandleRequest(SocketBroken)` to `Ok`, so a VMM hang-up ends the closure — and
`vendor/vhost/src/vhost_user/connection.rs:99-103`'s `impl Drop for Listener` **unlinks the path**.

`MicroVm::start`'s control-plane health gate (`orchestrator.rs:1160-1180`) exists to recover QEMU's
recorded ~11% `vhost-device-vsock` bring-up flake by dropping the instance and calling `vmm.create`
again on the *same* per-VM resources — and the NAT is one of those resources, held in
`staged.smoltcp` and deliberately not re-created. So on QEMU + `NetConfig::Unprivileged`, the first
VMM's exit destroys the NAT socket and every re-spawn dies on the 2 s socket wait, burning
`MAX_CONTROL_PLANE_RESPAWNS` attempts to report a control-plane error whose real cause is the
unlinked NAT UDS.

**Fix:** either re-accept in the vhost worker (a loop around `start`/`wait`, which also needs the
backend `Arc` restored), or re-create the `SmoltcpProcess` as part of the re-spawn and say so at the
site — today the re-spawn comment claims it "recreates on the SAME per-VM resources", which is
precisely why the NAT was overlooked.
**Gate:** a KVM-free test that drives `SmoltcpProcess::start`, connects and drops a client, and
asserts the socket path is still connectable; plus a live QEMU-unprivileged leg driving one forced
re-spawn.

### M3 — `Registry::snapshot` skips the reserved `.sha256` predicate
`crates/vmcell-daemon/src/registry.rs:290` *(CONFIRMED — verifier reproduced it with a running probe)*

`is_reserved_sidecar_name` is private to `artifact_store.rs` with call sites at `:69/:130/:156/:188`
(create/get/list/delete). `Registry::snapshot` validates with `validate_artifact_name` — which does
*not* carry the suffix rule — and then `self.artifacts.dir().join(artifact_prefix)`. So the
`.sha256` reservation AGENTS.md requires "on **every** verb" holds on four verbs and not the fifth.

The verifier ran it: `reg.snapshot(&id, "rootfs.sha256")` returned `Ok`, the directory exists, and
`delete`/`info`/`list` all report `NotFound` (the store hides sidecars) — **unreachable through every
verb, i.e. undeletable via the API**. Then `store.create("rootfs", b"body")` failed with
`Internal("cannot persist sidecar …/rootfs.sha256: Is a directory")` *with `rootfs` durably on disk*,
and the retry returned `AlreadyExists`. One authenticated request permanently breaks uploads of the
shadowed artifact name.

**Fix:** route the prefix through the same reserved-name predicate every other verb uses — promote
`is_reserved_sidecar_name` (or better, fold the rule into `validate_artifact_name` so a caller cannot
choose the weaker validator).
**Gate:** KVM-free — `snapshot(&id, "k.sha256")` returns `InvalidName`, with `snapshot(&id, "k")`
succeeding as the positive control.

---

## 2. Major — reliability

### M4 — `serve_engine` returns from `ShutdownAll` while dispatch tasks are still running
`crates/vmcell-daemon/src/bridge.rs:339-352` · `crates/vmcelld/src/main.rs:162-167,259-261`
*(CONFIRMED)*

Non-shutdown jobs are detached with `tokio::spawn(job)` (`:351`); `ShutdownAll` runs inline and
`return`s (`:346-350`) with no drain. `run_broker_child` then calls `libc::_exit(code)` immediately
after `serve_engine` returns, so the detached tasks are killed mid-flight and the registry `Drop`
never runs. `Registry::shutdown_all` only sees the table (`registry.rs:404-407`), while `create`
launches at `:204` and inserts at `:220` — a 16-line window covering the whole
`MicroVmLauncher::launch` → `MicroVm::start`. A VM booting inside that window is in nobody's table,
and `build_vmm_cmd` sets `process_group(0)` with no `PDEATHSIG` on the VMM, so it survives as an
orphan pinning guest RAM and `/dev/kvm` — **on the graceful path**, which is the one the broker's
SIG_IGN design exists to let win.

**Fix:** track the outstanding job handles and await them (bounded) before `ShutdownAll` returns, or
take a shutdown lock `create` also holds across the launch-and-insert window.
**Gate:** a daemon-suite leg that issues `create` and `ShutdownAll` concurrently and asserts no
orphan VMM process group survives — the shape `group_sigint_tears_down_vms_leaving_no_orphan_vmm`
already uses for the hard path.

### M5 — Every crosvm control op but one is unbounded
`crates/vmcell-crosvm/src/lib.rs:629-641` *(CONFIRMED)*

`run_control` is `Command::new(...).status().await?` with no timeout; `snapshot_take` (`:649-663`) is
the same shape. Callers: `boot()` (`:674`), `request_shutdown()` (`:679`), `pause()` (`:721`),
`resume()` (`:732`), `snapshot()` (`:750/751/759`). The only bounded one is `kill()`'s
`timeout(500 ms, run_control("stop"))` (`:684-688`) — one of seven.

The bound exists at no outer boundary either: `MicroVm::start` awaits `instance.boot()` bare
(`orchestrator.rs:1141`, and again in the respawn loop at `:1179`), `restore_inner` awaits `resume()`
bare (`:1376`), `snapshot` at `:1706`, and `shutdown()` awaits `request_shutdown()` (`:1796`)
**before** computing the ORCH-7 grace poll and before the guaranteed `inst.kill()` fallback (`:1815`)
— so a wedged `crosvm powerbtn` blocks the force-kill that is supposed to be unconditional, and the
VM's netns/tap/cgroup/scratch/vmid are never reclaimed. `Timeouts` carries no lifecycle budget.

Every sibling bounds this class: CH/FC via `unix_api_request`'s 5 s `REQUEST_TIMEOUT`
(`vmm/mod.rs:93`), QEMU via `timeout(2 s, …)` (`qemu:247`) plus `MIGRATION_BUDGET` (`:177,:320` — the
docs/78 M7 fix). The trigger class is not hypothetical: implementation-notes:1130 records crosvm's
non-`Suspendable` device wedging a device wake.

**Fix:** wrap `run_control`/`snapshot_take` in one named `CROSVM_CONTROL_BUDGET` (the 500 ms in
`kill()` becomes a *use* of it, not a second literal), map the elapse to `Error::Timeout` naming the
subcommand, and set `kill_on_drop(true)` so the abandoned client is reaped.
**Gate:** KVM-free — point `Crosvm::new` at a script that sleeps past the budget and assert
`boot()`/`request_shutdown()`/`resume()` each return a typed timeout inside a wall-clock guard, the
shape QEMU's `drive_migration_bounds_a_wedged_qmp_session` already uses.

### M6 — The guest-RAM-proportional `vm.snapshot` RPC rides the generic 5 s control ceiling
`crates/vmcell/src/vmm/mod.rs:93` *(CONFIRMED)*

`REQUEST_TIMEOUT = 5 s` wraps the whole connect→handshake→send→collect closure, and its own rustdoc
names `snapshot` among what it covers. `ChInstance::snapshot` is `vm.pause` →
`api_request("PUT", "/api/v1/vm.snapshot")` → `vm.resume` → return — so the write whose duration
scales with guest RAM sits on a fixed 5 s bound. Firecracker is identical (`fc:263`, `:1115-1127`).
Design §16 measures a 256 MiB guest's suspend image at ≈268.5 MB; a multi-GiB guest, or a slow or
contended disk, overruns. The failure is not merely a spurious `Error::Timeout`: `snapshot`'s
`vm.resume` is only reached on the `res` path, so a timed-out snapshot can leave the VM **paused**.

**Fix:** give the snapshot RPC its own budget (a `Timeouts` field, or an explicit
`unix_api_request_with(deadline)`), sized against guest RAM rather than a constant, and resume on the
timeout path as `snapshot`'s existing warn-and-continue arm already does for a failed resume.
**Gate:** unit — a fake API socket that stalls past 5 s on `vm.snapshot` returns the typed error
*and* leaves the instance resumed; red on today's shared const.

### M7 — A desynced cached `AgentClient` is never evicted
`crates/vmcell/src/orchestrator.rs:1436` *(ADJUSTED — scope narrowed on verification)*

`agent()` populates the cache only `if self.agent_client.is_none()` and otherwise hands the cached
handle back verbatim; the only two evictions in the file are the resync-failure path (`:1491`) and a
successful snapshot (`:1717`). The client sets `desynced` on a send error **or a timeout**
(`agent/mod.rs:825`), and `ensure_synced` then fails every later request with "reconnect required"
until `reconnect()` clears it — and `reconnect` has **no non-test caller** in the tree.

The verifier confirmed the race is real, not theoretical: the host wraps its wait in the same
duration it puts in `cmd.timeout` (`agent/mod.rs:841-844`) while the guest sleeps that duration
*before* killing and only then sends `Exit` (`guest-agent/main.rs:1241-1248`) — so the host's timer
can fire first on an exec that is behaving exactly as specified.

**Scope:** sessions and `dial_vsock` open their own connections and keep working; what dies
permanently is one-shot `exec`/`put_file`/`resync` on that VM. Recovery requires a manual
`AgentClient::reconnect` — which the daemon's `VmHandle` path cannot reach, and which is unavailable
on the AF_VSOCK arm.

**Fix:** have `agent()` check `is_desynced()` on the cached handle and reconnect (or evict) before
returning it — the eviction machinery already exists for the resync path.
**Gate:** unit — drive a `FakeVmm` exec to a timeout, then assert the next `agent()` call returns a
usable client; red on today's unconditional cache hit.

### M8 — A snapshot prefix is unpinned while it is being written, and the readback error is swallowed
`crates/vmcell-daemon/src/registry.rs:317-334` *(CONFIRMED — verifier reproduced both halves)*

`VmSlot::pins` knows only kernel/rootfs/extra_disks, and `delete_artifact_if_unused` holds the `vms`
map lock while `snapshot` holds only `slot.inner` — so they do not exclude each other. The verifier
drove it: with the snapshot mid-write, `delete_artifact_if_unused("snap1")` returned `Ok(())` and
`remove_dir_all`'d the prefix; the snapshot then returned **`Ok(SnapshotInfo { files: [] })`** — HTTP
200 for a snapshot that no longer exists. The second half is why the first is invisible:
`registry.rs:328` is `std::fs::read_dir(&out_dir).map(...).unwrap_or_default()`, a swallowed `Result`
(plus `rd.flatten()` dropping per-entry errors) — the exact `let _ =`-on-a-`Result` class AGENTS.md
bans.

**Fix:** pin the prefix in `VmSlot::pins` for the duration of the snapshot so the delete-in-use guard
covers it, and propagate the `read_dir` error as `Internal` rather than defaulting to an empty list.
**Gate:** KVM-free with a gated fake — a delete racing a snapshot returns `InUse`, and a snapshot dir
made unreadable surfaces an error rather than `files: []`.

### M9 — `VmState::Snapshotting` is unobservable, and one VM's snapshot blocks `GET /v1/vms` for all
`crates/vmcell-daemon/src/registry.rs:297-319` *(CONFIRMED — verifier reproduced it)*

`snapshot` takes `slot.inner` at `:297`, sets `state = Snapshotting` at `:317`, awaits the backend
write at `:318`, and resets to `Ready` at `:319` — all inside one hold. `VmSlot::info` reads
`self.inner.lock().await.state`, and `list` awaits `info()` for **every** slot. The verifier's probe:
`timeout(300 ms, reg.get(&id))` → `Elapsed`, `timeout(300 ms, reg.list())` → `Elapsed` (head-of-line
blocking across *all* VMs, not just the snapshotting one), and after release `get` reported
`state: Ready`. So the state `dto.rs:45-46` documents can never be observed, and `require_state`'s
promised 409 for an `exec` against a snapshotting VM never fires — it is evaluated only *after* the
lock is acquired, by which time the state is back to `Ready`.

**Fix:** carry the state in an atomic (or a separate small lock) read by `info` without taking the
per-VM handle lock — the immutable identity is already read lock-free for the delete-in-use guard, so
the pattern exists.
**Gate:** KVM-free — with a fake whose `snapshot` blocks, `get` returns `Snapshotting` promptly and
`list` does not block; `exec` against it returns 409.

---

## 3. Major — gates that cannot go red

### M10 — The P5 OpenAPI parity gate compares the document to the table it was generated from
`crates/vmcell-daemon/src/openapi.rs:173-239` · `crates/vmcell-daemon/src/server.rs:52-74`
*(CONFIRMED — two independent reviewers, two verifiers)*

`openapi_document()` is `for r in API_ROUTES { … }`, and all four parity tests read `API_ROUTES` on
both sides: `document_paths_match_route_table` compares `doc["paths"].keys()` — built from
`API_ROUTES` — against `API_ROUTES`. `rg 'API_ROUTES|OPEN_ROUTES'` over the whole tree returns only
`openapi.rs` plus two *comments* in `server.rs` (`:49`, `:393`). `build_router` hand-writes eight
`.route(...)` calls; **nothing in the router or its tests ever reads the table**, and the coupling
exists only as the prose claim at `server.rs:49` ("The routes mounted here are exactly
`crate::openapi::API_ROUTES`").

Design §13 P5 states the gate "asserts every mounted `(method, path)` is documented, every documented
one is mounted, every named schema exists, and every non-meta op carries the security requirement."
The first two are asserted against the wrong object; the third is vacuous (see m28); only the fourth
holds, and only over the table. A route added to `build_router`'s **`open`** subtree — which is not
wrapped by `route_layer` — would be unauthenticated, undocumented, and green. The verifier adds that
10 of the 11 authenticated `(method, path)` pairs have no router-side auth coverage at all: the
server tests exercise four URIs, and the live suite reaches the rest through the typed client, which
always sends the bearer key.

**Fix:** build the router **from** `API_ROUTES` (a fold over the table producing the `MethodRouter`
per path), so the coupling is structural rather than asserted. Failing that, walk the constructed
`Router` and compare — axum exposes no route introspection, which is itself the argument for
generating the router from the table.
**Gate:** whichever shape is chosen, the red-on-inverse is adding a route to `server.rs` alone and
watching the gate fail; today it passes.

### M11 — crosvm's only confinement can be deleted with every gate green
`crates/vmcell-crosvm/src/lib.rs:432` *(CONFIRMED — two independent reviewers)*

crosvm always launches `--disable-sandbox` (`vmm/seccomp.rs:83-92`, unconditional for both `Enforcing`
and `Disabled`), so the Layer-2 deny-list is its **only** seccomp confinement, and the one line that
turns it on is
`jail_spec_from_config(&effective_jail_config(cfg))?`. `rg` finds exactly three references to
`effective_jail_config`: the definition (`:181`), that call site, and the pure test (`:1222-1276`) —
which constructs configs, calls the pure function directly, never spawns, and would **pass verbatim**
if line 432 were changed to `&cfg.jail`. `JailConfig::hardened()` has `seccomp_deny_list: false`
(asserted as the test's own precondition), so that one-token rewrite ships every crosvm VM with
`--disable-sandbox` *and* no Layer-2 filter — parsing guest-controlled virtio rings next to
`CAP_NET_ADMIN` on the privileged path — with `cargo test -p vmcell-crosvm`, `just ci`, and the full
`just test-crosvm` matrix all green (the deny-list is default-allow/EPERM, so no functional leg
notices).

docs/78 M10 prescribed exactly the extraction that landed. The un-gateable surface moved from the
flip to the call. This is the shape the project's own completeness audit named: *a gate that tests the
extracted helper is not a gate on the claim.*

**Fix:** the in-repo precedent is the sibling source-scan `virtiofs_pacing_gate`
(`vmcell-qemu/src/lib.rs:2427`, `include_str!("lib.rs")`): assert the production text carries exactly
one `jail_spec_from_config(` call and that it names `effective_jail_config(cfg)`, with the predicate's
own red-on-inverse. Structurally better: have `spawn` build through one pure
`crosvm_launch_plan(cfg, res, …) -> (JailConfig, Vec<String>)` and assert on the returned pair.
**Gate:** `the_crosvm_jail_spec_comes_from_effective_jail_config`; red on rewriting `:432` to
`&cfg.jail`.

### M12 — The broker EOF drain — the only thing that stops every in-flight request hanging — has no test
`crates/vmcell-daemon/src/bridge.rs:393-402` *(CONFIRMED)*

`BrokerClientEngine::call` awaits a bare oneshot with **no deadline** (`:426-427`). The reader task
breaks on `read_frame` error (`:382`), and the only thing that resolves still-pending oneshots is the
post-loop drain sending `EngineReply::Err("broker connection closed")`. Delete that drain and the
senders stay alive inside `pending` — which the engine, not the task, owns — so `rx.await` never
resolves and **every in-flight HTTP request hangs forever**. `rg 'broker connection closed'` returns
exactly one hit: the production line. The seven bridge tests cover round-trip, error round-trip,
multiplex, over-cap read, over-cap exec reply, unwritable reply and write-frame cap — none closes the
broker end with a request in flight.

**Fix:** the gate is the deliverable here (the code is correct). Additionally, `call` should carry a
deadline so a *stalled* broker — as distinct from a dead one — is also bounded.
**Gate:** `broker_death_fails_in_flight_requests_rather_than_hanging`: issue a request against a
fake broker socket, close the broker end, assert the call returns the typed error within a wall-clock
guard. Red on deleting the drain loop.

### M13 — `ban-legacy-terms.sh` reports scanning the justfile while scanning zero bytes of it
`scripts/ban-legacy-terms.sh:48,56-60` *(CONFIRMED — reproduced during this review)*

The default roster is `dirs=(crates justfile)` under a comment that explains why: "the build
orchestration lives in the justfile. Both are non-historical code the rename must hold in (L-BIN-3)."
The collector is `for d in "${dirs[@]}"; do [[ -d "$d" ]] && find "$d" -type f -print0; done` — and
`justfile` is a regular file, so the `-d` guard drops it. Reproduced at HEAD:

```
$ ./scripts/ban-legacy-terms.sh
ok: no legacy imp-testing/rootless/TestVm/imp-*/Imp tokens (scanned: crates justfile)
$ ./scripts/ban-legacy-terms.sh justfile
ok: no files to scan under: justfile
```

The success message **names a target it never opened**. The verifier also appended `test-rootless:`
and `echo imp-testing` to a copy of the real justfile and the default run still returned rc=0.

**Fix:** collect files rather than gating on directories — `find "$d" -type f` for a dir, `printf
'%s\0' "$d"` for a regular file — and make the "scanned:" line report the file *count*, so a roster
that resolves to nothing cannot print a reassuring message.
**Gate:** extend `scripts/test-ban-legacy-terms.sh` with a justfile-shaped fixture carrying a banned
token; red today.

---

## 4. Deviations from design that should be FIXED IN CODE

Each of these is a place the tree does something design v31 says it does not, where the **design is
right**. (Deviations where the *code* is right are §5 and have been recorded in
`implementation-notes.md` by this review.)

| # | Deviation | Location |
|---|---|---|
| d1 | `resync`'s `mac` arm bounces the link (`netif.rs:148,162`) but only the `ipv4` arm re-installs the default route (`replace_default_route`, reachable solely from `set_ipv4`) — so a `Resync` carrying `mac` alone, which the type and the design present as independent options, **destroys the guest's default route**. The kernel side confirms it: `NETDEV_DOWN` → `fib_disable_ip` marks the nexthop dead. | `vmcell-guest-agent/src/main.rs:1060-1091` |
| d2 | `setup_env`'s three fallible steps after the proxy/netns exist (`assert_tap_wiring_matches`, `create_slice`, `cids.allocate`) run **before** `EnvSetup` is constructed, so an early return releases the net locals by *reverse-declaration order* — segment → proxy → smoltcp → netns — instead of the helper's law smoltcp → proxy → netns → segment. Today's order is benign only because `netns` happens to be declared first. The helper's own doc claims "a field reorder cannot silently invert this"; true for `EnvSetup`'s fields, not for this window. This is a fourth teardown path outside law L1's three. | `crates/vmcell/src/orchestrator.rs:928-1089` |
| d3 | `cgroup_events_path` hand-formats `format!("{base}/vmcell-vm-{vmid}")` with a hardcoded prefix under a rustdoc claiming it "matches the orchestrator's slice placement" — so `metrics.mem_limit_ooms` reads a path that does not exist for any VM with a non-default `resource_prefix`. The one law is `metrics::vm_slice_name`, which is `pub(crate)` and therefore unreachable from the validator (a third copy also sits in `tests/common/mod.rs`). | `vmcell-artifact-validator/src/checks.rs:643-650` |
| d4 | `Lineage::probe_cow_support` answers from a hardcoded `ReflinkOverlayStore` with no seam-routed alternative and no doc caveat — the docs/78 `overlay-probe-not-side-effect-free` seam half landed on `Zygote` (which *does* carry the caveat and gained `probe_cow_support_in`) and not on `Lineage`, bypassing law S4. | `crates/vmcell/src/lineage.rs:224-229` |
| d5 | §11.5 states the error body is "documented as an OpenAPI component" and §13 P5 claims the gate asserts "every named schema exists". The served document's `components` carries `securitySchemes` only — **no `schemas` object at all** — and every operation's responses are a bare `default` with no `content` and no `$ref`. The assertion is vacuous and clients get no machine-readable error contract. | `crates/vmcell-daemon/src/openapi.rs:136-161` |
| d6 | FC's create-path `PUT /network-interfaces/eth0` URL is an open-coded literal while the body and the restore override both use `FC_IFACE_ID` — so the const's own rustdoc ("A second literal is exactly the divergence this const removes") and design §2.3 are false for the third copy, which the gate cannot see. Loud on drift (FC 400s the path/body mismatch), hence note-severity. | `crates/vmcell-firecracker/src/lib.rs:837-845` |
| d7 | Firecracker and crosvm `create()` accept `cfg.nested_virt: true` while advertising `nested_virt: false`, with no typed refusal — the only in-tree consumer is the shared cmdline, which emits `kvm-intel.nested=1` for *every* backend. Three sibling capability fields (`virtio_console`, `disk_io_throttle`, `usb_host_passthrough`) do reject. The same shape applies to `RestoreMode::Lazy`, which FC/QEMU/crosvm silently degrade to eager. **Verification note:** design §2.1's stated contract is caller-consults-the-descriptor, and §2.6 annotates fail-loud only for the flags that have it — so this is a consistency/hardening item against F1, not a design-text violation. | `vmcell-firecracker/src/lib.rs:93` · `vmcell-crosvm/src/lib.rs:226` |
| d8 | `bench-vm` composes kernel/rootfs paths from the artifacts dir alone and never consults `VMCELL_KERNEL`/`VMCELL_ROOTFS`, so an override set for every other tool is silently not reflected in a benchmark run's attribution. (§10.4's two rows are written against the harness getters, which `bench-vm` does not use — so this is a consistency gap, not a contract break.) | `vmcell-bench/src/bin/bench-vm.rs:878-887` |

---

## 5. Justified deviations — RECORDED in `implementation-notes.md` by this review

Three findings are places where the **code is right and the document is stale**. Per AGENTS.md's
instruction to record justified deviations rather than "fix" them, this review appended them to
`docs/implementation-notes.md` under **"The docs/81 review pass (2026-08-14)"**:

1. **The session mux's writer is a channel, not an `Arc<Mutex<SplitSink>>`.** Design §3.2 sketches
   and states the mutex shape; the shipped `SessionMux` has always used an `mpsc::UnboundedSender<Bytes>`
   plus a sole-owner writer task. Both satisfy law C4; the channel form is better (no lock held across
   an await) and is what the pure-sink `writer_task` depends on. Recorded; design §3.2 to be amended
   at the next reissue.
2. **The runner's privilege transition is uid-drop-then-ambient-raise.** Design §11.2 and §15.5 both
   state it the other way round ("raise ambient → drop to the dev uid"). The shipped order is the
   inverse and deliberately so — `vmcell-privilege/src/lib.rs:414-416` documents why, and the
   setuid-fallback correctness argument depends on it. The design text is backwards, not the code.
3. **The daemon's start-up sweep is cross-process liveness-blind.** Design §11.4 asserts "Nothing is
   live at start-up, so the empty set can never sweep a resource in use" — false for a same-prefix
   multi-process host, since `sweep_orphans` consults no claim file and discards the pid embedded in
   the scratch-dir name. The sibling `clean_vmcell_netns` blindness is already recorded; this call
   site was not. The behavior is acceptable (the daemon owns its prefix) but the parenthetical
   over-claims.

A fourth is a *retirement* rather than a new entry: `vmm/jail.rs:62-67` and the notes still describe
`reboot`/`swapon`/`swapoff` as "deliberate additions BEYOND the §12.3 roster" with "the design folds
them into the roster at the next revision" — **design v31 already folded them in**, so the const now
matches the roster exactly and the deviation record is superseded. AGENTS.md's rule applies: *retire
an entry when it is empirically disproven.*

---

## 6. Minor findings

### Correctness

- **m1 — F3's alias law does not cover dash/underscore respelling.** `is_reserved_cmdline_arg`
  compares keys byte-exactly, but the Linux cmdline parser normalizes `-`↔`_` inside a parameter name
  (`kernel/params.c`'s `dash2underscore`) — which is the only reason the emitted `kvm-intel.nested=0`
  reaches a module registered as `kvm_intel.nested` at all. So `kvm_intel.nested=1`,
  `random.trust-cpu=off` and `ignore-loglevel` all pass the guard and, being appended last, **override
  the token vmcell emitted**. Reachable over REST: `CreateVmRequest.extra_kernel_args` →
  `with_kernel_arg`, and `MicroVmLauncher::launch` never sets `nested_virt`. docs/78 closed this class
  for `rw`/`quiet`/`debug`/`ignore_loglevel`; the respelling spelling was never in scope. *Fix:*
  normalize the key with `.replace('-', "_")` before the membership test. *Gate:* iterate
  `RESERVED_CMDLINE_KEYS` and assert both respellings are refused. `config.rs:499`
- **m2 — The VMID is released before the scratch dir named after it.** `teardown_post_instance` does
  `drop(self.vmid.take())` at `:1760` and `drop(self.tmp_dir.take())` at `:1765`. The scratch path is a
  pure function of `(prefix, pid, vmid)`, so a same-process reallocation inside that window has its
  fresh directory deleted by the departing VM. netns/tap/cgroup already follow the right rule (they are
  reclaimed before the id). *Fix:* swap the two lines. `orchestrator.rs:1760`
- **m3 — `FsIdClaim::try_claim` reports I/O failure as id exhaustion.** A discarded `create_dir_all`
  (`:126` — also a bare `let _ =` on a `Result`, which AGENTS.md bans), an `EACCES` open (`:141`), a
  failed `flock` (`:147`) and a failed write (`:171`) all collapse to `false`, which `allocate` renders
  as `Exhaustion("No available VMIDs (limit 254)")`. An operator with an unwritable `/tmp/vmcell-vmid`
  chases a phantom capacity limit. Reachable only through `HostEnv::shared()`, i.e. the daemon.
  `orchestrator.rs:126`
- **m4 — `Lineage::branch`/`fork_from_vm` and `Zygote::suspend` have no create-only guard.**
  `create_dir_all` then snapshot-in-place, so re-snapshotting into a populated lineage master
  overwrites it. The daemon's equivalent path is guarded (`create_dir` + EEXIST, `registry.rs:307`);
  the library's is not. `lineage.rs:287,139`
- **m5 — The guest `ip` shim accepts and ignores argv.** `run_ip_link`'s catch-all arm swallows
  `mtu 9000`/`master br0`/`promisc on` and returns 0; `address` with no value yields `None` and the
  consumer silently skips. This is the accept-then-ignore shape docs/78 fixed in the sibling `curl`
  applet, one applet over. `vmcell-guest-tools/src/main.rs:560`
- **m6 — `privileged_net_available()` omits the `cap_sys_admin` conjunct.** It is
  `cap_net_admin && netns_reachable`, and `netns_reachable()` is `/run` or `/var/run` exists — true on
  every Linux host, as its own doc concedes. Design §6.1/§6.5 promise three caps. A NET_ADMIN-only
  consumer of `NetSegment::new` gets an untyped `Error::Network` from inside `netns_rs` instead of the
  typed `CapabilityUnavailable`. Narrow: both shipped privileged entry points already verify all three
  via `ensure_blessed_or_explain`. `net/segment.rs:148` · `hostcaps.rs:84`
- **m7 — The TPROXY `log prefix "vmcell-drop: "` emits nothing.** netfilter suppresses the syslog LOG
  target in a non-init netns unless `net.netfilter.nf_log_all_netns=1` (measured on this host: `0`).
  The kernel's own selftest vendored in this tree sets that sysctl before asserting on such a prefix.
  The security property (drop) is intact and live-asserted; the *diagnostic* the rustdoc promises has
  never existed, and the only gate pins the rule text. `net/tap.rs:664,650-651`
- **m8 — An over-cap one-shot frame desyncs a byte-clean stream.** `exec`/`put_file` encode and send
  with no pre-send `MAX_FRAME_BYTES` check (the session path has one, `session.rs:45-54`). The codec
  does reject it before anything reaches the wire — so the stream is byte-clean — but the failure
  surfaces as an opaque `Error::Io` and marks the client desynced, against `finish_request`'s own
  "desync only if a stale frame could be in flight" contract. Compounds M7. `agent/mod.rs:919`
- **m9 — A restored VM's boot failure is rendered by the fresh-boot classifier.** A restored VM's
  console is empty by construction, and `explain_boot_failure`'s last arm reads "no banner ⇒ not a
  direct-boot PVH-ELF vmlinux" — so `snapshot.restore_roundtrip` diagnoses a kernel that provably just
  booted as not being a kernel. Wrong explanation on an already-failing restore, not a wrong verdict.
  `vmcell-artifact-validator/src/checks.rs:582-591`

### Reliability

- **m10 — `connect_framed`'s deadline bounds the gaps, not the attempt.** The deadline is checked at
  the top of the loop and `connect_framed_once` is awaited bare; inside it, `connect_control_stream`
  has no budget and the frame read uses a hardcoded `timeout(2 s, …)` unrelated to the caller's
  deadline. The connect can overrun its caller's `timeout` — the same defect class docs/78 M7 fixed for
  QEMU's migration budget. `agent/mod.rs:637-671`
- **m11 — The NAT's per-mapping host dial has no deadline and discards its error.**
  `TcpStream::connect(...).await` with no timeout, on the single task servicing the whole datapath
  (`grep '\.await'` finds three sites in the file), and the `Err` arm is dropped with no log — unlike
  the neighbouring `send_slice`/`recv` errors, which log at `error!`. `net/smoltcp.rs:1024-1028`
- **m12 — PID 1's listener thread dies if the OS refuses a thread.** The accept arm uses a bare
  `std::thread::spawn`, which panics on `EAGAIN`; the listener thread is detached, nothing observes the
  unwind, and there is no `panic = "abort"` anywhere in the tree. The control plane dies with no kernel
  panic and no supervisor — the one failure mode C1's "never exit" rule cannot catch, because the
  process does not exit. `vmcell-guest-agent/src/main.rs:709-734`
- **m13 — The POLLERR rebind arm is the one recover-by-rebind path without the L-GUEST-4 back-off.**
  Its two sibling arms both `sleep(accept_poll)` under a comment claiming "every recover-by-rebind path
  is rate-limited" — false as written. (The console-flood consequence is unproven: each iteration binds
  a fresh socket.) `vmcell-guest-agent/src/main.rs:689-697`
- **m14 — Every privileged namespace move on the hot path `setns`es a pooled tokio worker.**
  `net_sys::setns_net`'s contract is explicit: "run this on a **dedicated** thread it owns — never a
  pooled runtime worker." `NetSegment::dial_tcp` and the proxy obey it; the seven `ns.run(...)` sites in
  `net/tap.rs` do not, and all are reached synchronously from the async `setup_env`. The verifier read
  netns-rs 0.2.0's source: `run` is `enter()?; let r = f(self); src_ns.enter()?;` with **no
  `catch_unwind`** — so a panic in `f` (reachable: the closure calls `thread::scope`'s `spawn`, which
  panics when the OS refuses a thread) leaves a runtime worker permanently inside the VM's netns,
  silently originating every later socket there. `scripts/ban-inline-setns.sh` greps `crates/` for a
  call-shaped `setns(`, so a `setns` inside the dependency is invisible to it. `net/tap.rs:151,250,290,335,391,423,497`
- **m15 — The pack tail rewrites the published CA outside the `.ca.lock` protocol.** HEAD's newest
  commit introduced a cross-process `flock` for CA publish; the shared inject+pack tail then does a
  bare non-atomic `std::fs::write` to the canonical `<artifacts_dir>/ca.pem` with no lock held. Same
  bytes, so no divergent CA — but a transient truncate window a concurrent `CaManager::new()` can read
  as a short PEM. `artifact/rootfs/mod.rs:480-486`
- **m16 — The OCI blob cache is sited on the stage's output dir.** `out.parent().join("oci-cache")`, and
  both in-VM builders pass an output inside a per-run `TempDir` — so the cache dies with the run and the
  digest-pinned builder base is re-pulled every time. The canonical `vmcell build` path is unaffected.
  `artifact/rootfs/oci.rs:180`
- **m17 — `SERIAL_TAIL_LINES` bounds lines, not bytes.** The rustdoc promises "a failure message never
  carries a multi-megabyte console log into a caller's report", but `serial_tail` applies `.take(N)` to
  the *line* iterator with no per-line byte cap — and the console is guest-controlled.
  `vmcell-artifact-validator/src/classify.rs:264-274,47-49`
- **m18 — The smoltcp daemon bring-up error is swallowed** (the worker logs `start returned {:?}` and
  proceeds) — related to M2 and worth fixing with it. `net/smoltcp.rs:742`
- **m19 — The CI device-widening step asserts only `/dev/kvm`.** It writes udev rules for `kvm`,
  `vhost-vsock` and `vhost-net`, then swallows both non-kvm probes with `|| true` — defeating the
  "the assertion is the gate" rationale written into the step itself. `.github/workflows/ci.yml:310-329`

### Test coverage

- **m20 — The teardown drop-order gate cannot see the last three steps of the order it asserts.** Both
  order tests build a `MicroVm` with `vmid: None, cid: None, tmp_dir: None`, so the
  `cid → vmid → tmp_dir` tail executes three no-ops, and the assertion covers only
  `instance < netns < cgroup`. m2 lives in exactly the region the gate cannot reach.
  `orchestrator.rs:2637-2690`
- **m21 — The constant-time compare has no gate.** Design §11.6 claims "a timing test that the compare
  is constant-time in shape guards against a future `==` regression". The implementation is correct
  (`ct_eq`), but the only candidate test asserts three booleans over inputs that are both hashed to a
  fixed 32 bytes first — a plain `==` passes it unchanged. `vmcell-daemon/src/auth.rs:226`
- **m22 — Design §4.4's applets↔manifest cross-check does not exist.** The design states the `APPLETS`
  table and `rootfs_injection_manifest` "are checked against each other". They are independent literals,
  and both gates re-type a *third* copy of the same four names — so a one-sided edit stays green, which
  is the regression that has shipped twice (a custom-`init=` boot exits 2 and panics the guest kernel).
  `artifact/rootfs/mod.rs:720` · `vmcell-guest-tools/src/main.rs:110`
- **m23 — No test pins the tap name against IFNAMSIZ.** The module's only length assertion measures the
  *shorter* segment bridge name; `tap_name` — the longer one, and the stated reason
  `MAX_RESOURCE_PREFIX_LEN` exists — is never measured. A stem rename or a prefix-length bump passes the
  KVM-free suite and fails at rtnetlink. `naming.rs:173`
- **m24 — The validator's live smoke suite is selected by no recipe and no CI job.** Both tests are
  `#[ignore]`d and every `--run-ignored all` invocation is scoped to another package — so the *only*
  proof that the conformance battery can FAIL is compiled and skipped. `vmcell-artifact-validator/tests/smoke.rs:8`
- **m25 — The `netif` half of the kernel-ABI duplication guard is unpinned.** `netif` hardcodes eleven
  values libc exports; four of its seven ioctl request numbers and both `RTF_*` are pinned by no test.
  guest-tools does the opposite and states the rule. The recorded duplication entry's promise — "a copy
  that drifts from the ABI reddens in its own crate" — does not hold for the agent's copy.
  `vmcell-guest-agent/src/netif.rs:15-26`
- **m26 — The uid-drop-before-ambient-raise ordering is ungated.** It is statement order only, invisible
  to the order-blind `PrivilegePlan`, and design §15.5 names a gate that does not exist. Latent: the
  setuid-root form it protects is never provisioned by this repo. `vmcell-privilege/src/lib.rs:414-478`
- **m27 — The blessed-cap drift gate reads two of five copies.** `setcap_arg`'s own rustdoc names the
  README as a drift site; the gate `include_str!`s only the justfile and the preflight. The three README
  copies are currently correct. `vmcell-privilege/src/lib.rs:1021`
- **m28 — The client's lean-DTO boundary has no gate.** `default-features = false` holds today
  (verified by `cargo tree`), but no script or recipe covers `vmcell-daemon-client`, so dropping it
  would go unnoticed. `scripts/check-lean-tree.sh` already takes crate names — this is a one-line
  extension. `vmcell-daemon-client/Cargo.toml:19`

### Notes

- **m29 — `Pipeline::reset_to` leaves registered sibling artifacts behind** (the kernel's
  `<vmlinux>.config`), because it removes only the payload and `.cache_key`. Exposed narrowly: the
  default kernel's `kernel-config` in a `vmcell bundle` taken between reset and rebuild. *Fix:* parse
  the stage's `CacheMetadata` (already deserialized in `build()`) and remove every registered artifact
  under `target_dir`, which keeps `Pipeline` free of kernel-specific knowledge. `artifact/mod.rs:1595-1620`
- **m30 — `oci2erofs`'s tar merge drops unhandled entry types** rather than failing loud on them.
  `artifact/rootfs/tar2erofs.rs:240`
- **m31 — Re-registering a live `SessionId` unregisters the live session.** `vmcell-guest-agent/src/main.rs:1499`
- **m32 — A PTY clone failure leaks a reaper reservation.** `vmcell-guest-agent/src/main.rs:1763`
- **m33 — `serve_engine` replies nothing to an undecodable request** (as opposed to the reply-side
  fallback docs/78 M8 landed). `vmcell-daemon/src/bridge.rs:335`
- **m34 — The seccomp module doc overclaims for a *future* backend crate.** The golden test does gate a
  wrong flag, but `roster::dispatched_backend_ids()` scans this file's own `match` arms, so a backend
  crate that never adds an arm contributes nothing. Hypothetical today. `vmm/seccomp.rs:7-10`
- **m35 — `Netlink::setup_tap` returns a `Result<Option<tun_tap::Iface>>` that is always `Ok(None)` and
  always dead** — forcing every out-of-tree implementor of this ledgered public seam to take a
  `tun-tap` dependency (which `vmcell` does not re-export, so the pin must be guessed) for a value
  nothing reads, and teaching them they should hold the tap fd open — the one thing that breaks the
  single-opener discipline. `vmcell-broker/Cargo.toml:21-24` already carries that dev-dependency with a
  comment naming this exact cause. *Fix:* return `Result<()>`; `cargo machete` then makes the cleanup
  self-proving. `net/tap.rs:174`

---

## 7. Documentation debt

### 7.1 The hosted-runner move (highest leverage)
The CI-repair pass moved `test-integration` from a `[self-hosted, linux, kvm]` job that had **never
run** onto GitHub-hosted runners, and recorded it in the README and the job definitions. Four other
places still assert the opposite: design §5.6 (l.1499), §15.4 (l.3863) and **§18 delta 5** (l.4296-97,
which names a selector absent from `ci.yml`), plus `docs/76` l.261 — which is the *gate-spec* document
and therefore an actionable instruction to a future implementer. `ci.yml`'s own comments at 13, 53,
204 and 228 are stale too (228 points the live downstream half at "the self-hosted KVM job below"),
and `.github/actionlint.yaml` still whitelists the labels.

### 7.2 Counts and rosters checked against the tree
Verified mechanically this pass. Correct: the crate roster (19), `VmmCapabilities` (9 fields),
guest-tools applets (4), `DENIED_SYSCALLS` (21, matching design §12.3 name-for-name in both
directions), `Timeouts` (7 `Duration` fields), `vmcell` 0.13.0. Stale:

- **README's privileged tally is stale on both numbers** — "149/149, 5 capability skips" against
  `ci.yml:281-283` and implementation-notes:3400 both recording 156/156 with 8 skips. Measured on this
  host against a **reset** manifest: **156/156, 8 capability skips**, matching CI exactly. The `5`
  appears to have come from nextest's `5 skipped` summary field, which counts *deselected* tests, not
  `require_cap!` records — a conflation worth naming, since the two numbers sit one line apart in the
  same output. `README.md:380`
- **AGENTS.md's blessed-runner sentence** — stale on both facts: the `just` recipes invoke the
  **debug** runner (`justfile:5`, used by all four suite recipes), not the release one, and the file
  capability set is now **four** caps (`BLESSED_FILE_CAPS` = `PRIVILEGED_CAPS` + the transient
  `CAP_SETPCAP`), not three. `AGENTS.md:307`
- **Design §10.4's downstream `setcap` line** renders the 3-cap *delivered* set instead of 4-cap
  `BLESSED_FILE_CAPS`; the README and §15.5 are correct. l.2933
- **Design §9.2's module map** — the `vmm/` line still names `firecracker/qemu` (extracted to their own
  crates per §9.1, eighty lines earlier), `net_sys.rs` still claims "the ONE unsafe ioctl" though it now
  also hosts `setns_net`, and `vmm/usb.rs` is unlisted — despite the v31 preamble claiming §9.2 was
  corrected against the shipped names. l.2361
- **Design §9.3's `VmConfig` roster omits `vsock_transport`.** l.2435
- **Design §11.3** still describes artifact delete as the check-then-delete two-step the code replaced
  with `delete_artifact_if_unused` (whose own comment says the two-step "reopened the TOCTOU"). l.3092

### 7.3 A §17 entry the tree has closed, and a §17 premise that is false
- **Closed:** §17's "consolidations still open" still lists the integration harness's
  `computed_cgroup_name` as a local-`format!` duplicate. `tests/common/mod.rs:18-23` routes through
  `vmcell::naming::cgroup_slice_name` and implementation-notes:3098 records the closure. A stale
  open-gap is as misleading as a stale count. l.4101
- **False premise:** the NAT bring-up flake's recorded mechanism — "`VhostUserDaemon::start` binds
  lazily from a background thread" — is **false against the tree**, at all three sites that assert it
  (`vmcell-qemu/src/lib.rs:763`, the notes, and the §17 register). `Listener::new` *is* the bind
  (`vendor/vhost/src/vhost_user/connection.rs:35-43`), called synchronously on the caller's thread
  three lines before the `thread::spawn`; `start()` binds nothing. So §17's named fix ("make
  `SmoltcpProcess::start` block until the socket is bound") would retire nothing — it already does.
  The ~10% flake is real and its mechanism is **open**, which is exactly the state AGENTS.md's
  "'environmental' is a hypothesis, not a diagnosis" rule says to record honestly. This is the fifth
  empirically-false shipped-fact premise this project has found; the §18 convention ("premises are
  verified anchors, not memory") earns its place again.

### 7.4 Rustdoc contradicting shipped behavior
`Egress::Blocked`'s "All egress traffic is blocked" (M1); `net/tap.rs:650-651`'s "logged and dropped"
(m7); `classify.rs:47-49`'s "never carries a multi-megabyte console log" (m17);
`checks.rs:643-650`'s "matches the orchestrator's slice placement" (d3); `Lineage::probe_cow_support`'s
missing default-store caveat (d4); `vmm/seccomp.rs:7-10`'s new-backend claim (m34);
`Netlink::setup_tap`'s live-looking return type (m35).

---

## 8. Simplification and clarity

- **One law, one predicate — three still-open consolidations** (beyond the two §17 already lists,
  minus the one it wrongly still lists):
  `metrics::vm_slice_name` is `pub(crate)` with three copies of the composition (d3);
  the kernel artifact-key law is a private method byte-duplicated in `vmcell-kernel-builder`, and the
  `kernel_<label>_source_url` pin-key law is composed inline in the flattener and re-derived by both
  consumers — none exported, unlike every sibling law in `artifact::kernel`;
  the `1000` ms readiness ceiling is a bare literal in all four backends.
- **`Netlink::setup_tap`'s dead return** (m35) — deleting it removes a public-signature dependency.
- **`Egress::Blocked`** (M1) — if the answer is (b), the variant should simply be removed at the next
  breaking bump rather than left as a rejected input.

---

## 9. Extension points

The user's two named extension points were assessed by walking each path as an implementer would.

**Adding a crate that builds a kernel inside vmcell — healthy.** This is the §5.6/§10.4 toolkit, and
it is genuinely reachable from outside: every item on design §10.4's named contract list is in fact
`pub` and rustdoc'd (`Stage`/`Pipeline`/`ResolvePinsStage`/`StageInputs`/`StageOutputs`/`CacheKey`, the
hash helpers, `build_labelled_kernel`, `kernel::resolved_config_path`/`kernel_filename`,
`pack_erofs_with_injection` + `ExtraFile`, `KconfigValues`), `pipeline` is a default feature so
`cargo semver-checks` really sees the toolkit surface, and `examples/downstream-kernel/` is a living
consumer CI builds on every push. The friction found is narrow and listed above: the kernel
artifact-key and pin-key laws are triplicated and unexported (§8), so a downstream builder must
re-derive both spellings rather than call them — the same trap `InVmKernelStage` already fell into.

**Adding a VMM backend crate — reasonably easy *in-workspace*, deliberately not out-of-tree.** One
reviewer filed this as a defect ("a fifth backend cannot ship out of tree: `vmm_seccomp_args` is a
closed dispatch"). The verifier **refuted** it, and the refutation is the useful finding: the closed
dispatch is a documented decision, not an oversight — `vmm/seccomp.rs:100-105` states "an id it does
not match is a fail-loud `vmm_seccomp` `Unsupported`, so a backend cannot ship without an arm. That
makes its dispatch the authoritative roster." The `Vmm` trait is **absent** from design §10.4's
contract-surface list, and rubric v6's retired-rules section records that `VmmCapabilities` and
`PerVmResources` were made exhaustive *precisely* so a new field is a compile error in every backend
crate — which presumes in-workspace backends. So the honest statement is: adding a backend is a
supported **in-workspace** operation (three crates demonstrate it, and the shared helpers really are
shared — every backend routes through `build_vmm_cmd`, `register_and_await_ready`,
`reap_process_group`, `wait_for_socket`, `config_has_vhost_user_device`, `build_kernel_cmdline`,
`RootfsSource::effective_image`, `mac_math`, `vmm_seccomp_args` and `reject_unsupported_console`,
with no hand-rolled copies), and it is **not** an out-of-tree extension point.

Two real frictions surfaced anyway, both worth taking as in-tree cleanups: the triplicated `reaped`-flag
teardown dance (three hand-written copies of one pgid sequence, against law L1's "one ordered helper"),
and the three hand-rolled `TestCgroupFs` copies — the latter already answered at the site
(`fc:1202-1207` explains `FakeCgroupFs` is `#[cfg(test)]`-only and invisible downstream), so the fix
is a `test-support` feature rather than a fourth copy.

---

## 10. What was checked and held

Recorded so a later pass does not re-derive it. Each item below was traced in code by an area reviewer
this pass, not assumed:

- **Config/build (F1).** All 23 `VmConfig` fields have a builder setter and land verbatim; every
  validation the rustdoc advertises exists in the body — including both halves of docs/78's
  `rootfs-image-escapes-boundary-validation` and `share-tag-path-separator-escapes-scratch-dir`.
  `build_kernel_cmdline` matches §5.3 token-for-token and order-for-order. `Timeouts::clamped()` floors
  in the correct order and is re-applied at all three orchestrator boundaries.
- **Naming (F2).** Composers and sweep filters agree for both the `-net-`/`-vm-` and `-seg-` classes;
  `sweep_orphans` liveness-checks each class against its own id space; `validate_resource_prefix` has
  exactly one definition, re-exported rather than reimplemented by the daemon.
- **The NAT's six invariants (§6.2).** Walked one at a time. `HOST_NAT_MAC`'s third octet is `0xff`
  where `mac_math` always emits `0`; `AvailIter::next` is the only thing that advances `next_avail` in
  virtio-queue 0.18, and `chains.next()` is reached only after a successful `pop_front`;
  `enable_notification` is present in both event_idx arms; #4/#5/#6 each carry a named gate. Partial
  returns are clean everywhere reachable; guest-derived lengths are bounded before allocation; no `as`
  narrowing of a wire-derived value.
- **`apply_jail` (§12.3).** Allocation-free on **every** path including the error paths — the reviewer
  read `seccompiler` 0.5.0's `apply_filter` to confirm it too is allocation-free. Order is exactly
  rlimits → dumpable → ambient-clear → `no_new_privs` → seccomp → execve, with `setns` correctly ahead
  of it. All 11 `unsafe` blocks in `vmm/` hold one operation with a SAFETY comment naming that
  operation's obligation.
- **The CH restore config-rewrite (§2.2).** Handles both console wirings, zero and N net entries, a
  `null` file field, and missing keys — all `get_mut`-guarded and unit-pinned.
- **Capability honesty (§2.6).** All nine `VmmCapabilities` fields on all three secondary backends match
  both the design table and what the code emits; five of them have a matching fail-loud reject at
  `create()` (the two that do not are d7).
- **The privileged tier.** The fork genuinely precedes any thread spawn; the post-fork child window is
  two async-signal-safe calls; `plan_broker_parent_drop` `?`s on everything except the bounding shrink,
  which is warned exactly once through one shared edge. The runner's confinement resisted `..`,
  symlinked targets, sibling prefixes, an attacker-owned `target/` ancestor and non-UTF-8 argv — all
  fail closed, and the trusted root derives only from the runner's own canonicalized `current_exe()`.
  The transient `CAP_SETPCAP` is absent from `inheritable_add`/`ambient_raise`/`final_caps` and present
  in `bounding_drop`, pinned both ways plus a live `CapBnd` equality gate.
- **The guest PID-1 contract.** Every `?` in `main` is confined to the fatal core-mount set; both reaper
  loops terminate only into `power_off_never_returns()`. The reaper epoch protocol is correct in both
  directions and closes both AGENT-1 and AGENT-2 with named red-on-inverse tests. `teardown_sessions`
  runs on every `serve_loop` exit reason. C4 holds: every emitting site goes through one `send_msg`, and
  no path holds the sessions lock while taking the writer lock.
- **The host control plane.** The `CONNECT`/`OK` prologue is genuinely one function used by both the
  framed connect and the raw dial, reads byte-by-byte with no `BufReader`, and the recorded no-backoff
  busy-retry fix did land. The discriminant-stability test pins **all sixteen** variants, not just
  8..=15. `capped_debug` covers every guest-frame log site.
- **The five cache-key rules (F4).** Traced against all nine real stages. No input was found that
  affects a stage's output and is unfolded. F5 holds in both directions:
  `is_reserved_injection_path` *derives* its list from the manifest rather than restating it, and
  normalizes through the packer's own `normalize_path` so `.`/`//`/absolute evasions collapse.
- **The daemon.** `resolve_artifact_path` is a correct allowlist and every store op reaches disk through
  it; auth is genuinely opt-out with the per-request `--allow-unauthenticated` warn landed and gated;
  the `DaemonError` → status map is complete and single-sourced, with `Error::Config` → 400 pinned;
  ids are unique and never reused; the delete-in-use scan covers extra disks and is atomic under one
  lock hold; the start-up sweep passes both empty sets in the correct positions.
- **The gates.** All seven ban/check scripts carry self-tests driving both arms;
  `test-check-lean-tree.sh` exports `CARGO_TERM_COLOR=always` so the colour hazard itself is gated;
  `check-broker-lean.sh` separates absent/present/cargo-could-not-answer with its positive control.
  `--no-tests=fail` is real and the nextest version is pinned so it cannot silently regress. The CI
  jobs invoke the `just` recipes rather than hand-copying them; no step uses `continue-on-error`, and
  the only `if: always()` step is the non-gating skip-manifest surfacing, placed last. Fixture
  ownership is panic-safe (`TempTree` with a driven unwind leg).
- **The consumers.** The `classify` signatures check out against the real emitters (verified against
  the guest agent's literal strings); `ROOT_DEVICE_SIGNATURES` is genuinely tested first with a
  non-vacuous shared-panic fixture; `missing_symbols` filters on `is_builtin`. The `VMCELL_*` table
  holds in both directions for the validator getters. `pcts` is nearest-rank with a known-values test.

**Two findings were refuted** and are recorded here so they are not re-raised: the CA cache mutex is
not held across the blocking `flock` in a way that can deadlock, and the out-of-tree fifth-backend
"blocker" is a documented design decision (§9).

---

## 11. Suggested landing order

1. **M3, M8, M9** — the daemon `Registry` cluster. All three are small, all three were reproduced with
   a running probe, and M8's swallowed `read_dir` is a one-line fix that makes M8's first half visible.
2. **M1** — decide `Egress::Blocked`'s fate. It is a public-API security promise; the decision (honor
   or reject) is the maintainer's, and the recording is required either way.
3. **M4, M12** — the broker shutdown/drain pair; M12 is the gate for machinery that is already correct,
   M4 is a real orphan on the graceful path.
4. **M5, M6, m10, m11** — the deadline sweep. One theme, four sites, and a `Timeouts` field or two.
5. **M10, M11, M13** — the three gates that cannot go red. M13 is a two-line shell fix; M11 has an
   in-repo precedent to copy; M10 is the largest (generate the router from the table).
6. **M2, M7** — the two recovery paths that cannot recover.
7. **d1–d8**, then the minors by area, then §7's doc debt as one pass (it is mostly mechanical and
   benefits from being done together, since §7.1 touches four files for one fact).

The three justified deviations in §5 are already recorded; the superseded deny-list entry should be
retired from `vmm/jail.rs:62-67` and the notes in the same pass that touches §7.
