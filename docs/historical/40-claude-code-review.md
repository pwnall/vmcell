# vmcell — Code Review (Review 39)

*Full per-subsystem static review of the entire implementation against design **v15**
(`docs/39-claude-design-v15.md`) and the **v2 rubric** (`docs/36-claude-code-review-rubric.md`).
2026-06-30.*

## 1. Scope & method

The whole workspace was reviewed: the `vmcell` library (`vmm/`, `net/`, `proxy/`, `artifact/`,
`agent/`, `config`, `error`, `metrics`, `cpufreq`, `fs`, `orchestrator`, the CLI + bench bins),
plus `vmcell-protocol`, `vmcell-guest-agent`, `vmcell-test-runner`, `vmcell-guest-tools`, the
integration test suite, the CI/gate scripts, `justfile`, `nextest.toml`, `deny.toml`, and
`clippy.toml`. Coverage map in Appendix A.

The review was delegated to nine parallel per-subsystem sub-reviews, each applying the rubric's
governing question — *"write the buggy implementation; does a test go red?"* — and cross-checked
against `implementation-notes.md` so already-recorded, justified deviations are not re-reported.
Findings were then deduplicated and the Critical/High findings (plus several Mediums) were
**spot-verified by re-reading the cited source lines**; verified findings are marked ✓.

Per the review request, divergences from the design that are *justified* were recorded in
`implementation-notes.md` ("Review 39 — newly recorded justified deviations") rather than here;
this report contains the **unjustified divergences, correctness bugs, test-coverage gaps,
documentation gaps, Rust-idiom deviations, and code-quality opportunities**.

**What was NOT run.** This is a static, read-only review. `just ci`, `just test-privileged`,
`just test-unprivileged`, and VM boots were **not** executed as part of it; no code was changed
except this report and the implementation-notes append. Findings that assert runtime behavior
(e.g. the `EISDIR` snapshot-cache path, the bounding-drop no-op) were verified from the code and,
where noted, by the sub-reviewer empirically, but the suites were not re-run. Any fix landing from
this report that touches host-facing code must be validated on a KVM host per AGENTS.md before
being called done.

## 2. Executive summary

The implementation is in strong shape and materially better than the rubric's worst-case
expectations: teardown ordering, allocator release, the snapshot-eligibility law (across all
three `build()`/`orchestrator::restore()`/backend boundaries **including the data-share case**),
cache-key determinism (BTreeMap ordering, stage versions, content-addressed tamper rejection on
the hit path), digest-pinned OCI pulls, the reaper-vs-waiter coordination, the effective-set
capability probe, and the privilege-drop *ordering* are all implemented correctly and, in most
cases, guarded by tests that fail on their inverse. Many rubric line-items were checked and found
**compliant** (Appendix B).

The findings cluster into four themes:

1. **Backends diverge on the self-guard contract (VMM-1).** Firecracker rejects a `VirtioFs`
   rootfs with a typed `Unsupported`; Cloud Hypervisor and QEMU silently build an unbootable VM.
2. **A capability-dependent op silently no-ops in a non-default build (CFG-1).** Cgroup limit
   application is gated behind the `metrics` feature; a `--features cloud-hypervisor` host build
   drops every requested limit and returns `Ok(())`. The fake over-promises, so no test catches
   it — and the only gate that compiles that config is the non-blocking feature-powerset.
3. **Two load-bearing security assertions cannot fail on their inverse (TEST-1, PRIV-1).** The
   privileged transparent-egress filter test asserts a filter-independent outcome; and the
   test-runner's path-confinement is anchored on the untrusted exec argument, making it a no-op
   as a security boundary (a real local privilege-escalation surface, with a comment that claims
   the opposite).
4. **The most expensive artifact stage is uncached and several decode/round-trip paths are
   untested (ART-1..4, AGENT-3).** `SnapshotStage`'s directory output defeats the file-only cache
   machinery; the OCI pull, device-node/zstd decode, and guest wire-framing are exercised only on
   a KVM host or not at all.

| Severity | Count | IDs |
|---|---:|---|
| **High** | 4 | VMM-1, CFG-1, TEST-1, PRIV-1 |
| **Medium** | 15 | VMM-2, ORCH-2, ORCH-3, ORCH-5, ORCH-6, NET-1, NET-2, NET-3, ART-1, ART-2, ART-3, ART-4, AGENT-1, AGENT-3, TEST-2 |
| **Low** | 34 | VMM-3/4/5/6, ORCH-1/4/7/8, NET-4/5/6, CFG-2/3/4, AGENT-2/4/5/6, ART-5/6/7/8/9/10/11, CLI-1/2/3/4/5, PRIV-3/4/5/6/7, TEST-3/4 |

Three justified-and-new divergences (CLI snapshot-eligibility-by-construction; the runner's
`libc` dep; the deliberate `CAP_SETPCAP` exclusion) were moved to `implementation-notes.md`.

---

## 3. High-severity findings

### VMM-1 ✓ — CH & QEMU silently build an unbootable VM for a `VirtioFs` rootfs
*Category: design-divergence / correctness · Rubric B3 · §3.1*
`crates/vmcell/src/vmm/cloud_hypervisor.rs:405-421` (+ cmdline `:347-357`),
`crates/vmcell/src/vmm/qemu.rs` (same shape); Firecracker does it right at
`crates/vmcell/src/vmm/firecracker.rs:459-464`.

For `RootfsSource::VirtioFs`, CH's `create()` hits an empty match arm
(`VirtioFs { .. } => {}`) — no block disk is attached and no virtiofsd is started for the root —
while the kernel cmdline falls through `_ => "ext4"` / `_ => "rootflags=noload"`, emitting
`root=/dev/vda rootfstype=ext4 ro rootflags=noload` for a VM that has no `/dev/vda`. QEMU does the
same. `config::build()` only rejects a `VirtioFs` rootfs when *also* `snapshotting`
(`config.rs:442-447`), so a plain `VirtioFs`-rootfs config is buildable and reaches `create()`.
Firecracker instead returns `Error::Unsupported { vmm, feature: "virtio_fs_rootfs" }`.

**Impact.** A config the public builder accepts produces a guest that kernel-panics on a missing
root, silently, on two of three backends. This is the exact "create() rejects configs the backend
can't honor instead of silently building a broken VM" rule (B3) and the "contracts self-guard"
prime directive — and the primary (CH) path is not exempt.
**Direction.** In CH and QEMU `create()`, either wire virtio-fs rootfs (virtiofsd + `fs` entry +
`root=…/rootfstype=virtiofs`) or return `Error::Unsupported` up front, mirroring FC. (No backend
supports a virtio-fs *rootfs* today, so the fail-loud rejection is the correct minimal fix.)

### CFG-1 ✓ — Cgroup limits silently dropped in a non-`metrics` host build
*Category: design-divergence / correctness (fail-loud) · Rubric B2/A2 · §7.1*
`crates/vmcell/src/metrics.rs:290-324`; ungated caller `crates/vmcell/src/orchestrator.rs:592`.

`DefaultCgroupFs::create_slice` gates the *entire* limit-application block
(`memory.max`, `memory.swap.max`, `memory.oom.group`, `cpu.max`, `pids.max`, `io.max`) behind
`#[cfg(feature = "metrics")]`; the `#[cfg(not(feature = "metrics"))]` arm is `let _ = limits;`
then `Ok(())`. `orchestrator.rs:592` calls `create_slice(&name, &cfg.limits)?` from
`host-common`, *not* gated on `metrics`. So a build such as
`--no-default-features --features cloud-hypervisor` (compiled by the feature-powerset gate,
usable by any downstream consumer) creates the cgroup directory and returns `Ok(())` with every
requested limit **silently dropped** — the VM runs unbounded while the call reports success. This
is precisely the §7.1 "a requested functional op that silently no-ops" defect.

**Why no test catches it.** Every fail-loud limit test uses `FakeCgroupFs`, whose `create_slice`
enforces delegation *regardless of feature* — the fake over-promises relative to the real
non-`metrics` impl (a "dead fake / wrong target" smell). And the only gate that compiles the
non-`metrics` config is the feature-powerset, which is non-blocking accepted-RED debt (see §5.2).
**Impact.** In-scope for the rubric's #1 headline defect ("green-CI-that-masks-a-broken-non-default
config"). Caveat: the shipped `vmcell` binary pins `metrics` via `required-features`, so this
bites *library consumers* who select `cloud-hypervisor` without `metrics`, not the default CLI.
**Direction.** Don't gate limit *application* on the `metrics` feature (the code writes sysfs
directly and no longer needs the `metrics`-only deps), or have `config::build()`/`create_slice`
return `CapabilityUnavailable` when limits are requested without `metrics`.

### TEST-1 ✓ — Privileged transparent-egress filter test can't fail on its inverse
*Category: test-gap / correctness (security property) · Rubric Part C ("coincidental pass") · §12.4*
`crates/vmcell/tests/egress_proxy.rs:437-459`.

The transparent-egress case (no `http_proxy`) drives
`curl --resolve example.com:443:1.2.3.4 https://example.com` and asserts only
`assert_ne!(transparent.code, 0)` and `!stdout.starts_with(b"MITM SUCCESS!")`. The resolve target
`1.2.3.4:443` is a black-hole address, so the `curl` fails for network-unreachability **regardless
of whether any nft/TPROXY filter exists**. An implementation that emits *no* egress ruleset at all
(fully-open default egress) passes this test unchanged, and `!starts_with("MITM SUCCESS!")` is
trivially true in both worlds.

**Impact.** The security property "privileged transparent default egress is filtered" (H-PROXY-1)
has no assertion that reliably reddens on its inverse — the class of green-but-blind test the
whole project thesis targets. The recorded H-PROXY-1 note acknowledges the path emits no 403 body,
but not that the chosen assertion is filter-independent.
**Direction.** Drive the transparent attempt at a *reachable* control host (the same host the
explicit-proxy control proves reachable) and assert the transparent attempt is blocked while a
same-target explicit attempt succeeds; or assert a host-observable nft-drop/TPROXY counter. Do not
gate the security assertion on a black-hole address whose failure is filter-independent.

### PRIV-1 ✓ — Test-runner path-confinement is a no-op; local privilege-escalation surface
*Category: correctness (security) / design-divergence · Rubric B9 · §12.8*
`crates/vmcell-test-runner/src/main.rs:96-116` (comment `:84-89`; exec at `:373`).

`confine_under_target_dir_of(target)` canonicalizes the caller-supplied exec argument, locates its
nearest ancestor literally named `target`, then calls `confine_under(&resolved, that_ancestor)` —
where `target_root` is *by construction* an ancestor of `resolved`, so the `starts_with`
containment check is trivially satisfied. The only real constraints are "the path exists", "it has
an ancestor named `target`", and "no `..` in the raw input". `/home/attacker/target/debug/evil`
passes. The blessed runner carries `cap_net_admin,cap_sys_admin,cap_dac_override+ep` and the
file-cap path does **not** drop uid, so any user who can execute the runner can exec an arbitrary
binary under any `target/`-named directory and obtain those caps (CAP_SYS_ADMIN ≈ root) in their
own session. `just bless` sets caps but never restricts the file's mode (the justfile only *notes*
"group-restrict on shared hosts").

The v15 change (anchor on the exec target rather than the runner's own `/proc/self/exe`)
**weakened** the v14 anchor, which required the target to share the runner's own project `target/`;
the code comment at `:88-89` calling the new form "a *stronger* defense-in-depth" is backwards.
**Impact.** Local privilege escalation on any multi-user host where the blessed runner is
executable by more than its intended owner; the confinement that is supposed to be the
defense-in-depth boundary is inert. (Medium if the runner is *strictly* single-user or
group-restricted per the justfile note, as intended for a dev box — but that restriction is not
enforced by `bless`, and the misleading comment invites relying on the confinement.)
**Direction.** Anchor confinement on a *trusted* root — the workspace `target/` that is the sibling
of `.vmcell-bin/`, or the artifacts dir — not on the untrusted argument; and correct the comment.
Additionally, have `just bless` set a restrictive mode / document group-restriction as the actual
security boundary.

---

## 4. Medium-severity findings

### Resource lifecycle & teardown (B1)

- **ORCH-2 ✓ — `shutdown()` deletes the netns before dropping the proxy that runs inside it.**
  `orchestrator.rs:958-966`: `shutdown()` tears down instance → **netns → cgroup → smoltcp →
  proxy**, deleting the netns (`:958-959`) before the egress proxy (`:966`), which on the
  privileged path runs *inside* that netns (`netns: Some("vmcell-net-{vmid}")`, `:515`). `Drop`
  (`:974-990`) uses the correct order (proxy/smoltcp before netns). Removing a netns while the
  proxy still holds sockets/threads in it is the "remove netns while something holds interfaces →
  hang/leak" hazard AGENTS.md warns about; only `Drop` is tested, so the wrong `shutdown()` order
  is unexercised. *Direction:* route `shutdown()` and `Drop` through one shared ordered-teardown
  helper. (B1 · correctness · §2 step 7)

- **ORCH-6 — No orphan registry / periodic sweeper.** `orchestrator.rs` teardown is purely
  RAII/`Drop`-driven; a hard crash (SIGKILL/OOM, bypassing `Drop`) leaks
  `/var/run/netns/vmcell-net-*`, cgroups, and sockets that later vmids collide with. B1 requires a
  sweeper + orphan registry the lifecycle test asserts against. *Already-recorded as forward work*
  (`implementation-notes.md:304-307`); surfaced here because it is a standing B1 gap, not closed.
  (B1 · design-divergence)

### Failure visibility & fail-loud (B2)

- **ORCH-3 ✓ — Non-zero clock-resync exit is swallowed; `restored` cleared anyway.**
  `orchestrator.rs:344-356,422-425`: the post-restore `date -s @{host_time}` exec is
  `?`-propagated only for the *transport* error; a non-zero exit code merely `warn!`s (`:351-356`),
  then `*restored = false` runs unconditionally (`:425`) under a comment claiming the resync
  "succeeded." A persistently failing clock set is thus swallowed, never retried, and
  time-sensitive tests silently see a frozen wall clock. §9.2 calls this resync mandatory.
  *Direction:* treat a non-zero exit as a surfaced/typed failure (or keep `restored` set for a
  bounded retry). (B2/A1 · correctness · §9.2)

- **AGENT-1 — Reaper/`record_exit` non-atomic under PID reuse (residual false-exit-code race).**
  `crates/vmcell-guest-agent/src/main.rs:25-35` + `lib.rs:100-107,143-175`: `drain_zombies`
  `wait(WNOHANG)` frees the pid, then calls `record_exit(pid, code)` — the two are not atomic, so a
  grandchild reaped and recorded *after* a reused pid has been `reserve()`d can be stamped with a
  generation past the reservation epoch and accepted as that child's exit (false result, the B2
  class narrowed but not closed). Code matches the recorded note exactly.
  *Already-recorded as a deliberately-deferred issue* (`implementation-notes.md:1436-1446`);
  surfaced so it is not lost — record the reaped status inside the same critical section that does
  the reservation + generation bump. (B2 · correctness · §4.3)

### Concurrency & guest-driven state (B2/NET-5, B6)

- **NET-1 ✓ — Unbounded proxy request log on the production egress path.**
  `crates/vmcell/src/proxy/doubles.rs:81,98`; `RequestLog = Vec<String>`
  (`crates/vmcell/src/proxy/mod.rs:21`); getter `:310-315`. `ProxyHandler::route_request` (the real
  hudsucker handler, not a test double despite the file name) pushes one `String` per request —
  both `403 BLOCKED {host}` and forwarded `{method} {uri}` — into an unbounded `Vec` that is never
  truncated, pruned, or ring-buffered. A guest issuing N requests grows host memory O(N). This is
  the same NET-5 class the *smoltcp* pool correctly caps. *Direction:* bound the log (ring buffer /
  cap with drop-oldest) and assert it stays capped after a flood. (B2/NET-5 · correctness)

- **NET-2 — smoltcp advertises `VIRTIO_NET_F_CTRL_VQ` but declares only 2 queues, no handler.**
  `crates/vmcell/src/net/smoltcp.rs:260` sets `1 << 17` (CTRL_VQ) while `:33` `NUM_QUEUES = 2` and
  `handle_event` only services the TX queue; a negotiated control vq (index 2) is never declared or
  drained, and no dependent CTRL_RX/CTRL_MQ sub-features are advertised. An advertised-but-unbacked
  feature (B8 "no dead feature variants advertised as live"); at best pointless, at worst perturbs
  guest driver queue setup. *Direction:* drop the CTRL_VQ bit, or implement a real control queue +
  handler and bump `NUM_QUEUES`. (B8/B3 · design-divergence)

### Artifact pipeline (B4/B5)

- **ART-1 — `SnapshotStage`'s directory output is never cached or content-verified.**
  `crates/vmcell/src/artifact/mod.rs` build cache-write path + `snapshot.rs:91-94`: `SnapshotStage`
  produces a **directory**, but `Pipeline::build` validates/caches via `hash_file(out_path)`, which
  `File::open`s the directory and `read`s it → `EISDIR`, landing in the `Err(e) => warn!(...)` arm,
  so **no `.cache_key` sidecar is ever written for the snapshot stage**. The most expensive stage
  (it boots a VM) is thus never cached and never tamper-verified — the content-addressed guarantee
  §11 claims silently does not hold for it. Latent today only because no shipped CLI pipeline wires
  `SnapshotStage` (ART's D3), but it is a public exported `Stage` and *the* real cache-key example
  in `test_pipeline_determinism`. *Direction:* hash directory outputs (recursive content hash over
  a sorted walk) or let a `Stage` advertise file-vs-dir. (B4/B5 · correctness)

- **ART-2 — `reset_to` errors on the snapshot directory instead of purging it.**
  `artifact/mod.rs` `remove_if_present` uses `std::fs::remove_file`, which returns `EISDIR` (not
  `NotFound`) on a directory → propagated as `Error::Io`. Since the snapshot output is a directory
  (ART-1), `reset_to(<any stage at/before snapshot>)` fails once the snapshot dir exists, so a
  stale snapshot cannot be invalidated via the intended path. `test_reset_to_propagates_remove_error`
  actually *locks in* this behavior by forcing the dir-error. *Direction:* handle a directory in
  `remove_if_present` (`remove_dir_all`), or declare output kind per stage. (B5 · correctness)

- **ART-3 — No injectable OCI pull seam; the pull→cache→re-verify→decode chain is untested e2e.**
  `crates/vmcell/src/artifact/rootfs/oci.rs:17` constructs `Client::default()` inline (contrast the
  kernel stage's `HttpClient` trait). Only the pure leaf helpers are unit-tested; the cache-hit
  re-verify (`oci.rs:64-68`), tag-rejection, and gzip/zstd decode-selection are never exercised
  through `build_rootfs`, so a regression that (e.g.) skipped re-verify on the hit path would not go
  red. B5 explicitly requires an injectable OCI pull seam for record/replay + tamper tests.
  *Direction:* introduce a recording/replaying pull seam and drive a pull+cache-hit+tamper test.
  (B5 · test-gap)

- **ART-4 — Decode-completeness regressions are untested.** `crates/vmcell/src/artifact/tar2erofs.rs`
  device-node handling uses `libc::makedev` (correct), but no test builds a tar with a Char/Block
  device node, so replacing it with `(major<<8)|minor` passes every test; likewise there is no
  zstd-layer decode test and no whiteout (`.wh.`) test. These are exactly the "zstd layer → empty
  rootfs; rdev via makedev" regressions the rubric names. *Direction:* add device-node round-trip,
  zstd-layer, and whiteout tests. (B4 · test-gap)

### Guest wire framing (Part C)

- **AGENT-3 — Guest `send_framed`/`read_framed` are never exercised in the default suite.**
  `crates/vmcell-guest-agent/src/main.rs:428-450`: the guest's hand-rolled length framing is the
  load-bearing interop with the host's `tokio_util` `LengthDelimitedCodec`, but every default-suite
  test uses `LengthDelimitedCodec` on *both* ends — the guest framing runs only under the KVM-gated
  matrix tests. A buggy `send_framed`/`read_framed` (wrong endianness, off-by-the-prefix, or a
  `MAX_FRAME_BYTES` cap mismatch at `:441`) passes the entire non-KVM suite green and fails only on
  a KVM host (skip==pass hazard). *Direction:* add a KVM-free `#[cfg(test)]` round-trip in `main.rs`
  that frames with `send_framed` and decodes with a real `LengthDelimitedCodec` (and vice-versa),
  plus an over-`MAX_FRAME_BYTES` reject. (Part C · test-gap · §4.1)

### Backends & tests (B7, Part C)

- **VMM-2 — Triplicated spawn/register/readiness boilerplate has already diverged.**
  `cloud_hypervisor.rs:269-279`, `firecracker.rs:181-191`, `qemu.rs:439-449`: the "capture pgid →
  `add_task` (reap-on-err) → `wait_for_socket` (reap-on-err)" sequence is copy-pasted in all three
  `spawn_*`, and QEMU already wraps the readiness error differently (`Error::Vmm(format!(...))`)
  while CH/FC propagate the raw error. This is the exact triplication where per-backend divergence
  bugs hide (B7). *Direction:* extract one shared spawn+register+await-ready helper (the primitives
  already exist). (B7 · code-quality)

- **ORCH-5 — No unit test that dropping a `MicroVm` returns CID+VMID to the allocator.**
  `orchestrator.rs` tests: the drop-order test builder sets `cid: None, vmid: None`, so the
  guard-Drop release paths are no-ops there; `test_allocate_vmid` exercises the `release()` *method*
  directly, not guard-Drop. The B6 "no-op release" inverse would not redden in this file. (Partly
  covered at the integration level — `lifecycle.rs:175-180` asserts CID reuse after release — so
  this is a unit-level gap, not an uncaught bug.) *Direction:* add a unit test that builds a
  `MicroVm`, captures its ids, drops it, and asserts re-allocation of the same ids. (B1/B6 ·
  test-gap)

- **TEST-2 ✓ — The CH primary path is exempted from the capability check.**
  `crates/vmcell/tests/egress_proxy.rs:276-286`: `test_egress_proxy_unprivileged` does
  `println!("SKIP…"); return;` on the concrete cloud-hypervisor backend when
  `unprivileged_vhost_user_net` is false, bypassing `require_cap!` (which `panic!`s for the primary
  path). A CH capability-descriptor regression (the flag flipping to false) makes the very test
  `just test-unprivileged` selects pass green instead of hard-failing. The rubric requires the
  CH/primary path *not* be exempted. *Direction:* route the CH primary path through `require_cap!` /
  hard-fail. (Part C · test-gap · §12.4)

---

## 5. Test coverage & gates

### 5.1 Additional test-gaps (Low)

- **TEST-3 — CID-release proptest asserts too little.** `crates/vmcell/tests/proptests.rs:7-40`:
  after releasing half the CIDs, it asserts only `cid >= 3` and "not among the still-held second
  half," never that a reallocated CID is one of the *freed* values, and never exercises wraparound.
  A no-op `release()` still returns a fresh unique `>=3` CID → passes. (Capped Low: the no-op-release
  bug is separately caught by `lifecycle.rs:175-180`.) *Direction:* assert reuse of a released value
  + a wrap-without-colliding-with-live case.
- **NET-3 — smoltcp pool cap is unit-tested in isolation but the SYN loop is not driven.**
  `crates/vmcell/src/net/smoltcp.rs:711-754`: `reclaim_and_has_room` has good unit tests, but no
  test feeds the real `run_network` SYN loop N distinct destination ports to assert `port_mappings`
  stays ≤ `MAX_DYNAMIC_SOCKETS`; a `run_network` that skipped the cap guard would not redden.
- **AGENT-4 / TEST-5 — No positive runtime zero-netlink assertion.** The agent does zero
  `ip link/addr/route` (by construction; loopback via ioctl), and the *structural* guard (the
  lean-agent `cargo tree` ban on `rtnetlink`) is recorded and correct
  (`implementation-notes.md:1630-1645`). The residual gap: a regression that *shells out* to `ip`
  (adding no crate) at boot/restore would pass every gate. A cheap grep-ban on `ip ` invocation
  inside the agent would close it. (Largely covered by the recorded structural guard; noted as the
  remaining hole.)
- **TEST-4 — Loose `or` body assertion.** `crates/vmcell/tests/host_endpoint.rs:130-134` asserts
  `stdout.contains("Directory listing") || stdout.contains("html")`; `egress_proxy.rs:234` already
  uses the tighter `"Directory listing for"`. Minor (`code == 0` is asserted separately).

### 5.2 Gate coverage (Part D)

All Part D gates are present and, in several cases, notably strong (the `ban-global-state.sh`
covers alias-bypass with a red-on-inverse self-test; `deny.toml` carries per-crate ignore
rationales; `-D warnings` is set identically local and CI via `RUSTFLAGS`; the `--ignored`
integration matrix selects > 0 tests on both suites; nextest has per-test timeouts). Two gaps:

- **The host crate is only built `--all-features`; no *blocking* gate compiles a reduced host
  feature config.** The gate that would catch a `#[cfg]`-gating break in a partial-host build (i.e.
  CFG-1's class) is the feature-powerset clippy, which is **non-blocking accepted-RED debt**
  (`ci.yml` `continue-on-error: true`; `justfile` runs it last, non-gating; recorded as C-GATE-1).
  This is the direct enabler of CFG-1 reaching this review. Part D's own row 2 prescribes building
  *and* clippy-ing each build target including reduced host configs as the replacement for the
  powerset once features collapse — that collapse was deliberately deferred (recorded), leaving the
  powerset as the only (non-blocking) coverage. *Consider* a small blocking build of the two or
  three host feature configs that actually ship, rather than the full powerset.
- **PRIV-4 — `test-ban-global-state.sh` does not prove the `OnceLock`/`Mutex`/`RwLock`/`Lazy`
  detection can fail.** `scripts/test-ban-global-state.sh:18-30`: all MUST-be-flagged fixtures use
  `Atomic*`; the only `OnceLock` fixture is expected *clean* (it carries the exemption marker). So
  deleting `OnceLock|OnceCell|Mutex|RwLock|Lazy|once_cell` from the scanner's keyword list leaves
  every fixture expectation intact and the self-test still passes — a "gate that can't fail" for
  that half of its keyword list. *Direction:* add a MUST-be-flagged fixture with a bare
  (un-exempted) `static X: Mutex<..> = Mutex::new(..)` / `OnceLock` declaration.

Positive Part-C verifications (checked, correct) are in Appendix B.

---

## 6. Low-severity findings & code-quality opportunities

**Backends (VMM).**
- VMM-3 — `probe_t2_template` (`firecracker.rs:224-236`) hand-rolls its own readiness loop
  (`try_exists` only, no `try_wait`) and reaps with leader-only `process.kill()` instead of the
  shared group-kill. Reuse `wait_for_socket` + `reap_process_group`.
- VMM-4 — Any non-template probe failure (`firecracker.rs`) is cached permanently as "no T2" on the
  shared `Arc<OnceLock>` with no `warn!`; a transient host error silently disables the T2 template
  for all VMs. Distinguish "T2 unsupported" from "probe failed," and log.
- VMM-5 — QEMU's `-incoming defer` restore branch (`qemu.rs:421-423`) is dead (`create` passes
  `None`; `restore` errors before spawning). Remove or wire behind the (off) capability.
- VMM-6 — FC restore sets `serial_path` to the snapshot's baked path while FC writes serial to the
  fresh `tmp_dir/serial.log`, and `FcInstance` has no `restored` flag so `boot()` would
  `InstanceStart` a restored VM. Currently unreachable (FC `snapshot_restore` honest-false); must be
  fixed before FC warm-restore is un-gated.

**Orchestrator (ORCH).**
- ORCH-1 — Restore resync execs `ip link set … address && ip addr flush && ip addr add && ip route
  add` (`orchestrator.rs:399-420`) — the form §9.2 declares wrong. Safe *only* because the in-rootfs
  guest-tools helper no-ops the `ip addr`/`route` forms; fragile if PATH ever resolves a real `ip`
  first (a BYO `oci2erofs` base). The base deviation is recorded, but the inline comment (`:391-398`)
  contradicts the recorded no-op rationale. *Direction:* send only `ip link set eth0 address {mac}`
  on restore and fix the comment.
- ORCH-4 — Restore-path law rejections return `Error::Config` (`:736,742,751`) where §3.3 boundary 2
  specifies `Error::Unsupported`; a caller matching `Unsupported` for capability rejections won't
  match. Minor contract divergence.
- ORCH-7 — `request_shutdown()` is immediately followed by an unconditional `kill()`
  (`:952-955`) with no bounded grace window; the guest may get ~0 time to flush. Await a bounded
  `try_wait` before the SIGKILL fallback.
- ORCH-8 — `VmidAllocator::allocate()` seeds its search start from `SystemTime::now()` directly
  (`:144-148`) while the file injects a `Clock` everywhere else. Non-critical (a hermetic seed), but
  a non-injected time source.

**Networking (NET).**
- NET-4 — TOCTOU on concurrent first-time CA materialization (`proxy/tls.rs:95-141`): two concurrent
  `new_in(dir)` each generate + `rename`, last-writer-wins on disk while the cache keeps the first,
  so on-disk `ca.pem` can diverge from the in-memory authority. Narrow (the CA is normally baked at
  build time before proxies run). Serialize generate-or-load under the cache lock.
- NET-5 — Two unlabeled `.expect("push ip")` / `.expect("add route")` in `run_network` iface setup
  (`smoltcp.rs:602,606`); effectively unreachable but would silently kill the net thread. Convert to
  logged early-return or annotate `expect("invariant: …")`.
- NET-6 — Stale line reference in `implementation-notes.md:113` (cites `net/tap.rs:315-326`; the
  renderer is now `render_tproxy_rules` and UDP/443 is dropped by default-policy, not an explicit
  rule).

**Config / metrics / fs (CFG).**
- CFG-2 — `try_apply_limit` (`metrics.rs:148-168`) skips the `subtree_control` delegation
  read-back for parent-less cgroup names (the `vmcell-vm-{vmid}` fallback), relying solely on the
  write-failure backstop. Fail-loud is preserved by the backstop; belt-and-suspenders erosion.
- CFG-3 — In-process virtiofsd correctly *refuses* a read-only share (fails loud), but surfaces it
  as stringly `Error::Subprocess` (`fs.rs:207-209`) rather than a typed
  `Unsupported { feature: "read-only share" }`; and the recorded deviation wording ("RO not
  enforced") is stale — the code refuses rather than mounting rw. Reword both.
- CFG-4 — `CpuFreqPin::engage` (`cpufreq.rs:267-268`) propagates `Err` on a CPU-enumeration failure
  rather than `warn!`+no-op; §7.1 lists cpufreq as the best-effort exception that degrades visibly,
  never aborts. Documented in-module as the single intentional fatal case — a minor tension; the
  maintainer may prefer to degrade it or record the intent.

**Guest agent (AGENT).**
- AGENT-2 — On SIGTERM the agent's signal loop `break`s and `main` returns `Ok(())`
  (`main.rs:301-304,325`) → for PID 1 this kernel-panics the guest ("Attempted to kill init"), which
  the host's `contains_panic()` then flags. The *fallback* branch's own comment (`:309-310`) states
  "PID 1 must never exit on a recoverable condition" — which the primary SIGTERM path contradicts.
  Narrow reachability (normal teardown force-kills the VMM group, not the guest PID 1). Loop / power
  off instead of returning, or document why the exit is safe.
- AGENT-5 — `handle_connection` (`main.rs:416-425`) handles only `Exec`/`PutFile`; any other decoded
  variant falls through with no log/reply — a silent protocol-desync swallow. Add a trailing
  `warn!` (and consider closing the connection).
- AGENT-6 — `create_dir_all("/sys")?` (`main.rs:86`) is fatal, while a `/sys` *mount* failure is
  deliberately tolerated (`:127-138`) — inconsistent with its own documented core-mount policy
  ({overlay, /proc, /dev}). Near-unreachable; treat the `/sys` dir op as log-and-continue.

**Artifact (ART).**
- ART-5 — The OCI manifest bytes are not independently re-hashed against the pinned digest in-code
  (`oci.rs:29-32`); the whole layer-verification chain roots in an unverified-in-code manifest.
  Confirm `oci_client` guarantees this, else re-hash the raw manifest against the `sha256:` pin.
- ART-6 — `ResolvePinsStage` docstring (`mod.rs:657,671`) says it "resolves abstract versions into
  exact hashes"; it actually copies the committed `pins.json` lock. Deviation itself is recorded;
  fix the stale docstring.
- ART-7 — mmdebstrap pins the `snapshot.debian.org` timestamp (good) but passes no explicit
  `--keyring`/`Signed-By` and uses `http://[check-valid-until=no]`; gpg is implicit (apt default).
  Path is currently deferred/unreachable. Pass an explicit pinned keyring when un-deferred, or
  document reliance on apt defaults.
- ART-8 — On a `hash_file` miss the cache-key fallback (`mod.rs:213-216`) folds the artifact's
  absolute `PathBuf` under `target/` — the non-traveling identity B4 warns against. Prefer a stable
  error marker or a hard error.
- ART-9 — The rootfs cache key folds *all* upstream artifacts including the kernel, so a kernel
  rebuild spuriously invalidates the OCI rootfs (which doesn't depend on it). Correct for the
  mmdebstrap source; over-invalidating (never stale-serving) for OCI. Fold only consumed artifacts.
- ART-10 — Base-config failure (`kernel.rs:313-316`) reports `"Failed to write kernel config
  fragment"` for the `make defconfig kvm_guest.config` step, which writes the base config, not a
  fragment. Reword.
- ART-11 — `ResolvePinsStage::cache_key` (`mod.rs:676,687`) uses `unwrap_or_default()`, collapsing
  distinct error states to `""` (contrast `GuestToolsStage`, which folds the error into the key).
  Low (run() fails hard on these). Mirror the guest-tools pattern.

**CLI & benches (CLI).**
- CLI-1 — `let _ = stdout().write_all(&outcome.stdout);` (`bin/vmcell.rs:284-285`) and pervasive
  `let _ =` teardown discards in `bench-vm.rs` lack the B2-required justifying comment.
- CLI-2 — `benches/micro.rs:59-67` benches a hand-rolled `format!("10.200.{}.1", vmid)` instead of
  the production `/30` helper (`net::mod`), which applies `(vmid%254)+1` and a different octet — so
  the tracked "math_30_ipv4_parse" metric guards a strawman that a real `/30` regression can't move.
  `black_box` the real helper.
- CLI-3 — `bench-vm.rs:166` uses `.expect("required configuration failed")` on `create_dir_all` in
  the restore-baseline path, while the sibling `run_suspend_size` handles the identical call
  gracefully; a real I/O failure panics the whole harness. Mirror the graceful return.
- CLI-4 — `bench-vm.rs:437-440` (`latency` mode) drops the Warm-Restore benchmark for a
  no-snapshot backend with **no** printed skip-reason, while `suspend-size`/`phase-budget` print one
  (§13.2 visible-skip). Emit a skip-with-reason.
- CLI-5 — The `latency`/Warm-Restore path snapshots to `temp_dir()` (commonly tmpfs) rather than
  honoring `--snap-dir` (`bench-vm.rs:141-142`), making warm-restore latency systematically
  optimistic (RAM-backed). Known §13.1 caveat; honor `--snap-dir` or comment the intent.

**Privileged window (PRIV).**
- PRIV-3 — `scripts/review-preflight-priv.sh:53` (and design §12.8 snippet) tell the operator
  `just bless` builds "with `--features test-runner`"; after the workspace split the runner is its
  own featureless crate built via `-p vmcell-test-runner`, so the reproduction command errors.
  Stale, unfollowable remediation in a privileged-review gate — update to `-p vmcell-test-runner`.
- PRIV-6 — The runner's remediation prose (`main.rs:16,34-39`) hardcodes "missing
  CAP_NET_ADMIN/CAP_SYS_ADMIN" and omits `CAP_DAC_OVERRIDE`, and discards the precisely-computed
  `missing` vec. The printed `setcap …+ep` is correct, so cosmetic. List the actual `missing` caps.
- PRIV-7 — guest-tools adds reqwest proxies in order all_proxy → http → https
  (`vmcell-guest-tools/src/main.rs:396-413`); since `Proxy::all` matches every scheme and reqwest
  uses first-match, an HTTPS URL is routed via all_proxy, shadowing a scheme-specific https_proxy —
  the opposite of curl precedence. Not load-bearing for the current tests; add scheme-specific
  proxies before all_proxy, or document the reduced contract.

---

## 7. Design divergences

**Unjustified / gaps (in this report):** VMM-1 (CH/QEMU no self-guard for a virtio-fs rootfs);
ORCH-2 (`shutdown()` teardown order); ORCH-3 (clock-resync swallow); ORCH-4 (`Config` vs
`Unsupported` variant on the restore-path law); NET-2 (CTRL_VQ advertised, unbacked); ART-1/ART-2
(snapshot dir output vs the file-only cache/reset machinery); PRIV-1 (confinement anchored on the
untrusted target; the "stronger defense-in-depth" comment). ORCH-1 is a recorded deviation
implemented in the design's deprecated form with a self-contradicting comment.

**Justified & new (moved to `implementation-notes.md` → "Review 39 …"):** the CLI verbs' snapshot-
eligibility-by-construction; `vmcell-test-runner`'s `libc` dependency (getgrnam / setres*uid); and
the deliberate exclusion of `CAP_SETPCAP` from the runner's standing set (which makes the
bounding-drop best-effort and requires correcting the impl-notes:52 "bare minimum" wording).

**Justified & already-recorded (dropped, not re-reported):** FC/QEMU snapshot gate-offs and the
FC `resume_vm:false`+`noxsave` choices; `restore(&VmConfig)` signature; the structural
zero-netlink guard; `NetConfig::host_services_port`; `Error` stringly per-subsystem payloads; the
in-process-virtiofsd RO handling (wording nit → CFG-3); Stage 0 as a committed-lock loader
(ARTIFACT-PIPELINE-5); the deferred mmdebstrap path; the daemon-deferred CLI verbs
(`exec`/`ls`/`rm`/`destroy`) and the `bundle`/`verify-bundle` additions; the `Hello`/`Ping` protocol
omission; guest-tools' `reqwest`; the M-FS-1 virtiofsd uid; the H-PROXY-1 explicit-proxy transparent
limitation; the TPROXY UDP/QUIC drop; the host-NAT-MAC literal; the ORCH-6 sweeper as forward work.

---

## Appendix A — Coverage map (subsystem → files reviewed)

| Sub-review | Files |
|---|---|
| VMM backends | `vmm/{mod,cloud_hypervisor,qemu,firecracker}.rs` |
| Orchestrator | `orchestrator.rs` |
| Networking + egress | `net/{tap,smoltcp}.rs`, `proxy/{mod,tls,doubles}.rs` |
| Artifact pipeline | `artifact/{mod,kernel,tar2erofs,snapshot,bundle,guest_tools}.rs`, `artifact/rootfs/{mod,oci,mmdebstrap}.rs`, `pins.json` |
| Config/error/metrics/fs | `config.rs`, `error.rs`, `metrics.rs`, `cpufreq.rs`, `fs.rs`, `fs/in_process.rs` |
| Guest agent + protocol | `vmcell-guest-agent/src/{main,lib}.rs`, `vmcell-protocol/src/lib.rs`, `agent/mod.rs` |
| Privileged window | `vmcell-test-runner/src/main.rs`, `vmcell-guest-tools/src/main.rs`, `scripts/*.sh` |
| CLI + benches | `bin/{vmcell,bench-vm}.rs`, `benches/micro.rs` |
| Tests + CI gates | `tests/**`, `.config/nextest.toml`, `justfile`, `.github/workflows/*`, `deny.toml`, `clippy.toml` |

## Appendix B — Verified compliant (checked, no finding)

Recorded so a later pass need not re-derive them:

- **B1 teardown:** all three backends cache pgid at spawn and reap the process *group*
  (`kill(-pgid)`+`waitpid`), VMM group → daemons → sockets; post-spawn failures reaped via
  `reap_process_group`; QEMU's vhost-device-vsock owned by an RAII `VsockDaemonGuard`.
  `MicroVm::Drop` releases **both** CID and VMID and asserts the `instance → netns → cgroup`
  sequence on normal *and* panic paths via recording fakes; post-acquire guards are armed before the
  fallible `create()`/`boot()`/`resume()`.
- **B3 snapshot-eligibility law:** enforced at `config::build()`, re-checked at
  `orchestrator::restore()`, and self-guarded in each backend `restore()`/`snapshot()` — for the
  virtio-fs rootfs, the **data-share** case, and `NetConfig::Unprivileged` — each with a negative
  test. CH `lazy_restore` is genuinely plumbed via `prefault`; FC/QEMU capabilities are honest-false
  with guarding tests.
- **B4/B5:** cache keys use `blake3` over a `BTreeMap` (no `HashMap` order), embed a stage version +
  pinned SHA, fold the guest-agent src hash and guest-tools content into the rootfs key; validity is
  content-addressed with tamper-rejection on the *hit* path (incl. the cached OCI blob); digest-
  pinned pulls with tag-rejection; gzip+zstd decode with fail-loud on unknown media type; `makedev`;
  `reset_to` errors on an unknown stage; determinism tested on a **real** stage with a golden
  cross-process key; the tamper test corrupts artifact bytes (sidecar intact) and asserts abort.
- **B6:** `(vmid%254)+1` centralized in `net::ip_math`, used at every site, overflow rejected at
  vmid ∈ {0,255}; host NAT MAC pinned outside `mac_math(1..=254)` with a test; allocators injected
  (no module-global statics), `release()` on the real instance, reserved CIDs skipped.
- **B2 hot paths:** no `.expect()` on guest-controlled descriptor indices (both TX and RX vring dirs
  log-and-skip); `bounded_tx_read` caps guest `desc.len()`; mutex poison recovered via `into_inner`.
- **B8:** `#[non_exhaustive]` on growable public types; `#[from]` variants `#[cfg]`-gated to their
  features; no `Error::Other`; no `Hello`/`Ping`; `#![forbid(unsafe_code)]` on the I/O-free modules.
- **B9:** effective-set (not permitted) capability probe with a matching `+ep` remediation;
  privilege-drop ordering correct and singular (uid→inheritable→bounding→ambient→trim, one path, no
  dead second block); no logging stack at full privilege; standing set exactly the three caps, KVM
  via group; guest-tools implement real `ip`/`curl`/`kvm-ok` (only the `ip addr/route add|del|flush`
  forms no-op, per the zero-netlink invariant).
- **Part C:** OOM test sets guest RAM (512 MiB) *above* the cap (256 MiB) and asserts
  `memory.events oom_kill > 0` + `swap.max==0` + `oom.group==1`; the clock-resync FakeClock is driven
  on the *first* post-restore call and the CSPRNG reseed asserted via a typed control *and* a byte
  diff; `put_file` is a real in-guest round-trip; serial execution comes from the nextest
  `serial-host` group; the `--ignored` matrix selects > 0 on both suites.
