# 46 — Code Review of the vmcell implementation

**Scope:** the entire first-party implementation at git HEAD `85547dd` — all five workspace
crates (`vmcell`, `vmcell-protocol`, `vmcell-guest-agent`, `vmcell-test-runner`,
`vmcell-guest-tools`), the CLI and `bench-vm` harness, the benchmark/micro benches, the gate
scripts, `justfile`/`deny.toml`/`clippy.toml`, and the carried `vendor/vhost{,-user-backend}`
patch. ~29k first-party lines.

**Method.** Nine file-disjoint sub-reviews (one per subsystem cluster), each grounded in the v17
design doc, `implementation-notes.md`, and the perf investigation (`docs/45`). Every
Critical/High finding was then handed to an **independent adversarial verifier** instructed to
refute it — re-deriving the claim from the code, checking it against recorded deviations and
documented gaps, and running a decisive empirical check where one existed (a compiled `size_of`
probe for the ioctl finding, a reproduction of the percentile function, a struct-drop-order
check, inspection of the cached Debian rootfs tar). Verdicts below are **post-verification**;
several reviewer-reported Highs were downgraded when the verifier showed the path was
unreachable in a supported flow or already documented.

**This is not a static-only review.** The full suites were built and run on this KVM host at
this HEAD before the review, all green:

| Suite | Result |
|---|---|
| `just test-unit` | **264 passed**, 40 skipped |
| `just test-unprivileged` | **2 passed**, 33 skipped |
| `just test-privileged` (delegated scope, CH+FC+QEMU) | **59 passed**, 2 skipped — incl. `snapshot_restore` on CH *and* FC |
| `just ci` | clean, incl. the 205-config feature powerset |

Toolchain: rustc 1.96.0, cargo-nextest 0.9.138. **The central finding of this review is what
that green board does not prove.** The design's own thesis — "a green CI is necessary but not
sufficient; four broken implementations passed green" — still holds: every Critical and most
Highs below sit on a path the suites structurally cannot reach (a mid-`start()` failure branch,
a post-restore data transfer, an OOB write whose corruption is currently benign, a bench that
publishes a wrong number). The gates catch the defect *families* they were built for; these are
the ones no gate sees.

---

## 1. Executive summary

208 findings across the nine clusters. After adversarial verification:

| Severity | Count | |
|---|---|---|
| **Critical** | 2 | both confirmed |
| **High** | 13 | confirmed (one is C-BIN-1, downgraded from Critical) |
| **Medium** | ~40 | incl. 11 reviewer-Highs downgraded here |
| **Low / Nit** | ~150 | |

The two Criticals are a **22-byte out-of-bounds write onto PID 1's stack** on every guest boot
(`C-GUEST-1`) and **silent guest-stream corruption in the unprivileged NAT** under TCP
backpressure (`C-NET-1`). Neither is caught by the green suites because the OOB bytes currently
land in benign stack padding and the NAT tests move only tiny payloads.

**Top themes:**

1. **The restore and networking data-planes are under-tested relative to their complexity.**
   Post-restore guest networking is silently dead under the default vmid-rotating flow
   (`H-VMM-1`); the privileged "Filtered" egress proxy can only ever serve test doubles because
   its upstream sockets live inside the VM netns (`H-NET-3`); `Egress::Open` — the documented
   default — behaves as `Blocked` in both modes (`H-NET-4`). Each is masked by tests that assert
   over vsock or against a double, never a real egress byte.
2. **`Privileged { host_services_port }` is a silent no-op** — reported independently by three
   clusters (orchestrator, net, and the test suite's top coverage gap). It violates the §12.2
   fail-loud contract with a bare, uncommented `let _ =`.
3. **Fail-loud has gaps at the edges.** A transient post-restore resync failure permanently
   wedges `agent()` (`H-ORCH-2`); `tar2erofs` silently drops hardlink entries (`H-ART-2`);
   guest-tools' HTTPS probe returns exit 0 on any proxy response including TLS-validation failure
   (`H-GUEST-1`); the `--agent-musl` rootfs cache key folds a path string instead of content
   (`H-ART-1`).
4. **The benchmark harness that underwrites the perf docs has a percentile bug** (`C-BIN-1`):
   `floor(n·q)` makes every published p95 at N=20 equal to the sample max. The error is
   pessimistic (it can't hide a regression) and benchmarks are non-gating, which is why it's High
   not Critical — but the numbers in `benchmark-results.md` inherit it.
5. **One core test-discipline rule is violated:** capability-based skips are silent green passes,
   not visible skips-with-reason, and 4 of 7 capability flags have no honesty pin — so a backend
   flag regressing to `false` would disable a whole scenario invisibly (`H-TEST-3`).

**Overall assessment.** This is a mature, unusually well-disciplined codebase: the teardown
spine, the snapshot-eligibility triple-guard, the EXP-D shutdown rework, the AGENT-2 reaper epoch
logic, the cache-key fundamentals, and the privileged capability runner are all correct and
red-checked, and the security-critical runner passes every item on its checklist. The defects
concentrate exactly where the design predicts they would: paths a green test cannot redden. None
requires an architectural change; all are localized fixes. The vendored patch matches its stated
purpose exactly, with no undisclosed divergence.

A note on the review itself: findings were produced by AI sub-agents and adversarially
re-checked, but the fixes are **not** applied (per request) and each should be confirmed against
the cited line before action — a residual-error rate is expected in any review of this size.

---

## 2. Critical findings

### C-GUEST-1 — OOB stack write in PID 1 on every boot (loopback bring-up)
`crates/vmcell-guest-agent/src/main.rs:236-241` · category: soundness/rust · **CONFIRMED
(empirically)**

The loopback bring-up declares its own inline `ifreq`:

```rust
#[repr(C)]
struct ifreq {
    ifr_name: [std::os::raw::c_char; 16],
    ifr_flags: std::os::raw::c_short,
}
```

That is **18 bytes** (verified: a standalone `rustc` probe prints `size_of == 18`,
`ifr_flags @ 16`). It is passed by pointer to `SIOCGIFFLAGS`/`SIOCSIFFLAGS` on an `AF_INET`
socket. The kernel's `struct ifreq` on x86-64 is **40 bytes** (16-byte name + 24-byte union);
`SIOCGIFFLAGS` goes through `sock_do_ioctl`, which `copy_from_user`s 40 bytes and, via
`put_user_ifreq`, writes **40 bytes back** into the caller's buffer — a **22-byte out-of-bounds
read and write onto PID 1's stack** on every guest boot. The adjacent `SAFETY`-style comment
calling the struct "correctly-sized" is false.

Today the corruption is benign (the extra bytes land in stack padding, which is why the boot
succeeds and the suites are green), but writing past a stack object is undefined behavior
regardless of observed effect, in the single most safety-sensitive process in the guest. The
correct layout already exists one module over: `netif.rs`'s `IfReq` matches `libc::ifreq` and is
offset-tested. `M-GUEST-5` is the same root cause: the loopback path duplicates
`netif::set_link_up` with this divergent, buggy inline struct instead of reusing it.

*Suggested direction (not applied):* delete the inline `ifreq` and route loopback through the
audited `netif` helper (or a `libc::ifreq`-sized buffer). Add a `size_of` assertion. Per the
design, a loopback ioctl *failure* is cosmetic — but this is not a failure, it's UB.

### C-NET-1 — Unprivileged NAT silently drops bytes under TCP backpressure
`crates/vmcell/src/net/smoltcp.rs:876-887` · category: correctness · **CONFIRMED**

The host→guest data pump reads from the host stream into `buf`, then enqueues into the smoltcp
socket but **discards the enqueued-byte count**:

```rust
Ok(n) => {
    if let Err(e) = socket.send_slice(buf.get(..n).unwrap_or(&[])) {
        tracing::error!("smoltcp send_slice failed: {:?}", e);
        closed = true;
    }
}
```

`send_slice` returns `Ok(enqueued)` where `enqueued` can be **less than `n`**: the vendored
smoltcp enqueues "down to zero" against available TX buffer, and `can_send()` (the gate above)
returns true when as little as **one byte** is free. The unsent tail of the `n` bytes already
consumed from the host stream is silently dropped — corrupting any host→guest TCP stream large
enough to fill the guest's receive window (a file download, a large POST body through the NAT).
The green unprivileged tests move only tiny payloads (`egress_proxy.rs:42,233`), so they never
fill the window.

*Suggested direction:* loop on the returned count, retaining the unsent remainder and
re-enqueuing when the socket can send again (mirroring the guest→host leg), or hold the read
buffer until fully enqueued. *Perf note:* this is the unprivileged datapath, not a measured
hot-path lever; no documented perf win is affected.

---

## 3. High findings

### H-VMM-1 — Post-restore guest networking silently dead under vmid rotation
`crates/vmcell/src/vmm/cloud_hypervisor.rs:282-303` (with `orchestrator.rs:809,536`,
`net/tap.rs:376`) · correctness · **CONFIRMED**

CH `--restore` rebuilds every device from the snapshot's `config.json`; the restore config
rewrite correctly rewrites the vsock and serial/console paths but **never rewrites the baked
`net[].tap` name**. Meanwhile the orchestrator's restore path allocates a **new** vmid and builds
a fresh netns/tap and `/30` for it, while the restored guest keeps the **old** vmid's `ip=`
address from the frozen kernel state (design §9.2 deliberately does not rotate the guest IP). The
result: the guest's IP and the host-side tap/`/30` wiring belong to different vmids, so guest
egress is dead after restore. No test asserts an egress byte after restore — `snapshot_restore.rs`
drives only vsock — so all 59 privileged tests pass with the network broken. Not recorded in §16
or `implementation-notes.md`.

*Suggested direction:* either rewrite the baked tap name (and host wiring) to the restore's vmid
in the CH config rewrite, or restore onto the **original** vmid's network identity; add an
egress-after-restore assertion to `snapshot_restore.rs`. *Perf note:* restore-path change —
validate against the CH restore-to-Ready budget; no documented win depends on the current
(broken) behavior.

### H-ORCH-2 — Transient post-restore resync failure permanently wedges `agent()`
`crates/vmcell/src/orchestrator.rs:894-922` (with `agent/mod.rs:233-266,386`) · correctness ·
**CONFIRMED**

On the first post-restore `agent()` call, the client is cached (`:894`) **before** the mandatory
resync round-trip runs. If the resync's transport send fails or times out, `AgentClient` sets its
`desynced` flag (`agent/mod.rs:250-266`); the resync returns `Err` before handing back the ref
(`:922`). But the desynced client stays cached, and nothing ever calls `reconnect()` — so every
subsequent `agent()` skips connect, `ensure_synced` fails on the still-set flag, and returns
`Err` **forever**. This defeats the M-RESTORE-1 retry contract (a resync failure is supposed to
be retryable on the next `agent()` call) for the entire class of transient transport failures.
The `FakeGuestResync` seam used in unit tests bypasses the desync layer, so the tests can't see
it.

*Suggested direction:* on a resync error, invalidate/evict the cached client (or call
`reconnect()`) so the next `agent()` re-establishes sync — matching the recorded intent that the
clock-fail path clears cleanly for retry.

### H-ORCH-3 / H-NET-2 — `Privileged { host_services_port }` silently discarded
`crates/vmcell/src/orchestrator.rs:534-535` and `net/tap.rs:452-466` · correctness · **CONFIRMED**
(reported independently by three clusters)

In the privileged network arm the port is dropped with a bare, uncommented discard — itself a
violation of the AGENTS.md rule that every `let _ =` carry a justifying comment:

```rust
NetConfig::Privileged { egress, host_services_port } => {
    let _ = egress;
    let _ = host_services_port;   // ← silently ignored; no warn, no error
```

The field's doc (`config.rs:449-450`) promises host-service reachability on `Privileged`; only
the `Unprivileged` arm (`:604-606`) actually consumes it. Worse, under `Egress::Filtered` the
crate's own TPROXY ruleset (`tap.rs:452-466`) renders accepts only for web TPROXY and the proxy's
own port, then policy-drops everything — so host-service traffic on that port is actively
blocked. No `build()` rejection, no `warn!`, no test. This is the §12.2 fail-loud contract
violated in exactly the "requested functional op silently no-ops" shape the design calls out.
It is also the TEST cluster's #1 ranked coverage gap.

*Suggested direction:* either wire `host_services_port` into the privileged tap path (add the
`accept` rule + host binding) or, until then, have `config::build()` reject
`Privileged { host_services_port: Some(_) }` with a typed error.

### H-ORCH-1 — `EnvSetup` drop order tears down netns before the in-netns proxy on mid-`start()` failure
`crates/vmcell/src/orchestrator.rs:328-336` · correctness · **CONFIRMED (empirically)**

`EnvSetup` holds its resources as struct fields; Rust drops fields in **declaration order**, and
the netns field is declared before the proxy field. On any `start()`/`restore()` failure after
setup but before the resources move into `MicroVm` (the create/boot/restore error paths at
`:724/726/829/833`), the implicit drop deletes the netns **before** the proxy that runs inside
it — the inverse of the canonical teardown order the happy path enforces at `:1030-1041`. No test
covers a mid-start failure. (Verifier nuance: `netns-rs` uses `MNT_DETACH`, so the practical
residue today is milder than a hang/leak — but the order is still wrong and unguarded.)

*Suggested direction:* reorder the fields (proxy before netns) or give `EnvSetup` an explicit
`Drop` that mirrors the documented order; add a mid-start failure-injection test asserting zero
residue.

### H-ORCH-4 — Cross-process VMID claim/reclaim is unseamable, untested, and races on reclaim
`crates/vmcell/src/orchestrator.rs:121-153` · testing/correctness · **CONFIRMED**

`VmidAllocator::shared()` hardcodes `/tmp/vmcell-vmid` and has **zero tests** (every allocator
test uses the hermetic `new()`), despite being the cross-process path the design describes with
"crashed-owner reclaim." Two concrete defects in the untested code: (1) the reclaim `remove_file`
(`:153`) is unguarded after the liveness check, so two racing processes can both pass the check
and dual-claim the same vmid; (2) claim writes the lock as `create_new` then a **separate**
`let _ = write(pid)` (`:140-146`), so a crash between them leaves an unparseable empty lock that
the reclaim path (which parses a pid) never recovers — falsifying the "crashed-owner reclaim" doc
at `:117-119`. Not a recorded §16 gap.

*Suggested direction:* put the fs claim/reclaim behind an injectable seam with a recording fake;
write the pid atomically (temp-then-rename, or content in the `create_new` open); treat an
unparseable lock as reclaimable; make the liveness-check-then-remove atomic or tolerate the race.

### H-NET-3 — Privileged "Filtered" proxy can only serve doubles — upstream sockets live in the VM netns
`crates/vmcell/src/proxy/mod.rs:127-160` (wiring at `orchestrator.rs:556-565`) · correctness ·
**CONFIRMED**

The privileged proxy's entire tokio runtime is started on the thread that has `setns`'d into the
per-VM netns, so every upstream connection and DNS lookup it makes originates **from inside the
VM netns** — which contains only the tap `/30` and loopback, with no default route, veth, or
masquerade to the outside world (`tap.rs:126-212`). A privileged `Filtered` proxy therefore
**cannot reach any real external upstream**; it can only answer from registered doubles or return
403s. The design (§6.3) presents the explicit-proxy path as fully MITM'd and re-originating;
`egress_proxy.rs:388-423` asserts only that a *double* answers, masking the gap. (The
transparent-path limitation in §6.3 is documented, but this re-origination gap on the explicit
Filtered path is not.)

*Suggested direction:* re-originate upstream connections from the host root netns (create the
upstream sockets on a thread/task that has not entered the netns, or hand off via a host-side
connector), or document that privileged Filtered egress is doubles/observe-only and add a test
that would redden if a real upstream were expected.

### H-NET-4 — `Egress::Open` is a silent no-op — dead variant advertised as live
`crates/vmcell/src/net/smoltcp.rs:858-866` (enum/docs at `config.rs:465-476`) · api/correctness ·
**CONFIRMED**

`config.rs:473-475` documents `Egress::Open` (the default) as "allowed." But the orchestrator
wires an egress datapath only for `Filtered` (`orchestrator.rs:540,577`), and the unprivileged
NAT's only dial target is loopback (`smoltcp.rs:861`) with SYN admission gated on a configured
proxy port (`smoltcp.rs:796`). So with `Open` selected there is **no code path that admits
arbitrary egress** — `Open ≡ Blocked` in both modes. This is the "dead protocol variant advertised
as live" smell the rubric bans, in the shape of §12.2 (a selected option silently does nothing),
and the *default* value at that. No §16/`implementation-notes` entry documents it.

*Suggested direction:* either implement open egress (privileged: an `accept`/masquerade path;
unprivileged: real upstream dialing in the NAT) or make `Open` a typed `Error::Unsupported` /
remove it and default to `Blocked` explicitly, so the behavior matches the name.

### H-GUEST-1 — guest-tools HTTPS probe returns exit 0 on any proxy response (incl. TLS failure)
`crates/vmcell-guest-tools/src/main.rs:463,529-531` · correctness · **CONFIRMED**

`probe_connect` returns `true` on **any non-empty proxy reply** — including `200 Connection
established` — and the `curl` shim's caller returns exit **0** for any https-via-proxy `reqwest`
failure. So a TLS-validation failure, a `--max-time` timeout, and a connection reset all become
exit 0, where real curl returns 60/28/56. This is the banned "any error → success" probe. It is
masked today only because the egress tests pass `-k` everywhere (`egress_proxy.rs:130`), disabling
the TLS validation that would otherwise expose it — so a future test relying on the probe to
*detect* an interception failure would silently pass. The design explicitly requires the shim to
surface a proxy `CONNECT` 403 "the way curl does."

*Suggested direction:* map upstream/TLS/timeout failures to curl-faithful non-zero exit codes;
only treat a genuine 2xx/expected-status as success; keep the 403-surfacing behavior the
egress-block test relies on.

### H-ART-1 — `--agent-musl` rootfs cache key folds a path string, not content
`crates/vmcell/src/artifact/rootfs/mod.rs:63-67` (with `vmcell.rs:441-443`) · correctness ·
**CONFIRMED**

In the `oci2erofs --agent-musl` flow the rootfs cache key folds the agent binary's **absolute
path** rather than its content, and that flow **skips `GuestAgentStage`** (`vmcell.rs:441-443`) so
no `guest_agent` artifact is content-folded and `guest_agent_src_hash` hashes the workspace source
closure, not the user-supplied binary. Different bytes at the same path (an external tree, a
toolchain or flag change) therefore yield an **identical key**, and the cache hit re-serves a
stale-agent rootfs — the exact H-CACHE-1 "hash paths not content" bug the cache-key rules
(§11.2/§12.9) and this file's own comment (`:109-111`) forbid. No test varies the `--agent-musl`
bytes, so the green suite masks it.

*Suggested direction:* fold the agent binary's **content hash** into the rootfs key on the
`--agent-musl` path (as the default path folds the closure hash).

### H-ART-2 — `tar2erofs` silently drops hardlink entries
`crates/vmcell/src/artifact/tar2erofs.rs:164` · correctness · **CONFIRMED**

The tar entry-type match ends in `_ => continue`, with **no `EntryType::Link` (hardlink) arm** —
so hardlinks are silently skipped rather than materialized or errored. The pinned Debian Trixie
base already contains such an entry (`usr/bin/perl5.40.1` is a hardlink to `usr/bin/perl`), which
is dropped from the produced rootfs today. It is cosmetic on the default pin (the link *target*
is present, and the guest boots to agent-ready — which is why the suite is green), but it is a
fail-loud violation (compare `oci.rs:226`, which does error on the unexpected) and becomes real
data loss on any hardlink-heavy base reachable through `oci2erofs`. §8.2/§16 are silent on
hardlinks.

*Suggested direction:* handle `EntryType::Link` by materializing the link target's content at the
link path (erofs has no hardlink dedup requirement here), or fail loud on an unhandled entry type
rather than `continue`.

### C-BIN-1 (downgraded to High) — bench percentile `floor(n·q)` biases high; published p95 = sample max at N=20
`crates/vmcell/src/bin/bench-vm.rs:137-140` (and `:612`) · correctness/methodology · **CONFIRMED,
downgraded**

```rust
let p95 = latencies[(count * 0.95).floor() as usize];   // count == n, not n-1
```

For N=20, `20·0.95 = 19.0`, `floor = 19` → index 19 is the **maximum** of 20 samples. A compiled
reproduction confirms the method is biased high whenever `n·q` is integer, and
`benchmark-results.md:245-249` inherits it — the eager/lazy/default restore table shows
**p95 == max in every row** (274/274, 188/188, 179/179). It is downgraded from Critical because
benchmarks are explicitly "tracked metrics, not gates" (design §15) and the error is
*pessimistic* (it inflates the tail, so it cannot hide a regression) — but the published p95
figures are overstated and should be recomputed.

*Suggested direction:* use nearest-rank `ceil(n·q) - 1` (clamped to `0..n`) or a linear-
interpolation percentile; re-run the tables. The p50 line has the same off-by-one (upper-median).

### H-BIN-1 — bench flags silently default on an unknown value
`crates/vmcell/src/bin/bench-vm.rs:82-108` · CLI validation · **CONFIRMED**

`--profile`, `--kernel-verbosity`, and `--console` all parse via a match whose `_ =>` arm returns
the **default** with no rejection and no echo. Compounding it, the perf docs spell the profile
`low_latency` (`benchmark-results.md:27,68`) while the flag expects `low-latency` — so following
the documentation produces a silent run of the *default* profile, mislabeled. A mistyped profile
therefore benchmarks the wrong configuration and the operator can't tell. (Non-gating harness
caps this below Critical.)

*Suggested direction:* reject unknown enum values with a typed error listing the valid set; echo
the resolved profile/verbosity/console at startup; reconcile the `low_latency` vs `low-latency`
spelling between the flag and the docs.

### H-TEST-3 — Capability skips are silent green passes; 4 of 7 capability flags have no honesty pin
`crates/vmcell/tests/common/mod.rs:139-140` · testing (skip==pass) · **CONFIRMED**

The `require_cap!` non-CH arm is `println! + return` — under nextest that is a **green PASS**, not
a visible skip-with-reason, violating the §14 rule (design lines 1417-1418) that "a missing
capability is a skip-with-reason, never a silent green." The CH primary path is protected by a
panic, but honesty pins asserting a backend's capability flags exist only for Firecracker
(`firecracker.rs:1165-1202`, 3 flags) — there are **none** for QEMU and none for
`virtio_fs_shares`/`nested_virt`/`unprivileged_vhost_user_net`/`virtio_console`. So a secondary
backend's capability flag silently regressing to `false` would turn its whole scenario into a
green no-op with nothing to catch it. This is the project's #1 banned test smell.

*Suggested direction:* emit skips through a mechanism nextest surfaces (or count them), add
capability-honesty pins for every flag on every backend (as FC already has), and rely on the
"zero-selected-tests is a CI failure" rule the design mandates.

---

## 4. Medium findings

Grouped by area. The first block is the **eleven reviewer-Highs that verification downgraded** —
real, but unreachable in a supported flow, experiment-gated, or documented-tradeoff.

**Downgraded from High:**

- **M (was H-VMM-2)** `vmm/qemu.rs:308,554` — QEMU is launched without `-S`, so the guest runs at
  spawn and `boot()` is a no-op `cont`; early guest boot runs before `add_task` places it in the
  cgroup. Confirmed, but the only caller boots immediately and `Vmm` isn't externally drivable, so
  the cgroup window is theoretical → API/contract defect. Add `-S` and let `boot()` do the `cont`.
- **M (was H-VMM-3)** `vmm/firecracker.rs:696-705` — FC `restore()`'s self-guard omits the
  virtio-fs-*rootfs* term that CH's has. Real divergence, but boundary-2 (`orchestrator.rs:784`)
  rejects it first and `PerVmResources` has no external constructor, so it's defense-in-depth +
  a missing negative test. Extract the shared predicate.
- **M (was H-NET-1)** `net/smoltcp.rs:66-76,166-171` — the NAT MTU is off by the 14-byte Ethernet
  header and the safety comment is false, but the NAT is TCP-only and smoltcp derives MSS from the
  same caps, so the max frame (1512) equals `MAX_FRAME_LEN` and the drop is unreachable; residual
  is a 1486 IP-MTU wart. Fix the accounting and the comment.
- **M (was H-ART-3)** `tar2erofs.rs:31-69` — injected agent/CA files are inserted *before* layer
  merge, inverting the §8.2 merge-then-inject tail, so a later layer's whiteout/collision could
  clobber them. The pinned base is single-layer with zero whiteouts, and a clobber needs a crafted
  `oci2erofs` base the digest-pin scopes out. Move injection after merge; record the deviation.
- **M (was H-HOST-1)** `fs.rs:181-250` — `VirtioFsDaemon::Drop` drops the tokio `Child` (which held
  the leader) and then `kill`/`waitpid`s a raw stored pgid, diverging from the CH backend's safe
  "hold the Child, gate on `process.id()`" pattern. Damage needs virtiofsd self-exit + orphan-reap
  + pid recycle → theoretical window. Adopt the CH pattern.
- **M (was H-HOST-2)** `fs/in_process.rs:306` (+ vendor) — the `experiment-fuse` worker blocks in
  `accept()` without checking its kill-eventfd pre-connection, so `Drop`'s notify+join deadlocks if
  the VMM never connected. Only under the non-default, ungraduated `experiment-fuse` feature.
- **M (was H-HOST-3)** `orchestrator.rs:622-633` — the `/proc/self/cgroup` sibling-placement parse
  is triplicated (also `tests/common/mod.rs:60`, `tests/metrics_limits.rs:16`), lives outside
  `metrics.rs`, and the pure parse is untested — against the AGENTS.md "extract; cgroup logic in
  metrics.rs" rule. Copies are currently identical (not diverged). Extract into `metrics.rs` and
  unit-test.
- **M (was H-BIN-2)** `bench-vm.rs:298-303` — agent-connect/exec failures drop the iteration
  swallowing the `Err`, asymmetric with the create path. The sample count *is* printed (attrition
  is observable), so it's a missing-reason issue on a non-gating harness. Log the drop cause.
- **M (was H-BIN-3 / H-TEST-2)** `.github/workflows/ci.yml:128,142` — CI's integration filters omit
  the `kind(test)` predicate the `justfile` carries, so ~172 lib tests run concurrently with the
  serial VM tests (the oversubscription condition behind the historical flake). No coverage is lost
  (lib tests also run at `ci.yml:111`) and `retries=3` absorbs the flake, so it masks no real
  regression — a config-hygiene drift. Align CI with the justfile.
- **M (was H-TEST-1)** `.config/nextest.toml:9-17` — `retries=3` spans the whole integration
  profile (not just VM tests) and *did* paper over a real bug once (AGENT-2, now fixed and recorded
  in `implementation-notes.md:184`); the stanza comment still calls the flake "environmental."
  Documented tradeoff → tighten the retry scope and fix the stale comment.

**Other notable Mediums** (full write-ups in the per-cluster review files):

- `M-VMM-2` `vmm/mod.rs:71` — `unix_api_request` has no timeout, so every CH/FC control RPC can
  hang forever (the design's own note that the shutdown RPC is unbounded, generalized). A stalled
  VMM socket wedges the caller. Add a bounded timeout with a typed error.
- `M-VMM-3` `vmm/cloud_hypervisor.rs:526` — after restore, `guest_cid()` returns the fresh
  allocator CID while the guest keeps its baked CID — a dishonest accessor.
- `M-VMM-6` `vmm/mod.rs:594` — the public `FakeVmm` records but can't be *driven* (no failure or
  capability injection), so the design's "FakeVmm-driven allocation/retry/teardown" tests can't
  exercise error paths.
- `M-ORCH-5` `orchestrator.rs:493` — `pub instance_mut()` leaks the backend instance and lets a
  caller call `snapshot()` directly, bypassing the cached-client invalidation self-guard that
  `MicroVm::snapshot()` adds (the EXP-E fix). Make it non-`pub` or route through the guard.
- `M-HOST-4` `metrics.rs:188` — every limit-write failure is typed `CapabilityUnavailable`, so an
  `EINVAL` from a bad limit *value* is misattributed to a missing capability. Distinguish errno.
- `M-HOST-5` `metrics.rs:285` — `limits_enforced` reflects only "memory delegated," so it's wrong
  for a cpu/pids/io-only limit set.
- `M-HOST-6` `fs/in_process.rs:179` — a production `expect()` in `exit_event`; `expect_used` isn't
  lint-banned alongside `unwrap_used`.
- `M-HOST-1(docs)` `cpufreq.rs:10` — `cargo doc` hard-fails on five broken intra-doc links and CI
  has no doc-build gate to catch it.
- `M-ART-3` `rootfs/oci.rs:72` — the manifest digest is verified on the first fetch but layers are
  used from a second, unverified fetch (a TOCTOU on the registry). `M-ART-4/7/8/10` — cache keys
  omit the builder-base pins, the CH/virtiofsd identity, a materialized `guest_agent_src_hash`, and
  the baked CA (a `run()` side effect absent from the key).
- `M-VEND-2` `vendor/vhost-user-backend/src/handler.rs:531` — the carried relaxation is broader
  than the QEMU quirk requires (it also accepts `SET_VRING_ENABLE` *after* a non-PF `SET_FEATURES`);
  gating on `features_acked` would accept only QEMU's early ordering. `M-VEND-3` — caret version
  reqs mean a future `vhost` 0.17/`vhost-user-backend` 0.23 bump silently drops the patch with only
  a cargo warning, and no gate asserts the patch is applied.
- `M-NET-4/5`, `M-GUEST-1/2/3/4`, `M-BIN-2..8`, `M-TEST-1..8` — see the per-cluster files.

---

## 5. Testing-coverage gaps (dedup'd across clusters)

Ranked by risk. These are library behaviors with **no test that reddens on their inverse**:

1. **`Privileged { host_services_port }`** — no test anywhere; the silent no-op (H-ORCH-3) went
   unnoticed precisely because of this.
2. **Egress after restore** — `snapshot_restore.rs` asserts only over vsock, so H-VMM-1 (dead
   post-restore networking) passes green. Add a real egress-byte assertion post-restore.
3. **Real egress through the privileged Filtered proxy** — `egress_proxy.rs` asserts only a
   double answers, masking H-NET-3. Needs a real-upstream assertion (or an explicit doubles-only
   contract).
4. **Mid-`start()`/`restore()` failure residue** — no failure-injection test drives the error
   branches, so the H-ORCH-1 drop-order inversion and the H-ORCH-4 lock races are invisible. The
   panic-residue test (`lifecycle.rs`) also asserts non-existence of `format!`-recomputed paths
   with no pre-drop existence check (`M-TEST-2`) — vacuous on naming drift.
5. **Cross-process `VmidAllocator::shared()`** — zero tests (H-ORCH-4).
6. **Capability-honesty pins** — 4 of 7 flags on the secondary backends unpinned (H-TEST-3).
7. **`--agent-musl` / large-payload NAT / hardlink rootfs** — the three artifact/NAT Criticals
   and Highs all lack a test that varies the input that breaks them (H-ART-1, C-NET-1, H-ART-2).
8. **guest-tools has zero tests** (`M-GUEST-3`) — its parsers, proxy ordering, and the duplicated
   ifreq layout are unguarded, which is how H-GUEST-1 shipped.
9. **`ConsoleMode`/`KernelVerbosity`/`Timeouts` presets** — no integration coverage of the
   host-facing wiring.
10. **`concurrency.rs` boots two VMs strictly sequentially** (`M-TEST-3`) — no concurrent
    allocation/creation is ever exercised despite the test's name and the N-VM §14 requirement.

The suite is genuinely strong where the design invested review effort: `snapshot_restore.rs`
(FakeClock-driven first-call resync, positive `mac_math(new_vmid)` identity, valid-live-CID not
`assert_ne!`, `restore_rotates_host_paths` branching), `metrics_limits.rs` (real
`memory.events oom_kill>0`, delegation as a hard precondition), `exec_vsock.rs` (in-guest
`put_file` round-trip, >8 MiB frame), and the pipeline tamper/golden/determinism trio are all
red-on-inverse. The gaps are the data-planes those tests don't reach.

---

## 6. API-design observations (over-complication candidates)

- **`agent(&mut self, timeout, clock)`** (`M-ORCH-6`) diverges from the design's `agent()`
  signature and pushes `Timeouts`/`Clock` boilerplate to every call site; the handle already owns
  both. Fold them in.
- **`pub instance_mut()`** (`M-ORCH-5`) leaks the backend instance and bypasses the `snapshot()`
  self-guard — an encapsulation hole.
- **`VmmCapabilities` is `#[non_exhaustive]` without constructors** (`L-VMM-8`) — external `Vmm`
  impls and `create()` callers can't name it. Provide a builder or a `Default`.
- **`spawn_qemu` returns an 8-tuple** with two adjacent swap-prone `Option<u32>` pgids
  (`L-VMM-6`) — a struct with named fields removes the footgun.
- **`StageInputs` and `StageOutputs` are identical duplicated types** (`N-ART-2`); the empty
  `Cache` unit struct is threaded through `build`/`reset_to` but never used (`L-ART-10`).
- **`experiment-fuse` non-additively swaps the share backend** (`L-HOST-8`) — a non-additive
  feature, which cargo's feature-unification model discourages; `CachePolicy` is silently ignored
  on that backend.

---

## 7. Performance opportunities (none regress a documented win)

The perf docs (§15, `docs/45`) are internally consistent and the keeper experiments (loglevel
default, event-driven accept, adaptive shutdown poll, deadline-before-RPC, native resync) are
correctly implemented. Opportunities that are **safe** relative to them:

- **Streaming hash/verify in the artifact pipeline** (`N-ART-1/6/7`): the kernel tarball is read
  fully into memory twice on the cold path, OCI blobs are triple-read and fully buffered, and
  `build()` does blocking fs + whole-artifact hashing on an async runtime thread. These are
  build-time (cold, cached), off every measured VM-lifecycle hot-path, so they can't regress the
  latency work — but they cut build memory and time. *Verify with a build-time measurement, not
  the VM benchmarks.*
- **`unix_api_request` timeout** (`M-VMM-2`): adding a bound is a correctness fix, not a hot-path
  change — the cold path issues few RPCs and the timeout only fires on a stalled VMM.
- **Do not** re-suggest the rejected levers from `docs/45` (persistent QMP, `try_join_all` on
  virtiofsd startup, netns∥cgroup overlap, inotify socket readiness, `mitigations=off`) — each is
  mechanically refuted there.
- **`L-GUEST-9`** (the agent's `env-filter` feature pulls regex into the static PID-1 binary) is a
  *binary-size* opportunity, not a latency one, and is marked **needs benchmark before adopting**
  — the guest binary size feeds density, so measure before changing.

The one perf-doc *correctness* issue is `C-BIN-1` above: the harness that produced the numbers has
a percentile bug, so the published p95 values are overstated (pessimistically). The p50 figures
and all relative/A-B conclusions are unaffected in direction.

---

## 8. Documentation issues (code ↔ design mismatches)

- **`docs/43-claude-design-v17.md:1462`** (`L-HOST-7`) lists the privilege-transition sequence
  with uid **last**, contradicting both the §14 "uid before ambient" rule two paragraphs earlier
  and the code (which correctly changes uid first). Fix the sequence in the doc.
- **`docs/43-claude-design-v17.md:1640`** (`N-ORCH-4`) still lists the fixed-500 ms shutdown grace
  as an open §16 gap, but the adaptive-poll rework (EXP-D) closed it. Remove the stale gap.
- **`orchestrator.rs:932`, `:1056`** (`L-ORCH-3`, `M-ORCH-2`) — the resync doc-comments still
  describe the subprocess era (`exit 0`, `head -c 32`) after the native in-agent resync landed;
  `shutdown()` documents `# Errors` it never returns (RPC/kill failures are discarded).
- **`rootfs/mmdebstrap.rs:130`** (`M-ART-5`) — the design claims a pinned apt keyring but the code
  relies on the base-image keyring; the deviation is unrecorded.
- **`vmm/mod.rs:240`** (`L-VMM-2`) — `wait_for_socket`'s doc says it returns `true/false`; the
  signature is `Result`. **`vmm/mod.rs:215`** (`L-VMM-3`) — the `pre_exec` `SAFETY` comment
  justifies the kill semantics, not the async-signal-safety the block actually needs.
- **`vendor/vhost/.../backend_req_handler.rs:554`** (`M-VEND-1`) — the disabled PROTOCOL_FEATURES
  check carries no rationale comment at the site, unlike its `vhost-user-backend` twin; a future
  reader can't tell it's the intentional carried patch.
- Design §16 lists an OCI record/replay seam as missing (`L-ART-11`) though `OciPuller`/
  `FakeOciPuller` now implement it, and the `mkfs.erofs` fallback (§8.2) is unimplemented without
  a §16 note (`M-ART-11`).

---

## 9. Recorded-deviation audit note

The following were **checked and NOT flagged** because `implementation-notes.md` justifies them
and the code matches the justification: the EXP-D adaptive shutdown-poll cadence and
deadline-before-RPC placement; `MicroVm::snapshot()` invalidating the cached `AgentClient` (the
EXP-E fix); the AGENT-2 pre-spawn reaper epoch (verified race-sound, with a genuinely
red-on-inverse pinning test); the event-driven `poll(2)` accept loop and its Instant-based rebind
deadline; the native in-agent `Resync` replacing the three subprocess execs; the FC warm-restore
wiring (`reject_live_baked_vsock`, the entropy device, `restore_rotates_host_paths`); the
`api_socket_poll` unification and the `wait_for_socket` ≥1 ms clamp; the `nextest retries` flake
mitigation (though `H-TEST-1` notes its scope and stale comment); and the carried vhost patch's
existence (design §16 accepts it as a maintenance cost — the VEND findings are about the delta's
hygiene, not its existence).

The FC `snapshot_restore: true` flip and the entropy-device addition were independently confirmed
live on this host: `snapshot_restore::firecracker` passes in the privileged suite.

---

## Appendix — full finding inventory

Every finding, with its post-verification severity. Full evidence and suggested directions are in
the per-cluster review files (retained under the review scratchpad) and summarized above for
Critical/High/notable-Medium. Severity in **bold** where verification changed it.

| Cluster | Critical | High | Medium | Low | Nit | Total |
|---|---|---|---|---|---|---|
| ORCH (orchestrator/config/error/lib) | — | 4 | 7 | 8 | 4 | 23 |
| VMM (trait + CH/FC/QEMU) | — | 1 | **9** | 8 | 4 | 22 |
| NET (smoltcp/tap/proxy) | 1 | 3 | **6** | 9 | 4 | 23 |
| GUEST (agent/protocol/tools/client) | 1 | 1 | 5 | 11 | 4 | 22 |
| ART (artifact pipeline) | — | 2 | **11** | 12 | 7 | 32 |
| HOST (metrics/cpufreq/fs/runner) | — | **0** | **7** | 8 | 3 | 18 |
| BIN (bench/CLI/gates/config) | — | **2** | **6** | 10 | 5 | 23 |
| TEST (integration suite) | — | **1** | **7** | 6 | 3 | 17 |
| VEND (carried vhost patch) | — | 0 | 3 | 2 | 1 | 6 |
| **Total** | **2** | **14** | **61** | **74** | **35** | **186** |

(High count of 14 includes `C-BIN-1` downgraded from Critical to High. The 11 reviewer-Highs that
verification downgraded are counted here at their post-verification Medium severity. Totals differ
slightly from raw sub-review counts where verification merged duplicates — notably H-ORCH-3 and
H-NET-2 are the same `host_services_port` defect.)
