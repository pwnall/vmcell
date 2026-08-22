# vmcell — Code Review (docs/90)

A comprehensive review of the tree at `main` @ `c276da7` — `vmcell` 0.20.0, the **closed** v33 delta
register (all ten deltas landed) plus the doc retirement that followed it — against design v33
(`docs/83`), rubric v7 (`docs/84`), `AGENTS.md`, and `docs/implementation-notes.md`. Dated
2026-08-16.

**Method.** Twenty-five independent area reviews over disjoint slices: eighteen by subsystem
(orchestrator/teardown, config/cmdline, vmm-core/jail/CH/USB, the three secondary backend crates,
the smoltcp NAT, tap/segments/proxy, the host control plane, the guest steward, the artifact
pipeline, the rootfs and pack tail, the daemon tier, the privileged tier, features and the
conformance kit, guest-tools and the protocol, metrics/zygote/lineage, the CLI and bench harness,
and the gates themselves) and seven cross-cutting (the library's public API, the downstream contract
surface, two design-versus-code contradiction sweeps, live-coverage reachability, KVM-free-coverage
reachability, and the extension points the documented use cases need). Every finding was then handed
to a **separate adversarial verifier** instructed to refute it — re-read the cited code, hunt for the
guard elsewhere on the path, test the failure scenario for reachability, and check the item against
`implementation-notes.md`, design §17 and `docs/todo.md` before allowing it to stand. Items already
recorded as justified deviations or on the §17 register were excluded up front. The reviewer also
ran an independent pass by hand; where that pass and an area reviewer converged, it is noted.

**Live validation (AGENTS rule 5 — executed, not presumed).** `scripts/review-preflight-priv.sh`
printed **READY**. Every suite was run on this host during the review:

| Gate | Result |
|---|---|
| `just ci` | green — 1142 tests, the 298-config feature powerset, all 19 gate self-tests |
| `just test-privileged` (delegated scope) | **228/228**, 348 s |
| `just test-unprivileged` | **4/4** |
| `just test-daemon` | **16/16** |
| `just test-validator` (delegated scope) | **4/4** |
| `just test-crosvm` (delegated scope) | **30/30**, 83 s |
| `just test-systemd` (delegated scope) | **2/2** |
| Skip manifest | **9** capability skips against a reset manifest: FC `unprivileged_vhost_user_net` ×4 / `nested_virt` ×2 / `virtio_fs_shares`, CH `systemd_proof_cell_not_opted_in` ×2 — exactly the roster the v5 handoff records, including the two that are the *evidence* delta 9's opt-in still holds |
| `cargo test --doc --workspace` | **6/6** — run by hand, because **no gate runs it** (finding G1) |

`just bless` was attempted and correctly declined (no terminal for sudo), preserving the existing
blessing — which surfaced finding G9. The working tree was clean before and after the review; the
only files this pass changes are this document and `docs/implementation-notes.md`.

**Post-review correction (2026-08-17).** Two rows of that table have been overtaken, and both were
*findings* rather than mismeasurements:

- The doctest row's "**no gate runs it**" is closed. `just test-doc`
  (`cargo test --locked --workspace --all-features --doc`) is invoked by `just ci` and by `ci.yml`'s
  `test-unit` job, and the count is **7**, not 6 — the seventh is the `proxy::doubles` module example
  that arrived with E1's re-exports.
- The `just ci` row's figures (1142 tests, 19 gate self-tests) predate the fix pass and are not
  restated here, because the recipe is the number's source: `just test-unit` prints the test count and
  the gate roster is whatever `just gates` invokes. Both moved substantially — the fix pass added four
  test files, several batteries and six gate scripts.

Every other row stands as measured. It is the record of this review's own run, not a claim about the
tree today.

**Status: CLOSED (2026-08-17).** Every finding below has been worked; **§11, Resolution** records the
per-finding outcome — fixed, fixed-with-a-deviation, or partly open — against the tree, and §10's
closing subsection records the one thing this review's own method could not see. The findings
themselves are left exactly as written: they are the record of what was found. Where the tree has
since falsified a statement *inside* a finding, the correction is marked **Post-review correction**
beside it rather than edited in silently.

**Verdict.** The tree is in strong shape and its disciplines hold where it claims them: all thirty
one-law predicates `AGENTS.md` names exist, every `VmConfig` field is read on a production path, the
`Error` enum has no dead variant, the NAT's six silent-wedge invariants are each implemented as
described, `spawn_clones` is cancellation-safe in the shape the design records, and the two
doc-discovery gates (the deny-list roster parse and the blessing-copy tree walk) both work as
documented — verified by re-running them against an edited `docs/` tree.

**77 findings survived adversarial verification** (57 from the subsystem pass, 20 cross-cutting);
51 were refuted and 26 were already recorded. Three are **high**, ten **medium**, the rest low.

The two high ones are the only findings that make a shipped verb produce a wrong artifact, and they
are the same shape: **v33's newest registry surface was wired at the parse boundary and never
connected at the far end.** `vmcell build --handler-label <any>` — including the explicit spelling of
the reserved `default` — publishes the handler under a per-label artifact key that **no consumer
reads**, so the pack tail finds nothing and emits a rootfs with no tools binary and no applet
symlinks, successfully (H1). And a registry entry declaring `format: ext4` cannot be built at all,
because the OCI stage still calls the erofs-only door delta 8 left behind (H2). Both are new-surface
integration holes rather than regressions, both fail in the direction that reports success, and both
are one line from correct.

Otherwise the defects cluster in four places, and three of the four are the project's own named
failure modes recurring one step to the side of where they were last fixed:

1. **The v33 re-key finished in the code and stopped at the prose.** Delta 4 moved control-plane
   availability off `cfg.init` onto `StewardPlacement`, and its call-site gate strips comments —
   so seven prose sites, four of them public rustdoc on a contract crate, still describe the retired
   derivation (D1). Worse, one *code* site was missed entirely: QEMU's health gate dials the
   hardcoded port rather than the declared one (M1), and the `Service`-scoped budget §3.5 specifies
   was never implemented while the comment above the call site asserts it as shipped (M2).
2. **Gates that cannot go red, in a repo that has hunted this class three times.** No gate runs
   doctests at all (G1); three live tests in `vmcell-bench` are selected by no recipe — the identical
   defect the `test-validator` recipe's own header documents as discovered and closed for the
   validator (G2); a delta-8 skip uses the `println!("SKIP") + return` shape its own twin file names
   as banned (G3); eight of twelve ban scripts pass vacuously on an empty scan while the two newest
   fail loudly (G4).
3. **The contract surface grew faster than the list that names it.** A new public pack entry point
   is in no ledger and on no list (C1); the ledger skips the two versions spanning the most breaking
   release in the crate's history (C2); two library entry points the design names do not exist (C3);
   and the living consumer gate — the mechanism §10.4 designates as the thing that reddens on drift —
   exercises **none** of v33's contract additions while its README claims it consumes every item (C4).
4. **Config knobs the suite never boots.** Three of four `ResourceLimits` fields, `VirtioConsole`,
   both `Timeouts` presets, `ksm_mergeable` and both non-default `RestoreMode`s are shipped,
   documented, and never applied in a live boot (T1–T5). One of them, the guest tuning channel, is
   *structurally* unfalsifiable: the guest's compiled fallbacks are byte-identical to the host's
   emitted defaults (T2).

The doc debt is concentrated and mechanical, and every instance is a count or a roster that AGENTS.md
already says must be read from the tree rather than from memory.

---

## Convergent findings (independent confirmation)

Findings reported by two reviewers who never saw each other's work. Convergence from disjoint slices
is the strongest evidence this method produces; all three survived verification.

| Defect | Found independently by |
|---|---|
| The labelled handler artifact reaches no consumer (H1) | the artifact-pipeline slice · the CLI slice |
| QEMU's health gate dials the hardcoded port (M1) | the QEMU slice · the design-versus-code sweep |
| The `Service` probe window was never implemented (M2) | the orchestrator slice · the design-versus-code sweep |
| The C8 prose still asserts the `cfg.init` derivation delta 4 removed (D1) | the reviewer's own pass · the api-library sweep (which found two more sites) · the config slice (a seventh site, `config.rs:90`) |
| `vmcell-bench`'s three live tests are selected by no recipe (G2) | the reviewer's own pass · the KVM-free-coverage sweep · the gates slice |
| The delta-8 ext4 skip is the banned `println!("SKIP") + return` shape (G3) | the reviewer's own pass · the KVM-free-coverage sweep · the gates slice |
| A third `ch_bin` copy in `vmcell-cli` (A2) | the reviewer's own pass · the CLI slice |

---

## 1. Major — correctness

### H1 — a labelled handler artifact reaches nothing: `vmcell build --handler-label <any>` packs a rootfs with no guest tools and no applet symlinks, and reports success
`crates/vmcell/src/artifact/rootfs/mod.rs:1360` · `crates/vmcell/src/artifact/rootfs/mod.rs:767` ·
`crates/vmcell/src/artifact/guest_tools.rs:203` · `crates/vmcell/src/artifact/handler.rs:45` ·
`crates/vmcell-cli/src/main.rs:485-488`
*(found by two reviewers — the artifact-pipeline slice and the CLI slice — and confirmed by both verifiers)*

Delta 6b made the guest handler an artifact with a per-label key:

```rust
pub fn handler_artifact_key(label: Option<&str>) -> String {
    match label { Some(l) => format!("guest_tools-{l}"), None => "guest_tools".to_string() }
}
```

`GuestToolsStage` registers its output under that key. **The one consumer reads only the default
one:** the pack tail does `inputs.artifacts.get("guest_tools")`, and the identity fold's `consumed`
list is the hardcoded `&["steward", "guest_tools"]`. A repo-wide grep for `handler_artifact_key`
returns `handler.rs`, `guest_tools.rs` and the registry battery — **no consumer of
`guest_tools-<label>` exists anywhere.**

*Failure:* a consumer registers `handlers.acme` (digest-pinned, `applets: ["acme-run"]`) and runs
`vmcell build --handler-label acme`. The stage fetches and digest-verifies acme's binary and
publishes it as `guest_tools-acme`. The rootfs stage's lookup returns `None`, so
`rootfs_injection_manifest` emits the steward and the CA but **neither the tools binary nor a single
applet symlink**. The build reports success and the image ships. In the guest, every applet path is
absent: `/vmcell-tools/curl`, `ip`, `kvm-ok`, `echo-server`, `xattr` — and `mini-init`, which is a
`init=` target, so a cell pointed at it panics the guest kernel.

The reachability is broader than a consumer overlay: the CLI normalizes only the *rootfs* label
through `registry_label` (`main.rs:476`) and passes the handler label through raw, so
**`vmcell build --handler-label default`** — committed pins, no overlay — already composes
`guest_tools-default` and falls into the same hole. That is finding #51 in the fan-out's own
numbering, and it is a second defect in its own right: the explicit spelling of the reserved default
label builds a *different* artifact, with a different cache key, than the omitted spelling — which
§10.5's "canonical artifacts stay byte-identical for a cell that names no label" forbids.

*Why nothing catches it:* `handler_registry.rs`'s seven legs test the registry's *parsing* and key
composition; delta 6b's own notes record that the live leg — "a registered handler boots and its
applet answers in-guest" — was deferred to delta 9, and delta 9 shipped without it. The rootfs cache
key does move (dropping `guest_tools` out of `consumed` changes the fold), so the build is not a
no-op — it is a *successful* build of a broken image.

*Fix:* read the handler through `handler_artifact_key(label)` at both the pack tail and the
`consumed` fold, normalize `--handler-label` through `registry_label` beside the rootfs one, and
land delta 6b's deferred live leg. The gate that would have caught it is one boot asserting an
applet answers in-guest.

### H2 — a registry entry declaring `format: ext4` cannot be built: the OCI stage packs through the erofs-only door
`crates/vmcell/src/artifact/rootfs/oci.rs:174-184` · `crates/vmcell/src/artifact/rootfs/mod.rs:1254-1268`

```rust
let streams = layer_tar_streams_with(puller, image, digest).await?;
super::pack_erofs_with_injection(streams, inputs, out, options).await
```

and that door, since delta 8, refuses anything but erofs:

```rust
if options.format != RootfsFormat::Erofs {
    return Err(Error::Artifact(format!(
        "`pack_erofs_with_injection` was handed `format: {}` (§4.7): this door packs erofs by name. \
         Call `pack_rootfs_with_injection`, …",
```

*Failure:* a pins overlay carrying
`{"rootfs": {"acme": {"image": "…", "digest": "sha256:…", "format": "ext4"}}}` and
`vmcell build --rootfs-label acme`. The stage assembles with `format: Ext4`, `out_path` resolves to
`rootfs-acme.ext4`, the cache misses, the layers are pulled — and the pack then returns
`Error::Artifact` naming the door. **No vmcell-built ext4 rootfs can be produced through the
registry at all.** The `format` key is an accepted input that cannot be honored, which is exactly
the F1 shape; the ext4 producer that delta 8 landed is reachable only through the `unpinned_path`
development registration, which `bundle` refuses by design.

*Why nothing catches it:* delta 8's battery packs ext4 by calling the producer directly, never
through a registry entry and never through `RootfsStage::run`. `format` was validated at the parse
boundary and never driven end to end.

*Fix:* call `pack_rootfs_with_injection` from `oci::build_rootfs_with` — a one-line change to the
function delta 8 created for exactly this — and add a registry leg that builds a `format: ext4`
label. This is the same seam C1 reports as unledgered.

### M1 — QEMU's control-plane health gate dials the hardcoded steward port, not the declared one
`crates/vmcell-qemu/src/lib.rs:1569-1583` · `crates/vmcell-qemu/src/lib.rs:1222,1227` ·
`crates/vmcell/src/orchestrator.rs:1511-1515`

Design §3.5 re-keys the control-plane health gate to run "whenever `steward_port()` is `Some`", and
the re-keyed sites "dial the **declared** port". `MicroVm::steward` does exactly that —
`instance.vsock_endpoint().with_port(port)` where `port = self.steward_placement.steward_port()`
(orchestrator.rs:1837-1841). `QemuInstance::verify_control_plane` does not:

```rust
vmcell::steward::StewardClient::connect_endpoint(&self.endpoint, budget, timeouts, &serial)
```

It uses the instance's endpoint verbatim, and that endpoint is constructed with
`port: vmcell::vmm::STEWARD_VSOCK_PORT` (lib.rs:1222 and :1227). The orchestrator's call site passes
a budget and a `Timeouts` and **no port**, so there is nowhere for the declared one to enter.

*Failure:* `VmConfig::builder(..).steward_placement(StewardPlacement::Service { port: 5100 })` on the
QEMU backend. The guest steward parses `vmcell_steward_port=5100` and binds 5100; the health gate
dials 5000; the external `vhost-device-vsock` daemon accepts the CONNECT and never answers a dead
port, so the probe runs out its budget; the VM is destroyed and re-spawned; after
`MAX_CONTROL_PLANE_RESPAWNS` (4) `MicroVm::start` returns
`Error::Vmm("guest control plane did not come up after 4 re-spawns")`. A healthy cell, killed four
times and refused.

*Why nothing catches it:* `verify_control_plane` is a no-op for `VsockEndpoint::Vsock` (in-kernel)
and the trait default is a no-op for CH and FC, so QEMU on the external-daemon transport is the only
path that probes at all — and every `Service` leg in the tree runs on Cloud Hypervisor
(`tests/service_steward.rs:55,57,255,290`), including the non-default-port leg
`a_non_default_declared_port_is_actually_bound_by_the_guest` (port 5100, `:493`). The C8 call-site
scan reads only `orchestrator.rs` and `config.rs`, so it cannot see a backend crate.

*Fix:* thread the resolved port into the probe — either give `verify_control_plane` the port (or the
resolved endpoint) from `MicroVm::start`, or apply `.with_port(..)` inside the QEMU implementation —
and extend the C8 call-site scan past the two files it reads, or add a backend-side twin. The gate
that would have caught it is a `Service{5100}` leg on QEMU.

### M2 — the `Service` health-gate window design §3.5 specifies was never implemented, and the comment above the call site asserts it as shipped
`crates/vmcell/src/orchestrator.rs:1505-1515` · `crates/vmcell/src/orchestrator.rs:18`

Design §3.5 (and its restatement at design line 1022): "under `Service` the gate's overall window
derives from the caller's connect budget (the 10 s default, or the caller-supplied window), never the
`Pid1`-tuned constant, or a slow-but-healthy systemd cell would be killed and re-booted to exhaustion
by its own health check." The comment at orchestrator.rs:1505-1509 restates that sentence almost
verbatim. The code beneath it then passes the constant unconditionally:

```rust
.verify_control_plane(CONTROL_PLANE_PROBE_BUDGET, &clamped)   // const … = Duration::from_secs(4)
```

There is no placement branch. The claim is also unreachable as written: `Timeouts` carries no
connect-budget field (the design says so itself in §9.3), and the caller's connect window is the
per-call `steward(timeout)` argument, which `start()` never sees.

*Failure:* a `Service` cell whose guest init needs more than 4 s to bring the steward up — a systemd
ordering chain, a slow unit — fails every probe, is torn down and re-booted four times, and
`start()` returns the same "did not come up after 4 re-spawns" error. That is precisely the outcome
§3.5 says the sizing consequence exists to prevent.

*Why nothing catches it:* as with M1, every `Service` leg runs on CH, whose probe is the
trait-default no-op. The systemd proof cell (delta 9) is CH too.

*Fix (or doc, if the intent changed — but then both places, together):* select the budget on the
placement, keeping the 4 s constant for `Pid1` and deriving the `Service` window from the caller's
connect budget threaded into `start()`. Whichever way it resolves, the orchestrator comment and the
design sentence must move with it; today they agree with each other and not with the code.

---

### M3 — a leading double quote defeats every reserved kernel-cmdline key, and it is reachable from a REST client
`crates/vmcell/src/config.rs:611,624,672` · `crates/vmcell-daemon/src/dto.rs:211`

`normalize_cmdline_key` folds `-` to `_` and nothing else; the single-token guard rejects whitespace
and control characters, and `"` is neither. The kernel's `next_arg()` strips a leading quote
**before** taking the parameter name (`lib/cmdline.c`: `if (*args == '"') { args++; in_quote = 1; }`),
so a token vmcell keys as `"rw` is a token the kernel reads as `rw`.

*Failure:* `extra_kernel_args: ["\"rw"]` — accepted by `build()`, appended last, after the owned
`ro`. The kernel strips the quote, runs `__setup("rw")`, and clears `MS_RDONLY`. The same trick
reaches `"init`, `"root`, `"quiet` and every other reserved key. `CreateVmRequest::extra_kernel_args`
threads straight to `with_kernel_arg` with no daemon-side validation, so this is reachable from any
authenticated REST client — and law F3 exists precisely to make "an extra arg may add a parameter but
never clobber a token vmcell owns" true. The fuzz oracle shares the blind spot, because it models the
key the same way the predicate does.

*Fix:* strip a leading `"` in `normalize_cmdline_key` (matching the kernel's own parse), or reject a
token containing `"` in the single-token guard. Either way the gate is the existing all-emitted-tokens
test with a quoted variant of each key.

### M4 — `sweep_orphans`' cgroup arm is structurally unreachable in a systemd user session
`crates/vmcell/src/orchestrator.rs:2591-2601` · `crates/vmcell/src/metrics.rs:133-142`

`scan_cgroup_slices` walks from `/sys/fs/cgroup` with `depth = 4`, and the walk returns at
`depth == 0` before reading — so the deepest name it can match sits at path component 4. The slice it
must find is `metrics::vm_slice_name`, composed as `{cgroup_base_from_proc}/{leaf}`, which in a
systemd user session lives at
`/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/<scope>/<prefix>-vm-<vmid>` —
component 5 or deeper.

*Failure:* a hard-killed `vmcelld` (or a blessed-runner test process) leaves its per-VM slices behind;
the next start-up sweep reports zero cgroup slices reclaimed and the leak persists until reboot. The
netns and scratch arms of the same sweep work, so the failure is partial and quiet — the sweep reports
success having reclaimed two of three resource classes. This is the crash-recovery path §11.4 says
closes the hard-kill case.

### M5 — `ensure_blessed_or_explain` fails open for any euid-0 process with a narrowed capability set
`crates/vmcell-privilege/src/lib.rs:187-191`

```rust
let euid = rustix::process::geteuid();
if euid.as_raw() == 0 {
    return Ok(());
}
```

The function's own rustdoc twelve lines above states the opposite rule — the precondition "must test
`effective`, never `permitted`" — and law P1 is "refuses to start degraded". Real root with a narrowed
effective set is the common containerized shape: default Docker/Podman root holds neither
`CAP_NET_ADMIN` nor `CAP_SYS_ADMIN`, and a systemd unit with `User=root` plus a
`CapabilityBoundingSet=` that omits one of the three is the documented production deployment.

*Failure:* `vmcelld` starts cleanly in a container, prints its blessing precondition as satisfied, and
then fails every privileged create at first use — the exact "degraded server" outcome P1 exists to
forbid, arrived at through the one function both the daemon and the runner share.

*Fix:* drop the euid short-circuit and test the effective set unconditionally (a real root process
with the caps passes it anyway), or keep the fast path only when the effective set is genuinely full.
Design §13's named gate for P1 — "the daemon start-up precondition test" — does not exist either
(fan-out finding 38), so this needs the gate as much as the fix.

### M6 — `Registry::destroy` unpins an in-flight snapshot prefix for the whole duration of the write
`crates/vmcell-daemon/src/registry.rs:467-475`

`destroy` removes the slot from `self.vms` **before** it waits on the per-VM handle lock, and the
delete-in-use scan reads pins only through that table. So while a multi-second guest-RAM snapshot is
still writing, the slot is unreachable by the scan.

*Failure:* VM `A` is snapshotting into prefix `snap-a`; a client issues `DELETE /v1/vms/A`; `destroy`
removes the slot in microseconds and parks on `slot.inner`. A second client's
`DELETE /v1/artifacts/snap-a` now sees a pin-free table, returns 204, and `remove_dir_all`s the
directory the VMM is writing into. The `SnapshotPin` type exists specifically to prevent this; the
window is the gap between table removal and lock acquisition.

*Fix:* mark the slot `Destroying` in place and remove it from the table only after the handle lock is
held — the state machine already has that state.

### M7 — a `handle_event` error silently kills the NAT's only vring worker and wedges the link
`crates/vmcell/src/net/smoltcp.rs:444-449,600,609`

`process_tx_queue`'s `iter()` error propagates through `handle_event`, which the vendored event loop
treats as terminal: the worker thread exits and its result is discarded at join. The vhost-user device
stays attached, so the guest sees a live link that never drains — the same silent-wedge shape as the
ring-wrap panic §6.2 records, one error path over.

*Reachable by:* a guest driver that advances `avail.idx` past the negotiated queue size, or re-inits
with `avail.idx` at 0 while the backend's `next_avail` is non-zero — which `virtio-queue` documents as
its guest-misbehaviour detection. The unprivileged NAT's whole job is to survive a hostile guest.

*Fix:* log-and-continue on a per-queue iterate error rather than propagating it, or tear the device
down loudly. Sibling finding 20 (`tx_queue` has no depth bound, and its only consumer needs the mutex
`handle_event` holds across an unbounded drain loop) is the same module's other hostile-guest hazard
and is worth fixing in the same pass.

### M8 — the snapshot conformance probe reports every setup failure as `DoesNotWork`, so an unbootable artifact earns a green "verified absence"
`crates/vmcell-artifact-validator/src/conformance.rs:562-567` · `crates/vmcell-artifact-validator/src/checks.rs:781-798`

`snapshot_restore_roundtrip` returns `Err` for config-build failure, `MicroVm::start` failure, tempdir
failure and a failed steward handshake alike; the probe maps every `Err` to `DoesNotWork`, and
`judge` maps `DoesNotWork` on an absence declaration to `Pass`.

*Failure:* an artifact declaring `snapshot_restore: false` that cannot boot at all is certified as a
*verified absence* while the healthy control keeps the run green. That is precisely the shape §10.6
introduced `Unverified` for — "an absence that cannot be decided, with why, never counted as a pass" —
and the kit's own four-leg matrix cannot see it, because its `ScriptedProbe` supplies outcomes
directly.

*Fix:* split setup failure from probe result — a candidate that never reached the point where the
feature could be exercised is `NotRun` → `Unverified`, not `DoesNotWork`.

### M9 — Firecracker's restore occupies the ancestor's vmid-keyed scratch dir without reserving that vmid
`crates/vmcell-firecracker/src/lib.rs:1127,1141` · `crates/vmcell/src/orchestrator.rs:1690`

FC re-binds the baked vsock path verbatim, and that path is a pure function of
`(prefix, pid, **ancestor** vmid)`. `restore()` re-creates the ancestor's scratch directory and lives
in it, while the orchestrator hands the restored VM a *freshly allocated* vmid — and nothing reserves
the ancestor's, so it is free for same-process reallocation.

*Failure:* VM A (vmid 5) is snapshotted and torn down; VM C later draws vmid 5 and binds
`/tmp/<prefix>-vm-<pid>-5/vsock.sock`; a restore of A's snapshot now probes that path, finds C's live
listener, and is refused — or, worse, C's teardown removes the directory the restored VM is living in.
The recently-hardened `reject_live_baked_vsock` makes the first outcome loud rather than destructive,
which is why this is medium rather than high; the underlying identity collision is unaddressed.

*Fix:* reserve the ancestor's vmid across the restore (`VmidAllocator::reserve` exists and is used for
exactly this shape on the QEMU CID path), or key the restored VM's scratch dir on its own vmid and
bind-mount the baked path.

### M10 — `--handler-label default` builds a different artifact than the omitted spelling
`crates/vmcell-cli/src/main.rs:476,486`

Covered under H1: the CLI normalizes the rootfs label through `registry_label` and passes the handler
label raw, so the explicit spelling of the reserved default composes `guest_tools-default` — a
different stage name, artifact key, output file and cache key — where the omitted spelling composes
`guest_tools`. §10.5's byte-identity rule for a cell that names no label is the property this breaks.

### Remaining confirmed findings

The fan-out confirmed 57 subsystem findings and 20 cross-cutting ones after adversarial verification
(34 and 17 respectively were refuted and are not listed). The ones above are the highs and mediums;
the rest are low-severity and are grouped by theme in the sections below, with the balance recorded
here so nothing is lost:

| Area | Finding |
|---|---|
| `orchestrator.rs:2133` | `teardown_post_instance`'s rustdoc states the release order backwards at the tail — the exact inversion finding `m2` closed in the code |
| `orchestrator.rs:2217` | `shutdown()`'s post-ack-floor comment rests on a false premise: `unix_api_request` *is* bounded, by `CONTROL_REQUEST_TIMEOUT` |
| `config.rs:1915` | a `"` in a share tag or `guest_path` silently swallows every kernel parameter emitted after it (M3's sibling, different input surface) |
| `config.rs:1888` | `host_services_port: Some(0)` is accepted, and the NAT's discarded `listen()` result is justified by that unenforced precondition |
| `config.rs:1719` | the kernel path is the one host-path input `build()` does not check for absoluteness |
| `cloud_hypervisor.rs:926` | `ChInstance::snapshot`'s "resume on EVERY exit path" is false for a `vm.pause` timeout, and that branch is untested |
| `vmcell-firecracker:789` | the T2 probe spawns a Firecracker VM outside the composed launch — no Layer-2 jail, no netns — and the M11 source gate does not see it |
| `vmcell-crosvm:833` | the CID sidecar has no KVM-free gate: neither its format contract nor either error branch is ever driven |
| `vmcell-qemu:1017` | two comments say restore "reuses the baked CID", contradicting the shipped rotating-CID behavior they sit on |
| `smoltcp.rs:553` | a failed `exit_event` clone makes `drop(vu_daemon)` hang forever; its rustdoc asserts the opposite |
| `smoltcp.rs:764` | `admit_syn`'s `has_open` short-circuit caps transparent interception at `SYN_BURST` concurrent connections per destination |
| `net/tap.rs:27` | `netns_path`'s rustdoc claims the `/var/run/netns` layout is spelled in exactly one place; four other production sites compose it |
| `steward/mod.rs:842` | `StewardClient::reconnect` hardcodes AF_UNIX, so the documented recovery path cannot recover an AF_VSOCK connection |
| `vmcell-steward/serve.rs:432` | a panic in a connection thread skips law C3's session teardown while the registry ticket still deregisters, orphaning sessions |
| `vmcell-steward/run.rs:263` | service-mode shutdown sweeps only sessions, so a live one-shot `exec` child outlives the steward |
| `vmcell-steward/tests.rs:1005` | `the_shutdown_flag_stops_the_vsock_listener` cannot fail on the inner-loop inverse it names |
| `vmcell-cli:690,738` | `bundle` pins the stale rootfs when both formats are present, and names dotted labels under the sanitized spelling |
| `vmcell-cli:906` | the mmdebstrap arm silently drops the `applets` roster it is handed |
| `vmcell-cli:80` | `--release` is accepted and silently ignored on the OCI rootfs source |
| `daemon-client:215` | `DaemonClient` joins unvalidated caller strings into request paths on every verb except `upload_artifact` |
| `artifact_store.rs:114` | a failed digest-sidecar write leaves the artifact persisted while `create` returns 500 — deterministic for names of 249–255 bytes, since the sidecar suffix overruns `NAME_MAX` |
| `registry.rs:316` | `create` with an inline command and `ephemeral: false` leaks a running VM whose id the caller never receives |
| `conformance.rs:633` | `run_battery`'s `fill_unrecorded` tail can never fire, and both its comment and the as-built record claim a red-on-inverse it cannot have |
| `bridge/deadline_tests.rs:47` | the exec-budget margin assertion is structurally vacuous |
| `guest-tools:1738,1676` | the curl shim turns a failed or truncated body read into an empty body and exit 0; a malformed proxy env var is warned and dropped, so the request silently goes direct |
| `metrics.rs:222` | `classify_limit_write_err` sends `ENODEV` (a bad or partition `io.max` device) down the "enable delegation" path |
| `fs.rs:380` | `SOCKET_READY_TIMEOUT_MS` is a second, unlinked copy of the readiness ceiling whose doc asserts a coupling it does not have |
| `justfile:577` | `just ci` hand-copies the `test-unit` recipe body instead of invoking it — the drift shape `ci.yml` was already fixed for |

## 2. Gates that cannot go red

This section is the rubric's own meta-rule applied to the tree: AGENTS.md rule 2 is "every test and
every gate must be able to fail", and this project has already found and fixed this class three
separate times (the docs/81 campaign's five, the CI-repair pass's five, the v33 pass's four). It is
not exhausted.

### G1 — no gate runs doctests; six documented examples on the public API are never compiled
`justfile:105,577` · `.github/workflows/ci.yml:231-232`

`just ci` and `just test-unit` both run `cargo nextest run --locked --all-features`, and **nextest
does not support doctests**. `cargo test --doc` appears nowhere in the `justfile`, in any workflow,
or in any script — verified by grep across all of them.

Measured: the tree carries **six** doctests — `MicroVm::start`, `MicroVm::restore`,
`VmConfigBuilder::build`, `StewardClient::connect`, `EgressProxy::start`, and
`KconfigValues`' module example — and all six pass today. Five of them are on `vmcell`, a
contract-surface crate; three are on the entry points a new consumer reads first.

*Failure:* change `MicroVm::start`'s signature, or `HostEnv::shared`'s, and the example that shows a
consumer how to call it silently stops compiling while every gate stays green. The examples are
correct today by luck rather than by construction, and the tree's own rustdoc gate
(`RUSTDOCFLAGS="-D warnings" cargo doc`) does not compile examples — its comment even says "`cargo
doc` runs nowhere else", which is true of *links* and silent about *code*.

*Fix:* add `cargo test --locked --all-features --doc` to the `ci` recipe and a matching CI step —
nextest's own documentation prescribes exactly this pairing. It runs in about a second on this tree.
The second-order value is larger than the first: with doctests gated, adding worked examples to the
public API becomes safe, and the library's front door badly needs them (D11).

**Post-review correction.** The measured six is now **seven**: E1's fix added a `proxy::doubles`
module example, and `just test-doc` — the recipe `just ci` and `ci.yml` both invoke — runs the set
workspace-wide, which is what reaches the validator's `kconfig` example as well as `vmcell`'s six.

### G2 — three `#[ignore]`d live tests in `vmcell-bench` are selected by no recipe and no CI job
`crates/vmcell-bench/tests/benchmark.rs:101,122,144` · `justfile:152,167,175,200,219,256,285`

`test_benchmark_fc`, `test_benchmark_qemu` and `test_benchmark_crosvm` are `#[ignore = "needs KVM"]`.
Every `--run-ignored all` invocation in the tree is package-scoped elsewhere: `-p vmcell` (five
recipes), `-p vmcelld`, `-p vmcell-artifact-validator`. `just ci` and `just test-unit` pass no
`--run-ignored`, so ignored tests are skipped. `grep -n "vmcell-bench" justfile` returns only two
`cargo clippy` lines.

This is the identical defect the `test-validator` recipe's own header documents as discovered and
closed one package over (`justfile:180-183`):

> until this recipe existed NO invocation in the tree selected them — every `--run-ignored all` was
> scoped to another package — so the only proof that the battery can go red was compiled and skipped.

*Failure:* `bench-vm`'s Firecracker, QEMU or crosvm wiring breaks — a renamed flag, a dropped backend
in the composition root, a report that stops printing percentiles. All three tests would catch it;
none of them runs. The breakage surfaces when a human runs `bench-vm` by hand, which is how
`test_benchmark_qemu` was last exercised (the QEMU snapshot pass records running it).

*Fix:* a `just test-bench` recipe mirroring `test-validator`
(`-p vmcell-bench --run-ignored all --no-tests=fail` through the blessed runner), called from
`ci.yml` beside the other live suites. `--no-tests=fail` is the clause that makes the mis-scoped
filter loud rather than green.

### G3 — the delta-8 out-of-checkout gates use the banned `println!("SKIP") + return` shape, and say they do not
`crates/vmcell/tests/repack_outside_checkout.rs:299-308,324-327,358-361`

```rust
/// Whether this host can produce ext4 images at all, recording a reviewable capability skip when it
/// cannot (§7.2 — an absent facility, classified by the product's own probe).
fn ext4_available() -> bool {
    match vmcell::artifact::ext4::Ext4Producer::probe() {
        Ok(_) => true,
        Err(Error::CapabilityUnavailable { op, needed }) => {
            println!("SKIP: this host cannot produce ext4 rootfs images ({op}: {needed})");
            false
        }
```

There is no `record_capability_skip` call; the file does not even declare `mod common`. The
doc-comment's "recording a reviewable capability skip" is false. AGENTS.md: *"Skips go through
`require_cap!` only … A `println!("SKIP") + return` is a green PASS."*

The sharpest part is that the correct form ships in the same delta, in the sibling file, and names
this exact hazard: `ext4_cell.rs:95-111`'s `probe_or_record_skip()` calls
`crate::common::record_capability_skip("cloud-hypervisor", "ext4_producer")` before printing, under a
rustdoc reading *"Skipping on it would be the `println!("SKIP") + return` green-PASS defect wearing
the probe's clothes."*

*Failure:* on a host whose e2fsprogs is older than 1.47.1 or lacks libarchive, both delta-8
position-independence gates report PASS having packed nothing, and `just skip-manifest-show` — which
"Done means" requires reviewing after the suite sequence — shows no entry, so the reviewer has no
signal that the out-of-checkout ext4 claim went unverified.

*Fix:* route both call sites through the one law — lift `probe_or_record_skip()` into
`tests/common/mod.rs`, or at minimum add the `record_capability_skip` call here.

### G4 — eight of twelve ban gates pass vacuously on an empty scan; the two newest fail loudly
`scripts/ban-global-state.sh:45` and seven siblings

Measured by handing each script a directory containing no Rust sources:

| Behavior on an empty scan | Scripts |
|---|---|
| **exit 0**, `ok: no Rust sources under: …` | `ban-global-state`, `ban-inline-setns`, `ban-artifact-path-join`, `ban-kernel-key-composers`, `ban-rootfs-key-composers`, `ban-handler-key-composers`, `ban-readiness-timeout-literal`, `ban-agent-ip-shellout` |
| **exit 1/2**, `gate misconfigured: …` | `ban-unpinned-path-literal`, `ban-registry-digest-check`, `ban-root-disk-writability-literal`, `ban-legacy-terms` |

The correct shape is already in the tree — it is what the two delta-6c scripts and the docs/81 M13
fix to `ban-legacy-terms` adopted — and it was never swept across the rest. `just gates` invokes them
with no arguments today, so `crates/` exists and the scan is non-empty; the exposure is a
reorganization or an explicit-path invocation, and the class is one this repo treats as
first-class (the `setcap` tree walk asserts `files.len() > 50` for exactly this reason, and the C8
scan asserts `out.len() > 500`).

*Fix:* replace the eight `echo ok; exit 0` empty-scan arms with the `gate misconfigured` arm the
other four use, and add an empty-tree leg to each self-test so the fix itself can go red. Also worth
noting: `ban-uncolored-cargo-parse.sh` ignores its directory argument entirely (it scans the
`justfile` and workflows regardless), which is correct for its job but means its argument is inert.

**Post-review correction.** The finding was right and its table was short. Sweeping it, measured the
same way (hand each script a directory with no Rust sources), turned up three things this section did
not say:

- The table lists twelve scripts. A **ninth** vacuously-green one was not on it —
  `ban-test-support-in-production.sh` — and its roster form was the worst of the set: one real tree
  plus one mistyped tree scanned only the real one and still printed green.
- Two of the scripts carried a **second** vacuous arm the empty-directory probe cannot see: an
  explicitly-passed *missing* directory was also reported `ok`.
- The closing note's premise about `ban-uncolored-cargo-parse.sh` is inaccurate. That script does not
  ignore its argument: it takes a roster of **files** and defaults to the repo's gate-bearing ones. The
  real defect was one step down — a non-regular-file argument (a directory, or a missing path) was
  swallowed by the per-file `[[ -f ]]` guard and reported as `ok (1 files; …)`, so a caller who
  believed a tree had been scanned had had nothing opened. That is the accepted-but-ignored (F1) shape,
  and it is a hard error now.

All nineteen `scripts/ban-*.sh` fail loudly on a zero-file scan today, each with an empty-tree leg in
its own self-test; `ban-legacy-terms.sh`'s odd `exit 2` folded to 1 after its callers were checked.
The rule earned a line in `AGENTS.md` under "one law, one predicate", which is where the next
source-scanning ban will read it.

### G5 — the C8 gate's second assertion is structurally unfailable
`crates/vmcell/src/config.rs:4646-4651`

```rust
for s in &port_sites {
    assert!(
        !s.contains("fn resync_reachable"),
        "the availability method must not be defined in terms of eligibility: {s}"
    );
}
```

`port_sites` is, by construction, the set of production lines containing `steward_port()`. A line
containing `steward_port()` cannot also be the `fn resync_reachable` signature line, so the assertion
holds for every possible tree. The inverse it names — an availability method defined in terms of
eligibility — lives in `resync_reachable`'s **body**, which this loop never looks at.

The two assertions above it are load-bearing and do go red (they require ≥3 availability sites and ≥2
eligibility sites, so deleting a call reddens). Only this third one is theater.

*Fix:* assert on the definition instead of the call sites — extract `resync_reachable`'s body from
the production text (the `fn_body` helper in `vmcell-daemon/src/auth.rs` is the shipped idiom) and
assert it does not mention `steward_port`.

### G6 — the mandatory KSM coupling has no gate
`crates/vmcell/src/vmm/cloud_hypervisor.rs:716-720`

```rust
// `mergeable` (KSM) lever requires `shared=off`. Default keeps
// shared memory (the vhost-user paths need it); only the opt-in
shared: !cfg.ksm_mergeable,
mergeable: cfg.ksm_mergeable,
```

Design §8.3 states the coupling is mandatory and records the measurement that makes it so: KSM merges
only private-anonymous pages, so with `shared=on` it deduplicates **zero** of guest RAM. `ksm_mergeable`
has builder and rejection tests in `config.rs`; nothing anywhere asserts the payload this arm
produces. The string `ksm` does not appear in `cloud_hypervisor.rs` outside that one comment.

*Failure:* a refactor that sets `mergeable: true` and leaves `shared: true` compiles, passes every
test, and silently deduplicates nothing — the caller asked for a density lever and got a no-op. That
is the F1 shape the fail-loud law exists to kill, in the one place §8.3 warns about it.

*Fix:* a KVM-free serialization assertion on the CH memory payload for both values of
`ksm_mergeable`, in the shape of the existing `CH_RAW_IMAGE_TYPE` pin. It costs nothing and needs no
KVM.

### G7 — the host→guest tuning channel is unfalsifiable: the guest's fallbacks are the host's defaults
`crates/vmcell/src/config.rs:358-359,429` · `crates/vmcell-steward/src/options.rs:130,140,200,207`

The two tuning tokens are hand-spelled on both sides of the process boundary with no shared const
(`vmcell` does not depend on `vmcell-steward`; the sibling `STEWARD_VSOCK_PORT` solved this by moving
to `vmcell-protocol`, which both link). That alone is survivable. What makes the channel
unfalsifiable is that the guest's compiled fallbacks are byte-identical to the host's emitted
defaults — `ACCEPT_POLL = 20 ms` / `REBIND_IDLE = 250 ms` against `guest_accept_poll: 20 ms` /
`guest_rebind_idle: 250 ms` — and no live suite boots a non-default `Timeouts` profile (T2).

*Failure:* rename either literal on either side, or delete the guest's parse block outright, and
every suite stays green: the steward falls back to exactly the numbers the host meant to send. A
caller selecting `low_latency()` (5 ms / 150 ms) silently gets 20 / 250, including the post-restore
re-bind window that bounds how long a restored guest stays unreachable.

*Fix:* move the two token names into `vmcell-protocol` as consts both crates import (removes the
spelling drift), and add one live leg that boots under a non-default profile and observes the honored
cadence (removes the unfalsifiability). Recorded in `implementation-notes.md` in the meantime.

### G8 — the living consumer gate exercises none of v33's contract additions, while its README claims it consumes every item
`examples/downstream-kernel/README.md:7` · `examples/downstream-kernel/pins-overlay.json` ·
`examples/downstream-kernel/ci-check.sh`

The example workspace's README opens: *"Design v30 §10.4 names the downstream contract surface; this
workspace consumes every item on that list, so a change that breaks it is contract drift."* Its
overlay carries exactly two namespaces (`kernel_fragments`, `kernels`). Grepping the whole workspace
for `XattrPolicy`, `PackOptions`, `feature_manifest_path`, `CheckStatus::Warn`, `Unverified`,
`run_battery`, `ConformanceOptions`, `--rootfs-label` or `--handler-label` returns **nothing**.

*Failure:* the `example-downstream` CI job is the mechanism §10.4 names as "the living consumer that
reddens CI when any listed surface drifts", and AGENTS.md calls breaking it "the intended failure mode
of contract drift". A change to the rootfs or handler registry namespaces, to `PackOptions` or
`XattrPolicy`, to the feature-manifest sidecar's name or format, or to `CheckStatus`'s variants passes
that job green. The surface v33 added is exactly the surface the gate cannot see — and the README
sentence makes the hole invisible to a reviewer who reads it.

*Fix:* the cheap half is KVM-free and small — a `rootfs` label in the overlay resolved through the
registry, a `feature_manifest_path` round-trip, and a `run_battery` leg exercising `Warn`. If any row
is deliberately out of scope, say which in both the README and `src/lib.rs`'s table, so the claim
matches the coverage.

### G9 — `review-preflight-priv.sh` prints READY against a blessed runner two commits stale
`scripts/review-preflight-priv.sh` · `justfile` (`bless`) · `docs/historical/89-…-v5.md` §5.2

The preflight verifies the blessed runner's capabilities and its 0700 mode. It does **not** compare
the blessed copy against the current source; that check is the content-hash `.blessed` stamp, and it
lives only in the `bless` recipe, which needs one sudo and therefore cannot run in a
non-interactive session.

Measured during this review: preflight printed READY while the blessed copy (2026-08-14 11:24)
predated `d02527b`'s rewrite of the privilege transition into a step-list executor. The probe is
decisive — `strings` finds **0** occurrences of `PrivilegeStep` in the blessed copy and **84** in the
current build. Every privileged run since 2026-08-15, including this review's 228/228 and the v5
handoff's stated bar, executed through the pre-rewrite binary. `bless` detected the staleness
correctly and refused to replace a working blessing when sudo was unavailable, which is the
stage-then-swap design working exactly as written.

CI is unaffected — `ci.yml` runs `just bless` before the privileged suite — so this is a reviewer-path
defect, not a product one, and no behavioral difference between the two binaries has been
demonstrated. The exposure is that the live gate on the runner's *own* posture
(`the_bounding_set_is_shrunk_to_exactly_the_delivered_caps`) certifies whichever binary happens to be
blessed, and AGENTS rule 5 sends the reviewer through a probe that cannot tell.

*Fix:* give the preflight a stale-stamp verdict mapped onto its existing BLOCKED-ON-BLESS exit — it
can compare the stable copy's hash to `.blessed` and its mtime against the newest mtime under
`crates/vmcell-test-runner/src`, `crates/vmcell-privilege/src` and `Cargo.lock` without taking the
cargo lock — and add the bless step to the documented reproduction sequence. Recorded in
`implementation-notes.md`.

---

## 3. Contract surface and the ledger

### C1 — `pack_rootfs_with_injection` is a new public entry point on a contract crate, in no ledger and on no list
`crates/vmcell/src/artifact/rootfs/mod.rs:1294,1615`

Delta 8 turned `pack_erofs_with_injection` — the function design §10.4 names as contract surface —
into a format-checking wrapper that **refuses** any `PackOptions::format` other than `Erofs`, and put
the format-honoring tail behind a new `pub async fn pack_rootfs_with_injection`. The new function
appears in **none** of: the `crates/vmcell/Cargo.toml` comment ledger, `implementation-notes.md`,
design §10.4's "one named list", or the README's copy of that list.

*Failure:* a consumer following the contract to pack an ext4 artifact calls the listed function with
`format: Ext4` and gets a typed error telling it to call a function the contract does not name.
Adding a `pub fn` is additive, so `cargo semver-checks` is silent by construction — which is the
whole reason §10.4 asks for a ledger entry rather than trusting the tool.

*Fix:* one ledger line and one §10.4 line. The wrapper/tail split itself is right and is now recorded
as a justified deviation in `implementation-notes.md`.

### C2 — the ledger skips 0.8 → 0.9 → 0.10, the two versions spanning the most breaking release in the crate's history
`crates/vmcell/Cargo.toml:20-25`

The comment changelog runs `0.2 → 0.3` … `0.7 → 0.8` and then jumps straight to a bare `0.11.0:`
entry. There is no `0.8 → 0.9` and no `0.9 → 0.10`. Per `implementation-notes.md:573`, 0.9 → 0.10 is
"the v28 delta register … eleven deltas landed as one breaking pass" — the `HostEnv` threading that
changed every spawn call site, the `limits_enforced` → `mem_limit_enforced` rename, the removal of
`host_services_port` from `NetConfig::Privileged`, the removal of `RootfsSource::VirtioFs`, and the
demotion of `instance_mut`.

*Failure:* the ledger is the mechanism §10.4 designates so a break is "a deliberate, findable ledger
entry, never discovered by compile failure". A consumer migrating across the gap reads nothing about
the single largest break the crate ever shipped. The validator's ledger, by contrast, is contiguous
(0.1 → 0.2 → 0.3 → 0.4 → 0.5) — so this is a hole in one of the two, not a convention nobody follows.

*Fix:* backfill the two entries from `implementation-notes.md`'s v26 and v28 sections, and add the
gate that would have caught it: a unit test parsing the `# X → Y:` lines out of both contract crates'
`Cargo.toml` and asserting they form an unbroken chain ending at `version`. Note also that
`crates/vmcell/src/lib.rs:16` describes the ledger as "gated by `cargo semver-checks`" — semver-checks
gates the version *number*, never the presence of an entry.

### C3 — `build_labelled_rootfs` and `build_labelled_handler` do not exist
`docs/historical/83-claude-fable-design-v33.md:3360,3509`

§10.4's contract list names "the labelled rootfs/handler build entry points"; §10.5's "where selection
lives" paragraph names them explicitly as `build_labelled_rootfs`/`…_handler`. Neither function
exists anywhere in the tree. The shipped shape is the constructor pair `RootfsStage::labelled` /
`GuestToolsStage::labelled` plus the `vmcell build --rootfs-label / --handler-label` verbs, and the
register's own convention ("a shift is recorded, never silent") was not honored — nothing in
`implementation-notes.md` mentions it until this pass.

*Consequence:* a git-dep consumer building a labelled rootfs writes more code than one building a
labelled kernel and is sent to a function that is not there — the "public in the Rust-visibility
sense but semi-public in practice" state §10.4 exists to retire, reintroduced for the two kinds v33
added. The constructors are the better shape and stay; that decision is now recorded in
`implementation-notes.md`. What needs fixing is the two design lines.

### C4 — the README's contract-surface list is the v30 one, and is now a second, disagreeing copy
`README.md:43-47`

The README enumerates the v30-era five rows and names `pack_erofs_with_injection` + `ExtraFile` as
the pack shape. Design §10.4 and `AGENTS.md` both name four v33 additions the README omits (the
rootfs and handler registry namespaces, the labelled build entry points and the feature-manifest
sidecar, the `XattrPolicy` parameter, `CheckStatus`'s two new variants), and the shipped pack
signature has taken `&PackOptions` since the ledgered 0.16 → 0.17 break.

*Failure:* §10.4 designates the README as "the guidance section a consumer follows". A consumer
follows it, writes the pre-0.17 call, and does not compile. And because the README does not list the
registry namespaces or `XattrPolicy` as contract, a future change to them reads as unlisted surface
and skips the ledger.

*Fix:* bring the README list into agreement, naming `PackOptions`. Then consider gating it: this is a
third copy of one list, and `scripts/check-agents-md-sync.sh` exists because *"two copies of one
document is the same shape as two copies of one law, and it failed the same way."*

### C5 — design §17 says `validate()`'s missing battery budget was closed by delta 3; it was not
`docs/historical/83-claude-fable-design-v33.md` §17 · `crates/vmcell-artifact-validator/src/lib.rs:165-184,354`

§17: *"`validate()` has **no overall wall-clock budget** today … **directed closed by §18 delta 3**
(`ConformanceOptions.battery_budget`)."* Delta 3 landed `battery_budget` on `ConformanceOptions` and
bounds `run_battery` with it. `ValidationOptions` still carries exactly one field, `level`, and
`validate()` never calls `run_battery` — they are parallel entry points.

The scoping is defensible and is recorded as a justified deviation; what needs fixing is §17 reading
as though the older, documented downstream conformance route were bounded. A `Level::Full`
`validate()` run boots several VMs sequentially and is bounded only by the sum of its per-check
deadlines.

*Fix:* either give `ValidationOptions` the same field (a small, additive, ledgered change) or correct
§17 to scope the closure to the conformance battery and keep `validate()`'s gap on the register.

---

## 4. Documentation

### D1 — the C8 re-key finished in the code and stopped at the prose: seven sites still assert the retired `cfg.init` derivation
`crates/vmcell/src/orchestrator.rs:674, 1917, 2088, 2098, 2282, 4551` · `crates/vmcell/src/config.rs:90`
*(convergent: the reviewer's own pass and the api-library sweep)*

Delta 4 moved control-plane availability from `cfg.init.is_some()` onto
`StewardPlacement::steward_port()`, and moved snapshot eligibility onto `resync_reachable()`. The
assignments are correct (`orchestrator.rs:1558` and `:1768` both read
`cfg.steward_placement.steward_port().is_none()`). Seven prose sites were not swept:

| Site | What it says | What is true |
|---|---|---|
| `:674` field doc | "`true` when the VM boots a custom `init=` … Set from `cfg.init` at construction" | set from `steward_port().is_none()`; contradicts the `steward_placement` doc 16 lines above |
| `:1917` `connect_sessions` `# Errors` | "immediately when this VM boots a custom `init=`" | wrong both ways: `Service` + custom init does *not* take the arm; declared `None` + no init does |
| `:2088` `snapshot` `# Errors` | "when this VM boots a custom `init=`" | the guard is `!resync_reachable()`, so `Service{5000}` + `init: None` is refused while booting no custom init |
| `:2282` `resolve_cell_features` doc | "config … Today that is one arm: a custom `init=`" | the arm is `steward_port().is_none()`, emitting "declares StewardPlacement::None" |
| `:2098`, `:4551` comments | "`control_plane_disabled` is the retained `cfg.init.is_some()`" | it is the retained *availability* answer, which differs from `cfg.init.is_some()` exactly at `Service` + custom init |
| `config.rs:90` `VmConfig::init` rustdoc | still asserts the pre-v33 conflation — a custom init costs the control plane | a seventh site, found by the config slice; `Service` + custom init keeps it |

Four of the seven are public rustdoc on a contract crate, so this is a published-contract error for
`Service` cells, not only an internal note. The mis-described case is constructible and is the one
v33 deltas 4–5 exist to enable: `build()` rejects only `Pid1` + custom init, and `config.rs` asserts
that `Service{5000}` + `/lib/systemd/systemd` "must build — the systemd shape".

*Why nothing catches it:* the C8 call-site scan strips comments — `code = l.split("//").next()` at
`config.rs:4558` — so `//` and `///` alike are invisible to it. The behavioral risk is genuinely
low (a maintainer re-keying a guard is caught by two independent gates), which is why this is filed
as documentation rather than correctness; the cost is that the authoritative-looking rustdoc on the
contract crate is wrong.

*Fix:* rewrite all six to the shipped derivation. Extending the scan to comment lines is precedented
(`ban-legacy-terms.sh` scans every line of every file kind), and would close the class rather than
the instance.

### D2 — the served OpenAPI document points consumers at "design §D", a section that does not exist
`crates/vmcell-daemon/src/openapi.rs:199`

```rust
"description": "The vmcell daemon HTTP REST API (design §D).",
```

The design has §1–§18 plus Appendices A–E; there is no §D. This is a dangling reference in a document
the daemon *serves* to clients. The daemon is design §11. *Fix:* point at §11, and fix the sibling
references in the same edit.

### D3 — `naming` is listed among the modules carrying `#![forbid(unsafe_code)]` and does not carry it
`crates/vmcell/src/naming.rs:1` · design §15.2

Design §15.2 lists "`net/` …, `config`, `naming`, `artifact`'s pure core, the protocol codec". Every
module on that list carries the attribute except `naming.rs`, and there is no crate-level substitute
in `lib.rs`. The module has no `unsafe` today, so nothing is broken — but the structural guarantee
§15.2 claims does not hold for law F2's sole home, the module whose output the orphan sweep uses to
decide what to delete.

*Fix:* CODE, not doc — add the attribute. It is free and makes the design's statement true by
construction. Dropping `naming` from the list instead weakens a stated structural gate for nothing.

### D4 — README rosters and figures are stale in three places
`README.md:11,208` · `justfile:138`

- `README.md:11` lists the guest-tools applets as `ip`/`curl`/`kvm-ok`/`echo-server` — four of the
  **six** in `vmcell_protocol::GUEST_TOOLS_APPLETS` (`mini-init` and `xattr` landed in v33 deltas 5
  and 7).
- `README.md:208` states the crosvm matrix is 29/29; measured on this host today it is **30/30**.
  The line already carries the right instinct ("that recipe is the number's source, so read it there
  rather than from here") — the embedded figure beside it is what goes stale.
- `justfile:138`'s `test-privileged` comment restates the same four-applet roster.

AGENTS.md: *"Counts and rosters quoted in docs … are checked against the tree, never from memory …
Prefer a pointer to the recipe that produces a number over an embedded figure."* *Fix:* correct the
rosters, or replace them with a pointer at `GUEST_TOOLS_APPLETS`, which is const-asserted against the
dispatch table and cannot go stale.

### D5 — §7.4's host axis is not `HostCapabilities`, and the code's own rustdoc repeats the false derivation
`crates/vmcell/src/feature.rs:586` · design §7.4

§7.4 says the host contributes `HostCapabilities`; the intersection actually reads
`feature::HostDeclaration::probe()`, which decides `NestedVirt` only, and `feature.rs:586`'s rustdoc
repeats "derived from `HostCapabilities`". *Fix:* DOC at minimum (name `HostDeclaration` and say what
it decides). CODE is the better fix if §7.2's one-probe law is to hold: give `HostCapabilities` the
nested-virt read and construct `HostDeclaration` from the descriptor, so the host axis has one probe
rather than two.

### D6 — §9.3 calls `steward_port()` "the ONE C8 predicate", the exact spelling §13's C8 defines as the law's violation
`docs/historical/83-claude-fable-design-v33.md:2927` (and §18 delta 4's *What* line)

C8 is a **two-method** law precisely because the two questions differ at `Service`. The §9.3
annotation on `VmConfig::steward_placement`, and delta 4's own *What* line, each name only
`steward_port()`. *Fix:* DOC — name both methods, matching §13 and §8.1.

### D7 — §2.2's "every control RPC is bounded at 5 s" has a deliberate, unstated exception
`docs/historical/83-claude-fable-design-v33.md:356`

The snapshot RPC's budget scales with guest RAM through `vmm::snapshot_request_timeout(mem_mib)` —
correctly, since a suspend image tracks guest RAM. The design states the flat ceiling without the
exception. *Fix:* DOC, one clause.

### D8 — an implementation-notes "accepted limitation" survives its own retirement condition
`docs/implementation-notes.md:744-748`

The entry recording that `tar2erofs` does not preserve PAX xattrs ends "Retire if xattr passthrough
is implemented" — delta 7 implemented it — and names a test that delta 7 renamed. Its neighbour at
`:748` should be spot-checked for the same drift. *Fix:* DOC — retire the entry or rewrite it as the
delta-7 pointer.

### D9 — design §15.4 names a test delta 7 renamed
`docs/historical/83-claude-fable-design-v33.md:4673`

§15.4's xattr battery names `test_pax_xattrs_are_not_preserved`; the shipped names are
`pax_xattrs_are_stripped_under_the_default_policy` / `…_preserved_under_the_preserve_policy`. §4.7's
two mentions and delta 7's gate line carry the old name too. *Fix:* DOC, or record the rename under
delta 7 per the register's convention.

### D10 — design still advertises `RootfsSource::Block` as a writable root at two sites beyond the one already recorded
`docs/historical/83-claude-fable-design-v33.md:1391,1662`

`implementation-notes.md`'s delta-8 section records §4.7's sentence as needing correction; the same
claim survives at two more design sites. The authority is
`RootfsSource::root_device_read_only`. *Fix:* DOC all three together, and widen the notes entry so
the next reissue does not fix one and leave two.

### D11 — the library that calls itself "the product surface" has no worked example anywhere a consumer looks
`README.md` · `crates/vmcell/src/lib.rs`

The README states "The library API is the product surface" and contains **zero** Rust code blocks.
`crates/vmcell/src/lib.rs`'s crate doc is a long, good prose contract with no code. **Eleven of the
thirteen library crates carry no example at all** — including `vmcell-daemon-client`, whose
`DaemonClient` is literally "a typed Rust API matching the `vmcell` entry points" — and inside
`vmcell` itself the contract-surface entry points `Stage`, `Pipeline`, `pack_rootfs_with_injection`,
`PackOptions` and `run_battery` have none.

This is the lowest-cost, highest-leverage documentation work available, and it is gated the moment
G1 is fixed: a doctest is both the example and the test that it still compiles. The natural set is
one example each for boot-and-exec, snapshot-and-restore-via-`Zygote`, a `Pipeline` assembly, and a
`DaemonClient` round trip.

---

## 5. Testing coverage

Enumerated per AGENTS rule 4. The full list, with the rationale for recording rather than closing
each, is now in `docs/implementation-notes.md`; the items below are the ones worth closing first.

### T1 — three of four `ResourceLimits` fields are never applied in any live boot
`crates/vmcell/tests/metrics_limits.rs:38`

The only live test that sets a limit sets exactly one, `mem_max_mib`. `cpu_max_pct`, `pids_max` and
`io_max` appear in no integration test in the tree; their coverage is unit tests of the *rendered
strings*. The daemon side is thinner still — `stats_limits_enforced_matches_delegation` creates its
VM with no limits at all.

`io.max` is the sharp one: its `device` field is a caller-supplied `"major:minor"` string, and
whether the kernel's rejection of an unsupported device is fail-loud has never been observed. And
§7.3's own history is the argument — `memory.max` alone did **not** bind a CH guest until
`memory.swap.max=0` and `memory.oom.group=1` joined it, a fact no amount of string-rendering coverage
could have produced. A silently unenforced limit reads as isolation the product does not provide.

*Close first:* a `cpu_max_pct` leg (re-run the existing in-guest load under a 25% quota and assert
measured `cpu.stat` usage lands near the quota) and a `pids_max` leg (assert `pids.events max > 0`).

### T2 — four shipped `VmConfig` knobs are never booted
`console_mode`, `timeouts` presets, `ksm_mergeable`, `restore_mode`

None appears in any integration test. `bench-vm` drives all four, and `bench-vm` is not a gate
(and, per G2, three of its own live tests are unreachable). The consequences are covered under G6
(KSM), G7 (the tuning channel) and T3 (the console).

### T3 — `ConsoleMode::VirtioConsole` is never booted; crosvm's `virtio_console: true` has no live evidence
`crates/vmcell/tests/nested_virt.rs:45-53`

The honesty pin says so in its own comment: the flag "has no dedicated matrix integration leg, so its
descriptor value is pinned here". Three backends advertise it; the only live evidence on record is
the `bench-vm` console table, which covers CH and QEMU. crosvm's claim rests on
`--serial hardware=virtio-console` and a single arg-builder unit test.

*Failure:* under `VirtioConsole` the guest writes to `hvc0`; if the device wiring and the `console=`
token ever desync, `serial.log` goes silent — and silence is indistinguishable from a quiet boot,
on the one configuration that has already given up early-boot capture. *Close with:* one matrix leg
asserting a guest-written marker reaches `serial.log`, with `require_cap!` making the FC skip honest.

### T4 — `DiskIoLimit::iops` is never live-booted, and the daemon's `ExtraDiskSpec.io_limit` is never live-honored
`crates/vmcell/tests/extra_block.rs:155`

The bandwidth half is well covered (a 1 MiB/s cap floors a 4 MiB read at ~3 s on every backend, with
an un-throttled baseline in the same VM). The `iops` half has no live leg, and the daemon's DTO →
config translation for `io_limit` is never exercised end to end.

### T5 — `NetMode::snapshot_eligible` and the daemon's snapshot-ineligibility refusal have no test anywhere
`crates/vmcell-daemon/src/dto.rs:81` · `crates/vmcell-daemon/src/registry.rs:227`

A repo-wide grep for `snapshot_eligible` returns the definition and one call site. No unit test
drives it, and the `vmcelld` integration suite exercises only the positive path. Invert the predicate
or delete the guard and nothing reddens: `POST /v1/vms {"net":"unprivileged","snapshotting":true}`
stops being refused at the daemon's own boundary and falls through to the config builder, whose
refusal names a vhost-user device rather than the net mode the client typed — losing the "fail loud
early" contract §11.5 states. *Close with:* a KVM-free `registry.rs` unit test plus its two positive
controls; the check runs before any artifact resolution, so it is reachable with a fake.

### T6 — no live test asserts the confinement state of a running VMM
`crates/vmcell/tests/jail_hardening.rs:30`

The jail gates are thorough and all three read paths are covered — but every one of them runs against
a `/bin/cat` stand-in spawned through `build_vmm_cmd`, never against a live VMM. The link the
stand-in cannot reach is the one that matters: that a real Cloud Hypervisor process, after
`apply_jail`, actually carries `NoNewPrivs=1`, a loaded seccomp filter, and the ambient set the
backend needs. *Close with:* one privileged leg that boots a VM, resolves the VMM pid the way
`ch_pids_for_vmid` already does, and reads `/proc/<pid>/status`, with a `VmmSeccomp::Disabled` boot as
the red-on-inverse control.

---

## 6. API clarity and simplification

Assuming, as the review brief states, that migrating consumers is easy.

### A1 — `Cache` is a public, documented, entirely inert type every `Pipeline` caller must construct
`crates/vmcell/src/artifact/mod.rs:445-447`

```rust
/// Cache for previously built artifacts.
pub struct Cache {}
```

No fields, no methods, no `impl`. Both consumers ignore it by name: `build(&self, _cache: &Cache)`
and `reset_to(&self, stage: &str, _cache: &Cache)`. The real caching is entirely sidecar-driven
through `Stage::cache_sidecar_path`, to which this type has no connection. `Pipeline` is named
contract surface, so a consumer must write `pipeline.build(&Cache::default())` and reads the rustdoc
as a promise that the handle holds or shares cache state.

*(The adversarial verifier declined this one as churn. It is kept because the rustdoc makes a promise
the type does not keep, and the cheaper half of the fix is free.)* *Fix:* either say so in the
rustdoc — "a placeholder: caching is per-stage and sidecar-driven; this argument is ignored" — or drop
the parameter and ledger it. The pre-1.0 minor bump is cheap now and gets more expensive with every
consumer.

### A2 — a third copy of the Cloud Hypervisor binary resolver, and §17's consolidation register names only two
`crates/vmcell-cli/src/main.rs:1152-1156`

`vmcell::artifact::ch_binary_path()` is the designated one law and is `pub`.
`vmcell-cli::ch_bin()` is byte-identical to it and does not call it. §17's open-consolidation entry
names `harness::ch_bin()` and `bench-vm`'s workspace-root ascent, and misses this one.
(`vmcelld/src/main.rs`'s flag-then-env precedence and `vmcelld/tests/integration.rs`'s PATH-searching
variant are legitimately different and should stay; `bench-vm`'s table is principled and
parity-asserted.) *Fix:* call the one law from the CLI, and correct the §17 entry's inventory.

---

## 7. Extension points

The review brief asks that the extension points the documented use cases need be kept in mind. The
`Vmm` trait seam is in good shape: all fourteen helpers an out-of-tree backend would need
(`build_vmm_cmd`, `apply_jail`, `LaunchPlan`, `register_and_await_ready`, `reap_process_group`,
`config_has_vhost_user_device`, `build_kernel_cmdline`, `reject_unadvertised_capabilities`,
`reject_unsupported_console`, `VMM_SOCKET_READY_TIMEOUT_MS`, `snapshot_request_timeout`,
`wait_for_socket`, `VmmProcessGroup`, `jail_spec_from_config`) are `pub`, so a fourth-party backend
crate is genuinely writable out of tree. It stands on unledgered surface, but the design does not
promise otherwise.

### E1 — the proxy doubles seam, one of §1.3's two "designed-in" connection points, leaks unversioned third-party types
`crates/vmcell/src/proxy/doubles.rs:8-11`

```rust
pub type Matcher = Box<dyn Fn(&Request<hudsucker::Body>) -> bool + Send + Sync>;
pub type Responder =
    Box<dyn Fn(&Request<hudsucker::Body>) -> Response<hudsucker::Body> + Send + Sync>;
```

`vmcell` re-exports neither `hudsucker` nor `hyper`, and neither is on §10.4's contract list. So a
git-dep consumer writing a test double — the thing design §1.3 calls the proxy "the natural home"
for — must add both crates to its own manifest at exactly vmcell's resolved versions, discover those
versions by reading the lockfile, and accept that a bump inside vmcell silently breaks it. That bump
has already happened once (hudsucker 0.23 → 0.24, in the dependency-modernization pass), and
`cargo semver-checks` cannot see it: the alias's *shape* is unchanged.

The in-tree consumers do not notice because they share the workspace lock, and the example workspace
— the gate that exists to notice exactly this — never constructs a double.

*Fix, cheapest first:* `pub use hudsucker;` (and `hyper`) from `vmcell::proxy` so a consumer names one
version, and add both to §10.4's list so a bump is ledgered. The larger fix — vmcell-owned request and
response types at the seam — is worth considering only if the doubles surface grows.

---

## 8. Recorded as justified rather than fixed

Six divergences are recorded in `docs/implementation-notes.md` under "As built: the docs/90 review
pass" rather than reported here as defects, because the shipped shape is the right one and what was
missing was the record:

1. `pack_rootfs_with_injection` as the general tail with `pack_erofs_with_injection` as its erofs
   door (the ledger line is still a fix — C1).
2. The absence of `build_labelled_rootfs`/`build_labelled_handler`, and why the `labelled`
   constructors are the better shape (the design line is still a fix — C3).
3. Delta 3's battery budget belonging to the conformance battery rather than `validate()` (§17's
   sentence is still a fix — C5).
4. The enumerated live-coverage gap for the shipped config knobs (AGENTS rule 4's "cover it or record
   it").
5. The guest tuning-token channel's unfalsifiability (G7's fix is named there too).
6. The scope of `review-preflight-priv.sh`'s READY verdict (G9).

---

## 9. What was checked and found clean

A review that lists only defects hides its own coverage. These were checked against the tree and
hold:

- **All thirty one-law predicates `AGENTS.md` names exist** — from `config_has_vhost_user_device` and
  `is_reserved_cmdline_arg` through `resync_reachable`, `capped_debug` and `GUEST_TOOLS_APPLETS`.
- **Every `VmConfig` field is read on a production path.** A field-by-field sweep of all
  twenty-four found no accepted-and-ignored knob — the F1 class docs/81 found twice is closed at the
  field level.
- **The NAT's six silent-wedge invariants are each implemented as §6.2 describes**, including the
  subtle one: the guest→host drain writes from *inside* smoltcp's `recv` closure over the contiguous
  span, with a `min` guard against a writer that over-reports, so `consumed <= span` is true by
  construction.
- **`spawn_clones` is cancellation-safe in the recorded shape** — `join_all`, not `try_join_all`,
  with successes gathered and torn down in order on the first error.
- **The two doc-discovery gates work.** Both were re-run after this pass edited `docs/`: the
  deny-list roster parse (`vmm::jail`, 4/4) and the blessing-copy tree walk (`vmcell-privilege`,
  23/23).
- **`PackOptions` is destructured exhaustively at the identity fold**, so a new field that nobody
  folds is `error[E0027]` — the structural fix that closed the applet-roster cache collision.
- **The F6 parity gate reads the source of truth**, extracting `VmmCapabilities`' field names out of
  `vmm/mod.rs` rather than retyping them.
- **The `Error` enum has no dead variant**, and there is no `Error::Other` catch-all.
- **No bare `let _ =` on a `Result` anywhere under `crates/vmcell/src/`**; the instances elsewhere are
  best-effort cleanup and CLI output.
- **One `TODO` marker in the entire tree** (`fs/in_process.rs:256`), on the `experiment-fuse` backend
  §17 already records as blocked on read-only enforcement.
- **The example workspace's lockfile is current** (`vmcell` 0.20.0) — the staleness the v5 handoff
  warned about was heeded.
- **Seventeen fuzz targets** with a workflow carrying six explicit guards, including the one that
  fails the job if a target file has no `[[bin]]` stanza.

---

## 10. What this review could not check

- **`just test-usb-passthrough`** was not run as its own recipe; `VMCELL_TEST_USB_DEVICE` was
  exported for the privileged run, and the skip manifest records no USB skip, so the in-suite leg
  ran.
- **The privileged suites executed through a blessed runner two commits stale** (G9). No behavioral
  difference between it and a current build has been demonstrated, but the runner's own posture gate
  certified the older binary.
- **Multi-host, aarch64 and non-Debian guests** are out of scope by design.
- **The `Service` post-restore question** stays unmeasured, as §17 records; nothing here changes that.

### The one thing this method missed: CI had been red for three commits, and running every suite locally is why

*Added 2026-08-17, in the review's own voice, because "green locally" is exactly the evidence class
the method above rests on.*

`ci` on GitHub had been **failing since `3e8d658`** — three commits before this review was written —
on `test-unit` and `test-integration` (`lint` and `example-downstream` were green throughout). It was
still failing at `c276da7`, the commit this review reads, and at `aaf5f4c`, the commit this review
*is*. The §"Live validation" table above says READY and green because every suite in it ran **on this
host**, and the defect is a property of the *other* host:

- `mkfs.ext4 -d <tarball>` — the form delta 8's ext4 producer is built on — landed in **e2fsprogs
  1.47.1**. This box has 1.47.2; GitHub's `ubuntu-24.04` image packages **1.47.0**, and apt cannot
  supply newer at any pin.
- Delta 8's producer battery treated the tool as `Priority: required` and **panicked** on a failed
  probe rather than recording a capability skip. The package is required everywhere vmcell builds; the
  *version* is not — and one patch release is the whole gap.
- So four tests failed on every CI run, each retried four times by the integration profile, while
  every local run of the same suites passed. A permanently-red job is a job nobody reads, which is
  worse than a skip.

Two things follow, and both are corrections to method rather than to a finding:

1. **A locally-executed suite is evidence about this host, not about CI.** AGENTS rule 5 says to
   execute rather than presume, and this pass did — every row of the table above, all green. What it
   did not do is look at the last CI run, which is the one observation that costs nothing and was the
   only one that could have seen this. A review that runs the suites should read the workflow's own
   history in the same breath; "the suites are green here" and "the gates are green" are different
   claims.
2. **A host-facility probe is a capability boundary, and it belongs to §7.2's vocabulary, not to an
   assumption about package priority.** This is finding G3's class — the delta-8 skip shape — arriving
   from the opposite direction: G3 found a *silent green* where a skip should have been recorded, and
   this found a *hard panic* in the same battery for the same missing facility. One `probe()`, three
   answers, three different call-site policies. The review reported the first and could not see the
   second, because on this host the probe succeeds.

Closed in the fix pass, both halves, so the normal outcome is that the battery runs:
`crates/vmcell/tests/{ext4_producer,ext4_cell,repack_outside_checkout}.rs` all ask the one law,
`common::probe_ext4_or_record_skip`, which records `SKIP cloud-hypervisor ext4_producer` to
`VMCELL_SKIP_MANIFEST` and returns `None` (a *broken* facility still panics, §7.2 rule 3); and
`.github/workflows/ci.yml` builds a pinned, checksum-verified e2fsprogs 1.47.2 from source, non-gating,
in every job that runs those legs — with `ci_obtains_the_ext4_facility_rather_than_living_with_the_skip`
as that step's gate and `every_ext4_battery_asks_the_one_law` as the call-site scan.

*That last clause read "the call-site scan that keeps a fourth answer from appearing" until the tree
produced one: the scan named three files and `rootfs_registry.rs` was the fourth. It discovers its roster
now — see §11's G3 row, which is where this document's corrections live.*

---

## 11. Resolution (post-review)

**Re-verified 2026-08-17 against commit `c34f9c2` plus 17 uncommitted files in the working tree**
(`git log -1 --format=%h`; `git status --short | wc -l`, both measured). `c34f9c2` carries the pass's
code and its design reissue together; four later fix lanes had not been committed when this was written,
so the tree — not the commit — is what every row below was read against. Each row names the file, and
where that is the load-bearing part the line, which makes its status true; a row that names nothing is a
row to distrust.

Six rows were **stale in the fixing direction** once those lanes landed — H2, G2, G3, D1, M7 and
`artifact_store.rs:114` — and each is corrected in place below with its correction marked, because a
resolution record that understates a fix costs the next reader exactly as much work as one that
overstates it. Only one of the six changed *status*: `artifact_store.rs:114` is **fixed**, not "fixed
(deviation)", because the deviation that row described was the pre-fix behavior. Subsection 9 records the
four lanes themselves — none of which is a finding of this review, which is precisely why they belong in
this document rather than in a new one.

*This section's first draft was written while the lanes were still landing, and an adversarial re-audit
of all 84 items found it false in five places — each one describing an earlier tree, and each one in the
direction that costs a later reader work:* C5 asserted a design gap as open that had been closed by a
shipped field, so acting on the row would have **reversed a correct design sentence**; G1 quoted a
doctest count that was stale before the pass ended; D11 said no worked example existed anywhere, after
examples had landed on both front doors it named and on all but one of the entry points; D8 said an implementation-notes entry was still open, after it had been retired and
dated; and nine rows prescribed design sentences that were already written. A resolution record without
the stamp above cannot be checked for that, which is the whole reason it now carries one — and a figure
copied out of a half-landed tree is why the rows below point at recipes and laws instead of quoting
counts.

Statuses: **fixed**; **fixed (deviation)** where the shipped fix deliberately departs from the
finding's own *Fix:* line; and **partly open** where a named remainder stands. Every deviation's
reasoning is at its call site and in `docs/implementation-notes.md`; this table names the deviation in
a clause and does not re-argue it.

Nine findings (C1, C3, C5, D6, D7, D9, D10, A2, E1) were whole or in part a body sentence in
`docs/historical/83-claude-fable-design-v33.md`, and **that reissue landed in the same commit**
(`git show c34f9c2 -- docs/historical/83-claude-fable-design-v33.md` carries every one of those sentences as an
addition). Their rows therefore name the design line that *now* carries the sentence instead of
prescribing one, and `docs/todo.md`'s design-corrections list retired with them. Each was a
**body-sentence** edit inside an existing section; none was fixed by renumbering a heading, because two
gates resolve `§`/`Appendix` references against the discovered-newest design's real headings —
`scripts/ban-dangling-design-ref.sh` over `crates/*/src` plus the `Cargo.toml`s, the `justfile` and
`scripts/`, and `scripts/check-docs-pointers.sh` over the root markdown's references and every
`docs/…` pointer in the root files and `docs/*.md`. Neither script's totals are quoted here: each
prints the references and headings it resolved, and that output is the roster.

### 1. Major — correctness

| id | Status | What landed, and where it can be checked |
|---|---|---|
| H1 | fixed | The pack tail *and* `cache_key`'s consumed fold read one composer, `PackOptions::handler_key()` = `handler_artifact_key(self.handler_label)` — `crates/vmcell/src/artifact/rootfs/mod.rs`, where the fold is now `let consumed: [&str; 2] = ["steward", handler_key.as_str()]` and `OCI_ROOTFS_STAGE_VERSION` is bumped for the key move. `--handler-label` normalizes through `registry_label` beside the rootfs one, `crates/vmcell-cli/src/main.rs`. Delta 6b's deferred live leg exists: `crates/vmcell/tests/handler_cell.rs` boots a registered handler and has *its own* applet answer in-guest, with `curl`'s `ENOENT` proving the emitted symlinks came from the entry's roster rather than the const. |
| H2 | fixed | `oci::build_rootfs_with` calls the general tail, `crates/vmcell/src/artifact/rootfs/oci.rs`. Its gate is the registry-driven leg at that seam, `the_oci_stage_packs_through_the_general_tail_so_an_ext4_label_builds`, with an erofs positive control on the same layers. **Corrected after `c34f9c2`: the gate as first shipped did not discriminate on every host, which is what this row claimed.** Its absent-facility arm matched the refusal's *wording* (`needed.contains("e2fsprogs")` and two siblings) and returned green — so on any host that cannot produce ext4 it reported PASS for a claim, real ext4 bytes, that nothing had checked, and it is an in-crate unit test, so the skip law is unreachable from it and the skip manifest said nothing either. It now asks the one format→emitter law, `emitter_for`, and requires the pack's outcome to **match that route**: a producer means superblock bytes, a refusing route means the caller got that same refusal verbatim (`oci.rs:820-869`). Both arms are unenterable on the wrong kind of host, no wording is matched at all, and the arm's comment names which batteries own the ext4-bytes claim instead. |
| M1 | fixed | QEMU composes one endpoint through `steward_endpoint(params, vsock_path, placement)`, taking `placement.steward_port()`; `crates/vmcell-qemu/src/lib.rs`. The C8 scan's "cannot see a backend crate" blind spot is closed at the workspace instead of per backend: `no_crate_bakes_the_steward_port_outside_the_justified_sites` (`crates/vmcell/src/config.rs`) walks every crate's production text and allows `STEWARD_VSOCK_PORT` only at its justified sites, with non-vacuity anchors; and `crates/vmcell/src/vmm/mod.rs` pins the *pair* of rustdoc blocks (`vsock_endpoint`'s baked default and `verify_control_plane`'s probe) to name each other, so the next backend to override the probe reads the warning. |
| M2 | fixed (deviation) | `control_plane_probe_budget(placement)` is the one selector and `start()`'s single probe is *scanned* for passing exactly that expression — `crates/vmcell/src/orchestrator.rs`, `mod probe_budget_gate`, which also pins `CONTROL_PLANE_PROBE_BUDGET` to exactly two mentions so a second policy site cannot appear. Two deviations from the *Fix:* line, both argued at the site: `Service` takes `DEFAULT_STEWARD_CONNECT_BUDGET` (the caller's connect-budget **default**, since `Timeouts` carries no connect field and `start()` sees no per-call window), rather than a window threaded through `start()`; and the budget stays **per attempt**, a narrowing of §3.5's "overall window" wording that keeps the re-spawn loop's QEMU bring-up recovery intact. |
| M3 | fixed | Two independent layers in `crates/vmcell/src/config.rs`: `is_cmdline_unsafe_char` rejects `"` outright at every cmdline-encoded input surface, and `normalize_cmdline_key` strips a leading quote so the predicate answers about the token the *kernel* reads. This closes the `config.rs:1915` sibling (a `"` in a share tag or `guest_path` swallowing every later token) under the same law, and the fuzz oracle moved with the predicate — `fuzz/fuzz_targets/kernel_cmdline_args.rs`. |
| M4 | fixed | The walk depth is derived, never a literal: `crate::metrics::vm_slice_scan_depth(&self.cgroup.slice_name)` in `HostOrphanScanner::scan_cgroup_slices`, `crates/vmcell/src/orchestrator.rs`, with a systemd-user-session-depth leg and a flat-tree leg (red on restoring the `4`). |
| M5 | fixed | The euid short-circuit is gone. `blessing_verdict(euid, effective, need)` decides on the **effective** set unconditionally and the euid only selects *which* remediation to print; `crates/vmcell-privilege/src/lib.rs`. |
| M6 | fixed | `destroy` marks the slot `Destroying` **in place** and removes it from the table only after the handle lock is held, so the delete-in-use scan sees the pin for the whole write; `crates/vmcell-daemon/src/registry.rs`. |
| M7 | fixed | A ring the guest broke ends the tick and re-arms the kick — `TxPass::Unreadable`, never an `Err` the vendored epoll loop treats as terminal; `crates/vmcell/src/net/smoltcp.rs`. Sibling 20 landed in the same pass: one state lock per pass, released between passes, so the drain the queue is being filled for is no longer starved. **Two defects of the fix's own making were closed after `c34f9c2`, and this row did not name them.** The restructured loop left four notification toggles discarding their `Result` — one `let _ = …enable_notification()` the fix itself added in the `Unreadable` arm, plus a carried-forward `let _ = …disable_notification()` and two `.unwrap_or(false)` — and sibling 20's depth bound made the NAT lossy under a stalled consumer while saying so at `trace!`, one `RUST_LOG` from silence. All four toggles route through `mask_tx_notifications` (`:511`, `warn` — advisory) / `rearm_tx_notifications` (`:534`, `error` — the mask being lifted is what tells the *guest's* driver it may kick again, so leaving it set is M7's own wedge reached through the error path of M7's fix), and every dropped frame is counted and reported at `warn`, flood-capped by `tx_drop_is_reportable` (`:198`). Gates are KVM-free, reaching the toggle error paths by re-pointing the used ring at an unmapped guest address (`TxRing::break_used_ring`, `:2671`); see `docs/implementation-notes.md`. |
| M8 | fixed | Setup failure is `ProbeOutcome::NotRun` → `CheckStatus::Unverified`, never `DoesNotWork`; `crates/vmcell-artifact-validator/src/conformance.rs`, with the unbootable-candidate leg asserting `Unverified` where the pre-fix path earned `Pass`. |
| M9 | fixed | `adopt_lineage(ancestor)` reserves the ancestor's vmid for the restored VM's lifetime and releases it on drop, keyed off `crate::vmm::adopted_scratch_vmid`; `crates/vmcell/src/orchestrator.rs`. A same-id/different-pid ancestor is handled ahead of the reserve. |
| M10 | fixed | With H1 — `registry_label` on `--handler-label`, `crates/vmcell-cli/src/main.rs`. |

### The "Remaining confirmed findings" table

| Row | Status | What landed |
|---|---|---|
| `orchestrator.rs:2133` | fixed | `teardown_post_instance`'s rustdoc now states the tail order the body executes, `crates/vmcell/src/orchestrator.rs`. |
| `orchestrator.rs:2217` | fixed | The post-ack-floor comment names the real bound (`vmm::unix_api_request`'s `CONTROL_REQUEST_TIMEOUT`, *longer* than the shipped grace), and a stalled-RPC leg asserts ≥1 post-ack poll. |
| `config.rs:1915` | fixed | Under M3's one law — `"` is refused at the share-tag and `guest_path` surfaces too. |
| `config.rs:1888` | fixed | `host_services_port: Some(0)` is refused at `build()` naming the bind wildcard, `crates/vmcell/src/config.rs`. |
| `config.rs:1719` | fixed | The kernel path is checked for absoluteness like every other host path (`"kernel … must be an absolute path"`), with existence still deliberately unchecked. |
| `cloud_hypervisor.rs:926` | fixed | A timed-out `vm.pause` still issues `vm.resume` and refuses to snapshot a guest whose pause is unproven; the third exit path has its own ordered-paths leg. |
| `vmcell-firecracker:789` | fixed | **Post-review correction to the row's own text:** the fix is not just the probe. The T2 probe now composes through `firecracker_launch_plan` — the same `LaunchPlan` every real boot gets — *and* the M11 source gate was **widened**: it grew a third ban on a hand-rolled spawner, the route its two existing bans (no local `JailSpec`, no VMM command outside the plan) structurally could not see. The row said the gate does not see it; the gate now does. |
| `vmcell-crosvm:833` | fixed | `the_baked_cid_sidecar_round_trips_and_both_error_arms_are_typed` — the bare-decimal format contract, the trailing-newline tolerance, and both error branches, KVM-free. |
| `vmcell-qemu:1017` | fixed | Both "restore reuses the baked CID" comments are gone; the file's prose matches the shipped rotating-CID behavior. |
| `smoltcp.rs:553` | fixed | The exit-event pair is reserved at bring-up (`arm_exit_event`) so `exit_event` cannot fail into a `None` that hangs `drop(vu_daemon)` forever, and the framework premise is pinned rather than asserted in prose. |
| `smoltcp.rs:764` | fixed | `admit_syn` no longer short-circuits on `has_open`; the `SYN_BURST + 1`-th concurrent connection to one destination earns a listener, bounded by `MAX_DYNAMIC_SOCKETS`. |
| `net/tap.rs:27` | fixed | All four production sites compose from `netns_path`/`netns_dir`, and the claim is gated: `netns_layout_gate` plus the new `scripts/ban-inline-netns-path.sh` and its self-test. |
| `steward/mod.rs:842` | fixed | `reconnect_endpoint` is the transport-generic recovery (`redial` is the one shared body); `reconnect` stays as the AF_UNIX coordinate wrapper and now **fails loud** on an AF_VSOCK client, naming `reconnect_endpoint`. |
| `vmcell-steward/serve.rs:432` | fixed | Law C3's teardown has one owner — the registry ticket's own drop — so a panicking connection thread cannot deregister without tearing its sessions down. |
| `vmcell-steward/run.rs:263` | fixed | Service-mode shutdown sweeps live one-shot `exec` children *then* interactive sessions, through the same ordered helper the other two shutdown paths use. |
| `vmcell-steward/tests.rs:1005` | fixed | Split into two legs that each fail on their own inverse: `…_between_bind_retries` and `…_parked_in_poll`. |
| `vmcell-cli:690,738` | fixed | `rootfs_bundle_candidates` composes each candidate through the key/filename laws from the recorded registration (so the declared format wins over whatever is present), and always includes the default artifact the filename walk cannot see. |
| `vmcell-cli:906` | fixed (deviation) | Honored-or-rejected, resolved as **rejected**: `reject_unbakeable_handler_for_mmdebstrap` refuses an entry declaring its own `applets` beside a workspace build rather than silently dropping the roster. The clause is unreachable today by construction, and its premise carries its own gate (`the default handler must declare no applets`) so it becomes reachable loudly. |
| `vmcell-cli:80` | fixed | `--release` beside `--rootfs-source oci` is refused naming both, keyed on the **raw** flag so the default is applied at the one arm that consumes it — the omitted spelling and `--release trixie` compose the identical stage and cache key. |
| `daemon-client:215` | fixed | `validate_path_segment` runs on every verb before any `Url::join`, with a source-scan gate that reddens if a new verb joins a caller string directly; `crates/vmcell-daemon-client/src/lib.rs`. |
| `artifact_store.rs:114` | fixed | **This row's first draft described the PRE-fix behavior as the fix.** It said the create "keeps the name taken rather than rolling the artifact back", and quoted the warn string that is only the *rollback's own* failure path. `create` is all-or-nothing: a failed `write_sidecar` removes the persisted artifact before returning the 500, so the error reply describes the store's actual state (`crates/vmcell-daemon/src/artifact_store.rs:114-127`). Gate: `a_failed_sidecar_write_rolls_the_artifact_back` (`:565`), which injects the failure the way a real one arrives — a directory at the sidecar path, so the `rename` fails `EISDIR` — and asserts the name is free again. The rollback is **best-effort**, and that residue is recorded in `docs/implementation-notes.md`: a failed `remove_file` burns the name for the daemon's lifetime, with one `warn` naming the artifact. The deterministic instance the finding named cannot reach it — a name whose `.sha256` sidecar would overrun `NAME_MAX` is a 400 at the boundary, because `MAX_ARTIFACT_NAME_LEN` is `NAME_MAX` less the suffix (`crates/vmcell-daemon/src/name.rs:29`), gated by `create_rejects_a_name_whose_sidecar_would_not_fit` (`artifact_store.rs:523`). |
| `registry.rs:316` | fixed | The VM is torn down whenever the exec itself failed, not only under `ephemeral`, so no running VM is left whose id the caller never received — with a non-ephemeral working-exec positive control. |
| `conformance.rs:633` | fixed (deviation) | The dead `fill_unrecorded` tail is **deleted** rather than repaired, and the property it claimed is gated where it actually lives: `the_battery_reports_its_whole_roster_whatever_is_declared`, red on a `battery_inner` arm that skips a feature instead of judging it. |
| `bridge/deadline_tests.rs:47` | fixed | The `|| budget >= BROKER_VM_CALL_BUDGET` escape clause is gone; the margin assertion is unconditional and both branches of the `max` are driven (840/841 straddle the crossover). |
| `guest-tools:1738,1676` | fixed | A truncated body fails loud as curl 56 rather than becoming an empty body with exit 0, and a malformed proxy env var is a **rejection** naming the variable rather than a warning that sends the request direct; `crates/vmcell-guest-tools/src/main.rs`. |
| `metrics.rs:222` | fixed | `ENODEV` joins `EINVAL` as a rejected **value**, so a bad `io.max` device is `Error::Cgroup` and not a delegation remediation; `crates/vmcell/src/metrics.rs`. |
| `fs.rs:380` | fixed | The local `1000` is gone: `socket_wait_budget` reads `crate::vmm::VMM_SOCKET_READY_TIMEOUT_MS`, and the coupling its doc asserts is pinned by a test. |
| `justfile:577` | fixed | `just ci` invokes `{{just_executable()}} test-unit`, and the class is gated one level in by the new `scripts/ban-recipe-body-handcopy.sh`, which reads bodies back through `just --show` and fails if `ci` or `ci.yml` restates another recipe's lines. |

### 2. Gates that cannot go red

| id | Status | What landed |
|---|---|---|
| G1 | fixed | `just test-doc` (`cargo test --locked --workspace --all-features --doc`, `justfile:156-157`), invoked by `just ci` (`justfile:796`) and by `ci.yml`'s `test-unit` job (`.github/workflows/ci.yml:328`) as a recipe call, never a copied cargo line. **No doctest count is quoted here, deliberately:** the recipe's own header says why — "No count is quoted here on purpose — this recipe IS the roster; run it" (`justfile:142`) — and this row's first draft quoted a figure that was already stale when the pass ended, which is the exact defect AGENTS.md's pointer-over-figure rule exists to prevent. |
| G2 | fixed | `just test-bench` — `-p vmcell-bench --run-ignored all --no-tests=fail` through the blessed runner, called from `ci.yml`'s kvm job under a delegated scope (`justfile:299`, `ci.yml:626`). Its argument is a features list defaulting to `cloud-hypervisor,firecracker,qemu`, so the crosvm leg is never compiled where there is no binary, and a list omitting `cloud-hypervisor` is refused up front rather than failing inside a test. **The recipe that closed this finding shipped unable to execute what it selected, and a single local invocation would have caught it.** All five of its tests died at ~0.008 s on the first CI run with a bare `Operation not permitted (os error 1)`: the recipe wrapped the test binary in the blessed runner and `assert_cmd`'s `Command::cargo_bin` read that same `CARGO_TARGET_<TRIPLET>_RUNNER` variable and re-composed `<runner> <bench-vm>`, so `execve` refused the second wrap with EPERM. Children are spawned directly now, inheriting through the ambient set — the shape `just test-daemon` documents — from `env!("CARGO_BIN_EXE_bench-vm")` so the path cannot be redirected by the environment; four KVM-free gates and the measured mechanism are in `crates/vmcell-bench/tests/common/mod.rs` and in `docs/implementation-notes.md`. The features guard's stated premise was also wrong and is corrected there: cargo sets `CARGO_BIN_EXE_bench-vm` even when the bin's `required-features` are unmet, so the hazard was a stale binary reported as this run, not a panic. |
| G3 | fixed | All three delta-8 ext4 batteries ask one law, `common::probe_ext4_or_record_skip` in `crates/vmcell/tests/common/mod.rs`, which records the skip to `VMCELL_SKIP_MANIFEST` before returning `None`. That the fix is wider than the finding is thanks to its call-site scan: `ext4_producer.rs`, the third file in the same battery, answered the *same* absent facility with a hard **panic** — which is what had CI red. See §10's closing subsection. **Corrected after `c34f9c2`: `every_ext4_battery_asks_the_one_law` enumerated three files, and there was a fourth answer already in the tree.** `rootfs_registry.rs`'s `format: ext4` leg spelled its own `record_capability_skip("cloud-hypervisor", "ext4_producer")` and printed its own `SKIP` — exactly the two shapes that scan's arms 4 and 5 exist to catch — and both arms stayed green for the whole pass because the scan never opened the file. The law gained a refusal-side door rather than a second copy (`classify_ext4_refusal`, `common/mod.rs:332`; that leg cannot pre-probe without skipping past the erofs-only door it exists to assert), and the scan now **discovers** its roster (`ext4_answer_findings`, `:537`, driven from `every_ext4_battery_answers_an_absent_facility_through_the_one_law`, `rootfs_registry.rs:1877`). It also matches whitespace-free, because rustfmt had wrapped the offending `println!(` and a line-wise needle would have stayed green even once the file entered the roster. The enumerated scan is retained — it holds a call-site floor and a structural arm the discovered one does not — and the two residuals that leaves are in `docs/implementation-notes.md`. |
| G4 | fixed | Measured the same way the finding was — hand each script a directory with no Rust sources — every `scripts/ban-*.sh` now refuses a scan it cannot perform: a non-zero exit, a message naming the broken roster, and an empty-tree leg in its own self-test. All but one print the shared `gate misconfigured` verdict; `ban-legacy-terms.sh` prints its own `roster resolved to 0 files` and folds its odd `exit 2` to 1, with the reasoning in its header (`scripts/ban-legacy-terms.sh:65-70`, the arm at `:117-120`) — so grep the roster rather than the verdict string. `just gates` is that roster. See the post-review correction under the finding for the three things its table did not say. |
| G5 | fixed | The third assertion reads the **definition**: `fn_body(SELF_SOURCE, "pub const fn resync_reachable(self) -> bool")` is asserted not to mention `steward_port`, with a shape check so a failed extraction cannot pass silently; `crates/vmcell/src/config.rs`. |
| G6 | fixed | `ch_memory_payload_couples_ksm_mergeable_to_unshared_memory` asserts the composed CH memory payload for both values of `ksm_mergeable`, KVM-free — and the arm was lifted out of `create()` into a named composer so `ksm` appears in the file's test text at all; `crates/vmcell/src/vmm/cloud_hypervisor.rs`. |
| G7 | fixed | Both halves. The spelling half is compile-time: `vmcell_protocol::STEWARD_ACCEPT_POLL` / `STEWARD_REBIND_IDLE` are one `TuningToken` definition each side reads. The unfalsifiability half is `crates/vmcell/tests/guest_tuning.rs`, which boots a cell with a non-default re-bind window and counts the **distinct socket inodes** PID 1 creates — a measured cadence read out of `/proc/1/fd`, with no guest-side code added, because the steward logs at `info` and the guest has no `RUST_LOG`. Its KVM-free vacuity guard was red in CI as first shipped and is fixed after `c34f9c2` (subsection 9): the guard survives, with the artifact pair as a parameter. |
| G8 | fixed | The example workspace's overlay now carries `rootfs.acme` (digest-pinned, `"xattrs": "preserve"`, a hand-declared `features` stance) and `handlers.acme` (registered by digest, with its own applet roster), and `tests/contract.rs` exercises `XattrPolicy`, `PackOptions`, `feature_manifest_path`, `run_battery`, `ConformanceOptions`, `DEFAULT_BATTERY_BUDGET` and `CheckStatus`. The README's sweeping claim is now scoped: four rows are consumed only as far as a network-free, KVM-free job reaches, and `src/lib.rs`'s table says which and why. |
| G9 | fixed | `scripts/review-preflight-priv.sh` decides freshness **cargo-free** — sha256 against the `.blessed` stamp plus `find -newer` over the runner's in-tree source closure — and maps stale onto the existing BLOCKED-ON-BLESS exit. `--check-runner` is the one home of that predicate, shared with `bless`. |

### 3. Contract surface and the ledger

| id | Status | What landed |
|---|---|---|
| C1 | fixed | The ledger line exists — `crates/vmcell/Cargo.toml`'s 0.19 → 0.20 entry (`:472`, the tail itself at `:493`) names `pack_rootfs_with_injection` as "the one a consumer of §10.4's list must act on", records that it was ledgered late, and points at `docs/implementation-notes.md` for the split's justification. `README.md`'s copy of the list names it too. **The design line landed with the pass:** §10.4 now lists "the one inject+pack tail `pack_rootfs_with_injection` **and** its erofs-only door `pack_erofs_with_injection`, both contract surface" (`docs/historical/83-claude-fable-design-v33.md:3429-3431`), and §4.7 states the door relationship at `:1521`. |
| C2 | fixed | The chain is contiguous — `0.8 → 0.9` and `0.9 → 0.10` are written — and the mechanism is gated: `crates/vmcell/tests/contract_ledger.rs` reddens on a gap, a duplicate, or a chain that stops short of `version`, for both contract crates, and its header says plainly what it cannot check (content, not shape). |
| C3 | fixed | `build_labelled_rootfs` / `build_labelled_handler` do not exist and are not going to; the `RootfsStage::labelled` / `GuestToolsStage::labelled` constructors are the decision, recorded in `docs/implementation-notes.md`. **The design lines landed with the pass:** §10.4's contract list names the two constructors plus the `vmcell build --rootfs-label`/`--handler-label` verbs that drive them (`docs/historical/83-claude-fable-design-v33.md:3425-3428`), and §10.5's "Where selection lives" names the same shape *and* records the second shift — why no thin assembler mirrors `build_labelled_kernel` (`:3602-3613`). |
| C4 | fixed | `README.md`'s list is reconciled with §10.4 and `AGENTS.md`: the registry namespaces, the feature-manifest sidecar, `XattrPolicy`, `CheckStatus`'s five states, and `pack_rootfs_with_injection` beside its erofs-only door — with the shipped `&PackOptions` signature named. |
| C5 | fixed | **This row's first draft said `ValidationOptions` "still carries only `level`". It does not, and a reader acting on that would have re-opened a closed gap.** The scoping half of the finding was right — `battery_budget` belongs to `run_battery` — and the gap it exposed is closed by its own field: `ValidationOptions::run_budget: Option<Duration>` (`crates/vmcell-artifact-validator/src/lib.rs:300`), defaulting to `Some(DEFAULT_RUN_BUDGET)` (`:307`, 20 minutes at `:280`) and bounding the **whole** run — every level, every boot — through `run_levels_bounded` at `:534`, whose overrun is the typed `Error::Timeout` naming the budget, the level that outran it and the checks that finished (`:543`). `None` opts out explicitly. `::level(l)` sets the field by functional update so a later field cannot silently make every `level()` caller unbudgeted (`the_default_and_the_level_constructor_both_carry_the_default_budget`), and `validate_on` exists precisely so the budget is drivable without KVM (`:529`). It is a breaking addition to an exhaustive struct and is ledgered as one (`crates/vmcell-artifact-validator/Cargo.toml:82`, with `DEFAULT_RUN_BUDGET` additive at `:90`). **The design line landed with the pass:** §17 states the closure by that field and scopes delta 3's to the battery, naming why the two constants stay separate (`docs/historical/83-claude-fable-design-v33.md:5119-5132`); §10.4 carries it as ledgered validator surface (`:3438-3440`). |

### 4. Documentation

| id | Status | What landed |
|---|---|---|
| D1 | fixed | All seven prose sites state the shipped derivation, including the four public rustdoc ones; `crates/vmcell/src/config.rs`'s `VmConfig::init` doc is now explicit that the field decides init **identity only**, and that `Service` beside a custom init *keeps* the control plane. The class is closed, not just the instance: `no_production_prose_asserts_the_retired_init_derivation` reddens on a comment block that asserts the retired conflation, with its own predicate driven against both the retired and the shipped sentences. **Corrected after `c34f9c2`: the reader is no longer scoped to two files, which is what this row said.** A prose reader over `config.rs` + `orchestrator.rs` is the same two-file scope whose blindness let QEMU bake the steward port for a whole release on the *code* side of this law (M1), and four of the seven sites were public rustdoc — as wrong in `vmcell-qemu`'s rustdoc as in this crate's. It now stands on the one workspace walk the port half already used (`workspace_source_files`, `config.rs:5611`, with three readers over it), floored on blocks *and* bytes *and* **per crate** against a roster read independently of the walk (`crates_with_src`, `:5127`), because `vmcell` alone carries over half the workspace's prose. The widened scan has its own red-on-inverse against a fabricated backend file (`:5314`). |
| D2 | fixed | The served OpenAPI names `design §11`; `crates/vmcell-daemon/src/openapi.rs`. The class is gated tree-wide by two new scripts, `scripts/ban-dangling-design-ref.sh` (every `§` and `Appendix` under `crates/*/src`) and `scripts/check-docs-pointers.sh` (root markdown + `docs/*.md`), which is a wider fix than the finding asked for. |
| D3 | fixed | `#![forbid(unsafe_code)]` is on `crates/vmcell/src/naming.rs`, and the §15.2 roster is now **gated against the design that states it** rather than trusted. |
| D4 | fixed (deviation) | Taken the second way the finding offered: the stale rosters and the crosvm pass/total are **deleted**, not corrected, per AGENTS.md's pointer-over-figure rule. Both applet rosters now point at the const that cannot go stale — `README.md:14-17` and the `test-privileged` comment at `justfile:193-196`, the latter naming the embedded-roster failure it replaces — and the matrix figure is replaced by a pointer at the recipe that produces it: "No pass/total is quoted here: run the recipe, which **is** the number's source" (`README.md:298-299`). |
| D5 | fixed | The CODE fix, not the doc one: `HostCapabilities` carries the nested-virt read and `HostDeclaration::probe` derives the host axis from that one descriptor, so §7.4's sentence and §7.2's one-probe law are both true; `crates/vmcell/src/feature.rs`. |
| D6 | fixed | The code states the two-method law correctly at every site. **The design lines landed with the pass:** §9.3's annotation on `VmConfig::steward_placement` now names both, with the question each answers and where they differ — "`steward_port()` answers 'is a steward expected, and where', `resync_reachable()` answers 'may this cell snapshot/clone', and they differ exactly at `Service`" (`docs/historical/83-claude-fable-design-v33.md:2988-2994`) — and §18 delta 4's *What* line names "C8's **two** predicates" the same way (`:5389-5391`), with the `resync_reachable()` gate leg at `:5406`. |
| D7 | fixed | **The design clause landed with the pass:** §2.2 keeps the flat 5 s statement and adds "**One deliberate exception:** the snapshot RPC's budget is guest-RAM-proportional, sized by the one law `vmm::snapshot_request_timeout(mem_mib)`" — with why (a suspend image tracks guest RAM ~1:1, so a multi-GiB guest overruns the flat ceiling and is left paused over a half-written image) and the degenerate case (a zero-RAM probe instance falls back to the flat ceiling) — `docs/historical/83-claude-fable-design-v33.md:358-362`. |
| D8 | fixed | **This row's first draft said "open, owned by that document's own pass". It had already been retired in this one.** the entry (grep `RETIRED 2026-08-17`; `docs/implementation-notes.md:745` at this commit) opens "(RETIRED 2026-08-17 — the entry met its own retirement condition)": delta 7 implemented the passthrough the entry was waiting on, so what survives is a pointer — `XattrPolicy` as a per-artifact parameter of the one inject+pack tail, the default `Strip` reframed as *what pins the canonical bytes* rather than a limitation, and the renamed test named as the shipped pair `pax_xattrs_are_stripped_under_the_default_policy` / `…_preserved_under_the_preserve_policy` (`crates/vmcell/src/artifact/tar2erofs.rs:1339,1361`), including the one route where `Preserve` is refused loud rather than honored (`mkfs.ext4 -d`). The neighbour the finding asked to spot-check was checked and **stands**, with its evidence recorded beside it (grep `The neighbour below was spot-checked`): the opaque-whiteout behavior is still as described (`tar2erofs.rs:404-419`), its test still exists under its own name (`:1799`), and its retirement condition — per-layer whiteout application — has not landed. |
| D9 | fixed | **The design edits landed with the pass:** §15.4's xattr battery names the shipped pair (`docs/historical/83-claude-fable-design-v33.md:4819`) and so do §4.7's two mentions (`:1463-1464`, `:1488-1489`). The retired spelling survives in exactly one place, correctly: delta 7's *Premise* (`:5497-5499`), which records the pre-delta state and the rename — the register's own convention for a name that moved. |
| D10 | fixed | The authority is shipped and stated: `RootfsSource::root_device_read_only` is the one law, and the 0.19 → 0.20 ledger entry records the behavior and the data-plane evidence. **All three design sites landed together, and the notes entry widened to hold them:** §4.7 now pitches POSIX-completeness and says "**Not a writable one**" outright (`docs/historical/83-claude-fable-design-v33.md:1512-1521`), §4.6 scopes the read-write attach to the past (`:1418`), §5.3 states the rule for both variants and gives the honest pairings — its own tmpfs, a writable *extra* disk, a read-write share (`:1708`) — and delta 8's record says the attach was deleted (`:5539`). The widened notes entry is the one opening "**The writable-root claim lived at THREE design sites, not one**" (`docs/implementation-notes.md:4666` at this commit): it names all three sites and what each now says, which is what stops the next reissue from fixing one and leaving two. |
| D11 | partly open | **This row's first draft said there was still no example anywhere. Both front doors the finding named have one now, and so does every entry point it named except `Stage` — all compiled by G1's gate.** `README.md:29-62` is a `rust,no_run` cell (boot → exec → assert on what the guest printed → tear down), doctested through the `#[cfg(doctest)] #[doc = include_str!(…)]` item at `crates/vmcell/src/lib.rs:188-190` — the trick that stops the *front door's* example from rotting, since nothing else compiles a README. `vmcell`'s crate doc carries two: boot-and-exec (`lib.rs:21-53`) and the `Zygote` fan-out (`:60-99`). The `artifact` module carries the other two contract-surface ones: a `Pipeline` assembled from `ResolvePinsStage` + the `labelled` constructors (`crates/vmcell/src/artifact/mod.rs:20-56`) and the inject-and-pack tail driven through `PackOptions` / `XattrPolicy` / `ExtraFile` (`:69-99`). `run_battery` has one with its paired positive control (`crates/vmcell-artifact-validator/src/lib.rs:106-164`, beside `validate`'s at `:66-99`), and `DaemonClient` an upload plus two round trips (`crates/vmcell-daemon-client/src/lib.rs:15-53`) with the `ErrorKind` branch as a second (`:58-67`). **The honest residue, and all that is left of this finding:** `Stage` — the trait a consumer *implements* to extend the pipeline — carries a one-line doc and no example (`crates/vmcell/src/artifact/mod.rs:505-506`), so the one extension point with no worked shape is the one a consumer writes code against; and the examples for `Pipeline` (`:2691-2697`), `PackOptions` (`crates/vmcell/src/artifact/rootfs/mod.rs:200-209`) and `run_battery` (`crates/vmcell-artifact-validator/src/conformance.rs:585-594`) live on the enclosing module, so a reader landing on the item's own rustdoc page sees none. `docs/todo.md` carries exactly that remainder and nothing more. |

### 5. Testing coverage

| id | Status | What landed |
|---|---|---|
| T1 | fixed | `crates/vmcell/tests/metrics_limits.rs` gained the two legs the finding named to close first — a 25 % `cpu_max_pct` quota measured against `cpu.stat` (sharing "the load" with the unthrottled leg) and a `pids_max` leg asserting `pids.events max > 0` — plus the sharp one: `io_max` with a `major:minor` naming no block device must be **refused loudly**, with the same config minus the limit as the positive control. That leg records honestly that its kernel-`ENODEV` arm is dead on a default systemd user session, where `io` is not delegated. |
| T2 | partly open | Two of four closed: `console_mode` under T3, the tuning channel under G7. `ksm_mergeable` is now covered KVM-free at the composed CH payload (G6) rather than in a boot, which is what G6's own *Fix:* line asked for. Still never live-booted: both non-default `RestoreMode`s, and the `Timeouts::low_latency()` preset as such — `guest_tuning.rs` boots a non-default profile, which is what removes the unfalsifiability, not the preset. |
| T3 | fixed | `crates/vmcell/tests/nested_virt.rs` boots `ConsoleMode::VirtioConsole` and asserts on the data plane: the guest's active console is `hvc0` and a guest-written marker reaches the file, with `require_cap!` making the Firecracker skip honest and the four-backend descriptor pin beside it. |
| T4 | fixed | `crates/vmcell/tests/extra_block.rs` gained the `iops` half as a matrix leg — `IOPS_READS` direct 4 K reads against a capped disk and an uncapped baseline in the same VM — with crosvm's absent rate limiter recorded as a capability skip. |
| T5 | fixed | `snapshot_eligible` has a KVM-free unit test in `crates/vmcell-daemon/src/dto.rs` pinning it to exactly the net modes with no vhost-user device, and the daemon's refusal has its own leg in `crates/vmcell-daemon/src/registry.rs` with both positive controls. |
| T6 | fixed | `crates/vmcell/tests/vmm_confinement.rs` — a real Cloud Hypervisor process, after `apply_jail` *and* after CH's own start-up, read out of `/proc/<pid>/status`: `NoNewPrivs`, a loaded seccomp filter, the ambient set the backend needs, with a `VmmSeccomp::Disabled` boot as the red-on-inverse control. |

### 6–7. API clarity, extension points

| id | Status | What landed |
|---|---|---|
| A1 | fixed (deviation) | The cheaper half, deliberately: `Cache`'s rustdoc now says what the type is — no fields, no methods, nothing about a hit or a miss travelling through the handle, `Cache::default()` the only value worth constructing — and the parameter stays, because `Pipeline` is contract surface. Dropping it remains a ledgerable option, not a defect. |
| A2 | fixed | `vmcell-cli::ch_bin()` calls `vmcell::artifact::ch_binary_path()`, and the class is gated by the new `scripts/ban-ch-binary-resolver-copies.sh` plus its self-test — more than the finding asked for, since the review had already found this copy twice. **The design line landed with the pass:** §17's consolidation register now records the resolver as *closed in the docs/90 pass*, says plainly that it "had inventoried at two copies when there were three", names the gate and its two-directional exemption roster, and states why a parity assertion could not have replaced the scan — leaving `bench-vm`'s workspace-root ascent as the one consolidation still open (`docs/historical/83-claude-fable-design-v33.md:5155-5175`). |
| E1 | fixed | `crates/vmcell/src/proxy/doubles.rs` re-exports `hudsucker` (`:53`) and `hyper` (`:56`), so a consumer names one version, and the seam gained the worked example that is also a doctest (`doubles.rs:18-31`, building a double that names nothing but the re-exports; `the_seam_types_are_reachable_through_the_reexported_crates` is its compile-time gate). **The design line landed with the pass:** §10.4's list carries "the proxy doubles seam's `hudsucker` and `hyper` re-exports (§1.3)" with the reason a bump must be ledgered rather than discovered from a lockfile (`docs/historical/83-claude-fable-design-v33.md:3433-3437`). The larger fix (vmcell-owned request/response types) stays deferred as the finding recommended. |

### 8. The "recorded as justified rather than fixed" list

All six have been overtaken by the fix pass, so every entry should now be read as the record of a
decision rather than as a live limitation:

- **Items 1–3 kept their shipped shapes, and the lines they were holding the reasoning for have
  landed.** §10.4 names the general tail beside its erofs-only door (C1) and the two `labelled`
  constructors (C3); §17 records `validate()`'s wall-clock budget as closed by its own `run_budget`
  field (C5) — the one row whose first draft would have had a reader *undo* a correct sentence rather
  than merely re-verify a done one. The notes entries
  survive as the *why* — the ledgered-late split, the rejected thin assembler, the two-constant
  separation — which no design sentence carries.
- **Item 4** (the enumerated live-coverage gap) narrowed: T1's `cpu_max_pct` and `pids_max`, T3's
  `VirtioConsole`, T4's `iops` and T5's `snapshot_eligible` are covered now. What remains recorded is
  listed in `docs/todo.md`: both non-default `RestoreMode`s, `Timeouts::low_latency()` as a preset, and
  the `io_max` leg's kernel-refusal arm, which is dead on a host that does not delegate `io`.
- **Item 5 no longer applies.** The guest tuning-token channel is falsifiable: one `TuningToken`
  definition per token in `vmcell-protocol`, and a live leg that measures the honored cadence (G7).
- **Item 6 no longer applies as scoped.** `review-preflight-priv.sh` decides blessing freshness itself
  now, cargo-free, and maps stale onto BLOCKED-ON-BLESS (G9). The recorded *scope* of its READY verdict
  was the thing the fix changed.

### 9. What landed after this section was first written

Four lanes, all after `c34f9c2` and all uncommitted at the time of the stamp above. **Not one of them is
a finding of this review**: three are defects the review's own fixes and tests shipped, and the fourth is
a live fuzz crash. That is exactly why they are recorded here rather than in a new document — a resolution
record that stops at the pass's own findings is a record of what was *intended*, not of what the tree
does. Each lane's mechanism, trade-offs and gates are in `docs/implementation-notes.md`; these rows say
what it was and where to check it.

| Lane | What it was | Where it can be checked |
|---|---|---|
| A live `fuzz-nightly` crash on `feature_manifest` | Two bytes, `=z`, red for two consecutive scheduled runs (reproducer from Actions run 32017582821). `parse_manifest`'s `Feature::parse(key.trim())?` arm propagated a token-only refusal while its three siblings hand-attached the line number, and for an empty key that token is the empty string — so the message named neither a line nor any byte of the input, which is exactly the property the target asserts. | Two private composers plus a per-line `reject` closure, so all five arms attach the locator once, and the empty key split out as its own malformed-line arm (nothing was misspelled): `crates/vmcell/src/feature.rs:366,374,417,422`. `Feature::names_joined()` (`:157`) so two refusals cannot list two rosters. The fuzz property is now a **conjunction** over one candidate line rather than a disjunction (`fuzz/fuzz_targets/feature_manifest.rs`). Three gates in `mod manifest_locator_gates` (`:1240`): per arm, at the call sites, and on the discovered bytes. The reproducer lives in an in-crate constant driven through the target's own property rather than as a committed corpus file — this repo's `fuzz/.gitignore` scopes its `seed-*` mechanism to reachability and speed, not crash regression — recorded as the deliberate choice it is. |
| `just test-bench` could not execute what it selected | G2's own row, corrected above. Not `no_new_privs`; the double wrap, measured. | `crates/vmcell-bench/tests/common/mod.rs` (the law in the module header, four KVM-free gates), `justfile:279`, `ci.yml`'s step comment. |
| Three CI failures in tests **this pass added** | Each a defect in the test, not the product. (1) A KVM-free premise check reached the artifact getters, which *require* a built artifact, so it was green here and red in CI's artifact-free job. (2) A gate compared whole error strings that embed an allocated vmid — and *which* setup seam refuses first depends on cgroup delegation. (3) Deliberate misspelled-token fixtures collided with the `typos` gate. | (1) The artifact pair is a **parameter** of `tuned_cell_cfg` (`crates/vmcell/tests/guest_tuning.rs:113`) rather than the file's only artifact-free vacuity proof being `#[ignore]`d — that guard is the one part of the file a reviewer on a KVM-free box can check at all. (2) Classification plus the composed stage prefix, with the rosters non-vacuity-checked against the probe's own source (`crates/vmcell-artifact-validator/src/checks.rs:2418,2435,2466`). (3) A wrong **word**, not a misspelling (`examples/downstream-kernel/tests/contract.rs:74`) — which also closed a real vacuity, since the old needle was a prefix of a valid feature name inside the refusal's own roster echo, so the assertion passed whether or not the refusal named the offending token; `OTHER_BOGUS_FEATURE_TOKEN` (`:78`) now proves it does. |
| M7's and G3's and D1's own fixes, widened | The rows above carry these: M7's restructured loop left four discarding toggles and a silent tail drop; G3's scan enumerated three files past a fourth wrong answer; D1's prose reader saw two files. | `crates/vmcell/src/net/smoltcp.rs`, `crates/vmcell/tests/common/mod.rs` + `crates/vmcell/tests/rootfs_registry.rs`, `crates/vmcell/src/config.rs`. |

**The lesson the second and third lanes share, stated once in `docs/implementation-notes.md` and pointed
at from here:** this review validated only locally, and therefore recorded a green bar CI contradicted —
twice, for two unrelated reasons (the e2fsprogs version, §10's closing subsection, and the recipe plus the
three tests above). A host-facing claim owes the CI host's differences **enumerated**, not a passing local
run generalized; and a new recipe is not a gate until it has been run once, because reading its text
cannot see a failure that lives in the privilege transition it composes. Two honest qualifications, both
in the notes: only two of the three test defects were host differences at all — the `typos` collision
reddens `just ci` on this box too — and the fuzz lane is a *different* class, a premise about which inputs
a parser would ever see.

