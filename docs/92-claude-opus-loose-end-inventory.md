# Loose-end inventory — everything specified-but-unbuilt, verified against the tree

Companion to `docs/91-claude-opus-workaround-inventory.md` (what we *carry*) and to
`docs/90-claude-opus-code-review.md` (what was *wrong*). This one answers a third question:
**what did we say we would build, and never did?**

Method: seven parallel sweeps, one per register — `docs/todo.md`, design §17, the design body
outside §17, `docs/implementation-notes.md`, `docs/requirements.md`, the source tree's own
markers, and the gate roster. Every candidate then went to an independent adversarial verifier
whose default was to **refute** it, i.e. to assume it had already shipped. 199 candidates in,
142 confirmed open, 57 refuted as already-built or already-retired. The refuted ones are
**deleted, not recorded** — this project's own rule is that a stale register entry is worse than
no entry, and the docs/90 pass had one that would have reversed a correct design sentence.

Deduplicated, the 142 collapse to **66 distinct items**: the same gap is frequently named by
§17, by the design body sentence it summarizes, and by the at-site rustdoc, which is the
intended redundancy and not a finding.

Tiers below are about *what kind of work closes it*, not about value:

- **A — defects.** The tree does something wrong, or a gate cannot see something it claims to.
- **B — gate holes.** AGENTS.md rules 1–3 name a gate the roster does not carry.
- **C — specified, small, unbuilt.** The semantic is designed; nobody wrote it.
- **D — coverage.** Shipped behavior no test ever executes.
- **E — features.** A designed capability of real size.
- **F — roadmap.** Needs its own design pass before any code. Recorded, not scheduled.

A tier-F item is **not** a defect and must not be re-opened as one; §17 records each with its
blocker.

---

## Tier A — defects

| # | Item | Where | What is wrong |
|---|------|-------|---------------|
| A1 | e2fsprogs cache key never bumped with the pin it caches | `.github/workflows/ci.yml` (both jobs) | The `actions/cache` key spells the **retired** `1.47.2` and the retired digest's hex prefix against a `1.47.4` pin, so a pin bump restores the *old* build from cache. The durable half is a gate: nothing couples a cache key to the pin it keys. |
| A2 | crosvm's baked guest CID is reserved by no allocator across a restore | design §17 (crosvm item 7 — the one gap stated with a full *Owner:*/*Fix:*/*Gate:* triple) | `restore()` programs the snapshot's baked CID; the orchestrator's `CidGuard` holds a *different*, freshly allocated one. Once the ancestor is gone the baked CID is free for reallocation, and crosvm's vsock is in-kernel — a host-global identity. A later VM can collide with the live restored one. Half the fix already ships (`VmInstance::guest_cid()` reports the adopted CID); the reservation is what is missing. |
| A3 | No backend's `restore()` runs the USB precheck its `create()` runs | `docs/implementation-notes.md` "Still open after these two waves" | CH/FC/crosvm silently drop host-USB devices on restore instead of refusing. Note the trap: `reject_usb_host_devices` only fires when the capability is false, and QEMU's is **true** — so copying `create()`'s precheck is a no-op on the one backend that actually splices the argv. Two-part fix. |
| A4 | `tar2erofs` has no refusal for an internal file-vs-symlink clobber | `docs/implementation-notes.md` "Still open — deliberately not fixed here" | Reachable from the shipped injection manifest, not merely "a manifest edit away": the manifest writes the multicall binary as a **file** and one **symlink** per roster entry into the same directory, and since v33 delta 6 that roster is registry data. |
| A5 | The mmdebstrap rootfs source leaves a prior OCI build's stale `rootfs.features` sidecar | `docs/implementation-notes.md` "Recorded gaps" | No `clear_feature_declaration` counterpart to `artifact::kernel::clear_resolved_config`; republishing at the same path leaves the previous source's feature declaration in place to be read as this image's. |
| A6 | Both orphan sweeps are liveness-blind | `docs/implementation-notes.md` | A same-prefix sibling's live resources are reapable. |
| A7 | `Session::write_stdin`/`close_stdin`/`resize`/`close` return `Ok(())` after the reader closed the registry | design §17 (Sessions) | They observe only the writer channel, which dies one transport failure later; their rustdoc promises `Error::Steward`. A no-op write, not a hang — but the docs are wrong for a window. |
| A8 | `mini-init`'s restart loop has no pacing on the exit path | `docs/implementation-notes.md` | A service that exits immediately spins. |
| A9 | `TUNSETIFF` silently adopts a stale unattached tap | `docs/implementation-notes.md` (recorded open at the tun-tap port) | `IFF_TUN_EXCL` is the one-flag fix, but it also makes re-adopting *our own* stale tap fail, so it belongs with a sweep that reclaims it. |
| A10 | Design §5.4/§5.6 still assert `validate()` has no overall wall-clock budget | `docs/implementation-notes.md` | The field shipped (`ValidationOptions::run_budget`); two body sentences outside §17 were not folded. |

## Tier B — gate holes

| # | Item | Rule it serves |
|---|------|----------------|
| B1 | No class-wide ban for a bare `let _ =` on a `Result` | AGENTS "Fail loud" — nothing in the tree can go red on the class; 259 `let _ =` sites, and the `checks.rs` residue is only the named part. |
| B2 | No gate for the **orphan-recipe** class | `ban-ci-script-handcopy.sh` ARM 4 covers orphan *scripts* in both directions; the same argument one level up (a recipe nothing invokes) has no gate. |
| B3 | `with-delegated-scope.sh` has no red-on-inverse self-test | It is the sole entry of the ban script's exemption allowlist, has **four** warn-and-continue arms (`set -euo pipefail` is inert on all four, each being `if !`-guarded) and three invocation sites. AGENTS rule 2. |
| B4 | The `example-downstream` CI job hand-copies its steps instead of calling a recipe | AGENTS rule 3 — "a CI step that hand-copies a `just` recipe drifts from it". There is no recipe to call. |
| B5 | `cargo-semver-checks` is PR-only while every non-dependabot change lands as a direct push to `main` | It has never run against a change to vmcell's own public API. The contract-surface gate is structurally unable to fire on the path changes actually take. |
| B6 | `test-unit-undelegated` has no caller and no vacuity guard | Its premise — a non-user-writable bind source — is asserted nowhere, so a writable `/srv` yields a green run that reads as "the undelegated condition passes". The repo's own zero-file-scan doctrine, one level out. |
| B7 | `scripts/git-pre-commit` has no installer recipe and nothing checks it is installed | It falls outside ARM 4's `{ban,check,test}-*.sh` glob silently rather than by exemption. |
| B8 | CI unconditionally pays a second release build + `setcap` for a runner half only the hand-run bench workflow uses | Not dead (`run-bench.sh`/`perf-matrix.sh` use it) — but unconditional cost with no CI consumer. |

## Tier C — specified, small, unbuilt

`Stage` has no worked rustdoc example (the one contract-surface item a consumer *implements*).
Contract-surface examples live on the enclosing module and are not intra-doc-linked from the
items themselves. README has no benchmark section at all — not even the pointer-plus-shape the
`todo` entry itself prescribes. `ValidationOptions` has no backend knob, so `validate()`
hardcodes Cloud Hypervisor although every check is generic over `Vmm`. `bench-vm` hand-rolls the
library's workspace-root ascent — the **last** open "one law, one predicate" consolidation, which
needs a `vmcell`-side `pub` export before it can be collapsed. The two ext4-answer scans await
consolidation. The `#[cfg(not(feature = "am-fs-erofs"))]` pack arm refuses with a stringly
`Error::Artifact` where the feature-gate law calls for a typed `CapabilityUnavailable`. The
deprecated unpaced `VirtioFsDaemon::start` shims are past their recorded delete-at-next-bump date.
`virtiofsd` and `debian_snapshot_timestamp` are parser-recognized pins that `pins.json` does not
commit. The guest `exec` capture has no host-side size ceiling. `Egress::Open` needs either real
re-origination or the typed refusal §6.2 names as the alternative. README's external-tool list
omits tools the production code and suites actually spawn.

## Tier D — shipped behavior no test executes

Both non-default `RestoreMode`s (`Eager`/`Lazy`) — no restore is ever performed under either.
`Timeouts::low_latency()` as a preset — its values are unit-asserted, never booted.
`io_max` is never observed actually throttling. USB passthrough and the systemd proof cell record
capability skips on this host rather than running, although the facilities are present
(a free camera at `0bda:5634`, and the proof cell's opt-in recipe). Nested virtualization is
validated by opening `/dev/kvm` in the L1 guest; no L2 guest is ever booted.

## Tier E — designed features of real size

Daemon: pause/resume routes (the handle half ships, the routes do not), streaming artifact upload
(v1 reads the whole file into memory), copy-on-attach writable scratch disks, artifact GC/quota,
a UDS transport under `XDG_RUNTIME_DIR`, segments and the raw dial over REST, and a periodic
orphan sweeper (start-up-only today). Networking: per-VM byte counters (needs a netns-scoped
usage type), privileged-path `host_services` wiring, second-octet expansion past the ≈254-VM-per-`/16`
ceiling, a typed netem/impairment API (today: stable names plus the harness's own `tc`), and full
MITM on the transparent raw-80/443 path. Guest/host: PTY `StdinEof` half-close, daemon-side
session streaming, a raw-mode interactive CLI with `SIGWINCH` forwarding, proxy snapshot-and-replay
cassettes, deterministic clock control over vsock, post-restore secrets injection, a generic
vsock↔TCP forwarder, and oops/KASAN/lockdep → typed `vmcell::Error` (the boolean panic detector and
the validator's `classify` are the shipped halves). Storage: `fuse-backend-rs` read-only enforcement,
which is what blocks `experiment-fuse` graduating.

Validation work with the hardware present but the flags still honest-false: crosvm `virtio_fs_shares`,
crosvm unprivileged vhost-user-net, crosvm vsock privilege in the unprivileged mode, and the Layer-2
seccomp deny-list default-on (per-backend live validation is its stated precondition).

**The smoltcp NAT bring-up flake** sits alone: ~10% of networked boots, real, and its mechanism is
**open** — the previously recorded mechanism was falsified and withdrawn, and AGENTS.md's rule
governs ("environmental" is a hypothesis, not a diagnosis). What a diagnosis must explain is why a
socket bound before `start()` returns is not connectable within 2 s.

## Tier F — roadmap, needs design first

UFFD/demand-paged `lazy_restore` on any backend. The thin broker + fd-passing (and the
`clear_ambient_caps` default-on and jailer chroot/uid-drop increments that are blocked behind it).
A CH `--net fd=` variant. `clone3(CLONE_INTO_CGROUP)`. Per-share virtiofsd service-uid allocator.
crosvm concurrent zygote fan-out (needs a crosvm that accepts a rotated `--vsock cid=` on restore).
A warm-pool manager. JWT bearer tokens + per-key scopes. A non-reflink `OverlayStore`; a
lineage-aware sweep; a sparse-snapshot `SEEK_HOLE` density lever; daemon fork/branch verbs over REST.
Per-segment filtered egress. Hardware-profile matrix (CPUID masking + aarch64). In-VM filesystem
checkpoint/rollback. gdbstub + crash-dump capture. Scale-to-zero lifecycle. kcov/gcov extraction.
Observability (OTLP + per-step quotas + a typed event stream). Live tag→digest pin resolution.
Declarative per-sandbox egress policy + connection audit. QEMU `blkdebug` disk error injection.
The `io_max` refusal leg's kernel-`ENODEV` arm, which is dead on any host whose systemd user
session delegates `cpu memory pids` and not `io`.

---

## What this pass closed

Recorded per item in `docs/implementation-notes.md`. Tiers A, B, C and D are the pass's scope;
E and F are recorded here and left on the register, each with its blocker, which is what
distinguishes a scheduled cut from a forgotten one.

**Wave 1 — Tier A defects, all six with their gates:** A2 (the crosvm baked CID, whose §17 entry is
rewritten as closed and whose live leg was proven red under a real crosvm at baked 4 / fresh 3), A3
(the restore-side USB law, two arms because copying `create()`'s precheck is a no-op on the one
backend that splices the argv), A4 (the tar2erofs kind-clobber refusal), A5
(`clear_feature_declaration`, at the one inject+pack tail rather than in the mmdebstrap arm, so it
covers every source), A7 (the session closed-flag — the registry `Option` that already existed, not
a second flag), A8 (mini-init pacing, through the predicate that already owned the rapid-failure cap).

**Wave 1 — Tier B gate holes:** A1/B-class (the e2fsprogs cache key, now interpolated and held by
arm 8), B4 (`just example-downstream`), B5 (semver-checks on push — it had never once run against a
change to vmcell's own public API), B6 (`test-unit-undelegated`'s vacuity guard), B2
(`ban-orphan-recipe.sh` + self-test), B3 (`test-with-delegated-scope.sh`, which surfaced an
unguarded `mkdir` that aborted where its four siblings degrade), B7 (`just install-hooks`).

Still open from Tier B: **B8**, the release-half runner CI builds and `setcap`s unconditionally for
a consumer only the hand-run bench workflow has. It is a cost, not a defect, and is left deliberate.
