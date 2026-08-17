# vmcell — Automated quality gates (v5)

Deployable contents for every automatable gate in `docs/84-claude-fable-code-review-rubric-v7.md`
(rubric v7, Parts D/E — issued in the same pass as this revision and as design v33). v5 supersedes
v4 (`docs/76`, reissued to `docs/historical/`), reconciled against the **as-built v4 landing** (the
v30 delta gates, the docs/78 + docs/81 fix waves, the CI-repair pass — every shape v4 specified as
"to add" that has since landed is baseline here, cited by its `docs/implementation-notes.md`
record, not restated) and against **design v33** with its ten-delta §18 register (the serial-nexus
consumer-platform pass: the steward rename, the feature intersection, the two-directional
conformance kit, steward placement + service mode, the artifact registry, xattr policy, the ext4
producer, the systemd proof cell, daemon placement). Sections are one of two kinds: **full
contents** for files this doc owns, or **delta** for repo-owned files, giving only the lines to add
in the repo's established idiom. Repo-established names win, unchanged from v1's rule. **No
standing errata.**

New in v5: the **landed-baseline reconciliation** (v4's directed gates are now the tree's — the one
`gates` recipe, the meta-gate, the extracted `check-*` predicates, the hosted-runner facts, the
15-target fuzz roster); the crate roster follows the **steward rename** (v33 delta 1); and the
**v33 delta-pass gates** table — each delta's KVM-free gate contents, landing with the change that
implements it, exactly as the v30 table did.

---

## The landed baseline (v4's directed shapes, now the tree's — cite, don't re-specify)

Everything below is **as built at `vmcell` 0.14 / validator 0.2** and is the floor v5 builds on. A
review or an implementation that re-derives one of these re-litigates a landed decision; the
per-shape record is in `docs/implementation-notes.md` (the docs/78 fix waves, the CI-repair pass,
and the docs/81 fix waves sections):

- **One `gates` recipe** carries every ban/check script + red-on-inverse self-test + the
  `shellcheck` sweep; both `just ci` and `ci.yml` invoke it (`run: just gates`), and
  `scripts/ban-ci-script-handcopy.sh` is the **meta-gate that runs first**: it fails if `ci.yml`
  names a `scripts/*.sh` directly and asserts the recipe's roster equals the gate-shaped scripts on
  disk in **both** directions (orphan script *and* stale entry). A new gate script is added to that
  recipe and nowhere else.
- The current roster, in recipe order: `ban-ci-script-handcopy`, `check-agents-md-sync`
  (AGENTS.md ≡ the newest non-historical `docs/*claude-agents*.md`, byte-equal),
  `check-vendored-vhost`, `check-lean-tree --all` (the one lean predicate, `--color never` inside
  it — the `CARGO_TERM_COLOR: always` class that silently disarmed six inline copies),
  `check-broker-lean` (absent / present / cargo-could-not-answer three-way split with its axum
  positive control), `ban-global-state`, `ban-legacy-terms` (file-count-reporting roster — the
  docs/81 M13 fix), `ban-agent-ip-shellout`, `ban-artifact-path-join`, `ban-inline-setns`,
  `ban-kernel-key-composers`, `ban-readiness-timeout-literal`, `ban-test-support-in-production`,
  `ban-uncolored-cargo-parse` (the class gate for cargo-output parsing), `test-review-preflight-priv`,
  then `shellcheck scripts/*.sh scripts/git-pre-commit examples/downstream-kernel/*.sh` — each
  `ban-*`/`check-*` paired with its `test-*` twin.
- **CI runs on GitHub-hosted runners**; `test-integration` is `ubuntu-24.04`, widens
  `/dev/kvm`/`/dev/vhost-*` with a udev rule whose written file is also the roster its assertion
  reads back, and wraps **every** live suite in a delegated scope. `fuzz.yml` forces
  `RUSTUP_TOOLCHAIN: nightly` (the toolchain **file** outranks `rustup default`), asserts
  nightly-ness up front, and holds a target-count + roster guard (GUARD 5) so an empty `cargo fuzz
  list` cannot read as green.
- **`fuzz/` carries 15 targets** with the roster law (`[[bin]]` stanzas ≡ `fuzz_targets/*.rs` ≡
  `cargo fuzz list`, asserted by fuzz.yml) and `vmcell`'s non-default `fuzzing` feature exposes the
  three fuzz-only entry points. `test-support` is likewise non-default;
  `ban-test-support-in-production.sh` is the backstop against feature unification leaking fixtures
  into production builds.
- `HostEnv::hermetic()` is `#[cfg(not(test))]` with `for_unit_tests()` for in-crate units;
  `just test-unit-undelegated` mirrors the hosted runner's undelegated-cgroup condition locally.
  The CA generate-or-load holds the cross-process `.ca.lock`. `cargo semver-checks` covers **both**
  contract crates with `fetch-depth: 0` on the PR job.

---

## Crate-root lint preambles — roster

The two sanctioned preamble variants are unchanged (the repo's crate roots are the landed source of
truth). What v5 changes is one **row**, bound to v33 delta 1:

| Crate | Class | Notes |
|---|---|---|
| `vmcell` | full family | the host library; `feature.rs` (v33 §7.4) joins the `#![forbid(unsafe_code)]` pure-module set |
| `vmcell-protocol` | full family **+ wire casts** | wire crate; gains `STEWARD_VSOCK_PORT` (v33 delta 4) |
| `vmcell-firecracker`, `vmcell-qemu`, `vmcell-crosvm` | full family | unchanged |
| `vmcell-artifact-validator` | full family | contract surface; `CheckStatus` grows `Warn`/`Unverified` (v33 delta 3, ledgered bump) |
| `vmcell-rootfs-builder`, `vmcell-kernel-builder` | full family | unchanged |
| `vmcell-privilege` | full family | unchanged |
| `vmcell-steward` | full family **+ wire casts** | `v5:` **renamed from `vmcell-guest-agent` by v33 delta 1** — the row binds when the rename lands; until then the crate keeps its old name. PID-1 rationale unchanged (a panic aborts the guest under the `Pid1` placement); the R5 library split must keep the full deny family on the library target too, since the whole steward now lives there |
| `vmcell-daemon`, `vmcell-daemon-client`, `vmcell-broker`, `vmcelld` | full family | unchanged |
| `vmcell-cli`, `vmcell-guest-tools`, `vmcell-test-runner`, `vmcelld-ctl` | print-by-contract | unchanged; guest-tools gains the `xattr` + `mini-init` applets (v33 deltas 7, 5) under the same class |
| `vmcell-bench` (`bench-vm`) | print-by-contract | landed per v4 |

`clippy.toml`, `deny.toml`, the workspace `Cargo.toml`/`rust-toolchain.toml` MSRV single-sourcing,
and `.config/nextest.toml` (the integration-profile serial-host glob, the 0.9.85 pin, the scoped
retry stanza): **delta: none** — the landed files stand. v33 adds no linked dependency that touches
`deny.toml` (`mkfs.ext4`, if the delta-8 fallback route is taken, is a spawned external binary —
the QEMU/nft carve-out shape; a permissive pure-Rust ext4 writer, the preferred route, enters
through the ordinary allow-list like any crate).

---

## `scripts/ban-legacy-terms.sh` — delta: the steward-rename identifiers (v33 delta 1)

The landed scanner (file-count roster, per-line `allow-legacy-term:` exemptions, comment-stripping,
`crates/` + `justfile` default scope with `scripts/`/`docs/` deliberately excluded) stands. Delta 1
extends the awk pattern block with the retired **identifiers** — never the bare word "agent":

```awk
       || code ~ /vmcell[_-]guest[_-]agent/ \
       || code ~ /AgentClient|AgentPlacement|AgentOptions|GuestAgentStage/ \
       || code ~ /Error::Agent([^A-Za-z0-9_]|$)/ \
       || code ~ /AGENT_VSOCK_PORT/ \
       || code ~ /guest_agent_(src_hash|closure_hash)/ \
       || code ~ /boot\.agent_ready|agent\.exec_roundtrip/ \
       || code ~ /--agent-musl|agent[_-]musl/ \
```

Scoping rationale, recorded in the header alongside the imp-testing block's: the ban is
**identifier-shaped** because "agent" legitimately survives as the *domain* word — the
agentic-execution prose in design §1.1, the `AGENTS.md` repo-convention file (which the default
roster never scans, but the header says so anyway), historical finding IDs (`AGENT-2`), and
external names (Kata's `agent-ctl`). A bare-word ban would redden the tree on its own charter.

Self-test delta (`test-ban-legacy-terms.sh`): **one MUST-flag fixture per new pattern line**
(`vmcell-guest-agent`, `AgentClient`, `Error::Agent`, `AGENT_VSOCK_PORT`, `GuestAgentStage`,
`boot.agent_ready`, `--agent-musl`, `guest_agent_src_hash`) — the meta-rule: deleting a scanner
branch must redden a fixture — plus MUST-PASS fixtures for the kept words: a line containing
`AGENTS.md`, a line containing `agentic execution`, a line containing `AGENT-2`, a line containing
`agent-ctl`, and an `// allow-legacy-term:` exemplar. The gate lands **with** delta 1, and the
rename pass itself must leave the default scan green — which is the rename's own completeness
check.

---

## Call-site scans are Rust source-scan tests, not shell scripts

v33's C8 and F6 laws each require a **call-site** gate ("a gate on the extracted predicate is not a
gate on the claim" — the completeness-audit convention, now in the §18 register). These land as
`include_str!`/scan **unit tests inside the owning crates** — the shipped precedent is
`vmcell-qemu`'s `virtiofs_pacing_gate` and crosvm's launch-plan scan — not as `scripts/*.sh`
entries, so **the `gates` recipe roster does not grow for them** and `ban-ci-script-handcopy.sh`'s
both-direction roster assertion is untouched:

- **C8 (delta 4):** a scan over `orchestrator.rs` + `config.rs` asserting the exact production
  call sites of **both** C8 methods — `steward_port()` (the health gate, `steward()`,
  `connect_sessions()`) and `resync_reachable()` (`snapshot()`'s guard, the eligibility
  predicate's placement arm; an eligibility site reading `steward_port()` is the violation the
  design's own review caught) — and **zero** production reads of
  `cfg.init` outside the cmdline builder / `validate_init_path` / the reserved-key set.
- **F6 (delta 2):** the intersection-site scan (exactly one computation site) plus the sweep test
  asserting no production refusal site composes a feature string by hand (red on re-introducing
  one).

---

## `justfile` — delta: the `test-systemd` opt-in recipe (v33 delta 9)

Staged exactly like `test-crosvm`/`test-usb-passthrough` (opt-in because it pulls a full-Debian
image; its KVM-free halves run under the ordinary unit gates). The recipe is the capstone gate over
deltas 4–7 and is **deliberately reddened once at landing** (drop the steward unit file; the
fail-loud must name the placement):

```bash
# v33 delta 9: the systemd proof cell — the capstone over placement (4), the service steward (5),
# the registry (6), and xattr policy (7). Opt-in: it pulls the digest-registered `debian-systemd`
# image (a full Debian, ~50 MB), so it stays out of test-privileged the way test-crosvm does.
# Boots real systemd as PID 1 with the steward as a unit under StewardPlacement::Service, drives
# the control plane end-to-end, and runs the §10.6 conformance kit over the composition.
test-systemd:
    VMCELL_SKIP_MANIFEST="${VMCELL_SKIP_MANIFEST:-{{skip-manifest}}}" \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="{{justfile_directory()}}/{{runner}}" \
        cargo nextest run --locked --profile integration -p vmcell --run-ignored all \
        --no-tests=fail -E 'kind(test) & test(systemd_cell)'
```

(The H-TEST-3 skip-manifest export and `--no-tests=fail` follow every sibling suite recipe; the
delegated-scope wrapper is applied at the call site as `ci.yml` does for the other live suites.)
Delta 6 also changes `build-kernels` to selection-driven with `--all` preserving the eager roster —
the CI nightly matrix and the `test-usb-passthrough` comment's `build-kernels` invocation gain
`--all` **in the same commit**, per the design's migration note.

---

## `fuzz/` — delta: two targets for the new strict parsers (v33 deltas 2, 6)

v33 adds two strict, consumer-reachable parse surfaces, and each gets a `[[bin]]` target under the
existing roster law (fuzz.yml GUARD 5 picks them up automatically; the budget arithmetic at GUARD 6
is re-read before landing, per the workflow's own header):

```toml
# fuzz/Cargo.toml — additions (each with its fuzz_targets/<name>.rs twin, per the roster law)

# v33 §7.4: the feature-manifest sidecar's strict parser — unknown tokens must be hard
# errors, never silent absences (F6)
[[bin]]
name = "feature_manifest"

# v33 §10.5: the rootfs/handlers registry-entry parser, incl. the legacy-singleton-shape
# reject and the digest-format check
[[bin]]
name = "registry_entry"
```

The `xattr` and `mini-init` applets parse only argv inside the guest and add **no** host-reachable
decode surface (the guest-tools posture is unchanged — argv comes from the host's own exec
requests); no target. The daemon's delta-10 DTO fields ride the existing `daemon_create_vm_dto`
target, which must gain the new fields' arbitrary coverage when they land.

---

## Gates that land with the v33 delta pass

Per design v33 §18 (each delta ships with its named gate; KVM-free halves here, the live legs in
§3.5/§4.7/§10.5/§10.6/§15.4's battery paragraphs):

| Delta | KVM-free gate contents |
|---|---|
| 1 — steward rename | the extended `ban-legacy-terms.sh` fixture battery (above); every existing suite green under the new names; the check-id renames ledgered in the validator's `Cargo.toml` |
| 2 — feature vocabulary | the two-sided provenance pair (same artifact, two backends — the removal names the rootfs on one, the backend on the other); misspelled-token hard error naming the token; `require()` pre-boot typed refusal; the F6 intersection-site scan + no-hand-spelled-feature-string sweep (red on re-introducing one) |
| 3 — two-directional kit | `CheckStatus` `Warn`/`Unverified` arms with `into_result()`'s Fail-only contract pinned; the four-leg present/absent × capable/incapable matrix per decidable feature; the paired-id positive-control gate (deleting the control reddens the roster); `battery_budget` wall-clock test (a stalled fake check trips typed, never hangs); the rustdoc roster gates extended to Core/Extended via the records-or-skips-on-every-path refactor, red-on-inverse on all three levels |
| 4 — steward placement | the `Service{5000}`+`init: None` composition leg (placement end-to-end, `Service` not taking the fail-loud arm, the health gate ran); the **discriminating** `Service`+custom-`init` refusal-identity leg (transport timeout, never the placement refusal — the arm that reddens on the `cfg.init` re-key); the `Service`-cell `snapshot()` typed refusal (`resync_reachable()`); the `None` typed-refusal-before-transport leg; the byte-identical default-cmdline pin; the C8 two-method call-site scan; `dial_vsock`'s existing gate green verbatim |
| 5 — service steward | the subreaper double-fork leg red-on-inverse (remove `PR_SET_CHILD_SUBREAPER` → the exec hangs into its harness timeout); both SIGTERM twins (service: C3 residue gone, clean exit, mini-init **restarts** it, guest survives, next exec works; Pid1: powers off) + the rapid-failure-cap leg; `check-lean-tree` surviving the library split; the thin-`main.rs` source-scan pin (red on a planted stray `fn`); the reservation/epoch unit suite green unmoved; the `GUEST_TOOLS_APPLETS`/manifest pins growing `mini-init` together |
| 6 — artifact registry | same-digest-two-labels byte-identity + the default cache key unmoved (the empty-change gate); the laziness leg red on eager; corrupt-one-byte-of-the-cached-blob → loud digest-mismatch failure (F7 — a stored-but-unchecked digest has passing output identical to not running); bundle-refuses-unpinned; the legacy-singleton-shape reject naming the migration; the handler-roster manifest pin's labelled arm |
| 7 — repack + xattr | `test_pax_xattrs_are_not_preserved` green for `Strip` **plus** its `Preserve` twin (the fixture xattr survives); the pack-twice byte-determinism gate (new — the doc's determinism claim finally has a gate); cache-key invalidation on policy change; the derived-`XattrPreserved` contradictory-pair reject (an explicit `xattr_preserved` token in a vmcell-built entry errors naming the derivation); the outside-a-checkout pack green with `--tools`, red-loud without naming `vmcell-guest-tools`; the `--inject`-style parser tests for `--tools`/`--work-dir` |
| 8 — ext4 producer (separable) | the version-probe typed refusal (e2fsprogs < 1.47.1 or no libarchive → classified error, never a silent mis-build); the parent-dirs-present pin; the mount-and-diff battery is the live leg and doubles as the crate-route qualifier |
| 9 — systemd proof cell | the recipe itself (above), reddened once deliberately at landing; its KVM-free halves are deltas 2–7's gates |
| 10 — daemon placement (separable) | the asymmetric-`Some`/`None` JSON round-trip (the presence-attribute codec rule's named test); `StewardPlacement::None` rejected 400 with the `Service` positive control; `daemon_create_vm_dto` fuzz coverage of the new fields |

---

## One-time reconciliations directed with this revision

Not gates — stale artifacts the v33 research verified are still in the tree, fixed once alongside
the doc landing:

1. `crates/vmcell-qemu/src/lib.rs` — **two comment sites still assert the withdrawn lazy-bind
   mechanism** (the `SMOLTCP_SOCKET_READY_TIMEOUT_MS` rustdoc: "the orchestrator's smoltcp NAT
   binds this UDS lazily from a background *thread*"; the `-chardev` composer comment: "must not
   race smoltcp's lazy bind"). Design §17 withdrew that mechanism (`Listener::new` *is* the bind,
   synchronous, before the worker spawns); the docs/81 fix-wave notes recorded these two sites as
   still stale, and they still are at HEAD `77a3868`. The ceiling both justify is right for the
   independent stated reason (a thread has no child exit to fail fast on); only the "lazily"
   clauses go.
2. The guest steward's core-mount comment (`main.rs` ~172–176, ~235–236) claims the fatal set is
   "EXACTLY {overlay, /proc, /dev}" while the code makes **four** mounts fatal (tmpfs `/mnt`
   included) — design v33 §3.4 now states four; the comment is corrected by delta 5's split (its
   premise block records this), listed here so a doc-only pass can take it earlier.

---

## Coverage map

Rubric Part D/E row → where it is enforced. Rows tagged `review`/`test` (fake fidelity, assertion
quality, suppression scope, the live batteries) stay with the reviewer and the suite. v30's rows
are landed baseline (first table above); the v33 rows:

| Rubric gate | Enforced by |
|---|---|
| Delta 1: no retired steward identifiers | `ban-legacy-terms.sh` + fixture battery (in `gates`) |
| C8: one placement predicate, call-sites bound | the `orchestrator.rs`/`config.rs` source-scan test (in-crate) |
| F6: one intersection site; unknown features are errors | the scan + misspelled-token tests (in-crate); `feature_manifest` fuzz target |
| F7: registrations are digests, verified | the corrupt-blob + bundle-refuses-unpinned tests; `registry_entry` fuzz target |
| The v33 batteries (placement, service-steward, feature, conformance, registry, xattr, ext4) | suite tests per §15.4; live legs under the existing suite recipes |
| The systemd proof cell | `just test-systemd` (opt-in; CI-documented like `test-crosvm`) |
| Kit budget: fails loudly per battery | the `battery_budget` wall-clock test (validator crate) |
| Daemon placement DTO honesty | JSON round-trip + 400 tests (daemon crate); `daemon_create_vm_dto` fuzz |
| Local ≡ CI for every new gate | the one `gates` recipe + `ban-ci-script-handcopy.sh` (unchanged — no new shell gates in this pass) |

Everything else in the v4 coverage map stands as landed.
