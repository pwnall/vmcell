# vmcell — Automated quality gates (v4)

Deployable contents for every automatable gate in `docs/75-claude-fable-code-review-rubric-v6.md`
(rubric v6, Parts D/E). v4 supersedes v3 (`docs/historical/70-claude-fable-automated-quality-v3.md`),
reconciled against the **as-built v3 landing** (the four justified gate corrections recorded in
`docs/implementation-notes.md`, "Automated quality gates (docs/70 v3)", are folded in here as the
authoritative shapes) and against **design v30** (`docs/74-claude-fable-design-v30.md`) with its
nine-delta register. Sections are one of two kinds: **full contents** for files this doc owns, or
**delta** for repo-owned files, giving only the lines to add in the repo's established idiom
(monolithic `ci` recipe, step-mirrored `ci.yml`, per the docs/historical/54 implementation report
§4.3). Repo-established names win,
unchanged from v1's rule. (Version-series note: this "v4" is unrelated to the retired
`docs/historical/56` "automated-quality-v4" of the pre-reset series — the doc number
disambiguates.)

New in v4: the crate roster gains the five post-v3 members (the three extracted backends,
`vmcell-artifact-validator`, `vmcell-bench`); the four v3 gate corrections become the specified
shapes (the P3 ban's daemon-scoped bare-identifier pattern with `name.rs` as the sanctioned home;
the broker assertion as `axum` + `vmcell-daemon` — **not** `hyper`; the `broker_frame` fuzz target
over `postcard::from_bytes::<BrokerRequest>`; the `if/then/exit` idiom for negated tree greps under
`set -e`); and the **v30 delta-pass gates** land with the changes that implement them (the pins
overlay battery, the downstream vendor-assertion script, the example-workspace CI job, the
semver-checks extension to the validator crate, the segment/dial/injection batteries' KVM-free
halves, and the opt-in USB recipe). **No standing errata**: v30 folded the two v3-era design errata
into the design body (§9.7 MSRV, §15.2 broker leanness), so this doc now cites the design instead
of overriding it.

---

## Crate-root lint preambles — full

Every crate root, in the two sanctioned variants the docs/historical/54 report §3.2 rolled out (the full-family and
wire-cast blocks are unchanged from v3 — see `docs/historical/70` for the verbatim listing; the
repo's crate roots are the landed source of truth). What v4 changes is the **roster**:

| Crate | Class | Notes |
|---|---|---|
| `vmcell` | full family | the host library |
| `vmcell-protocol` | full family **+ wire casts** | wire crate |
| `vmcell-firecracker`, `vmcell-qemu`, `vmcell-crosvm` | full family | `v4:` extracted secondary backends — libraries, same bar as `vmcell` |
| `vmcell-artifact-validator` | full family | `v4:` downstream **contract surface** (rubric B15) — `missing_docs` here is a contract obligation, not hygiene |
| `vmcell-rootfs-builder`, `vmcell-kernel-builder` | full family | `Stage` impls |
| `vmcell-privilege` | full family | lean security predicates |
| `vmcell-guest-agent` | full family **+ wire casts** | PID-1 — `unwrap_used`/`panic` are load-bearing (a panic aborts the guest) |
| `vmcell-daemon`, `vmcell-daemon-client`, `vmcell-broker`, `vmcelld` | full family | daemon tier + cap-holder; `tracing`, never stdout |
| `vmcell-cli`, `vmcell-guest-tools`, `vmcell-test-runner`, `vmcelld-ctl` | print-by-contract | drop the two `print_*` denies, rationale in the crate doc |
| `vmcell-bench` (`bench-vm`) | print-by-contract | `v4: TO ADD` — the bin currently carries **no preamble at all** (verified); land the print-by-contract block (the `vmcell-cli` shape) with this doc so "crate roots are the landed source of truth" holds |

The wire-crate cast lints stay `#[cfg_attr(not(test), deny(...))]`-scoped — the recorded v3-era
deviation (B10 is a production decode-surface rule; test byte-vector construction carries no wire
risk) stands. Per-module `#![forbid(unsafe_code)]` on the I/O-free modules per design §9.2; the
suppression policy (statement-scope `#[expect]` with mandatory reasons, `cfg_attr` for
config-conditional lints, one helper per repeated legitimate site) is unchanged (rubric B11).

---

## `clippy.toml` — delta: none (optional citation)

The landed file stands (msrv 1.96.1, the tests-may-unwrap toggles, the `DefaultHasher`/`RandomState`
disallowed-types, the `set_var`/`process::exit` disallowed-methods, the deliberate `temp_dir`
non-ban) — and, unlike the v3 doc's sketch, the landed `msrv` comment never carried the "supersedes
§9.7" erratum clause, so there is nothing to delete. Optional on the next touch: cite the design as
the canonical statement —

```toml
# Declared MSRV = the tested floor (1.96.1); single-sourced with rust-toolchain.toml and
# [workspace.package] rust-version, sync-asserted in `ci`. An UNDERSTATED rust-version re-resolves
# older consumers onto vulnerable dep versions (the time 0.3.45 / RUSTSEC-2026-0009 class).
# Design v30 §9.7 is the canonical statement.
msrv = "1.96.1"
```

---

## `deny.toml` — delta: none

The landed `[bans]` block stands verbatim — **six named denies**: the five libseccomp-linked
crates (`libseccomp`, `libseccomp-sys`, `seccomp-sys`, `seccomp`, `syscallz` — their LGPL-2.1 C
link is invisible to the license scan, design §12.5, rubric B13) plus the `birdcage`
alternative-sandbox ban (so `seccompiler` stays the single sanctioned sandbox dependency). crosvm adds
**nothing** here by design: it is a spawned external binary, never a linked crate — the same
carve-out as the QEMU binary. Do not add crosvm as a crate dependency.

---

## `Cargo.toml` (workspace root) / `rust-toolchain.toml` — delta: none

The single-source MSRV (1.96.1 in `[workspace.package] rust-version`, mirrored by
`rust-toolchain.toml`, sync-asserted in `ci`) stands; every member — the backends, validator, and
bench crates included — carries `rust-version.workspace = true`. One stale comment to fix on the
next touch (a one-time reconciliation, below): `crates/vmcell/Cargo.toml:225` still says
"alongside rtnetlink 0.14" — the dep is 0.21.

---

## `.config/nextest.toml` — delta: none (v3's selector landed, on the right profile)

The workspace-glob serial-host selector landed **as an override on `profile.integration`** (the
profile the VM suites actually run under), not `profile.default` as the v3 sketch showed — the
as-built placement is correct and is the specified shape:

```toml
[[profile.integration.overrides]]
filter = 'package(~vmcell) & kind(test) & !binary(proptests)'
test-group = 'serial-host'
```

The `nextest-version = "0.9.85"` pin (zero-selected-tests fails) and the VM-scoped retry stanza
with its honest "environmental backstop, not a diagnosis" comment stand.

---

## `scripts/ban-artifact-path-join.sh` — the as-built shape is the specification

The v3 sketch was corrected at landing (recorded in the implementation notes); v4 specifies the
**landed** shape, which is authoritative:

- **Scope: the daemon crate only** (`crates/vmcell-daemon/src`). P3 is about *client-supplied*
  names; scanning the whole workspace produced 17 hits, all legitimate internal joins.
- **Sanctioned home: `name.rs`** (where `resolve_artifact_path` actually lives), exempted by
  basename — not the v3 sketch's `artifact_store.rs`.
- **Pattern:** a bare-identifier argument closed by `)` on a `dir`/`path`/`artifacts_dir`/`base`
  receiver, with line comments stripped first, a method-call-receiver exclusion
  (`store.dir().join(prefix)` is legal), and literals/`format!`/computed joins unmatched.
- **A missing default scan dir is a gate misconfiguration** (fail loud — a rename must not
  silently retire the gate); an explicitly-supplied missing dir is a clean pass (the self-test's
  fixture-tree mode).
- The self-test (`test-ban-artifact-path-join.sh`) keeps both directions: MUST-flag the inline
  `dir.join(name)` handler, MUST-pass the validator's own sanctioned join.

The sibling bans stand unchanged: `ban-global-state.sh`, `ban-agent-ip-shellout.sh` (the
behavioral half of the C6 zero-netlink gate), and `ban-legacy-terms.sh` — each with its
red-on-inverse self-test, all under `shellcheck`.

---

## `scripts/check-vendored-vhost.sh` — new in v4, full (v30 delta 2)

The **downstream-runnable** form of the vendored-patch assertion (rubric B15; design §10.4). The
in-repo `ci` assertion greps this workspace's `cargo tree`; a git-dep consumer silently loses the
`[patch.crates-io]` vendored-vhost stanza (cargo honors patch sections only from the consuming
workspace root) and with it the QEMU-unprivileged `SET_VRING_ENABLE` fix — so the same check must
run, path-independent, in *any* workspace:

```bash
#!/usr/bin/env bash
# Asserts the vendored vhost patch is live IN THE CURRENT WORKSPACE (vmcell's own, or a git-dep
# consumer's that replicated the [patch.crates-io] stanza — design v30 §10.4 says when that is
# load-bearing: QEMU + NetConfig::Unprivileged only). Path-independent: greps this workspace's own
# resolution. `cargo tree` only — resolves, never compiles. --locked ONLY: a stale/absent lockfile
# fails loud with cargo's own message (the repo's --locked policy; an unlocked fallback would
# silently re-resolve and could rewrite the consumer's Cargo.lock as a side effect of a "check").
# Two sanctioned replication shapes pass (both resolve the patched sources):
#   path form  — copy the stanza AND the vendor/vhost* trees to your workspace root
#                (cargo tree prints "… (/…/vendor/vhost…)")
#   git form   — a [patch.crates-io] entry pointing at the vmcell git repo
#                (cargo tree prints "… (https://… or git+…vmcell…)")
# A crate ABSENT from the graph entirely means this workspace never links vhost (no QEMU-unpriv
# feature set) — the check is not applicable and exits 0, saying so; exit 1 is reserved for
# present-but-unpatched, the actual dropped-patch trap.
set -euo pipefail

tree=$(cargo tree --locked -e normal --all-features)
fail=0
for spec in "vhost v0.16.0 vendor/vhost" "vhost-user-backend v0.22.0 vendor/vhost-user-backend"; do
    crate=${spec%% *}; ver=$(cut -d' ' -f2 <<<"$spec"); dirpat=$(cut -d' ' -f3 <<<"$spec")
    if ! grep -qE "\b${crate} v" <<<"$tree"; then
        echo "check-vendored-vhost: ${crate} not in this workspace's graph — check not applicable"
        echo "  (enable the QEMU-unprivileged feature set to make it meaningful)"
        continue
    fi
    # the \) after the dir keeps `vendor/vhost` from also matching `vendor/vhost-user-backend`
    if ! grep -qE "\b${crate} ${ver//./\\.} \((.*${dirpat//./\\.}\)|https?://|git\+)" <<<"$tree"; then
        echo "check-vendored-vhost: ${crate} resolves from the REGISTRY — the carried" >&2
        echo "  SET_VRING_ENABLE patch is dropped in this workspace. Replicate vmcell's" >&2
        echo "  [patch.crates-io] stanza at YOUR workspace root (path form needs the vendor/" >&2
        echo "  trees copied too; the git form needs only the stanza — design v30 §10.4)." >&2
        fail=1
    fi
done
if [ "$fail" -eq 0 ]; then echo "check-vendored-vhost: ok"; fi
exit "$fail"
```

Gate legs (v30 delta 2): the **green positive control** runs in the example workspace (whose
manifest replicates the stanza against a vhost-resolving feature set); the **red inverse** runs the
script in a temp copy of that workspace with the stanza dropped and asserts failure; a third leg
asserts the **not-applicable** exit-0 path on a vhost-less fixture (the accept-then-reject shape —
a hard failure the consumer is told to ignore — is exactly what the three-way split avoids).
**One law:** the `ci` recipe **replaces** its two inline M-VEND-3 grep lines with a call to this
script (keeping the M-VEND-3 comment above the call) — two independently-written copies of the
vendored-patch predicate had already diverged on pattern strictness, the exact
duplication-hides-divergence trap; the `=`-pins in `Cargo.toml` remain the version source the
script's two `spec` strings must track (noted at both sites).

---

## `justfile` — delta: the v30 recipes

The v3 gates stand as landed (MSRV sync, shellcheck/actionlint/zizmor/machete/typos, the four ban
scripts + self-tests, the lean-tree assertions with the **as-built** broker form — `vmcell-daemon`
and `axum` absent, `hyper` deliberately not asserted, in the `if …; then …; exit 1; fi` idiom the
repo uses because a leading `!` exempts a pipeline from `set -e`). v4 adds:

```bash
    # M-VEND-3 (v30 delta 2): one vendored-patch predicate, here and downstream — this call
    # REPLACES the two inline cargo-tree grep lines (two independently-written copies had already
    # diverged on pattern strictness; keep this comment, drop the greps).
    ./scripts/check-vendored-vhost.sh

    # v30 delta 2: the validator crate is downstream contract surface — semver-gate it like vmcell.
    if [ -n "$baseline" ]; then cargo semver-checks --baseline-rev "$baseline" -p vmcell -p vmcell-artifact-validator; else echo "semver-checks: no main baseline available locally, skipping (CI enforces it on PRs)"; fi
```

(The second line **replaces** the existing `-p vmcell`-only semver-checks invocation rather than
duplicating it.) And one new opt-in recipe, staged exactly like `test-crosvm` (CI has no designated
USB device; the recipe is the live half of v30 delta 9 — its KVM-free argv goldens and honesty
pins run under the ordinary unit gates):

```bash
# v30 delta 9 (FR-V5): host-USB passthrough live validation — QEMU only, opt-in.
# Needs KVM, a blessed runner, and a designated test device: VMCELL_TEST_USB_DEVICE=<vid>:<pid>.
# The guest kernel is the `usbhost` label built through the §5.6 toolkit (a vmcell-owned GENERIC
# xhci/USB-core fragment — never the consumer usbip/gadget closure; design §2.4 defends this).
test-usb-passthrough:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${VMCELL_TEST_USB_DEVICE:?set VMCELL_TEST_USB_DEVICE=<vid>:<pid> (a designated, disposable test device)}"
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="{{justfile_directory()}}/{{runner}}" \
        cargo nextest run --locked --profile integration -p vmcell --features qemu --run-ignored all \
        --no-tests=fail -E 'kind(test) & test(usb_passthrough)'
```

---

## `examples/downstream-kernel/` + its CI job — new in v4 (v30 delta 5)

The out-of-tree consumer workspace is the toolkit contract's living gate (rubric B15; design §5.6/
§10.4): its own Cargo workspace outside the vmcell members, consuming `vmcell` +
`vmcell-artifact-validator` the way a git-dep consumer does, carrying its own pins overlay and the
neutral self-proving `IKCONFIG`/`IKCONFIG_PROC` fragment. Its CI job:

```yaml
  example-downstream:
    # ubuntu-latest: build the consumer + the KVM-free contract legs (overlay resolution, the
    # documented CLI invocations, the harness-getter fail-loud leg, the vendor-assertion trio).
    # Mirrors the established job preamble — zizmor's artipacked audit requires
    # persist-credentials: false on every checkout, and the pinned toolchain + cache steps keep
    # the example on 1.96.1 (the root rust-toolchain.toml applies; examples/ is a descendant dir).
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>            # SHA-pinned, per policy
        with:
          persist-credentials: false
      - run: rustup toolchain install           # honors the root rust-toolchain.toml
      - uses: Swatinem/rust-cache@<sha>         # SHA-pinned, per policy
      - run: cd examples/downstream-kernel && cargo build --locked
      - run: cd examples/downstream-kernel && ./ci-check.sh   # overlay + getters + CLI + vendor legs

  # The live half (build vmlinux-ikconfig, boot it, validate, prove /proc/config.gz on the data
  # plane) joins the existing KVM job on [self-hosted, linux, kvm], after the operating-mode suites.
```

Two further `ci.yml` deltas ride along: the PRs-only semver step widens to **both contract crates**
(`cargo semver-checks --baseline-rev "${{ github.event.pull_request.base.sha }}" -p vmcell
-p vmcell-artifact-validator` — without this, the delta-2 gate exists locally but not on PRs,
violating the local ≡ CI meta-rule), and the KVM job **surfaces the skip manifest**: the suite
recipes export `VMCELL_SKIP_MANIFEST` to a run-scoped path and the job prints it (count + contents)
as its final step — until now the manifest defaulted to a temp file nobody surfaced, making the
"skip manifest surfaced in CI output" rubric row unenforced (gate theater by our own meta-rules).

The job is the **intended failure mode of contract drift** — a change that edits the example to
keep it green instead of versioning the contract inverts the gate (rubric B15). During landing,
redden it once deliberately (break the overlay resolution or drop the sidecar) per gate meta-rule 2.

---

## `fuzz/` — delta: the as-built broker target is the specification

The v3 sketch's `vmcell_broker::decode_frame` does not exist; the landed target — authoritative —
mirrors `protocol_decode.rs` over the broker's real codec (length-prefixed postcard):

```rust
// fuzz/fuzz_targets/broker_frame.rs — as built: guard len ≤ MAX_BROKER_FRAME_BYTES, then feed the
// payload to postcard::from_bytes::<BrokerRequest>, the decode the privileged child actually runs.
// (The daemon↔broker ENGINE channel is JSON — a different surface, vmcell_daemon::bridge — per
// Appendix A reversal 10.)
```

The recorded follow-ups stand: one `[[bin]]` each for the CH REST/chunked response parser and the
OCI/tar layer ingest, added as they stabilize. v30 adds **no new wire codec** (the dial is a raw
byte pipe; segments are netlink/nft, not a parser), so no new target lands with the v30 pass.

---

## Gates that land with the v30 delta pass

Per design v30 §18 (each delta ships with its named gate; the KVM-free halves are listed here, the
live legs in the design's §6.5/§3.2/§4.2/§2.4 battery paragraphs):

| Delta | KVM-free gate contents |
|---|---|
| 1 — pins overlay | overlay-wins / falls-back / referenced-absent-fails-naming-the-key / **misspelled-override-key-rejected** unit tests; overlay-edit invalidates the stage key |
| 2 — env contract | `check-vendored-vhost.sh` green + red legs; semver-checks `-p vmcell-artifact-validator`; the README/rustdoc git-dep section exercised by the example job |
| 3 — labelled build | resolved-config sidecar exists + contains a fragment symbol; prebuilt-with-label typed reject; sorted-label pin; missing-fragment-marker key test |
| 4 — validation battery | serial-classifier red-on-inverse on canned logs (`VFS: Unable to mount root fs`, vsock `EAFNOSUPPORT`, no-banner); `KconfigValues` parser tests |
| 5 — example workspace | the CI job itself (reddened once deliberately at landing) |
| 6 — extra files | injected-entry **present + mode** asserted at the image level; reserved-dest + duplicate-dest rejects red-on-inverse; `--inject` parser; identity-fold cache-invalidation; both `STAGE_VERSION` bumps asserted |
| 7 — raw dial | extracted-prologue mock-handshake test (the `exec_vsock.rs` template); dead-port EOF-interpretation unit test; the manifest pin test grows the `echo-server` symlink |
| 8 — segments | `segment_ip_math` range/injectivity/disjointness; the naming starts-with pin grows the `-seg-` class; slot free-list claim/free/exhaustion; the generalized id-claim exactly-one-winner race re-parameterized; every `build()` rejection |
| 9 — USB (separable, last) | the ninth `capability_honesty_*` pin across all four backends; the xhci/usb-host argv golden (a **pure extracted args helper** — the crosvm `build_crosvm_run_args` precedent); both `build()` rejections |

---

## One-time reconciliations directed with this revision

Not gates — stale artifacts the research for v30 surfaced, fixed once alongside the doc landing:

1. `justfile` `test-crosvm` comment (lines ~115–117) still calls crosvm runtime claims "all
   currently UNVERIFIED" — crosvm has been validated live (21/21) since; the comment predates the
   validation pass.
2. `crates/vmcell/Cargo.toml:225` — "alongside rtnetlink 0.14" → 0.21.
3. `crates/vmcell-crosvm/src/lib.rs:216–219` — a stale comment inside `build_crosvm_run_args`
   claims a rotated restore CID and `restore_rotates_host_paths: true`; the shipped behavior is
   the opposite (baked-CID sidecar reuse, `false`). A comment contradicting the honesty test it
   sits next to is a defect per rubric B8's comments-are-audited rule.

---

## Coverage map

Rubric Part D/E row → where it is enforced. Rows the rubric tags `review`/`test` (fake fidelity,
assertion quality, suppression *scope*, the segment/dial/toolkit behaviors that need the live
suite) stay with the reviewer and the suite.

| Rubric gate | Enforced by |
|---|---|
| Lint families, fmt | crate-root preambles (roster incl. backends/validator/bench), `clippy.toml`, fmt/clippy steps |
| B11 suppression hygiene | `clippy::allow_attributes`, `allow_attributes_without_reason` in every preamble |
| B10 wire casts; one obligation per `unsafe`; API honesty | wire-crate cast lints (`not(test)`-scoped, recorded); `multiple_unsafe_ops_per_block`, `unreachable_pub` |
| B12 P3: one artifact-name validator | `ban-artifact-path-join.sh` (as-built daemon-scoped shape) + self-test |
| B13 §12.5: seccomp wrappers banned by name | `deny.toml` `[bans]` |
| Lean members; agent/runner/privilege ∌ tokio/hyper/rtnetlink; broker ∌ **axum + vmcell-daemon** (as built) | `ci` lean steps + tree assertions (`if/then/exit` idiom) |
| Reduced-host configs; feature powerset (last, blocking) | `ci` build steps + `cargo hack` |
| cargo-deny; semver-checks over **both contract crates** | `deny.toml`; `ci`/CI PR job |
| B15 downstream contract observable | the example-workspace job; `check-vendored-vhost.sh` both ways; the documented-CLI invocations in `ci-check.sh` |
| nextest pins, integration-profile serial-host glob, scoped retries | `.config/nextest.toml` (as built) |
| KVM matrix + `just test-daemon`; opt-in `test-crosvm` / `test-usb-passthrough`; skip manifest surfaced | suite recipes + CI kvm job |
| Grep bans (global-state, agent-ip, legacy-terms, artifact-path) with both-direction self-tests | `scripts/ban-*.sh` + `test-ban-*.sh` |
| Vendored patch live — here and downstream | `ci` M-VEND-3 grep; `check-vendored-vhost.sh` |
| `--locked` everywhere; toolchain honesty (one MSRV fact) | every cargo invocation; the `ci` sync assertion |
| Shell/workflow/deps/spelling hygiene | `shellcheck`, `actionlint`, `zizmor`, SHA pins + Dependabot, `machete`, `typos` |
| Nightly fuzz on decode surfaces | `fuzz.yml` (`protocol_decode`, `broker_frame` as built) |
| v30 delta gates | the table above; land with the change per design §18 |
| Gate meta-rules: reachable, red-on-inverse, local ≡ CI | step ordering; the `test-ban-*` self-tests; `ci.yml` mirrors the `ci` recipe |
| Part E preflight: probe, bless block-and-ask, static-only only on NOT READY | `scripts/review-preflight-priv.sh` (exit 2 = ask for `just bless`; exit 1 = static-only) + its self-test |
