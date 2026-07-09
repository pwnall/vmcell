# vmcell — Automated quality gates (v3)

Deployable contents for every automatable gate in `docs/69-claude-fable-code-review-rubric-v5.md`
(rubric v5, Parts D/E). v3 supersedes `docs/65-claude-fable-automated-quality.md` (v2), reconciled
against docs/52 and the v28 design restructure. Sections are one of two kinds: **full contents**
for files this doc owns, or **delta** for repo-owned files, giving only the lines to add in the
repo's established idiom (monolithic `ci` recipe, step-mirrored `ci.yml`, per docs/52 §4.3).
Repo-established names win, unchanged from v1's rule.

New in v3, all tracking rubric v5's daemon/broker/jail additions (Parts B12–B14) and the delta
register (design §18): the full-family lint preamble extends to the new crates (`vmcell-daemon`,
`vmcell-daemon-client`, `vmcell-broker`, `vmcell-privilege`, `vmcelld`); two new grep bans (the
artifact-path `dir.join(` ban, P3; the seccomp-wrapper `[bans]` block, §12.5); the broker's
web-stack tree assertion; the `just test-daemon` CI job; and the eleven delta-pass gates land with
the 0.10 change they enforce. Two design-doc errata this doc is authoritative over are called out
where they bite: the §9.7 Rust-1.85/1.88 toolchain note (superseded by the 1.96.1 single-source
MSRV) and the §15.2 phrasing that the broker excludes `tokio`/`hyper`/`rtnetlink` (it excludes only
the **web** stack — `axum`/`hyper` — and legitimately owns the engine).

---

## Crate-root lint preambles — full

Every crate root, in the two sanctioned variants docs/52 §3.2 rolled out. Lines marked `v3:` are the
additions this revision makes on top of what landed. Full family (the library crates and the two
binaries where the `unwrap_used`/`panic` denies are load-bearing):

```rust
#![deny(missing_docs, unsafe_op_in_unsafe_fn, rustdoc::broken_intra_doc_links)]
#![deny(unreachable_pub)]                          // pub-in-private-module API surface honesty
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::multiple_unsafe_ops_per_block          // one obligation per SAFETY comment
)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::dbg_macro,
        clippy::allow_attributes,                  // B11 — #[expect] only in prod code
        clippy::allow_attributes_without_reason    // B11 — every suppression states why
    )
)]
```

**Crate → preamble class** (v3 extends the roster to the daemon tier and broker):

| Crate | Class | Notes |
|---|---|---|
| `vmcell` | full family | the host library |
| `vmcell-protocol` | full family **+ wire casts** | see wire-crate block below |
| `vmcell-rootfs-builder`, `vmcell-kernel-builder` | full family | `Stage` impls |
| `vmcell-privilege` | full family | lean security predicates; keeps the full family at privilege |
| `vmcell-guest-agent` | full family **+ wire casts** | PID-1 — `unwrap_used`/`panic` are load-bearing (a panic aborts the guest); wire casts apply |
| `vmcell-daemon` | full family | `v3:` — a daemon logs via `tracing`, never stdout |
| `vmcell-daemon-client` | full family | `v3:` — a library, not a print-by-contract binary |
| `vmcell-broker` | full family | `v3:` — the cap-holder; logs via `tracing` |
| `vmcelld` | full family | `v3:` — the daemon binary; `tracing`, not stdout |
| `vmcell-cli` | print-by-contract | drops `print_stdout`/`print_stderr`, rationale in crate doc |
| `vmcell-guest-tools` | print-by-contract | drops the two `print_*` (a curl/ip shim prints) |
| `vmcell-test-runner` | print-by-contract | drops the two `print_*` (prints remediation) |
| `vmcelld-ctl` | print-by-contract | `v3:` — a CLI; streams stdout/stderr + guest exit code |

Print-by-contract binaries keep the same family minus `print_stdout`/`print_stderr`, rationale in
the crate doc. Wire crates (`vmcell-protocol`, `vmcell-guest-agent`) additionally deny
`clippy::cast_possible_truncation`, `clippy::cast_sign_loss`, `clippy::cast_possible_wrap` — the
B10 `try_from`-not-`as` rule as a lint instead of a review item:

```rust
// wire crates only — integer narrowing from the wire is try_from, never `as`
#![deny(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap)]
```

Per-module `#![forbid(unsafe_code)]` on the I/O-free modules (design §9.2 lists them: `net/`,
`config`, `naming`, `reflink`, `overlay`, `artifact`'s pure core, the protocol codec); crates with
real FFI drop it and rely on the unsafe-audit lints, saying why in the crate doc. `vmcell-broker`
and `vmcell-privilege` do real FFI (fork/setns/caps), so they carry the audit lints, not the
forbid.

Suppression policy the two B11 lints enforce, and its manual migration:

- The existing statement-scope allows (the five `process::exit` callsites from docs/52 §4.2) become
  `#[expect(clippy::disallowed_methods, reason = "…")]` — same narrowest scope, but a suppression
  whose lint stops firing now self-reports (`unfulfilled_lint_expectation` is red under
  `-D warnings`) instead of silently outliving its reason.
- Scope stays on the single statement, never the fn/module/crate; the crate-root policy blocks
  above are the sole sanctioned broad suppressions.
- A lint that fires only in some feature/platform configs makes a bare `#[expect]` red in the
  configs where it doesn't fire (clippy runs default-features in `ci`): scope it
  `#[cfg_attr(<the firing cfg>, expect(...))]`, or fall back to a reasoned `#[allow]` there.
- If codegen ever emits `#[allow]` into an `include!`d file, scope one
  `#[expect(clippy::allow_attributes, reason = "generated code")]` to that include site — do not
  weaken the crate root. Vendored crates (`vendor/vhost*`) carry no preamble and are unaffected.

---

## `clippy.toml` — full

Workspace root. As landed (docs/52 §3.1) with the v2 `msrv` change kept and one v3 addition: the
disallowed-methods list gains no new entry, but the `dir.join(`-on-a-client-string ban is a
**script** gate (below), not a clippy lint — clippy can't see which `Path::join` arguments are
client-controlled. The `temp_dir` non-ban stands (the rubric classifies bare-`/tmp` as a recorded,
visible `[BP]` trade; burying ~10 intentional scratch-base sites under suppressions inverts "kept
visible").

```toml
# Declared MSRV = the tested floor (1.96.1). An UNDERSTATED rust-version is worse than cosmetic:
# an MSRV-aware resolver re-resolves older consumers onto dependency versions the lockfile pins
# were bumped past (the time 0.3.45 / RUSTSEC-2026-0009 class). Kept in lockstep with
# rust-toolchain.toml + [workspace.package] rust-version by the sync assertion in `ci`.
# NOTE: this supersedes the design §9.7 "targets 1.85 / effective floor 1.88" note, which described
# the pre-bump state; 1.96.1 is the single source of truth now.
msrv = "1.96.1"

# Tests may unwrap/expect/print/dbg; production code may not (see the not(test) deny-list in lib.rs).
allow-unwrap-in-tests  = true
allow-expect-in-tests  = true
allow-print-in-tests   = true
allow-dbg-in-tests     = true

# Cache keys must be reproducible across Rust versions and processes (rubric B4).
disallowed-types = [
    { path = "std::collections::hash_map::DefaultHasher", reason = "not stable across Rust versions — use blake3/sha2 for cache keys (B4)" },
    { path = "std::hash::DefaultHasher", reason = "same as hash_map::DefaultHasher — unstable hash for content addressing (B4)" },
    { path = "std::collections::hash_map::RandomState", reason = "seeded per process — never for content-addressed keys (B4)" },
]

# NOTE on `std::env::temp_dir`: NOT banned on purpose. The rubric (B1) records the bare-/tmp
# dev-workstation scope as a visible trade; the per-VM scratch base (`VmTempDir::create`,
# `OrphanScanner::scan_scratch_dirs`) uses it deliberately. A hard ban would bury ~10 intentional
# sites under suppressions — the trade stays visible in code instead.
disallowed-methods = [
    { path = "std::env::set_var", reason = "unsafe in 2024 and process-global; if truly needed, call before any threads start with a // SAFETY note" },
    { path = "std::process::exit", reason = "skips Drop-based ordered teardown; return from main instead. The PID-1 guest agent must never exit at all (§3.4/C1) — statement-scope #[expect] with reason if a bin truly requires it" },
]
```

---

## `deny.toml` — delta: the seccomp-wrapper bans

The repo's file is ahead of v1 (per-crate advisory rationales, the permissive allow-list,
`yanked = "deny"`); that contract stands. v3 adds one **`[bans]` block** (rubric B13 / design
§12.5): the libseccomp-wrapper crates carry permissive Rust metadata over an LGPL-2.1 C link the
license scan cannot see, so they are banned by name — the one place metadata is insufficient.

```toml
[bans]
# These wrap or link the LGPL-2.1 C libseccomp; cargo-deny's license scan sees only the permissive
# Rust crate and would pass them. seccompiler (Apache-2.0/BSD-3, the compiler CH and FC use) is the
# only sanctioned seccomp dependency. Design §12.5, rubric B13.
deny = [
    { name = "libseccomp" },
    { name = "libseccomp-sys" },
    { name = "syscallz" },
    { name = "seccomp" },
    { name = "birdcage" },
]
```

If any wrapper is only ever a transitive dep of something benign, prefer `wrappers`/`deny-multiple`
scoping over an allow-exception; the point is that none of these ever links, directly or
transitively.

---

## `Cargo.toml` (workspace root) — delta

`exclude = ["fuzz"]` and the `[patch.crates-io]` vendored entries with exact `=` pins are landed;
they stand. The v2 single-source MSRV stands unchanged:

```toml
[workspace.package]
# The tested floor, not an aspiration — see clippy.toml's msrv comment for why understating this
# is a live vulnerability path. Sync-asserted in `ci` against rust-toolchain.toml. Supersedes the
# design §9.7 pre-bump note.
rust-version = "1.96.1"
```

Each member manifest — the daemon tier and broker included — carries
`rust-version.workspace = true` in place of its own literal.

---

## `rust-toolchain.toml` — full

Repo root. The single toolchain source: rustup honors it locally, CI installs from it, and the `ci`
sync assertion keeps it equal to the declared `rust-version`.

```toml
[toolchain]
channel = "1.96.1"
components = ["clippy", "rustfmt"]
profile = "minimal"
```

---

## `.config/nextest.toml` — delta: broaden the serial-host selector

The repo's file is ahead of v1: the `nextest-version` pin (zero-selected-tests fails), the
`serial-host` override, and the retry stanza under `profile.integration`. v3 makes **one** change —
the serial-host selector widens from `package(vmcell)` to a workspace-glob so the new
`vmcell-daemon` integration binary (and any future member's) auto-joins the serial group instead of
racing the VM suite (rubric C positive requirements):

```toml
# was: filter = 'package(vmcell) & kind(test) & !binary(proptests)'
# v3: any vmcell-* member's integration tests join the serial-host group automatically —
# the mild cost (serializing a few cheap KVM-free daemon integration tests) buys auto-inclusion,
# which the old per-package name silently denied new members.
[[profile.default.overrides]]
filter = 'package(~vmcell) & kind(test) & !binary(proptests)'
test-group = 'serial-host'

[test-groups.serial-host]
max-threads = 1
```

The `nextest-version` pin and the `profile.integration` retry stanza (VM-integration-scoped, with
the honest "residual-environment backstop, not a diagnosis" comment) are unchanged.

---

## `justfile` — delta

Insertable block for the repo's monolithic `ci` recipe (its idiom, per docs/52 §4.3). The v2 tool
gates (`shellcheck`/`actionlint`/`zizmor`/`machete`/`typos`) and the MSRV-sync line stand; v3 adds
the two new grep bans and the broker tree assertion. The suppression-hygiene lints need no recipe
(they fire under the existing clippy step).

```bash
    # ---- v2 gates (unchanged) ----
    # Toolchain honesty: declared MSRV == pinned toolchain (understated rust-version = the
    # time 0.3.45 re-resolution vuln).
    rv=$(sed -nE 's/^rust-version *= *"([0-9.]+)".*/\1/p' Cargo.toml | head -n1)
    ch=$(sed -nE 's/^channel *= *"([0-9.]+)".*/\1/p' rust-toolchain.toml)
    [ -n "$rv" ] && [ "$rv" = "$ch" ] || { echo "MSRV drift: rust-version=$rv vs rust-toolchain channel=$ch" >&2; exit 1; }
    shellcheck scripts/*.sh
    actionlint
    zizmor .github/workflows/
    cargo machete
    typos

    # ---- v3 gates (docs/69) ----

    # P3: the ONLY function that turns a client-supplied artifact name into a path is
    # resolve_artifact_path. A handler that builds `<dir>.join(<client string>)` itself is a
    # traversal hole (rubric B12). Grep-ban dir.join( / artifacts_dir.join( outside that fn; the
    # self-test fixtures (below) prove the ban can fire.
    scripts/ban-artifact-path-join.sh

    # B9/design §12.4 erratum-aware: the broker OWNS the engine (tokio, rtnetlink are legitimate);
    # its lean boundary is the WEB stack. Assert axum/hyper are absent from vmcell-broker — NOT
    # tokio/rtnetlink (the design §15.2 phrasing that lumps them in is the recorded erratum).
    ! cargo tree -p vmcell-broker -e no-dev -i axum  2>/dev/null | grep -q . \
        || { echo "vmcell-broker must not link axum (network-input stack must not share the cap-holder)" >&2; exit 1; }
    ! cargo tree -p vmcell-broker -e no-dev -i hyper 2>/dev/null | grep -q . \
        || { echo "vmcell-broker must not link hyper" >&2; exit 1; }
```

The existing lean-target tree assertions (`vmcell-guest-agent`, `vmcell-test-runner` ∌
`tokio`/`hyper`/`rtnetlink`) gain `vmcell-privilege` in the same idiom; `vmcell-broker` is
deliberately governed by the **axum/hyper-only** assertion above, not the full-stack one.

---

## `scripts/ban-artifact-path-join.sh` — new, full

The P3 grep ban with a both-direction self-test (gate meta-rule 2). Anchors on the rubric's
grep-gate: `dir.join(` / `artifacts_dir.join(` on a client-derived string is legal **only** inside
`resolve_artifact_path`.

```bash
#!/usr/bin/env bash
# Bans `<dir>.join(<name>)`-style path construction outside resolve_artifact_path (rubric B12, P3).
# The one validator turns a client string into a path; a handler doing it inline is a traversal hole.
set -euo pipefail

root="${1:-crates}"
# The sanctioned home. Everything else is a hit.
allow_file='crates/vmcell-daemon/src/artifact_store.rs'

# Match `.join(` on an identifier ending in dir/path fed a bare variable (not a string literal
# component like .join("fixed")). Tunable; err toward flagging and #[expect]-ing a false positive.
pattern='\b(dir|path|artifacts_dir|base)\.join\([a-z_]'

hits=$(grep -rnE "$pattern" "$root" --include='*.rs' \
        | grep -v '/tests/' \
        | grep -vF "$allow_file" || true)

if [[ -n "$hits" ]]; then
    echo "artifact-path ban: client-string path join outside resolve_artifact_path (P3):" >&2
    echo "$hits" >&2
    exit 1
fi
echo "ban-artifact-path-join: ok"
```

```bash
#!/usr/bin/env bash
# scripts/test-ban-artifact-path-join.sh — the ban must fire on the bug and pass on the fix.
set -euo pipefail
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/crates/vmcell-daemon/src"

# MUST-FLAG: a handler joining a client name itself.
cat > "$tmp/crates/vmcell-daemon/src/handler.rs" <<'RS'
fn upload(dir: &Path, name: &str) -> PathBuf { dir.join(name) }
RS
if scripts/ban-artifact-path-join.sh "$tmp/crates" >/dev/null 2>&1; then
    echo "FAIL: ban did not fire on inline dir.join(name)" >&2; exit 1
fi

# MUST-PASS: the same construction inside the sanctioned validator.
rm "$tmp/crates/vmcell-daemon/src/handler.rs"
cat > "$tmp/crates/vmcell-daemon/src/artifact_store.rs" <<'RS'
pub fn resolve_artifact_path(dir: &Path, name: &str) -> Result<PathBuf> { Ok(dir.join(name)) }
RS
scripts/ban-artifact-path-join.sh "$tmp/crates" >/dev/null || { echo "FAIL: ban fired on the validator" >&2; exit 1; }
echo "test-ban-artifact-path-join: ok (fires on bug, passes on fix)"
```

Both go inside the `shellcheck scripts/*.sh` gate; the self-test runs as its own `ci` step next to
`test-ban-global-state.sh`.

---

## `.github/workflows/ci.yml` — delta

The v2 changes stand (toolchain from `rust-toolchain.toml`; the `taiki-e/install-action` tool step;
SHA-pinned third-party actions). v3 adds the new steps mirroring the `ci` recipe (gate meta-rule 3
keeps local ≡ CI):

```yaml
      - name: artifact-path join ban + self-test (P3)
        run: |
          scripts/test-ban-artifact-path-join.sh
          scripts/ban-artifact-path-join.sh

      - name: broker web-stack exclusion (axum/hyper absent from the cap-holder)
        run: |
          ! cargo tree -p vmcell-broker -e no-dev -i axum  | grep -q .
          ! cargo tree -p vmcell-broker -e no-dev -i hyper | grep -q .

      - name: daemon end-to-end suite (inverted runner)
        # KVM job only; the test binary holds the caps and spawns vmcelld in a delegated scope.
        run: just test-daemon
```

`just test-daemon` belongs to the **KVM** job (it boots real VMs through `vmcelld`), alongside the
two operating-mode suites and `--features firecracker,qemu`. The KVM-free daemon gates (auth,
OpenAPI parity, the name-validator inverse battery, delete-in-use) run in the ordinary
`cargo nextest run` job with the rest of the unit/integration-KVM-free tests — they need no runner.

Every third-party action stays SHA-pinned (`uses: owner/action@<full-commit-sha>  # vN.n.n`);
zizmor's `unpinned-uses` audit flags any that returns; Dependabot moves the pins.

---

## `.github/dependabot.yml` — delta: none

Landed at v2 (weekly github-actions + cargo, minor/patch grouped, majors individually). With
`--locked` everywhere, dependency bumps land only through these reviewed PRs, each running the full
gate suite. No change.

---

## `_typos.toml` — delta: vocabulary from the new subsystems

The v2 file stands (`extend-exclude` covers `vendor/`, `target/`, `fuzz/corpus|artifacts/`). Add
project vocabulary only on a demonstrated false positive — the daemon/broker additions likely need
a handful (`vmcelld`, `virtiofsd`, `smoltcp`, `seccompiler`, `pidfd`, `netns`), each with a
one-line comment when `typos` actually misfires. Do not add preemptively; every entry is a
permanent blind spot.

```toml
[files]
extend-exclude = ["vendor/", "target/", "fuzz/corpus/", "fuzz/artifacts/"]

[default.extend-words]
# Add only on a demonstrated false positive, one comment each. Likely candidates as they surface:
#   vmcelld    = "vmcelld"     # the daemon binary, not a typo of "vmcell"
#   seccompiler = "seccompiler" # the rust-vmm crate
```

---

## `fuzz/` + `.github/workflows/fuzz.yml` — delta: add the broker frame target

Landed as specified (the `postcard::from_bytes::<Message>` target behind `MAX_FRAME_BYTES`, the
crate workspace-excluded, the workflow scheduled/non-blocking, actions SHA-pinned). v3 adds one
`[[bin]]` for the cross-privilege decode surface the broker introduces (rubric B10):

```toml
# fuzz/Cargo.toml
[[bin]]
name = "broker_frame"
path = "fuzz_targets/broker_frame.rs"
test = false
doc  = false
```

```rust
// fuzz/fuzz_targets/broker_frame.rs — the cap-holder parses these; a panic here is a
// crash in the privileged process. Decode behind the same MAX_BROKER_FRAME_BYTES precondition
// the real reader enforces.
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() <= vmcell_broker::MAX_BROKER_FRAME_BYTES {
        let _ = vmcell_broker::decode_frame(data); // must never panic; Err is fine
    }
});
```

The remaining B10 follow-ups stay recorded: one `[[bin]]` each for the CH REST/chunked response
parser and the OCI/tar layer ingest, added as they stabilize.

---

## `scripts/review-preflight-priv.sh` — delta: none beyond v2

The v2 bless-vs-environmental verdict split (exit 2 + `BLOCKED-ON-BLESS` = ask for `just bless`;
exit 1 = genuine static-only) stands and already satisfies the Part E Phase-0 contract. The daemon
suite (`just test-daemon`) uses the **same** blessed runner and delegated scope the privileged
suite does, so preflight needs no daemon-specific check — a green preflight means `just
test-daemon` can run too.

---

## Coverage map

Rubric Part D/E row → where it is enforced. Rows the rubric tags `review`/`test` (fake fidelity,
drop-order judgment, assertion quality, suppression *scope*, the daemon/broker/jail behaviors that
need the live suite) stay with the reviewer and the suite.

| Rubric gate | Enforced by |
|---|---|
| Lint families, fmt | crate-root preambles (roster incl. daemon/broker/privilege), `clippy.toml`, fmt/clippy steps |
| B11 suppression hygiene: `#[expect]`-only, mandatory reasons | `clippy::allow_attributes`, `clippy::allow_attributes_without_reason` in every preamble (scope narrowness: `review`) |
| B10 `try_from`-not-`as` on the wire; one obligation per `unsafe`; API surface honesty | wire-crate cast lints; `multiple_unsafe_ops_per_block`, `unreachable_pub` in the preambles |
| B12 P3: one artifact-name validator, no inline `dir.join(client)` | `scripts/ban-artifact-path-join.sh` + its self-test (behavioral P3/auth/OpenAPI-parity assertions: `test`) |
| B13 §12.5: libseccomp-wrapper crates banned by name | `deny.toml` `[bans]` block |
| Lean members built **and** clippied; agent/runner/privilege ∌ tokio/hyper/rtnetlink | `ci` lean steps + `ban-agent-ip-shellout` |
| B9/§12.4 erratum: broker ∌ **axum/hyper** (owns the engine) | `ci` broker web-stack tree assertion (NOT the full-stack one) |
| Reduced-host configs blocking; feature powerset; client `default-features=false` builds | `ci` blocking build steps |
| cargo-deny with per-crate rationales + the seccomp `[bans]` | `deny.toml` |
| semver-checks; the §18 deltas as one announced 0.10 pass | `ci` |
| `cargo doc` deny-warnings | `ci` |
| nextest pins, serial-host **workspace-glob** positive selection, scoped retries | `.config/nextest.toml` (`profile.integration`) |
| KVM `--ignored` matrix with `--features firecracker,qemu`; **`just test-daemon`**; skip manifest surfaced | suite recipes + CI kvm job |
| Global-state ban with both-direction self-test | `scripts/ban-global-state.sh` + `test-ban-global-state.sh` |
| Vendored-patch resolution + exact pins | `vendor-check` in `ci`, `[patch.crates-io]` |
| `--locked` everywhere | every cargo invocation |
| Toolchain honesty: one MSRV fact, tested floor (supersedes design §9.7 note) | `rust-toolchain.toml` + `[workspace.package] rust-version` + the `ci` sync assertion |
| Shell scripts linted; workflow correctness + security; SHA-pinned actions kept fresh | `shellcheck`, `actionlint`, `zizmor`, pin policy, `dependabot.yml` |
| No unused dependencies; doc spelling | `cargo machete`; `typos` + `_typos.toml` |
| Nightly fuzz on decode surfaces incl. the broker frame | `fuzz.yml`, `fuzz/` (`broker_frame` + the recorded follow-ups) |
| Delta-pass gates (drop-order, `HostEnv` seam re-param, `mem_limit_enforced` doc-test, `FakeVmm` fault arms, store sidecar, CLI redirect, …) | land with the 0.10 change per design §18; tracked in the rubric Part D "delta pass" block |
| Gate meta-rule 3: local ≡ CI | `ci.yml` steps mirror the `ci` recipe; toolchain single-sourced |
| Part E Phase-0 preflight; probe-don't-presume, bless block-and-ask | `scripts/review-preflight-priv.sh` (exit 2 = ask for `just bless`; exit 1 = static-only) |
