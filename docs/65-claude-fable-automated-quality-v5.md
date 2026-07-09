# vmcell — Automated quality gates (v2)

Deployable contents for every automatable gate in `docs/53-claude-fable-code-review-rubric.md`
(rubric v4, Parts D/E). v2 supersedes `docs/51-claude-fable-automated-quality.md`, reconciled
against `docs/52` — the repo landed v1 and is ahead of it in several places, so sections are now one
of two kinds: **full contents** for files this doc owns, or **delta** for repo-owned files, giving
only the lines to add in the repo's established idiom (monolithic `ci` recipe, step-mirrored
`ci.yml`, per docs/52 §4.3). Repo-established names win, unchanged from v1's rule.

New in v2: the suppression-hygiene lints (rubric B11 — narrowest-scope `#[expect]` with mandatory
reasons), `unreachable_pub` + `multiple_unsafe_ops_per_block` + wire-crate cast lints in the
preambles, a single-source toolchain with an MSRV-honesty assertion, and five new tools:
`shellcheck`, `actionlint`, `zizmor`, `cargo machete`, `typos`.

---

## Crate-root lint preambles — full

Every crate root, in the two sanctioned variants docs/52 §3.2 rolled out; lines marked `v2:` are
the additions this revision makes on top of what landed. Full family (the five library crates and
the PID-1 agent binary, where the `unwrap_used`/`panic` denies are load-bearing):

```rust
#![deny(missing_docs, unsafe_op_in_unsafe_fn, rustdoc::broken_intra_doc_links)]
#![deny(unreachable_pub)]                          // v2: pub-in-private-module API surface honesty
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::multiple_unsafe_ops_per_block          // v2: one obligation per SAFETY comment
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
        clippy::allow_attributes,                  // v2: B11 — #[expect] only in prod code
        clippy::allow_attributes_without_reason    // v2: B11 — every suppression states why
    )
)]
```

Print-by-contract binaries (`vmcell-cli`, `vmcell-guest-tools`, `vmcell-test-runner`) keep the same
family minus `print_stdout`/`print_stderr`, rationale in the crate doc, exactly as landed. Wire
crates (`vmcell-protocol`, `vmcell-guest-agent`) additionally deny
`clippy::cast_possible_truncation`, `clippy::cast_sign_loss`, `clippy::cast_possible_wrap` — the
B10 `try_from`-not-`as` rule as a lint instead of a review item.

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
  weaken the crate root. Vendored crates carry no preamble and are unaffected.

---

## `clippy.toml` — full

Workspace root. As landed (docs/52 §3.1) with one v2 change: `msrv` moves to the tested floor. The
`temp_dir` non-ban stands — the rubric classifies bare-`/tmp` as a recorded, visible trade (`[BP]`),
and burying ~10 intentional scratch-base sites under suppressions inverts "kept visible."

```toml
# Declared MSRV = the tested floor (1.96.1). An UNDERSTATED rust-version is worse than cosmetic:
# an MSRV-aware resolver re-resolves older consumers onto dependency versions the lockfile pins
# were bumped past (the time 0.3.45 / RUSTSEC-2026-0009 class). Kept in lockstep with
# rust-toolchain.toml + [workspace.package] rust-version by the sync assertion in `ci`.
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
    { path = "std::process::exit", reason = "skips Drop-based ordered teardown; return from main instead. The PID-1 guest agent must never exit at all (§12.6) — statement-scope #[expect] with reason if a bin truly requires it" },
]
```

---

## `deny.toml` — delta: none

The repo's file is ahead of v1 (per-crate advisory rationales, the §10.4 permissive allow-list,
`yanked = "deny"`). The contract stands; no change.

---

## `Cargo.toml` (workspace root) — delta

`exclude = ["fuzz"]` and the `[patch.crates-io]` vendored entries with exact `=` pins are landed;
they stand. v2 adds the single-source MSRV:

```toml
[workspace.package]
# The tested floor, not an aspiration — see clippy.toml's msrv comment for why understating this
# is a live vulnerability path. Sync-asserted in `ci` against rust-toolchain.toml.
rust-version = "1.96.1"
```

Each member manifest replaces its own `rust-version = "…"` with:

```toml
rust-version.workspace = true
```

---

## `rust-toolchain.toml` — new, full

Repo root. The single toolchain source: rustup honors it locally, CI installs from it (see the
`ci.yml` delta), and the `ci` sync assertion keeps it equal to the declared `rust-version` — the
declared-vs-effective drift the design §10.5 toolchain note documents can no longer widen silently.

```toml
[toolchain]
channel = "1.96.1"
components = ["clippy", "rustfmt"]
profile = "minimal"
```

---

## `.config/nextest.toml` — delta: none

The repo's file is ahead of v1: the `nextest-version` pin (zero-selected-tests fails), the
`serial-host` positive-selection override, and the retry stanza under the established
`profile.integration` name. The contract stands; no change.

---

## `justfile` — delta

Insertable block for the repo's monolithic `ci` recipe (its idiom, per docs/52 §4.3). The
suppression-hygiene lints need no recipe — they live in the preambles and fire under the existing
clippy step. Tool availability: `shellcheck` ships on `ubuntu-latest` and in distro repos; the rest
install via `taiki-e/install-action` / `cargo install --locked`.

```bash
    # ---- v2 gates (docs/55) ----

    # Toolchain honesty (rubric Part D [52]): the declared MSRV equals the pinned toolchain.
    # An understated rust-version lets MSRV-aware resolvers hand consumers the vulnerable
    # time 0.3.45 the lockfile exists to avoid.
    rv=$(sed -nE 's/^rust-version *= *"([0-9.]+)".*/\1/p' Cargo.toml | head -n1)
    ch=$(sed -nE 's/^channel *= *"([0-9.]+)".*/\1/p' rust-toolchain.toml)
    [ -n "$rv" ] && [ "$rv" = "$ch" ] || { echo "MSRV drift: rust-version=$rv vs rust-toolchain channel=$ch" >&2; exit 1; }

    # The ban scripts, preflight, and bless path are load-bearing, security-adjacent bash.
    shellcheck scripts/*.sh

    # Workflow files: correctness (actionlint also shellchecks run: blocks) + security (zizmor:
    # script injection, over-broad permissions, unpinned actions — the suites run on a SELF-HOSTED
    # KVM runner, where a compromised action is lateral movement onto the host).
    actionlint
    zizmor .github/workflows/

    # Unused dependencies enlarge the audited, licensed, advisory-scanned surface. Macro-only
    # false positives get a per-crate [package.metadata.cargo-machete] ignored entry.
    cargo machete

    # Docs are a first-class artifact in this repo.
    typos
```

---

## `.github/workflows/ci.yml` — delta

Three changes, in the repo's step-mirrored idiom:

**1. Toolchain from `rust-toolchain.toml`** — replaces the explicit-version toolchain step, so the
file is the only place the version lives:

```yaml
      - name: install pinned toolchain (rust-toolchain.toml)
        run: rustup toolchain install    # reads rust-toolchain.toml, incl. components
```

**2. New named steps** mirroring the `ci` additions (same commands; the toolchain-sync line can
stay inside the `just ci` step if the repo prefers fewer steps):

```yaml
      - uses: taiki-e/install-action@v2
        with:
          tool: actionlint,cargo-machete,typos-cli,zizmor
          # if install-action lacks a tool: cargo install <tool> --locked

      - name: shellcheck (scripts are load-bearing)
        run: shellcheck scripts/*.sh
      - name: actionlint (workflow correctness incl. run: shell)
        run: actionlint
      - name: zizmor (workflow security — self-hosted KVM runner)
        run: zizmor .github/workflows/
      - name: cargo machete (unused deps)
        run: cargo machete
      - name: typos
        run: typos
```

**3. SHA-pin every third-party action** (both workflows and `fuzz.yml`): replace each
`uses: owner/action@vN` with the full 40-character commit SHA of that release, keeping the tag as a
comment — `uses: owner/action@<full-commit-sha>  # vN.n.n`. A tag is movable; on a self-hosted
runner a moved tag is arbitrary code on the KVM host. Dependabot (below) moves the pins, so this
costs nothing after the first pass; zizmor's `unpinned-uses` audit flags any unpinned action that returns.

---

## `.github/dependabot.yml` — new, full

Freshness automation for the two update surfaces the gates created: SHA-pinned actions and the
`--locked` lockfile. With `--locked` everywhere, dependency bumps land *only* through these
reviewed PRs — each one runs the full gate suite, and `cargo deny` still adjudicates
licenses/advisories on the result.

```yaml
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly

  - package-ecosystem: cargo
    directory: /
    schedule:
      interval: weekly
    # Group the routine noise; majors arrive as individual PRs that get real review.
    groups:
      minor-and-patch:
        update-types: ["minor", "patch"]
```

---

## `_typos.toml` — new, full

Repo root. Keep it near-empty: every exception is a permanent blind spot, so add entries only when
`typos` misfires on project vocabulary, not preemptively.

```toml
[files]
extend-exclude = ["vendor/", "target/", "fuzz/corpus/", "fuzz/artifacts/"]

[default.extend-words]
# Add only on a demonstrated false positive, one comment each.
```

---

## `fuzz/` + `.github/workflows/fuzz.yml` — delta: pins only

Landed as specified in docs/52 §3.4 — the target decodes the real surface
(`postcard::from_bytes::<Message>` behind the `MAX_FRAME_BYTES` precondition), the crate is
workspace-excluded, the workflow is scheduled/non-blocking. Two follow-ups: SHA-pin its actions
like the rest, and add one `[[bin]]` per remaining B10 surface as they stabilize (the CH
REST/chunked response parser, the OCI/tar layer ingest).

---

## `scripts/` (ban scripts, preflight) — delta: a bless-only sentinel in the preflight

The repo's `ban-global-state.sh` + `test-ban-global-state.sh` self-test satisfy meta-rule 2 in both
directions, and `ban-legacy-terms` / `ban-agent-ip-shellout` cover their invariants; all are now
inside the `shellcheck` gate. One delta to `review-preflight-priv.sh`: agents were reading "KVM
host" as "somewhere else" and skipping the suites, so the verdict now separates the failure a
maintainer's one-sudo `just bless` fixes from a genuinely missing facility — machine-keyable (exit
code + sentinel line), so an agent asks for the bless instead of downgrading itself to static-only.
Classify each check as bless-remediable (runner missing / perms / caps / stamp) or environmental,
then:

```bash
if (( env_fail )); then
    echo "preflight: FAILED — fix the items above, or label this run STATIC-ONLY and mark every runtime claim unverified."
    exit 1
elif (( bless_fail )); then
    echo "preflight: BLOCKED-ON-BLESS — ask the maintainer to run 'just bless', then rerun preflight and the suites."
    exit 2
fi
echo "preflight: ok — both operating-mode suites can run."
```

---

## Coverage map

Rubric Part D/E row → where it is enforced. Rows the rubric tags `review`/`test` (fake fidelity,
drop-order, assertion quality, suppression *scope* judgment, …) stay with the reviewer and the
suite.

| Rubric gate | Enforced by |
|---|---|
| Lint families, fmt | crate-root preambles, `clippy.toml`, fmt/clippy steps in `ci` |
| B11 suppression hygiene: `#[expect]`-only, mandatory reasons | `clippy::allow_attributes`, `clippy::allow_attributes_without_reason` in every preamble (scope narrowness itself: `review`) |
| B10 `try_from`-not-`as` on the wire | cast lints in the wire-crate preambles |
| One obligation per `unsafe` block; API surface honesty | `clippy::multiple_unsafe_ops_per_block`, `unreachable_pub` in the preambles |
| Lean members built **and** clippied; tree ∌ tokio/hyper/rtnetlink; agent shell-out ban | `ci` lean steps + `ban-agent-ip-shellout` |
| Reduced-host configs blocking; feature powerset | `ci` (205/205 blocking) |
| cargo-deny with per-crate rationales | `deny.toml` |
| semver-checks | `ci` |
| `cargo doc` deny-warnings | `ci` (landed, docs/52 §3.3) |
| nextest pins, serial-host positive selection, scoped retries | `.config/nextest.toml` (`profile.integration`) |
| KVM `--ignored` matrix with `--features firecracker,qemu`; skip manifest surfaced | suite recipes (`just test-privileged` + unprivileged) + CI kvm job |
| Global-state ban with both-direction self-test | `scripts/ban-global-state.sh` + `test-ban-global-state.sh` |
| Vendored-patch resolution + exact pins | `vendor-check` in `ci`, `[patch.crates-io]` |
| `--locked` everywhere | every cargo invocation |
| Toolchain honesty: one MSRV fact, tested floor | `rust-toolchain.toml` + `[workspace.package] rust-version` + the sync assertion in `ci` |
| Shell scripts linted | `shellcheck` in `ci` |
| Workflow correctness + security; SHA-pinned actions kept fresh | `actionlint`, `zizmor`, pin policy, `dependabot.yml` |
| No unused dependencies | `cargo machete` |
| Doc spelling | `typos` + `_typos.toml` |
| Nightly fuzz on decode surfaces | `fuzz.yml`, `fuzz/` |
| Gate meta-rule 3: local ≡ CI | `ci.yml` steps mirror the `ci` recipe; toolchain single-sourced |
| Part E Phase-0 preflight; probe-don't-presume, bless block-and-ask | `scripts/review-preflight-priv.sh` (exit 2 + `BLOCKED-ON-BLESS` sentinel = ask for `just bless`; exit 1 = genuine static-only) |
