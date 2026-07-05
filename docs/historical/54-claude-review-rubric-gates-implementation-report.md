# Report — Doc↔Codebase reconciliation for the automated quality gates

Scope: how the codebase now compares to `docs/51-claude-fable-automated-quality.md` (the deployable
gate config) and `docs/50-claude-fable-code-review-rubric.md` (the rubric doc 51 automates), what was
merged, and where the implementation deliberately deviated.

---

## 1. Method

Doc 51 states its own merge rule up front: it is a *"v3 target"*, and *"names the repo already
established (recipes, env selectors, fixture names) win over the ones here"*, with interfaces it
invented marked *(align with repo)*. That was treated as binding. The repo was already substantially
ahead of the doc — most gates existed in richer form — so the work was: (a) add the genuinely missing
gates, (b) strengthen the lint surface to the doc's target, (c) fix the real defects those stronger
gates surfaced, and (d) keep the repo's established structures where they were equal-or-better.

Everything below is verified: `just ci` passes green (exit 0) — fmt, workspace clippy, deny, vendor
checks, lean, reduced-host, the new doc gate, all ban scripts + self-tests, 401 tests, semver, and the
full 205/205 feature powerset.

---

## 2. Element-by-element: doc 51 vs. repo

| Doc 51 section | Repo before | Action |
|---|---|---|
| Crate-root lint preamble | Only `vmcell` carried the full family | **Merged** onto every crate root (all nine crates; print-exempt variant for the three printing bins) |
| `clippy.toml` | Had `disallowed-types` + `set_var`; no `msrv`, no exit/temp_dir bans | **Merged** `msrv`, `process::exit` ban; **deviated** on `temp_dir` |
| `deny.toml` | Richer than doc (per-crate advisory rationales already present) | **Kept repo's** — doc adds nothing |
| `Cargo.toml` vendored patch | Already present + `vendor-check` in `ci` | **Kept**; added `exclude = ["fuzz"]` |
| `.config/nextest.toml` | Richer (`profile.integration`, serial-host positive-select, version pin) | **Kept repo's** — doc's `profile.vm` naming loses to established names |
| `justfile` | Monolithic `ci` recipe; no doc gate | **Merged** the `doc` gate; kept repo's recipe structure |
| `.github/workflows/ci.yml` | No doc step | **Merged** the `doc` step; kept repo's job structure |
| `.github/workflows/fuzz.yml` | Absent | **Created** |
| `fuzz/` crate | Absent | **Created** (target aligned to real decode surface) |
| `ban-global-state.sh` + fixtures | Script + `test-ban-global-state.sh` self-test present | **Kept repo's** equivalent self-test; **deviated** from `ban-fixtures/` layout |
| `review-preflight-priv.sh` | Present, richer | **Kept repo's** |

---

## 3. What was added (merges)

### 3.1 `clippy.toml`

Added the declared `msrv` and the `process::exit` ban from doc 51, preserved the repo's existing
`disallowed-types` (rubric B4) and `set_var` ban, and left `temp_dir` out with an inline rationale
(§4.1).

```toml
# Declared MSRV. The EFFECTIVE build floor is 1.88 via the committed lockfile (time 0.3.47 pins
# RUSTSEC-2026-0009); CI builds --locked on 1.88 (see the toolchain note in the design §10.5 and
# AGENTS.md). This declared value keeps clippy's msrv-gated lints honest without lowering that floor.
msrv = "1.85"

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

# NOTE on `std::env::temp_dir` (docs/51 lists it as a candidate ban): NOT banned here on purpose.
# The rubric (docs/50 B1) classifies bare-/tmp as `[BP]` with an explicit "dev-workstation scope is a
# recorded trade, kept visible", and the repo uses `temp_dir` deliberately for the per-VM scratch base
# (`VmTempDir::create`, `OrphanScanner::scan_scratch_dirs`). A hard ban would contradict that recorded
# trade and bury ~10 intentional sites under per-site allows — the trade stays visible in code instead.
disallowed-methods = [
    { path = "std::env::set_var", reason = "unsafe in 2024 and process-global; if truly needed, call before any threads start with a // SAFETY note" },
    { path = "std::process::exit", reason = "skips Drop-based ordered teardown; return from main instead. The PID-1 guest agent must never exit at all (§12.6) — per-site allow with rationale if a bin truly requires it" },
]
```

### 3.2 Crate-root lint preambles

Doc 51 wants the Part D family on *every* crate root; only `vmcell` had it. Across the nine crates
(and both roots of `vmcell-guest-agent`, which has a `lib.rs` and a `main.rs`) two variants were
rolled out. **The full family** (including the `print_*` bans) went to the five library crates
(`vmcell-protocol`, `vmcell-guest-agent` lib, `vmcell-rootfs-builder`, `vmcell-kernel-builder`,
`vmcell-artifact-validator`) *and* to the `vmcell-guest-agent` **PID-1 binary** (`main.rs`), which
does not print — there the `unwrap_used`/`panic` bans are load-bearing, since a PID-1 panic aborts
the whole guest. Example, `vmcell-protocol` (keeping its I/O-free `forbid(unsafe_code)`):

```rust
#![forbid(unsafe_code)]
#![deny(missing_docs, unsafe_op_in_unsafe_fn, rustdoc::broken_intra_doc_links)]
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
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
        clippy::dbg_macro
    )
)]
```

**Print-by-contract binaries** (`vmcell-cli`, `vmcell-guest-tools`, `vmcell-test-runner`) get the same
family *minus* `print_stdout`/`print_stderr`, with a rationale in the crate doc. Example
(`vmcell-test-runner`):

```rust
//! Privileged nextest target-runner: raises the three capabilities the privileged suite needs
//! (`cap_net_admin,cap_sys_admin,cap_dac_override`), confines the exec target under the trusted
//! cargo `target/` dir derived from its OWN location, then `execvp`s the test binary.
//!
//! No crate-level `forbid(unsafe_code)`: the privilege transition uses raw capability/syscall FFI,
//! audited via `undocumented_unsafe_blocks` + `unsafe_op_in_unsafe_fn`. `print_stdout`/`print_stderr`
//! are intentionally NOT denied — a target-runner's operator diagnostics go to stderr by contract.
#![deny(missing_docs, unsafe_op_in_unsafe_fn, rustdoc::broken_intra_doc_links)]
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
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
        clippy::dbg_macro
    )
)]
```

Doc 51's footnote about `#![forbid(unsafe_code)]` on I/O-free modules is honored: `vmcell-protocol`
(pure codec) keeps `forbid`; crates with real unsafe (`vmcell-guest-agent`, `vmcell-test-runner`) drop
it and rely on the unsafe-audit lints, stating why in the crate doc.

### 3.3 The `cargo doc` gate (justfile + ci.yml)

This was the biggest *missing* KVM-free gate — clippy does not run rustdoc lints, and `cargo doc` ran
nowhere, so broken doc links were invisible. Added inline in the `ci` recipe (matching the repo's
monolithic style rather than doc 51's separate `doc:` recipe):

```make
    # rustdoc gate (docs/51): RUSTDOCFLAGS=-D warnings turns EVERY rustdoc lint into a hard error —
    # broken/private intra-doc links, unresolved links — for the whole public surface. clippy does
    # NOT run rustdoc lints, and `cargo doc` runs nowhere else, so without this a broken doc link is
    # invisible until someone reads the HTML. `--all-features` documents the widest API; `--no-deps`
    # keeps it to our crates. (Benign cargo warning: the `vmcell` lib and the `vmcell` CLI bin share a
    # doc output path — cosmetic, not a rustdoc lint, so it does not fail the -D-warnings gate.)
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --locked
```

And the matching named step in `.github/workflows/ci.yml`:

```yaml
      - name: rustdoc (deny warnings)   # broken/private intra-doc links; clippy does NOT run rustdoc lints
        run: RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --locked
```

### 3.4 Fuzz crate + nightly workflow

`fuzz/Cargo.toml` — target names and dep path aligned to the repo's `crates/` layout:

```toml
# cargo-fuzz crate for the guest/network decode surfaces (rubric B10). Deliberately EXCLUDED from
# the root workspace (see `exclude = ["fuzz"]` in the top-level Cargo.toml): libfuzzer-sys links the
# libFuzzer/sanitizer runtime and only builds under `cargo fuzz` on nightly, so it must never be
# pulled into a stable `cargo build --workspace` / nextest / doc / hack run.
[package]
name = "vmcell-fuzz"
version = "0.0.0"
publish = false
edition = "2024"
rust-version = "1.85"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
# The real wire type; path points at the repo's `crates/` layout (docs/51 wrote `../vmcell-protocol`,
# aligned here to the actual member path).
vmcell-protocol = { path = "../crates/vmcell-protocol" }
# postcard is the actual decode surface (`vmcell-protocol` has no `decode_frame`; the doc's name was a
# placeholder — the honest entry point is a framed postcard `Message`).
postcard = { version = "1", features = ["use-std"] }

[[bin]]
name = "protocol_decode"
path = "fuzz_targets/protocol_decode.rs"
test = false
doc = false
```

`fuzz/fuzz_targets/protocol_decode.rs` — the target deviates from doc 51's placeholder `decode_frame`
(see §4.4):

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use vmcell_protocol::{MAX_FRAME_BYTES, Message};

// The decode surface that guest- and network-derived bytes actually reach: a single framed
// postcard `Message`. Both ends (`vmcell::agent` on the host, the guest agent's `read_framed`)
// reject any frame longer than the shared `MAX_FRAME_BYTES` cap BEFORE handing the payload to
// postcard, so we mirror that precondition here and fuzz exactly what production decodes.
//
// Contract under fuzz (rubric B10): decoding arbitrary bytes must reject cleanly — a returned
// `Err` is fine. A panic, an abort, an integer-narrowing truncation, or an allocation past the
// frame cap is a finding, and libFuzzer captures the reproducer.
fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FRAME_BYTES {
        return;
    }
    let _ = postcard::from_bytes::<Message>(data);
});
```

`fuzz/.gitignore`:

```gitignore
# cargo-fuzz working state — build output, evolving corpus, and crash reproducers are all local.
/target
/corpus
/artifacts
/coverage
```

`.github/workflows/fuzz.yml` (adapted to the repo's CI conventions — `permissions`, `concurrency`,
grouped log output):

```yaml
name: fuzz-nightly

# Non-blocking by construction: it is scheduled (gates no PR), but a red run is visible on the
# Actions tab and any crash uploads its reproducer. Covers the rubric B10 decode surfaces — today
# the framed postcard `Message` decoder (fuzz/fuzz_targets/protocol_decode.rs); add a target per new
# parser guest or network bytes reach (CH REST/chunked response, OCI/tar layer ingest).

on:
  schedule:
    - cron: "17 9 * * *"
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: fuzz-${{ github.ref }}
  cancel-in-progress: true

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - uses: taiki-e/install-action@v2
        with: { tool: "cargo-fuzz" }

      - name: run all fuzz targets (5 min each)
        run: |
          for t in $(cargo fuzz list); do
            echo "::group::cargo fuzz run $t"
            cargo fuzz run "$t" -- -max_total_time=300
            echo "::endgroup::"
          done

      - name: upload crash reproducers
        if: ${{ failure() }}
        uses: actions/upload-artifact@v4
        with:
          name: fuzz-artifacts
          path: fuzz/artifacts/
```

Workspace `Cargo.toml` gained the exclude that keeps stable `--workspace` commands off the
nightly-only crate:

```toml
# The cargo-fuzz crate is NOT a workspace member: libfuzzer-sys only builds under `cargo fuzz` on
# nightly, so keeping it out means `cargo build --workspace` / nextest / doc / hack (all stable, all
# --locked) never try to compile it. The nightly `fuzz.yml` job drives it via `cargo fuzz` directly.
exclude = ["fuzz"]
```

---

## 4. Deviations from doc 51 (with reasoning)

### 4.1 `temp_dir` is **not** banned
Doc 51 lists `std::env::temp_dir` in `disallowed-methods`. It was not added. Doc 50 (the authority
doc 51 automates) classifies bare-`/tmp` as **`[BP]`** (best-practice, not Critical) and says
explicitly *"the dev-workstation scope is a recorded trade, kept visible."* The repo relies on
`temp_dir` by design for the per-VM scratch base (`VmTempDir::create`, `OrphanScanner::scan_scratch_dirs`).
A hard clippy ban is *stricter than the rubric mandates*, would contradict a recorded trade, and would
require ~10 per-site allows on intentional code — turning "kept visible" into "buried under allows."
The trade stays visible in code, and the omission is documented inline in `clippy.toml`.

### 4.2 `process::exit` ban kept, with **narrow callsite allows**
This ban was added (it catches a real defect class — skipping Drop teardown). Five legitimate
`process::exit` callsites across three binaries keep a callsite allow — two in the CLI
(`vmcell-cli`), two in guest-tools, and one in the `vmcell-test-runner` helper — each at the
**narrowest (statement) scope**, directly preceding the call. In `vmcell-test-runner` the eight
logical error-exits are routed through a single `exit_failure()` helper, so they collapse to that one
real `process::exit` callsite bearing the allow:

```rust
fn exit_failure() -> ! {
    #[allow(clippy::disallowed_methods)]
    std::process::exit(1)
}
```

### 4.3 justfile/ci.yml structure kept monolithic
Doc 51's model is one `just` recipe per gate with `ci.yml` calling `just <recipe>` ("one command
source"). The repo instead uses a single shebang `ci` recipe and a `ci.yml` that mirrors it
step-by-step. Re-architecting into per-gate recipes would be an *override* of the repo's established
structure and would risk the working, security-sensitive recipes (`bless`, `test-privileged`,
`ban-legacy-terms`, `ban-agent-ip-shellout`) that doc 51 does not mention. The new `doc` gate was added
in the repo's existing idiom (inline in `ci`, named step in `ci.yml`).

### 4.4 Fuzz target hits the real decode surface, not `decode_frame`
Doc 51's skeleton calls `vmcell_protocol::decode_frame(data)` and flags it *(align with repo)*. No such
function exists — the protocol crate's honest decode surface is `postcard::from_bytes::<Message>`, and
the length-framing (`MAX_FRAME_BYTES`) lives in `read_framed`/the host codec. The target decodes a real
`Message` and mirrors the frame-cap precondition, rather than inventing an entry point (which would also
violate the rubric's "one law, one predicate").

### 4.5 Ban self-test kept as `test-ban-global-state.sh`, not `ban-fixtures/`
Doc 51 proposes a `scripts/ban-fixtures/` directory driving a keyword-derived self-test. The repo
already ships `scripts/test-ban-global-state.sh` — an equivalent red-on-inverse self-test (multi-line,
alias, comment-prose, and exemption fixtures) already wired into `ci`. Replacing a working, wired
self-test with the doc's alternate layout is churn with no gate gained, so the established one was kept.

### 4.6 `deny.toml` / `nextest.toml` unchanged
Both are already *ahead* of doc 51: `deny.toml` carries the per-crate advisory rationales doc 51 asks
for (the "no boilerplate crate-less ignore" rule), and `nextest.toml` already has the version pin, the
`serial-host` positive-selection override, and retry stanza — under the established `profile.integration`
name (doc 51's `profile.vm` loses per the doc's own "repo names win").

---

## 5. Defects the new/stronger gates surfaced (and fixed)

The point of these gates is to go red on real problems; turning them on found several that had
accumulated because the gate never existed:

- **10 broken/unresolved rustdoc links** (caught by the new doc gate — four flagged on the first run,
  six on the second, across seven doc comments in four files): a broken `Error::Unsupported` link in
  `orchestrator.rs`; private-item links from public docs in `orchestrator.rs`, `vmm/mod.rs`, and
  `netif.rs` (`IfReq`, `set_link_up`); and unresolved
  `pack_erofs_with_injection`/`resolve_builder_base` (in `artifact/rootfs/mod.rs`) and
  `Zygote::spawn_clone(s)` (in `orchestrator.rs`) links. Fixed by fully-qualifying (`crate::…`) or
  demoting private links to plain code spans.
- **3 missing `SAFETY:` comments** in `netif.rs` (`std::mem::zeroed()` and raw-pointer writes) — added
  obligations per the AGENTS.md rule.
- **Panic-prone indexing** in PID-1 (`handle_exec`, stdout/stderr pumps), the privileged runner (`argv`
  handling), and guest-tools (arg/MAC/HTTP parsing) — rewritten to `split_first` / `get(..)`,
  behavior-preserving.
- **14 missing `# Errors` + 2 missing `# Panics`** doc sections in `vmcell-artifact-validator` (its
  check functions are genuine public API — `vmcell`'s integration tests call them directly, so reducing
  visibility was not an option).

---

## 6. Relationship to doc 50 (rubric)

Doc 50 is unchanged — it is the source of truth doc 51 automates, and it was treated as the tie-breaker
(it decided §4.1). The coverage-map rows in doc 51 that doc 50 marks `review`/`test` (fake fidelity,
drop-order, assertion quality) remain human/suite responsibilities with no config file, exactly as both
docs intend. No rubric rule was weakened; where doc 51 proposed something *stricter* than doc 50 (the
`temp_dir` ban), the implementation followed doc 50.

---

## 7. Not runnable locally (structural verification only)

- **Fuzz**: needs nightly + `cargo-fuzz` (neither installed). Verified the manifest, dependency graph,
  exclusion, and API surface (`Message`, `MAX_FRAME_BYTES`, `postcard::from_bytes`) all resolve.
- **KVM suites / preflight / bless**: need a KVM host and the blessed runner. Unchanged from the
  committed versions; not exercised in this session.
