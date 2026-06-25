# Imp Testing — Automation Files

Every part of the review rubric that can be enforced by a machine, as a set of files you drop
into the repo. Each section gives the deploy path, a one-line note on what it enforces, and the
full contents.

**Before deploying:** these are templates that encode *rules*, not your exact filenames. Adapt
paths (e.g. the allocator module, the artifact-build entrypoint), feature names, and integration
test-binary names to the real crate. Pin the GitHub Action versions to current tags/SHAs.

| File | Enforces (rubric ref) |
|---|---|
| `src/lib.rs` (header) + per-module `forbid` | Failure visibility, unsafe scoping, doc gates (B2, B8) |
| `clippy.toml` | `DefaultHasher` ban; test-only unwrap/expect allowances (B4, B2) |
| `deny.toml` | License allow-list, advisories with rationale (B8, gate hygiene) |
| `rustfmt.toml` | `cargo fmt --check` is meaningful (the D1 drift) |
| `.config/nextest.toml` | Per-test timeouts; mechanical serial groups (B1, C) |
| `.github/workflows/ci.yml` | The whole gate pipeline incl. the `--ignored` matrix (Part D) |
| `scripts/ban-global-state.sh` | No new module-global mutable ID state (B6) |
| `justfile` | Dev loop + the §12.8 capability-runner bless |
| `scripts/git-pre-commit` *(optional)* | Local fmt/clippy before commit (D1) |
| `tests/common/mod.rs` *(template)* | Consistent capability-gated skip-with-reason (C, Q10) |

---

## `src/lib.rs` — crate-root lint header

Place these attributes at the very top of your existing `src/lib.rs`, above all items. They turn
whole defect families into compile errors. (Note: integration tests under `tests/*.rs` are
separate crates and do **not** inherit these — `clippy.toml` + `clippy --all-targets` covers them;
these `not(test)` denials bind production paths in the library crate.)

```rust
// src/lib.rs — top of file, above everything.
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
)]
#![cfg_attr(not(test), deny(
    clippy::unwrap_used,        // `.expect("invariant: …")` is the only escape hatch —
                                //   and NOT on guest-/network-driven hot paths (rubric B2).
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,      // a loud todo!() is fine in review; a silent `Ok(())` stub is the real
                                //   hazard (B2/B5) — reject those in review since no lint sees them.
    clippy::indexing_slicing,   // forces `.get()` / bounded reads (the fixed-4096 buffer family).
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
))]
```

Additionally, put this inner attribute at the **top of each I/O-free module file** (`config.rs`,
`agent/protocol.rs`, the cache-key code, the `/30` math in `net`) so a stray `unsafe` there is a
compile error rather than a review note:

```rust
// e.g. top of src/config.rs
#![forbid(unsafe_code)]
```

---

## `clippy.toml`

Deploy at the **repo root**. Catches the cache-key portability footgun at lint time and tells
clippy that tests may `unwrap`/`expect`/print freely (production paths still may not).

```toml
# Tests may unwrap/expect/print/dbg; production code may not (see the not(test) deny-list in lib.rs).
allow-unwrap-in-tests  = true
allow-expect-in-tests  = true
allow-print-in-tests   = true
allow-dbg-in-tests     = true

# Cache keys must be reproducible across Rust versions and processes (rubric B4).
disallowed-types = [
    { path = "std::collections::hash_map::DefaultHasher",
      reason = "not stable across Rust versions — use blake3/sha2 for cache keys (B4)" },
    { path = "std::hash::DefaultHasher",
      reason = "same as hash_map::DefaultHasher — unstable hash for content addressing (B4)" },
    { path = "std::collections::hash_map::RandomState",
      reason = "seeded per process — never for content-addressed keys (B4)" },
]

disallowed-methods = [
    { path = "std::env::set_var",
      reason = "unsafe in 2024 and process-global; if truly needed, call before any threads start with a // SAFETY note" },
]
```

---

## `deny.toml`

Deploy at the **repo root**. The license allow-list *is* the gate (anything not listed fails the
build); every advisory `ignore` must carry a rationale, or the security gate is defeated.

```toml
[graph]
all-features = true          # check optional deps too — this crate is feature-heavy.

[licenses]
# Allow-only. Anything outside this list (e.g. GPL/AGPL) fails the build.
allow = [
    "MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception",
    "BSD-3-Clause", "BSD-2-Clause", "ISC", "Zlib", "0BSD", "Unicode-3.0",
]
private = { ignore = true }  # don't license-check the workspace's own crates.

[bans]
multiple-versions = "warn"
wildcards = "deny"           # no `*` version requirements.

[advisories]
yanked = "deny"
# Every entry MUST carry an inline `reason` — bulk-suppression with no rationale defeats the gate.
ignore = [
    # { id = "RUSTSEC-0000-0000", reason = "why this is safe to ignore in our usage" },
]

[sources]
unknown-registry = "deny"
unknown-git = "deny"
```

---

## `rustfmt.toml`

Deploy at the **repo root**. Keeps `cargo fmt --check` (a CI gate) deterministic so drift like the
two-file divergence actually fails CI instead of sneaking in.

```toml
edition = "2024"
use_field_init_shorthand = true
use_try_shorthand = true
# Otherwise default style. The hard requirement is only that `cargo fmt --check` stays green.
```

---

## `.config/nextest.toml`

Deploy at `<repo>/.config/nextest.toml`. Turns a hang into a timeout failure (not a stuck CI job)
and replaces fragile `#[serial_test::serial]` annotations with a mechanical serial group for any
suite that mutates global host state.

```toml
[profile.default]
# Unit/codec/property tests are fast; flag anything that stalls.
slow-timeout = { period = "30s", terminate-after = 2 }
fail-fast = false

[profile.integration]
# VM boot + snapshot restore are slower; the builder-VM mmdebstrap run is the long outlier.
slow-timeout = { period = "120s", terminate-after = 5 }
retries = 0
fail-fast = false

[test-groups]
# Mechanical equivalent of #[serial]: run host-state-mutating tests one at a time so parallel
# --ignored runs don't race on netns / cgroups / nft.
serial-host = { max-threads = 1 }

[[profile.integration.overrides]]
# List the suites that create a VM or touch netns/cgroups/nft. Extend as you add tests.
filter = '''
    binary(boot) | binary(lifecycle) | binary(concurrency) | binary(snapshot_restore)
  | binary(egress_proxy) | binary(host_endpoint) | binary(metrics_limits)
  | binary(nested_virt) | binary(shares_ro_rw)
'''
test-group = 'serial-host'
```

---

## `.github/workflows/ci.yml`

Deploy at `<repo>/.github/workflows/ci.yml`. The full pipeline: static gates on a normal runner,
fast tests, and — critically — the `--ignored` integration matrix on a KVM runner so that suite is
not CI-invisible. (Per the design, CI may use `sudo -E` / a root step for the privileged suite
because CI runners are single-tenant and ephemeral; the capability runner is the dev-box path, in
the `justfile`.)

```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: "-D warnings"   # any leftover `warn` (e.g. a regression to warn(missing_docs)) fails CI.

jobs:
  # ---- Static gates: no KVM, no privileges. Most of the rubric lives here. ----
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { components: "rustfmt, clippy" }
      - uses: Swatinem/rust-cache@v2
      - uses: taiki-e/install-action@v2
        with: { tool: "cargo-hack,cargo-deny,cargo-semver-checks" }

      - name: rustfmt
        run: cargo fmt --all --check

      - name: clippy (all features)
        run: cargo clippy --all-targets --all-features

      - name: clippy feature-powerset      # catches deps imported under a feature gate but used unconditionally
        run: cargo hack --feature-powerset --depth 2 clippy --all-targets

      - name: cargo-deny
        run: cargo deny check

      - name: lean-agent invariant         # guest PID-1 binary must omit the host stack
        run: |
          if cargo tree -e no-dev --no-default-features --features agent \
               | grep -E '── (tokio|hyper|rtnetlink) v'; then
            echo "::error::lean-agent invariant violated — host stack leaked into the agent build"
            exit 1
          fi

      - name: ban module-global mutable ID/atomic state
        run: ./scripts/ban-global-state.sh

      - name: public-API semver (PRs only)
        if: github.event_name == 'pull_request'
        run: cargo semver-checks --baseline-rev "${{ github.event.pull_request.base.sha }}"

  # ---- Fast tests: unit, codec, property. No KVM. DEFAULT (non-ignored) set only. ----
  test-unit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - uses: taiki-e/install-action@v2
        with: { tool: "cargo-nextest" }
      - name: nextest (unit/codec/prop)
        run: cargo nextest run --all-features

  # ---- Integration matrix: needs /dev/kvm. Runs the #[ignore]'d suite so it is NOT CI-invisible. ----
  test-integration:
    # Self-hosted runner labelled `kvm`, with /dev/kvm and the runner user in the `kvm` group.
    runs-on: [self-hosted, linux, kvm]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - uses: taiki-e/install-action@v2
        with: { tool: "cargo-nextest" }

      - name: build VM artifacts        # adapt to your real artifact-build entrypoint
        run: cargo run --bin imp-testing -- build

      - name: rootless suite (no elevation — keeps the rootless path honest)
        run: cargo nextest run --profile integration --run-ignored all -E 'test(rootless) | test(smoltcp)'

      - name: privileged suite (sudo -E is acceptable on a single-tenant CI runner)
        run: sudo -E env "PATH=$PATH" cargo nextest run --profile integration --run-ignored all
             -E 'not (test(rootless) | test(smoltcp))'
```

---

## `scripts/ban-global-state.sh`

Deploy at `<repo>/scripts/ban-global-state.sh` (`chmod +x`); invoked by CI. Fails if a new
module-global mutable ID/atomic is introduced outside the one allowed allocator module — the
recurring "static `AtomicU32` instead of an injected allocator" defect (B6).

```bash
#!/usr/bin/env bash
# Enforces rubric B6 / design §12.5: IDs come from injected allocators, never module-global statics.
# Heuristic and line-based; shrink ALLOW_REGEX toward empty as the real allocators replace the globals.
set -euo pipefail

# The only file(s) currently permitted to hold the global allocator — adapt to your layout.
ALLOW_REGEX='src/vmm/mod\.rs|src/orchestrator\.rs'

violations="$(grep -rnE 'static[[:space:]]+mut[[:space:]]|static[[:space:]]+[A-Z0-9_]+[[:space:]]*:[[:space:]]*(std::sync::atomic::)?Atomic' src \
  | grep -vE "^($ALLOW_REGEX):" || true)"

if [[ -n "$violations" ]]; then
  echo "Forbidden module-global mutable state — use an injected allocator (rubric B6):"
  echo "$violations"
  exit 1
fi
echo "ok: no new global mutable ID/atomic state"
```

---

## `justfile`

Deploy at the **repo root** (`cargo install just`). The dev inner loop, including the §12.8
capability-runner blessing (the dev-box path; CI uses `sudo -E` instead). The bless step must be
re-run after every rebuild of the runner — writing the binary strips its caps, which is the
intended security property.

```just
set shell := ["bash", "-uc"]

runner := "target/debug/imp-test-runner"

# (Re)grant the two caps the privileged suite needs. Re-run after every rebuild of the runner.
bless:
    cargo build --bin imp-test-runner
    sudo setcap cap_net_admin,cap_sys_admin+p {{runner}}

# Fast inner loop: unit + codec + property tests. No KVM, no privileges.
test-unit:
    cargo nextest run --all-features

# Privileged integration suite via the capability runner (dev box only; group-restrict the runner
# on shared hosts). Wraps every test binary with imp-test-runner via the cargo target-runner hook.
test-priv:
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="{{justfile_directory()}}/{{runner}}" \
        cargo nextest run --profile integration --run-ignored all \
        -E 'not (test(rootless) | test(smoltcp))'

# Rootless integration suite under no elevation (keeps the rootless path honest).
test-rootless:
    cargo nextest run --profile integration --run-ignored all -E 'test(rootless) | test(smoltcp)'

# Everything the `lint` CI job runs, locally.
ci:
    cargo fmt --all --check
    cargo clippy --all-targets --all-features
    cargo hack --feature-powerset --depth 2 clippy --all-targets
    cargo deny check
    ./scripts/ban-global-state.sh
    cargo nextest run --all-features
```

---

## `scripts/git-pre-commit` *(optional local gate)*

A repo-tracked hook that runs fmt + clippy on commit, so format drift never reaches CI. Activate
once per clone: `ln -sf ../../scripts/git-pre-commit .git/hooks/pre-commit` (`chmod +x` the script).

```bash
#!/usr/bin/env bash
# Repo-tracked pre-commit hook. Symlink into .git/hooks/pre-commit (see deploy note).
set -euo pipefail

if ! cargo fmt --all --check; then
    echo "pre-commit: rustfmt drift — run 'cargo fmt --all' and re-stage." >&2
    exit 1
fi

# Fast clippy on default features; the full powerset runs in CI.
cargo clippy --all-targets -- -D warnings
```

---

## `tests/common/mod.rs` *(template — adapt signatures to your API)*

Deploy at `<repo>/tests/common/mod.rs`. This is the one piece of test *scaffolding* worth
centralizing: it gives every integration test a Drop-guarded `start_vm`, and a macro that emits one
capability-gated test per compiled-in backend with a **single** skip-with-reason string — closing
the recurring gap where the CH/primary path was silently exempted from the capability check and
skip strings drifted across files. Serial execution is handled by the `nextest.toml` group above,
not `#[serial_test::serial]`. **Adapt the `Vmm`/`TestVm`/constructor names to your real types.**

```rust
//! tests/common/mod.rs — shared integration-test harness. TEMPLATE: adapt to your real API.

use imp_testing::*; // your crate's public surface

/// Build and start a VM, allocating CID + VMID from the injected allocators. The returned
/// `TestVm` guard runs the full ordered teardown on Drop, so an assertion panic still cleans up
/// (rubric B1). Centralizing this removes the ~9 copies of the alloc + start boilerplate.
pub async fn start_vm<V: Vmm>(vmm: &V, cfg: VmConfig) -> TestVm<V> {
    TestVm::start(vmm, cfg)
        .await
        .expect("start_vm: VM failed to start")
}

/// Skip-with-reason if a capability is false for this backend. The ONE place skip strings live,
/// so no backend (including the primary) is silently exempted (rubric C).
#[macro_export]
macro_rules! require_cap {
    ($caps:expr, $field:ident) => {
        if !$caps.$field {
            eprintln!("SKIP: backend lacks capability `{}`", stringify!($field));
            return;
        }
    };
}

/// Emit one `#[ignore]`'d test per compiled-in backend, so an unsupported scenario is a visible,
/// attributed skip — never a silent green, and never a missing backend.
#[macro_export]
macro_rules! vmm_matrix_test {
    ($name:ident, |$vmm:ident| $body:block) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            #[cfg(feature = "cloud-hypervisor")]
            #[tokio::test]
            #[ignore = "needs KVM"]
            async fn cloud_hypervisor() {
                let $vmm = imp_testing::CloudHypervisor::new();
                $body
            }

            #[cfg(feature = "firecracker")]
            #[tokio::test]
            #[ignore = "needs KVM"]
            async fn firecracker() {
                let $vmm = imp_testing::Firecracker::new();
                $body
            }

            #[cfg(feature = "qemu")]
            #[tokio::test]
            #[ignore = "needs KVM"]
            async fn qemu() {
                let $vmm = imp_testing::Qemu::new();
                $body
            }
        }
    };
}

// Usage in e.g. tests/snapshot_restore.rs:
//
//   mod common;
//   vmm_matrix_test!(snapshot_round_trip, |vmm| {
//       require_cap!(vmm.capabilities(), snapshot_restore);
//       // … build a privileged/tap config, start_vm, snapshot, restore,
//       //     then ASSERT: vsock reconnected, CID/MAC rotated, RNG reseeded, clock resynced …
//   });
```
